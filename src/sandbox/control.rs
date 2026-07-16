//! The `ask`-posture control plane: the pending-decision queue plus the per-session Unix control
//! socket a host-side `ops net pending` reaches to list and answer parked egress requests.
//!
//! Under `[network] mode = "ask"`, the proxy parks a request that no rule decides and blocks until
//! a human answers it (allow/deny) or the configured timeout elapses (deny — fail-closed). The
//! answer arrives out-of-band: a launch binds a control socket at
//! `<data>/egress/control-<pid>.sock` (under the `0700` data dir, owner-only) and serves it on a
//! thread alongside the proxy; a separate `ops net pending allow|deny` process connects to it.
//!
//! Security: the control socket is **never** bound into the cage — only the proxy socket and the CA
//! cross in (see [`super::egress`]). In Mode B the in-cage agent is the adversary, so letting it
//! reach this socket would let it answer its own asks, defeating the whole posture. The socket lives
//! beside `<data>`, which the cage never sees, and answering is inherently a trusted host-side act.
//!
//! Discovery is a glob of the egress directory; the socket filename carries the session pid, which
//! is also the `<pid>.<seq>` id prefix the proxy prints in its notice and the CLI parses to address
//! one session. The wire protocol is line-based and minimal (one command per connection): `LIST`
//! returns the pending rows, `ALLOW <seq>` / `DENY <seq>` answer one destination (every identical
//! retry of it, since a tool re-parks one URL many times), naming the host so a `--save` can persist
//! it; `RULES` lists the session's live manual `--session` rules; and `ALLOW *` / `DENY *` drain
//! every parked request at once (one `answered host=…` line each, then `ok` — an older server that
//! predates this replies `err …`, which the CLI reports as unsupported).

use std::collections::{BTreeMap, VecDeque};
use std::io::{self, BufRead, BufReader, Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::allowlist::Rule;

/// A human's answer to a parked request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Verdict {
    Allow,
    Deny,
}

/// One request parked awaiting a decision: what it is, when it started waiting, and the channel the
/// control side sends the verdict on to wake the blocked proxy thread.
struct Entry {
    host: String,
    port: u16,
    path: String,
    since: Instant,
    answer: mpsc::Sender<Verdict>,
}

/// A snapshot row of one pending request, for listing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PendingRow {
    pub(crate) seq: u64,
    pub(crate) host: String,
    pub(crate) port: u16,
    pub(crate) path: String,
    pub(crate) waiting_secs: u64,
}

/// The shared, lock-guarded queue of parked requests. The proxy [`park`](PendingState::park)s into
/// it and blocks; the control socket [`list`](PendingState::list)s and
/// [`answer_like`](PendingState::answer_like)s it. One per launch, shared (via `Arc`) between the
/// proxy serve threads and the control serve thread.
#[derive(Default)]
pub(crate) struct PendingState {
    inner: Mutex<Inner>,
}

#[derive(Default)]
struct Inner {
    /// A monotonic per-session counter — an id is never reused within a session, so a stale answer
    /// for a since-removed request can never hit a different one.
    next_seq: u64,
    entries: BTreeMap<u64, Entry>,
}

impl PendingState {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// Park a request until it is answered or `timeout` elapses (`None` waits indefinitely),
    /// returning the verdict. A timeout or a dropped channel is a deny — fail-closed. `on_enqueue`
    /// is called with the assigned sequence id immediately after the request is registered and
    /// *before* the thread blocks, so the caller can emit its notice with the live id.
    ///
    /// Flood guard: once `cap` requests are already parked, a new one is denied immediately without
    /// enqueuing, so an in-cage agent cannot pin unbounded host threads by opening connections that
    /// all park (the default `ask` timeout being indefinite, parked threads would otherwise live
    /// until answered).
    ///
    /// Residual (a departed-client ghost): the block is on the channel, not on socket I/O, so a cage
    /// tool that hits its *own* client-side timeout and disconnects mid-park is not noticed — the
    /// entry then sits in the queue (listed, and counting against `cap`) until answered or the
    /// `ask_timeout` elapses. Reaping a departed client denies nothing live, so it is compatible with
    /// the indefinite default; a future increment can poll the socket for a half-close while parked.
    pub(crate) fn park(
        &self,
        host: &str,
        port: u16,
        path: &str,
        timeout: Option<Duration>,
        cap: usize,
        on_enqueue: impl FnOnce(u64),
    ) -> Verdict {
        let (seq, rx) = {
            let mut inner = self.inner.lock().unwrap();
            if inner.entries.len() >= cap {
                return Verdict::Deny;
            }
            inner.next_seq += 1;
            let seq = inner.next_seq;
            let (tx, rx) = mpsc::channel();
            inner.entries.insert(
                seq,
                Entry {
                    host: host.to_string(),
                    port,
                    path: path.to_string(),
                    since: Instant::now(),
                    answer: tx,
                },
            );
            (seq, rx)
        };
        on_enqueue(seq);
        let verdict = match timeout {
            Some(t) => rx.recv_timeout(t).unwrap_or(Verdict::Deny),
            None => rx.recv().unwrap_or(Verdict::Deny),
        };
        // On a real answer the control side already removed the entry; on a timeout/disconnect it
        // is still present. Removing is idempotent, so this cleans up either case.
        self.inner.lock().unwrap().entries.remove(&seq);
        verdict
    }

    /// The currently-parked requests, oldest id first (the `BTreeMap` orders by sequence).
    pub(crate) fn list(&self) -> Vec<PendingRow> {
        let inner = self.inner.lock().unwrap();
        inner
            .entries
            .iter()
            .map(|(&seq, e)| PendingRow {
                seq,
                host: e.host.clone(),
                port: e.port,
                path: e.path.clone(),
                waiting_secs: e.since.elapsed().as_secs(),
            })
            .collect()
    }

    /// Answer every parked request sharing the named request's destination — its `(host, port, path)`
    /// — with `verdict`, waking each blocked proxy thread, and return `(host, port, count)` where
    /// `count` is how many were answered (the host for a `--save`, the port for a `--session` remember
    /// of the exact request). `None` if `seq` is not parked (already answered, or timed out). A send
    /// failure (a thread that just timed out on its own) is ignored — that entry is gone either way.
    ///
    /// This is the destination-grained answer the grouped listing addresses: a tool that retries one
    /// URL re-parks it many times, and they are a single decision, so `allow <id>`/`deny <id>` on the
    /// representative id decides the whole group at once. A *different* destination stays parked — this
    /// is not the blanket [`answer_all`](PendingState::answer_all) drain.
    pub(crate) fn answer_like(&self, seq: u64, verdict: Verdict) -> Option<(String, u16, usize)> {
        let mut inner = self.inner.lock().unwrap();
        let (host, port, path) = {
            let e = inner.entries.get(&seq)?;
            (e.host.clone(), e.port, e.path.clone())
        };
        // The seqs of every parked request to the same destination (collected first — the map cannot
        // be mutated while it is borrowed for the scan).
        let matching: Vec<u64> = inner
            .entries
            .iter()
            .filter(|(_, e)| e.host == host && e.port == port && e.path == path)
            .map(|(&s, _)| s)
            .collect();
        let count = matching.len();
        for s in matching {
            if let Some(entry) = inner.entries.remove(&s) {
                let _ = entry.answer.send(verdict);
            }
        }
        Some((host, port, count))
    }

    /// Answer *every* currently-parked request with `verdict`: drain the queue under one lock, wake
    /// each proxy thread, and return the `(host, port)` of each, oldest id first (the `BTreeMap`
    /// orders by sequence). A point-in-time drain — a request that parks after this returns is not
    /// affected. The lock is released before the sends, so a woken `park` thread's idempotent
    /// self-`remove` does not contend (the entry is already gone — taken with the rest of the map).
    pub(crate) fn answer_all(&self, verdict: Verdict) -> Vec<(String, u16)> {
        let entries = {
            let mut inner = self.inner.lock().unwrap();
            std::mem::take(&mut inner.entries)
        };
        entries
            .into_values()
            .map(|e| {
                let _ = e.answer.send(verdict);
                (e.host, e.port)
            })
            .collect()
    }
}

/// The live, per-session manual egress rules a user adds at runtime — either by answering an `ask`
/// with `--session` (an exact `host:port` for the answered request) or by loading a rule ahead of
/// time with `ops net allow|deny <rule> --session` (any egress rule). A runtime overlay distinct
/// from the (immutable) config policy, shared via `Arc` between the proxy serve threads and the
/// control thread (which appends to it). The proxy consults it by **folding these rules into the
/// effective policy** it evaluates per request — so an overlay allow/deny is enforced through the
/// same allow/deny/path/method/deny-wins machinery as a config rule, in every filtering posture
/// (allowlist, denylist, and `ask`), not only when a request would otherwise park.
#[derive(Default)]
pub(crate) struct ManualRules {
    inner: RwLock<ManualInner>,
}

#[derive(Default)]
struct ManualInner {
    allow: Vec<Rule>,
    deny: Vec<Rule>,
    /// Live `--session` mute (`dontaudit`) rules — a denied request matching one has its log line
    /// suppressed for this session, never its verdict. Folded into the effective policy's mute set
    /// alongside the config mutes; carried separately from allow/deny because it is a log filter,
    /// not a verdict rule.
    mute: Vec<Rule>,
}

impl ManualRules {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// Remember an answered `host:port` as a manual allow or deny, so re-running that exact request
    /// is decided without re-asking. Deduped — re-answering the same `host:port` does not stack.
    pub(crate) fn remember(&self, verdict: Verdict, host: &str, port: u16) {
        self.remember_rule(verdict, crate::allowlist::host_port_rule(host, port));
    }

    /// Add an arbitrary egress `rule` to the overlay as a manual allow or deny — the proactive
    /// `ops net allow|deny <rule> --session` path. Deduped, so re-loading the same rule does not
    /// stack. A deny takes precedence over an allow at decision time (deny wins in the policy).
    pub(crate) fn remember_rule(&self, verdict: Verdict, rule: Rule) {
        let mut inner = self.inner.write().unwrap();
        let list = match verdict {
            Verdict::Allow => &mut inner.allow,
            Verdict::Deny => &mut inner.deny,
        };
        if !list.contains(&rule) {
            list.push(rule);
        }
    }

    /// Add an egress `rule` to the live **mute** overlay — the `ops net mute <rule> --session` path.
    /// A `dontaudit` log filter: a denied request matching it is still refused (and still counted),
    /// only its log line is suppressed for this session. Deduped, so re-loading does not stack. Kept
    /// off [`Verdict`] deliberately — a mute is not a park answer, so it never touches the
    /// allow/deny/ask verdict paths.
    pub(crate) fn remember_mute(&self, rule: Rule) {
        let mut inner = self.inner.write().unwrap();
        if !inner.mute.contains(&rule) {
            inner.mute.push(rule);
        }
    }

    /// Whether the overlay is empty — the common case, letting the proxy skip building an effective
    /// policy and evaluate its immutable config policy directly (no per-request allocation). Includes
    /// the mute overlay, so a live `--session` mute is folded in like an allow/deny.
    pub(crate) fn is_empty(&self) -> bool {
        let inner = self.inner.read().unwrap();
        inner.allow.is_empty() && inner.deny.is_empty() && inner.mute.is_empty()
    }

    /// A snapshot of the manual verdict rules `(allow, deny)` — cloned out so the read lock is not
    /// held across the fold into the effective policy, listing, or I/O.
    pub(crate) fn snapshot(&self) -> (Vec<Rule>, Vec<Rule>) {
        let inner = self.inner.read().unwrap();
        (inner.allow.clone(), inner.deny.clone())
    }

    /// A snapshot of the manual **mute** rules — cloned out (like [`Self::snapshot`]) so the read
    /// lock is not held across the fold into the effective policy.
    pub(crate) fn mute_snapshot(&self) -> Vec<Rule> {
        self.inner.read().unwrap().mute.clone()
    }
}

// ── The live egress event log ─────────────────────────────────────────────────────────────────
//
// A bounded, in-memory ring of the decisions the proxy makes, read live by `ops net log` over the
// same per-session control socket. It is **never written to disk and never crosses into the cage**:
// it lives in the launch process's owner-only RAM for the session's lifetime and dies with it, at
// the same trust level as the injected secret the proxy already holds. The proxy redacts a request's
// query against the configured secret needles *before* pushing, so even in RAM the ring never holds a
// raw configured secret; the default `ops net log` display drops the query entirely.

/// The default number of recent egress events a session retains for the live log.
pub(crate) const LOG_RING_CAP: usize = 1000;

/// The verdict class of a logged egress decision. A superset of the `ops net stats` taxonomy
/// (allow/deny/blocked): the log is a diagnostic record, not a counter, so it also carries `error` —
/// a request the policy permitted but that could not complete (DNS failed, the host was unreachable,
/// its certificate was rejected). Keeping `error` distinct from `blocked` (a *refusal*) is the point:
/// "allowed but it failed" reads differently from "we said no", which is the question the log exists
/// to answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LogVerdict {
    /// The request was permitted and egressed.
    Allow,
    /// The request was refused by *policy*: a matching deny rule, a method scope, or an `ask`
    /// decision/timeout. (Security-guard and malformed/IP-literal refusals are recorded as
    /// [`Blocked`](Self::Blocked), not here.)
    Deny,
    /// A security guard or protocol check refused the request (SSRF, host/SNI mismatch, an
    /// outbound-secret leak, the splice cap, an IP-literal target, a malformed/smuggling request).
    Blocked,
    /// The request was allowed but did not complete: the name did not resolve, the host was
    /// unreachable, or its certificate was rejected. Not a refusal — a downstream failure.
    Error,
}

impl LogVerdict {
    /// The stable wire/display token for this verdict.
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            LogVerdict::Allow => "allow",
            LogVerdict::Deny => "deny",
            LogVerdict::Blocked => "blocked",
            LogVerdict::Error => "error",
        }
    }

    /// Parse a verdict token back, or `None` if it is not one of the four.
    pub(crate) fn parse(s: &str) -> Option<Self> {
        match s {
            "allow" => Some(LogVerdict::Allow),
            "deny" => Some(LogVerdict::Deny),
            "blocked" => Some(LogVerdict::Blocked),
            "error" => Some(LogVerdict::Error),
            _ => None,
        }
    }
}

/// The transport the proxy used for a decided request — the *how*, distinct from the port. The three
/// enforcement paths map one-to-one: an inspected TLS tunnel (a MITM'd `CONNECT`, including a
/// WebSocket over TLS) is [`Https`](Self::Https); an inspected cleartext `http://` absolute-form is
/// [`Http`](Self::Http); a raw `tcp://` L4 splice is [`Tcp`](Self::Tcp). [`Other`](Self::Other) is
/// the honest fallback for a request refused before its transport was known (a malformed `CONNECT`
/// line, a non-routable non-`CONNECT` request). Shown as a column in `ops net logs` because the port
/// alone is ambiguous — a `tcp://` splice can ride 443, and an inspected host can ride any port.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Proto {
    /// Inspected over TLS (a MITM'd `CONNECT`) — the default `https://` path, WebSockets included.
    Https,
    /// Inspected in the clear (an `http://` absolute-form request).
    Http,
    /// A raw L4 splice selected by a `tcp://` rule — bytes forwarded uninspected.
    Tcp,
    /// The transport was not yet known when the request was refused (a malformed `CONNECT`, a
    /// non-routable request). Rendered as `-`.
    Other,
}

impl Proto {
    /// The stable wire/display token.
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Proto::Https => "https",
            Proto::Http => "http",
            Proto::Tcp => "tcp",
            Proto::Other => "-",
        }
    }

    /// Parse a proto token back, defaulting to [`Other`](Self::Other) for an absent or unknown token
    /// (an older persisted log line carries no `proto=`, so it reads as `-` rather than failing).
    pub(crate) fn parse(s: &str) -> Self {
        match s {
            "https" => Proto::Https,
            "http" => Proto::Http,
            "tcp" => Proto::Tcp,
            _ => Proto::Other,
        }
    }
}

/// The HTTP protocol version an **inspected** request used — a second axis beside [`Proto`] (which
/// names the transport *security*: TLS-inspected / cleartext / raw splice). Kept separate so the
/// display can carry both without conflating them: an inspected TLS request reads `https/h1` or
/// `https/h2`, never a bare `h2` that would drop the "it was TLS" signal. Only a completed inspected
/// request has a version; a refusal (no HTTP exchange) or a raw `tcp://` splice (no HTTP at all) is
/// [`Unknown`](Self::Unknown), rendered without a suffix.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum HttpVer {
    /// HTTP/1.1 — the default MITM path, and the only version cleartext (`http://`) ever uses.
    H1,
    /// HTTP/2 — a `[network] http2`-designated host, MITM'd with ALPN `h2` (for gRPC).
    H2,
    /// Not known: a refusal before any HTTP exchange, a raw `tcp://` splice, or an older persisted
    /// log line that predates this field. Rendered without a version suffix.
    Unknown,
}

impl HttpVer {
    /// The wire token, or `""` when unknown (the field is then omitted from the line entirely).
    pub(crate) fn as_wire(self) -> &'static str {
        match self {
            HttpVer::H1 => "h1",
            HttpVer::H2 => "h2",
            HttpVer::Unknown => "",
        }
    }

    /// The display suffix appended to the proto token (`https` → `https/h1`); empty when unknown, so
    /// a refusal or a raw splice keeps its bare `https`/`tcp`/`-`.
    pub(crate) fn suffix(self) -> &'static str {
        match self {
            HttpVer::H1 => "/h1",
            HttpVer::H2 => "/h2",
            HttpVer::Unknown => "",
        }
    }

    /// Parse a version token back, defaulting to [`Unknown`](Self::Unknown) for an absent or unknown
    /// token (an older persisted line carries no `ver=`).
    fn parse(s: &str) -> Self {
        match s {
            "h1" => HttpVer::H1,
            "h2" => HttpVer::H2,
            _ => HttpVer::Unknown,
        }
    }
}

/// The RPC framing of an inspected request, recognized from its `Content-Type`. **Ground truth from
/// the header, never inferred from the path** — a request whose content-type does not name an RPC
/// framing is [`None`](Self::None) even if its path looks like `/pkg.Service/Method`. Consequence
/// worth knowing: **Connect *unary*** rides bare `application/proto`/`application/json` (byte-for-byte
/// indistinguishable from a plain protobuf POST), so it reads as `None`; only gRPC, gRPC-web, and
/// Connect *streaming* (`application/connect+…`) carry a self-identifying content-type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RpcKind {
    /// `application/grpc[+…]` — native gRPC (HTTP/2 framed).
    Grpc,
    /// `application/grpc-web[+…]` — gRPC-web (rides HTTP/1.1 or HTTP/2).
    GrpcWeb,
    /// `application/connect+…` — the Connect protocol's streaming framing.
    Connect,
    /// No RPC content-type recognized (a plain request, or Connect unary's ambiguous `application/proto`).
    None,
}

impl RpcKind {
    /// Classify from a request `Content-Type` value (case-insensitive; grpc-web is tested before grpc
    /// since it shares the `application/grpc` prefix).
    pub(crate) fn from_content_type(ct: &str) -> Self {
        let ct = ct.trim().to_ascii_lowercase();
        if ct.starts_with("application/grpc-web") {
            RpcKind::GrpcWeb
        } else if ct.starts_with("application/grpc") {
            RpcKind::Grpc
        } else if ct.starts_with("application/connect+") {
            RpcKind::Connect
        } else {
            RpcKind::None
        }
    }

    /// The wire/display token, or `""` when not an RPC framing (the field is then omitted).
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            RpcKind::Grpc => "grpc",
            RpcKind::GrpcWeb => "grpc-web",
            RpcKind::Connect => "connect",
            RpcKind::None => "",
        }
    }

    /// Parse an `l7` token back, defaulting to [`None`](Self::None) for an absent or unknown token.
    fn parse(s: &str) -> Self {
        match s {
            "grpc" => RpcKind::Grpc,
            "grpc-web" => RpcKind::GrpcWeb,
            "connect" => RpcKind::Connect,
            _ => RpcKind::None,
        }
    }
}

/// One decided egress request captured for the live view: when, where, how, and why. `method`/`path`
/// are present only for the inspected L7 path (an early-CONNECT block or a raw `tcp://` splice has no
/// HTTP head to read). The `path` is stored **already query-redacted** by the proxy, so the ring is
/// safe to hold in RAM; the `reason` is a stable category token (or `allowed`), never a rule's text
/// or a secret name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct LogEvent {
    pub(crate) seq: u64,
    /// Wall-clock capture time in epoch milliseconds — a clean stamp for `--json`; the human view
    /// renders it as a local `hh:mm:ss` time.
    pub(crate) at_epoch_ms: u128,
    pub(crate) host: String,
    pub(crate) port: u16,
    pub(crate) method: Option<String>,
    pub(crate) path: Option<String>,
    pub(crate) verdict: LogVerdict,
    pub(crate) reason: String,
    /// The transport the proxy used (or would have): `https` (inspected TLS), `http` (inspected
    /// cleartext), `tcp` (raw L4 splice), or `-` when unknown at refusal time. Shown as a column
    /// because the port alone does not name the protocol (a `tcp://` splice can ride 443).
    pub(crate) proto: Proto,
    /// The HTTP version of an inspected request (`h1`/`h2`), or `Unknown` for a refusal / raw splice
    /// / older line. A second axis beside `proto`: rendered as a suffix (`https/h2`) so the transport
    /// security (`https` vs cleartext `http`) is never lost. Set only at the inspected-forward sites.
    pub(crate) http_ver: HttpVer,
    /// The RPC framing recognized from the request `Content-Type` (`grpc`/`grpc-web`/`connect`), or
    /// `None`. Ground truth from the header — never inferred from the path — so Connect *unary*
    /// (bare `application/proto`) reads as `None`. Set only at the inspected-forward sites.
    pub(crate) rpc: RpcKind,
    /// Whether this refusal was suppressed from the default `sbx net log` view by a `mute`
    /// (SELinux `dontaudit`) rule. A muted event is still counted in `sbx net stats` and lives in a
    /// **separate** ring (so a muted flood never evicts a real event); it appears only under
    /// `ops net log --all`, tagged. Only ever `true` for a `deny` (mute suppresses refusals, never
    /// an allow, a security-guard `blocked`, or a downstream `error`).
    pub(crate) muted: bool,
    /// The upstream HTTP status code (200/404/…), for a **completed L7** request only — filled in by
    /// [`LogRing::set_status`] once the response head returns, after the event was pushed at the
    /// decision point. `None` for an L4 (`tcp://`) splice (no HTTP response to parse), a refusal, an
    /// `error` (no response), or a request whose response has not yet arrived.
    pub(crate) status: Option<u16>,
    /// The amendment sequence at which [`LogRing::set_status`] filled in `status`, or `None` while
    /// the status is unset. It is a SECOND monotonic cursor (distinct from `seq`): a `--follow`
    /// reader that already passed this event's `seq` uses it to pick the event up again once its
    /// status arrives, so `--with-status` is not blank in follow mode. Server-side only — never sent
    /// over the wire (the reader tracks the ring's amend cursor from the `amended=` reply line).
    pub(crate) amend_seq: Option<u64>,
}

/// The result of a `LOG` query: the events past the caller's cursor, how many fell off the ring
/// before that cursor (surfaced, not silently dropped — a bursty agent between `--follow` polls),
/// the newest sequence number (the seq cursor to pass next time, even when `events` is empty), and
/// the newest amendment sequence (the amend cursor to pass next time, for retroactive status).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct LogSnapshot {
    pub(crate) events: Vec<LogEvent>,
    pub(crate) dropped: u64,
    pub(crate) head: u64,
    pub(crate) amend_head: u64,
}

/// A bounded ring of recent egress decisions, newest appended, oldest evicted past `cap`. Shared
/// (via `Arc`) between the proxy serve threads (which [`push`](LogRing::push)) and the control serve
/// thread (which [`snapshot`](LogRing::snapshot)s for `ops net log`). Sequence numbers start at 1 and
/// never repeat within a session, so a `--follow` cursor of 0 means "from the beginning" and can
/// never collide with a real event.
pub(crate) struct LogRing {
    inner: Mutex<LogInner>,
    cap: usize,
}

struct LogInner {
    next_seq: u64,
    /// The next amendment sequence [`LogRing::set_status`] will stamp — a second monotonic counter,
    /// bumped only when a status is filled in, so a follow reader can pick up retroactive statuses.
    next_amend: u64,
    events: VecDeque<LogEvent>,
    /// Muted refusals, kept out of the default view. A **separate** ring with the same cap so a
    /// chatty muted host can never evict a real event from `events`; merged in (by `seq`) only when
    /// a reader passes `include_muted` (`ops net log --all`). Shares `next_seq` with `events`, so the
    /// two interleave in one monotonic order.
    muted: VecDeque<LogEvent>,
}

impl LogRing {
    pub(crate) fn new(cap: usize) -> Self {
        LogRing {
            inner: Mutex::new(LogInner {
                next_seq: 1,
                next_amend: 1,
                events: VecDeque::new(),
                muted: VecDeque::new(),
            }),
            cap: cap.max(1),
        }
    }

    /// Append one decision, assigning it the next sequence number and evicting the oldest if the ring
    /// is full. Called from the proxy with the path already query-redacted. Returns the assigned
    /// sequence number, so a later [`set_status`](LogRing::set_status) can amend this same event once
    /// its upstream response returns.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn push(
        &self,
        muted: bool,
        host: &str,
        port: u16,
        method: Option<&str>,
        path: Option<&str>,
        verdict: LogVerdict,
        reason: &str,
        proto: Proto,
        http_ver: HttpVer,
        rpc: RpcKind,
    ) -> u64 {
        let at_epoch_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis())
            .unwrap_or(0);
        let mut g = self.inner.lock().unwrap();
        let seq = g.next_seq;
        g.next_seq += 1;
        let event = LogEvent {
            seq,
            at_epoch_ms,
            host: host.to_string(),
            port,
            method: method.map(str::to_string),
            path: path.map(str::to_string),
            verdict,
            reason: reason.to_string(),
            proto,
            http_ver,
            rpc,
            muted,
            status: None,
            amend_seq: None,
        };
        // A muted refusal goes to its own ring so it can never evict a real event from `events`;
        // both rings share `self.cap` and the monotonic `seq`.
        let ring = if muted { &mut g.muted } else { &mut g.events };
        ring.push_back(event);
        while ring.len() > self.cap {
            ring.pop_front();
        }
        seq
    }

    /// Amend an already-pushed event with the upstream HTTP status code its response returned. A no-op
    /// if the event has already been evicted from the ring (a very bursty session between the push and
    /// the response), so a late status never resurrects an evicted event. Events are appended in
    /// sequence order, so a reverse scan finds the target quickly (the amend usually lands on the
    /// newest events).
    pub(crate) fn set_status(&self, seq: u64, status: u16) {
        let mut guard = self.inner.lock().unwrap();
        let g = &mut *guard;
        if let Some(ev) = g.events.iter_mut().rev().find(|e| e.seq == seq) {
            ev.status = Some(status);
            // Stamp the amendment cursor so a follow reader that already passed this event's `seq`
            // re-reads it once (with its status now filled) on its next poll.
            ev.amend_seq = Some(g.next_amend);
            g.next_amend += 1;
        }
    }

    /// The events past `after`, plus the eviction gap and the newest sequences. `after = None` is a
    /// tail read (the whole retained window; never reports a gap — a first read has nothing to miss);
    /// `after = Some(cursor)` is a follow read (events with `seq > cursor`, reporting how many between
    /// the cursor and the retained window were evicted unseen).
    ///
    /// `after_amend = Some(a)` additionally RE-EMITS an already-seen event (`seq <= after`) whose
    /// status was filled in since amendment cursor `a` — so a `--follow --with-status` reader sees a
    /// status that arrives after it passed the event's `seq`. A brand-new event (`seq > after`) is
    /// already included, so it is not re-emitted (no duplicate). `after_amend = None` (a tail read, or
    /// an old reader that does not track the amend cursor) does no retroactive re-emission.
    pub(crate) fn snapshot(
        &self,
        after: Option<u64>,
        after_amend: Option<u64>,
        include_muted: bool,
    ) -> LogSnapshot {
        let g = self.inner.lock().unwrap();
        let head = g.next_seq - 1;
        let amend_head = g.next_amend - 1;
        let cursor = after.unwrap_or(0);
        let mut events: Vec<LogEvent> = g
            .events
            .iter()
            .filter(|e| e.seq > cursor)
            .cloned()
            .collect();
        // `--all` folds the separate muted ring into the view, re-sorted into one `seq` order. The
        // default view omits it entirely (muted refusals are suppressed). `dropped`/amend stay keyed
        // on the main ring — a muted eviction never reports a gap (it is suppressed by design).
        if include_muted {
            events.extend(g.muted.iter().filter(|e| e.seq > cursor).cloned());
            events.sort_by_key(|e| e.seq);
        }
        if let Some(a) = after_amend {
            for e in g.events.iter() {
                if e.seq <= cursor && e.amend_seq.is_some_and(|s| s > a) {
                    events.push(e.clone());
                }
            }
        }
        let dropped = match (after, g.events.front()) {
            (Some(a), Some(oldest)) if oldest.seq > a + 1 => oldest.seq - a - 1,
            _ => 0,
        };
        LogSnapshot {
            events,
            dropped,
            head,
            amend_head,
        }
    }
}

// ── The live active-flow registry ─────────────────────────────────────────────────────────────
//
// The set of egress tunnels currently OPEN through the proxy, read live by `ops net live` over the
// same per-session control socket. Unlike the event log (a *history* of decisions), this is volatile
// state: a flow appears when its tunnel is established and vanishes when it closes. It is never
// persisted and never crosses into the cage — it lives in the launch process's owner-only RAM for the
// session's lifetime, at the same trust level as the log the proxy already holds.
//
// The two byte counters (`up` = client→upstream, `down` = upstream→client) are lock-free
// `Arc<AtomicU64>` the relay increments per read/write; the registry mutex is taken only at
// register / deregister / snapshot — never per byte — so the hot relay path stays unlocked.

/// One open tunnel captured for `ops net live`: where it goes, how it is carried, when it opened, and
/// how much has flowed each way so far. `up`/`down` are byte totals — application-plaintext bytes on
/// an inspected L7/cleartext path, raw ciphertext bytes on a `tcp://` L4 splice (the proxy sees only
/// the encrypted stream there).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct FlowSnapshot {
    pub(crate) host: String,
    pub(crate) port: u16,
    pub(crate) proto: Proto,
    /// When the tunnel was established, epoch milliseconds. The CLI renders the age (now − start).
    pub(crate) start_epoch_ms: u128,
    pub(crate) up: u64,
    pub(crate) down: u64,
}

struct FlowEntry {
    host: String,
    port: u16,
    proto: Proto,
    start_epoch_ms: u128,
    up: Arc<AtomicU64>,
    down: Arc<AtomicU64>,
}

/// The set of currently-open egress tunnels. Shared (via `Arc`) between the proxy serve threads
/// (which [`register`](FlowRegistry::register) a flow for the tunnel's lifetime) and the control serve
/// thread (which [`snapshot`](FlowRegistry::snapshot)s for `ops net live`). Ids start at 1 and never
/// repeat within a session, so the snapshot order is stable (oldest-open first).
pub(crate) struct FlowRegistry {
    inner: Mutex<FlowInner>,
}

struct FlowInner {
    next_id: u64,
    flows: BTreeMap<u64, FlowEntry>,
}

/// RAII handle for one open flow: it is registered on [`register`](FlowRegistry::register) and
/// deregistered when this guard drops (the tunnel closed). It always carries the two byte counters the
/// relay increments — `up` (client→upstream) and `down` (upstream→client) — so the counting wrappers
/// can bump them without touching the registry lock. A **detached** guard ([`detached`](Self::detached))
/// carries live counters but is not in any registry (its `registry` is `None`), so the relay counts
/// unconditionally without a branch and a session with no registry (tests) still works.
pub(crate) struct FlowGuard {
    registry: Option<Arc<FlowRegistry>>,
    id: u64,
    pub(crate) up: Arc<AtomicU64>,
    pub(crate) down: Arc<AtomicU64>,
}

impl FlowGuard {
    /// A guard not tied to any registry — it carries counters (so the relay's counting wrappers work
    /// uniformly) but registers/deregisters nothing. Used when no flow registry is attached (tests).
    pub(crate) fn detached() -> Self {
        FlowGuard {
            registry: None,
            id: 0,
            up: Arc::new(AtomicU64::new(0)),
            down: Arc::new(AtomicU64::new(0)),
        }
    }
}

impl Drop for FlowGuard {
    fn drop(&mut self) {
        // Remove the flow from the live view the instant its tunnel closes (a detached guard has no
        // registry and nothing to remove).
        if let Some(registry) = &self.registry {
            if let Ok(mut g) = registry.inner.lock() {
                g.flows.remove(&self.id);
            }
        }
    }
}

impl FlowRegistry {
    pub(crate) fn new() -> Self {
        FlowRegistry {
            inner: Mutex::new(FlowInner {
                next_id: 1,
                flows: BTreeMap::new(),
            }),
        }
    }

    /// Register an open tunnel and return its RAII guard, which deregisters it on drop. Call this only
    /// after the request is permitted and the upstream connection is established — a flow is a live
    /// *allowed* tunnel, never a refused request. The returned guard carries fresh zeroed `up`/`down`
    /// counters for the relay to increment.
    pub(crate) fn register(self: &Arc<Self>, host: &str, port: u16, proto: Proto) -> FlowGuard {
        let up = Arc::new(AtomicU64::new(0));
        let down = Arc::new(AtomicU64::new(0));
        let start_epoch_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis())
            .unwrap_or(0);
        let mut g = self.inner.lock().unwrap();
        let id = g.next_id;
        g.next_id += 1;
        g.flows.insert(
            id,
            FlowEntry {
                host: host.to_string(),
                port,
                proto,
                start_epoch_ms,
                up: up.clone(),
                down: down.clone(),
            },
        );
        FlowGuard {
            registry: Some(self.clone()),
            id,
            up,
            down,
        }
    }

    /// A snapshot of every currently-open flow, oldest-open first (ascending id). Reads each flow's
    /// live byte counters — a value climbing between two snapshots is a transfer in progress.
    pub(crate) fn snapshot(&self) -> Vec<FlowSnapshot> {
        let g = self.inner.lock().unwrap();
        g.flows
            .values()
            .map(|e| FlowSnapshot {
                host: e.host.clone(),
                port: e.port,
                proto: e.proto,
                start_epoch_ms: e.start_epoch_ms,
                up: e.up.load(Ordering::Relaxed),
                down: e.down.load(Ordering::Relaxed),
            })
            .collect()
    }
}

/// Serve the control socket: one short-lived thread per connection, each handling exactly one
/// command. A per-connection error is that connection's problem, never the server's. The pending
/// queue, the manual-rule overlay, and the event log are shared in (the same ones the proxy holds).
pub(crate) fn serve(
    listener: UnixListener,
    state: Arc<PendingState>,
    manual: Arc<ManualRules>,
    log: Arc<LogRing>,
    flows: Arc<FlowRegistry>,
) -> io::Result<()> {
    for stream in listener.incoming() {
        let stream = stream?;
        let state = state.clone();
        let manual = manual.clone();
        let log = log.clone();
        let flows = flows.clone();
        std::thread::spawn(move || {
            let _ = handle(stream, &state, &manual, &log, &flows);
        });
    }
    Ok(())
}

/// The largest control command accepted. Most commands are short (`ALLOW <seq>`), but `REMEMBER
/// ALLOW|DENY <rule>` carries a full egress rule (a long regex or URL rule), so the bound matches the
/// reply bound rather than the terse-command size — still bounded so a confused or hostile peer
/// cannot make us buffer unboundedly. The peer is the owner-only, host-side control client.
const CMD_MAX: u64 = 8 * 1024;

/// The largest control *reply* accepted. Unlike a command, a reply carries the destination the agent
/// reached (`ok host=<h> …`), which for a URL rule can be far longer than `CMD_MAX` — bounding it at
/// `CMD_MAX` would truncate the host and, with `--save`, persist a wrong (agent-influenceable) rule.
/// Still bounded (a URL is not unbounded) so a hostile peer cannot make the reader buffer forever.
const REPLY_MAX: u64 = 8 * 1024;

/// Handle one control connection: read a single command line, dispatch it, write the response, and
/// close. The socket is owner-only and host-side, so the peer is trusted; the bound read and the
/// timeout are belt-and-braces against a stuck or malformed caller.
fn handle(
    stream: UnixStream,
    state: &PendingState,
    manual: &ManualRules,
    log: &LogRing,
    flows: &FlowRegistry,
) -> io::Result<()> {
    stream.set_read_timeout(Some(Duration::from_secs(10)))?;
    stream.set_write_timeout(Some(Duration::from_secs(10)))?;
    let mut reader = BufReader::new((&stream).take(CMD_MAX));
    let mut line = String::new();
    reader.read_line(&mut line)?;
    let response = dispatch(line.trim(), state, manual, log, flows);
    (&stream).write_all(response.as_bytes())?;
    (&stream).flush()
}

/// Map a control command to its response. `LIST` returns one `pending …` line per parked request
/// then `ok`; `ALLOW <seq>`/`DENY <seq>` answer every parked request to that request's destination
/// (its `host:port/path` — identical retries are one decision; a trailing `session` token also
/// remembers it as a manual rule), replying `ok host=<host> count=<n>` or `err not-found`;
/// `ALLOW *`/`DENY *`
/// drain *every* parked request, replying one `answered host=<host>` line each then `ok` (the
/// `session` token remembers each); `REMEMBER ALLOW|DENY <rule>` loads a proactive `--session` rule
/// into the overlay (`ok`, or `err bad-request` for an unclassifiable/absent rule), which the proxy
/// folds into its effective policy; `RULES` returns the session's manual rules
/// (`manual allow|deny <rule>` lines) then `ok`. `LOG` returns the recent egress events (a `dropped=`
/// line when a `--follow` cursor fell behind the ring, a `head=` cursor, then one `event …` line
/// each) then `ok`; `LOG after=<seq>` returns only events past that cursor. `path` is emitted last on
/// a `pending`/`event` line so a query string's `=` cannot be mistaken for a field separator (the
/// reader splits each token on its first `=`).
fn dispatch(
    cmd: &str,
    state: &PendingState,
    manual: &ManualRules,
    log: &LogRing,
    flows: &FlowRegistry,
) -> String {
    let mut parts = cmd.split_whitespace();
    match parts.next() {
        Some("LIST") => {
            let mut out = String::new();
            for row in state.list() {
                out.push_str(&format!(
                    "pending seq={} port={} waiting={} host={} path={}\n",
                    row.seq, row.port, row.waiting_secs, row.host, row.path
                ));
            }
            out.push_str("ok\n");
            out
        }
        Some(verb @ ("ALLOW" | "DENY")) => {
            let verdict = if verb == "ALLOW" {
                Verdict::Allow
            } else {
                Verdict::Deny
            };
            // The target is a seq, or `*` for every parked request (a bulk drain). A trailing
            // `session` token (after either) also remembers each decision as a live manual rule.
            let Some(target) = parts.next() else {
                return "err bad-request\n".to_string();
            };
            let remember = parts.next() == Some("session");
            if target == "*" {
                // Drain framing mirrors `LIST`: one `answered host=…` line per request, then `ok`.
                // An empty queue is a clean `ok` (nothing to answer is not an error).
                let mut out = String::new();
                for (host, port) in state.answer_all(verdict) {
                    if remember {
                        manual.remember(verdict, &host, port);
                    }
                    out.push_str(&format!("answered host={host}\n"));
                }
                out.push_str("ok\n");
                return out;
            }
            let Some(seq) = target.parse::<u64>().ok() else {
                return "err bad-request\n".to_string();
            };
            match state.answer_like(seq, verdict) {
                Some((host, port, count)) => {
                    if remember {
                        manual.remember(verdict, &host, port);
                    }
                    format!("ok host={host} count={count}\n")
                }
                None => "err not-found\n".to_string(),
            }
        }
        Some("REMEMBER") => {
            // `REMEMBER ALLOW|DENY <rule>` loads a proactive `--session` rule. The rule is the
            // remainder of the line taken **verbatim** (not whitespace-split): an egress rule can be a
            // `re:` regex carrying spaces. Re-validated here through the same classifier the config
            // resolver uses, so a malformed rule the CLI somehow let through cannot enter the overlay.
            let body = cmd["REMEMBER".len()..].trim_start();
            // `MUTE` is a log-suppression rule, not a verdict, so it routes to the mute overlay
            // rather than [`ManualRules::remember_rule`]; `ALLOW`/`DENY` stay verdict rules.
            enum Kind {
                Verdict(Verdict),
                Mute,
            }
            let (kind, rule_text) = if let Some(r) = body.strip_prefix("ALLOW ") {
                (Kind::Verdict(Verdict::Allow), r.trim())
            } else if let Some(r) = body.strip_prefix("DENY ") {
                (Kind::Verdict(Verdict::Deny), r.trim())
            } else if let Some(r) = body.strip_prefix("MUTE ") {
                (Kind::Mute, r.trim())
            } else {
                return "err bad-request\n".to_string();
            };
            match crate::allowlist::classify(rule_text) {
                Ok(rule) => {
                    match kind {
                        Kind::Verdict(v) => manual.remember_rule(v, rule),
                        Kind::Mute => manual.remember_mute(rule),
                    }
                    "ok\n".to_string()
                }
                Err(_) => "err bad-request\n".to_string(),
            }
        }
        Some("RULES") => {
            let (allow, deny) = manual.snapshot();
            let mut out = String::new();
            // The rule text is emitted after the `manual allow `/`manual deny `/`manual mute ` prefix;
            // the reader takes the whole remainder, so a rule carrying whitespace (a `re:` regex)
            // round-trips.
            for rule in allow {
                out.push_str(&format!("manual allow {rule}\n"));
            }
            for rule in deny {
                out.push_str(&format!("manual deny {rule}\n"));
            }
            for rule in manual.mute_snapshot() {
                out.push_str(&format!("manual mute {rule}\n"));
            }
            out.push_str("ok\n");
            out
        }
        Some("LOG") => {
            // An optional `after=<seq>` makes this a follow read (events past the cursor, with the
            // eviction gap reported); absent, it is a tail read of the whole retained window. An
            // optional `amended=<seq>` opts into retroactive status re-emission (a `--with-status`
            // follow); an old reader that omits it gets today's behavior (no re-emission).
            let mut after = None;
            let mut after_amend = None;
            let mut include_muted = false;
            for token in parts {
                if let Some(v) = token.strip_prefix("after=") {
                    after = v.parse().ok();
                } else if let Some(v) = token.strip_prefix("amended=") {
                    after_amend = v.parse().ok();
                } else if token == "all" {
                    // `ops net log --all` — fold the muted (`dontaudit`) ring into the view.
                    include_muted = true;
                }
            }
            let snapshot = log.snapshot(after, after_amend, include_muted);
            let mut out = String::new();
            if snapshot.dropped > 0 {
                out.push_str(&format!("dropped={}\n", snapshot.dropped));
            }
            out.push_str(&format!("head={}\n", snapshot.head));
            out.push_str(&format!("amended={}\n", snapshot.amend_head));
            for ev in &snapshot.events {
                out.push_str(&format_event_line(ev));
            }
            out.push_str("ok\n");
            out
        }
        Some("FLOWS") => {
            // The tunnels open right now (one `flow …` line each, then `ok`). `host` is emitted last
            // so the reader can split every other field on its first `=`; a host carries no space.
            let mut out = String::new();
            for f in flows.snapshot() {
                out.push_str(&format_flow_line(&f));
            }
            out.push_str("ok\n");
            out
        }
        _ => "err bad-request\n".to_string(),
    }
}

/// Format one open flow as a control-wire line, `host` last (the reader splits each token on its
/// first `=`; a host has no space and no `=`). A flow has no method/path — it is a live tunnel, not a
/// decided request.
fn format_flow_line(f: &FlowSnapshot) -> String {
    format!(
        "flow proto={} port={} start={} up={} down={} host={}\n",
        f.proto.as_str(),
        f.port,
        f.start_epoch_ms,
        f.up,
        f.down,
        f.host,
    )
}

/// Format one event as a control-wire line. Fields are `key=value` tokens split on their first `=`;
/// `method`/`path` are omitted when absent, and `path` is emitted **last** so a query string's `=`
/// round-trips (it is the only field that can carry one, and an HTTP request-target has no spaces).
fn format_event_line(ev: &LogEvent) -> String {
    let mut line = format!(
        "event seq={} at={} port={} verdict={} proto={} reason={}",
        ev.seq,
        ev.at_epoch_ms,
        ev.port,
        ev.verdict.as_str(),
        ev.proto.as_str(),
        ev.reason,
    );
    if let Some(status) = ev.status {
        line.push_str(&format!(" status={status}"));
    }
    // Emitted only for a muted event (so a default-view line is byte-unchanged); a reader that
    // requested `--all` uses it to tag the suppressed refusal.
    if ev.muted {
        line.push_str(" muted=1");
    }
    // Emitted only when known/non-default so an older reader ignores the unknown key and an older
    // persisted line (without them) parses back to `Unknown`/`None` — a forward/backward-compatible
    // extension of the line format.
    if ev.http_ver != HttpVer::Unknown {
        line.push_str(&format!(" ver={}", ev.http_ver.as_wire()));
    }
    if ev.rpc != RpcKind::None {
        line.push_str(&format!(" l7={}", ev.rpc.as_str()));
    }
    if let Some(method) = &ev.method {
        line.push_str(&format!(" method={method}"));
    }
    line.push_str(&format!(" host={}", ev.host));
    if let Some(path) = &ev.path {
        line.push_str(&format!(" path={path}"));
    }
    line.push('\n');
    line
}

// ── Client side (the `ops net pending` process) ───────────────────────────────────────────────

/// The egress control directory under the data dir, where the per-session control sockets live.
pub(crate) fn control_dir(data_dir: &Path) -> PathBuf {
    data_dir.join("egress")
}

/// The control socket path for a session pid.
pub(crate) fn control_socket(data_dir: &Path, pid: u32) -> PathBuf {
    control_dir(data_dir).join(format!("control-{pid}.sock"))
}

/// One reachable session's pending requests, for `ops net pending`.
pub(crate) struct SessionPending {
    pub(crate) pid: u32,
    pub(crate) rows: Vec<PendingRow>,
}

/// Format a pending id the user types and the notice prints: `<pid>.<seq>`.
pub(crate) fn format_id(pid: u32, seq: u64) -> String {
    format!("{pid}.{seq}")
}

/// Parse a `<pid>.<seq>` id back into its parts, or `None` if it is not that shape.
pub(crate) fn parse_id(id: &str) -> Option<(u32, u64)> {
    let (pid, seq) = id.split_once('.')?;
    Some((pid.parse().ok()?, seq.parse().ok()?))
}

/// Discover every reachable ask-mode session's pending requests: glob the control sockets, parse
/// each filename's pid, and query it. A socket whose session is gone (connect refused, or a stale
/// file from a crashed launch) is skipped — so a dead session never blocks the listing. Sessions
/// are returned ordered by pid for stable output.
pub(crate) fn list_all(data_dir: &Path) -> Vec<SessionPending> {
    let mut sessions = Vec::new();
    for pid in session_pids(data_dir) {
        if let Ok(rows) = query(&control_socket(data_dir, pid)) {
            sessions.push(SessionPending { pid, rows });
        }
    }
    sessions
}

/// The pids of every session that has a control socket present, sorted for stable output. A superset
/// of the still-live sessions: a stale socket from a crashed launch is included, but a connect to it
/// (a `query` or a [`drain_session`]) simply fails and the caller skips it. This is the authoritative
/// pid source (the socket glob), distinct from the session registry — a launch may have a control
/// socket before, or without, a registry record.
pub(crate) fn session_pids(data_dir: &Path) -> Vec<u32> {
    let Ok(entries) = std::fs::read_dir(control_dir(data_dir)) else {
        return Vec::new();
    };
    let mut pids: Vec<u32> = entries
        .flatten()
        .filter_map(|e| pid_from_socket(&e.file_name().to_string_lossy()))
        .collect();
    pids.sort_unstable();
    pids
}

/// Extract the pid from a `control-<pid>.sock` filename.
fn pid_from_socket(name: &str) -> Option<u32> {
    name.strip_prefix("control-")?
        .strip_suffix(".sock")?
        .parse()
        .ok()
}

/// Query one session's control socket for its pending rows (`LIST`).
fn query(socket: &Path) -> io::Result<Vec<PendingRow>> {
    let stream = UnixStream::connect(socket)?;
    stream.set_read_timeout(Some(Duration::from_secs(10)))?;
    stream.set_write_timeout(Some(Duration::from_secs(10)))?;
    (&stream).write_all(b"LIST\n")?;
    (&stream).flush()?;
    let mut rows = Vec::new();
    for line in BufReader::new(&stream).lines() {
        let line = line?;
        if line == "ok" {
            break;
        }
        if let Some(row) = parse_pending_line(&line) {
            rows.push(row);
        }
    }
    Ok(rows)
}

/// Parse one `pending seq=… port=… waiting=… host=… path=…` line into a row, or `None` if it is
/// not a well-formed pending line. Each token is split on its first `=`, so a `path` carrying a
/// query string's `=` round-trips (it is the last field).
fn parse_pending_line(line: &str) -> Option<PendingRow> {
    let mut seq = None;
    let mut port = None;
    let mut waiting = None;
    let mut host = None;
    let mut path = None;
    let mut tokens = line.split_whitespace();
    if tokens.next()? != "pending" {
        return None;
    }
    for token in tokens {
        let (key, value) = token.split_once('=')?;
        match key {
            "seq" => seq = value.parse().ok(),
            "port" => port = value.parse().ok(),
            "waiting" => waiting = value.parse().ok(),
            "host" => host = Some(value.to_string()),
            "path" => path = Some(value.to_string()),
            _ => {}
        }
    }
    Some(PendingRow {
        seq: seq?,
        host: host?,
        port: port?,
        path: path?,
        waiting_secs: waiting?,
    })
}

// The client half of the event log — the reader the `ops net logs` command connects through.

/// One reachable session's recent egress events, for `ops net logs`.
pub(crate) struct SessionLog {
    pub(crate) pid: u32,
    pub(crate) snapshot: LogSnapshot,
}

/// Query one session's control socket for its recent egress events (`LOG`, or `LOG after=<seq>` for a
/// follow read past a cursor). A session whose socket is gone (a dead/stale launch) fails the connect
/// and the caller skips it.
pub(crate) fn read_log(
    socket: &Path,
    after: Option<u64>,
    after_amend: Option<u64>,
    include_muted: bool,
) -> io::Result<LogSnapshot> {
    let stream = UnixStream::connect(socket)?;
    stream.set_read_timeout(Some(Duration::from_secs(10)))?;
    stream.set_write_timeout(Some(Duration::from_secs(10)))?;
    let mut cmd = String::from("LOG");
    if let Some(seq) = after {
        cmd.push_str(&format!(" after={seq}"));
    }
    // Only sent for a `--with-status` follow; an older session ignores the token (no re-emission).
    if let Some(a) = after_amend {
        cmd.push_str(&format!(" amended={a}"));
    }
    // `--all` — ask the session to fold its muted (`dontaudit`) ring in; an older session ignores
    // the token (it has no muted ring) and returns its normal view.
    if include_muted {
        cmd.push_str(" all");
    }
    cmd.push('\n');
    (&stream).write_all(cmd.as_bytes())?;
    (&stream).flush()?;
    let mut events = Vec::new();
    let mut dropped = 0;
    let mut head = 0;
    let mut amend_head = 0;
    for line in BufReader::new(&stream).lines() {
        let line = line?;
        if line == "ok" {
            break;
        }
        if let Some(v) = line.strip_prefix("dropped=") {
            dropped = v.parse().unwrap_or(0);
        } else if let Some(v) = line.strip_prefix("head=") {
            head = v.parse().unwrap_or(0);
        } else if let Some(v) = line.strip_prefix("amended=") {
            amend_head = v.parse().unwrap_or(0);
        } else if let Some(ev) = parse_event_line(&line) {
            events.push(ev);
        }
    }
    Ok(LogSnapshot {
        events,
        dropped,
        head,
        amend_head,
    })
}

/// Discover every reachable session's recent egress events: glob the control sockets, parse each
/// filename's pid, and query it (with an optional per-nothing tail read — a shared cursor makes no
/// sense across sessions, whose sequence spaces are independent). A dead/stale socket is skipped.
/// Sessions are returned ordered by pid for stable output.
pub(crate) fn log_all(data_dir: &Path, include_muted: bool) -> Vec<SessionLog> {
    let mut sessions = Vec::new();
    for pid in session_pids(data_dir) {
        if let Ok(snapshot) = read_log(&control_socket(data_dir, pid), None, None, include_muted) {
            sessions.push(SessionLog { pid, snapshot });
        }
    }
    sessions
}

/// One reachable session's currently-open flows, for `ops net live`.
pub(crate) struct SessionFlows {
    pub(crate) pid: u32,
    pub(crate) flows: Vec<FlowSnapshot>,
}

/// Query one session's control socket for the tunnels open right now (`FLOWS`). A session whose
/// socket is gone (a dead/stale launch) fails the connect and the caller skips it.
pub(crate) fn read_flows(socket: &Path) -> io::Result<Vec<FlowSnapshot>> {
    let stream = UnixStream::connect(socket)?;
    // A short timeout: `ops net live` polls every session sequentially on a ~1s redraw, so a single
    // stuck session must not freeze the whole frame for long (a dead one is skipped on the connect).
    stream.set_read_timeout(Some(Duration::from_secs(2)))?;
    stream.set_write_timeout(Some(Duration::from_secs(2)))?;
    (&stream).write_all(b"FLOWS\n")?;
    (&stream).flush()?;
    let mut flows = Vec::new();
    for line in BufReader::new(&stream).lines() {
        let line = line?;
        if line == "ok" {
            break;
        }
        if let Some(f) = parse_flow_line(&line) {
            flows.push(f);
        }
    }
    Ok(flows)
}

/// Discover every reachable session's open flows: glob the control sockets, parse each filename's
/// pid, and query it. A dead/stale socket is skipped. Sessions are returned ordered by pid for stable
/// output. An old session that predates the `FLOWS` verb replies `err bad-request`, which parses to no
/// flow lines — so it simply contributes an empty list rather than failing the whole listing.
pub(crate) fn flows_all(data_dir: &Path) -> Vec<SessionFlows> {
    let mut sessions = Vec::new();
    for pid in session_pids(data_dir) {
        if let Ok(flows) = read_flows(&control_socket(data_dir, pid)) {
            sessions.push(SessionFlows { pid, flows });
        }
    }
    sessions
}

/// Parse one `flow proto=… port=… start=… up=… down=… host=…` line into a snapshot, or `None` if it
/// is malformed. Each token is split on its first `=`; `host` is last (it carries no space or `=`).
fn parse_flow_line(line: &str) -> Option<FlowSnapshot> {
    let mut proto = Proto::Other;
    let mut port = None;
    let mut start = None;
    let mut up = 0u64;
    let mut down = 0u64;
    let mut host = None;
    let mut tokens = line.split_whitespace();
    if tokens.next()? != "flow" {
        return None;
    }
    for token in tokens {
        let (key, value) = token.split_once('=')?;
        match key {
            "proto" => proto = Proto::parse(value),
            "port" => port = value.parse().ok(),
            "start" => start = value.parse().ok(),
            "up" => up = value.parse().unwrap_or(0),
            "down" => down = value.parse().unwrap_or(0),
            "host" => host = Some(value.to_string()),
            _ => {}
        }
    }
    Some(FlowSnapshot {
        host: host?,
        port: port?,
        proto,
        start_epoch_ms: start?,
        up,
        down,
    })
}

/// Parse one `event seq=… at=… port=… verdict=… reason=… [method=…] host=… [path=…]` line into an
/// event, or `None` if it is malformed. Each token is split on its first `=`, so a `path` carrying a
/// query string's `=` round-trips (it is the last field).
fn parse_event_line(line: &str) -> Option<LogEvent> {
    let mut seq = None;
    let mut at = None;
    let mut port = None;
    let mut verdict = None;
    let mut reason = None;
    let mut method = None;
    let mut host = None;
    let mut path = None;
    let mut status = None;
    let mut muted = false;
    let mut proto = Proto::Other;
    let mut http_ver = HttpVer::Unknown;
    let mut rpc = RpcKind::None;
    let mut tokens = line.split_whitespace();
    if tokens.next()? != "event" {
        return None;
    }
    for token in tokens {
        let (key, value) = token.split_once('=')?;
        match key {
            "seq" => seq = value.parse().ok(),
            "at" => at = value.parse().ok(),
            "port" => port = value.parse().ok(),
            "verdict" => verdict = LogVerdict::parse(value),
            "proto" => proto = Proto::parse(value),
            "ver" => http_ver = HttpVer::parse(value),
            "l7" => rpc = RpcKind::parse(value),
            "reason" => reason = Some(value.to_string()),
            "method" => method = Some(value.to_string()),
            "host" => host = Some(value.to_string()),
            "path" => path = Some(value.to_string()),
            "status" => status = value.parse().ok(),
            "muted" => muted = value == "1",
            _ => {}
        }
    }
    Some(LogEvent {
        seq: seq?,
        at_epoch_ms: at?,
        host: host?,
        port: port?,
        method,
        path,
        verdict: verdict?,
        reason: reason?,
        proto,
        http_ver,
        rpc,
        muted,
        status,
        // Amend bookkeeping is server-side; a parsed (client-side) event never carries it.
        amend_seq: None,
    })
}

/// The outcome of answering a request over the control socket.
pub(crate) enum AnswerOutcome {
    /// The request was answered: the host it was for (for a `--save`) and how many parked requests to
    /// that destination the answer woke (identical retries collapse to one decision).
    Answered { host: String, count: usize },
    /// No such request is parked (already answered, timed out, or a wrong id).
    NotFound,
}

/// Parse a control `ALLOW`/`DENY` reply line into an outcome. `ok host=<h> count=<n>` is an answer;
/// `count` is **optional** (defaults to 1) so a freshly-built client degrades cleanly against an
/// older server that omits it — a long-lived session serves the wire protocol of the binary that
/// launched it, so new-client ↔ older-server skew is real before a release. Anything else (`err …`)
/// is [`AnswerOutcome::NotFound`].
fn parse_answer_reply(line: &str) -> AnswerOutcome {
    if let Some(rest) = line.strip_prefix("ok ") {
        let mut host = None;
        let mut count = 1usize;
        for token in rest.split_whitespace() {
            if let Some(h) = token.strip_prefix("host=") {
                host = Some(h.to_string());
            } else if let Some(c) = token.strip_prefix("count=") {
                count = c.parse().unwrap_or(1);
            }
        }
        if let Some(host) = host {
            return AnswerOutcome::Answered { host, count };
        }
    }
    AnswerOutcome::NotFound
}

/// Answer the parked request `<pid>.<seq>`: connect to that session's control socket and send the
/// verdict. With `remember`, a trailing `session` token also records the decision as a live manual
/// rule (so the same request is not re-asked this session). A missing socket / dead session surfaces
/// as a connect error; a live session that has no such request returns [`AnswerOutcome::NotFound`].
pub(crate) fn answer_request(
    data_dir: &Path,
    pid: u32,
    seq: u64,
    verdict: Verdict,
    remember: bool,
) -> io::Result<AnswerOutcome> {
    let stream = UnixStream::connect(control_socket(data_dir, pid))?;
    stream.set_read_timeout(Some(Duration::from_secs(10)))?;
    stream.set_write_timeout(Some(Duration::from_secs(10)))?;
    let verb = match verdict {
        Verdict::Allow => "ALLOW",
        Verdict::Deny => "DENY",
    };
    let cmd = if remember {
        format!("{verb} {seq} session\n")
    } else {
        format!("{verb} {seq}\n")
    };
    (&stream).write_all(cmd.as_bytes())?;
    (&stream).flush()?;
    let mut response = String::new();
    let n = BufReader::new((&stream).take(REPLY_MAX)).read_line(&mut response)?;
    // If the reply filled the bound with no terminating newline it was truncated — refuse to parse a
    // partial host (which `--save` would persist as a wrong rule) and report it as not answered.
    if n as u64 >= REPLY_MAX && !response.ends_with('\n') {
        return Ok(AnswerOutcome::NotFound);
    }
    Ok(parse_answer_reply(response.trim()))
}

/// The outcome of a bulk drain (`ALLOW *`/`DENY *`) of one session.
pub(crate) enum DrainOutcome {
    /// The session drained: the hosts it answered, oldest first. An empty vec means the session was
    /// healthy but had nothing parked.
    Drained(Vec<String>),
    /// The session's control server did not understand the bulk-drain command (it replied `err …`) —
    /// it was launched by an `ops` predating `--all`. Its requests are still parked; only relaunching
    /// the agent with the current binary lets `--all` reach them. (Answering by id is *not* a fallback:
    /// destination-grouping is server-side, so an old server's `ALLOW <seq>` wakes one connection of
    /// the group, leaving the retries parked.)
    Unsupported,
}

/// Drain *every* parked request in one session (`ALLOW *`/`DENY *`): connect, send the bulk verdict,
/// and collect the hosts it answered (oldest first). With `remember`, the trailing `session` token
/// also records each as a live manual rule. An empty queue is `Drained(vec![])`; a control server too
/// old to know `ALLOW *` (it replies `err …`) is `Unsupported` — distinct from a clean empty drain,
/// so the caller can tell "nothing parked" from "this session predates --all". A connect error (the
/// session is gone, or a stale socket) propagates so the caller skips that session.
pub(crate) fn drain_session(
    data_dir: &Path,
    pid: u32,
    verdict: Verdict,
    remember: bool,
) -> io::Result<DrainOutcome> {
    let stream = UnixStream::connect(control_socket(data_dir, pid))?;
    stream.set_read_timeout(Some(Duration::from_secs(10)))?;
    stream.set_write_timeout(Some(Duration::from_secs(10)))?;
    let verb = match verdict {
        Verdict::Allow => "ALLOW",
        Verdict::Deny => "DENY",
    };
    let cmd = if remember {
        format!("{verb} * session\n")
    } else {
        format!("{verb} *\n")
    };
    (&stream).write_all(cmd.as_bytes())?;
    (&stream).flush()?;
    let mut hosts = Vec::new();
    for line in BufReader::new(&stream).lines() {
        let line = line?;
        if line == "ok" {
            return Ok(DrainOutcome::Drained(hosts));
        }
        if let Some(host) = line.strip_prefix("answered host=") {
            hosts.push(host.to_string());
        } else if line.starts_with("err ") {
            // A current server never answers a bulk drain with `err` — so any `err` line is an older
            // server that does not understand `ALLOW *`/`DENY *`.
            return Ok(DrainOutcome::Unsupported);
        }
    }
    // EOF without a terminating `ok` (defensive — a current server always closes with `ok`): report
    // what we collected rather than inventing an error.
    Ok(DrainOutcome::Drained(hosts))
}

/// The kind of a manual (`--session`) rule reported by a live session: a verdict rule (allow/deny)
/// or a mute (`dontaudit`) log-suppression rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ManualKind {
    Allow,
    Deny,
    Mute,
}

/// One manual rule reported by a live session: its kind and its display text.
pub(crate) struct ManualRuleRow {
    pub(crate) kind: ManualKind,
    pub(crate) rule: String,
}

/// The outcome of loading a proactive `--session` rule into one session's overlay.
pub(crate) enum InjectOutcome {
    /// The rule was loaded into the live overlay — the proxy folds it into its effective policy, so
    /// it decides the matching request from now on.
    Loaded,
    /// The server refused it (a rule it could not classify, or a control server too old to know
    /// `REMEMBER`) — reported so the caller does not present it as loaded.
    Refused,
}

/// Load a proactive egress `rule` into one session's live manual overlay (`REMEMBER ALLOW|DENY
/// <rule>`) — the `ops net allow|deny <rule> --session` path. A connect error (the session is gone,
/// or a stale socket) propagates so the caller skips that session.
pub(crate) fn inject_rule(
    data_dir: &Path,
    pid: u32,
    verdict: Verdict,
    rule: &str,
) -> io::Result<InjectOutcome> {
    let verb = match verdict {
        Verdict::Allow => "ALLOW",
        Verdict::Deny => "DENY",
    };
    send_remember(data_dir, pid, verb, rule)
}

/// Load a proactive **mute** (`dontaudit`) `rule` into one session's live overlay — the
/// `ops net mute <rule> --session` path. A denied request matching it has its log line suppressed
/// for this session; the verdict and the `ops net stats` count are untouched. Same wire shape as
/// [`inject_rule`], with the `MUTE` verb.
pub(crate) fn inject_mute(data_dir: &Path, pid: u32, rule: &str) -> io::Result<InjectOutcome> {
    send_remember(data_dir, pid, "MUTE", rule)
}

/// Send one `REMEMBER <verb> <rule>` to a session's control socket and read its one-line reply.
/// Shared by [`inject_rule`] (ALLOW/DENY) and [`inject_mute`] (MUTE) so the connection handling and
/// the reply parsing cannot drift.
fn send_remember(data_dir: &Path, pid: u32, verb: &str, rule: &str) -> io::Result<InjectOutcome> {
    let stream = UnixStream::connect(control_socket(data_dir, pid))?;
    stream.set_read_timeout(Some(Duration::from_secs(10)))?;
    stream.set_write_timeout(Some(Duration::from_secs(10)))?;
    (&stream).write_all(format!("REMEMBER {verb} {rule}\n").as_bytes())?;
    (&stream).flush()?;
    let mut response = String::new();
    BufReader::new((&stream).take(REPLY_MAX)).read_line(&mut response)?;
    Ok(match response.trim() {
        "ok" => InjectOutcome::Loaded,
        _ => InjectOutcome::Refused,
    })
}

/// Query a session's live manual rules (`RULES`) — the runtime rules added by `--session` answers.
/// A connect error (the session is gone) propagates so the caller can skip it.
pub(crate) fn query_manual(data_dir: &Path, pid: u32) -> io::Result<Vec<ManualRuleRow>> {
    let stream = UnixStream::connect(control_socket(data_dir, pid))?;
    stream.set_read_timeout(Some(Duration::from_secs(10)))?;
    stream.set_write_timeout(Some(Duration::from_secs(10)))?;
    (&stream).write_all(b"RULES\n")?;
    (&stream).flush()?;
    let mut rules = Vec::new();
    for line in BufReader::new(&stream).lines() {
        let line = line?;
        if line == "ok" {
            break;
        }
        // The rule text is everything after the kind prefix — taken as the whole remainder, so a
        // rule carrying whitespace (a `re:` regex loaded with `--session`) round-trips intact.
        if let Some(rule) = line.strip_prefix("manual allow ") {
            rules.push(ManualRuleRow {
                kind: ManualKind::Allow,
                rule: rule.to_string(),
            });
        } else if let Some(rule) = line.strip_prefix("manual deny ") {
            rules.push(ManualRuleRow {
                kind: ManualKind::Deny,
                rule: rule.to_string(),
            });
        } else if let Some(rule) = line.strip_prefix("manual mute ") {
            rules.push(ManualRuleRow {
                kind: ManualKind::Mute,
                rule: rule.to_string(),
            });
        }
    }
    Ok(rules)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;

    #[test]
    fn park_returns_the_answered_verdict() {
        let state = Arc::new(PendingState::new());
        let s = state.clone();
        // Park in a thread; the main thread answers it.
        let handle =
            thread::spawn(move || s.park("api.example.com", 443, "/v1/x", None, 256, |_| {}));
        // Wait for the request to appear, then allow it.
        let seq = wait_for_one(&state);
        assert_eq!(
            state.answer_like(seq, Verdict::Allow),
            Some(("api.example.com".to_string(), 443, 1))
        );
        assert_eq!(handle.join().unwrap(), Verdict::Allow);
        // The queue is drained.
        assert!(state.list().is_empty());
    }

    #[test]
    fn park_returns_deny_when_denied() {
        let state = Arc::new(PendingState::new());
        let s = state.clone();
        let handle = thread::spawn(move || s.park("evil.test", 443, "/", None, 256, |_| {}));
        let seq = wait_for_one(&state);
        assert_eq!(
            state.answer_like(seq, Verdict::Deny),
            Some(("evil.test".to_string(), 443, 1))
        );
        assert_eq!(handle.join().unwrap(), Verdict::Deny);
    }

    #[test]
    fn park_times_out_to_deny() {
        let state = PendingState::new();
        // A tiny timeout with no answer → deny, and the entry is cleaned up.
        let verdict = state.park(
            "slow.test",
            443,
            "/",
            Some(Duration::from_millis(30)),
            256,
            |_| {},
        );
        assert_eq!(verdict, Verdict::Deny);
        assert!(state.list().is_empty(), "a timed-out entry is removed");
    }

    #[test]
    fn the_flood_cap_denies_without_enqueuing() {
        let state = Arc::new(PendingState::new());
        // Fill the queue to a cap of 1 with one indefinitely-parked request.
        let s = state.clone();
        let parked = thread::spawn(move || s.park("first.test", 443, "/", None, 1, |_| {}));
        wait_for_one(&state);
        // A second park at cap 1 is denied immediately, never enqueued.
        let verdict = state.park("second.test", 443, "/", None, 1, |_| {});
        assert_eq!(verdict, Verdict::Deny);
        assert_eq!(
            state.list().len(),
            1,
            "the flooding request was not enqueued"
        );
        // Release the first so the thread joins.
        let seq = state.list()[0].seq;
        state.answer_like(seq, Verdict::Allow);
        assert_eq!(parked.join().unwrap(), Verdict::Allow);
    }

    #[test]
    fn answer_an_unknown_seq_is_none() {
        let state = PendingState::new();
        assert_eq!(state.answer_like(999, Verdict::Allow), None);
    }

    #[test]
    fn answer_like_wakes_the_whole_destination_and_leaves_others_parked() {
        let state = Arc::new(PendingState::new());
        // Two identical retries of one URL (same host:port/path) plus a different destination,
        // parked one at a time so the seqs are 1, 2, 3 in this order.
        let a1 = park_next(&state, "dl.test", 443, 0);
        let a2 = park_next(&state, "dl.test", 443, 1);
        let other = park_next(&state, "logs.test", 443, 2);

        // Answering the representative (seq 1) wakes BOTH dl.test retries and reports the count.
        assert_eq!(
            state.answer_like(1, Verdict::Allow),
            Some(("dl.test".to_string(), 443, 2))
        );
        assert_eq!(a1.join().unwrap(), Verdict::Allow);
        assert_eq!(a2.join().unwrap(), Verdict::Allow);

        // The different destination stays parked — this is destination-grained, not the `--all` drain.
        let still = state.list();
        assert_eq!(
            still.len(),
            1,
            "the other destination is untouched: {still:?}"
        );
        assert_eq!(still[0].host, "logs.test");

        state.answer_like(still[0].seq, Verdict::Deny);
        assert_eq!(other.join().unwrap(), Verdict::Deny);
    }

    #[test]
    fn parse_answer_reply_reads_count_and_tolerates_its_absence() {
        match parse_answer_reply("ok host=api.test count=9") {
            AnswerOutcome::Answered { host, count } => {
                assert_eq!(host, "api.test");
                assert_eq!(count, 9);
            }
            AnswerOutcome::NotFound => panic!("a well-formed ok must answer"),
        }
        // An older server omits `count` → defaults to 1 (new-client ↔ older-server version skew).
        match parse_answer_reply("ok host=api.test") {
            AnswerOutcome::Answered { host, count } => {
                assert_eq!(host, "api.test");
                assert_eq!(count, 1);
            }
            AnswerOutcome::NotFound => panic!("a countless ok must still answer"),
        }
        assert!(matches!(
            parse_answer_reply("err not-found"),
            AnswerOutcome::NotFound
        ));
    }

    #[test]
    fn manual_rules_store_remembered_and_proactive_rules_deduped() {
        // The overlay is a rule store; the proxy folds `snapshot()` into its effective policy, so the
        // *decision* semantics (deny-wins, allow-opens, SSRF breadth) are proven there. Here we pin
        // only the store contract: an ask answer records an exact host:port, a `--session` load
        // records an arbitrary rule, each in the right list, deduped, and `is_empty` tracks it.
        let m = ManualRules::new();
        assert!(m.is_empty());

        // An ask answer records the exact host:port on the right list.
        m.remember(Verdict::Allow, "api.test", 8080);
        assert!(!m.is_empty());
        assert_eq!(
            m.snapshot().0,
            vec![crate::allowlist::host_port_rule("api.test", 8080)]
        );

        // A proactive `--session` load records an arbitrary (wildcard) rule.
        let wildcard = crate::allowlist::classify("*.internal.test").unwrap();
        m.remember_rule(Verdict::Allow, wildcard.clone());
        let (allow, deny) = m.snapshot();
        assert!(allow.contains(&wildcard) && deny.is_empty());

        // A deny goes on the deny list.
        m.remember_rule(
            Verdict::Deny,
            crate::allowlist::classify("bad.internal.test").unwrap(),
        );
        assert_eq!(m.snapshot().1.len(), 1);

        // Dedup: re-loading the same rule does not stack.
        m.remember(Verdict::Allow, "api.test", 8080);
        m.remember_rule(Verdict::Allow, wildcard);
        assert_eq!(
            m.snapshot().0.len(),
            2,
            "a re-loaded rule is not duplicated"
        );
    }

    #[test]
    fn dispatch_remembers_only_on_the_session_token() {
        let state = Arc::new(PendingState::new());
        let manual = Arc::new(ManualRules::new());
        let log = LogRing::new(LOG_RING_CAP);
        let flows = FlowRegistry::new();

        // A bare ALLOW answers but does not remember.
        let s = state.clone();
        let parked = thread::spawn(move || s.park("api.test", 8080, "/", None, 256, |_| {}));
        let seq = wait_for_one(&state);
        assert_eq!(
            dispatch(&format!("ALLOW {seq}"), &state, &manual, &log, &flows),
            "ok host=api.test count=1\n"
        );
        assert_eq!(parked.join().unwrap(), Verdict::Allow);
        assert!(
            manual.snapshot().0.is_empty(),
            "a bare ALLOW must not remember"
        );

        // `ALLOW <seq> session` answers AND remembers the exact host:port.
        let s = state.clone();
        let parked = thread::spawn(move || s.park("api.test", 8080, "/", None, 256, |_| {}));
        let seq = wait_for_one(&state);
        let _ = dispatch(
            &format!("ALLOW {seq} session"),
            &state,
            &manual,
            &log,
            &flows,
        );
        parked.join().unwrap();
        assert_eq!(manual.snapshot().0.len(), 1, "`… session` must remember");
        // And `RULES` reports the remembered rule with its exact port.
        assert!(
            dispatch("RULES", &state, &manual, &log, &flows)
                .contains("manual allow https://api.test:8080"),
            "RULES must list the remembered host:port"
        );
    }

    #[test]
    fn dispatch_remember_loads_a_rule_into_the_overlay() {
        let state = Arc::new(PendingState::new());
        let manual = Arc::new(ManualRules::new());
        let log = LogRing::new(LOG_RING_CAP);
        let flows = FlowRegistry::new();

        // `REMEMBER ALLOW <rule>` loads an arbitrary (here wildcard) rule into the overlay and
        // `RULES` reports it — the proactive `--session` path. It is accepted in any posture (the
        // proxy folds the overlay into its effective policy for every filtering posture).
        assert_eq!(
            dispatch("REMEMBER ALLOW *.foo.test", &state, &manual, &log, &flows),
            "ok\n"
        );
        assert!(
            dispatch("RULES", &state, &manual, &log, &flows)
                .contains("manual allow https://*.foo.test"),
            "REMEMBER must load the rule"
        );

        // A malformed rule (a `*` catch-all) and a missing kind/rule are `err bad-request`.
        assert_eq!(
            dispatch("REMEMBER ALLOW *", &state, &manual, &log, &flows),
            "err bad-request\n"
        );
        assert_eq!(
            dispatch("REMEMBER ALLOW", &state, &manual, &log, &flows),
            "err bad-request\n"
        );

        // `REMEMBER MUTE <rule>` loads into the dedicated mute overlay (a log filter, not a verdict),
        // so it lands in `mute_snapshot`, never the allow/deny verdict lists.
        assert_eq!(
            dispatch(
                "REMEMBER MUTE play.googleapis.com",
                &state,
                &manual,
                &log,
                &flows
            ),
            "ok\n"
        );
        let (allow, deny) = manual.snapshot();
        assert!(
            allow
                .iter()
                .all(|r| r.to_string() != "https://play.googleapis.com")
                && deny.is_empty(),
            "a MUTE must not enter the verdict lists"
        );
        assert_eq!(
            manual.mute_snapshot().len(),
            1,
            "a MUTE lands in the mute overlay"
        );
        assert!(
            !manual.is_empty(),
            "a loaded mute makes the overlay non-empty"
        );
        // …and `RULES` reports it as a `manual mute` line, so `ops net rules --source session` lists
        // a live mute (distinct from the allow/deny lines).
        assert!(
            dispatch("RULES", &state, &manual, &log, &flows)
                .contains("manual mute https://play.googleapis.com"),
            "RULES must list a live mute"
        );
    }

    #[test]
    fn flow_registry_registers_counts_and_deregisters() {
        let reg = Arc::new(FlowRegistry::new());
        assert!(reg.snapshot().is_empty(), "a fresh registry has no flows");

        let g1 = reg.register("api.test", 443, Proto::Https);
        let g2 = reg.register("db.test", 5432, Proto::Tcp);
        let snap = reg.snapshot();
        assert_eq!(snap.len(), 2, "two open tunnels are visible");
        // Oldest-open first (ascending id).
        assert_eq!(snap[0].host, "api.test");
        assert_eq!(snap[0].port, 443);
        assert_eq!(snap[0].proto, Proto::Https);
        assert_eq!((snap[0].up, snap[0].down), (0, 0), "counters start at zero");
        assert_eq!(snap[1].host, "db.test");
        assert_eq!(snap[1].proto, Proto::Tcp);

        // The snapshot reads the live shared atomics the relay's counting wrappers bump.
        g1.up.fetch_add(1024, Ordering::Relaxed);
        g1.down.fetch_add(2048, Ordering::Relaxed);
        let snap = reg.snapshot();
        assert_eq!((snap[0].up, snap[0].down), (1024, 2048));

        drop(g1);
        let snap = reg.snapshot();
        assert_eq!(snap.len(), 1, "a closed tunnel drops off the view");
        assert_eq!(snap[0].host, "db.test");
        drop(g2);
        assert!(
            reg.snapshot().is_empty(),
            "no flow remains once every guard is dropped"
        );
    }

    #[test]
    fn detached_flow_guard_counts_but_registers_nothing() {
        // A detached guard (no registry) still carries usable counters, and dropping it is a no-op —
        // the relay counts uniformly whether or not a registry is attached (tests).
        let g = FlowGuard::detached();
        g.up.fetch_add(10, Ordering::Relaxed);
        assert_eq!(g.up.load(Ordering::Relaxed), 10);
        drop(g); // must not panic: there is no registry to touch
    }

    #[test]
    fn flows_verb_lists_open_tunnels_and_round_trips() {
        // `FLOWS` returns one `flow …` line per open tunnel then `ok`, and the client parser reads each
        // back — the server format and the client parser agree (not just by inspection).
        let state = Arc::new(PendingState::new());
        let manual = Arc::new(ManualRules::new());
        let log = LogRing::new(LOG_RING_CAP);
        let flows = Arc::new(FlowRegistry::new());

        let g = flows.register("api.test", 8443, Proto::Https);
        g.up.fetch_add(100, Ordering::Relaxed);
        g.down.fetch_add(200, Ordering::Relaxed);

        let resp = dispatch("FLOWS", &state, &manual, &log, &flows);
        assert!(resp.ends_with("ok\n"), "the reply ends with ok: {resp:?}");
        let parsed: Vec<FlowSnapshot> = resp.lines().filter_map(parse_flow_line).collect();
        assert_eq!(parsed.len(), 1, "one open flow is listed");
        let f = &parsed[0];
        assert_eq!(f.host, "api.test");
        assert_eq!(f.port, 8443);
        assert_eq!(f.proto, Proto::Https);
        assert_eq!((f.up, f.down), (100, 200));

        // An empty registry lists no flow, just `ok`.
        drop(g);
        assert_eq!(dispatch("FLOWS", &state, &manual, &log, &flows), "ok\n");
    }

    #[test]
    fn format_and_parse_flow_line_round_trip() {
        let f = FlowSnapshot {
            host: "example.test".into(),
            port: 443,
            proto: Proto::Tcp,
            start_epoch_ms: 1_700_000_000_000,
            up: 4096,
            down: 8192,
        };
        let line = format_flow_line(&f);
        let back = parse_flow_line(line.trim()).expect("a well-formed flow line parses");
        assert_eq!(back, f);
    }

    #[test]
    fn inject_rule_round_trips_over_the_control_socket() {
        // The proactive-`--session` integration seam: `inject_rule` (client) against a real `serve`
        // (server) over a bound socket, so the `REMEMBER` wire format is exercised end to end.
        use crate::testutil::TmpDir;
        let data = TmpDir::new();
        std::fs::create_dir_all(control_dir(data.path())).unwrap();
        let pid = 24680u32;
        let sock = control_socket(data.path(), pid);
        let listener = UnixListener::bind(&sock).unwrap();
        let pending = Arc::new(PendingState::new());
        let manual = Arc::new(ManualRules::new());
        let log = Arc::new(LogRing::new(LOG_RING_CAP));
        let served_manual = manual.clone();
        let flows = Arc::new(FlowRegistry::new());
        thread::spawn(move || {
            let _ = serve(listener, pending, served_manual, log, flows);
        });

        // A loaded rule reports `Loaded` and lands in the overlay the proxy folds into its policy.
        assert!(matches!(
            inject_rule(data.path(), pid, Verdict::Allow, "*.svc.test").unwrap(),
            InjectOutcome::Loaded
        ));
        let (allow, _) = manual.snapshot();
        assert_eq!(
            allow,
            vec![crate::allowlist::classify("*.svc.test").unwrap()]
        );
    }

    #[test]
    fn the_control_socket_round_trips_answer_and_rules() {
        // The integration seam: drive the client functions (`answer_request`, `query_manual`)
        // against a real `serve` over a bound socket, so the server's wire format and the client's
        // parser are exercised *together* — not just agreeing by inspection.
        use crate::testutil::TmpDir;
        let data = TmpDir::new();
        std::fs::create_dir_all(control_dir(data.path())).unwrap();
        let pid = 12345u32; // a stand-in session pid; the socket path is keyed by it
        let socket = control_socket(data.path(), pid);

        let pending = Arc::new(PendingState::new());
        let manual = Arc::new(ManualRules::new());
        let log = Arc::new(LogRing::new(LOG_RING_CAP));
        let flows = Arc::new(FlowRegistry::new());
        let listener = UnixListener::bind(&socket).unwrap();
        {
            let pending = pending.clone();
            let manual = manual.clone();
            let log = log.clone();
            let flows = flows.clone();
            thread::spawn(move || {
                let _ = serve(listener, pending, manual, log, flows);
            });
        }

        // Park one request (a non-standard port — the granularity that must survive the round-trip).
        let p = pending.clone();
        let parked = thread::spawn(move || p.park("api.test", 8080, "/x", None, 256, |_| {}));
        let seq = wait_for_one(&pending);

        // Answer it ALLOW with `--session` (remember) over the real socket.
        match answer_request(data.path(), pid, seq, Verdict::Allow, true).unwrap() {
            AnswerOutcome::Answered { host, count } => {
                assert_eq!(host, "api.test");
                assert_eq!(count, 1);
            }
            AnswerOutcome::NotFound => panic!("the live request must be answered"),
        }
        assert_eq!(parked.join().unwrap(), Verdict::Allow);

        // The remembered rule round-trips back through RULES with its exact host:port.
        let rules = query_manual(data.path(), pid).unwrap();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].kind, ManualKind::Allow);
        assert_eq!(rules[0].rule, "https://api.test:8080");

        // The consumed seq is now gone — a second answer is NotFound (not a phantom success).
        match answer_request(data.path(), pid, seq, Verdict::Allow, false).unwrap() {
            AnswerOutcome::NotFound => {}
            AnswerOutcome::Answered { .. } => panic!("an already-answered seq must be NotFound"),
        }
    }

    #[test]
    fn on_enqueue_sees_the_assigned_id() {
        let state = Arc::new(PendingState::new());
        let s = state.clone();
        let (tx, rx) = mpsc::channel();
        let handle = thread::spawn(move || {
            s.park(
                "h.test",
                443,
                "/",
                Some(Duration::from_millis(50)),
                256,
                |seq| {
                    tx.send(seq).unwrap();
                },
            )
        });
        // The id handed to on_enqueue is the one the queue assigned.
        let seq = rx.recv().unwrap();
        assert_eq!(seq, 1, "the first parked request gets seq 1");
        let _ = handle.join();
    }

    #[test]
    fn parse_pending_line_round_trips_a_query_path() {
        let row = parse_pending_line(
            "pending seq=3 port=443 waiting=12 host=api.example.com path=/v1?a=b&c=d",
        )
        .unwrap();
        assert_eq!(row.seq, 3);
        assert_eq!(row.port, 443);
        assert_eq!(row.waiting_secs, 12);
        assert_eq!(row.host, "api.example.com");
        // the query string's `=` is preserved (path is the last field, split on the first `=`)
        assert_eq!(row.path, "/v1?a=b&c=d");
    }

    #[test]
    fn parse_id_and_format_id_round_trip() {
        assert_eq!(format_id(12345, 7), "12345.7");
        assert_eq!(parse_id("12345.7"), Some((12345, 7)));
        assert_eq!(parse_id("nope"), None);
        assert_eq!(parse_id("12345"), None);
        assert_eq!(parse_id("12345.x"), None);
    }

    #[test]
    fn pid_from_socket_parses_the_filename() {
        assert_eq!(pid_from_socket("control-4321.sock"), Some(4321));
        assert_eq!(pid_from_socket("proxy-4321.sock"), None);
        assert_eq!(pid_from_socket("control-.sock"), None);
    }

    /// Block briefly until exactly one request is parked, returning its seq — so a test can answer a
    /// request a sibling thread just parked without racing the enqueue.
    fn wait_for_one(state: &PendingState) -> u64 {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let rows = state.list();
            if let Some(row) = rows.first() {
                return row.seq;
            }
            assert!(Instant::now() < deadline, "no request was parked");
            thread::sleep(Duration::from_millis(5));
        }
    }

    /// Block until at least `n` requests are parked (used by the bulk-drain tests).
    fn wait_for_n(state: &PendingState, n: usize) {
        let deadline = Instant::now() + Duration::from_secs(5);
        while state.list().len() < n {
            assert!(Instant::now() < deadline, "fewer than {n} requests parked");
            thread::sleep(Duration::from_millis(5));
        }
    }

    /// Spawn one parked request and block until it is enqueued (its seq assigned). Parking one at a
    /// time makes the per-host seq order deterministic — each `park` grabs the lock and increments
    /// the counter before the next is spawned — so a test can assert the oldest-first drain order.
    fn park_next(
        state: &Arc<PendingState>,
        host: &'static str,
        port: u16,
        already: usize,
    ) -> thread::JoinHandle<Verdict> {
        let s = state.clone();
        let handle = thread::spawn(move || s.park(host, port, "/", None, 256, |_| {}));
        wait_for_n(state, already + 1);
        handle
    }

    #[test]
    fn answer_all_drains_every_parked_request_oldest_first() {
        let state = Arc::new(PendingState::new());
        // Park three requests one at a time, so their seqs are 1,2,3 in this order.
        let parked: Vec<_> = ["a.test", "b.test", "c.test"]
            .iter()
            .enumerate()
            .map(|(i, host)| park_next(&state, host, 443, i))
            .collect();

        // One drain answers all three, oldest id first (so the parking order is preserved).
        let answered = state.answer_all(Verdict::Allow);
        assert_eq!(
            answered,
            vec![
                ("a.test".to_string(), 443),
                ("b.test".to_string(), 443),
                ("c.test".to_string(), 443),
            ]
        );
        for p in parked {
            assert_eq!(p.join().unwrap(), Verdict::Allow);
        }
        assert!(state.list().is_empty(), "the queue is fully drained");
        // A second drain on the empty queue answers nothing (clean, not an error).
        assert!(state.answer_all(Verdict::Deny).is_empty());
    }

    #[test]
    fn dispatch_star_drains_all_and_remembers_only_with_session() {
        let state = Arc::new(PendingState::new());
        let manual = Arc::new(ManualRules::new());
        let log = LogRing::new(LOG_RING_CAP);
        let flows = FlowRegistry::new();

        // A bare `DENY *` drains every request but remembers nothing. Parked one at a time so the
        // response lines come back in a deterministic oldest-first order.
        let _ = park_next(&state, "x.test", 8080, 0);
        let _ = park_next(&state, "y.test", 8080, 1);
        let response = dispatch("DENY *", &state, &manual, &log, &flows);
        assert_eq!(response, "answered host=x.test\nanswered host=y.test\nok\n");
        assert!(
            manual.snapshot().1.is_empty(),
            "a bare `DENY *` must not remember"
        );

        // `ALLOW * session` drains and remembers each host:port as a manual rule.
        let _ = park_next(&state, "p.test", 8080, 0);
        let _ = park_next(&state, "q.test", 8080, 1);
        let _ = dispatch("ALLOW * session", &state, &manual, &log, &flows);
        let (allow, _) = manual.snapshot();
        assert_eq!(allow.len(), 2, "`* session` remembers each answered host");

        // An empty queue replies a clean `ok` with no `answered` lines.
        assert_eq!(dispatch("ALLOW *", &state, &manual, &log, &flows), "ok\n");
    }

    #[test]
    fn drain_session_round_trips_over_the_socket() {
        // The integration seam for the bulk drain: the client `drain_session` against a real `serve`.
        use crate::testutil::TmpDir;
        let data = TmpDir::new();
        std::fs::create_dir_all(control_dir(data.path())).unwrap();
        let pid = 22222u32;
        let socket = control_socket(data.path(), pid);

        let pending = Arc::new(PendingState::new());
        let manual = Arc::new(ManualRules::new());
        let log = Arc::new(LogRing::new(LOG_RING_CAP));
        let flows = Arc::new(FlowRegistry::new());
        let listener = UnixListener::bind(&socket).unwrap();
        {
            let pending = pending.clone();
            let manual = manual.clone();
            let log = log.clone();
            let flows = flows.clone();
            thread::spawn(move || {
                let _ = serve(listener, pending, manual, log, flows);
            });
        }

        // Parked one at a time so the drained order is deterministic (seqs 1 then 2).
        let parked = vec![
            park_next(&pending, "one.test", 8080, 0),
            park_next(&pending, "two.test", 8080, 1),
        ];

        // Drain ALLOW with `--session` (remember) over the real socket.
        match drain_session(data.path(), pid, Verdict::Allow, true).unwrap() {
            DrainOutcome::Drained(hosts) => {
                assert_eq!(hosts, vec!["one.test".to_string(), "two.test".to_string()])
            }
            DrainOutcome::Unsupported => {
                panic!("a current server must drain, not report unsupported")
            }
        }
        for p in parked {
            assert_eq!(p.join().unwrap(), Verdict::Allow);
        }
        // Each answered host:port round-trips back as a remembered manual rule.
        let rules = query_manual(data.path(), pid).unwrap();
        assert_eq!(rules.len(), 2);
        assert!(rules.iter().all(|r| r.kind == ManualKind::Allow));

        // A drain on the now-empty queue is a clean *empty* Drained — distinct from Unsupported.
        match drain_session(data.path(), pid, Verdict::Allow, false).unwrap() {
            DrainOutcome::Drained(hosts) => assert!(hosts.is_empty()),
            DrainOutcome::Unsupported => {
                panic!("an empty healthy queue is Drained, not Unsupported")
            }
        }
    }

    #[test]
    fn drain_session_reports_unsupported_when_the_server_does_not_know_the_command() {
        // An older control server (one predating `--all`) replies `err bad-request` to a bulk drain.
        // `drain_session` must report that as `Unsupported`, NOT silently swallow it as an empty drain
        // — the difference between "nothing parked" and "this session is too old to drain in bulk".
        use crate::testutil::TmpDir;
        use std::io::{BufRead, BufReader, Write};
        let data = TmpDir::new();
        std::fs::create_dir_all(control_dir(data.path())).unwrap();
        let pid = 24242u32;
        let socket = control_socket(data.path(), pid);
        let listener = UnixListener::bind(&socket).unwrap();
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut cmd = String::new();
            BufReader::new(&stream).read_line(&mut cmd).unwrap();
            assert!(cmd.starts_with("ALLOW *"));
            (&stream).write_all(b"err bad-request\n").unwrap();
        });
        let outcome = drain_session(data.path(), pid, Verdict::Allow, false).unwrap();
        server.join().unwrap();
        assert!(
            matches!(outcome, DrainOutcome::Unsupported),
            "an `err` reply must surface as Unsupported"
        );
    }

    // ── The live egress event log ──────────────────────────────────────────────────────────────

    fn push_event(ring: &LogRing, host: &str, verdict: LogVerdict, reason: &str) {
        ring.push(
            false,
            host,
            443,
            Some("GET"),
            Some("/x"),
            verdict,
            reason,
            Proto::Https,
            HttpVer::H1,
            RpcKind::None,
        );
    }

    #[test]
    fn log_ring_assigns_monotonic_seqs_and_evicts_oldest_past_cap() {
        let ring = LogRing::new(3);
        for i in 0..5 {
            push_event(&ring, &format!("h{i}.test"), LogVerdict::Allow, "allowed");
        }
        let snap = ring.snapshot(None, None, false);
        // Cap is 3, so only the newest three survive; seqs are 1..=5 and never repeat.
        assert_eq!(snap.events.len(), 3);
        assert_eq!(snap.head, 5, "head is the newest seq assigned");
        let seqs: Vec<u64> = snap.events.iter().map(|e| e.seq).collect();
        assert_eq!(seqs, vec![3, 4, 5], "the oldest two were evicted");
        assert_eq!(snap.events[0].host, "h2.test");
        assert_eq!(snap.dropped, 0, "a tail read never reports a gap");
    }

    #[test]
    fn log_ring_tail_returns_the_whole_window_with_no_gap() {
        let ring = LogRing::new(LOG_RING_CAP);
        push_event(&ring, "a.test", LogVerdict::Allow, "allowed");
        push_event(&ring, "b.test", LogVerdict::Deny, "denied-default");
        let snap = ring.snapshot(None, None, false);
        assert_eq!(snap.events.len(), 2);
        assert_eq!(snap.dropped, 0);
        assert_eq!(snap.head, 2);
        assert_eq!(snap.events[1].verdict, LogVerdict::Deny);
        assert_eq!(snap.events[1].reason, "denied-default");
    }

    #[test]
    fn log_ring_follow_reports_the_eviction_gap_and_advances() {
        let ring = LogRing::new(2);
        // Push 4 events; the ring keeps only seqs 3 and 4.
        for i in 0..4 {
            push_event(&ring, &format!("h{i}.test"), LogVerdict::Allow, "allowed");
        }
        // A follower whose cursor is 1 missed seq 2 (evicted, never seen): report the gap.
        let snap = ring.snapshot(Some(1), None, false);
        let seqs: Vec<u64> = snap.events.iter().map(|e| e.seq).collect();
        assert_eq!(seqs, vec![3, 4]);
        assert_eq!(snap.dropped, 1, "seq 2 fell off the ring between polls");
        // A follower already at the head sees nothing new and no gap.
        let caught_up = ring.snapshot(Some(snap.head), None, false);
        assert!(caught_up.events.is_empty());
        assert_eq!(caught_up.dropped, 0);
        assert_eq!(caught_up.head, 4);
    }

    #[test]
    fn set_status_amends_a_live_event_and_is_a_noop_once_evicted() {
        let ring = LogRing::new(2);
        let s1 = ring.push(
            false,
            "a.test",
            443,
            Some("GET"),
            Some("/1"),
            LogVerdict::Allow,
            "allowed",
            Proto::Https,
            HttpVer::H1,
            RpcKind::None,
        );
        let s2 = ring.push(
            false,
            "b.test",
            443,
            Some("GET"),
            Some("/2"),
            LogVerdict::Allow,
            "allowed",
            Proto::Https,
            HttpVer::H1,
            RpcKind::None,
        );
        // A status amends the matching still-resident event, and only it.
        ring.set_status(s2, 404);
        let snap = ring.snapshot(None, None, false);
        assert_eq!(
            snap.events[0].status, None,
            "the untouched event keeps None"
        );
        assert_eq!(
            snap.events[1].status,
            Some(404),
            "the amended event carries its code"
        );

        // Evict s1 and s2 (push two more, cap is 2), then a late status for s1 is a silent no-op —
        // an evicted event is never resurrected.
        ring.push(
            false,
            "c.test",
            443,
            Some("GET"),
            Some("/3"),
            LogVerdict::Allow,
            "allowed",
            Proto::Https,
            HttpVer::H1,
            RpcKind::None,
        );
        ring.push(
            false,
            "d.test",
            443,
            Some("GET"),
            Some("/4"),
            LogVerdict::Allow,
            "allowed",
            Proto::Https,
            HttpVer::H1,
            RpcKind::None,
        );
        ring.set_status(s1, 500);
        let after = ring.snapshot(None, None, false);
        assert!(
            after.events.iter().all(|e| e.seq != s1),
            "s1 is gone from the ring"
        );
        assert!(
            after.events.iter().all(|e| e.status.is_none()),
            "a late status for an evicted event resurrects nothing"
        );
    }

    #[test]
    fn a_follow_reader_gets_a_status_amended_after_it_passed_the_event() {
        let ring = LogRing::new(8);
        let s1 = ring.push(
            false,
            "a.test",
            443,
            Some("GET"),
            Some("/1"),
            LogVerdict::Allow,
            "allowed",
            Proto::Https,
            HttpVer::H1,
            RpcKind::None,
        );
        // A follow reader catches up: it has seen seq s1, with no amendment yet.
        let seen = ring.snapshot(Some(s1), Some(0), false);
        assert!(seen.events.is_empty(), "nothing new past the head");
        let (seq_cursor, amend_cursor) = (seen.head, seen.amend_head);

        // The response returns later and the status is filled in — after the reader passed s1.
        ring.set_status(s1, 200);

        // The next follow poll RE-EMITS the already-seen event, now carrying its status.
        let after = ring.snapshot(Some(seq_cursor), Some(amend_cursor), false);
        assert_eq!(after.events.len(), 1, "the amended event resurfaces");
        assert_eq!(after.events[0].seq, s1);
        assert_eq!(after.events[0].status, Some(200));

        // A reader that does NOT track the amend cursor gets today's behavior: no re-emission.
        let no_amend = ring.snapshot(Some(seq_cursor), None, false);
        assert!(
            no_amend.events.is_empty(),
            "without the amend cursor there is no retroactive status"
        );

        // Once the reader advances its amend cursor, the amendment is not shown a second time.
        let caught_up = ring.snapshot(Some(after.head), Some(after.amend_head), false);
        assert!(
            caught_up.events.is_empty(),
            "an amendment resurfaces exactly once"
        );
    }

    #[test]
    fn event_line_round_trips_through_the_wire() {
        // A full L7 event whose path carries a query string's `=` (the field that must stay last).
        let ev = LogEvent {
            seq: 7,
            at_epoch_ms: 1_700_000_000_123,
            host: "api.test".into(),
            port: 8443,
            method: Some("POST".into()),
            path: Some("/v1/x?a=1&b=2".into()),
            verdict: LogVerdict::Allow,
            proto: Proto::Https,
            // Non-default version + RPC framing so the `ver=`/`l7=` tokens are exercised end to end.
            http_ver: HttpVer::H2,
            rpc: RpcKind::Grpc,
            reason: "allowed".into(),
            muted: false,
            // A captured upstream status round-trips on the wire alongside the query path.
            status: Some(200),
            amend_seq: None,
        };
        let line = format_event_line(&ev);
        let parsed = parse_event_line(line.trim()).expect("a well-formed line parses");
        assert_eq!(
            parsed, ev,
            "the event round-trips including the status and query path"
        );

        // An early-CONNECT / L4 event has no method/path — those tokens are omitted and parse None.
        let bare = LogEvent {
            seq: 8,
            at_epoch_ms: 1_700_000_000_456,
            host: "raw.test".into(),
            port: 22,
            method: None,
            path: None,
            verdict: LogVerdict::Allow,
            proto: Proto::Https,
            // A raw/early event carries no HTTP version or RPC framing — both stay default and their
            // tokens are omitted from the line.
            http_ver: HttpVer::Unknown,
            rpc: RpcKind::None,
            reason: "allowed".into(),
            muted: false,
            status: None,
            amend_seq: None,
        };
        let parsed = parse_event_line(format_event_line(&bare).trim()).unwrap();
        assert_eq!(
            parsed, bare,
            "a status-less L4 event omits the token and parses None"
        );

        // Every verdict token round-trips — in particular `error` (allowed-but-failed), the one the
        // proxy tests only ever assert in memory, so a typo in its wire token would otherwise surface
        // only when the CLI reads a live event over the socket.
        for verdict in [
            LogVerdict::Allow,
            LogVerdict::Deny,
            LogVerdict::Blocked,
            LogVerdict::Error,
        ] {
            let ev = LogEvent {
                seq: 9,
                at_epoch_ms: 1_700_000_000_789,
                host: "h.test".into(),
                port: 443,
                method: Some("GET".into()),
                path: Some("/p".into()),
                verdict,
                reason: "dns-failure".into(),
                proto: Proto::Https,
                // HTTP/1.1 here exercises the `ver=h1` token alongside every verdict.
                http_ver: HttpVer::H1,
                rpc: RpcKind::None,
                // A muted deny exercises the `muted=1` token on the wire (mute only ever applies to
                // a deny), so its round-trip is covered here alongside every verdict token.
                muted: verdict == LogVerdict::Deny,
                status: None,
                amend_seq: None,
            };
            let parsed = parse_event_line(format_event_line(&ev).trim()).unwrap();
            assert_eq!(
                parsed.verdict, verdict,
                "verdict {verdict:?} must round-trip"
            );
            assert_eq!(parsed, ev);
        }
    }

    #[test]
    fn rpc_kind_classifies_by_content_type_family_never_the_path() {
        use RpcKind::*;
        // gRPC-web is matched before gRPC (it shares the `application/grpc` prefix).
        assert_eq!(RpcKind::from_content_type("application/grpc"), Grpc);
        assert_eq!(RpcKind::from_content_type("application/grpc+proto"), Grpc);
        assert_eq!(RpcKind::from_content_type("APPLICATION/GRPC"), Grpc);
        assert_eq!(RpcKind::from_content_type("application/grpc-web"), GrpcWeb);
        assert_eq!(
            RpcKind::from_content_type("application/grpc-web+proto"),
            GrpcWeb
        );
        assert_eq!(
            RpcKind::from_content_type("application/connect+proto"),
            Connect
        );
        assert_eq!(
            RpcKind::from_content_type("application/connect+json"),
            Connect
        );
        // Connect *unary* and a plain protobuf/JSON POST are byte-identical on the wire, so they are
        // deliberately NOT tagged — the classifier never guesses from the path.
        assert_eq!(RpcKind::from_content_type("application/proto"), None);
        assert_eq!(RpcKind::from_content_type("application/json"), None);
        assert_eq!(RpcKind::from_content_type("text/plain"), None);
        assert_eq!(RpcKind::from_content_type(""), None);
    }

    #[test]
    fn a_line_without_ver_or_l7_parses_to_unknown_and_none() {
        // Backward compatibility: a persisted line predating these two axes (no `ver=`/`l7=`) must
        // still parse, defaulting them rather than failing the whole line.
        let old = "event seq=1 at=1700000000000 port=443 verdict=allow proto=https \
                   reason=allowed host=h.test path=/p";
        let parsed = parse_event_line(old).expect("an older line still parses");
        assert_eq!(parsed.http_ver, HttpVer::Unknown);
        assert_eq!(parsed.rpc, RpcKind::None);
        assert_eq!(parsed.proto, Proto::Https);
    }

    #[test]
    fn read_log_round_trips_over_the_socket() {
        // The integration seam: the client `read_log`/`log_all` against a real `serve` over a bound
        // socket, so the server's wire format and the client's parser are exercised together.
        use crate::testutil::TmpDir;
        let data = TmpDir::new();
        std::fs::create_dir_all(control_dir(data.path())).unwrap();
        let pid = 33333u32;
        let socket = control_socket(data.path(), pid);

        let pending = Arc::new(PendingState::new());
        let manual = Arc::new(ManualRules::new());
        let log = Arc::new(LogRing::new(LOG_RING_CAP));
        log.push(
            false,
            "a.test",
            443,
            Some("GET"),
            Some("/one"),
            LogVerdict::Allow,
            "allowed",
            Proto::Https,
            HttpVer::H1,
            RpcKind::None,
        );
        log.push(
            false,
            "b.test",
            443,
            Some("POST"),
            Some("/two?t=1"),
            LogVerdict::Deny,
            "denied-by-rule",
            Proto::Https,
            HttpVer::H1,
            RpcKind::None,
        );

        let flows = Arc::new(FlowRegistry::new());
        let listener = UnixListener::bind(&socket).unwrap();
        {
            let pending = pending.clone();
            let manual = manual.clone();
            let log = log.clone();
            let flows = flows.clone();
            thread::spawn(move || {
                let _ = serve(listener, pending, manual, log, flows);
            });
        }

        // A tail read over the socket returns both events, newest last, with the fields intact.
        let snap = read_log(&socket, None, None, false).unwrap();
        assert_eq!(snap.events.len(), 2);
        assert_eq!(snap.head, 2);
        assert_eq!(snap.events[0].host, "a.test");
        assert_eq!(snap.events[0].verdict, LogVerdict::Allow);
        assert_eq!(snap.events[1].host, "b.test");
        assert_eq!(snap.events[1].reason, "denied-by-rule");
        assert_eq!(snap.events[1].path.as_deref(), Some("/two?t=1"));

        // A follow read past the first event returns only the second, no gap.
        let after = read_log(&socket, Some(1), None, false).unwrap();
        assert_eq!(after.events.len(), 1);
        assert_eq!(after.events[0].seq, 2);
        assert_eq!(after.dropped, 0);

        // Discovery: `log_all` globs the egress dir and finds this session by its socket pid.
        let sessions = log_all(data.path(), false);
        assert_eq!(sessions.len(), 1);
        assert_eq!(sessions[0].pid, pid);
        assert_eq!(sessions[0].snapshot.events.len(), 2);
    }
}
