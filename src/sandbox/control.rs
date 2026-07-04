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

    /// Whether the overlay is empty — the common case, letting the proxy skip building an effective
    /// policy and evaluate its immutable config policy directly (no per-request allocation).
    pub(crate) fn is_empty(&self) -> bool {
        let inner = self.inner.read().unwrap();
        inner.allow.is_empty() && inner.deny.is_empty()
    }

    /// A snapshot of the manual rules `(allow, deny)` — cloned out so the read lock is not held
    /// across the fold into the effective policy, listing, or I/O.
    pub(crate) fn snapshot(&self) -> (Vec<Rule>, Vec<Rule>) {
        let inner = self.inner.read().unwrap();
        (inner.allow.clone(), inner.deny.clone())
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
}

impl LogRing {
    pub(crate) fn new(cap: usize) -> Self {
        LogRing {
            inner: Mutex::new(LogInner {
                next_seq: 1,
                next_amend: 1,
                events: VecDeque::new(),
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
        host: &str,
        port: u16,
        method: Option<&str>,
        path: Option<&str>,
        verdict: LogVerdict,
        reason: &str,
    ) -> u64 {
        let at_epoch_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis())
            .unwrap_or(0);
        let mut g = self.inner.lock().unwrap();
        let seq = g.next_seq;
        g.next_seq += 1;
        g.events.push_back(LogEvent {
            seq,
            at_epoch_ms,
            host: host.to_string(),
            port,
            method: method.map(str::to_string),
            path: path.map(str::to_string),
            verdict,
            reason: reason.to_string(),
            status: None,
            amend_seq: None,
        });
        while g.events.len() > self.cap {
            g.events.pop_front();
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
    pub(crate) fn snapshot(&self, after: Option<u64>, after_amend: Option<u64>) -> LogSnapshot {
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

/// Serve the control socket: one short-lived thread per connection, each handling exactly one
/// command. A per-connection error is that connection's problem, never the server's. The pending
/// queue, the manual-rule overlay, and the event log are shared in (the same ones the proxy holds).
pub(crate) fn serve(
    listener: UnixListener,
    state: Arc<PendingState>,
    manual: Arc<ManualRules>,
    log: Arc<LogRing>,
) -> io::Result<()> {
    for stream in listener.incoming() {
        let stream = stream?;
        let state = state.clone();
        let manual = manual.clone();
        let log = log.clone();
        std::thread::spawn(move || {
            let _ = handle(stream, &state, &manual, &log);
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
) -> io::Result<()> {
    stream.set_read_timeout(Some(Duration::from_secs(10)))?;
    stream.set_write_timeout(Some(Duration::from_secs(10)))?;
    let mut reader = BufReader::new((&stream).take(CMD_MAX));
    let mut line = String::new();
    reader.read_line(&mut line)?;
    let response = dispatch(line.trim(), state, manual, log);
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
fn dispatch(cmd: &str, state: &PendingState, manual: &ManualRules, log: &LogRing) -> String {
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
            let (verdict, rule_text) = if let Some(r) = body.strip_prefix("ALLOW ") {
                (Verdict::Allow, r.trim())
            } else if let Some(r) = body.strip_prefix("DENY ") {
                (Verdict::Deny, r.trim())
            } else {
                return "err bad-request\n".to_string();
            };
            match crate::allowlist::classify(rule_text) {
                Ok(rule) => {
                    manual.remember_rule(verdict, rule);
                    "ok\n".to_string()
                }
                Err(_) => "err bad-request\n".to_string(),
            }
        }
        Some("RULES") => {
            let (allow, deny) = manual.snapshot();
            let mut out = String::new();
            // The rule text is emitted after the `manual allow `/`manual deny ` prefix; the reader
            // takes the whole remainder, so a rule carrying whitespace (a `re:` regex) round-trips.
            for rule in allow {
                out.push_str(&format!("manual allow {rule}\n"));
            }
            for rule in deny {
                out.push_str(&format!("manual deny {rule}\n"));
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
            for token in parts {
                if let Some(v) = token.strip_prefix("after=") {
                    after = v.parse().ok();
                } else if let Some(v) = token.strip_prefix("amended=") {
                    after_amend = v.parse().ok();
                }
            }
            let snapshot = log.snapshot(after, after_amend);
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
        _ => "err bad-request\n".to_string(),
    }
}

/// Format one event as a control-wire line. Fields are `key=value` tokens split on their first `=`;
/// `method`/`path` are omitted when absent, and `path` is emitted **last** so a query string's `=`
/// round-trips (it is the only field that can carry one, and an HTTP request-target has no spaces).
fn format_event_line(ev: &LogEvent) -> String {
    let mut line = format!(
        "event seq={} at={} port={} verdict={} reason={}",
        ev.seq,
        ev.at_epoch_ms,
        ev.port,
        ev.verdict.as_str(),
        ev.reason,
    );
    if let Some(status) = ev.status {
        line.push_str(&format!(" status={status}"));
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
pub(crate) fn log_all(data_dir: &Path) -> Vec<SessionLog> {
    let mut sessions = Vec::new();
    for pid in session_pids(data_dir) {
        if let Ok(snapshot) = read_log(&control_socket(data_dir, pid), None, None) {
            sessions.push(SessionLog { pid, snapshot });
        }
    }
    sessions
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
            "reason" => reason = Some(value.to_string()),
            "method" => method = Some(value.to_string()),
            "host" => host = Some(value.to_string()),
            "path" => path = Some(value.to_string()),
            "status" => status = value.parse().ok(),
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

/// One manual rule reported by a live session: whether it allows (vs denies) and its display text.
pub(crate) struct ManualRuleRow {
    pub(crate) is_allow: bool,
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
    let stream = UnixStream::connect(control_socket(data_dir, pid))?;
    stream.set_read_timeout(Some(Duration::from_secs(10)))?;
    stream.set_write_timeout(Some(Duration::from_secs(10)))?;
    let verb = match verdict {
        Verdict::Allow => "ALLOW",
        Verdict::Deny => "DENY",
    };
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
                is_allow: true,
                rule: rule.to_string(),
            });
        } else if let Some(rule) = line.strip_prefix("manual deny ") {
            rules.push(ManualRuleRow {
                is_allow: false,
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

        // A bare ALLOW answers but does not remember.
        let s = state.clone();
        let parked = thread::spawn(move || s.park("api.test", 8080, "/", None, 256, |_| {}));
        let seq = wait_for_one(&state);
        assert_eq!(
            dispatch(&format!("ALLOW {seq}"), &state, &manual, &log),
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
        let _ = dispatch(&format!("ALLOW {seq} session"), &state, &manual, &log);
        parked.join().unwrap();
        assert_eq!(manual.snapshot().0.len(), 1, "`… session` must remember");
        // And `RULES` reports the remembered rule with its exact port.
        assert!(
            dispatch("RULES", &state, &manual, &log).contains("manual allow https://api.test:8080"),
            "RULES must list the remembered host:port"
        );
    }

    #[test]
    fn dispatch_remember_loads_a_rule_into_the_overlay() {
        let state = Arc::new(PendingState::new());
        let manual = Arc::new(ManualRules::new());
        let log = LogRing::new(LOG_RING_CAP);

        // `REMEMBER ALLOW <rule>` loads an arbitrary (here wildcard) rule into the overlay and
        // `RULES` reports it — the proactive `--session` path. It is accepted in any posture (the
        // proxy folds the overlay into its effective policy for every filtering posture).
        assert_eq!(
            dispatch("REMEMBER ALLOW *.foo.test", &state, &manual, &log),
            "ok\n"
        );
        assert!(
            dispatch("RULES", &state, &manual, &log).contains("manual allow https://*.foo.test"),
            "REMEMBER must load the rule"
        );

        // A malformed rule (a `*` catch-all) and a missing kind/rule are `err bad-request`.
        assert_eq!(
            dispatch("REMEMBER ALLOW *", &state, &manual, &log),
            "err bad-request\n"
        );
        assert_eq!(
            dispatch("REMEMBER ALLOW", &state, &manual, &log),
            "err bad-request\n"
        );
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
        thread::spawn(move || {
            let _ = serve(listener, pending, served_manual, log);
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
        let listener = UnixListener::bind(&socket).unwrap();
        {
            let pending = pending.clone();
            let manual = manual.clone();
            let log = log.clone();
            thread::spawn(move || {
                let _ = serve(listener, pending, manual, log);
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
        assert!(rules[0].is_allow);
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

        // A bare `DENY *` drains every request but remembers nothing. Parked one at a time so the
        // response lines come back in a deterministic oldest-first order.
        let _ = park_next(&state, "x.test", 8080, 0);
        let _ = park_next(&state, "y.test", 8080, 1);
        let response = dispatch("DENY *", &state, &manual, &log);
        assert_eq!(response, "answered host=x.test\nanswered host=y.test\nok\n");
        assert!(
            manual.snapshot().1.is_empty(),
            "a bare `DENY *` must not remember"
        );

        // `ALLOW * session` drains and remembers each host:port as a manual rule.
        let _ = park_next(&state, "p.test", 8080, 0);
        let _ = park_next(&state, "q.test", 8080, 1);
        let _ = dispatch("ALLOW * session", &state, &manual, &log);
        let (allow, _) = manual.snapshot();
        assert_eq!(allow.len(), 2, "`* session` remembers each answered host");

        // An empty queue replies a clean `ok` with no `answered` lines.
        assert_eq!(dispatch("ALLOW *", &state, &manual, &log), "ok\n");
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
        let listener = UnixListener::bind(&socket).unwrap();
        {
            let pending = pending.clone();
            let manual = manual.clone();
            let log = log.clone();
            thread::spawn(move || {
                let _ = serve(listener, pending, manual, log);
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
        assert!(rules.iter().all(|r| r.is_allow));

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
        ring.push(host, 443, Some("GET"), Some("/x"), verdict, reason);
    }

    #[test]
    fn log_ring_assigns_monotonic_seqs_and_evicts_oldest_past_cap() {
        let ring = LogRing::new(3);
        for i in 0..5 {
            push_event(&ring, &format!("h{i}.test"), LogVerdict::Allow, "allowed");
        }
        let snap = ring.snapshot(None, None);
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
        let snap = ring.snapshot(None, None);
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
        let snap = ring.snapshot(Some(1), None);
        let seqs: Vec<u64> = snap.events.iter().map(|e| e.seq).collect();
        assert_eq!(seqs, vec![3, 4]);
        assert_eq!(snap.dropped, 1, "seq 2 fell off the ring between polls");
        // A follower already at the head sees nothing new and no gap.
        let caught_up = ring.snapshot(Some(snap.head), None);
        assert!(caught_up.events.is_empty());
        assert_eq!(caught_up.dropped, 0);
        assert_eq!(caught_up.head, 4);
    }

    #[test]
    fn set_status_amends_a_live_event_and_is_a_noop_once_evicted() {
        let ring = LogRing::new(2);
        let s1 = ring.push(
            "a.test",
            443,
            Some("GET"),
            Some("/1"),
            LogVerdict::Allow,
            "allowed",
        );
        let s2 = ring.push(
            "b.test",
            443,
            Some("GET"),
            Some("/2"),
            LogVerdict::Allow,
            "allowed",
        );
        // A status amends the matching still-resident event, and only it.
        ring.set_status(s2, 404);
        let snap = ring.snapshot(None, None);
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
            "c.test",
            443,
            Some("GET"),
            Some("/3"),
            LogVerdict::Allow,
            "allowed",
        );
        ring.push(
            "d.test",
            443,
            Some("GET"),
            Some("/4"),
            LogVerdict::Allow,
            "allowed",
        );
        ring.set_status(s1, 500);
        let after = ring.snapshot(None, None);
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
            "a.test",
            443,
            Some("GET"),
            Some("/1"),
            LogVerdict::Allow,
            "allowed",
        );
        // A follow reader catches up: it has seen seq s1, with no amendment yet.
        let seen = ring.snapshot(Some(s1), Some(0));
        assert!(seen.events.is_empty(), "nothing new past the head");
        let (seq_cursor, amend_cursor) = (seen.head, seen.amend_head);

        // The response returns later and the status is filled in — after the reader passed s1.
        ring.set_status(s1, 200);

        // The next follow poll RE-EMITS the already-seen event, now carrying its status.
        let after = ring.snapshot(Some(seq_cursor), Some(amend_cursor));
        assert_eq!(after.events.len(), 1, "the amended event resurfaces");
        assert_eq!(after.events[0].seq, s1);
        assert_eq!(after.events[0].status, Some(200));

        // A reader that does NOT track the amend cursor gets today's behavior: no re-emission.
        let no_amend = ring.snapshot(Some(seq_cursor), None);
        assert!(
            no_amend.events.is_empty(),
            "without the amend cursor there is no retroactive status"
        );

        // Once the reader advances its amend cursor, the amendment is not shown a second time.
        let caught_up = ring.snapshot(Some(after.head), Some(after.amend_head));
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
            reason: "allowed".into(),
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
            reason: "allowed".into(),
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
            "a.test",
            443,
            Some("GET"),
            Some("/one"),
            LogVerdict::Allow,
            "allowed",
        );
        log.push(
            "b.test",
            443,
            Some("POST"),
            Some("/two?t=1"),
            LogVerdict::Deny,
            "denied-by-rule",
        );

        let listener = UnixListener::bind(&socket).unwrap();
        {
            let pending = pending.clone();
            let manual = manual.clone();
            let log = log.clone();
            thread::spawn(move || {
                let _ = serve(listener, pending, manual, log);
            });
        }

        // A tail read over the socket returns both events, newest last, with the fields intact.
        let snap = read_log(&socket, None, None).unwrap();
        assert_eq!(snap.events.len(), 2);
        assert_eq!(snap.head, 2);
        assert_eq!(snap.events[0].host, "a.test");
        assert_eq!(snap.events[0].verdict, LogVerdict::Allow);
        assert_eq!(snap.events[1].host, "b.test");
        assert_eq!(snap.events[1].reason, "denied-by-rule");
        assert_eq!(snap.events[1].path.as_deref(), Some("/two?t=1"));

        // A follow read past the first event returns only the second, no gap.
        let after = read_log(&socket, Some(1), None).unwrap();
        assert_eq!(after.events.len(), 1);
        assert_eq!(after.events[0].seq, 2);
        assert_eq!(after.dropped, 0);

        // Discovery: `log_all` globs the egress dir and finds this session by its socket pid.
        let sessions = log_all(data.path());
        assert_eq!(sessions.len(), 1);
        assert_eq!(sessions[0].pid, pid);
        assert_eq!(sessions[0].snapshot.events.len(), 2);
    }
}
