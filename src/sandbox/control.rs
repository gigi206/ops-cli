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

use std::collections::BTreeMap;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

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

/// The live, per-session manual egress rules a user adds while answering with `--session`: a runtime
/// overlay distinct from the (immutable) config policy. Shared via `Arc` between the proxy serve
/// threads (which consult it on the `ask` branch, before parking) and the control thread (which
/// appends to it). Each rule is an exact `host:port` — the answered request — so remembering a
/// decision suppresses the re-ask of *that* request without widening to the host's other ports.
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
        let rule = crate::allowlist::host_port_rule(host, port);
        let mut inner = self.inner.write().unwrap();
        let list = match verdict {
            Verdict::Allow => &mut inner.allow,
            Verdict::Deny => &mut inner.deny,
        };
        if !list.contains(&rule) {
            list.push(rule);
        }
    }

    /// The manual overlay's verdict for a request: `Some(true)` a remembered allow, `Some(false)` a
    /// remembered deny (deny wins), `None` if no manual rule matches (the request still parks). The
    /// read lock is held only for the check — nothing I/O-bound runs under it.
    pub(crate) fn decide(&self, host: &str, port: u16, path: &str) -> Option<bool> {
        let inner = self.inner.read().unwrap();
        if inner
            .deny
            .iter()
            .any(|r| crate::allowlist::rule_matches(r, host, port, path))
        {
            return Some(false);
        }
        if inner
            .allow
            .iter()
            .any(|r| crate::allowlist::rule_matches(r, host, port, path))
        {
            return Some(true);
        }
        None
    }

    /// A snapshot of the manual rules `(allow, deny)` for listing — cloned out so the read lock is
    /// not held across formatting or I/O.
    pub(crate) fn snapshot(&self) -> (Vec<Rule>, Vec<Rule>) {
        let inner = self.inner.read().unwrap();
        (inner.allow.clone(), inner.deny.clone())
    }
}

/// Serve the control socket: one short-lived thread per connection, each handling exactly one
/// command. A per-connection error is that connection's problem, never the server's. Both the
/// pending queue and the manual-rule overlay are shared in (the same ones the proxy holds).
pub(crate) fn serve(
    listener: UnixListener,
    state: Arc<PendingState>,
    manual: Arc<ManualRules>,
) -> io::Result<()> {
    for stream in listener.incoming() {
        let stream = stream?;
        let state = state.clone();
        let manual = manual.clone();
        std::thread::spawn(move || {
            let _ = handle(stream, &state, &manual);
        });
    }
    Ok(())
}

/// The largest control command accepted — commands are short (`ALLOW <seq>`), so anything larger is
/// malformed; bounding the read keeps a confused or hostile peer from making us buffer unboundedly.
const CMD_MAX: u64 = 256;

/// Handle one control connection: read a single command line, dispatch it, write the response, and
/// close. The socket is owner-only and host-side, so the peer is trusted; the bound read and the
/// timeout are belt-and-braces against a stuck or malformed caller.
fn handle(stream: UnixStream, state: &PendingState, manual: &ManualRules) -> io::Result<()> {
    stream.set_read_timeout(Some(Duration::from_secs(10)))?;
    stream.set_write_timeout(Some(Duration::from_secs(10)))?;
    let mut reader = BufReader::new((&stream).take(CMD_MAX));
    let mut line = String::new();
    reader.read_line(&mut line)?;
    let response = dispatch(line.trim(), state, manual);
    (&stream).write_all(response.as_bytes())?;
    (&stream).flush()
}

/// Map a control command to its response. `LIST` returns one `pending …` line per parked request
/// then `ok`; `ALLOW <seq>`/`DENY <seq>` answer every parked request to that request's destination
/// (its `host:port/path` — identical retries are one decision; a trailing `session` token also
/// remembers it as a manual rule), replying `ok host=<host> count=<n>` or `err not-found`;
/// `ALLOW *`/`DENY *`
/// drain *every* parked request, replying one `answered host=<host>` line each then `ok` (the
/// `session` token remembers each); `RULES` returns the session's manual rules
/// (`manual allow|deny <rule>` lines) then `ok`. `path` is emitted last on a `pending` line so a
/// query string's `=` cannot be mistaken for a field separator (the reader splits each token on its
/// first `=`).
fn dispatch(cmd: &str, state: &PendingState, manual: &ManualRules) -> String {
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
        Some("RULES") => {
            let (allow, deny) = manual.snapshot();
            let mut out = String::new();
            // A manual rule is always an exact `host:port`, so its display carries no whitespace —
            // the client takes everything after `manual allow `/`manual deny ` as the rule text.
            for rule in allow {
                out.push_str(&format!("manual allow {rule}\n"));
            }
            for rule in deny {
                out.push_str(&format!("manual deny {rule}\n"));
            }
            out.push_str("ok\n");
            out
        }
        _ => "err bad-request\n".to_string(),
    }
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
    BufReader::new((&stream).take(CMD_MAX)).read_line(&mut response)?;
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
        // The rule text is everything after the kind prefix — it carries no whitespace (an exact
        // `host:port`), but taking the remainder is robust regardless.
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
    fn manual_rules_remember_decide_and_dedup_by_host_port() {
        let m = ManualRules::new();
        // Nothing remembered → no decision (the request still parks).
        assert_eq!(m.decide("api.test", 443, "/"), None);

        // Remember an allow for a non-standard port (the very reason the request asked).
        m.remember(Verdict::Allow, "api.test", 8080);
        // The exact `host:port` is decided allow...
        assert_eq!(m.decide("api.test", 8080, "/x"), Some(true));
        // ...but a DIFFERENT port to the same host is not — no widening (the `classify` trap the
        // advisor flagged: a host-only remember would re-ask `:8080`, or over-trust `:443`).
        assert_eq!(m.decide("api.test", 443, "/x"), None);

        // A deny is remembered and wins for its own host:port.
        m.remember(Verdict::Deny, "evil.test", 443);
        assert_eq!(m.decide("evil.test", 443, "/"), Some(false));

        // Dedup: re-answering the same host:port does not stack duplicates.
        m.remember(Verdict::Allow, "api.test", 8080);
        assert_eq!(
            m.snapshot().0.len(),
            1,
            "a re-answered host:port is not duplicated"
        );
    }

    #[test]
    fn dispatch_remembers_only_on_the_session_token() {
        let state = Arc::new(PendingState::new());
        let manual = Arc::new(ManualRules::new());

        // A bare ALLOW answers but does not remember.
        let s = state.clone();
        let parked = thread::spawn(move || s.park("api.test", 8080, "/", None, 256, |_| {}));
        let seq = wait_for_one(&state);
        assert_eq!(
            dispatch(&format!("ALLOW {seq}"), &state, &manual),
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
        let _ = dispatch(&format!("ALLOW {seq} session"), &state, &manual);
        parked.join().unwrap();
        assert_eq!(manual.snapshot().0.len(), 1, "`… session` must remember");
        // And `RULES` reports the remembered rule with its exact port.
        assert!(
            dispatch("RULES", &state, &manual).contains("manual allow api.test:8080"),
            "RULES must list the remembered host:port"
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
        let listener = UnixListener::bind(&socket).unwrap();
        {
            let pending = pending.clone();
            let manual = manual.clone();
            thread::spawn(move || {
                let _ = serve(listener, pending, manual);
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
        assert_eq!(rules[0].rule, "api.test:8080");

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

        // A bare `DENY *` drains every request but remembers nothing. Parked one at a time so the
        // response lines come back in a deterministic oldest-first order.
        let _ = park_next(&state, "x.test", 8080, 0);
        let _ = park_next(&state, "y.test", 8080, 1);
        let response = dispatch("DENY *", &state, &manual);
        assert_eq!(response, "answered host=x.test\nanswered host=y.test\nok\n");
        assert!(
            manual.snapshot().1.is_empty(),
            "a bare `DENY *` must not remember"
        );

        // `ALLOW * session` drains and remembers each host:port as a manual rule.
        let _ = park_next(&state, "p.test", 8080, 0);
        let _ = park_next(&state, "q.test", 8080, 1);
        let _ = dispatch("ALLOW * session", &state, &manual);
        let (allow, _) = manual.snapshot();
        assert_eq!(allow.len(), 2, "`* session` remembers each answered host");

        // An empty queue replies a clean `ok` with no `answered` lines.
        assert_eq!(dispatch("ALLOW *", &state, &manual), "ok\n");
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
        let listener = UnixListener::bind(&socket).unwrap();
        {
            let pending = pending.clone();
            let manual = manual.clone();
            thread::spawn(move || {
                let _ = serve(listener, pending, manual);
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
}
