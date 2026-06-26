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
//! returns the pending rows, `ALLOW <seq>` / `DENY <seq>` answer one, naming the host so a
//! `--save` can persist it.

use std::collections::BTreeMap;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

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
/// [`answer`](PendingState::answer)s it. One per launch, shared (via `Arc`) between the proxy serve
/// threads and the control serve thread.
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

    /// Answer a parked request by sequence id: remove it and wake its proxy thread with `verdict`,
    /// returning the host it was for (so a `--save` can persist a rule). `None` if no such request
    /// is parked (already answered, or timed out). A send failure (the thread just timed out) is
    /// ignored — the entry is gone either way.
    pub(crate) fn answer(&self, seq: u64, verdict: Verdict) -> Option<String> {
        let mut inner = self.inner.lock().unwrap();
        let entry = inner.entries.remove(&seq)?;
        let _ = entry.answer.send(verdict);
        Some(entry.host)
    }
}

/// Serve the control socket: one short-lived thread per connection, each handling exactly one
/// command. A per-connection error is that connection's problem, never the server's.
pub(crate) fn serve(listener: UnixListener, state: Arc<PendingState>) -> io::Result<()> {
    for stream in listener.incoming() {
        let stream = stream?;
        let state = state.clone();
        std::thread::spawn(move || {
            let _ = handle(stream, &state);
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
fn handle(stream: UnixStream, state: &PendingState) -> io::Result<()> {
    stream.set_read_timeout(Some(Duration::from_secs(10)))?;
    stream.set_write_timeout(Some(Duration::from_secs(10)))?;
    let mut reader = BufReader::new((&stream).take(CMD_MAX));
    let mut line = String::new();
    reader.read_line(&mut line)?;
    let response = dispatch(line.trim(), state);
    (&stream).write_all(response.as_bytes())?;
    (&stream).flush()
}

/// Map a control command to its response. `LIST` returns one `pending …` line per parked request
/// then `ok`; `ALLOW <seq>`/`DENY <seq>` answer one request, replying `ok host=<host>` or
/// `err not-found`. `path` is emitted last on a `pending` line so a query string's `=` cannot be
/// mistaken for a field separator (the reader splits each token on its first `=`).
fn dispatch(cmd: &str, state: &PendingState) -> String {
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
            let Some(seq) = parts.next().and_then(|s| s.parse::<u64>().ok()) else {
                return "err bad-request\n".to_string();
            };
            let verdict = if verb == "ALLOW" {
                Verdict::Allow
            } else {
                Verdict::Deny
            };
            match state.answer(seq, verdict) {
                Some(host) => format!("ok host={host}\n"),
                None => "err not-found\n".to_string(),
            }
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
    let Ok(entries) = std::fs::read_dir(control_dir(data_dir)) else {
        return sessions;
    };
    let mut pids: Vec<u32> = entries
        .flatten()
        .filter_map(|e| pid_from_socket(&e.file_name().to_string_lossy()))
        .collect();
    pids.sort_unstable();
    for pid in pids {
        if let Ok(rows) = query(&control_socket(data_dir, pid)) {
            sessions.push(SessionPending { pid, rows });
        }
    }
    sessions
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
    /// The request was answered; the host it was for (for a `--save`).
    Answered(String),
    /// No such request is parked (already answered, timed out, or a wrong id).
    NotFound,
}

/// Answer the parked request `<pid>.<seq>`: connect to that session's control socket and send the
/// verdict. A missing socket / dead session surfaces as a connect error; a live session that has
/// no such request returns [`AnswerOutcome::NotFound`].
pub(crate) fn answer_request(
    data_dir: &Path,
    pid: u32,
    seq: u64,
    verdict: Verdict,
) -> io::Result<AnswerOutcome> {
    let stream = UnixStream::connect(control_socket(data_dir, pid))?;
    stream.set_read_timeout(Some(Duration::from_secs(10)))?;
    stream.set_write_timeout(Some(Duration::from_secs(10)))?;
    let verb = match verdict {
        Verdict::Allow => "ALLOW",
        Verdict::Deny => "DENY",
    };
    (&stream).write_all(format!("{verb} {seq}\n").as_bytes())?;
    (&stream).flush()?;
    let mut response = String::new();
    BufReader::new((&stream).take(CMD_MAX)).read_line(&mut response)?;
    let response = response.trim();
    if let Some(rest) = response.strip_prefix("ok host=") {
        Ok(AnswerOutcome::Answered(rest.to_string()))
    } else {
        // "err not-found" / "err bad-request" / anything unexpected → not answered.
        Ok(AnswerOutcome::NotFound)
    }
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
            state.answer(seq, Verdict::Allow),
            Some("api.example.com".to_string())
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
            state.answer(seq, Verdict::Deny),
            Some("evil.test".to_string())
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
        state.answer(seq, Verdict::Allow);
        assert_eq!(parked.join().unwrap(), Verdict::Allow);
    }

    #[test]
    fn answer_an_unknown_seq_is_none() {
        let state = PendingState::new();
        assert_eq!(state.answer(999, Verdict::Allow), None);
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
}
