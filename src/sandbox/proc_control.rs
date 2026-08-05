//! The process-observation control plane: a bounded, in-RAM ring of the exec events the supervisor
//! observes in the cage, plus the per-session Unix socket a host-side `sbx proc logs` reaches to read
//! them.
//!
//! This is the process/exec analogue of the egress control plane in [`super::control`], and
//! deliberately independent of it: process observation must work whether or not a network posture is
//! filtering, so it owns its own ring and its own socket at `<data>/proc/control-<pid>.sock` rather
//! than riding the egress one (which exists only under an allowlist).
//!
//! Security mirrors the egress control socket exactly. The socket is bound under the `0700` data dir
//! and is **never** bound into the cage: in Mode B the in-cage agent is the adversary, so letting it
//! reach this socket would let it read — and, once the seccomp user-notification enforcement lands,
//! answer — its own observation. It lives beside `<data>`, which the cage never sees. The ring is
//! never written to disk and never crosses into the cage; it is the supervisor's owner-only RAM for
//! the session's lifetime and dies with it.
//!
//! The wire protocol is line-based and minimal (one command per connection): `LOG` returns the
//! retained events (a `dropped=` line when a `--follow` cursor fell behind the ring, a `head=` cursor,
//! then one `event …` line each) then `ok`; `LOG after=<seq>` returns only events past that cursor.
//! The observed command carries spaces, so it is emitted **last** on an event line and taken verbatim
//! by the reader; the observer sanitises it of control characters, so it can never inject a second
//! line.

use std::io::{self, BufRead, BufReader, Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use super::proc_enforce::ProcOverlay;
use crate::proc_policy::{self, ProcMode, Verdict};

/// The default number of recent exec events a session retains for the live feed.
pub(crate) const EXEC_RING_CAP: usize = 1000;

/// The largest control command / reply line accepted — bounded so a confused or hostile peer cannot
/// make the reader buffer unboundedly. A command is short (`LOG after=<seq>`); a reply carries the
/// observed command line, which can be long, so the bound is generous but still finite. The peer is
/// the owner-only, host-side control client.
const LINE_MAX: u64 = 8 * 1024;

/// One observed exec event: a process the agent spawned in the cage, as the supervisor's `/proc` poll
/// first saw it. `command` is the process's argv joined — already sanitised of control characters and
/// length-capped by the observer — so it is safe to carry on the line-based wire and to print.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ExecEvent {
    pub(crate) seq: u64,
    /// Wall-clock capture time in epoch milliseconds — a clean stamp for `--json`; the human view
    /// renders it as a local `hh:mm:ss` time.
    pub(crate) at_epoch_ms: u128,
    pub(crate) pid: u32,
    /// The enforcement verdict, when the event came from the seccomp user-notification supervisor:
    /// `allow` / `deny` / `ask`. The cheap `/proc` poll observer (a non-enforcing `observe` run) sets
    /// `observe` — it records what ran, not a decision. A short, fixed token, so it is safe before the
    /// verbatim `command` on the wire.
    pub(crate) verdict: String,
    /// The program that issued the `execve`, as its own executable — empty when the policy did not
    /// need to know (the flat model decides by target alone, so asking would be a syscall spent on
    /// an answer nobody reads). Where a policy decides **by caller**, this is the other half of the
    /// fact: a refusal that names only the target reads as "you did not declare this" even when it
    /// was declared, just not for whoever reached for it.
    pub(crate) caller: String,
    pub(crate) command: String,
}

impl super::lens::Event for ExecEvent {
    fn seq(&self) -> u64 {
        self.seq
    }
}

/// The result of a `LOG` query over this lens. See [`super::lens::Snapshot`].
pub(crate) type ExecSnapshot = super::lens::Snapshot<ExecEvent>;

/// A bounded ring of recent exec events. Shared (via `Arc`) between the observer thread (which
/// [`push`](ExecRing::push)es) and the control serve thread (which [`snapshot`](ExecRing::snapshot)s
/// for `sbx proc logs`). The sequencing and eviction are [`super::lens::Ring`]'s; what this adds is
/// the shape of an exec event, and the two ways one arrives.
pub(crate) struct ExecRing(super::lens::Ring<ExecEvent>);

impl ExecRing {
    pub(crate) fn new(cap: usize) -> Self {
        ExecRing(super::lens::Ring::new(cap))
    }

    /// Append one observed exec (the non-enforcing `/proc` poll path — verdict `observe`). `command`
    /// must already be sanitised of control characters and length-capped by the caller. Returns the
    /// assigned sequence.
    pub(crate) fn push(&self, pid: u32, command: &str) -> u64 {
        self.push_verdict(pid, "", command, "observe")
    }

    /// Append one enforced exec (the seccomp user-notification path), tagged with its `verdict`
    /// (`allow` / `deny` / `ask` / `absent`) and the `caller` that issued it (empty where the policy
    /// decides by target alone). `command` — here the exec target path — must already be sanitised of
    /// control characters and length-capped by the caller. Returns the assigned sequence.
    pub(crate) fn push_verdict(&self, pid: u32, caller: &str, command: &str, verdict: &str) -> u64 {
        self.0.push_with(|seq, at_epoch_ms| ExecEvent {
            seq,
            at_epoch_ms,
            pid,
            verdict: verdict.to_string(),
            caller: caller.to_string(),
            command: command.to_string(),
        })
    }

    pub(crate) fn snapshot(&self, after: Option<u64>) -> ExecSnapshot {
        self.0.snapshot(after)
    }
}

/// Serve the control socket: one short-lived thread per connection, each handling exactly one
/// command. A per-connection error is that connection's problem, never the server's. The ring is
/// shared in (the same one the observer pushes to).
pub(crate) fn serve(listener: UnixListener, ring: Arc<ExecRing>) -> io::Result<()> {
    for stream in listener.incoming() {
        let stream = stream?;
        let ring = ring.clone();
        std::thread::spawn(move || {
            let _ = handle(stream, &ring);
        });
    }
    Ok(())
}

/// Serve the control socket for an **enforcing** session (`[proc] mode = enforce|ask`): like
/// [`serve`], but the dispatch also answers the `ask` decision verbs (`LIST` the parked `execve`s,
/// `ALLOW`/`DENY <id>` or `*` to decide them) against the shared [`PendingExec`].
pub(crate) fn serve_enforced(
    listener: UnixListener,
    ring: Arc<ExecRing>,
    pending: Arc<super::proc_enforce::PendingExec>,
    overlay: Arc<ProcOverlay>,
    mode: ProcMode,
) -> io::Result<()> {
    for stream in listener.incoming() {
        let stream = stream?;
        let ring = ring.clone();
        let pending = pending.clone();
        let overlay = overlay.clone();
        std::thread::spawn(move || {
            let _ = handle_enforced(stream, &ring, &pending, &overlay, mode);
        });
    }
    Ok(())
}

/// Handle one control connection: read a single command line, dispatch it, write the response, and
/// close. The socket is owner-only and host-side, so the peer is trusted; the bound read and the
/// timeout are belt-and-braces against a stuck or malformed caller.
fn handle(stream: UnixStream, ring: &ExecRing) -> io::Result<()> {
    stream.set_read_timeout(Some(Duration::from_secs(10)))?;
    stream.set_write_timeout(Some(Duration::from_secs(10)))?;
    let mut reader = BufReader::new((&stream).take(LINE_MAX));
    let mut line = String::new();
    reader.read_line(&mut line)?;
    let response = dispatch(line.trim(), ring);
    (&stream).write_all(response.as_bytes())?;
    (&stream).flush()
}

/// Handle one control connection for an enforcing session, dispatching the ask verbs too.
fn handle_enforced(
    stream: UnixStream,
    ring: &ExecRing,
    pending: &super::proc_enforce::PendingExec,
    overlay: &ProcOverlay,
    mode: ProcMode,
) -> io::Result<()> {
    stream.set_read_timeout(Some(Duration::from_secs(10)))?;
    stream.set_write_timeout(Some(Duration::from_secs(10)))?;
    let mut reader = BufReader::new((&stream).take(LINE_MAX));
    let mut line = String::new();
    reader.read_line(&mut line)?;
    let response = dispatch_enforced(line.trim(), ring, pending, overlay, mode);
    (&stream).write_all(response.as_bytes())?;
    (&stream).flush()
}

/// Dispatch an enforcing-session command: the observe `LOG` plus the ask decision verbs. `LIST`
/// returns the parked `execve`s (`pending id=… pid=… waiting=… path=…`, `path` last/verbatim);
/// `ALLOW <id>`/`DENY <id>` decides one by its notification id (`ok path=…` / `err not-found`);
/// `ALLOW *`/`DENY *` decides them all (`answered path=…`* then `ok`).
fn dispatch_enforced(
    cmd: &str,
    ring: &ExecRing,
    pending: &super::proc_enforce::PendingExec,
    overlay: &ProcOverlay,
    mode: ProcMode,
) -> String {
    // `REMEMBER ALLOW|DENY <rule>` loads a live `--session` rule into the overlay; the rule is taken
    // verbatim (not whitespace-split) so a glob with a space survives. `RULES` lists the overlay.
    if let Some(body) = cmd.strip_prefix("REMEMBER ") {
        let (verdict, rule) = if let Some(r) = body.strip_prefix("ALLOW ") {
            (Verdict::Allow, r.trim())
        } else if let Some(r) = body.strip_prefix("DENY ") {
            (Verdict::Deny, r.trim())
        } else {
            return "err bad-request\n".to_string();
        };
        if proc_policy::validate_rule(rule).is_err() {
            return "err bad-request\n".to_string();
        }
        // An `allow` only takes effect under `ask` (under `enforce` everything not denied already
        // runs), so loading one into an enforce session would be inert — refuse it, consistent with
        // the config-write guard, rather than store a rule that does nothing.
        if verdict == Verdict::Allow && mode != ProcMode::Ask {
            return "err inert\n".to_string();
        }
        overlay.remember(verdict, rule);
        return "ok\n".to_string();
    }
    if cmd == "RULES" {
        let mut out = String::new();
        for (kind, rule) in overlay.snapshot() {
            out.push_str(&format!("rule {kind} {rule}\n"));
        }
        out.push_str("ok\n");
        return out;
    }
    let mut parts = cmd.split_whitespace();
    match parts.next() {
        Some("LOG") => dispatch(cmd, ring),
        Some("LIST") => {
            let mut out = String::new();
            for (id, pid, path, waited) in pending.list() {
                out.push_str(&format!(
                    "pending id={} pid={} waiting={} path={}\n",
                    id,
                    pid,
                    waited.as_secs(),
                    path
                ));
            }
            out.push_str("ok\n");
            out
        }
        Some(verb @ ("ALLOW" | "DENY")) => {
            let allow = verb == "ALLOW";
            match parts.next() {
                Some("*") => {
                    let mut out = String::new();
                    for (_, _, path) in pending.answer_all(allow) {
                        out.push_str(&format!("answered path={path}\n"));
                    }
                    out.push_str("ok\n");
                    out
                }
                Some(tok) => match tok.parse::<u64>() {
                    Ok(id) => match pending.answer(id, allow) {
                        Some((_, path)) => format!("ok path={path}\n"),
                        None => "err not-found\n".to_string(),
                    },
                    Err(_) => "err bad-request\n".to_string(),
                },
                None => "err bad-request\n".to_string(),
            }
        }
        _ => "err bad-request\n".to_string(),
    }
}

/// Map a control command to its response. `LOG` returns the retained events (a `dropped=` line when a
/// `--follow` cursor fell behind the ring, a `head=` cursor, then one `event …` line each) then `ok`;
/// `LOG after=<seq>` returns only events past that cursor. `cmd` is emitted last on an event line so a
/// command's spaces cannot be mistaken for a field separator (the reader takes the whole remainder).
fn dispatch(cmd: &str, ring: &ExecRing) -> String {
    let mut parts = cmd.split_whitespace();
    match parts.next() {
        Some("LOG") => {
            let mut after = None;
            for token in parts {
                if let Some(v) = token.strip_prefix("after=") {
                    after = v.parse().ok();
                }
            }
            let snap = ring.snapshot(after);
            let mut out = String::new();
            if snap.dropped > 0 {
                out.push_str(&format!("dropped={}\n", snap.dropped));
            }
            out.push_str(&format!("head={}\n", snap.head));
            for ev in &snap.events {
                out.push_str(&format_event_line(ev));
            }
            out.push_str("ok\n");
            out
        }
        _ => "err bad-request\n".to_string(),
    }
}

/// Format one event as a control-wire line. The fixed fields are `key=value` tokens; `cmd` is emitted
/// **last** and taken verbatim by the reader (the command carries spaces). The observer has stripped
/// control characters from the command, so it cannot inject a second line.
///
/// `by=` appears only when a caller was read, which keeps every line a policy deciding by target
/// alone produces byte-for-byte what it produced before — and the reader ignores tokens it does not
/// know, so neither side has to be the newer one.
fn format_event_line(ev: &ExecEvent) -> String {
    let by = match ev.caller.is_empty() {
        true => String::new(),
        false => format!("by={} ", ev.caller),
    };
    format!(
        "event seq={} at={} pid={} verdict={} {by}cmd={}\n",
        ev.seq, ev.at_epoch_ms, ev.pid, ev.verdict, ev.command
    )
}

// ── Client side (the `sbx proc logs` process) ─────────────────────────────────────────────────

/// The process-observation control directory under the data dir, where the per-session sockets live.
pub(crate) fn proc_control_dir(data_dir: &Path) -> PathBuf {
    data_dir.join("proc")
}

/// The control socket path for a session pid.
pub(crate) fn proc_control_socket(data_dir: &Path, pid: u32) -> PathBuf {
    proc_control_dir(data_dir).join(format!("control-{pid}.sock"))
}

/// Query one session's control socket for its exec events (`LOG`, or `LOG after=<seq>` for a follow
/// read past a cursor). A session whose socket is absent (not observed, or a dead/stale launch) fails
/// the connect, which the caller distinguishes from an empty log.
pub(crate) fn read_exec_log(socket: &Path, after: Option<u64>) -> io::Result<ExecSnapshot> {
    let stream = UnixStream::connect(socket)?;
    stream.set_read_timeout(Some(Duration::from_secs(10)))?;
    stream.set_write_timeout(Some(Duration::from_secs(10)))?;
    let mut cmd = String::from("LOG");
    if let Some(seq) = after {
        cmd.push_str(&format!(" after={seq}"));
    }
    cmd.push('\n');
    (&stream).write_all(cmd.as_bytes())?;
    (&stream).flush()?;
    let mut events = Vec::new();
    let mut dropped = 0;
    let mut head = 0;
    for line in BufReader::new(&stream).lines() {
        let line = line?;
        if line == "ok" {
            break;
        }
        if let Some(v) = line.strip_prefix("dropped=") {
            dropped = v.parse().unwrap_or(0);
        } else if let Some(v) = line.strip_prefix("head=") {
            head = v.parse().unwrap_or(0);
        } else if let Some(ev) = parse_event_line(&line) {
            events.push(ev);
        }
    }
    Ok(ExecSnapshot {
        events,
        dropped,
        head,
    })
}

/// One parked `execve` awaiting an `ask` decision, as `sbx proc pending` lists it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ParkedView {
    /// The kernel notification id — the token `sbx proc allow`/`deny` decides by.
    pub(crate) id: u64,
    pub(crate) pid: u32,
    pub(crate) waiting_secs: u64,
    pub(crate) path: String,
}

/// List the `execve`s currently parked for a decision on one session's control socket (`LIST`).
pub(crate) fn read_pending(socket: &Path) -> io::Result<Vec<ParkedView>> {
    let reply = query(socket, "LIST")?;
    let mut out = Vec::new();
    for line in reply.lines() {
        if line == "ok" {
            break;
        }
        if let Some(p) = parse_pending_line(line) {
            out.push(p);
        }
    }
    Ok(out)
}

/// Decide one parked `execve` by its notification id (`ALLOW <id>` / `DENY <id>`). Returns the exec
/// path that was decided, or `None` if the id was unknown (already answered / timed out).
pub(crate) fn answer_pending(socket: &Path, id: u64, allow: bool) -> io::Result<Option<String>> {
    let verb = if allow { "ALLOW" } else { "DENY" };
    let reply = query(socket, &format!("{verb} {id}"))?;
    let line = reply.lines().next().unwrap_or("");
    if let Some(path) = line.strip_prefix("ok path=") {
        Ok(Some(path.to_string()))
    } else {
        Ok(None)
    }
}

/// Decide every parked `execve` on a session at once (`ALLOW *` / `DENY *`). Returns each decided path.
pub(crate) fn answer_all_pending(socket: &Path, allow: bool) -> io::Result<Vec<String>> {
    let verb = if allow { "ALLOW" } else { "DENY" };
    let reply = query(socket, &format!("{verb} *"))?;
    Ok(reply
        .lines()
        .filter_map(|l| l.strip_prefix("answered path=").map(str::to_string))
        .collect())
}

/// The outcome of loading a `--session` rule into a running session's overlay.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum InjectOutcome {
    /// The rule was loaded into the session's live overlay.
    Loaded,
    /// The rule was refused as inert — an `allow` into a session not in `ask` mode (under `enforce`
    /// everything not denied already runs, so the allow would do nothing).
    Inert,
    /// The server refused the rule (a malformed rule, or a server without this verb).
    Refused,
}

/// Load a live `--session` rule into one session's overlay (`REMEMBER ALLOW|DENY <rule>`). A session
/// whose socket is absent (not enforcing, or a dead/stale launch) fails the connect, which the caller
/// distinguishes from a refusal.
pub(crate) fn inject_proc_rule(
    socket: &Path,
    verdict: Verdict,
    rule: &str,
) -> io::Result<InjectOutcome> {
    let verb = if verdict == Verdict::Deny {
        "DENY"
    } else {
        "ALLOW"
    };
    let reply = query(socket, &format!("REMEMBER {verb} {rule}"))?;
    let first = reply.lines().next().unwrap_or("");
    Ok(if first == "ok" {
        InjectOutcome::Loaded
    } else if first == "err inert" {
        InjectOutcome::Inert
    } else {
        InjectOutcome::Refused
    })
}

/// One live `--session` overlay rule, as `sbx proc rules` lists it.
pub(crate) struct OverlayRule {
    /// The verdict list the rule is on (`"allow"` / `"deny"`).
    pub(crate) verdict: &'static str,
    pub(crate) rule: String,
}

/// List a session's live `--session` overlay rules (`RULES`). An absent socket (not enforcing / dead)
/// fails the connect, distinguished from an empty overlay.
pub(crate) fn read_overlay_rules(socket: &Path) -> io::Result<Vec<OverlayRule>> {
    let reply = query(socket, "RULES")?;
    let mut out = Vec::new();
    for line in reply.lines() {
        if line == "ok" {
            break;
        }
        if let Some(rest) = line.strip_prefix("rule allow ") {
            out.push(OverlayRule {
                verdict: "allow",
                rule: rest.to_string(),
            });
        } else if let Some(rest) = line.strip_prefix("rule deny ") {
            out.push(OverlayRule {
                verdict: "deny",
                rule: rest.to_string(),
            });
        }
    }
    Ok(out)
}

/// Send one command line to a session's control socket and return the full reply text.
fn query(socket: &Path, cmd: &str) -> io::Result<String> {
    let stream = UnixStream::connect(socket)?;
    stream.set_read_timeout(Some(Duration::from_secs(10)))?;
    stream.set_write_timeout(Some(Duration::from_secs(10)))?;
    (&stream).write_all(format!("{cmd}\n").as_bytes())?;
    (&stream).flush()?;
    let mut reply = String::new();
    BufReader::new(&stream).read_to_string(&mut reply)?;
    Ok(reply)
}

/// Parse one `pending id=… pid=… waiting=… path=…` line, `path` verbatim last.
fn parse_pending_line(line: &str) -> Option<ParkedView> {
    let rest = line.strip_prefix("pending ")?;
    let (head, path) = rest.split_once("path=")?;
    let (mut id, mut pid, mut waiting) = (None, None, None);
    for token in head.split_whitespace() {
        let (key, value) = token.split_once('=')?;
        match key {
            "id" => id = value.parse().ok(),
            "pid" => pid = value.parse().ok(),
            "waiting" => waiting = value.parse().ok(),
            _ => {}
        }
    }
    Some(ParkedView {
        id: id?,
        pid: pid?,
        waiting_secs: waiting?,
        path: path.to_string(),
    })
}

/// Parse one `event seq=… at=… pid=… cmd=…` line back into an event, or `None` if malformed. Every
/// field but `cmd` is a simple `key=value` token; `cmd` is the verbatim remainder after the first
/// `cmd=` (it carries spaces, and the fixed numeric fields precede it, so the first `cmd=` is always
/// the field marker even if the command itself contains `cmd=`).
fn parse_event_line(line: &str) -> Option<ExecEvent> {
    let rest = line.strip_prefix("event ")?;
    let (head, command) = match rest.split_once("cmd=") {
        Some((h, c)) => (h, c.to_string()),
        None => return None,
    };
    let (mut seq, mut at, mut pid) = (None, None, None);
    let (mut verdict, mut caller) = (String::new(), String::new());
    for token in head.split_whitespace() {
        let (key, value) = token.split_once('=')?;
        match key {
            "seq" => seq = value.parse().ok(),
            "at" => at = value.parse().ok(),
            "pid" => pid = value.parse().ok(),
            "verdict" => verdict = value.to_string(),
            "by" => caller = value.to_string(),
            _ => {}
        }
    }
    Some(ExecEvent {
        seq: seq?,
        at_epoch_ms: at?,
        pid: pid?,
        verdict,
        caller,
        command,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The ring's own sequencing and eviction are [`super::super::lens`]'s and tested there. What is
    /// this lens's to get right is the mapping — including that the cheap poll path tags its events
    /// `observe` and reads no caller, which is what keeps its wire line the one it has always been.
    #[test]
    fn push_maps_its_arguments_onto_the_event() {
        let ring = ExecRing::new(10);
        assert_eq!(ring.push(100, "rg foo"), 1);
        assert_eq!(
            ring.push_verdict(101, "/bin/bash", "/usr/bin/git", "deny"),
            2
        );
        let snap = ring.snapshot(None);
        assert_eq!(snap.events.len(), 2);
        assert_eq!(snap.events[0].pid, 100);
        assert_eq!(snap.events[0].command, "rg foo");
        assert_eq!(snap.events[0].verdict, "observe");
        assert_eq!(snap.events[0].caller, "");
        assert_eq!(snap.events[1].verdict, "deny");
        assert_eq!(snap.events[1].caller, "/bin/bash");
        assert_eq!(snap.events[1].command, "/usr/bin/git");
    }

    #[test]
    fn an_event_line_round_trips_including_a_command_with_spaces_and_an_equals() {
        // The command carries spaces and its own `cmd=`/`=`; it must survive the verbatim-last framing.
        let ev = ExecEvent {
            seq: 7,
            at_epoch_ms: 1_700_000_000_123,
            pid: 4242,
            verdict: "deny".to_string(),
            caller: "/nix/store/x/bin/bash".to_string(),
            command: "sh -c FOO=bar cmd=baz --flag=v".to_string(),
        };
        let line = format_event_line(&ev);
        let line = line.trim_end();
        assert_eq!(parse_event_line(line), Some(ev));
    }

    /// A policy that decides by target alone reads no caller, and the line it produces must be the
    /// one it produced before there was a field for it — a reader on either side of the change sees
    /// the same bytes.
    #[test]
    fn an_event_with_no_caller_carries_no_field_for_one() {
        let ev = ExecEvent {
            seq: 1,
            at_epoch_ms: 2,
            pid: 3,
            verdict: "allow".to_string(),
            caller: String::new(),
            command: "/bin/rg".to_string(),
        };
        let line = format_event_line(&ev);
        assert_eq!(line, "event seq=1 at=2 pid=3 verdict=allow cmd=/bin/rg\n");
        assert_eq!(parse_event_line(line.trim_end()), Some(ev));
    }

    #[test]
    fn parse_rejects_a_line_without_a_command_field_or_the_prefix() {
        assert_eq!(parse_event_line("event seq=1 at=2 pid=3"), None);
        assert_eq!(parse_event_line("noise seq=1 at=2 pid=3 cmd=x"), None);
    }

    #[test]
    fn serve_answers_a_log_query_over_a_real_socket() {
        use crate::testutil::TmpDir;
        let dir = TmpDir::new();
        let socket = dir.join("proc.sock");
        let ring = Arc::new(ExecRing::new(10));
        ring.push(200, "node agent.js");
        ring.push(201, "rg --json needle");
        let listener = UnixListener::bind(&socket).unwrap();
        let serve_ring = ring.clone();
        std::thread::spawn(move || {
            let _ = serve(listener, serve_ring);
        });

        // A tail read sees both events; a follow read past seq 1 sees only the second.
        let all = read_exec_log(&socket, None).unwrap();
        assert_eq!(all.events.len(), 2);
        assert_eq!(all.head, 2);
        assert_eq!(all.events[1].command, "rg --json needle");

        let tail = read_exec_log(&socket, Some(1)).unwrap();
        assert_eq!(tail.events.iter().map(|e| e.seq).collect::<Vec<_>>(), [2]);
    }

    #[test]
    fn dispatch_enforced_remember_loads_the_overlay_and_rules_lists_it() {
        let ring = ExecRing::new(4);
        let pending = crate::sandbox::proc_enforce::PendingExec::new();
        let overlay = ProcOverlay::new();
        let policy = proc_policy::ProcPolicy::new(ProcMode::Ask, &[], &[]);

        // REMEMBER DENY loads the deny list; the folded decision then denies the target.
        assert_eq!(
            dispatch_enforced(
                "REMEMBER DENY curl",
                &ring,
                &pending,
                &overlay,
                ProcMode::Ask
            ),
            "ok\n"
        );
        assert_eq!(overlay.decide(&policy, &[], "/bin/curl"), Verdict::Deny);

        // REMEMBER ALLOW under ask un-parks a target that would otherwise park.
        assert_eq!(
            dispatch_enforced(
                "REMEMBER ALLOW git",
                &ring,
                &pending,
                &overlay,
                ProcMode::Ask
            ),
            "ok\n"
        );
        assert_eq!(overlay.decide(&policy, &[], "/usr/bin/git"), Verdict::Allow);

        // RULES lists what was loaded, then `ok`.
        let listing = dispatch_enforced("RULES", &ring, &pending, &overlay, ProcMode::Ask);
        assert!(listing.contains("rule allow git"), "{listing}");
        assert!(listing.contains("rule deny curl"), "{listing}");
        assert!(listing.trim_end().ends_with("ok"));
    }

    #[test]
    fn dispatch_enforced_refuses_an_inert_allow_and_a_malformed_remember() {
        let ring = ExecRing::new(4);
        let pending = crate::sandbox::proc_enforce::PendingExec::new();
        let overlay = ProcOverlay::new();

        // An allow into an enforce session is inert → refused, nothing loaded.
        assert_eq!(
            dispatch_enforced(
                "REMEMBER ALLOW git",
                &ring,
                &pending,
                &overlay,
                ProcMode::Enforce
            ),
            "err inert\n"
        );
        assert!(overlay.snapshot().is_empty());

        // A malformed REMEMBER (no verdict word) is a bad request.
        assert_eq!(
            dispatch_enforced("REMEMBER curl", &ring, &pending, &overlay, ProcMode::Ask),
            "err bad-request\n"
        );

        // A deny is always live under enforce.
        assert_eq!(
            dispatch_enforced(
                "REMEMBER DENY curl",
                &ring,
                &pending,
                &overlay,
                ProcMode::Enforce
            ),
            "ok\n"
        );
    }
}
