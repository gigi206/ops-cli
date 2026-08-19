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

use std::io::{self, BufReader, Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use super::proc_enforce::ProcOverlay;
use crate::proc_policy::{self, ProcMode, Verdict};

/// The default number of recent exec events a session retains for the live feed.
pub(crate) const EXEC_RING_CAP: usize = 1000;

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

    /// The fixed fields are `key=value` tokens; `cmd` is emitted **last** and taken verbatim by the
    /// reader (the command carries spaces). Both free-form fields reach the ring already stripped of
    /// control characters ([`ExecRing::push_verdict`]), so neither can inject a second line — the
    /// stripping is the ring's, not each producer's, because the two that push here (the `/proc`
    /// observer and the seccomp enforcer) are written apart and only one of them used to do it.
    ///
    /// `by=` appears only when a caller was read, which keeps every line a policy deciding by target
    /// alone produces byte-for-byte what it produced before — and the reader ignores tokens it does
    /// not know, so neither side has to be the newer one.
    fn format_line(&self) -> String {
        let by = match self.caller.is_empty() {
            true => String::new(),
            false => format!("by={} ", self.caller),
        };
        format!(
            "event seq={} at={} pid={} verdict={} {by}cmd={}\n",
            self.seq, self.at_epoch_ms, self.pid, self.verdict, self.command
        )
    }

    /// Read one `event seq=… at=… pid=… cmd=…` line back, or `None` if malformed.
    fn parse_line(line: &str) -> Option<Self> {
        let (mut seq, mut at, mut pid) = (None, None, None);
        let (mut verdict, mut caller) = (String::new(), String::new());
        let command = super::lens::read_event_line(line, "cmd=", |key, value| match key {
            "seq" => seq = value.parse().ok(),
            "at" => at = value.parse().ok(),
            "pid" => pid = value.parse().ok(),
            "verdict" => verdict = value.to_string(),
            "by" => caller = value.to_string(),
            _ => {}
        })?;
        Some(ExecEvent {
            seq: seq?,
            at_epoch_ms: at?,
            pid: pid?,
            verdict,
            caller,
            command: command.to_string(),
        })
    }
}

/// The result of a `LOG` query over this lens. See [`super::lens::Snapshot`].
pub(crate) type ExecSnapshot = super::lens::Snapshot<ExecEvent>;

/// A bounded ring of recent exec events. Shared (via `Arc`) between the observer thread (which
/// [`push`](ExecRing::push)es) and the control serve thread (which [`snapshot`](super::lens::Ring::snapshot)s
/// for `sbx proc logs`). The sequencing and eviction are [`super::lens::Ring`]'s; what this adds is
/// the shape of an exec event, and the two ways one arrives.
pub(crate) struct ExecRing(super::lens::Ring<ExecEvent>);

impl ExecRing {
    pub(crate) fn new(cap: usize) -> Self {
        ExecRing(super::lens::Ring::new(cap))
    }

    /// Append one observed exec (the non-enforcing `/proc` poll path — verdict `observe`). Returns
    /// the assigned sequence.
    pub(crate) fn push(&self, pid: u32, command: &str) -> u64 {
        self.push_verdict(pid, "", command, "observe")
    }

    /// Append one enforced exec (the seccomp user-notification path), tagged with its `verdict`
    /// (`allow` / `deny` / `ask` / `absent`) and the `caller` that issued it (empty where the policy
    /// decides by target alone). `command` is the exec target path. Returns the assigned sequence.
    ///
    /// Both free-form values are sanitised **here**, on the way in, rather than by each producer.
    /// They are the two an in-cage caller chooses: the target path is read out of the calling
    /// process's own memory and the caller is the link `/proc/<pid>/exe` resolves to, so both may
    /// carry any byte a Linux path may carry — a newline included, which on the line-based control
    /// wire would end the event and let what follows read as a second, forged one. One door, because
    /// the two producers are written apart: the observer sanitised its command and the enforcer did
    /// not, and a duty stated in a doc comment is exactly the kind the second implementation misses.
    /// Sanitising is idempotent, so the path that already did it is unchanged.
    ///
    /// This is not the decision's view of either value: a verdict is reached on the raw path, above,
    /// and only what is *reported* passes through here.
    pub(crate) fn push_verdict(&self, pid: u32, caller: &str, command: &str, verdict: &str) -> u64 {
        let caller = super::observe_feed::sanitize(caller);
        let command = super::observe_feed::sanitize(command);
        // Sanitised above rather than in here: `push_with` runs its closure under the ring's lock,
        // which is for building the event and nothing else.
        self.0.push_with(move |seq, at_epoch_ms| ExecEvent {
            seq,
            at_epoch_ms,
            pid,
            verdict: verdict.to_string(),
            caller,
            command,
        })
    }
}

/// The ring underneath, so a snapshot reads the same on this lens as on any other: `snapshot` is
/// [`super::lens::Ring`]'s and is reached through here, while `push` above stays this lens's own.
impl std::ops::Deref for ExecRing {
    type Target = super::lens::Ring<ExecEvent>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

/// Serve the control socket, answering `LOG` from the ring the observer pushes to. See
/// [`super::lens::serve`].
pub(crate) fn serve(listener: UnixListener, ring: Arc<ExecRing>) -> io::Result<()> {
    super::lens::serve(listener, move |cmd| super::lens::dispatch_log(cmd, &ring))
}

/// Serve the control socket for an **enforcing** session (`[proc] mode = enforce|ask`): like
/// [`serve`], but the dispatch also answers the `ask` decision verbs (`LIST` the parked `execve`s,
/// `ALLOW`/`DENY <id>` or `*` to decide them) against the shared [`PendingExec`](super::proc_enforce::PendingExec).
pub(crate) fn serve_enforced(
    listener: UnixListener,
    ring: Arc<ExecRing>,
    pending: Arc<super::proc_enforce::PendingExec>,
    overlay: Arc<ProcOverlay>,
    mode: ProcMode,
) -> io::Result<()> {
    super::lens::serve(listener, move |cmd| {
        dispatch_enforced(cmd, &ring, &pending, &overlay, mode)
    })
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
        Some("LOG") => super::lens::dispatch_log(cmd, ring),
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

// ── Client side (the `sbx proc logs` process) ─────────────────────────────────────────────────

/// The process-observation control directory under the data dir, where the per-session sockets live.
pub(crate) fn proc_control_dir(data_dir: &Path) -> PathBuf {
    data_dir.join("proc")
}

/// The control socket path for a session pid.
pub(crate) fn proc_control_socket(data_dir: &Path, pid: u32) -> PathBuf {
    super::lens::control_socket(&proc_control_dir(data_dir), pid)
}

/// Query one session's control socket for its exec events. A session whose socket is absent (not
/// observed, or a dead/stale launch) fails the connect, which the caller distinguishes from an empty
/// log. See [`super::lens::read_log`].
pub(crate) fn read_exec_log(socket: &Path, after: Option<u64>) -> io::Result<ExecSnapshot> {
    super::lens::read_log(socket, after)
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
    read_pending_within(socket, QUERY_TIMEOUT)
}

/// [`read_pending`] under a caller-chosen deadline — see [`GLANCE_TIMEOUT`].
pub(crate) fn read_pending_within(socket: &Path, timeout: Duration) -> io::Result<Vec<ParkedView>> {
    let reply = query_within(socket, "LIST", timeout)?;
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

/// How long a query the user typed waits on a session that is slow to answer. Generous:
/// the caller is a verb whose whole job is that answer, and a wrong verdict is worse than
/// a wait.
const QUERY_TIMEOUT: Duration = Duration::from_secs(10);

/// The budget a query made *on the user's behalf* gets — the completion oracle, which runs
/// on a keystroke. A session that does not answer inside it is reported as holding nothing,
/// because a menu that is one item short is better than a prompt that stalls.
pub(crate) const GLANCE_TIMEOUT: Duration = Duration::from_millis(150);

/// Send one command line to a session's control socket and return the full reply text.
fn query(socket: &Path, cmd: &str) -> io::Result<String> {
    query_within(socket, cmd, QUERY_TIMEOUT)
}

/// [`query`] under a caller-chosen deadline, for a caller that would rather come back empty
/// than wait.
fn query_within(socket: &Path, cmd: &str, timeout: Duration) -> io::Result<String> {
    let stream = UnixStream::connect(socket)?;
    stream.set_read_timeout(Some(timeout))?;
    stream.set_write_timeout(Some(timeout))?;
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sandbox::lens::Event as _;

    /// Neither free-form field can put a second line on the wire. Both are the cage's to choose —
    /// the exec target is read out of the calling process's memory and the caller is what
    /// `/proc/<pid>/exe` points at — and a Linux path may carry a newline, so an event answering
    /// `sbx proc logs` could otherwise be followed by one the cage wrote, claiming any verdict it
    /// liked for any pid.
    ///
    /// What the reader takes back is the measure, not the text: `cmd` is verbatim to end of line, so
    /// a *command* spelling an event line is simply part of that command and never a second event.
    /// A caller spelling one is a different matter — `by=` sits among the whitespace-split head
    /// tokens, so the attempt costs the event its readability rather than forging anything, and that
    /// framing is recorded as its own defect.
    #[test]
    fn neither_the_target_nor_the_caller_can_forge_a_second_event_line() {
        let forged = "event seq=999 at=0 pid=1 verdict=allow cmd=/bin/sh";
        for (caller, command) in [
            ("/bin/bash", format!("/tmp/x\n{forged}")),
            (
                // The same attempt through the caller: a binary sitting at a path spelling a line.
                "/tmp/y\nevent seq=998 at=0 pid=1 verdict=allow cmd=/bin/sh",
                "/usr/bin/git".to_string(),
            ),
        ] {
            let ring = ExecRing::new(10);
            ring.push_verdict(7, caller, &command, "deny");
            let snap = ring.snapshot(None);
            let line = snap.events[0].format_line();
            assert_eq!(
                line.matches('\n').count(),
                1,
                "one event, one line: {line:?}"
            );
            // Read the wire back the way `sbx proc logs` does, line by line.
            let read: Vec<ExecEvent> = line.lines().filter_map(ExecEvent::parse_line).collect();
            assert!(
                read.len() <= 1,
                "the wire carried more than one event: {read:?}"
            );
            for ev in read {
                assert_eq!(
                    (ev.pid, ev.verdict.as_str()),
                    (7, "deny"),
                    "the cage dictated an event of its own: {line:?}"
                );
            }
        }
    }

    /// The same rule the observer already applied, now applied to everything the ring takes — an
    /// escape sequence in a target path drives the terminal that reads `sbx proc logs`, and the two
    /// producers pushing here are written apart.
    #[test]
    fn control_characters_are_stripped_whichever_producer_pushed() {
        let ring = ExecRing::new(10);
        ring.push(100, "rg \u{1b}[2J");
        ring.push_verdict(101, "/bin/\u{7}bash", "/usr/bin/gi\tt", "deny");
        let snap = ring.snapshot(None);
        assert_eq!(snap.events[0].command, "rg  [2J");
        assert_eq!(snap.events[1].caller, "/bin/ bash");
        assert_eq!(snap.events[1].command, "/usr/bin/gi t");
    }

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
        let line = ev.format_line();
        let line = line.trim_end();
        assert_eq!(ExecEvent::parse_line(line), Some(ev));
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
        let line = ev.format_line();
        assert_eq!(line, "event seq=1 at=2 pid=3 verdict=allow cmd=/bin/rg\n");
        assert_eq!(ExecEvent::parse_line(line.trim_end()), Some(ev));
    }

    #[test]
    fn parse_rejects_a_line_without_a_command_field_or_the_prefix() {
        assert_eq!(ExecEvent::parse_line("event seq=1 at=2 pid=3"), None);
        assert_eq!(ExecEvent::parse_line("noise seq=1 at=2 pid=3 cmd=x"), None);
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
