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
//! reach this socket would let it read its own observation and, under enforcement, answer its own
//! parked `execve` or load a rule. The ring itself is the supervisor's owner-only RAM for the
//! session's lifetime and dies with it; the record file a launch may ask for, and what holds where a
//! bind shows the data dir to the cage anyway, are the same as for every lens ([`super::lens`]).
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

/// Make `value` safe to occupy one whitespace-split `key=value` token of an event line's **head**.
///
/// `ExecEvent` is the only lens whose head carries a free-form field: every other one
/// (`fs_control`, `broker_control`, `signer_control`, `sshagent_control`) puts its free text in the
/// *tail*, after the marker, where `lens::read_event_line` takes it verbatim. `by=<caller>` sits
/// among the head tokens instead, and the head is parsed as `split_whitespace()` then
/// `split_once('=')` with the field closure called **in order**, later tokens overwriting earlier
/// ones.
///
/// The caller is the target of `/proc/<pid>/exe`, so a cage names it by naming its own binary. A
/// path holding ` pid=1 verdict=allow ` therefore rewrote the event's own pid and verdict on the way
/// back in, and one holding a space but no `=` made `split_once` return `None`, which fails the
/// whole parse and *erases* the event. `observe_feed::sanitize` does not close either: it maps
/// control characters to **spaces**, so it turns a newline into exactly the separator that breaks
/// the head.
///
/// Whitespace and `=` cannot appear in a head token, so they are replaced. It costs fidelity on a
/// legitimate path containing a space — which the head parse could not carry either way, and which
/// used to drop the event rather than render it oddly. Every other control character is replaced
/// too: a head token is printed as well as parsed, and an escape kept here would drive the terminal
/// that reads `sbx proc logs`. What reaches this through [`ExecRing::push_verdict`] is sanitised
/// first, so on that path nothing is left for it to catch; it is what makes the token safe on its
/// own, whatever is handed to it.
fn head_token(value: &str) -> String {
    value
        .chars()
        .map(|c| {
            if c.is_whitespace() || c == '=' || c.is_control() {
                '_'
            } else {
                c
            }
        })
        .collect()
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
/// [`push`](ExecRing::push)es) and the control serve thread (which [`snapshot`](ExecRing::snapshot)s
/// for `sbx proc logs`). The sequencing and eviction are [`super::lens::Ring`]'s; what this adds is
/// the shape of an exec event, and the two ways one arrives.
pub(crate) struct ExecRing(super::lens::Ring<ExecEvent>);

impl ExecRing {
    pub(crate) fn new(cap: usize) -> Self {
        ExecRing(super::lens::Ring::new(cap))
    }

    /// Attach this session's record, so the events also reach a file that outlives the session.
    /// Relayed to [`super::lens::Ring::with_record`]; `None` leaves the ring memory-only.
    pub(crate) fn with_record(mut self, record: Option<super::lens::Recorder>) -> Self {
        self.0 = self.0.with_record(record);
        self
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
    ///
    /// The verdict is one of a few fixed words today, and it is still made a head token here: it
    /// sits among the whitespace-split head fields, and nothing in a `&str` says it is one of those
    /// words. A verdict spelling `deny pid=1` would rewrite the pid beside it on the way back in, the
    /// way a caller path could ([`head_token`]).
    pub(crate) fn push_verdict(&self, pid: u32, caller: &str, command: &str, verdict: &str) -> u64 {
        let caller = head_token(&super::observe_feed::sanitize(caller));
        let command = super::observe_feed::sanitize(command);
        let verdict = head_token(&super::observe_feed::sanitize(verdict));
        // Sanitised above rather than in here: `push_with` runs its closure under the ring's lock,
        // which is for building the event and nothing else.
        self.0.push_with(move |seq, at_epoch_ms| ExecEvent {
            seq,
            at_epoch_ms,
            pid,
            verdict,
            caller,
            command,
        })
    }

    /// The events past `after` — [`super::lens::Ring::snapshot`], and the only part of the ring
    /// this lens hands out.
    ///
    /// The ring itself stays private to this module. Its [`push_with`](super::lens::Ring::push_with)
    /// takes an event as given, so a ring reachable from outside would be a second door, one where
    /// no caller or command is sanitised, and nothing would say a new producer had used it.
    pub(crate) fn snapshot(&self, after: Option<u64>) -> ExecSnapshot {
        self.0.snapshot(after)
    }
}

/// Serve the control socket, answering `LOG` from the ring the observer pushes to. See
/// [`super::lens::serve`].
pub(crate) fn serve(listener: UnixListener, ring: Arc<ExecRing>) -> io::Result<()> {
    super::lens::serve(listener, move |cmd| super::lens::dispatch_log(cmd, &ring.0))
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
        Some("LOG") => super::lens::dispatch_log(cmd, &ring.0),
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
///
/// A session that answers `err …` fails the read ([`read_within`]): an observing session serves
/// `LOG` alone, and its refusal is not a list of nothing parked.
pub(crate) fn read_pending_within(socket: &Path, timeout: Duration) -> io::Result<Vec<ParkedView>> {
    let mut out = Vec::new();
    for line in read_within(socket, "LIST", timeout, PARKED_ANSWER_MAX)? {
        if let Some(p) = parse_pending_line(&line) {
            out.push(p);
        }
    }
    Ok(out)
}

/// Decide one parked `execve` by its notification id (`ALLOW <id>` / `DENY <id>`). Returns the exec
/// path that was decided, or `None` if the session holds no such id (already answered / timed out).
///
/// Only `err not-found` means that. Any other `err …` is a session that refused the verb, an
/// observing one among them, and is an error ([`super::reply::refused`]); so is an answer that did
/// not arrive whole ([`answer_line`]), after which the exec may or may not have been decided. Read
/// as an unknown id, either one told the user the exec had been decided or had timed out.
pub(crate) fn answer_pending(socket: &Path, id: u64, allow: bool) -> io::Result<Option<String>> {
    let verb = if allow { "ALLOW" } else { "DENY" };
    let line = answer_line(socket, &format!("{verb} {id}"))?;
    match line.strip_prefix("ok path=") {
        Some(path) => Ok(Some(path.to_string())),
        None if line == "err not-found" => Ok(None),
        None => Err(super::reply::refused(&line)),
    }
}

/// Decide every parked `execve` on a session at once (`ALLOW *` / `DENY *`). Returns each decided
/// path, none when nothing was parked.
///
/// The answer is taken whole ([`read_within`]): a server's `err …` is an error, the refusal of a
/// session that does not decide, rather than nothing decided, and an answer cut before its `ok` is
/// an error too. By then some of the parked `execve`s may have been decided, so the caller cannot
/// say which, and says that, rather than list the paths that arrived as all there were.
pub(crate) fn answer_all_pending(socket: &Path, allow: bool) -> io::Result<Vec<String>> {
    let verb = if allow { "ALLOW" } else { "DENY" };
    Ok(read_within(
        socket,
        &format!("{verb} *"),
        QUERY_TIMEOUT,
        PARKED_ANSWER_MAX,
    )?
    .into_iter()
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
/// distinguishes from a refusal. So does an answer that did not arrive whole ([`answer_line`]): the
/// rule may have been loaded before it was cut, and a refusal would say it is not in force.
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
    let first = answer_line(socket, &format!("REMEMBER {verb} {rule}"))?;
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
/// fails the connect, distinguished from an empty overlay, and a session answering `err …` fails the
/// read ([`read_within`]).
///
/// This answer has no ceiling of its own: the overlay holds every rule the host loaded into it, as
/// many as were loaded, so any bound would be one a real listing could run past.
pub(crate) fn read_overlay_rules(socket: &Path) -> io::Result<Vec<OverlayRule>> {
    let mut out = Vec::new();
    for line in read_within(socket, "RULES", QUERY_TIMEOUT, u64::MAX)? {
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

/// The decimal digits of the largest `u64`, and of the largest `u32`: the widest a number on a
/// `pending` row can be written.
const U64_DIGITS: usize = u64::MAX.ilog10() as usize + 1;
const U32_DIGITS: usize = u32::MAX.ilog10() as usize + 1;

/// The longest line the server of this socket writes about a parked `execve`, which is also the
/// longest it answers a verb that acts with ([`dispatch_enforced`]). Of the three shapes, a `LIST`
/// row is the longest: three numbers ahead of the path, where the `ok path=` of an answer by id
/// and the `answered path=` of `ALLOW *` carry the path alone (a `REMEMBER` is answered by a
/// word). The path is sanitised on its way into the registry, so it holds at most
/// [`SANITIZED_CHARS`](super::SANITIZED_CHARS) characters, of four bytes each at most.
///
/// A `LOG` event line can run longer, with a caller and a command each that long. It is read by
/// [`super::lens::read_log`], never against this bound.
const LINE_MAX: usize = "pending id= pid= waiting= path=\n".len()
    + 2 * U64_DIGITS
    + U32_DIGITS
    + 4 * super::SANITIZED_CHARS;

/// The most an answer about the parked `execve`s can hold: a line for each of the most a session
/// parks at once ([`super::proc_enforce::ASK_PENDING_CAP`]), then its `ok`. A reader stops there, so
/// an answer that runs on is read as one cut short ([`super::reply`]) and never held in full.
const PARKED_ANSWER_MAX: u64 =
    (super::proc_enforce::ASK_PENDING_CAP * LINE_MAX + "ok\n".len()) as u64;

/// Send `cmd` and read the one line a verb that acts is answered with, at most [`LINE_MAX`] bytes.
///
/// A line that ends before its newline is an [`io::ErrorKind::UnexpectedEof`] error, which
/// [`super::reply::unanswered`] counts: the session closed before it had answered, or wrote a line
/// longer than any it answers such a verb with. Either way it was reached and its answer did not
/// arrive whole, so what the verb did is not known, and a caller says so rather than read the
/// fragment as a refusal. The line is read as bytes and decoded only once whole, for the reason
/// [`super::reply::answer`] does: a cut inside a character is a cut, not a decode error no caller
/// counts as one.
fn answer_line(socket: &Path, cmd: &str) -> io::Result<String> {
    let stream = send(socket, cmd, QUERY_TIMEOUT)?;
    let mut line = Vec::new();
    BufReader::new((&stream).take(LINE_MAX as u64)).read_until(b'\n', &mut line)?;
    match line.strip_suffix(b"\n") {
        Some(whole) => Ok(String::from_utf8_lossy(whole).into_owned()),
        None => Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "the session's answer ended before its line did",
        )),
    }
}

/// Send `cmd` and take its answer whole ([`super::reply`]): the lines before the closing `ok`, read
/// from at most `most` bytes. An answer cut before its `ok`, or one running past `most`, is an error a
/// caller tells from an empty answer.
///
/// So is a server's `err …` line ([`super::reply::refused`]). An observing session serves `LOG`
/// alone and refuses every other verb with one, and a refusal read as a whole answer listed nothing
/// parked, no rule loaded, and nothing decided.
fn read_within(socket: &Path, cmd: &str, timeout: Duration, most: u64) -> io::Result<Vec<String>> {
    let stream = send(socket, cmd, timeout)?;
    let mut lines = Vec::new();
    for line in super::reply::answer(BufReader::new((&stream).take(most))) {
        let line = line?;
        if line.starts_with("err ") {
            return Err(super::reply::refused(&line));
        }
        lines.push(line);
    }
    Ok(lines)
}

/// Connect to a session's control socket and send it one command line, the connect and the write
/// both under `timeout`. A plain `UnixStream::connect` cannot be bounded, and one to a listener whose
/// backlog is full sleeps until the backlog drains ([`super::broker::connect_unix_within`]), which a
/// supervisor that stopped accepting never lets happen.
///
/// A command carrying a control character is refused before anything is sent. The server reads one
/// line, so a newline in a `REMEMBER` rule would end the command early, load the part before it as
/// a rule of its own and answer `ok`, and the caller would report the whole rule loaded. The rule
/// grammar every caller admits rules through refuses one already ([`proc_policy::validate_rule`]);
/// this keeps the wire from depending on that.
fn send(socket: &Path, cmd: &str, timeout: Duration) -> io::Result<UnixStream> {
    if cmd.chars().any(char::is_control) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "a control command must not contain control characters",
        ));
    }
    let stream = super::broker::connect_unix_within(socket, timeout)?;
    stream.set_read_timeout(Some(timeout))?;
    stream.set_write_timeout(Some(timeout))?;
    (&stream).write_all(format!("{cmd}\n").as_bytes())?;
    (&stream).flush()?;
    Ok(stream)
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
    /// A caller spelling one used to be a different matter — `by=` sits among the whitespace-split
    /// head tokens, so the sanitiser's newline-to-space left a token the head parse either read as
    /// another field or choked on, costing the event its readability. [`head_token`] closes that, so
    /// the assertion is now that the event survives *and stays readable*, not merely that nothing
    /// was forged.
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
            assert_eq!(
                read.len(),
                1,
                "one event in, one event out — neither forged nor erased: {line:?}"
            );
            assert_eq!(
                (read[0].pid, read[0].verdict.as_str()),
                (7, "deny"),
                "the cage dictated an event of its own: {line:?}"
            );
        }
    }

    /// The same rule the observer already applied, now applied to everything the ring takes — an
    /// escape sequence in a target path drives the terminal that reads `sbx proc logs`, and the two
    /// producers pushing here are written apart.
    ///
    /// The caller takes one step more than the command, and the difference is where each sits on the
    /// wire. `cmd` is the verbatim tail, so a space in it is just a space; `by=` is a head token, and
    /// the sanitiser *produces* spaces (it maps every control character to one), so on the caller it
    /// would hand the head parse the separator that breaks it. See [`head_token`].
    #[test]
    fn control_characters_are_stripped_whichever_producer_pushed() {
        let ring = ExecRing::new(10);
        ring.push(100, "rg \u{1b}[2J");
        ring.push_verdict(101, "/bin/\u{7}bash", "/usr/bin/gi\tt", "deny");
        let snap = ring.snapshot(None);
        assert_eq!(snap.events[0].command, "rg  [2J");
        assert_eq!(
            snap.events[1].caller, "/bin/_bash",
            "a control character in the caller must not become a head separator"
        );
        assert_eq!(snap.events[1].command, "/usr/bin/gi t");
    }

    /// A head token is safe on its own, not only after the sanitiser: a control character that is
    /// not whitespace (an escape, a bell, DEL) breaks no parse, so only this rule keeps it from the
    /// terminal that prints the token.
    #[test]
    fn a_head_token_carries_no_control_character() {
        assert_eq!(
            head_token("/bin/\u{1b}[2Jba\u{7}sh\u{7f}"),
            "/bin/_[2Jba_sh_"
        );
        assert_eq!(head_token("a b=c\nd"), "a_b_c_d");
    }

    /// The head is parsed as `split_whitespace()` then `split_once('=')`, with the field closure
    /// called in order and later tokens overwriting earlier ones. The caller is the target of
    /// `/proc/<pid>/exe`, so a cage picks it by naming its own binary — and a path spelling
    /// `pid=1 verdict=allow` rewrote the event's own pid and verdict on the way back in, while one
    /// carrying a space but no `=` failed the whole parse and erased the event.
    #[test]
    fn a_caller_path_cannot_overwrite_or_erase_the_fields_beside_it() {
        for caller in [
            "/tmp/evil pid=1 verdict=allow",
            "/tmp/evil seq=999",
            "/tmp/a plain space",
        ] {
            let ring = ExecRing::new(10);
            ring.push_verdict(7, caller, "/usr/bin/git", "deny");
            let line = ring.snapshot(None).events[0].format_line();
            let read = ExecEvent::parse_line(line.trim_end())
                .unwrap_or_else(|| panic!("the event was erased by its caller: {line:?}"));
            assert_eq!(
                (read.pid, read.verdict.as_str(), read.seq),
                (7, "deny", 1),
                "the caller rewrote a field beside it: {line:?}"
            );
            assert_eq!(read.command, "/usr/bin/git");
        }
    }

    /// The verdict is a head token like the caller, and is held to the same rule. Every producer
    /// passes one of a few fixed words, but the parameter is a `&str`, and a verdict carrying a space
    /// and an `=` rewrote the fields after it on the way back in, or erased the event when a token
    /// had no `=`. A policy deciding by target alone passes no caller, so the line has no `by=` of
    /// its own, and a verdict spelling one would have named a caller nobody read.
    #[test]
    fn a_verdict_cannot_overwrite_or_erase_the_fields_beside_it() {
        for (caller, verdict) in [
            ("/bin/bash", "deny pid=1 seq=999"),
            ("/bin/bash", "deny\nevent seq=998 pid=1"),
            ("/bin/bash", "deny plain"),
            ("", "deny by=/tmp/evil"),
        ] {
            let ring = ExecRing::new(10);
            ring.push_verdict(7, caller, "/usr/bin/git", verdict);
            let line = ring.snapshot(None).events[0].format_line();
            let read = ExecEvent::parse_line(line.trim_end())
                .unwrap_or_else(|| panic!("the event was erased by its verdict: {line:?}"));
            assert_eq!(
                (read.pid, read.seq, read.caller.as_str()),
                (7, 1, caller),
                "the verdict rewrote a field beside it: {line:?}"
            );
            assert_eq!(read.command, "/usr/bin/git");
        }
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

    /// A rule that would not reach the server as one line is never sent. The socket here does not
    /// exist, so a rule that got as far as the connect fails there instead, with `NotFound`.
    #[test]
    fn a_rule_carrying_a_control_character_is_refused_before_it_is_sent() {
        let dir = crate::testutil::TmpDir::new();
        let socket = dir.join("absent.sock");
        for rule in ["curl\nsh", "curl\rsh", "curl\u{1b}sh"] {
            let e = inject_proc_rule(&socket, Verdict::Deny, rule)
                .expect_err("a rule with a control character must not load");
            assert_eq!(e.kind(), io::ErrorKind::InvalidInput, "{rule:?}: {e}");
        }
        let e = inject_proc_rule(&socket, Verdict::Deny, "curl").expect_err("no socket");
        assert_eq!(
            e.kind(),
            io::ErrorKind::NotFound,
            "a clean rule goes as far as the connect"
        );
    }

    /// A session whose listener stopped accepting does not hold a reader past its budget.
    ///
    /// Once a listener's backlog is full, a plain connect sleeps until it drains, and a supervisor
    /// that stopped accepting (stopped by a signal, or wedged) never drains it: `sbx proc pending`,
    /// `sbx proc logs` and the completion oracle waited there for good, whatever timeout they had
    /// asked for. A backlog of zero holds one connection, so every reader after it is the one that
    /// waits. Both doors are tried: the verbs this module sends, and the `LOG` read every lens shares.
    #[test]
    fn a_session_that_stopped_accepting_does_not_hold_the_reader() {
        use crate::testutil::TmpDir;
        use std::os::fd::AsRawFd;
        let dir = TmpDir::new();
        let socket = dir.join("full.sock");
        let listener = UnixListener::bind(&socket).expect("bind");
        // SAFETY: listen(2) on a listening socket this test owns; it only lowers the backlog.
        assert_eq!(unsafe { libc::listen(listener.as_raw_fd(), 0) }, 0);
        let _queued = UnixStream::connect(&socket).expect("the first connection fits the backlog");

        type Reader = fn(&Path) -> io::Result<()>;
        let readers: [(&str, Reader); 2] = [
            ("LIST", |s| {
                read_pending_within(s, Duration::from_millis(200)).map(drop)
            }),
            ("LOG", |s| read_exec_log(s, None).map(drop)),
        ];
        let (tx, rx) = std::sync::mpsc::channel();
        for (name, read) in readers {
            let (tx, socket) = (tx.clone(), socket.clone());
            std::thread::spawn(move || {
                let _ = tx.send((name, read(&socket).map_err(|e| e.kind())));
            });
        }
        for _ in 0..readers.len() {
            let (name, read) = rx
                .recv_timeout(Duration::from_secs(30))
                .expect("a reader is still held by a listener that never accepts");
            assert_eq!(
                read,
                Err(io::ErrorKind::WouldBlock),
                "{name}: the connect must end on its budget"
            );
        }
        drop(listener);
    }

    /// Bind `socket`, take one connection, read its command line, write `wire` and close: a session
    /// whose answer is exactly those bytes. Both directions are bounded, so a reader that never sends
    /// its command, or stops reading, ends the stand-in rather than holding it.
    fn answer_once(socket: &Path, wire: Vec<u8>) -> std::thread::JoinHandle<()> {
        let listener = UnixListener::bind(socket).expect("bind the stand-in session");
        std::thread::spawn(move || {
            if let Ok((conn, _)) = listener.accept() {
                let _ = conn.set_read_timeout(Some(Duration::from_secs(5)));
                let _ = conn.set_write_timeout(Some(Duration::from_secs(5)));
                let mut command = String::new();
                let _ = BufReader::new(&conn).read_line(&mut command);
                let _ = (&conn).write_all(&wire);
            }
        })
    }

    /// Ask a stand-in session answering `wire` through `read`, one connection each.
    fn ask_once<T>(
        socket: &Path,
        wire: &[u8],
        read: impl Fn(&Path) -> io::Result<T>,
    ) -> io::Result<T> {
        let _ = std::fs::remove_file(socket);
        let session = answer_once(socket, wire.to_vec());
        let got = read(socket);
        session.join().expect("the stand-in session");
        got
    }

    /// An observing session serves `LOG` alone and answers every other verb `err bad-request`. Read as
    /// a whole answer, that refusal listed nothing parked and no rule, decided nothing for `*`, and
    /// made an id unknown, "already decided or timed out". Each reader fails on it now, with an error
    /// that is not a cut, so a listing passes over the session and a decision says why none was made.
    #[test]
    fn an_observing_session_refuses_the_ask_verbs_rather_than_answering_none() {
        use crate::testutil::TmpDir;
        let dir = TmpDir::new();
        let socket = dir.join("observe.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        let ring = Arc::new(ExecRing::new(10));
        std::thread::spawn(move || {
            let _ = serve(listener, ring);
        });
        type Reader = fn(&Path) -> io::Result<()>;
        let readers: [(&str, Reader); 4] = [
            ("LIST", |s| read_pending(s).map(drop)),
            ("RULES", |s| read_overlay_rules(s).map(drop)),
            ("ALLOW <id>", |s| answer_pending(s, 1, true).map(drop)),
            ("ALLOW *", |s| answer_all_pending(s, true).map(drop)),
        ];
        for (verb, read) in readers {
            match read(&socket) {
                Ok(()) => panic!("{verb}: an observing session's refusal read as an answer"),
                Err(e) => {
                    assert_eq!(e.kind(), io::ErrorKind::InvalidData, "{verb}: {e}");
                    assert!(
                        !crate::sandbox::reply::unanswered(&e),
                        "{verb}: a refusal is not a cut"
                    );
                }
            }
        }
    }

    /// A verb that acts may have acted by the time its answer is cut. Read at face value, a cut
    /// answer to `ALLOW <id>` made the id unknown, one to `ALLOW *` listed the paths that happened to
    /// arrive as all there were, and one to `REMEMBER` was a refusal: each a claim about what the
    /// session did that it never made. Each is an error [`super::super::reply::unanswered`] counts
    /// now, and a whole answer reads as it did.
    #[test]
    fn a_decision_whose_answer_is_cut_is_not_read_as_made_or_refused() {
        use crate::testutil::TmpDir;
        type Ask = fn(&Path) -> io::Result<String>;
        let by_id: Ask = |s| answer_pending(s, 7, true).map(|p| format!("{p:?}"));
        let all: Ask = |s| answer_all_pending(s, true).map(|p| format!("{p:?}"));
        let load: Ask = |s| inject_proc_rule(s, Verdict::Deny, "curl").map(|o| format!("{o:?}"));
        let dir = TmpDir::new();
        let socket = dir.join("answer.sock");
        for (wire, read, want) in [
            (&b"ok path=/bin/sh\n"[..], by_id, r#"Some("/bin/sh")"#),
            (&b"err not-found\n"[..], by_id, "None"),
            (&b"answered path=/bin/sh\nok\n"[..], all, r#"["/bin/sh"]"#),
            (&b"ok\n"[..], all, "[]"),
            (&b"ok\n"[..], load, "Loaded"),
            (&b"err inert\n"[..], load, "Inert"),
            (&b"err bad-request\n"[..], load, "Refused"),
        ] {
            let got = ask_once(&socket, wire, read);
            assert_eq!(
                got.as_deref().map_err(io::Error::kind),
                Ok(want),
                "a whole answer {wire:?}"
            );
        }
        for (wire, read) in [
            (&b""[..], by_id),
            (&b"ok path=/bin/sh"[..], by_id),
            (&b""[..], all),
            (&b"answered path=/bin/sh\n"[..], all),
            (&b""[..], load),
            (&b"o"[..], load),
        ] {
            let got = ask_once(&socket, wire, read);
            assert!(
                got.as_ref().is_err_and(crate::sandbox::reply::unanswered),
                "a cut answer {wire:?} read as {got:?}"
            );
        }
    }

    /// A reader takes no more of an answer than a session can write, so one that runs on is read as
    /// cut and never held whole. The bound comes from the server's own limits: a row for each
    /// `execve` it can park at once, each as long as a sanitised path makes it. So a full answer of
    /// the longest rows is still read whole, and one twice as long is not.
    #[test]
    fn an_answer_is_read_up_to_the_longest_a_session_writes_and_no_further() {
        use crate::sandbox::proc_enforce::ASK_PENDING_CAP;
        use crate::testutil::TmpDir;
        let dir = TmpDir::new();
        let socket = dir.join("answer.sock");
        // The longest path a parked row carries: what the sanitiser makes of a long name written in
        // four-byte characters.
        let path =
            crate::sandbox::sanitize(&"\u{1d11e}".repeat(2 * crate::sandbox::SANITIZED_CHARS));
        let row = format!(
            "pending id={} pid={} waiting={} path={path}\n",
            u64::MAX,
            u32::MAX,
            u64::MAX
        );
        assert!(
            row.len() <= LINE_MAX && row.len() + 4 > LINE_MAX,
            "{}",
            row.len()
        );
        let answered = format!("answered path={path}\n");
        let answer = |line: &str, rows: usize| (line.repeat(rows) + "ok\n").into_bytes();
        let list = |s: &Path| read_pending_within(s, QUERY_TIMEOUT).map(|v| v.len());
        let all = |s: &Path| answer_all_pending(s, true).map(|v| v.len());

        assert_eq!(
            ask_once(&socket, &answer(&row, ASK_PENDING_CAP), list).ok(),
            Some(ASK_PENDING_CAP)
        );
        assert_eq!(
            ask_once(&socket, &answer(&answered, ASK_PENDING_CAP), all).ok(),
            Some(ASK_PENDING_CAP)
        );
        for (verb, got) in [
            (
                "LIST",
                ask_once(&socket, &answer(&row, 2 * ASK_PENDING_CAP), list),
            ),
            (
                "ALLOW *",
                ask_once(&socket, &answer(&answered, 2 * ASK_PENDING_CAP), all),
            ),
        ] {
            assert!(
                got.as_ref().is_err_and(crate::sandbox::reply::unanswered),
                "{verb}: an answer past the longest a session writes read as {got:?}"
            );
        }
        for long in [
            format!("ok path={}\n", "x".repeat(LINE_MAX)),
            format!("ok path={}\n", "\u{1d11e}".repeat(LINE_MAX / 4 + 1)),
        ] {
            let got = ask_once(&socket, long.as_bytes(), |s| answer_pending(s, 7, true));
            assert!(
                got.as_ref().is_err_and(crate::sandbox::reply::unanswered),
                "a line past the longest a session writes read as {got:?}"
            );
        }
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
    /// The record is written through [`super::redact::redact_string`], so a credential that reached
    /// a lens becomes `${NAME}` on the way to disk. That substitution happens on the **whole**
    /// formatted line, fixed fields included, so the round trip has to survive it: a reader that
    /// could not parse a redacted line would present a session with a secret in it as a session with
    /// no events at all.
    ///
    /// The needle sits in `caller=` as well as in the verbatim tail, because a placeholder landing in a
    /// fixed field is the case a tail-only fixture would never reach.
    #[test]
    fn a_redacted_event_line_still_parses_back() {
        let ev = ExecEvent {
            seq: 7,
            at_epoch_ms: 1_700_000_000_123,
            pid: 4242,
            verdict: "deny".to_string(),
            caller: "/tmp/zzsecretvalue0123/bash".to_string(),
            command: "curl -H authorization:zzsecretvalue0123".to_string(),
        };
        let needles = vec![crate::sandbox::proxy::SecretNeedle::named(
            "API_TOKEN",
            b"zzsecretvalue0123".to_vec(),
        )];
        let (line, n) = crate::sandbox::redact::redact_string(
            &ev.format_line(),
            &needles,
            &crate::sandbox::redact::Placeholder::Plain,
        );
        assert!(n > 0, "the fixture must actually carry the needle");
        assert!(!line.contains("zzsecretvalue0123"), "{line}");
        let back =
            ExecEvent::parse_line(line.trim_end()).expect("a redacted line must still parse");
        assert_eq!(back.seq, 7);
        assert_eq!(back.pid, 4242);
        assert_eq!(back.verdict, "deny");
        assert_eq!(back.caller, "/tmp/${API_TOKEN}/bash");
        assert_eq!(back.command, "curl -H authorization:${API_TOKEN}");
    }
}
