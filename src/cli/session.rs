//! `sbx session <subcommand>` (alias `sbx sessions`): every operation on a live sandbox session —
//! `ls` lists the on-disk registry, `logs` reads a detached session's output, `attach` enters a
//! running cage, `stop` ends sessions.

use std::ffi::OsString;
use std::path::Path;
use std::process::ExitCode;
use std::time::Duration;

use crate::{
    diag, format_age, help, layout_or_fail, live_sessions, sandbox, session, style, uptime_seconds,
};

/// `sbx session <subcommand>` (alias `sbx sessions`): the namespace grouping every operation on a
/// live sandbox session — `ls` lists them, `attach` runs a shell or a command inside one, `stop`
/// ends them.
///
/// A `--help` at any depth is intercepted by [`help::maybe_help`], which resolves the deepest
/// subcommand named — under its own name or an accepted alias — and shows that page. A bare
/// `sbx session` prints the namespace page; an unknown subcommand is a usage error.
pub(crate) fn session_cmd(args: &[OsString]) -> ExitCode {
    if let Some(code) = help::maybe_help("session", args) {
        return code;
    }
    match args.first().and_then(|a| a.to_str()) {
        Some("ls") | Some("list") => {
            let (json, rest) = crate::split_json_flag(&args[1..]);
            match crate::cli::reject_extra(&["session", "ls"], &rest) {
                Err(code) => code,
                Ok(()) => list_sessions(json),
            }
        }
        Some("logs") | Some("log") => logs_cmd(&args[1..]),
        Some("attach") => attach_cmd(&args[1..]),
        Some("stop") => stop_cmd(args[1..].to_vec()),
        None => {
            err!("{}", help::page_usage(&["session"]).unwrap_or_default());
            ExitCode::from(2)
        }
        Some(other) => {
            diag::error(&format!("sbx: session: unknown subcommand `{other}`"));
            diag::hint("       run `sbx help session` for usage.");
            ExitCode::from(2)
        }
    }
}

/// One rendered `sbx session ls` row. Materialised before printing so every column can flex to
/// its widest value; named rather than a tuple because the columns are same-typed strings that a
/// positional swap would silently transpose.
struct Row {
    name: String,
    kind: String,
    mode: String,
    pid: String,
    age: String,
    project: String,
}

/// How a session was launched, as the `MODE` column shows it: `detached` for a background daemon
/// (`--detach`), `foreground` for one running in the terminal that started it.
///
/// This is exactly the "does it have a log" answer — a detached session's stdout/stderr is
/// redirected to a file `sbx session logs` can read, a foreground one's is on the user's own
/// terminal — so the column doubles as the guide to which sessions that verb applies to.
fn session_mode(s: &session::Session) -> &'static str {
    if s.detached { "detached" } else { "foreground" }
}

/// `sbx session ls [--json]`: list the live sandbox sessions from the on-disk registry. Reading
/// the registry re-validates and prunes dead records as a side effect, so the
/// list is always current without a daemon.
///
/// `--json` emits the registry's own values rather than this table's: the age is the raw number of
/// seconds, not `2h13m`, and an unknowable age is `null` rather than `?`. A consumer wants the
/// number it can compare; the table wants the string a reader can scan. The empty case is an empty
/// array, never the prose line, so a script does not have to distinguish "no sessions" from a
/// parse failure.
fn list_sessions(json: bool) -> ExitCode {
    let layout = match layout_or_fail() {
        Ok(l) => l,
        Err(code) => return code,
    };
    let sessions = match live_sessions(layout.data_dir()) {
        Ok(s) => s,
        Err(code) => return code,
    };
    let uptime = uptime_seconds();
    // SAFETY: `sysconf` takes a single integer name and returns a process-wide configuration value;
    // no pointer is passed and nothing is mutated.
    let ticks = unsafe { libc::sysconf(libc::_SC_CLK_TCK) };
    if json {
        let age_secs = |s: &session::Session| -> Option<u64> {
            let up = uptime?;
            if ticks <= 0 {
                return None;
            }
            let started = s.start_ticks as f64 / ticks as f64;
            Some((up - started).max(0.0) as u64)
        };
        let rows: Vec<serde_json::Value> = sessions
            .iter()
            .map(|s| {
                serde_json::json!({
                    "name": sandbox::cage_name(s.app(), &s.project),
                    "kind": s.label(),
                    "app": s.app(),
                    "detached": s.detached,
                    "pid": s.pid,
                    "age_seconds": age_secs(s),
                    "project": s.project.display().to_string(),
                })
            })
            .collect();
        if let Err(code) = crate::print_json("session ls", &serde_json::json!({ "sessions": rows }))
        {
            return code;
        }
        return ExitCode::SUCCESS;
    }
    if sessions.is_empty() {
        outln!("sbx: no active sandbox sessions.");
        return ExitCode::SUCCESS;
    }

    let ticks_per_sec = ticks;
    // Each row is materialized first so the column widths can flex to the widest value: an
    // app session's KIND is `app:<name>` and a cage name is `sbx-<slug>`, either of which can
    // exceed a fixed width and shift every following column out of alignment.
    let rows: Vec<Row> = sessions
        .iter()
        .map(|s| {
            let age = match uptime {
                Some(up) if ticks_per_sec > 0 => {
                    let started = s.start_ticks as f64 / ticks_per_sec as f64;
                    format_age((up - started).max(0.0) as u64)
                }
                _ => "?".to_string(),
            };
            Row {
                name: sandbox::cage_name(s.app(), &s.project),
                kind: s.label(),
                mode: session_mode(s).to_string(),
                pid: s.pid.to_string(),
                age,
                project: s.project.display().to_string(),
            }
        })
        .collect();

    // NAME is the cage's own name — the same `sbx-<slug>` its systemd scope and in-cage hostname
    // show — so a session cross-references with the host tooling. An app session's KIND is
    // `app:<name>`, so the user can tell which sessions are agents (and that `sbx session
    // attach`/`sbx session stop` act on that app's isolated environment). MODE says where the
    // session's output went, which is the one thing the other columns cannot convey: only a
    // `detached` session has a log for `sbx session logs` to read.
    //
    // Rendered by the shared table renderer rather than by a local width calculation, because a
    // listing that reads differently from verb to verb is one the reader has to re-learn each
    // time — and because that renderer measures a cell in characters. This one measured bytes,
    // on the assumption that cage slugs and app names are ASCII, so a non-ASCII app label
    // mis-padded every following column.
    style::print_table(
        &["NAME", "KIND", "MODE", "PID", "AGE", "PROJECT"],
        &[
            style::Align::Left,
            style::Align::Left,
            style::Align::Left,
            style::Align::Right,
            style::Align::Right,
            style::Align::Left,
        ],
        &rows
            .iter()
            .map(|r| {
                vec![
                    r.name.clone(),
                    r.kind.clone(),
                    r.mode.clone(),
                    r.pid.clone(),
                    r.age.clone(),
                    r.project.clone(),
                ]
            })
            .collect::<Vec<_>>(),
    );
    ExitCode::SUCCESS
}

/// `sbx session attach <id> [-- command [args...]]`: enter a running session's live cage. With no
/// command it opens an interactive shell; with `-- command` it runs that command inside the cage
/// (through a pty when stdin is a terminal, inherited stdio otherwise). The operand before any `--`
/// is the PID `sbx session ls` shows — exactly one; a missing, extra, or non-UTF-8 operand, or a
/// bare `--` with no command, is a usage error; a well-formed id that matches no live session is
/// reported by `attach` itself.
fn attach_cmd(args: &[OsString]) -> ExitCode {
    // Everything after the first `--` is the command to run in the cage; before it is the id alone.
    let dashdash = args.iter().position(|a| a == "--");
    let (head, cmd): (&[OsString], &[OsString]) = match dashdash {
        Some(i) => (&args[..i], &args[i + 1..]),
        None => (args, &[]),
    };
    let usage = || {
        diag::error(&format!(
            "sbx: usage: {}   (the PID shown by `sbx session ls`)",
            help::synopsis_of(&["session", "attach"])
        ));
        ExitCode::from(2)
    };
    // A `--` with nothing after it is a mistake (attach either takes a command or opens a shell).
    if dashdash.is_some() && cmd.is_empty() {
        return usage();
    }
    let Some(id) = (head.len() == 1).then(|| head[0].to_str()).flatten() else {
        return usage();
    };
    sandbox::attach(id, cmd)
}

/// The default grace period between SIGTERM and SIGKILL for `sbx session stop`: long enough for an agent to
/// finish writing and shut down cleanly, short enough not to hang. `--delay` overrides it.
const STOP_DEFAULT_DELAY: Duration = Duration::from_secs(10);

/// `sbx session stop <id>... [--delay <secs>]` / `sbx session stop --all [--delay <secs>]`: stop
/// running sessions. With ids, stop the named ones (the pids `sbx session ls` shows); with `--all`,
/// stop every live session.
///
/// Sends SIGTERM, then SIGKILL after the grace delay (default 10s; `--delay 0` escalates at once).
/// Either ids or `--all` is required (not both); a non-UTF-8 operand or a malformed `--delay` value
/// is a usage error. A bare `--` ends the options: every token after it is taken as an id.
fn stop_cmd(args: Vec<OsString>) -> ExitCode {
    match parse_stop_args(args) {
        Err(code) => code,
        Ok(parsed) => {
            let id_refs: Vec<&str> = parsed.ids.iter().map(String::as_str).collect();
            sandbox::stop(&id_refs, parsed.delay, parsed.all)
        }
    }
}

/// The parsed form of `sbx session stop`: which sessions to end, and how long to wait between
/// SIGTERM and SIGKILL.
struct StopArgs {
    ids: Vec<String>,
    delay: Duration,
    all: bool,
}

/// Parse `sbx session stop`'s arguments. Kept apart from [`stop_cmd`] so the grammar — the `--`
/// terminator, the unknown-flag refusal, and the either/or between ids and `--all` — is unit-tested
/// without signalling anything. `Err` carries the code the caller returns, the refusal already
/// reported.
fn parse_stop_args(args: Vec<OsString>) -> Result<StopArgs, ExitCode> {
    let mut delay = STOP_DEFAULT_DELAY;
    let mut all = false;
    let mut ids: Vec<String> = Vec::new();
    // Set by a bare `--`: everything after it is an id, whatever it looks like.
    let mut only_ids = false;
    let mut it = args.into_iter();
    while let Some(arg) = it.next() {
        match arg.to_str() {
            Some("--delay") if !only_ids => {
                let Some(value) = it.next() else {
                    diag::error("sbx: --delay needs a value in seconds (e.g. --delay 10).");
                    return Err(ExitCode::from(2));
                };
                match value.to_str().and_then(|v| v.parse::<u64>().ok()) {
                    // The grace becomes `Instant::now() + d` in [`crate::session::wait_for_exit`],
                    // and that addition panics on a duration the clock cannot represent. A config
                    // duration is already held to this ceiling for exactly that reason
                    // (`config::parse_duration`); this door was the one that let a value straight
                    // through, so `--delay 18446744073709551615` aborted the stop with a panic
                    // instead of refusing an unusable number.
                    Some(secs) if secs > crate::config::DURATION_MAX_SECS => {
                        diag::error(&format!(
                            "sbx: --delay may name at most {} seconds, not '{}'.",
                            crate::config::DURATION_MAX_SECS,
                            value.to_string_lossy()
                        ));
                        return Err(ExitCode::from(2));
                    }
                    Some(secs) => delay = Duration::from_secs(secs),
                    None => {
                        diag::error(&format!(
                            "sbx: --delay must be a whole number of seconds, not '{}'.",
                            value.to_string_lossy()
                        ));
                        return Err(ExitCode::from(2));
                    }
                }
            }
            Some("--all") if !only_ids => all = true,
            // The options end here, as they do for `sbx run` and the rule fronts. Taken for an id
            // instead, `--` named a session that cannot exist — ids are PIDs — so
            // `sbx session stop -- 1234` stopped 1234 cleanly and then reported a phantom target,
            // exiting 2 on a stop that had worked.
            Some("--") if !only_ids => only_ids = true,
            // An unrecognised flag is refused, not taken for an id. It was pushed onto `ids`, so a
            // mistyped `--dry-run` became a session to stop rather than an error — and a verb whose
            // job is to kill things must not read a flag it does not know as a target.
            Some(flag) if !only_ids && flag.starts_with('-') => {
                diag::error(&format!(
                    "sbx: unknown option '{flag}' for `session stop` (ids are the PIDs shown by \
                     `sbx session ls`; `--all` stops every session)."
                ));
                return Err(ExitCode::from(2));
            }
            Some(id) => ids.push(id.to_string()),
            None => {
                diag::error(
                    "sbx: stop ids must be valid text (the PID shown by `sbx session ls`).",
                );
                return Err(ExitCode::from(2));
            }
        }
    }
    if all && !ids.is_empty() {
        diag::error("sbx: stop takes either explicit ids or --all, not both.");
        return Err(ExitCode::from(2));
    }
    if !all && ids.is_empty() {
        diag::error(&format!(
            "sbx: usage: {}\n   (ids are the PIDs shown by `sbx session ls`)",
            help::synopsis_of(&["session", "stop"])
        ));
        return Err(ExitCode::from(2));
    }
    Ok(StopArgs { ids, delay, all })
}

/// How long `sbx session logs --follow` waits between polls of the log file. Short enough that a
/// followed session reads as live, cheap enough to cost nothing over an agent's whole run.
const FOLLOW_POLL: Duration = Duration::from_millis(250);

/// The parsed form of `sbx session logs`.
struct LogsArgs {
    /// The session id — the PID `sbx session ls` shows, which is also the log file's name.
    id: u32,
    follow: bool,
    /// `-n <N>`: show only the last N lines. Caps the initial listing, not the followed stream
    /// (the same split `sbx net logs` makes).
    limit: Option<usize>,
    /// `--all`: show every incarnation in the file, not just the most recent session's output.
    all: bool,
}

/// Parse `sbx session logs <id> [-f|--follow] [-n <N>] [--all]`.
///
/// The id is required and must be a PID: it is not looked up in the registry (a dead session has
/// no record, and reading a dead session's output is the main reason this verb exists), so it is
/// validated by shape here and resolved against the filesystem by the caller.
fn parse_logs_args(args: &[OsString]) -> Result<LogsArgs, String> {
    let (mut id, mut follow, mut limit, mut all) = (None, false, None, false);
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.to_str() {
            Some("--follow") | Some("-f") => follow = true,
            Some("--all") => all = true,
            Some("-n") | Some("--lines") => {
                let val = it.next().ok_or("`-n` needs a count")?;
                let n: usize = val.to_str().and_then(|s| s.parse().ok()).ok_or_else(|| {
                    format!(
                        "invalid count `{}` — expected a whole number",
                        val.to_string_lossy()
                    )
                })?;
                limit = Some(n);
            }
            // A bare operand is the id. A second one is a mistake, not a second target: this verb
            // reads one session's output, and silently ignoring the extra could show the wrong one.
            Some(other) if !other.starts_with('-') => {
                if id.is_some() {
                    return Err("takes exactly one session id".into());
                }
                id = Some(other.parse::<u32>().map_err(|_| {
                    format!(
                        "invalid session id `{other}` — expected a PID, as `sbx session ls` shows"
                    )
                })?);
            }
            _ => {
                return Err(format!(
                    "usage: {}",
                    help::synopsis_of(&["session", "logs"])
                ));
            }
        }
    }
    let id = id.ok_or_else(|| {
        format!(
            "usage: {}   (the PID shown by `sbx session ls`)",
            help::synopsis_of(&["session", "logs"])
        )
    })?;
    Ok(LogsArgs {
        id,
        follow,
        limit,
        all,
    })
}

/// How much of a log is read from its end before a reading is answered without holding it:
/// streamed from the session's header ([`last_header_at`]) or counted back on disk
/// ([`tail_start`]).
///
/// A session's log is whatever the agent printed, which is not a size sbx chooses: a verbose build
/// leaves hundreds of megabytes. Reading the whole file to print twenty lines of it would make the
/// memory the command needs the memory the agent spent, and a question about a long-running agent
/// would cost as much as the agent's own output.
///
/// This window is what a question is normally answered from. It is generous because the point is
/// not to be small, it is to be **bounded**: a log ten times this size costs the same here.
const TAIL_WINDOW_MAX: u64 = 8 * 1024 * 1024;

/// How much of the file is read at a time, in either direction.
const LOG_CHUNK: u64 = 64 * 1024;

/// The last `want` bytes of `path`, or the whole file when it is shorter — plus whether the window
/// does reach the start, which tells the caller its answer is complete, and the length the file had
/// when it was looked at.
///
/// That length is returned rather than asked for again later because a `--follow` resumes from it: a
/// second `metadata` after this read would name a different end for a session still writing, and the
/// bytes in between would be printed by nobody and followed by nobody.
fn tail_bytes(path: &Path, want: u64) -> std::io::Result<(Vec<u8>, bool, u64)> {
    use std::io::{Read as _, Seek as _, SeekFrom};
    let mut file = std::fs::File::open(path)?;
    let len = file.metadata()?.len();
    let from = len.saturating_sub(want);
    file.seek(SeekFrom::Start(from))?;
    let mut buf = Vec::with_capacity((len - from) as usize);
    file.take(len - from).read_to_end(&mut buf)?;
    Ok((buf, from == 0, len))
}

/// Grow a window back from the end of `path` until it holds what the caller has to see, and no
/// further.
///
/// `want_lines` is the `-n` limit when there is one: a window holding that many line breaks holds
/// the answer, whatever the rest of the file weighs. `stop_at_header` says whether reaching the last
/// session's header also ends the search — true for the ordinary reading, which is about that
/// session alone, and false under `--all`, where a line limit counts back across every session.
///
/// Returns the window and whether it is **complete**: it reached the start of the file, or it holds
/// the header the reading is bounded by. A `false` there is not a failure. A window that holds the
/// start of the lines a line limit counts back over still holds the answer. Otherwise the reading
/// reaches past [`TAIL_WINDOW_MAX`], and the caller answers it without holding the file: an
/// unlimited reading is streamed from the header, and a line limit is counted back on disk
/// ([`tail_start`]).
fn tail_window(
    path: &Path,
    want_lines: Option<usize>,
    stop_at_header: bool,
) -> std::io::Result<(Vec<u8>, bool, u64)> {
    let mut want = LOG_CHUNK;
    loop {
        let (buf, whole, len) = tail_bytes(path, want)?;
        let has_header = stop_at_header && last_session(&buf).0.is_some();
        // More breaks than the limit means the window already holds every byte `tail_lines` will
        // count back over, so growing it further would read what is not going to be printed.
        let enough_lines =
            want_lines.is_some_and(|n| buf.iter().filter(|&&b| b == b'\n').count() > n);
        if whole || has_header || enough_lines || want >= TAIL_WINDOW_MAX {
            return Ok((buf, whole || has_header, len));
        }
        want = (want * 4).min(TAIL_WINDOW_MAX);
    }
}

/// Where the last session's body starts in `path`, and the header that opens it — found by reading
/// the file in fixed chunks rather than holding it.
///
/// The fallback for a session whose output is longer than [`TAIL_WINDOW_MAX`]: an unlimited reading
/// is streamed from here, and a line limit counted back on disk ([`tail_start`]) stops here, rather
/// than either being truncated or buffered. A line longer than [`LOG_CHUNK`] cannot be a header, so
/// the carry is dropped and the scan picks up at the next break — which keeps this pass bounded
/// whatever the log holds.
fn last_header_at(path: &Path) -> std::io::Result<(Option<sandbox::SessionHeader>, u64)> {
    use std::io::Read as _;
    let mut file = std::fs::File::open(path)?;
    let mut chunk = vec![0u8; LOG_CHUNK as usize];
    let (mut at, mut carry, mut dropping) = (0u64, Vec::new(), false);
    let mut found = (None, 0u64);
    loop {
        let n = file.read(&mut chunk)?;
        if n == 0 {
            break;
        }
        let mut rest = &chunk[..n];
        while let Some(i) = rest.iter().position(|&b| b == b'\n') {
            let line_end = at + (n - rest.len()) as u64 + i as u64;
            if !dropping {
                carry.extend_from_slice(&rest[..i]);
                if let Some(h) = sandbox::parse_session_header(&carry) {
                    found = (Some(h), line_end + 1);
                }
            }
            carry.clear();
            dropping = false;
            rest = &rest[i + 1..];
        }
        if !dropping {
            carry.extend_from_slice(rest);
            if carry.len() > LOG_CHUNK as usize {
                carry.clear();
                dropping = true;
            }
        }
        at += n as u64;
    }
    Ok(found)
}

/// Split a log into its most recent session's header and body.
///
/// The log is append-only and keyed by pid, so a pid the kernel reuses writes into the file its
/// predecessor left. Taking everything after the *last* header is what keeps a listing honest:
/// without it, a reused pid's log would present a dead session's output as this one's. A log with
/// no header at all (written before headers existed) is returned whole — degraded, never wrong.
fn last_session(log: &[u8]) -> (Option<sandbox::SessionHeader>, &[u8]) {
    let mut found: Option<(sandbox::SessionHeader, usize)> = None;
    let mut pos = 0usize;
    while pos < log.len() {
        let end = log[pos..]
            .iter()
            .position(|&b| b == b'\n')
            .map(|i| pos + i)
            .unwrap_or(log.len());
        if let Some(h) = sandbox::parse_session_header(&log[pos..end]) {
            found = Some((h, (end + 1).min(log.len())));
        }
        pos = end + 1;
    }
    match found {
        Some((h, body_start)) => (Some(h), &log[body_start..]),
        None => (None, log),
    }
}

/// Where the last `n` newline-delimited lines of a text begin, counted back from its end over
/// pieces handed over last first. A single trailing newline does not count as an empty final line,
/// so `-n 1` on output ending in `\n` shows the last real line, not nothing.
///
/// The one definition of a line limit, for a body held in memory ([`tail_lines`]) and for one read
/// back from disk a chunk at a time ([`tail_start`]).
struct LinesBack {
    n: usize,
    seen: usize,
    at_end: bool,
}

impl LinesBack {
    fn new(n: usize) -> Self {
        LinesBack {
            n,
            seen: 0,
            at_end: true,
        }
    }

    /// Count back over `piece`, the bytes just before every piece already counted: the index in it
    /// where the last `n` lines begin, or `None` when they begin further back.
    fn back_over(&mut self, piece: &[u8]) -> Option<usize> {
        if self.n == 0 {
            return Some(piece.len());
        }
        let mut rest = piece;
        if self.at_end && !piece.is_empty() {
            self.at_end = false;
            rest = piece.strip_suffix(b"\n").unwrap_or(piece);
        }
        while let Some(i) = rest.iter().rposition(|&b| b == b'\n') {
            self.seen += 1;
            if self.seen == self.n {
                return Some(i + 1);
            }
            rest = &rest[..i];
        }
        None
    }
}

/// The last `n` lines of `body`, as [`LinesBack`] counts them.
fn tail_lines(body: &[u8], n: usize) -> &[u8] {
    match LinesBack::new(n).back_over(body) {
        Some(at) => &body[at..],
        None => body,
    }
}

/// Where the last `n` lines of the bytes `[floor, end)` of `path` begin, as [`LinesBack`] counts
/// them: the answer to a line limit no window holds.
///
/// Read back from `end` one [`LOG_CHUNK`] at a time, so what it holds is a chunk whatever the lines
/// weigh. Nothing before `floor` is read, and lines that reach back past it begin at it.
fn tail_start(path: &Path, n: usize, floor: u64, end: u64) -> std::io::Result<u64> {
    use std::os::unix::fs::FileExt as _;
    let file = std::fs::File::open(path)?;
    let mut lines = LinesBack::new(n);
    let mut chunk = vec![0u8; LOG_CHUNK as usize];
    let mut at = end;
    while at > floor {
        let from = at.saturating_sub(LOG_CHUNK).max(floor);
        let piece = &mut chunk[..(at - from) as usize];
        file.read_exact_at(piece, from)?;
        if let Some(i) = lines.back_over(piece) {
            return Ok(from + i as u64);
        }
        at = from;
    }
    Ok(floor)
}

/// Whether the registry still holds a live record for `id`.
///
/// Goes through the registry rather than a bare `kill(pid, 0)` so the decisive test stays the
/// `(pid, start_ticks)` match: a pid the kernel has since handed to an unrelated process must not
/// read as this session still running, which would leave `--follow` waiting forever on a file
/// nothing will ever append to.
///
/// The pair answers that for every reuser but one. `id` is a bare pid, and a *new* sbx session
/// landing on that number registers a live record under it: the registry holds the pair, this holds
/// only the number, and the two cannot be compared. The follow then reads as live — of the later
/// incarnation. The pid is the whole of what the user types and of what names the log file the two
/// sessions already share, so what would separate them is an id carrying the incarnation: a change
/// to the surface rather than to this function.
///
/// `Err` is the line to print when the registry cannot be read. Whether the session runs is then
/// not known, and is not answered as "exited": that ended a `--follow` at exit 0 with "nothing
/// further will be written" about a session that may still be writing.
fn session_is_live(data_dir: &Path, id: u32) -> Result<bool, String> {
    crate::asked_sessions(data_dir).map(|sessions| sessions.iter().any(|s| s.pid == id))
}

/// The refusal of a follow whose session cannot be told running or exited: following on would wait
/// for an end it could not see, and stopping quietly would say the session had ended.
fn not_followed(id: u32, why: &str) -> String {
    format!("sbx: {why} — whether session {id} still runs is not known, so its log is not followed")
}

/// `sbx session logs <id> [-f] [-n <N>] [--all]`: show a detached session's output.
///
/// The id is resolved straight to the log file, **not** through the session registry. That is the
/// load-bearing choice: the registry prunes a record the moment its process dies, so a lookup
/// would fail exactly in the case this verb exists for — reading why a background agent stopped.
/// The registry is consulted only to enrich (live or exited) and to explain an absent log.
///
/// The log's bytes go to stdout verbatim, so redirecting gives exactly what the agent wrote; the
/// context line goes to stderr, the same split `sbx session attach` makes for a piped command.
fn logs_cmd(args: &[OsString]) -> ExitCode {
    let parsed = match parse_logs_args(args) {
        Ok(v) => v,
        Err(e) => {
            diag::error(&format!("sbx: session logs: {e}"));
            return ExitCode::from(2);
        }
    };
    let layout = match layout_or_fail() {
        Ok(l) => l,
        Err(code) => return code,
    };
    let data_dir = layout.data_dir();
    let path = sandbox::detach_log_path(data_dir, parsed.id);

    // What has to be held to answer is not what the file holds. A session's log is as long as its
    // agent was talkative, so reading all of it to print twenty lines of it would make the command
    // cost whatever the agent spent. Everything is answered from a window at the end of the file;
    // the three cases a window cannot answer are streamed instead: the whole file under `--all`, a
    // session longer than the window, and a line limit whose lines begin before the window.
    // Copies `[at, until)`, and no further: the file is append-only and may be growing, so an
    // unbounded copy would print past the point a `--follow` then resumes from and repeat it.
    // `until` is the length the read that produced this answer saw, never a second `metadata` — two
    // looks at a file being written name two different ends, and the bytes between them are printed
    // by nobody and followed by nobody. Neither half is reachable from a test: both need a writer
    // appending inside the microseconds between two statements. What is asserted is the ordinary
    // output; this is the reasoning, stated where the bound is.
    //
    // `Err` carries the code the caller returns. A write that fails ends the reading there, which
    // is what keeps a `--follow` from polling into a pipe nobody holds, and is accounted for as
    // every verb's unwritable output is (`crate::cli::note_output_failure`): a reader that walked
    // away (`… | head`) leaves exit 0, since Rust ignores `SIGPIPE` and the write error is the only
    // notice of it, and anything else, a full disk under `> file`, is said once and exits 1. A log
    // that cannot be read is a failure of its own, named by its path.
    let unreadable = |e: std::io::Error| {
        diag::error(&format!(
            "sbx: cannot read the session log {}: {e}",
            path.display()
        ));
        ExitCode::FAILURE
    };
    let stream_range = |at: u64, until: u64| -> Result<(), ExitCode> {
        use std::io::{Read as _, Seek as _};
        let mut f = std::fs::File::open(&path).map_err(unreadable)?;
        if at > 0 {
            f.seek(std::io::SeekFrom::Start(at)).map_err(unreadable)?;
        }
        match copy_log(f.take(until.saturating_sub(at)), &mut std::io::stdout()) {
            Ok(()) => Ok(()),
            Err(CopyFailed::Read(e)) => Err(unreadable(e)),
            Err(CopyFailed::Write(e)) => Err(undelivered(&e)),
        }
    };

    // `--all` with no limit copies the whole file, so it needs no window at all — only the header
    // for the note, which the fallback below reads without holding anything. Asking for one anyway
    // would grow it to `TAIL_WINDOW_MAX` hunting a header these bytes are not used for.
    let windowed = parsed.limit.is_some() || !parsed.all;
    let read = if windowed {
        tail_window(&path, parsed.limit, !parsed.all)
    } else {
        // Still touch the file, so a log that is not there is explained rather than printed empty.
        std::fs::metadata(&path).map(|m| (Vec::new(), false, m.len()))
    };
    let (window, complete, end) = match read {
        Ok(w) => w,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return explain_missing_log(data_dir, parsed.id, &path);
        }
        Err(e) => {
            diag::error(&format!(
                "sbx: cannot read the session log {}: {e}",
                path.display()
            ));
            return ExitCode::FAILURE;
        }
    };

    // Sample liveness before printing, so the note describes the state the output belongs to.
    let live = session_is_live(data_dir, parsed.id);
    let (in_window, session_body) = last_session(&window);
    // At most one forward pass, and only when the window did not bring the header back: the note
    // needs the header and the streaming arm below needs the offset, and they are the same look.
    let fallback = match in_window {
        Some(_) => None,
        None => match last_header_at(&path) {
            Ok(found) => Some(found),
            // Propagated rather than dropped. This pass yields the offset the streaming arm below
            // starts from, and a swallowed error left that offset at 0 — which streams the whole
            // file, every earlier session of a reused pid included, for a reading that asked for
            // one. A log that cannot be scanned is a failure to report, not a wider answer to give.
            Err(e) => {
                diag::error(&format!(
                    "sbx: cannot scan the session log {} for its header: {e}",
                    path.display()
                ));
                return ExitCode::FAILURE;
            }
        },
    };
    let header = in_window
        .as_ref()
        .or_else(|| fallback.as_ref().and_then(|(h, _)| h.as_ref()));

    // A registry that cannot be read leaves the state unknown. Without `--follow` that only labels
    // the note, so it is said as a warning; a follow is refused over it below, and says so there.
    if let (Err(why), false) = (&live, parsed.follow) {
        diag::warn(&format!(
            "{why} — whether session {} still runs is not known",
            parsed.id
        ));
    }
    diag::note(&format!(
        "session {} — {}, started {}{}",
        parsed.id,
        match &live {
            Ok(true) => "running",
            Ok(false) => "exited",
            Err(_) => "state unknown",
        },
        // `checked_add`, and it is the untrusted-input form rather than a nicety: `h.started` is a
        // bare `u64` taken off a line of the session log, and that log holds the caged agent's own
        // stdout (`parse_session_header` scans every line, and its doc already concedes an agent can
        // emit a well-formed header). `SystemTime`'s seconds are an `i64` on Linux, so a `started`
        // at or above 2^63 makes the infix `+` panic — and this is the one command that exists to
        // find out what a background agent did, against an append-only log, so the panic would be
        // permanent for that session. An unreadable stamp degrades to the `?` the missing-header
        // arm below already renders.
        header
            .and_then(|h| std::time::UNIX_EPOCH.checked_add(Duration::from_secs(h.started)))
            .map(crate::paths::civil_date)
            .unwrap_or_else(|| "?".to_string()),
        if parsed.all { ", all sessions" } else { "" },
    ));

    // Where the last session's body starts, for the two arms below that read past a window that did
    // not hold its header: the offset the forward pass found, or 0 for a log holding no header at
    // all, whose whole content is the one session there is to show. A pass that failed is fatal
    // above, so a `None` here is a window that carried the header, which neither arm meets.
    let session_start = fallback.as_ref().map_or(0, |(_, at)| *at);
    use std::io::Write as _;
    let printed = match (parsed.limit, parsed.all, complete) {
        // Every session, unlimited: the whole file is what was asked for, so it is copied rather
        // than held.
        (None, true, _) => stream_range(0, end),
        // One session, unlimited, and longer than the window: stream it from its own header. The
        // forward pass that finds the header holds nothing either.
        (None, false, false) => stream_range(session_start, end),
        // A line limit the window does not answer: it stopped at its ceiling short of the header,
        // and the lines the limit counts back over begin before it. They are counted back on disk,
        // down to the session's header or to the start of the file under `--all`, and streamed.
        (Some(n), all, false) if LinesBack::new(n).back_over(&window).is_none() => {
            let floor = if all { 0 } else { session_start };
            match tail_start(&path, n, floor, end) {
                Ok(at) => stream_range(at, end),
                Err(e) => Err(unreadable(e)),
            }
        }
        // Everything else is answered from the window: it reached the start of the file, holds the
        // session's header, or holds the start of the lines the limit counts back over.
        (limit, all, _) => {
            let body = if all { &window[..] } else { session_body };
            let body = match limit {
                Some(n) => tail_lines(body, n),
                None => body,
            };
            let mut out = std::io::stdout();
            out.write_all(body)
                .and_then(|()| out.flush())
                .map_err(|e| undelivered(&e))
        }
    };
    if let Err(code) = printed {
        return code;
    }

    if !parsed.follow {
        return ExitCode::SUCCESS;
    }
    match live {
        Ok(true) => follow_log(&path, end, data_dir, parsed.id),
        Ok(false) => {
            // Nothing will ever be appended to a dead session's log, so following it would hang
            // for no reason. Say so and exit rather than leaving the user waiting on a silent
            // terminal.
            diag::hint("       session has exited — nothing further will be written.");
            ExitCode::SUCCESS
        }
        Err(why) => {
            diag::error(&not_followed(parsed.id, &why));
            ExitCode::FAILURE
        }
    }
}

/// Explain an absent log, distinguishing the two reasons it can be missing.
///
/// A foreground session has no log by design — its output is on the user's own terminal — which is
/// a different answer from "no such session", and conflating them would send someone hunting for a
/// file that was never meant to exist. When the registry cannot be read, neither reason can be told,
/// and the answer is the 1 of a failure about the id.
fn explain_missing_log(data_dir: &Path, id: u32, path: &Path) -> ExitCode {
    let sessions = match crate::asked_sessions(data_dir) {
        Ok(sessions) => sessions,
        // The log is still not there; whether `id` names a session is what the registry would have
        // said. Not knowing is not "no such session", so this is the 1 of an answer about the id
        // rather than the 2 of a name that names nothing — the choice `sbx task` makes for its own
        // session ids.
        Err(why) => {
            diag::error(&format!(
                "sbx: no log for session {id} ({}) — {why}, so whether that session runs is not \
                 known.",
                path.display()
            ));
            return ExitCode::FAILURE;
        }
    };
    let record = sessions.into_iter().find(|s| s.pid == id);
    let known = record.is_some();
    match record {
        Some(s) if !s.detached => {
            diag::error(&format!(
                "sbx: session {id} runs in the foreground — its output is on the terminal that started it, not in a log."
            ));
            diag::hint(
                "       only a session started with --detach writes a log; `sbx session attach` joins this one.",
            );
        }
        _ => {
            diag::error(&format!(
                "sbx: no log for session {id} ({}).",
                path.display()
            ));
            diag::hint(
                "       `sbx session ls` lists the live sessions and whether each one is detached.",
            );
        }
    }
    // An id no session answers to is a usage error (2), the exit every verb gives a name that
    // names nothing; a session that is there and has no log is an answer about it (1).
    if known {
        ExitCode::FAILURE
    } else {
        ExitCode::from(2)
    }
}

/// Stream a running session's log until the session exits.
///
/// Liveness is sampled *before* each drain, never after: a session that writes its last words and
/// exits between the two would otherwise have them dropped. Sampling first means a drain that
/// follows a dead reading has the complete final file in front of it.
///
/// A drain that cannot deliver ends the follow. Rust ignores `SIGPIPE`, so a reader that walked away
/// (`sbx session logs <id> -f | head`) is announced only by the write error, and a loop that went on
/// would open the log, read it and fail to write it every poll until the detached session exited,
/// with the user's shell held on the pipeline the whole time. The failure is accounted for by
/// [`undelivered`]: exit 0 for a reader gone, 1 for anything else.
///
/// A registry that can no longer be read ends the follow at exit 1, after the drain that sample
/// precedes: what the session wrote up to then is printed, and the follow does not go on waiting
/// for an end it cannot see.
fn follow_log(path: &Path, mut pos: u64, data_dir: &Path, id: u32) -> ExitCode {
    let mut out = std::io::stdout();
    loop {
        let live = session_is_live(data_dir, id);
        if let Err(e) = drain_log(path, &mut pos, &mut out) {
            return undelivered(&e);
        }
        match live {
            Ok(true) => {}
            Ok(false) => return ExitCode::SUCCESS,
            Err(why) => {
                diag::error(&not_followed(id, &why));
                return ExitCode::FAILURE;
            }
        }
        std::thread::sleep(FOLLOW_POLL);
    }
}

/// Copy whatever the log has gained since `pos` to `out`, advancing `pos` by what was delivered.
///
/// Best-effort on the *read* side: a transient read failure skips one poll rather than ending the
/// follow, and the log is append-only so a later poll picks up everything that was missed. A
/// *write* failure is the opposite — it is the only notice this process gets that its reader is
/// gone — so it is returned rather than swallowed, and `pos` does not move over bytes nobody
/// received. `out` is a parameter so that discipline is testable without a real pipe.
fn drain_log<W: std::io::Write>(path: &Path, pos: &mut u64, out: &mut W) -> std::io::Result<()> {
    use std::io::{Read as _, Seek as _, SeekFrom};
    let Ok(mut file) = std::fs::File::open(path) else {
        return Ok(());
    };
    if file.metadata().map(|m| m.len()).unwrap_or(0) <= *pos {
        return Ok(());
    }
    if file.seek(SeekFrom::Start(*pos)).is_err() {
        return Ok(());
    }
    let mut buf = Vec::new();
    if file.read_to_end(&mut buf).is_err() {
        return Ok(());
    }
    out.write_all(&buf)?;
    out.flush()?;
    *pos += buf.len() as u64;
    Ok(())
}

/// The code a reading ends with once a write of the log to standard output has failed. The failure
/// is accounted for as every verb's is ([`crate::cli::note_output_failure`]) and the reading stops
/// there. [`crate::cli::output_verdict`] turns the success into exit 1, except for a reader that
/// has gone.
fn undelivered(e: &std::io::Error) -> ExitCode {
    crate::cli::note_output_failure(e);
    ExitCode::SUCCESS
}

/// Why [`copy_log`] stopped short, by the side that failed: the log and standard output fail for
/// different reasons and are answered differently.
#[derive(Debug)]
enum CopyFailed {
    Read(std::io::Error),
    Write(std::io::Error),
}

/// Copy everything `src` yields to `out`, one [`LOG_CHUNK`] at a time, and flush it.
///
/// A read the kernel interrupted is retried. Any other failure is returned with the side it came
/// from, which `std::io::copy` does not say: a log that cannot be read is a failure about the log,
/// and a write that fails is accounted for as standard output's.
fn copy_log<R: std::io::Read, W: std::io::Write>(
    mut src: R,
    out: &mut W,
) -> Result<(), CopyFailed> {
    let mut chunk = vec![0u8; LOG_CHUNK as usize];
    loop {
        let n = match src.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(CopyFailed::Read(e)),
        };
        out.write_all(&chunk[..n]).map_err(CopyFailed::Write)?;
    }
    out.flush().map_err(CopyFailed::Write)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A log of two sessions with a body far larger than one read chunk, written to a real file:
    /// the readers under test are about where they stop reading, which a slice cannot show.
    fn big_log(dir: &crate::testutil::TmpDir) -> (std::path::PathBuf, Vec<u8>) {
        let mut log = String::new();
        log.push_str(&header_line(111, 1_000));
        for i in 0..40_000 {
            log.push_str(&format!("old line {i}\n"));
        }
        log.push_str(&header_line(222, 2_000));
        for i in 0..200 {
            log.push_str(&format!("new line {i}\n"));
        }
        let path = dir.join("222.log");
        std::fs::write(&path, &log).unwrap();
        (path, log.into_bytes())
    }

    /// A window from the end answers exactly what reading the whole file answered, and stops well
    /// short of it.
    ///
    /// Both halves matter, and neither implies the other. Reading the tail is only worth doing if
    /// the answer is the same one, and a window that quietly grew to the whole file would give the
    /// same answer while changing nothing. The reference is the previous implementation: the same
    /// two pure functions, over every byte.
    #[test]
    fn a_window_gives_the_whole_files_answer_without_reading_the_whole_file() {
        let dir = crate::testutil::TmpDir::new();
        let (path, full) = big_log(&dir);
        let size = full.len();

        // The ordinary reading: the last session, whole.
        let (window, complete, len) = tail_window(&path, None, true).unwrap();
        assert_eq!(
            len, size as u64,
            "the length reported is the one the read saw"
        );
        assert!(complete, "the last session's header is inside the window");
        assert_eq!(
            last_session(&window).1,
            last_session(&full).1,
            "the body must be the one the full read gave"
        );
        assert_eq!(
            last_session(&window).0.map(|h| h.started),
            Some(2_000),
            "and the window itself holds the header, no fallback needed"
        );
        assert!(
            window.len() < size / 4,
            "a window that reads most of the file has bounded nothing ({} of {size})",
            window.len()
        );

        // `-n`: the same answer, from a window that stops as soon as it holds the lines.
        for n in [1usize, 5, 50] {
            let (window, _, _) = tail_window(&path, Some(n), true).unwrap();
            assert_eq!(
                tail_lines(last_session(&window).1, n),
                tail_lines(last_session(&full).1, n),
                "-n {n} must give what the full read gave"
            );
            assert!(
                window.len() < size / 4,
                "-n {n} read {} bytes",
                window.len()
            );
        }

        // `--all -n`: the limit counts back across sessions, so a header must not end the search.
        // The count is far larger than the last session is long, which is what makes this test
        // separate the two: a window that stopped at the header would hold neither the lines nor
        // the answer, while one that stops on the header *and* the count would look identical.
        let (window, _, _) = tail_window(&path, Some(5_000), false).unwrap();
        assert_eq!(
            tail_lines(&window, 5_000),
            tail_lines(&full, 5_000),
            "under --all the count crosses the header"
        );
        assert!(
            tail_lines(&window, 5_000).starts_with(b"old line"),
            "five thousand lines back from the end reaches into the session above"
        );
    }

    /// The note names when the session started, and that has to survive a session bigger than the
    /// window: it is the ordinary case for the agent this verb exists to read.
    #[test]
    fn the_started_date_survives_a_session_larger_than_the_window() {
        let dir = crate::testutil::TmpDir::new();
        let mut log = String::new();
        log.push_str(&header_line(111, 1_000));
        log.push_str(&header_line(222, 2_000));
        // A last session comfortably past one read chunk, so a window that stops on the line count
        // stops well short of the header above it.
        for i in 0..20_000 {
            log.push_str(&format!("chatty line {i}\n"));
        }
        let path = dir.join("222.log");
        std::fs::write(&path, &log).unwrap();

        let (window, complete, _) = tail_window(&path, Some(5), true).unwrap();
        assert!(
            !complete,
            "this fixture only says something while the header is out of reach"
        );
        // What the command composes: the window first, then the forward pass for what it lost.
        assert_eq!(last_session(&window).0, None, "the window lost the header");
        assert_eq!(
            last_header_at(&path).unwrap().0.map(|h| h.started),
            Some(2_000),
            "and the forward pass is what puts the date back in the note"
        );
    }

    /// The fallback for a session longer than any window: find where its body starts without
    /// holding the file, so it can be streamed from there rather than buffered or truncated.
    #[test]
    fn the_last_headers_offset_is_found_without_holding_the_file() {
        let dir = crate::testutil::TmpDir::new();
        let (path, full) = big_log(&dir);
        let (header, at) = last_header_at(&path).unwrap();
        assert_eq!(header.map(|h| h.started), Some(2_000));
        assert_eq!(
            &full[at as usize..],
            last_session(&full).1,
            "the offset must name the same body the full read splits out"
        );

        // A log with no header at all is not an error: there is no offset, and the caller falls
        // back to the start, which is what `last_session` does with the same file.
        let plain = dir.join("plain.log");
        std::fs::write(&plain, b"just output\nno header\n").unwrap();
        assert_eq!(last_header_at(&plain).unwrap(), (None, 0));
    }

    /// A header line for `pid`, built through the same writer/parser format the launch uses.
    fn header_line(pid: u32, started: u64) -> String {
        format!("=== sbx session {pid} started={started} ===\n")
    }

    #[test]
    fn last_session_returns_only_the_most_recent_incarnations_output() {
        // The load-bearing property: the log is append-only and keyed by pid, so a pid the kernel
        // reuses writes into its predecessor's file. Showing the whole file by default would
        // present a dead session's output as this one's — the exact mistake the header prevents.
        let log = format!(
            "{}old output\n{}new output\n",
            header_line(7, 1_000),
            header_line(7, 2_000)
        );
        let (header, body) = last_session(log.as_bytes());
        assert_eq!(header.unwrap().started, 2_000);
        assert_eq!(body, b"new output\n");
        assert!(
            !body.windows(3).any(|w| w == b"old"),
            "the previous session's output must not appear in the default view"
        );
    }

    #[test]
    fn last_session_returns_a_headerless_log_whole() {
        // A log written before headers existed has no boundary to find. Degraded (the split is
        // lost) but never wrong: returning nothing would hide output that does exist.
        let (header, body) = last_session(b"raw output\n");
        assert!(header.is_none());
        assert_eq!(body, b"raw output\n");
    }

    #[test]
    fn last_session_yields_an_empty_body_for_a_session_that_has_written_nothing() {
        // A just-started session: the header is on disk, the agent has printed nothing yet.
        let log = header_line(7, 1_000);
        let (header, body) = last_session(log.as_bytes());
        assert_eq!(header.unwrap().pid, 7);
        assert!(body.is_empty(), "no output yet, not the header line itself");
    }

    #[test]
    fn tail_lines_counts_real_lines_not_the_trailing_newline() {
        // `-n 1` on output ending in a newline must show the last real line. Counting the trailing
        // newline as an empty final line would show nothing at all — the most common invocation.
        assert_eq!(tail_lines(b"a\nb\nc\n", 1), b"c\n");
        assert_eq!(tail_lines(b"a\nb\nc\n", 2), b"b\nc\n");
        // No trailing newline (an agent killed mid-line) still yields the last line.
        assert_eq!(tail_lines(b"a\nb\nc", 1), b"c");
        // More lines requested than exist yields everything, never a panic.
        assert_eq!(tail_lines(b"a\nb\n", 9), b"a\nb\n");
        assert_eq!(tail_lines(b"", 3), b"");
        assert_eq!(tail_lines(b"a\nb\n", 0), b"");
    }

    /// The lines found back on disk a chunk at a time are the ones [`tail_lines`] finds in the same
    /// bytes held whole. A break on a chunk's last byte counts, only the file's own final newline
    /// does not, and nothing before the floor is reached.
    #[test]
    fn lines_counted_back_on_disk_are_the_lines_of_the_bytes_held_whole() {
        let dir = crate::testutil::TmpDir::new();
        let chunk = LOG_CHUNK as usize;
        let line = |len: usize| [vec![b'x'; len - 1], vec![b'\n']].concat();
        // The last two lines weigh one chunk together, so the break that ends the third line from
        // the end is the last byte of the second chunk read.
        let sizes = [100, chunk + 5, 50, chunk / 2, chunk / 2];
        let lined: Vec<u8> = sizes.iter().flat_map(|&len| line(len)).collect();
        let starts: Vec<u64> = sizes
            .iter()
            .scan(0u64, |at, &len| {
                let start = *at;
                *at += len as u64;
                Some(start)
            })
            .collect();
        let path = dir.join("4242.log");

        for trailing in [true, false] {
            let mut full = lined.clone();
            if !trailing {
                full.pop();
            }
            std::fs::write(&path, &full).unwrap();
            let end = full.len() as u64;
            for floor in [0, starts[1], starts[1] + 7] {
                for n in 0..=6 {
                    let held = &full[floor as usize..];
                    let want = end - tail_lines(held, n).len() as u64;
                    assert_eq!(
                        tail_start(&path, n, floor, end).unwrap(),
                        want,
                        "-n {n} over [{floor}, {end}), final newline {trailing}"
                    );
                }
            }
            // Written out, so the comparison above is not all that holds the count.
            assert_eq!(tail_start(&path, 3, 0, end).unwrap(), starts[2]);
            assert_eq!(tail_start(&path, 2, 0, end).unwrap(), starts[3]);
            assert_eq!(tail_start(&path, 0, 0, end).unwrap(), end);
            assert_eq!(
                tail_start(&path, 6, starts[1] + 7, end).unwrap(),
                starts[1] + 7
            );
        }
    }

    #[test]
    fn the_mode_column_marks_exactly_the_sessions_that_have_a_log() {
        use crate::session::{Kind, Session, SessionRuntime};
        let base = Session::current(
            std::path::PathBuf::from("/w/p"),
            Kind::Run,
            SessionRuntime::Project,
        )
        .expect("read this process's session identity");
        assert_eq!(session_mode(&base), "foreground");
        assert_eq!(session_mode(&base.clone().detached()), "detached");
    }

    #[test]
    fn logs_args_require_exactly_one_numeric_id() {
        let v = |a: &[&str]| -> Vec<OsString> { a.iter().map(OsString::from).collect() };

        let a = parse_logs_args(&v(&["1234"])).unwrap();
        assert_eq!((a.id, a.follow, a.limit, a.all), (1234, false, None, false));

        let a = parse_logs_args(&v(&["1234", "-f", "-n", "20", "--all"])).unwrap();
        assert_eq!(
            (a.id, a.follow, a.limit, a.all),
            (1234, true, Some(20), true)
        );
        // Flags may precede the id, as they do for every other launch-side parser here.
        assert_eq!(parse_logs_args(&v(&["--follow", "9"])).unwrap().id, 9);

        // No id: the verb reads one session's output and cannot guess which, since the registry
        // holds no record for the dead sessions this command exists to read.
        assert!(parse_logs_args(&v(&[])).is_err());
        // A non-numeric id is refused rather than resolved to a path that cannot exist.
        assert!(parse_logs_args(&v(&["sbx-myproj"])).is_err());
        // Two ids are an ambiguity, not a second target — showing the wrong session's output
        // silently is worse than a usage error.
        assert!(parse_logs_args(&v(&["12", "34"])).is_err());
        assert!(parse_logs_args(&v(&["12", "-n"])).is_err());
        assert!(parse_logs_args(&v(&["12", "-n", "many"])).is_err());
        assert!(parse_logs_args(&v(&["12", "--nope"])).is_err());
    }

    /// A follow reads the registry again before each drain. Once the registry cannot be read,
    /// whether the session still runs is not known, and the follow ends at exit 1 rather than going
    /// on as if the session ran or stopping as if it had exited.
    ///
    /// The session is this process, registered as alive, so the follow runs until the registry is
    /// replaced by a plain file, which reading as a directory refuses with an error other than
    /// `NotFound`.
    #[test]
    fn a_follow_ends_with_a_failure_once_the_registry_cannot_be_read() {
        use crate::session::{Kind, Registry, Session, SessionRuntime};
        let data = crate::testutil::TmpDir::new();
        let me = Session::current(
            std::path::PathBuf::from("/home/u/proj"),
            Kind::Run,
            SessionRuntime::GlobalApp("demo".to_string()),
        )
        .expect("read this process's session identity");
        Registry::at(data.path())
            .register(&me)
            .expect("register the session");
        let log = data.join("empty.log");
        std::fs::write(&log, b"").unwrap();

        let (tx, rx) = std::sync::mpsc::channel();
        let (dir, pid) = (data.path().to_path_buf(), me.pid);
        std::thread::spawn(move || {
            let _ = tx.send(follow_log(&log, 0, &dir, pid));
        });
        assert!(
            rx.recv_timeout(FOLLOW_POLL * 4).is_err(),
            "a session the registry holds as running is followed"
        );
        // Exchanged for the file in one step: removing the directory and then writing the file
        // leaves a moment in which the registry is absent, which reads as no session at all, and a
        // follow that polls then ends at 0 as if the session had exited.
        let unreadable = data.join("sessions.file");
        std::fs::write(&unreadable, b"not a directory").unwrap();
        let c_path = |p: &std::path::Path| {
            use std::os::unix::ffi::OsStrExt as _;
            std::ffi::CString::new(p.as_os_str().as_bytes()).expect("a path without NUL")
        };
        let (from, to) = (c_path(&unreadable), c_path(&data.join("sessions")));
        // SAFETY: the raw `renameat2` is given its documented argument list, two
        // `AT_FDCWD`-relative paths and the `RENAME_EXCHANGE` flag; both `CString`s outlive the
        // call and the kernel only reads them.
        let rc = unsafe {
            libc::syscall(
                libc::SYS_renameat2,
                libc::AT_FDCWD,
                from.as_ptr(),
                libc::AT_FDCWD,
                to.as_ptr(),
                libc::RENAME_EXCHANGE,
            )
        };
        assert_eq!(
            rc,
            0,
            "exchange the registry for a file: {}",
            std::io::Error::last_os_error()
        );
        let ended = rx.recv_timeout(Duration::from_secs(10));
        assert!(ended == Ok(ExitCode::FAILURE), "{ended:?}");
    }

    /// A stdout stand-in that refuses every write, the way a pipe whose reader has exited does.
    struct ClosedPipe;

    impl std::io::Write for ClosedPipe {
        fn write(&mut self, _buf: &[u8]) -> std::io::Result<usize> {
            Err(std::io::Error::from(std::io::ErrorKind::BrokenPipe))
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    /// `sbx session logs <id> -f | head` leaves the pipe with no reader. Rust ignores `SIGPIPE`, so
    /// the EPIPE from this write is the only notice the follow ever gets; discarded, the loop kept
    /// opening the log, reading it and failing to write it every 250 ms until the detached session
    /// exited, and the shell waiting on the pipeline was held for as long as the agent ran. Pins
    /// that the error reaches the caller, and that the cursor does not move over bytes nobody
    /// received.
    #[test]
    fn a_drain_into_a_closed_pipe_reports_the_write_failure_rather_than_swallowing_it() {
        let dir = crate::testutil::TmpDir::new();
        let path = dir.join("4242.log");
        std::fs::write(&path, b"one\ntwo\n").unwrap();

        let mut pos = 0u64;
        assert!(drain_log(&path, &mut pos, &mut ClosedPipe).is_err());
        assert_eq!(pos, 0, "an undelivered drain must not advance the cursor");

        // The same drain into a reader that is still there delivers everything and advances the
        // cursor by exactly what it wrote, so the next poll re-prints nothing.
        let mut sink: Vec<u8> = Vec::new();
        let mut pos = 0u64;
        assert!(drain_log(&path, &mut pos, &mut sink).is_ok());
        assert_eq!((pos, sink.as_slice()), (8, &b"one\ntwo\n"[..]));
        assert!(drain_log(&path, &mut pos, &mut sink).is_ok());
        assert_eq!(sink.len(), 8, "nothing was appended, so nothing is re-sent");

        // A log that is not there is not a delivery failure: the follow keeps polling for it.
        let mut pos = 0u64;
        assert!(drain_log(&dir.join("no-such.log"), &mut pos, &mut ClosedPipe).is_ok());
    }

    /// A log that hands out its steps in order: bytes, or the error a read of it returns.
    struct Scripted(std::collections::VecDeque<std::io::Result<&'static [u8]>>);

    impl std::io::Read for Scripted {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            match self.0.pop_front() {
                None => Ok(0),
                Some(Ok(bytes)) => {
                    buf[..bytes.len()].copy_from_slice(bytes);
                    Ok(bytes.len())
                }
                Some(Err(e)) => Err(e),
            }
        }
    }

    /// A stdout stand-in that takes every write and refuses the flush, the way a line-buffered
    /// stdout on a full disk refuses the tail of a log that does not end in a newline.
    struct Unflushable;

    impl std::io::Write for Unflushable {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Err(std::io::Error::from(std::io::ErrorKind::StorageFull))
        }
    }

    /// A copy of the log says which side failed, which `std::io::copy` does not. A log that cannot be
    /// read is a failure about the log, and a write that fails is standard output's, accounted for
    /// by [`crate::cli::note_output_failure`], which exempts a reader gone and nothing else.
    #[test]
    fn a_copy_of_the_log_names_the_side_that_failed() {
        let log = |steps: Vec<std::io::Result<&'static [u8]>>| Scripted(steps.into());
        let interrupted = || std::io::Error::from(std::io::ErrorKind::Interrupted);

        // Delivered whole, the interrupted read retried rather than ending the copy.
        let mut sink: Vec<u8> = Vec::new();
        let copied = copy_log(
            log(vec![Ok(b"one\n"), Err(interrupted()), Ok(b"two\n")]),
            &mut sink,
        );
        assert!(copied.is_ok(), "{copied:?}");
        assert_eq!(sink, b"one\ntwo\n");

        // The log fails: what came before it is delivered, and the failure is the read's.
        let mut sink: Vec<u8> = Vec::new();
        let copied = copy_log(
            log(vec![Ok(b"one\n"), Err(std::io::Error::other("unreadable"))]),
            &mut sink,
        );
        assert!(
            matches!(&copied, Err(CopyFailed::Read(e)) if e.to_string() == "unreadable"),
            "{copied:?}"
        );
        assert_eq!(sink, b"one\n");

        // Standard output fails, on a write or on the flush that ends the copy.
        let copied = copy_log(log(vec![Ok(b"one\n")]), &mut ClosedPipe);
        assert!(
            matches!(&copied, Err(CopyFailed::Write(e)) if e.kind() == std::io::ErrorKind::BrokenPipe),
            "{copied:?}"
        );
        let copied = copy_log(log(vec![Ok(b"one")]), &mut Unflushable);
        assert!(
            matches!(&copied, Err(CopyFailed::Write(e)) if e.kind() == std::io::ErrorKind::StorageFull),
            "{copied:?}"
        );
    }

    /// A bare `--` ends the options rather than becoming a target. Ids are PIDs, so `--` can only
    /// ever name a session that does not exist: `sbx session stop -- 1234` stopped 1234 cleanly and
    /// then reported "no live session '--'", exiting 2 on a stop that had worked — and a script
    /// reading the status concluded the stop had failed.
    #[test]
    fn a_bare_double_dash_ends_the_options_instead_of_becoming_a_session_id() {
        let v = |a: &[&str]| -> Vec<OsString> { a.iter().map(OsString::from).collect() };

        let p = parse_stop_args(v(&["--", "1234"])).unwrap();
        assert_eq!(p.ids, vec!["1234".to_string()]);
        assert!(!p.all);

        // Everything after it is an id, flag-shaped or not — which is what a terminator is for.
        let p = parse_stop_args(v(&["--delay", "3", "--", "--all"])).unwrap();
        assert_eq!(p.ids, vec!["--all".to_string()]);
        assert_eq!(p.delay, std::time::Duration::from_secs(3));
        assert!(
            !p.all,
            "`--all` after the terminator is an id, not the flag"
        );

        // Before it, the options still parse and an unknown one is still refused.
        let p = parse_stop_args(v(&["--all", "--delay", "0"])).unwrap();
        assert!(p.all && p.ids.is_empty() && p.delay.is_zero());
        assert!(parse_stop_args(v(&["--dry-run", "1234"])).is_err());
        // A `--` with nothing after it leaves no target at all, which is a usage error.
        assert!(parse_stop_args(v(&["--"])).is_err());
    }

    /// The grace becomes `Instant::now() + d` in [`crate::session::wait_for_exit`], and that
    /// addition panics on a duration the clock cannot represent. `sbx session stop --all --delay
    /// 18446744073709551615` aborted with `overflow when adding duration to instant` instead of
    /// refusing the number, and a panicking teardown leaves the cage it was called to collect. A
    /// config duration has been held to this ceiling all along, for this reason and in these words;
    /// this door read the value straight into a `Duration`.
    #[test]
    fn a_grace_no_clock_can_represent_is_a_usage_error_not_a_panic() {
        let v = |a: &[&str]| -> Vec<OsString> { a.iter().map(OsString::from).collect() };

        assert!(parse_stop_args(v(&["--all", "--delay", "18446744073709551615"])).is_err());
        // The ceiling itself, and one second past it: the refusal is a bound, not a parse failure
        // on long digit strings.
        let max = crate::config::DURATION_MAX_SECS;
        let p = parse_stop_args(v(&["--all", "--delay", &max.to_string()])).unwrap();
        assert_eq!(p.delay, std::time::Duration::from_secs(max));
        assert!(parse_stop_args(v(&["--all", "--delay", &(max + 1).to_string()])).is_err());

        // Witness: an ordinary grace still parses, so the bound has not made the option unusable.
        let p = parse_stop_args(v(&["--all", "--delay", "10"])).unwrap();
        assert_eq!(p.delay, std::time::Duration::from_secs(10));
    }
}
