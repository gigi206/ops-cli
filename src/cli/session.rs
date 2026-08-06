//! `sbx session <subcommand>` (alias `sbx sessions`): every operation on a live sandbox session —
//! `ls` lists the on-disk registry, `logs` reads a detached session's output, `attach` enters a
//! running cage, `stop` ends sessions.

use std::ffi::OsString;
use std::io::IsTerminal;
use std::path::Path;
use std::process::ExitCode;
use std::time::Duration;

use crate::{diag, format_age, help, sandbox, session, store, style, uptime_seconds};

/// `sbx session <subcommand>` (alias `sbx sessions`): the namespace grouping every operation on a
/// live sandbox session — `ls` lists them, `attach` runs a shell or a command inside one, `stop`
/// ends them.
/// A `--help` at any depth is intercepted by [`help::maybe_help`], which resolves the deepest
/// subcommand named — under its own name or an accepted alias — and shows that page. A bare
/// `sbx session` prints the namespace page; an unknown subcommand is a usage error.
pub(crate) fn session_cmd(args: Vec<OsString>) -> ExitCode {
    if let Some(code) = help::maybe_help("session", &args) {
        return code;
    }
    match args.first().and_then(|a| a.to_str()) {
        Some("ls") | Some("list") => match crate::cli::reject_extra(&["session", "ls"], &args[1..])
        {
            Err(code) => code,
            Ok(()) => list_sessions(),
        },
        Some("logs") | Some("log") => logs_cmd(&args[1..]),
        Some("attach") => attach_cmd(args[1..].to_vec()),
        Some("stop") => stop_cmd(args[1..].to_vec()),
        None => {
            eprint!("{}", help::page_usage(&["session"]).unwrap_or_default());
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
    if s.detached {
        "detached"
    } else {
        "foreground"
    }
}

/// `sbx session ls`: list the live sandbox sessions from the on-disk registry. Reading
/// the registry re-validates and prunes dead records as a side effect, so the
/// list is always current without a daemon.
fn list_sessions() -> ExitCode {
    let Some(layout) = store::Layout::from_env() else {
        diag::error(
            "sbx: cannot resolve the data directory (no $SBX_DATA_DIR, $XDG_DATA_HOME or $HOME).",
        );
        return ExitCode::FAILURE;
    };
    let sessions = match session::Registry::at(layout.data_dir()).list() {
        Ok(s) => s,
        Err(e) => {
            diag::error(&format!("sbx: cannot read the session registry: {e}"));
            return ExitCode::FAILURE;
        }
    };
    if sessions.is_empty() {
        println!("sbx: no active sandbox sessions.");
        return ExitCode::SUCCESS;
    }

    let pal = style::Palette::for_stream(std::io::stdout().is_terminal());
    let (h, n, r) = (pal.head, pal.name, pal.reset);
    let uptime = uptime_seconds();
    let ticks_per_sec = unsafe { libc::sysconf(libc::_SC_CLK_TCK) };
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

    // NAME/KIND/MODE are left-aligned, PID/AGE right-aligned; each width is the wider of its
    // header label and the widest value. Cage slugs and app/label names are ASCII, so a byte
    // length equals the display width.
    let name_w = rows.iter().map(|r| r.name.len()).chain([4]).max().unwrap();
    let kind_w = rows.iter().map(|r| r.kind.len()).chain([4]).max().unwrap();
    let mode_w = rows.iter().map(|r| r.mode.len()).chain([4]).max().unwrap();
    let pid_w = rows.iter().map(|r| r.pid.len()).chain([3]).max().unwrap();
    let age_w = rows.iter().map(|r| r.age.len()).chain([3]).max().unwrap();

    // The header is padded first, then wrapped in color, so the color spans never count toward
    // the column widths and the alignment is identical with or without color.
    let header = format!(
        "{:<name_w$}  {:<kind_w$}  {:<mode_w$}  {:>pid_w$}  {:>age_w$}  PROJECT",
        "NAME", "KIND", "MODE", "PID", "AGE"
    );
    println!("{h}{header}{r}");
    for row in &rows {
        // NAME is the cage's own name — the same `sbx-<slug>` its systemd scope and in-cage
        // hostname show — so a session cross-references with the host tooling. An app session's
        // KIND is `app:<name>`, so the user can tell which sessions are agents (and that
        // `sbx session attach`/`sbx session stop` act on that app's isolated environment). MODE
        // says where the session's output went, which is the one thing the other columns cannot
        // convey: only a `detached` session has a log for `sbx session logs` to read. NAME is
        // padded before coloring so the color span does not disturb the width.
        let name = format!("{:<name_w$}", row.name);
        println!(
            "{n}{name}{r}  {:<kind_w$}  {:<mode_w$}  {:>pid_w$}  {:>age_w$}  {}",
            row.kind, row.mode, row.pid, row.age, row.project
        );
    }
    ExitCode::SUCCESS
}

/// `sbx session attach <id> [-- command [args...]]`: enter a running session's live cage. With no
/// command it opens an interactive shell; with `-- command` it runs that command inside the cage
/// (through a pty when stdin is a terminal, inherited stdio otherwise). The operand before any `--`
/// is the PID `sbx session ls` shows — exactly one; a missing, extra, or non-UTF-8 operand, or a
/// bare `--` with no command, is a usage error; a well-formed id that matches no live session is
/// reported by `attach` itself.
fn attach_cmd(args: Vec<OsString>) -> ExitCode {
    // Everything after the first `--` is the command to run in the cage; before it is the id alone.
    let dashdash = args.iter().position(|a| a == "--");
    let (head, cmd): (&[OsString], Vec<OsString>) = match dashdash {
        Some(i) => (&args[..i], args[i + 1..].to_vec()),
        None => (&args[..], Vec::new()),
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
/// Sends SIGTERM, then SIGKILL after the grace delay (default 10s; `--delay 0` escalates at once).
/// Either ids or `--all` is required (not both); a non-UTF-8 operand or a malformed `--delay` value
/// is a usage error.
fn stop_cmd(args: Vec<OsString>) -> ExitCode {
    let mut delay = STOP_DEFAULT_DELAY;
    let mut all = false;
    let mut ids: Vec<String> = Vec::new();
    let mut it = args.into_iter();
    while let Some(arg) = it.next() {
        match arg.to_str() {
            Some("--delay") => {
                let Some(value) = it.next() else {
                    diag::error("sbx: --delay needs a value in seconds (e.g. --delay 10).");
                    return ExitCode::from(2);
                };
                match value.to_str().and_then(|v| v.parse::<u64>().ok()) {
                    Some(secs) => delay = Duration::from_secs(secs),
                    None => {
                        diag::error(&format!(
                            "sbx: --delay must be a whole number of seconds, not '{}'.",
                            value.to_string_lossy()
                        ));
                        return ExitCode::from(2);
                    }
                }
            }
            Some("--all") => all = true,
            Some(id) => ids.push(id.to_string()),
            None => {
                diag::error(
                    "sbx: stop ids must be valid text (the PID shown by `sbx session ls`).",
                );
                return ExitCode::from(2);
            }
        }
    }
    if all && !ids.is_empty() {
        diag::error("sbx: stop takes either explicit ids or --all, not both.");
        return ExitCode::from(2);
    }
    if !all && ids.is_empty() {
        diag::error(&format!(
            "sbx: usage: {}\n   (ids are the PIDs shown by `sbx session ls`)",
            help::synopsis_of(&["session", "stop"])
        ));
        return ExitCode::from(2);
    }
    let id_refs: Vec<&str> = ids.iter().map(String::as_str).collect();
    sandbox::stop(&id_refs, delay, all)
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
                ))
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

/// The last `n` newline-delimited lines of `body`. A single trailing newline does not count as an
/// empty final line, so `-n 1` on output ending in `\n` shows the last real line, not nothing.
fn tail_lines(body: &[u8], n: usize) -> &[u8] {
    if n == 0 {
        return &body[..0];
    }
    let end = if body.ends_with(b"\n") {
        body.len() - 1
    } else {
        body.len()
    };
    let (mut seen, mut i) = (0usize, end);
    while i > 0 {
        i -= 1;
        if body[i] == b'\n' {
            seen += 1;
            if seen == n {
                return &body[i + 1..];
            }
        }
    }
    body
}

/// Whether the registry still holds a live record for `id`.
///
/// Goes through the registry rather than a bare `kill(pid, 0)` so the decisive test stays the
/// `(pid, start_ticks)` match: a pid the kernel has since handed to an unrelated process must not
/// read as this session still running, which would leave `--follow` waiting forever on a file
/// nothing will ever append to.
fn session_is_live(data_dir: &Path, id: u32) -> bool {
    session::Registry::at(data_dir)
        .list()
        .map(|sessions| sessions.iter().any(|s| s.pid == id))
        .unwrap_or(false)
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
    let Some(layout) = store::Layout::from_env() else {
        diag::error(
            "sbx: cannot resolve the data directory (no $SBX_DATA_DIR, $XDG_DATA_HOME or $HOME).",
        );
        return ExitCode::FAILURE;
    };
    let data_dir = layout.data_dir();
    let path = sandbox::detach_log_path(data_dir, parsed.id);

    let log = match std::fs::read(&path) {
        Ok(bytes) => bytes,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return explain_missing_log(data_dir, parsed.id, &path)
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
    let (header, body) = last_session(&log);
    let body = if parsed.all { &log[..] } else { body };
    let body = match parsed.limit {
        Some(n) => tail_lines(body, n),
        None => body,
    };

    diag::note(&format!(
        "session {} — {}, started {}{}",
        parsed.id,
        if live { "running" } else { "exited" },
        header
            .as_ref()
            .map(|h| crate::paths::civil_date(
                std::time::UNIX_EPOCH + Duration::from_secs(h.started)
            ))
            .unwrap_or_else(|| "?".to_string()),
        if parsed.all { ", all sessions" } else { "" },
    ));

    use std::io::Write as _;
    let mut out = std::io::stdout();
    let _ = out.write_all(body);
    let _ = out.flush();

    if !parsed.follow {
        return ExitCode::SUCCESS;
    }
    if !live {
        // Nothing will ever be appended to a dead session's log, so following it would hang for
        // no reason. Say so and exit rather than leaving the user waiting on a silent terminal.
        diag::hint("       session has exited — nothing further will be written.");
        return ExitCode::SUCCESS;
    }
    follow_log(&path, log.len() as u64, data_dir, parsed.id)
}

/// Explain an absent log, distinguishing the two reasons it can be missing.
///
/// A foreground session has no log by design — its output is on the user's own terminal — which is
/// a different answer from "no such session", and conflating them would send someone hunting for a
/// file that was never meant to exist.
fn explain_missing_log(data_dir: &Path, id: u32, path: &Path) -> ExitCode {
    let record = session::Registry::at(data_dir)
        .list()
        .ok()
        .and_then(|sessions| sessions.into_iter().find(|s| s.pid == id));
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
    ExitCode::FAILURE
}

/// Stream a running session's log until the session exits.
///
/// Liveness is sampled *before* each drain, never after: a session that writes its last words and
/// exits between the two would otherwise have them dropped. Sampling first means a drain that
/// follows a dead reading has the complete final file in front of it.
fn follow_log(path: &Path, mut pos: u64, data_dir: &Path, id: u32) -> ExitCode {
    loop {
        let live = session_is_live(data_dir, id);
        drain_log(path, &mut pos);
        if !live {
            return ExitCode::SUCCESS;
        }
        std::thread::sleep(FOLLOW_POLL);
    }
}

/// Copy whatever the log has gained since `pos` to stdout, advancing `pos`. Best-effort: a
/// transient read failure skips one poll rather than ending the follow, and the log is append-only
/// so a later poll picks up everything that was missed.
fn drain_log(path: &Path, pos: &mut u64) {
    use std::io::{Read as _, Seek as _, SeekFrom, Write as _};
    let Ok(mut file) = std::fs::File::open(path) else {
        return;
    };
    if file.metadata().map(|m| m.len()).unwrap_or(0) <= *pos {
        return;
    }
    if file.seek(SeekFrom::Start(*pos)).is_err() {
        return;
    }
    let mut buf = Vec::new();
    if file.read_to_end(&mut buf).is_err() {
        return;
    }
    let mut out = std::io::stdout();
    let _ = out.write_all(&buf);
    let _ = out.flush();
    *pos += buf.len() as u64;
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
