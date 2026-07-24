//! `sbx session <subcommand>` (alias `sbx sessions`): every operation on a live sandbox session —
//! `ls` lists the on-disk registry, `attach` enters a running cage, `stop` ends sessions.

use std::ffi::OsString;
use std::io::IsTerminal;
use std::process::ExitCode;
use std::time::Duration;

use crate::{diag, format_age, help, sandbox, session, store, style, uptime_seconds};

/// `sbx session <subcommand>` (alias `sbx sessions`): the namespace grouping every operation on a
/// live sandbox session — `ls` lists them, `attach` runs a shell or a command inside one, `stop`
/// ends them.
/// A leading `--help` (at any depth) is intercepted by [`help::maybe_help`], which also covers the
/// `sessions` alias that the top-level help interception does not reach. A bare `sbx session` prints
/// the namespace page; an unknown subcommand is a usage error.
pub(crate) fn session_cmd(args: Vec<OsString>) -> ExitCode {
    if let Some(code) = help::maybe_help("session", &args) {
        return code;
    }
    match args.first().and_then(|a| a.to_str()) {
        Some("ls") | Some("list") => list_sessions(),
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
    let rows: Vec<(String, String, String, String, String)> = sessions
        .iter()
        .map(|s| {
            let age = match uptime {
                Some(up) if ticks_per_sec > 0 => {
                    let started = s.start_ticks as f64 / ticks_per_sec as f64;
                    format_age((up - started).max(0.0) as u64)
                }
                _ => "?".to_string(),
            };
            (
                sandbox::cage_name(s.app(), &s.project),
                s.label(),
                s.pid.to_string(),
                age,
                s.project.display().to_string(),
            )
        })
        .collect();

    // NAME/KIND are left-aligned, PID/AGE right-aligned; each width is the wider of its header
    // label and the widest value. Cage slugs and app/label names are ASCII, so a byte length
    // equals the display width.
    let name_w = rows.iter().map(|r| r.0.len()).chain([4]).max().unwrap();
    let kind_w = rows.iter().map(|r| r.1.len()).chain([4]).max().unwrap();
    let pid_w = rows.iter().map(|r| r.2.len()).chain([3]).max().unwrap();
    let age_w = rows.iter().map(|r| r.3.len()).chain([3]).max().unwrap();

    // The header is padded first, then wrapped in color, so the color spans never count toward
    // the column widths and the alignment is identical with or without color.
    let header = format!(
        "{:<name_w$}  {:<kind_w$}  {:>pid_w$}  {:>age_w$}  PROJECT",
        "NAME", "KIND", "PID", "AGE"
    );
    println!("{h}{header}{r}");
    for (name, label, pid, age, project) in &rows {
        // NAME is the cage's own name — the same `sbx-<slug>` its systemd scope and in-cage
        // hostname show — so a session cross-references with the host tooling. An app session's
        // KIND is `app:<name>`, so the user can tell which sessions are agents (and that
        // `sbx session attach`/`sbx session stop` act on that app's isolated environment). NAME is
        // padded before
        // coloring so the color span does not disturb the width.
        let name = format!("{name:<name_w$}");
        println!("{n}{name}{r}  {label:<kind_w$}  {pid:>pid_w$}  {age:>age_w$}  {project}");
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
