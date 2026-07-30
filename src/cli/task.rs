//! `sbx task <subcommand>`: the declared-operation surface — list what a session offers, invoke one,
//! and read the host-side invocation log.
//!
//! This is the **host** side of that surface. The verbs read the same inside a cage, but nothing
//! here runs there: what a cage holds is a generated client that speaks the same wire and can
//! express nothing else (see [`crate::sandbox::task_shim`]). Two callers, one plane, and only one of
//! them gets a binary.
//!
//! On the host the verbs resolve a live session and talk to its socket, so a human can try an
//! operation exactly as the agent would see it — the value of that is that a task is testable
//! without an agent. `logs` is host-only by construction: the invocation log lives on a socket the
//! cage never sees, because the recorded party does not get to read the record.
//!
//! No policy lives here. The client sends a name, bounded values, and allowed variable names; every
//! decision — the program, the bounds, the credential, the ceilings — is the host-side engine's.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::path::PathBuf;
use std::process::ExitCode;

use crate::sandbox::task_control::{client, TASK_SOCKET_ENV};
use std::io::IsTerminal;

use crate::{diag, help, sandbox, store, style};

/// The exit code `sbx task run` returns when the plane **refused** an invocation — an unknown
/// operation, a value outside its declared bound, an unlisted variable, an exhausted quota. Distinct
/// from any code the wrapped command could plausibly return, so a script can tell "nothing ran" from
/// "it ran and failed"; 125 is the convention `env` and `docker` use for the same distinction.
const REFUSED_EXIT: u8 = 125;

/// `sbx task <subcommand>`: `list`, `secrets`, `run`, `status`, `stop`, or `logs`.
pub(crate) fn task_cmd(args: Vec<OsString>) -> ExitCode {
    if let Some(code) = help::maybe_help("task", &args) {
        return code;
    }
    match args.first().and_then(|a| a.to_str()) {
        Some("list") | Some("ls") => task_list(&args[1..]),
        Some("secrets") => task_secrets(&args[1..]),
        Some("run") => task_run(&args[1..]),
        Some("status") => task_status(&args[1..]),
        Some("stop") => task_stop(&args[1..]),
        Some("logs") | Some("log") => task_logs(&args[1..]),
        None => {
            eprint!("{}", help::page_usage(&["task"]).unwrap_or_default());
            ExitCode::from(2)
        }
        Some(other) => {
            diag::error(&format!("sbx: task: unknown subcommand `{other}`"));
            diag::hint("       run `sbx help task` for usage.");
            ExitCode::from(2)
        }
    }
}

/// The task socket to talk to: a live session's, or the one named outright.
///
/// `$SBX_TASK_SOCKET` short-circuits the search, which is how a specific plane can be addressed
/// without resolving a session. It is also the discovery handle the cage advertises, so a tool that
/// wants to find the plane looks in one place whichever side it is on.
fn socket_for(id: Option<&str>, verb: &str) -> Result<PathBuf, ExitCode> {
    if let Some(path) = std::env::var_os(TASK_SOCKET_ENV) {
        return Ok(PathBuf::from(path));
    }
    let Some(layout) = store::Layout::from_env() else {
        diag::error(
            "sbx: cannot resolve the data directory (no $SBX_DATA_DIR, $XDG_DATA_HOME or $HOME).",
        );
        return Err(ExitCode::FAILURE);
    };
    let pid = resolve_task_session(layout.data_dir(), id, verb)?;
    Ok(sandbox::task_control::task_dir(layout.data_dir(), pid).join("control.sock"))
}

/// Resolve which session's task plane to address: the id the user named, or the sole one that has a
/// plane. Ambiguity is an error rather than a guess — invoking an operation against the wrong
/// session would run a real command with a real credential.
fn resolve_task_session(
    data_dir: &std::path::Path,
    id: Option<&str>,
    verb: &str,
) -> Result<u32, ExitCode> {
    if let Some(id) = id {
        return id.parse::<u32>().map_err(|_| {
            diag::error(&format!("sbx: task {verb}: `{id}` is not a session id"));
            ExitCode::from(2)
        });
    }
    let pids = sandbox::task_control::session_pids(data_dir);
    match pids.as_slice() {
        [] => {
            diag::error(&format!(
                "sbx: task {verb}: no session is offering declared operations"
            ));
            diag::hint("       a session offers them when its config declares `[task.<name>]`.");
            Err(ExitCode::FAILURE)
        }
        [one] => Ok(*one),
        many => {
            diag::error(&format!(
                "sbx: task {verb}: {} sessions are offering operations — name one",
                many.len()
            ));
            diag::hint(&format!(
                "       ids: {}",
                many.iter()
                    .map(u32::to_string)
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
            Err(ExitCode::from(2))
        }
    }
}

/// `sbx task list [<id>]`: the operations this session offers, with their parameters and ceilings.
fn task_list(args: &[OsString]) -> ExitCode {
    let id = match positional_id(args, "list") {
        Ok(id) => id,
        Err(code) => return code,
    };
    let socket = match socket_for(id.as_deref(), "list") {
        Ok(s) => s,
        Err(code) => return code,
    };
    let rows = match client::list(&socket) {
        Ok(rows) => rows,
        Err(e) => return unreachable_plane(&e),
    };
    if rows.is_empty() {
        println!("no declared operations");
        return ExitCode::SUCCESS;
    }
    let palette = style::Palette::for_stream(std::io::stdout().is_terminal());
    for row in rows {
        println!(
            "{}{}{} {}",
            palette.name,
            row.name,
            palette.reset,
            row.fields.join("  ")
        );
    }
    ExitCode::SUCCESS
}

/// `sbx task secrets [<id>]`: the credentials the operations carry — names and descriptions only.
fn task_secrets(args: &[OsString]) -> ExitCode {
    let id = match positional_id(args, "secrets") {
        Ok(id) => id,
        Err(code) => return code,
    };
    let socket = match socket_for(id.as_deref(), "secrets") {
        Ok(s) => s,
        Err(code) => return code,
    };
    match client::secrets(&socket) {
        Ok(rows) if rows.is_empty() => {
            println!("no credentials are carried by the declared operations");
            ExitCode::SUCCESS
        }
        Ok(rows) => {
            for row in rows {
                println!("{row}");
            }
            ExitCode::SUCCESS
        }
        Err(e) => unreachable_plane(&e),
    }
}

/// `sbx task run <name> [--param k=v]… [--env K=V]… [--session <id>]`: invoke one operation.
///
/// The exit code is the command's own, so a task composes in a script exactly like the program it
/// wraps; a *refusal* (an unknown task, a value outside its bound) is exit 2, distinguishable from
/// the command having run and failed.
fn task_run(args: &[OsString]) -> ExitCode {
    let mut name: Option<String> = None;
    let mut id: Option<String> = None;
    let mut params = BTreeMap::new();
    let mut env = BTreeMap::new();
    let mut i = 0;
    while i < args.len() {
        match args[i].to_str() {
            Some("--param") | Some("-p") => match pair(args.get(i + 1), "--param") {
                Ok((k, v)) => {
                    params.insert(k, v);
                    i += 2;
                }
                Err(code) => return code,
            },
            Some("--env") | Some("-e") => match pair(args.get(i + 1), "--env") {
                Ok((k, v)) => {
                    env.insert(k, v);
                    i += 2;
                }
                Err(code) => return code,
            },
            Some("--session") => match args.get(i + 1).and_then(|a| a.to_str()) {
                Some(v) => {
                    id = Some(v.to_string());
                    i += 2;
                }
                None => {
                    diag::error("sbx: task run: `--session` needs a session id");
                    return ExitCode::from(2);
                }
            },
            Some(s) if !s.starts_with('-') && name.is_none() => {
                name = Some(s.to_string());
                i += 1;
            }
            other => {
                diag::error(&format!(
                    "sbx: task run: unexpected argument {:?}",
                    other.unwrap_or_default()
                ));
                eprint!("{}", help::page_usage(&["task", "run"]).unwrap_or_default());
                return ExitCode::from(2);
            }
        }
    }
    let Some(name) = name else {
        diag::error("sbx: task run: name the operation to run");
        eprint!("{}", help::page_usage(&["task", "run"]).unwrap_or_default());
        return ExitCode::from(2);
    };
    let socket = match socket_for(id.as_deref(), "run") {
        Ok(s) => s,
        Err(code) => return code,
    };
    let result = match client::run(&socket, &name, &params, &env) {
        Ok(r) => r,
        Err(e) => return unreachable_plane(&e),
    };
    if let Some(error) = &result.error {
        diag::error(&format!("sbx: task run: {error}"));
        // Not 2: that is a plausible exit code for the wrapped command itself, and a caller must be
        // able to tell "sbx refused to run it" from "it ran and exited 2". 125 is the convention
        // `env`/`docker` use for exactly this — the runner refused, nothing was executed.
        return ExitCode::from(REFUSED_EXIT);
    }
    // Streams go to their own channels, so a caller can pipe stdout while still seeing stderr.
    if let Some(out) = &result.stdout {
        print!("{out}");
    }
    if let Some(err) = &result.stderr {
        eprint!("{err}");
    }
    if result.timed_out {
        diag::warn(&format!(
            "the operation was killed at its timeout after {}ms",
            result.elapsed_ms
        ));
    }
    // Said for the same reason as the timeout: what came back is a partial result, and the exit
    // code alone would read as the command having failed on its own.
    if result.stopped {
        diag::warn(&format!(
            "invocation {} was stopped after {}ms",
            result.id, result.elapsed_ms
        ));
    }
    if result.truncated {
        diag::warn("the output reached the operation's `max_output` and was truncated");
    }
    if let Some((path, bytes)) = &result.output {
        diag::note(&format!("the operation wrote {bytes} byte(s) to {path}"));
    }
    // What `spawn` refused. Reported for the same reason as truncation: the refusal leaves no trace
    // in the result — the program that was refused decides whether to mention it, and many do not,
    // so an empty output would otherwise read as a command that simply found nothing.
    if !result.refused.is_empty() {
        diag::warn("the operation was not allowed to run:");
        for target in &result.refused {
            eprintln!("  {target}");
        }
        diag::note("this operation declares `spawn`; a program it needs must be listed there.");
    }
    if result.redacted > 0 {
        let named = match &result.nonce {
            // With the nonce on, report it: a `${NAME@nonce}` in the text is only unforgeable
            // because the nonce arrives out of band, here.
            Some(nonce) => format!(" (this invocation's nonce is {nonce})"),
            None => String::new(),
        };
        diag::warn(&format!(
            "{} credential value(s) were substituted out of the output{named}",
            result.redacted
        ));
    }
    // The command's own exit code, clamped into the byte a process can return.
    ExitCode::from(result.exit.clamp(0, 255) as u8)
}

/// The session's **host-only** socket — the log, what is running, and the stop.
///
/// Refuses outright when the environment says this sbx is talking to a plane rather than owning one:
/// these verbs are host-side by construction (the socket is never bound into a cage), and the
/// explicit refusal is what makes that a message instead of a connection error.
fn host_socket(id: Option<&str>, verb: &str) -> Result<PathBuf, ExitCode> {
    if std::env::var_os(TASK_SOCKET_ENV).is_some() {
        diag::error(&format!(
            "sbx: task {verb}: this is host-side only — a cage may invoke operations, not watch them"
        ));
        return Err(ExitCode::from(2));
    }
    let Some(layout) = store::Layout::from_env() else {
        diag::error(
            "sbx: cannot resolve the data directory (no $SBX_DATA_DIR, $XDG_DATA_HOME or $HOME).",
        );
        return Err(ExitCode::FAILURE);
    };
    let pid = resolve_task_session(layout.data_dir(), id, verb)?;
    Ok(sandbox::task_control::log_socket(layout.data_dir(), pid))
}

/// `sbx task status [<id>]`: the invocations this session is running right now.
fn task_status(args: &[OsString]) -> ExitCode {
    let id = match positional_id(args, "status") {
        Ok(id) => id,
        Err(code) => return code,
    };
    let socket = match host_socket(id.as_deref(), "status") {
        Ok(s) => s,
        Err(code) => return code,
    };
    match sandbox::task_control::read_status(&socket) {
        Ok(rows) if rows.is_empty() => {
            println!("no operation is running");
            ExitCode::SUCCESS
        }
        Ok(rows) => {
            let palette = style::Palette::for_stream(std::io::stdout().is_terminal());
            for row in rows {
                println!(
                    "{}{}{} {}",
                    palette.name,
                    row.id,
                    palette.reset,
                    row.fields.join("  ")
                );
            }
            ExitCode::SUCCESS
        }
        Err(e) => unreachable_plane(&e),
    }
}

/// `sbx task stop <invocation> [--session <id>]`: end one running invocation.
///
/// The argument is an **invocation** id — the number `sbx task status` shows and the one the
/// invocation's log line carries — while the session, when several offer operations, is named with
/// `--session`. That split is deliberate: the two ids are different things, and a verb that took
/// either positionally would let a mistyped session id read as an invocation.
fn task_stop(args: &[OsString]) -> ExitCode {
    let mut invocation: Option<String> = None;
    let mut session: Option<String> = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].to_str() {
            Some("--session") => match args.get(i + 1).and_then(|a| a.to_str()) {
                Some(v) => {
                    session = Some(v.to_string());
                    i += 2;
                }
                None => {
                    diag::error("sbx: task stop: `--session` needs a session id");
                    return ExitCode::from(2);
                }
            },
            Some(s) if !s.starts_with('-') && invocation.is_none() => {
                invocation = Some(s.to_string());
                i += 1;
            }
            other => {
                diag::error(&format!(
                    "sbx: task stop: unexpected argument {:?}",
                    other.unwrap_or_default()
                ));
                eprint!(
                    "{}",
                    help::page_usage(&["task", "stop"]).unwrap_or_default()
                );
                return ExitCode::from(2);
            }
        }
    }
    let Some(id) = invocation.and_then(|v| v.parse::<u64>().ok()) else {
        diag::error("sbx: task stop: name the invocation to stop, as `sbx task status` shows it");
        eprint!(
            "{}",
            help::page_usage(&["task", "stop"]).unwrap_or_default()
        );
        return ExitCode::from(2);
    };
    let socket = match host_socket(session.as_deref(), "stop") {
        Ok(s) => s,
        Err(code) => return code,
    };
    match sandbox::task_control::stop_invocation(&socket, id) {
        Ok(sandbox::task_control::StopReply::Stopped) => {
            println!("stopped invocation {id}");
            ExitCode::SUCCESS
        }
        // Accepted but not yet done, and said as exactly that: everything under way before the
        // command spawned — a credential resolving, a proxy standing up — completes first.
        Ok(sandbox::task_control::StopReply::Stopping) => {
            diag::warn(&format!(
                "invocation {id} was asked to stop and is still finishing"
            ));
            diag::hint("       `sbx task status` shows it until it ends.");
            ExitCode::FAILURE
        }
        Ok(sandbox::task_control::StopReply::Finished) => {
            diag::note(&format!("invocation {id} had already finished"));
            ExitCode::SUCCESS
        }
        Ok(sandbox::task_control::StopReply::Refused(reason)) => {
            diag::error(&format!("sbx: task stop: {reason}"));
            diag::hint("       `sbx task status` lists what is running.");
            ExitCode::FAILURE
        }
        Err(e) => unreachable_plane(&e),
    }
}

/// `sbx task logs [<id>]`: the session's invocation log — host-only, by design.
fn task_logs(args: &[OsString]) -> ExitCode {
    let id = match positional_id(args, "logs") {
        Ok(id) => id,
        Err(code) => return code,
    };
    let socket = match host_socket(id.as_deref(), "logs") {
        Ok(s) => s,
        Err(code) => return code,
    };
    match sandbox::task_control::read_log(&socket) {
        Ok(lines) => {
            let mut any = false;
            for line in lines {
                if line == "ok" {
                    continue;
                }
                if let Some(dropped) = line.strip_prefix("dropped=") {
                    diag::warn(&format!(
                        "{dropped} older invocation(s) fell out of the session's log ring"
                    ));
                    continue;
                }
                any = true;
                println!("{line}");
            }
            if !any {
                println!("no invocations recorded");
            }
            ExitCode::SUCCESS
        }
        Err(e) => unreachable_plane(&e),
    }
}

/// The single optional positional session id a listing verb takes.
fn positional_id(args: &[OsString], verb: &str) -> Result<Option<String>, ExitCode> {
    let mut id = None;
    for a in args {
        match a.to_str() {
            Some(s) if !s.starts_with('-') && id.is_none() => id = Some(s.to_string()),
            other => {
                diag::error(&format!(
                    "sbx: task {verb}: unexpected argument {:?}",
                    other.unwrap_or_default()
                ));
                return Err(ExitCode::from(2));
            }
        }
    }
    Ok(id)
}

/// Split a `KEY=VALUE` argument. A missing `=` is an error rather than an empty value: a parameter a
/// caller believes it set must never silently become nothing.
fn pair(arg: Option<&OsString>, flag: &str) -> Result<(String, String), ExitCode> {
    let Some(raw) = arg.and_then(|a| a.to_str()) else {
        diag::error(&format!("sbx: task run: `{flag}` needs KEY=VALUE"));
        return Err(ExitCode::from(2));
    };
    match raw.split_once('=') {
        Some((k, v)) if !k.is_empty() => Ok((k.to_string(), v.to_string())),
        _ => {
            diag::error(&format!("sbx: task run: `{flag} {raw}` is not KEY=VALUE"));
            Err(ExitCode::from(2))
        }
    }
}

/// Report a plane that could not be reached. The common causes are a session that has ended and a
/// config that declares no operation, so say both rather than only the errno.
fn unreachable_plane(e: &std::io::Error) -> ExitCode {
    diag::error(&format!("sbx: task: cannot reach the task plane: {e}"));
    diag::hint("       the session may have ended, or its config declares no `[task.<name>]`.");
    ExitCode::FAILURE
}
