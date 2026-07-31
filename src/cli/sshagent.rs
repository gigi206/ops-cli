//! `sbx ssh-agent <subcommand>`: the credential lens of a running session — what the cage asked the
//! ssh-agent broker for, and what it got. Currently one subcommand, `logs` (alias `log`), read
//! host-side from the session's decision ring. It shares the crate-root
//! `resolve_session_target`/`format_log_time` helpers with `sbx fs` and `sbx proc`.

use std::ffi::OsString;
use std::io::IsTerminal;
use std::process::ExitCode;
use std::time::Duration;

use crate::{diag, format_log_time, help, resolve_session_target, sandbox, session, store, style};

/// `sbx ssh-agent <subcommand>`. Currently one subcommand, `logs`; `log` is accepted as an alias.
pub(crate) fn ssh_agent_cmd(args: Vec<OsString>) -> ExitCode {
    if let Some(code) = help::maybe_help("ssh-agent", &args) {
        return code;
    }
    match args.first().and_then(|a| a.to_str()) {
        Some("logs") | Some("log") => agent_logs(&args[1..]),
        None => {
            eprint!("{}", help::page_usage(&["ssh-agent"]).unwrap_or_default());
            ExitCode::from(2)
        }
        Some(other) => {
            diag::error(&format!("sbx: ssh-agent: unknown subcommand `{other}`"));
            diag::hint("       run `sbx help ssh-agent` for usage.");
            ExitCode::from(2)
        }
    }
}

/// `sbx ssh-agent logs [<id>] [-f|--follow] [--json]`: the signature feed of a running session —
/// every key offered, every signature produced, and everything the broker turned away. `<id>` is the
/// PID `sbx session ls` shows; with no id the sole live session is used. A session whose config
/// grants no key has no broker at all, and is reported as such (distinct from an empty feed).
fn agent_logs(args: &[OsString]) -> ExitCode {
    let mut json = false;
    let mut follow = false;
    let mut id: Option<&str> = None;
    for a in args {
        match a.to_str() {
            Some("--json") => json = true,
            Some("-f") | Some("--follow") => follow = true,
            Some(s) if !s.starts_with('-') => {
                if id.is_some() {
                    diag::error("sbx: ssh-agent logs: at most one session id");
                    return ExitCode::from(2);
                }
                id = Some(s);
            }
            other => {
                diag::error(&format!(
                    "sbx: ssh-agent logs: unexpected argument {:?}",
                    other.unwrap_or_default()
                ));
                eprint!(
                    "{}",
                    help::page_usage(&["ssh-agent", "logs"]).unwrap_or_default()
                );
                return ExitCode::from(2);
            }
        }
    }

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
    let target = match resolve_session_target(&sessions, id, "ssh-agent logs") {
        Ok(t) => t,
        Err(code) => return code,
    };
    let socket = sandbox::sshagent_control::agent_control_socket(layout.data_dir(), target.pid);

    // The first read is a tail of the whole retained window. A connect failure means this session
    // has no broker — its config granted no key, or none the host agent held matched — which is a
    // different thing from a broker that has been asked for nothing.
    let first = match sandbox::sshagent_control::read_agent_log(&socket, None) {
        Ok(s) => s,
        Err(_) => {
            diag::error(&format!(
                "sbx: ssh-agent logs: session {} has no ssh-agent broker — nothing in its config \
                 grants a key (`[ssh_agent] allow`), or no key the host agent holds matched.",
                target.pid
            ));
            return ExitCode::from(2);
        }
    };

    let pal = style::Palette::for_stream(std::io::stdout().is_terminal());
    use std::io::Write as _;

    // Write the header and the tail batch through a locked, error-checked stdout: a closed
    // downstream pipe (`… | head`) ends the view cleanly (exit 0) rather than panicking on the
    // broken pipe (Rust ignores SIGPIPE, so a bare `println!` would panic on EPIPE).
    {
        let mut out = std::io::stdout().lock();
        let wrote = (|| -> std::io::Result<()> {
            if !json {
                let (h, r) = (pal.head, pal.reset);
                writeln!(
                    out,
                    "{h}ssh-agent feed — session {} [{}] {}{r}",
                    target.pid,
                    target.label(),
                    target.project.display()
                )?;
            }
            for e in &first.events {
                write_agent_event(&mut out, target.pid, e, json, &pal)?;
            }
            out.flush()
        })();
        if wrote.is_err() {
            return ExitCode::SUCCESS;
        }
    }

    if !follow {
        return ExitCode::SUCCESS;
    }

    // Follow: poll past the cursor until the session ends. The broker unlinks its socket on drop, so
    // a connect failure after the first successful read is the clean end-of-session signal (a local
    // UDS connect does not fail transiently); Ctrl+C stops it, and a closed downstream pipe too.
    let mut cursor = first.head;
    loop {
        std::thread::sleep(Duration::from_millis(400));
        let snap = match sandbox::sshagent_control::read_agent_log(&socket, Some(cursor)) {
            Ok(s) => s,
            Err(_) => {
                if !json {
                    let mut out = std::io::stdout().lock();
                    let (dim, r) = (pal.dim, pal.reset);
                    let _ = writeln!(out, "  {dim}(session {} ended){r}", target.pid);
                }
                return ExitCode::SUCCESS;
            }
        };
        let mut out = std::io::stdout().lock();
        let wrote = (|| -> std::io::Result<()> {
            if snap.dropped > 0 && !json {
                let (dim, r) = (pal.dim, pal.reset);
                writeln!(
                    out,
                    "  {dim}({} earlier event(s) evicted from the ring before this poll){r}",
                    snap.dropped
                )?;
            }
            for e in &snap.events {
                write_agent_event(&mut out, target.pid, e, json, &pal)?;
            }
            out.flush()
        })();
        drop(out);
        if wrote.is_err() {
            return ExitCode::SUCCESS;
        }
        cursor = snap.head;
    }
}

/// Write one broker decision to `out`: a human line (`hh:mm:ss  kind  detail`) or a JSON object (one
/// per line, so a `--follow` stream is valid NDJSON). Returns the write result so the caller ends
/// cleanly on a closed downstream pipe rather than panicking.
fn write_agent_event(
    out: &mut impl std::io::Write,
    session_pid: u32,
    e: &sandbox::sshagent_control::AgentEvent,
    json: bool,
    pal: &style::Palette,
) -> std::io::Result<()> {
    if json {
        let obj = serde_json::json!({
            "session_pid": session_pid,
            "seq": e.seq,
            "at_epoch_ms": e.at_epoch_ms as u64,
            "kind": e.kind.token(),
            "detail": e.detail,
        });
        writeln!(out, "{obj}")
    } else {
        let (dim, r) = (pal.dim, pal.reset);
        let time = format_log_time(e.at_epoch_ms);
        writeln!(out, "  {dim}{time}{r}  {:<7}  {}", e.kind.token(), e.detail)
    }
}
