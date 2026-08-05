//! `sbx ssh-agent <subcommand>`: the credential lens of a running session — what the cage asked the
//! ssh-agent broker for, and what it got. Currently one subcommand, `logs` (alias `log`), read
//! host-side from the session's decision ring through the shared lens view in [`crate::cli::logs`].

use std::ffi::OsString;
use std::process::ExitCode;

use crate::cli::logs;
use crate::{diag, format_log_time, help, sandbox, style};

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
/// every key offered, every signature produced, and everything the broker turned away. A session
/// whose config grants no key has no broker at all, and is reported as such (distinct from an empty
/// feed). See [`crate::cli::logs::run`] for the flags and the follow loop it shares with its sibling
/// lenses.
fn agent_logs(args: &[OsString]) -> ExitCode {
    logs::run(
        args,
        &logs::LogView {
            verb: "ssh-agent logs",
            page: &["ssh-agent", "logs"],
            session_verb: "ssh-agent logs",
            feed: "ssh-agent feed",
            socket: sandbox::sshagent_control::agent_control_socket,
            read: sandbox::sshagent_control::read_agent_log,
            absent: |pid| {
                format!(
                    "sbx: ssh-agent logs: session {pid} has no ssh-agent broker — nothing in its \
                     config grants a key (`[ssh_agent] allow`), or no key the host agent holds \
                     matched."
                )
            },
            write_event: write_agent_event,
        },
    )
}

/// Write one broker decision to `out`: a human line (`hh:mm:ss  kind  detail`) or a JSON object (one
/// per line, so a `--follow` stream is valid NDJSON). Returns the write result so the caller ends
/// cleanly on a closed downstream pipe rather than panicking.
fn write_agent_event(
    out: &mut dyn std::io::Write,
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
