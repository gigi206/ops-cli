//! `sbx fs <subcommand>`: observe the files a running session writes in its project tree.
//! Currently one subcommand, `logs` (alias `log`), read host-side from the session's write journal
//! through the shared lens view in [`crate::cli::logs`].

use std::ffi::OsString;
use std::process::ExitCode;

use crate::cli::logs;
use crate::{diag, format_log_time, help, sandbox, style};

/// `sbx fs <subcommand>`: observe the files a running session writes in its project tree. Currently
/// one subcommand, `logs`; `log` is accepted as an alias.
pub(crate) fn fs_cmd(args: Vec<OsString>) -> ExitCode {
    if let Some(code) = help::maybe_help("fs", &args) {
        return code;
    }
    match args.first().and_then(|a| a.to_str()) {
        Some("logs") | Some("log") => fs_logs(&args[1..]),
        None => {
            eprint!("{}", help::page_usage(&["fs"]).unwrap_or_default());
            ExitCode::from(2)
        }
        Some(other) => {
            diag::error(&format!("sbx: fs: unknown subcommand `{other}`"));
            diag::hint("       run `sbx help fs` for usage.");
            ExitCode::from(2)
        }
    }
}

/// `sbx fs logs [<id>] [-f|--follow] [--json]`: read the file-write feed of a running session — the
/// files the agent creates, writes, deletes, or moves in its project tree, observed host-side with
/// inotify (no privilege, no cage cooperation). Only a session launched with `--observe` has a feed;
/// a session without one is reported as unobserved (distinct from an empty feed). See
/// [`crate::cli::logs::run`] for the flags and the follow loop it shares with its sibling lenses.
fn fs_logs(args: &[OsString]) -> ExitCode {
    logs::run(
        args,
        &logs::LogView {
            verb: "fs logs",
            page: &["fs", "logs"],
            session_verb: "fs",
            feed: "file-write feed",
            socket: sandbox::fs_control::fs_control_socket,
            read: sandbox::fs_control::read_fs_log,
            absent: |pid| {
                format!(
                    "sbx: fs logs: session {pid} is not being observed — relaunch it with \
                     `--observe` to record the files it writes."
                )
            },
            write_event: write_fs_event,
        },
    )
}

/// Write one filesystem event to `out`: a human line (`hh:mm:ss  kind    path`) or a JSON object (one
/// per line, so a `--follow` stream is valid NDJSON). Returns the write result so the caller ends
/// cleanly on a closed downstream pipe rather than panicking. Shared by the tail and follow reads.
fn write_fs_event(
    out: &mut dyn std::io::Write,
    session_pid: u32,
    e: &sandbox::fs_control::FsEvent,
    json: bool,
    pal: &style::Palette,
) -> std::io::Result<()> {
    if json {
        let obj = serde_json::json!({
            "session_pid": session_pid,
            "seq": e.seq,
            "at_epoch_ms": e.at_epoch_ms as u64,
            "kind": e.kind.token(),
            "path": e.path,
        });
        writeln!(out, "{obj}")
    } else {
        let (dim, r) = (pal.dim, pal.reset);
        let time = format_log_time(e.at_epoch_ms);
        writeln!(out, "  {dim}{time}{r}  {:<6}  {}", e.kind.token(), e.path)
    }
}
