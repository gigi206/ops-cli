//! `sbx fs <subcommand>`: observe the files a running session writes in its project tree, and
//! manage the `[fs]` masks that close a project path off inside the cage. `logs` (alias `log`) is
//! read host-side from the session's write journal through the shared lens view in
//! [`crate::cli::logs`]; `deny`/`readonly` and their inverses write a config file through the same
//! trust-gated primitives `sbx net` and `sbx proc` use.
//!
//! **There is no `--session` form here, and it is not an omission.** A mask is a *mount*, and a
//! cage's mounts are fixed when it is built: `[fs]` resolves at launch, so there is no live overlay
//! to load one into the way `sbx proc allow --session` does. That is also why this family has no
//! `rules` verb — its siblings' `rules` lists the live session overlay, which nothing else surfaces,
//! and `sbx config show` already lists the effective masks and the layer that set each.

use std::ffi::OsString;
use std::path::Path;
use std::process::ExitCode;

use crate::cli::logs;
use crate::{
    config, config_cwd, diag, format_log_time, help, report_rule_write, sandbox, split_one_rule,
    style,
};

/// `sbx fs <subcommand>`: observe the files a running session writes in its project tree, and
/// manage the `[fs]` masks. `log` is accepted as an alias of `logs`.
pub(crate) fn fs_cmd(args: &[OsString]) -> ExitCode {
    if let Some(code) = help::maybe_help("fs", args) {
        return code;
    }
    use config::manage::FsList;
    match args.first().and_then(|a| a.to_str()) {
        Some("logs") | Some("log") => fs_logs(&args[1..]),
        Some("deny") => fs_add_mask(FsList::Deny, &args[1..]),
        Some("undeny") => fs_remove_mask(FsList::Deny, &args[1..]),
        Some("readonly") => fs_add_mask(FsList::Readonly, &args[1..]),
        Some("unreadonly") => fs_remove_mask(FsList::Readonly, &args[1..]),
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

/// The verb that writes one `[fs]` list and the noun a message calls its entries. Written once so
/// the usage error, the help lookup and the success line cannot drift from the verb typed — the
/// filesystem twin of `cli::proc::removal_words`, and separate from it for the same stated reason:
/// the two match over unrelated enums.
fn mask_words(list: config::manage::FsList) -> (&'static str, &'static str) {
    match list {
        config::manage::FsList::Deny => ("deny", "undeny"),
        config::manage::FsList::Readonly => ("readonly", "unreadonly"),
    }
}

/// Why this family refuses the session flags its siblings take. Stated rather than ignored: a
/// `--session` a user expected to close a path *now* would otherwise be silently dropped, and the
/// answer — relaunch — is not one they would guess from silence.
fn fs_takes_no_session_flags(verb: &str) -> String {
    format!(
        "sbx: fs {verb} does not take --session/--all — a mask is a mount, and a cage's mounts are \
         fixed when it is built, so a mask closes a path from the next launch on"
    )
}

/// `sbx fs deny|readonly <path> [--local|--global] [-a <app>]`: add one path mask to a config file.
/// `deny` closes the path to the cage (the name stays visible, the content is refused); `readonly`
/// leaves it readable and refuses writes. The entry is a path pattern relative to the project, on
/// the grammar [`crate::config::fspolicy`] states and validates at launch.
///
/// A project `.sbx.toml` write is trust-gated and re-trusted exactly like `sbx net allow` and
/// `sbx proc allow` — see [`crate::persist_fs_mask`] for why that gate applies to a table whose
/// masks are honored from an untrusted source anyway.
fn fs_add_mask(list: config::manage::FsList, args: &[OsString]) -> ExitCode {
    let (verb, _) = mask_words(list);
    if let Err(code) = refuse_session_flags(verb, args) {
        return code;
    }
    let (parsed, entry) = match split_one_rule("fs", verb, args) {
        Ok(v) => v,
        Err(code) => return code,
    };
    let cwd = match config_cwd() {
        Ok(d) => d,
        Err(code) => return code,
    };
    report_rule_write(crate::persist_fs_mask(
        list,
        &entry,
        &parsed.scope,
        parsed.app.as_deref(),
        &cwd,
    ))
}

/// `sbx fs undeny|unreadonly <path> [--local|--global] [-a <app>]`: take one path mask back out of a
/// config file — the inverse of [`fs_add_mask`], so a mask is undone with the vocabulary it was
/// written in. Idempotent: removing an entry that is not there is a reported no-op, not an error.
///
/// The entry is not validated here, unlike the add path, for the reason the proc removal states: a
/// file may already hold an entry a later grammar would refuse, and refusing to remove it would
/// leave no way out but a hand edit. Matching is an exact string compare.
fn fs_remove_mask(list: config::manage::FsList, args: &[OsString]) -> ExitCode {
    let (noun, verb) = mask_words(list);
    if let Err(code) = refuse_session_flags(verb, args) {
        return code;
    }
    let (parsed, entry) = match split_one_rule("fs", verb, args) {
        Ok(v) => v,
        Err(code) => return code,
    };
    let cwd = match config_cwd() {
        Ok(d) => d,
        Err(code) => return code,
    };
    report_rule_write(persist_fs_removal(
        list,
        noun,
        verb,
        &entry,
        &parsed.scope,
        parsed.app.as_deref(),
        &cwd,
    ))
}

/// Refuse `--session`/`--all` before anything is parsed or written, naming why this family does not
/// take them. Shared by both writing verbs so the sentence is one definition.
fn refuse_session_flags(verb: &str, args: &[OsString]) -> Result<(), ExitCode> {
    if args
        .iter()
        .any(|a| matches!(a.to_str(), Some("--session") | Some("--all")))
    {
        diag::error(&fs_takes_no_session_flags(verb));
        return Err(ExitCode::from(2));
    }
    Ok(())
}

/// Remove a `[fs]` mask from the scoped config file — the removal sibling of
/// [`crate::persist_fs_mask`], on the shared terms [`crate::persist_removal`] states: an entry that
/// is not present is a reported no-op (no write, no re-trust), a `-c <file>` scope or an untrusted
/// project config is code `2`, and a store/write/re-trust failure is code `1`.
fn persist_fs_removal(
    list: config::manage::FsList,
    noun: &str,
    verb: &str,
    entry: &str,
    scope: &config::manage::Scope,
    app: Option<&str>,
    base: &Path,
) -> Result<String, (u8, String)> {
    crate::persist_removal(
        "fs",
        (verb, noun),
        entry,
        scope,
        app,
        base,
        |path, app_key| config::manage::remove_fs_mask(path, app_key, list, entry),
    )
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
            dir: sandbox::fs_control::fs_control_dir,
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
