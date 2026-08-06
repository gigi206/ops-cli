//! `sbx proc <subcommand>`: observe and govern what a running sandbox does inside its cage —
//! snapshot its process tree (`ls`), follow live exec events (`live`), read the exec log (`logs`),
//! and manage the `[proc]` allow/deny rules (`rules`/`allow`/`deny`/`pending`). Read-only and
//! host-side except the rule writes, which are trust-gated like `sbx net`. The session-resolution
//! and rule-persistence primitives it drives stay at the crate root (shared with `sbx fs`).

use std::ffi::OsString;
use std::io::IsTerminal;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Duration;

use crate::cli::logs;
use crate::{config, diag, help, observe, proc_policy, sandbox, session, store, style};
use crate::{
    egress_data_dir, format_log_time, persist_proc_rule, resolve_session_target,
    session_pids_for_app, session_pids_for_project, split_scope,
};

/// `sbx proc <subcommand>`: observe what a running sandbox is doing inside its cage. `ls` snapshots
/// a session's process tree. Read-only and host-side — the observability sibling of `sbx net`.
pub(crate) fn proc_cmd(args: Vec<OsString>) -> ExitCode {
    if let Some(code) = help::maybe_help("proc", &args) {
        return code;
    }
    match args.first().and_then(|a| a.to_str()) {
        Some("ls") | Some("list") => proc_ls(&args[1..]),
        Some("live") => proc_live(&args[1..]),
        Some("logs") | Some("log") => proc_logs(&args[1..]),
        Some("pending") => proc_pending(&args[1..]),
        Some("rules") => proc_rules(&args[1..]),
        // Each list is added to and taken back out with one vocabulary, so undoing a rule never
        // means dropping to the schema key it was written under. The removal verbs are config-only:
        // a `--session` overlay rule cannot be un-loaded (the control plane injects, it does not
        // retract), so it dies with the session instead.
        Some("allow") => proc_add_rule(config::manage::ProcList::Allow, &args[1..]),
        Some("unallow") => proc_remove_rule(config::manage::ProcList::Allow, &args[1..]),
        Some("deny") => proc_add_rule(config::manage::ProcList::Deny, &args[1..]),
        Some("undeny") => proc_remove_rule(config::manage::ProcList::Deny, &args[1..]),
        None => {
            eprint!("{}", help::page_usage(&["proc"]).unwrap_or_default());
            ExitCode::from(2)
        }
        Some(other) => {
            diag::error(&format!("sbx: proc: unknown subcommand `{other}`"));
            diag::hint("       run `sbx help proc` for usage.");
            ExitCode::from(2)
        }
    }
}

/// `sbx proc allow|deny <rule> [--local|--global|-c <file>] [-a <app>]`: add a process/exec rule to a
/// config file's `[proc]` allow/deny list. On a fresh project a `deny` bootstraps `mode = "enforce"`
/// (the denylist posture) so it takes effect at once; an `allow` requires `mode = "ask"` (it is inert
/// otherwise). A project `.sbx.toml` write is trust-gated and re-trusted, exactly like
/// `sbx net allow|deny`.
fn proc_add_rule(list: config::manage::ProcList, args: &[OsString]) -> ExitCode {
    let verb = match list {
        config::manage::ProcList::Allow => "allow",
        config::manage::ProcList::Deny => "deny",
    };
    // `--session` (load the rule into the live overlay of the running session(s)) and its `--all` scope
    // widener are extracted before `split_scope`, which rejects any flag it does not know; the
    // config-scope flags (`--local`/`--global`/`-c`) and `-a` ride it.
    let session = args.iter().any(|a| a.to_str() == Some("--session"));
    let all = args.iter().any(|a| a.to_str() == Some("--all"));
    let rest: Vec<OsString> = args
        .iter()
        .filter(|a| !matches!(a.to_str(), Some("--session") | Some("--all")))
        .cloned()
        .collect();
    let parsed = match split_scope(&rest) {
        Ok(p) => p,
        Err(e) => {
            diag::error(&format!("sbx: {e}"));
            return ExitCode::from(2);
        }
    };
    let rule = match parsed.positionals.as_slice() {
        [r] => r.trim().to_string(),
        [] => {
            diag::error(&format!(
                "sbx: usage: {}",
                help::synopsis_of(&["proc", verb])
            ));
            return ExitCode::from(2);
        }
        _ => {
            diag::error(&format!("sbx: proc {verb}: expected exactly one rule"));
            return ExitCode::from(2);
        }
    };
    if let Some(name) = &parsed.app {
        if !config::is_valid_app_name(name) {
            diag::error(&format!("sbx: invalid app name '{name}'"));
            return ExitCode::from(2);
        }
    }
    if let Err(e) = proc_policy::validate_rule(&rule) {
        diag::error(&format!("sbx: invalid rule {rule:?}: {e}"));
        return ExitCode::from(2);
    }
    let cwd = match std::env::current_dir() {
        Ok(d) => d,
        Err(e) => {
            diag::error(&format!("sbx: cannot read the current directory: {e}"));
            return ExitCode::FAILURE;
        }
    };

    if session {
        // `--session` writes no config file, so the file-scope flags do not apply — point at the
        // session-scope flags rather than silently ignore a `--global` the user expected to matter.
        if parsed.scope_explicit {
            diag::error(
                "sbx: --session loads a live rule and writes no file, so --local/--global/-c do not \
                 apply — use -a <app> or --all to scope the session(s)"
            );
            return ExitCode::from(2);
        }
        return proc_inject_session(list, &rule, all, parsed.app.as_deref(), &cwd);
    }

    // `--all` is a session-scope widener, meaningless for a config write (which targets one file).
    if all {
        diag::error(
            "sbx: --all only applies with --session (it widens a live rule to every session); a config \
             write targets one file — drop --all"
        );
        return ExitCode::from(2);
    }

    match persist_proc_rule(list, &rule, &parsed.scope, parsed.app.as_deref(), &cwd) {
        Ok(message) => {
            println!(
                "{}",
                style::prose(
                    &message,
                    &style::Palette::for_stream(std::io::stdout().is_terminal())
                )
            );
            ExitCode::SUCCESS
        }
        Err((code, message)) => {
            diag::error(&format!("sbx: {message}"));
            ExitCode::from(code)
        }
    }
}

/// The removal verb and the rule noun for one process/exec list: `sbx proc unallow` takes an `allow`
/// rule back out, `undeny` a `deny`. One spelling, so the usage errors, the help lookup and the
/// confirmation sentence cannot drift from the verb the user actually typed.
///
/// Its egress twin is `cli::net::removal_words`, deliberately a separate function: the two match
/// over unrelated enums, and a trait to share five lines would cost more than it saves.
fn removal_words(list: config::manage::ProcList) -> (&'static str, &'static str) {
    match list {
        config::manage::ProcList::Allow => ("unallow", "allow"),
        config::manage::ProcList::Deny => ("undeny", "deny"),
    }
}

/// `sbx proc unallow|undeny <rule> [--local|--global|-c <file>] [-a <app>]`: remove one exec rule
/// from a config file — the inverse of `sbx proc allow|deny`, so a rule is undone with the
/// vocabulary it was written in. Idempotent (removing a rule that is not there is a reported no-op,
/// not an error); a project `.sbx.toml` write is trust-gated and re-trusted exactly like the add
/// path. There is no `--session` form: the live overlay only takes rules
/// ([`sandbox::proc_control::inject_proc_rule`] has no retraction), so an overlay rule dies with the
/// session rather than being un-loaded.
///
/// The posture is deliberately left alone. The add path refuses a rule that would sit inert under
/// the current mode; taking one back out cannot create that state, so `mode` is untouched.
fn proc_remove_rule(list: config::manage::ProcList, args: &[OsString]) -> ExitCode {
    let (verb, _) = removal_words(list);
    if args
        .iter()
        .any(|a| matches!(a.to_str(), Some("--session") | Some("--all")))
    {
        diag::error(&format!(
            "sbx: proc {verb}: --session/--all do not apply — this removes a rule from a config file"
        ));
        return ExitCode::from(2);
    }
    let parsed = match split_scope(args) {
        Ok(p) => p,
        Err(e) => {
            diag::error(&format!("sbx: {e}"));
            return ExitCode::from(2);
        }
    };
    let rule = match parsed.positionals.as_slice() {
        [r] => r.trim().to_string(),
        [] => {
            diag::error(&format!(
                "sbx: usage: {}",
                help::synopsis_of(&["proc", verb])
            ));
            return ExitCode::from(2);
        }
        _ => {
            diag::error(&format!("sbx: proc {verb}: expected exactly one rule"));
            return ExitCode::from(2);
        }
    };
    if let Some(name) = &parsed.app {
        if !config::is_valid_app_name(name) {
            diag::error(&format!("sbx: invalid app name '{name}'"));
            return ExitCode::from(2);
        }
    }
    // The rule is NOT validated here, unlike the add path. A config file may already hold a rule a
    // later grammar would refuse, and refusing to remove it would leave the user no way out but a
    // hand edit; matching is an exact string compare, so an invalid rule simply matches nothing.
    let cwd = match std::env::current_dir() {
        Ok(d) => d,
        Err(e) => {
            diag::error(&format!("sbx: cannot read the current directory: {e}"));
            return ExitCode::FAILURE;
        }
    };
    match persist_proc_removal(list, &rule, &parsed.scope, parsed.app.as_deref(), &cwd) {
        Ok(message) => {
            println!(
                "{}",
                style::prose(
                    &message,
                    &style::Palette::for_stream(std::io::stdout().is_terminal())
                )
            );
            ExitCode::SUCCESS
        }
        Err((code, message)) => {
            diag::error(&format!("sbx: {message}"));
            ExitCode::from(code)
        }
    }
}

/// Remove a process/exec `rule` from the scoped config file — the removal sibling of
/// [`crate::persist_proc_rule`]. A rule that is not present is a reported no-op (no write, no
/// re-trust). Same scope vocabulary, trust gate, and error codes as the add path: a `-c <file>`
/// scope or an untrusted project config is code `2`; a trust-store/write/re-trust failure is code
/// `1`.
fn persist_proc_removal(
    list: config::manage::ProcList,
    rule: &str,
    scope: &config::manage::Scope,
    app: Option<&str>,
    base: &Path,
) -> Result<String, (u8, String)> {
    use config::manage::{self, RemoveOutcome};
    let (verb, noun) = removal_words(list);
    // The missing-store sentence is shorter than the add path's, which explains a consequence a
    // removal does not have: a rule that is written but cannot be trusted takes no effect, while a
    // rule that is removed is gone from the file either way.
    let crate::RuleWrite {
        path,
        app_key,
        target,
        store,
    } = crate::open_rule_write(
        "proc",
        verb,
        "cannot determine the trust store (set XDG_STATE_HOME or HOME)",
        scope,
        app,
        base,
    )?;
    let gated = store.is_some();

    let outcome =
        manage::remove_proc_rule(&path, app_key, list, rule).map_err(|e| (2, e.to_string()))?;

    match outcome {
        RemoveOutcome::NotPresent => Ok(format!("{noun} {rule} was not in {target} — no change")),
        RemoveOutcome::Removed => {
            // Re-trust only after an actual change. Fail-safe ordering: a crash between the write
            // and the trust leaves a correct-but-untrusted file the next launch drops.
            if let Some(store) = &store {
                // Fully qualified: inside `cli`, a bare `trust` would bind the sibling `cli::trust`
                // command module, not the crate-root trust store.
                crate::trust::trust(store, &path).map_err(|e| {
                    (
                        1,
                        format!(
                            "removed the rule but could not re-trust {}: {e} — run `sbx trust {}`",
                            path.display(),
                            config::PROJECT_CONFIG
                        ),
                    )
                })?;
            }
            let mut msg = format!("removed {noun} {rule} from {target}");
            if gated {
                msg.push_str(&format!("\nre-trusted {}", config::PROJECT_CONFIG));
            }
            Ok(msg)
        }
    }
}

/// `sbx proc allow|deny <rule> --session [-a <app>] [--all]`: load a rule into the **live overlay** of
/// the running enforcing session(s) instead of a config file — the proactive sibling of
/// `sbx proc pending`, and the proc analogue of `sbx net allow|deny --session`. The supervisor folds
/// the overlay into every decision (deny wins over any allow), so a `--session deny` cuts a target
/// immediately and a `--session allow` un-parks one under `ask`. It writes no config (no re-trust) and
/// dies with the session. Scopes to the current project by default; `-a <app>` / `--all` widen it.
fn proc_inject_session(
    list: config::manage::ProcList,
    rule: &str,
    all: bool,
    app: Option<&str>,
    cwd: &Path,
) -> ExitCode {
    let verdict = match list {
        config::manage::ProcList::Allow => proc_policy::Verdict::Allow,
        config::manage::ProcList::Deny => proc_policy::Verdict::Deny,
    };
    let verb = match list {
        config::manage::ProcList::Allow => "allow",
        config::manage::ProcList::Deny => "deny",
    };
    let data_dir = match egress_data_dir() {
        Ok(d) => d,
        Err(e) => {
            diag::error(&format!("sbx: {e}"));
            return ExitCode::FAILURE;
        }
    };
    // Two composing pid filters: the project (unless `--all` widens machine-wide) and the app (`-a`).
    let project_pids = if all {
        None
    } else {
        let canonical = match sandbox::project_identity(cwd) {
            Ok((_, c)) => c,
            Err(e) => {
                diag::error(&format!(
                    "sbx: cannot resolve the current project directory: {e}"
                ));
                return ExitCode::FAILURE;
            }
        };
        Some(session_pids_for_project(&data_dir, &canonical))
    };
    let app_pids = app.map(|name| session_pids_for_app(&data_dir, name));

    let sessions = match session::Registry::at(&data_dir).list() {
        Ok(s) => s,
        Err(e) => {
            diag::error(&format!("sbx: cannot read the session registry: {e}"));
            return ExitCode::FAILURE;
        }
    };
    let mut loaded: Vec<u32> = Vec::new();
    let mut inert: Vec<u32> = Vec::new();
    for s in sessions {
        let pid = s.pid;
        if app_pids.as_ref().is_some_and(|p| !p.contains(&pid)) {
            continue;
        }
        if project_pids.as_ref().is_some_and(|p| !p.contains(&pid)) {
            continue;
        }
        let socket = sandbox::proc_control::proc_control_socket(&data_dir, pid);
        match sandbox::proc_control::inject_proc_rule(&socket, verdict, rule) {
            Ok(sandbox::proc_control::InjectOutcome::Loaded) => loaded.push(pid),
            Ok(sandbox::proc_control::InjectOutcome::Inert) => inert.push(pid),
            // Refused (an older server) or a dead/non-enforcing socket — skip it.
            Ok(sandbox::proc_control::InjectOutcome::Refused) | Err(_) => {}
        }
    }

    if !loaded.is_empty() {
        let pal = style::Palette::for_stream(std::io::stdout().is_terminal());
        println!(
            "{}",
            style::prose(
                &format!(
                    "loaded {verb} rule `{rule}` into {} live session(s): {}",
                    loaded.len(),
                    loaded
                        .iter()
                        .map(u32::to_string)
                        .collect::<Vec<_>>()
                        .join(", ")
                ),
                &pal
            )
        );
    }
    if !inert.is_empty() {
        diag::warn(&format!(
            "an `allow` is inert in {} non-`ask` session(s) ({}) — under `enforce` everything not \
             denied already runs; use `deny`, or run those sessions in `ask` mode",
            inert.len(),
            inert
                .iter()
                .map(u32::to_string)
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }
    if loaded.is_empty() && inert.is_empty() {
        diag::error(
            "sbx: no enforcing session in scope to load the rule into — launch one with `[proc] mode \
             = \"enforce\"`/`\"ask\"`, or write it to config (drop --session)",
        );
        return ExitCode::from(1);
    }
    ExitCode::SUCCESS
}

/// `sbx proc rules [-a <app>] [--all]`: list the live `--session` rule overlay of the running
/// enforcing session(s). Config-file rules are shown by `sbx config show`; this lists only the
/// session-scoped rules loaded with `sbx proc allow|deny --session`, which nothing else surfaces.
fn proc_rules(args: &[OsString]) -> ExitCode {
    let all = args.iter().any(|a| a.to_str() == Some("--all"));
    let rest: Vec<OsString> = args
        .iter()
        .filter(|a| a.to_str() != Some("--all"))
        .cloned()
        .collect();
    let parsed = match split_scope(&rest) {
        Ok(p) => p,
        Err(e) => {
            diag::error(&format!("sbx: {e}"));
            return ExitCode::from(2);
        }
    };
    if !parsed.positionals.is_empty() {
        diag::error(&format!(
            "sbx: proc rules: unexpected argument `{}`",
            parsed.positionals[0]
        ));
        return ExitCode::from(2);
    }
    if parsed.scope_explicit {
        diag::error(
            "sbx: proc rules lists live session rules, not a config file — use -a <app>/--all to \
             scope, and `sbx config show` for the config policy",
        );
        return ExitCode::from(2);
    }
    let data_dir = match egress_data_dir() {
        Ok(d) => d,
        Err(e) => {
            diag::error(&format!("sbx: {e}"));
            return ExitCode::FAILURE;
        }
    };
    let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    let project_pids = if all {
        None
    } else {
        sandbox::project_identity(&cwd)
            .ok()
            .map(|(_, c)| session_pids_for_project(&data_dir, &c))
    };
    let app_pids = parsed
        .app
        .as_deref()
        .map(|n| session_pids_for_app(&data_dir, n));

    let sessions = match session::Registry::at(&data_dir).list() {
        Ok(s) => s,
        Err(e) => {
            diag::error(&format!("sbx: cannot read the session registry: {e}"));
            return ExitCode::FAILURE;
        }
    };
    let mut rows: Vec<(u32, &'static str, String)> = Vec::new();
    for s in sessions {
        let pid = s.pid;
        if app_pids.as_ref().is_some_and(|p| !p.contains(&pid)) {
            continue;
        }
        if project_pids.as_ref().is_some_and(|p| !p.contains(&pid)) {
            continue;
        }
        let socket = sandbox::proc_control::proc_control_socket(&data_dir, pid);
        if let Ok(overlay) = sandbox::proc_control::read_overlay_rules(&socket) {
            for r in overlay {
                rows.push((pid, r.verdict, r.rule));
            }
        }
    }
    if rows.is_empty() {
        println!("no live session rules");
        return ExitCode::SUCCESS;
    }
    let pal = style::Palette::for_stream(std::io::stdout().is_terminal());
    println!("{}live session rules{}", pal.head, pal.reset);
    for (pid, verdict, rule) in rows {
        let hue = if verdict == "deny" { pal.err } else { pal.ok };
        println!(
            "  {dim}{pid}{r}  {hue}{verdict}{r}  {rule}",
            dim = pal.dim,
            r = pal.reset,
        );
    }
    ExitCode::SUCCESS
}

/// `sbx proc pending [allow|deny <id>]`: list the `execve`s an `ask`-mode session has parked awaiting a
/// decision, or decide one by its id. An id is `<session-pid>.<notif-id>` (as the listing shows), or
/// `<session-pid>.*` to decide every parked `execve` in that session at once.
fn proc_pending(args: &[OsString]) -> ExitCode {
    match args.first().and_then(|a| a.to_str()) {
        Some("allow") => proc_pending_answer(&args[1..], true),
        Some("deny") => proc_pending_answer(&args[1..], false),
        _ => proc_pending_list(args),
    }
}

/// List every parked `execve` across the live observed sessions.
fn proc_pending_list(args: &[OsString]) -> ExitCode {
    // Every argument, not just the flag-shaped ones: a stray positional was silently dropped, so
    // `proc pending <something>` printed the full list and read as if it had been filtered by it.
    if let Err(code) = crate::cli::reject_extra(&["proc", "pending"], args) {
        return code;
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
    let pal = style::Palette::for_stream(std::io::stdout().is_terminal());
    let (h, dim, r) = (pal.head, pal.dim, pal.reset);
    let mut any = false;
    for s in &sessions {
        let socket = sandbox::proc_control::proc_control_socket(layout.data_dir(), s.pid);
        let parked = sandbox::proc_control::read_pending(&socket).unwrap_or_default();
        for p in parked {
            if !any {
                println!("{h}parked exec — awaiting a decision{r}");
                any = true;
            }
            println!(
                "  {}.{}  {dim}pid {} · {}s{r}  {}",
                s.pid, p.id, p.pid, p.waiting_secs, p.path
            );
        }
    }
    if !any {
        println!("{dim}no exec is parked awaiting a decision.{r}");
    }
    ExitCode::SUCCESS
}

/// Decide one (or, with `*`, all) parked `execve` by id `<session-pid>.<notif-id>`.
fn proc_pending_answer(args: &[OsString], allow: bool) -> ExitCode {
    let Some(id) = args.first().and_then(|a| a.to_str()) else {
        diag::error(&format!("sbx: proc pending {}: an id is required (`<session-pid>.<notif-id>`, or `<session-pid>.*`)", if allow { "allow" } else { "deny" }));
        return ExitCode::from(2);
    };
    let Some((pid_s, notif_s)) = id.split_once('.') else {
        diag::error(
            "sbx: proc pending: id must be `<session-pid>.<notif-id>` (from `sbx proc pending`)",
        );
        return ExitCode::from(2);
    };
    let Ok(pid) = pid_s.parse::<u32>() else {
        diag::error(&format!(
            "sbx: proc pending: `{pid_s}` is not a session pid"
        ));
        return ExitCode::from(2);
    };
    let Some(layout) = store::Layout::from_env() else {
        diag::error(
            "sbx: cannot resolve the data directory (no $SBX_DATA_DIR, $XDG_DATA_HOME or $HOME).",
        );
        return ExitCode::FAILURE;
    };
    let socket = sandbox::proc_control::proc_control_socket(layout.data_dir(), pid);
    let verb = if allow { "allowed" } else { "denied" };
    if notif_s == "*" {
        match sandbox::proc_control::answer_all_pending(&socket, allow) {
            Ok(paths) if !paths.is_empty() => {
                for p in paths {
                    println!("{verb} {p}");
                }
                ExitCode::SUCCESS
            }
            Ok(_) => {
                diag::error(&format!(
                    "sbx: proc pending: nothing parked in session {pid}"
                ));
                ExitCode::from(2)
            }
            Err(_) => {
                diag::error(&format!(
                    "sbx: proc pending: session {pid} is not enforcing (no control socket)"
                ));
                ExitCode::from(2)
            }
        }
    } else {
        let Ok(notif_id) = notif_s.parse::<u64>() else {
            diag::error(&format!(
                "sbx: proc pending: `{notif_s}` is not a notification id"
            ));
            return ExitCode::from(2);
        };
        match sandbox::proc_control::answer_pending(&socket, notif_id, allow) {
            Ok(Some(path)) => {
                println!("{verb} {path}");
                ExitCode::SUCCESS
            }
            Ok(None) => {
                diag::error(&format!(
                    "sbx: proc pending: no parked exec `{id}` (already decided or timed out)"
                ));
                ExitCode::from(2)
            }
            Err(_) => {
                diag::error(&format!(
                    "sbx: proc pending: session {pid} is not enforcing (no control socket)"
                ));
                ExitCode::from(2)
            }
        }
    }
}

/// `sbx proc ls [<id>] [--json]`: snapshot the process tree of a running session — what the agent
/// has spawned inside the cage, read host-side from `/proc` (no privilege, no cage cooperation).
/// `<id>` is the PID `sbx session ls` shows; with no id the sole live session is used, otherwise the
/// live sessions are listed so one can be named.
fn proc_ls(args: &[OsString]) -> ExitCode {
    let mut json = false;
    let mut id: Option<&str> = None;
    for a in args {
        match a.to_str() {
            Some("--json") => json = true,
            Some(s) if !s.starts_with('-') => {
                if id.is_some() {
                    diag::error("sbx: proc ls: at most one session id");
                    return ExitCode::from(2);
                }
                id = Some(s);
            }
            other => {
                diag::error(&format!(
                    "sbx: proc ls: unexpected argument {:?}",
                    other.unwrap_or_default()
                ));
                eprint!("{}", help::page_usage(&["proc", "ls"]).unwrap_or_default());
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

    let target = match resolve_session_target(&sessions, id, "proc") {
        Ok(t) => t,
        Err(code) => return code,
    };

    let Some(tree) = observe::tree(target.pid) else {
        diag::error(&format!(
            "sbx: proc ls: session {} has no readable process tree (it may have just exited).",
            target.pid
        ));
        return ExitCode::from(2);
    };

    if json {
        let obj = serde_json::json!({
            "session": {
                "pid": target.pid,
                "label": target.label(),
                "project": target.project.display().to_string(),
            },
            "tree": observe::to_json(&tree),
        });
        println!("{obj}");
        return ExitCode::SUCCESS;
    }

    let pal = style::Palette::for_stream(std::io::stdout().is_terminal());
    let (h, r) = (pal.head, pal.reset);
    println!(
        "{h}process tree — session {} [{}] {}{r}",
        target.pid,
        target.label(),
        target.project.display()
    );
    print!("{}", observe::render_human(&tree));
    ExitCode::SUCCESS
}

/// Parsed `sbx proc live` arguments. The parser is pure (no I/O) so its reject paths are
/// unit-testable without a terminal.
#[derive(Debug)]
struct ProcLiveArgs {
    id: Option<String>,
    interval: Duration,
    json: bool,
}

/// Parse `live [<id>] [-i|--interval <secs>] [--json]`. The refresh defaults to 1 second; a
/// zero/non-numeric interval, an unknown flag, or a second id is an error.
fn parse_proc_live_args(args: &[OsString]) -> Result<ProcLiveArgs, String> {
    let mut interval_secs: u64 = 1;
    let mut json = false;
    let mut id: Option<String> = None;
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.to_str() {
            Some("-i") | Some("--interval") => {
                let v = it.next().ok_or("`--interval` needs a value in seconds")?;
                let secs: u64 = v.to_str().and_then(|s| s.parse().ok()).ok_or_else(|| {
                    format!(
                        "invalid interval `{}` — expected a whole number of seconds",
                        v.to_string_lossy()
                    )
                })?;
                if secs == 0 {
                    return Err("interval must be at least 1 second".into());
                }
                interval_secs = secs;
            }
            Some("--json") => json = true,
            Some(s) if !s.starts_with('-') => {
                if id.is_some() {
                    return Err("at most one session id".into());
                }
                id = Some(s.to_string());
            }
            _ => return Err(format!("usage: {}", help::synopsis_of(&["proc", "live"]))),
        }
    }
    Ok(ProcLiveArgs {
        id,
        interval: Duration::from_secs(interval_secs),
        json,
    })
}

/// `sbx proc live [<id>] [-i|--interval <secs>] [--json]`: watch a running session's process tree,
/// redrawn in place on an interval (default 1s) until the session ends or you interrupt — the
/// `top`-style live view of `sbx proc ls`, so you see the agent spawn and finish processes in real
/// time. Requires a terminal; `--json` emits one snapshot object per tick and works in a pipe. No
/// launch / nix / network — it just polls `/proc`.
fn proc_live(args: &[OsString]) -> ExitCode {
    use std::io::Write as _;
    let parsed = match parse_proc_live_args(args) {
        Ok(p) => p,
        Err(e) => {
            diag::error(&format!("sbx: {e}"));
            return ExitCode::from(2);
        }
    };
    let is_tty = std::io::stdout().is_terminal();
    if !parsed.json && !is_tty {
        diag::error(
            "sbx: `proc live` needs a terminal — use `--json` to script it (one snapshot per tick)",
        );
        return ExitCode::from(2);
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
    let target = match resolve_session_target(&sessions, parsed.id.as_deref(), "proc") {
        Ok(t) => t,
        Err(code) => return code,
    };
    // Resolve once, then poll `/proc` by pid — the record is not needed again. When the pid's tree
    // vanishes the session has ended, so the loop exits cleanly.
    let (pid, label, project) = (target.pid, target.label(), target.project.clone());
    let pal = style::Palette::for_stream(is_tty);
    let (dim, r) = (pal.dim, pal.reset);
    let secs = parsed.interval.as_secs();
    loop {
        let tree = observe::tree(pid);
        let mut out = std::io::stdout().lock();
        let wrote = match &tree {
            Some(tree) if parsed.json => {
                let obj = serde_json::json!({
                    "session": {
                        "pid": pid,
                        "label": label.as_str(),
                        "project": project.display().to_string(),
                    },
                    "tree": observe::to_json(tree),
                });
                writeln!(out, "{obj}").and_then(|_| out.flush())
            }
            Some(tree) => {
                let body = observe::render_human(tree);
                write!(
                    out,
                    "\x1b[H{dim}live process tree · session {pid} [{label}] · refresh {secs}s · Ctrl-C to quit{r}\n{project}\n{body}\x1b[J",
                    project = project.display()
                )
                .and_then(|_| out.flush())
            }
            None => {
                // The session ended: stop cleanly rather than spin on an empty tree.
                drop(out);
                if !parsed.json {
                    println!("session {pid} ended.");
                }
                return ExitCode::SUCCESS;
            }
        };
        drop(out);
        if wrote.is_err() {
            // A broken downstream pipe (`… | head`) ends the view cleanly.
            return ExitCode::SUCCESS;
        }
        std::thread::sleep(parsed.interval);
    }
}

/// `sbx proc logs [<id>] [-f|--follow] [--json]`: the exec-event feed of a running observed session —
/// the processes the agent has spawned in the cage, in order, read host-side from the session's
/// process-observation ring over its per-session control socket. Only a session launched with
/// observation on (`--observe`) has a ring; one without is reported as unobserved rather than empty.
/// See [`crate::cli::logs::run`] for the flags and the follow loop it shares with its sibling lenses.
fn proc_logs(args: &[OsString]) -> ExitCode {
    logs::run(
        args,
        &logs::LogView {
            verb: "proc logs",
            page: &["proc", "logs"],
            session_verb: "proc",
            feed: "process feed",
            socket: sandbox::proc_control::proc_control_socket,
            read: sandbox::proc_control::read_exec_log,
            absent: |pid| {
                format!(
                    "sbx: proc logs: session {pid} is not being observed — relaunch it with \
                     `--observe` to record the processes it spawns."
                )
            },
            write_event: write_exec_event,
        },
    )
}

/// Write one exec event to `out`: a human line (`hh:mm:ss  pid  command`) or a JSON object (one per
/// line, so a `--follow` stream is valid NDJSON). Returns the write result so the caller ends cleanly
/// on a closed downstream pipe rather than panicking. Shared by the tail and follow reads.
fn write_exec_event(
    out: &mut dyn std::io::Write,
    session_pid: u32,
    e: &sandbox::proc_control::ExecEvent,
    json: bool,
    pal: &style::Palette,
) -> std::io::Result<()> {
    if json {
        let obj = serde_json::json!({
            "session_pid": session_pid,
            "seq": e.seq,
            "at_epoch_ms": e.at_epoch_ms as u64,
            "pid": e.pid,
            "verdict": e.verdict,
            "command": e.command,
        });
        writeln!(out, "{obj}")
    } else {
        let (dim, r) = (pal.dim, pal.reset);
        let time = format_log_time(e.at_epoch_ms);
        // Colour the enforcement verdict: allow=ok, deny=err, ask=warn; the poll `observe` tag is dim
        // (it records what ran, not a decision). A short, fixed-width column so the paths align.
        let hue = match e.verdict.as_str() {
            "allow" => pal.ok,
            "deny" => pal.err,
            "ask" => pal.warn,
            _ => pal.dim,
        };
        writeln!(
            out,
            "  {dim}{time}{r}  {hue}{:<7}{r} {}  {}",
            e.verdict, e.pid, e.command
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_proc_live_args_defaults_id_and_flags() {
        let osv = |xs: &[&str]| xs.iter().map(OsString::from).collect::<Vec<_>>();

        // No args → 1s default, no id, human output.
        let d = parse_proc_live_args(&[]).expect("bare proc live parses");
        assert_eq!(d.interval, Duration::from_secs(1));
        assert!(d.id.is_none());
        assert!(!d.json);

        // A positional id plus both flag spellings.
        let a = parse_proc_live_args(&osv(&["12345", "-i", "2", "--json"])).unwrap();
        assert_eq!(a.id.as_deref(), Some("12345"));
        assert_eq!(a.interval, Duration::from_secs(2));
        assert!(a.json);
        let b = parse_proc_live_args(&osv(&["--interval", "4"])).unwrap();
        assert_eq!(b.interval, Duration::from_secs(4));
        assert!(b.id.is_none());
    }

    #[test]
    fn parse_proc_live_args_rejects_bad_input() {
        let osv = |xs: &[&str]| xs.iter().map(OsString::from).collect::<Vec<_>>();
        assert!(
            parse_proc_live_args(&osv(&["-i", "0"])).is_err(),
            "zero interval busy-loops"
        );
        assert!(parse_proc_live_args(&osv(&["-i", "soon"]))
            .unwrap_err()
            .contains("soon"));
        assert!(
            parse_proc_live_args(&osv(&["-i"])).is_err(),
            "missing value"
        );
        assert!(
            parse_proc_live_args(&osv(&["--nope"])).is_err(),
            "unknown flag"
        );
        assert!(
            parse_proc_live_args(&osv(&["1", "2"])).is_err(),
            "at most one id"
        );
    }
}
