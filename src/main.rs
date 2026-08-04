//! sbx — sandbox launcher (bubblewrap + daemonless nix).
//!
//! The `doctor` preflight verifies the load-bearing runtime requirements before
//! anything else can run: capability-bearing unprivileged user namespaces (the
//! security boundary everything else rests on), the bubblewrap engine, and the
//! nix binary that drives the user-owned store. A missing load-bearing
//! requirement is a hard failure with remediation — never a silent fallback to
//! a weaker engine, because that would mean no security boundary at all.

mod allowlist;
mod cli;
mod config;
mod diag;
#[cfg(test)]
mod docs_coverage;
mod help;
mod notify;
mod observe;
mod pathfind;
mod paths;
mod plugins;
mod proc_policy;
mod sandbox;
mod session;
mod storage;
mod store;
mod style;
#[cfg(test)]
mod testutil;
mod trust;

use std::ffi::OsString;
use std::io::IsTerminal;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

fn main() -> ExitCode {
    // `args_os`, not `args`: a command run via `sbx run` may carry non-UTF-8
    // arguments, and panicking on them would be wrong.
    let mut args = std::env::args_os().skip(1);
    let cmd = args.next();
    let rest: Vec<OsString> = args.collect();
    let name = match cmd.as_deref().and_then(|s| s.to_str()) {
        // No command at all is a usage error; an explicit help request is not. Both render
        // the same command list — to stderr/exit 2 for the error, to stdout/exit 0 for help.
        None => {
            eprint!("{}", help::top_level_usage());
            return ExitCode::from(2);
        }
        Some("help" | "--help" | "-h") => return help::dispatch(rest),
        Some(name) => name,
    };

    // A known command carrying a help flag shows the page for the deepest command path it
    // names (so `sbx plugins store add --help` lands on that page). `run` (which forwards
    // `--help` after a `--`) and `mise` (a passthrough) handle a leading help flag
    // themselves; an *unknown* command is left to the dispatch below, which names it.
    if help::is_command(name) && !matches!(name, "run" | "mise") {
        if let Some(code) = help::maybe_help(name, &rest) {
            return code;
        }
    }

    cli::dispatch(name, rest)
}

/// Resolve the session a `proc`/`fs` subcommand acts on: an explicit PID (a 0-or-1 match among the
/// live set), or the sole live session when no id is given. On ambiguity or absence it prints guidance
/// (tagged with `verb`) and returns the exit code the caller should propagate.
fn resolve_session_target<'a>(
    sessions: &'a [session::Session],
    id: Option<&str>,
    verb: &str,
) -> Result<&'a session::Session, ExitCode> {
    match id {
        Some(id) => sessions
            .iter()
            .find(|s| s.pid.to_string() == id)
            .ok_or_else(|| {
                diag::error(&format!(
                    "sbx: {verb}: no live session '{id}' — run `sbx session ls` to list them."
                ));
                ExitCode::from(2)
            }),
        None => match sessions {
            [one] => Ok(one),
            [] => {
                eprintln!("sbx: no active sandbox sessions.");
                Err(ExitCode::from(2))
            }
            many => {
                eprintln!(
                    "sbx: {verb}: {} live sessions — name one by its PID:",
                    many.len()
                );
                for s in many {
                    eprintln!("       {}  [{}]  {}", s.pid, s.label(), s.project.display());
                }
                Err(ExitCode::from(2))
            }
        },
    }
}

/// The trailing flags every `config` management verb accepts: the target scope (`-l`/`--local`
/// default, `-g`/`--global`, `-c`/`--config <file>`), `--trust`, and the cross-cutting
/// `-a`/`--app <name>` that rewrites a key under that app's table. A verb consumes the fields it
/// supports and rejects the rest (`path`/`edit` have no key, so they reject `--app`).
struct ScopeArgs {
    positionals: Vec<String>,
    scope: config::manage::Scope,
    /// Whether a scope flag (`-l`/`-g`/`-c`) was given explicitly, as opposed to the `Local`
    /// default — `sbx config path` shows the resolution overview when none was.
    scope_explicit: bool,
    trust: bool,
    app: Option<String>,
}

/// Parse a management verb's trailing flags out of `args`. `--` ends flag parsing, so a value that
/// begins with `-` can still be passed.
fn split_scope(args: &[OsString]) -> Result<ScopeArgs, String> {
    use config::manage::Scope;
    let mut positionals = Vec::new();
    let mut scope = Scope::Local;
    let mut scope_explicit = false;
    let mut trust = false;
    let mut app = None;
    let mut only_positional = false;
    let mut it = args.iter();
    while let Some(arg) = it.next() {
        if only_positional {
            positionals.push(arg.to_string_lossy().into_owned());
            continue;
        }
        match arg.to_str() {
            Some("--") => only_positional = true,
            Some("--local") | Some("-l") => {
                scope = Scope::Local;
                scope_explicit = true;
            }
            Some("--global") | Some("-g") => {
                scope = Scope::Global;
                scope_explicit = true;
            }
            Some("-c") | Some("--config") => {
                let file = it
                    .next()
                    .ok_or_else(|| "`-c` needs a file path".to_string())?;
                scope = Scope::File(PathBuf::from(file));
                scope_explicit = true;
            }
            Some("--app") | Some("-a") => {
                let name = it
                    .next()
                    .ok_or_else(|| "`--app` needs an app name".to_string())?;
                app = Some(name.to_string_lossy().into_owned());
            }
            Some("--trust") => trust = true,
            Some(flag) if flag.starts_with('-') && flag != "-" => {
                return Err(format!("unknown flag `{flag}`"));
            }
            _ => positionals.push(arg.to_string_lossy().into_owned()),
        }
    }
    Ok(ScopeArgs {
        positionals,
        scope,
        scope_explicit,
        trust,
        app,
    })
}

/// Resolve the working directory, mapping a failure to an error exit. Shared by the verbs.
fn config_cwd() -> Result<PathBuf, ExitCode> {
    std::env::current_dir().map_err(|e| {
        eprintln!("sbx: cannot read the current directory: {e}");
        ExitCode::FAILURE
    })
}

/// `sbx config path`: with no scope flag, show the config files a launch resolves, in order, each
/// with whether it exists — so it is clear where sbx looks (and that a default project `.sbx.toml`
/// need not exist). With an explicit scope (`-l`/`-g`/`-c`), print the single bare path that scope
/// targets — the file `set`/`unset`/`edit` would touch, for scripting and for finding the global
/// config.
/// `sbx path [--json]`: show every on-disk location sbx uses, grouped by XDG base
/// (data, config, state), marking which exist and enumerating the per-project /
/// per-app / per-profile entries actually on disk. Read-only, no trust gate, no
/// network — the layout map that answers "where on disk does sbx put things?".
/// The counterpart of `sbx config path` (the config files in resolution order)
/// for the rest of the filesystem.
fn path_cmd(args: &[OsString]) -> ExitCode {
    let mut json = false;
    for a in args {
        match a.to_str() {
            Some("--json") => json = true,
            Some(other) => {
                diag::error(&format!("sbx: path: unknown argument `{other}`"));
                diag::hint("       run `sbx help path` for usage.");
                return ExitCode::from(2);
            }
            None => {
                eprintln!("sbx: path: argument is not valid UTF-8");
                return ExitCode::from(2);
            }
        }
    }
    let layout = store::Layout::from_env();
    let view = paths::view(layout.as_ref());
    if json {
        match serde_json::to_string_pretty(&view) {
            Ok(s) => {
                println!("{s}");
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("sbx: path: failed to serialize: {e}");
                ExitCode::FAILURE
            }
        }
    } else {
        let pal = style::Palette::for_stream(std::io::stdout().is_terminal());
        print!("{}", paths::render(&view, &pal));
        ExitCode::SUCCESS
    }
}

/// Consume one leading override flag (`--config`/`--env`) and its value from `head` into `sink` —
/// the `--flag=value` inline form, or the next argument. A missing or non-text value is a usage
/// error (exit 2). Shared by the launch verbs so `--config`/`--env` parse identically everywhere.
fn take_flag_value(
    head: &mut Vec<OsString>,
    sink: &mut Vec<String>,
    verb: &str,
    flag: &str,
) -> Result<(), ExitCode> {
    let token = head.remove(0);
    // `--flag=value`: the value is inline (split on the first `=`, so `--env=K=V` keeps `K=V`).
    if let Some((_, inline)) = token.to_str().and_then(|s| s.split_once('=')) {
        sink.push(inline.to_string());
        return Ok(());
    }
    // `--flag value`: the value is the next argument.
    match head.first().and_then(|a| a.to_str()) {
        Some(v) => {
            let v = v.to_string();
            head.remove(0);
            sink.push(v);
            Ok(())
        }
        None => {
            diag::error(&format!("sbx: {verb}: `{flag}` needs a value"));
            Err(ExitCode::from(2))
        }
    }
}

/// The bare flag name of `raw`, stripping a `=value` suffix — so `--config` and `--config=x` both
/// dispatch on `--config`.
fn flag_name(raw: &str) -> &str {
    raw.split_once('=').map(|(f, _)| f).unwrap_or(raw)
}

/// Consume one leading boolean override flag (`--gpu`/`--dbus`) from `head` into `sink`. Unlike
/// [`take_flag_value`], a boolean flag is *optional-value*: a bare `--gpu` means `true`, and only the
/// inline `--gpu=true`/`--gpu=false` form carries a value — the next argument is **never** consumed,
/// so `--gpu <app>` leaves the app name in place. The raw `true`/`false` string is pushed as-is; the
/// override collector validates it (a value other than true/false is a usage error there), keeping the
/// grammar identical for the CLI flag and its `SBX_GPU`/`SBX_DBUS` environment twin.
fn take_flag_bool(head: &mut Vec<OsString>, sink: &mut Vec<String>) {
    let token = head.remove(0);
    // `--gpu=value`: the value is inline; a bare `--gpu` normalizes to `true`.
    let value = match token.to_str().and_then(|s| s.split_once('=')) {
        Some((_, v)) => v.to_string(),
        None => "true".to_string(),
    };
    sink.push(value);
}

/// If the leading token of `head` is a one-shot override flag, consume it and its value into `cli`
/// and return `Some(result)` (`Ok` on success, `Err(code)` on a missing value); return `None` when
/// the token is not an override flag, so the caller handles it (a command, the app name, an unknown
/// flag). Shared by `run`/`shell`/`app`, so the whole `--config`/`--env`/`--net`/`--gui`/`--nixpkgs`/
/// `--bind`/`--limit`/`--package` set parses identically everywhere. A scalar flag (`--net`/`--gui`/
/// `--nixpkgs`) may repeat — the merge takes the last; the collection flags take them all.
fn take_override_flag(
    head: &mut Vec<OsString>,
    cli: &mut config::CliOverrides,
    verb: &str,
) -> Option<Result<(), ExitCode>> {
    // Resolve the flag name to an owned string first, ending the borrow of `head` before the value
    // is taken (which mutates `head`).
    let name = flag_name(head.first()?.to_str()?).to_string();
    // The boolean flags are optional-value (`--gpu`, `--gpu=true`, `--gpu=false`) and must never
    // consume the following argument — else `sbx app --gpu <name>` would swallow the app name — so
    // they take a dedicated path rather than the value-required `take_flag_value`.
    match name.as_str() {
        "--gpu" => {
            take_flag_bool(head, &mut cli.gpu);
            return Some(Ok(()));
        }
        "--audio" => {
            take_flag_bool(head, &mut cli.audio);
            return Some(Ok(()));
        }
        "--dbus" => {
            take_flag_bool(head, &mut cli.dbus);
            return Some(Ok(()));
        }
        _ => {}
    }
    let sink = match name.as_str() {
        "--config" => &mut cli.config,
        "--env" => &mut cli.env,
        "--net" => &mut cli.net,
        "--gui" => &mut cli.gui,
        "--proc" => &mut cli.proc,
        "--notify" => &mut cli.notify,
        "--nixpkgs" => &mut cli.nixpkgs,
        "--bind" => &mut cli.binds,
        "--forward" => &mut cli.forward,
        "--limit" => &mut cli.limits,
        "--package" => &mut cli.packages,
        "--seccomp" => &mut cli.seccomp,
        "--device" => &mut cli.devices,
        _ => return None,
    };
    Some(take_flag_value(head, sink, verb, &name))
}

/// Build the one-shot override from the collected CLI flag values and the ambient `SBX_*`
/// environment, surfacing its notices. Fail-closed: a malformed override (bad TOML, an unreadable
/// `@file`, a `--env`/`--limit`/`--package` without `=`, a bad `--net`/`--bind` value) is a usage
/// error (exit 2), never a silent drop that would launch a different posture than asked.
fn build_override(cli: config::CliOverrides) -> Result<config::Override, ExitCode> {
    match config::overrides::collect(&cli) {
        Ok(ov) => {
            for notice in ov.notices() {
                diag::warn(notice);
            }
            Ok(ov)
        }
        Err(e) => {
            eprintln!("sbx: {e}");
            Err(ExitCode::from(2))
        }
    }
}

/// Fold the named app's overlay onto the resolved baseline so a read-only diagnostic sees the
/// *effective* policy `sbx app <name>` would launch with — the shared core of `sbx test net --app`
/// and `sbx net rules --app`. The baseline warnings are the caller's to surface; this captures the
/// warning count *before* the merge and emits only the app's own new ones (no double-print). On an
/// unknown app it returns a pointed message (the caller prepends its own `sbx: <verb>:` prefix);
/// the merge itself reuses `config::load` → `merge_app`, so the trust gate and the "a global app
/// keeps its posture under an untrusted project" property hold through that path, not new code.
fn fold_app_overlay(resolved: &mut config::Resolved, name: &str) -> Result<(), String> {
    let Some(app_cfg) = resolved.apps.remove(name) else {
        let names: Vec<&str> = resolved.apps.keys().map(String::as_str).collect();
        return Err(if names.is_empty() {
            format!("no app named {name:?} (no apps are declared for this directory)")
        } else {
            format!("no app named {name:?} (declared: {})", names.join(", "))
        });
    };
    let before = resolved.warnings.len();
    resolved.merge_app(app_cfg);
    for w in &resolved.warnings[before..] {
        diag::warn(w);
    }
    Ok(())
}

/// The displayed keyword for a filtered-egress policy's default action: `allow` (a denylist —
/// everything public reaches except the deny rules) or `deny` (an allowlist — only the listed and
/// built-in hosts reach). Used wherever `sbx config` renders a filtered network posture.
fn net_mode_word(default_action: config::view::NetDefaultView) -> &'static str {
    match default_action {
        config::view::NetDefaultView::Deny => "deny",
        config::view::NetDefaultView::Allow => "allow",
        config::view::NetDefaultView::Ask => "ask",
    }
}

/// The data directory the control sockets live under, or a pointed error.
fn egress_data_dir() -> Result<PathBuf, String> {
    store::Layout::from_env()
        .map(|l| l.data_dir().to_path_buf())
        .ok_or_else(|| {
            "cannot locate the data directory (set $SBX_DATA_DIR, $XDG_DATA_HOME or $HOME)"
                .to_string()
        })
}

/// The human context of the ask-mode control sockets, cross-referenced from the session registry:
/// `(pid, project root, display label)` per live session. Best-effort — a session not in the
/// registry (a race, or one that failed to register) simply lists without context, and a `--save`
/// for it falls back to the cwd. The registry is keyed by the same pid the control socket filename
/// carries, so the two line up.
fn pending_session_context(data_dir: &Path) -> Vec<(u32, PathBuf, String)> {
    session::Registry::at(data_dir)
        .list()
        .unwrap_or_default()
        .into_iter()
        .map(|s| {
            let label = s.label();
            (s.pid, s.project, label)
        })
        .collect()
}

/// The live-session pids that belong to app `name` (an `sbx app <name>` session), from the registry
/// — the basis for scoping `sbx net pending` to one app. A session not in the registry (a race, or a
/// plain shell) has no known app, so under a filter it is excluded: scoping to an app shows only
/// sessions the registry confirms are that app.
fn session_pids_for_app(data_dir: &Path, name: &str) -> std::collections::HashSet<u32> {
    session::Registry::at(data_dir)
        .list()
        .unwrap_or_default()
        .into_iter()
        .filter(|s| s.app() == Some(name))
        .map(|s| s.pid)
        .collect()
}

/// The app a session pid runs as (`sbx app <name>`), from the registry — or `None` if the session is
/// a plain project shell, or is not in the registry. The basis for validating that a `<pid>.<seq>` id
/// the user scoped with `--app` really belongs to that app.
fn session_app_of(data_dir: &Path, pid: u32) -> Option<String> {
    session::Registry::at(data_dir)
        .list()
        .unwrap_or_default()
        .into_iter()
        .find(|s| s.pid == pid)
        .and_then(|s| s.app().map(str::to_string))
}

/// The live-session pids running in `project` (a canonical project root), from the registry — the
/// basis for scoping `sbx net pending` to the current project. The match is `s.project == project`,
/// the exact comparison the launch path records and `sbx gc` already uses (both sides go through
/// [`sandbox::project_identity`]), so a session and its project never disagree. A session not in the
/// registry has no known project, so under a filter it is excluded.
fn session_pids_for_project(data_dir: &Path, project: &Path) -> std::collections::HashSet<u32> {
    session::Registry::at(data_dir)
        .list()
        .unwrap_or_default()
        .into_iter()
        .filter(|s| s.project == project)
        .map(|s| s.pid)
        .collect()
}

/// An event's wall-clock time of day as local `hh:mm:ss` — a stable, correlatable stamp for a log
/// (the JSON keeps the absolute `at_epoch_ms`). Local time comes from the process timezone via the C
/// library (`localtime_r`, the reentrant/thread-safe form); a conversion failure (an implausible
/// stamp) renders `--:--:--` rather than panicking.
fn format_log_time(at_epoch_ms: u128) -> String {
    // `libc::time_t` is the exact argument type `localtime_r` expects. On musl it carries a
    // deprecation notice — a heads-up that musl 1.2 widened `time_t` to 64-bit and a future `libc`
    // will drop this alias — but it stays the correct FFI type, and on sbx's x86_64 target it is
    // already 64-bit, so the widening is a no-op here. Silence the notice on the one line that names
    // it rather than reach for a hardcoded integer type that would be wrong on a 32-bit target.
    #[allow(deprecated)]
    let secs = (at_epoch_ms / 1000) as libc::time_t;
    // SAFETY: `localtime_r` writes the broken-down local time into our stack `tm` and reads only the
    // `time_t` we pass; it is the thread-safe variant, so no shared state is mutated.
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    if unsafe { libc::localtime_r(&secs, &mut tm) }.is_null() {
        return "--:--:--".to_string();
    }
    format!("{:02}:{:02}:{:02}", tm.tm_hour, tm.tm_min, tm.tm_sec)
}

/// Pre-flight the trust gate for a `--local` save at `cwd`, *before* any irreversible action (a bulk
/// drain unblocks agents and cannot be undone). Mirrors [`persist_egress_rule`]'s gate exactly — same
/// `scope_path`, same trust-store, same "existing config must be trusted" rule — so a save that would
/// later refuse refuses here instead, with nothing answered. Absent or already-trusted is fine (sbx's
/// append is then the sole delta).
/// The write-side trust gate for a `--local` save: an existing-but-untrusted (or changed) project
/// config must not be silently blessed by an appended rule — the user reviews and re-trusts it
/// first. An absent config (bootstrap) or an already-trusted one is fine, so sbx's edit is the sole
/// delta from the trusted bytes. Pure on the `(exists, state)` pair, so the refuse/allow matrix is
/// unit-testable without a filesystem.
fn local_save_permitted(exists: bool, state: trust::TrustState) -> bool {
    !exists || state == trust::TrustState::Trusted
}

fn precheck_local_save(cwd: &Path) -> Result<(), (u8, String)> {
    use config::manage::{self, Scope};
    let store = trust::default_store_dir().ok_or((
        1,
        "cannot determine the trust store (set XDG_STATE_HOME or HOME) — needed to trust the project \
         config a `--local` save writes; use --global instead"
            .to_string(),
    ))?;
    let path = manage::scope_path(&Scope::Local, cwd).map_err(|e| (1, e.to_string()))?;
    if !local_save_permitted(path.exists(), trust::state(&store, &path)) {
        return Err((
            2,
            format!(
                "{} is not trusted — review it and run `sbx trust {}`, then retry (a `--local` save \
                 will not silently bless an untrusted project)",
                path.display(),
                config::PROJECT_CONFIG
            ),
        ));
    }
    Ok(())
}

/// Resolve where an egress-rule write lands and how to name it, shared by the single-rule
/// [`persist_egress_rule`] and the bulk [`net_pending_drain_and_save`] so the two can never disagree
/// about the file or the target its summary reports. Returns the file to edit, the in-file app key
/// (`None` writes a top-level `[network]` — a profile's shape, or a baseline config; `Some(name)`
/// writes `[app.<name>.network]` — a project overlay), and the human target description (which
/// already carries the app, so no caller adds a separate " under app" suffix).
///
/// The one divergence from a plain scope→path map is an **app-scoped global** write: a global app
/// lives as a profile file (`apps/<name>.toml`), never an inline `[app.<name>]` in the global config
/// (which is forbidden), so it targets the profile with a top-level key.
fn egress_write_target<'a>(
    scope: &config::manage::Scope,
    app: Option<&'a str>,
    base: &Path,
) -> Result<(PathBuf, Option<&'a str>, String), (u8, String)> {
    use config::manage::{self, Scope};
    let (path, app_key) = match (scope, app) {
        (Scope::Global, Some(name)) => (
            manage::scope_app_path(scope, base, name).map_err(|e| (1, e.to_string()))?,
            None,
        ),
        (Scope::Local, Some(name)) => (
            manage::scope_path(scope, base).map_err(|e| (1, e.to_string()))?,
            Some(name),
        ),
        _ => (
            manage::scope_path(scope, base).map_err(|e| (1, e.to_string()))?,
            app,
        ),
    };
    let target = match (scope, app) {
        (Scope::Global, None) => "the global config".to_string(),
        (Scope::Global, Some(a)) => format!("the app profile `{a}` ({})", path.display()),
        (Scope::Local, None) => "the project config".to_string(),
        (Scope::Local, Some(a)) => format!("the project config (app `{a}`)"),
        (Scope::File(p), None) => p.display().to_string(),
        (Scope::File(p), Some(a)) => format!("{} (app `{a}`)", p.display()),
    };
    Ok((path, app_key, target))
}

/// Persist an egress `rule` to the scoped config file, trust-gating a project write and re-trusting
/// it after — the shared writer behind `sbx net allow|deny <rule>` and the `--save` of
/// `sbx net pending allow|deny`. Returns the success line to print, or `(exit-code, message)`: a
/// refusal (a `-c` file scope, an untrusted project config, a posture conflict) is code `2`; an
/// operational failure (no trust store, an unwritable path, a re-trust failure) is code `1`. A
/// `Scope::File` is refused — the vocabulary is local/global/app, and a `-c` write would be
/// silently dropped at launch (neither trusted-by-location nor the gated project path).
fn persist_egress_rule(
    list: config::manage::EgressList,
    rule: &str,
    scope: &config::manage::Scope,
    app: Option<&str>,
    base: &Path,
) -> Result<String, (u8, String)> {
    use config::manage::{self, AddOutcome, Scope};
    let verb = match list {
        manage::EgressList::Allow => "allow",
        manage::EgressList::Deny => "deny",
        manage::EgressList::Mute => "mute",
    };
    if matches!(scope, Scope::File(_)) {
        return Err((
            2,
            format!("`sbx net {verb}` does not take `-c <file>` — use --local, --global, or --app"),
        ));
    }
    // Validate the app name here, in the shared writer, so every path that persists a rule is
    // covered — including `sbx net pending --save --app <name>`, whose by-id form does not
    // pre-check the name. An invalid or reserved name keys a table `resolve_apps` drops at load,
    // so the rule would be silently inert; refuse it rather than report a durable restriction.
    if let Some(name) = app {
        if !config::is_valid_app_name(name) {
            return Err((2, format!("`{name}` is not a valid app name")));
        }
    }
    // `base` is the directory a `--local` scope resolves against: the cwd for `sbx net allow|deny`,
    // or the *answered session's* project for `sbx net pending --save` (so the rule lands in the
    // project the agent runs in, not wherever the user happens to stand). Global ignores it. The
    // file, the in-file table shape (`app_key`), and the human `target` are resolved together — and
    // shared with the drain path — so the write and the message it prints can never disagree about
    // where the rule landed.
    let (path, app_key, target) = egress_write_target(scope, app, base)?;

    // A write to the project `.sbx.toml` is trust-gated; the global config and the app profiles
    // under `apps/` are trusted by location.
    let gated = matches!(scope, Scope::Local);
    let store =
        if gated {
            Some(trust::default_store_dir().ok_or((
            1,
            "cannot determine the trust store (set XDG_STATE_HOME or HOME); the rule would be \
             written but could not be trusted, so it would not take effect — use --global, or set \
             the trust store"
                .to_string(),
        ))?)
        } else {
            None
        };

    // Pre-check: an existing-but-untrusted project config must not be silently blessed by an append
    // — the user reviews and trusts it first. Absent or already-trusted is fine: sbx's edit is then
    // the sole delta from the trusted bytes.
    if let Some(store) = &store {
        if !local_save_permitted(path.exists(), trust::state(store, &path)) {
            return Err((
                2,
                format!(
                    "{} is not trusted — review it and run `sbx trust {}`, then retry",
                    path.display(),
                    config::PROJECT_CONFIG
                ),
            ));
        }
    }

    let outcome =
        manage::add_egress_rule(&path, app_key, list, rule).map_err(|e| (2, e.to_string()))?;

    // Re-trust the project config after the write. Ordering is fail-safe: a crash between the write
    // and the trust leaves a correct-but-untrusted file, which the next launch drops — the rule does
    // not take effect, never a security hole.
    if let Some(store) = &store {
        trust::trust(store, &path).map_err(|e| {
            (
                1,
                format!(
                    "wrote the rule but could not re-trust {}: {e} — run `sbx trust {}` so it \
                     takes effect",
                    path.display(),
                    config::PROJECT_CONFIG
                ),
            )
        })?;
    }

    Ok(match outcome {
        AddOutcome::AlreadyPresent => {
            format!("{verb} {rule} is already present in {target} — no change")
        }
        AddOutcome::Added { created_mode } => {
            let mut msg = match created_mode {
                Some(mode) => {
                    format!("set network mode `{mode}` and added {verb} {rule} to {target}")
                }
                None => format!("added {verb} {rule} to {target}"),
            };
            if gated {
                msg.push_str(&format!("\nre-trusted {}", config::PROJECT_CONFIG));
            }
            msg
        }
    })
}

/// Persist a process/exec `rule` to the scoped config file's `[proc]` list, trust-gating a project
/// write and re-trusting it after — the proc sibling of [`persist_egress_rule`]. Returns the success
/// line to print, or `(exit-code, message)`: a refusal (a `-c` file scope, an untrusted project
/// config, a non-enforcing/inert posture) is code `2`; an operational failure (no trust store, an
/// unwritable path, a re-trust failure) is code `1`. The scope/app resolution and trust interaction
/// are shared with the egress path ([`egress_write_target`] / [`local_save_permitted`]).
fn persist_proc_rule(
    list: config::manage::ProcList,
    rule: &str,
    scope: &config::manage::Scope,
    app: Option<&str>,
    base: &Path,
) -> Result<String, (u8, String)> {
    use config::manage::{self, AddOutcome, ProcList, Scope};
    let verb = match list {
        ProcList::Allow => "allow",
        ProcList::Deny => "deny",
    };
    if matches!(scope, Scope::File(_)) {
        return Err((
            2,
            format!(
                "`sbx proc {verb}` does not take `-c <file>` — use --local, --global, or --app"
            ),
        ));
    }
    if let Some(name) = app {
        if !config::is_valid_app_name(name) {
            return Err((2, format!("`{name}` is not a valid app name")));
        }
    }
    let (path, app_key, target) = egress_write_target(scope, app, base)?;

    // A write to the project `.sbx.toml` is trust-gated; the global config and the app profiles under
    // `apps/` are trusted by location.
    let gated = matches!(scope, Scope::Local);
    let store =
        if gated {
            Some(trust::default_store_dir().ok_or((
            1,
            "cannot determine the trust store (set XDG_STATE_HOME or HOME); the rule would be \
             written but could not be trusted, so it would not take effect — use --global, or set \
             the trust store"
                .to_string(),
        ))?)
        } else {
            None
        };

    // Pre-check: an existing-but-untrusted project config must not be silently blessed by an append.
    if let Some(store) = &store {
        if !local_save_permitted(path.exists(), trust::state(store, &path)) {
            return Err((
                2,
                format!(
                    "{} is not trusted — review it and run `sbx trust {}`, then retry",
                    path.display(),
                    config::PROJECT_CONFIG
                ),
            ));
        }
    }

    let outcome =
        manage::add_proc_rule(&path, app_key, list, rule).map_err(|e| (2, e.to_string()))?;

    // Re-trust after the write; the ordering is fail-safe (a crash between leaves a correct-but-
    // untrusted file the next launch drops — the rule does not take effect, never a security hole).
    if let Some(store) = &store {
        trust::trust(store, &path).map_err(|e| {
            (
                1,
                format!(
                    "wrote the rule but could not re-trust {}: {e} — run `sbx trust {}` so it \
                     takes effect",
                    path.display(),
                    config::PROJECT_CONFIG
                ),
            )
        })?;
    }

    Ok(match outcome {
        AddOutcome::AlreadyPresent => {
            format!("{verb} {rule} is already present in {target} — no change")
        }
        AddOutcome::Added { created_mode } => {
            let mut msg = match created_mode {
                Some(mode) => format!("set proc mode `{mode}` and added {verb} {rule} to {target}"),
                None => format!("added {verb} {rule} to {target}"),
            };
            if gated {
                msg.push_str(&format!("\nre-trusted {}", config::PROJECT_CONFIG));
            }
            msg
        }
    })
}

/// A short revision for display — the first seven hex characters, like git.
fn short_rev(rev: &str) -> &str {
    &rev[..rev.len().min(7)]
}

/// Seconds since boot, from `/proc/uptime` (its first field). Used only to show a
/// session's age, so a parse failure degrades to "unknown", never an error.
fn uptime_seconds() -> Option<f64> {
    std::fs::read_to_string("/proc/uptime")
        .ok()?
        .split_whitespace()
        .next()?
        .parse()
        .ok()
}

/// A compact age like `2h05m` or `4m07s`.
fn format_age(secs: u64) -> String {
    let (h, m, s) = (secs / 3600, (secs % 3600) / 60, secs % 60);
    if h > 0 {
        format!("{h}h{m:02}m")
    } else {
        format!("{m}m{s:02}s")
    }
}

/// Best-effort nix version (the first line of `nix --version`). The version is
/// store-independent, so it runs nix directly.
fn nix_version(nix: &Path) -> Option<String> {
    let out = std::process::Command::new(nix)
        .arg("--version")
        .output()
        .ok()?;
    out.status.success().then(|| {
        String::from_utf8_lossy(&out.stdout)
            .lines()
            .next()
            .unwrap_or_default()
            .trim()
            .to_string()
    })
}

/// Outcome of probing unprivileged user-namespace support.
#[derive(Debug, PartialEq, Eq)]
enum Userns {
    /// A capability-bearing user namespace can be created — bwrap will work.
    Ok,
    /// `unshare(CLONE_NEWUSER)` itself fails — userns disabled outright.
    Unsupported,
    /// The namespace is created but stripped of capabilities (the restricted
    /// Ubuntu 24.04+ default): `unshare(CLONE_NEWUSER)` succeeds, yet the child
    /// cannot create the further namespaces bwrap needs. It looks available but
    /// is not — so it must be reported distinctly from outright absence.
    CapStripped,
}

/// Map the probe child's exit status to an outcome. Kept separate from the
/// unsafe fork machinery so this policy is unit-testable: the child exits `1`
/// when the user namespace cannot be created, `2` when it is created but lacks
/// the capabilities to nest a mount namespace, and `0` when both succeed.
fn classify_probe_exit(code: i32) -> Userns {
    match code {
        0 => Userns::Ok,
        2 => Userns::CapStripped,
        _ => Userns::Unsupported,
    }
}

/// Ground-truth probe in a forked child: create a user namespace, then create a
/// mount namespace inside it. The second step needs `CAP_SYS_ADMIN` in the new
/// userns, so it succeeds only when the namespace is capability-bearing — which
/// is exactly what bubblewrap requires. Doing it in a child keeps the parent's
/// namespaces untouched; only a real attempt is decisive (sysctls can lie).
fn probe_userns() -> Userns {
    // SAFETY: the child path touches only async-signal-safe calls (`unshare`,
    // `_exit`) before exiting; the parent only reaps it and classifies.
    unsafe {
        match libc::fork() {
            0 => {
                if libc::unshare(libc::CLONE_NEWUSER) != 0 {
                    libc::_exit(1);
                }
                if libc::unshare(libc::CLONE_NEWNS) != 0 {
                    libc::_exit(2);
                }
                libc::_exit(0);
            }
            -1 => Userns::Unsupported,
            pid => {
                let mut status: libc::c_int = 0;
                if libc::waitpid(pid, &mut status, 0) == -1 || !libc::WIFEXITED(status) {
                    return Userns::Unsupported;
                }
                classify_probe_exit(libc::WEXITSTATUS(status))
            }
        }
    }
}

fn read_sysctl(path: &str) -> Option<String> {
    std::fs::read_to_string(path)
        .ok()
        .map(|s| s.trim().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::TmpDir;

    #[test]
    fn read_sysctl_trims_value_and_handles_absence() {
        let dir = TmpDir::new();
        let f = dir.join("val");
        std::fs::write(&f, b"1\n").unwrap();
        assert_eq!(read_sysctl(f.to_str().unwrap()).as_deref(), Some("1"));
        assert_eq!(read_sysctl(dir.join("nope").to_str().unwrap()), None);
    }

    #[test]
    fn classify_probe_exit_maps_status_to_outcome() {
        assert_eq!(classify_probe_exit(0), Userns::Ok);
        assert_eq!(classify_probe_exit(2), Userns::CapStripped);
        assert_eq!(classify_probe_exit(1), Userns::Unsupported);
        assert_eq!(classify_probe_exit(42), Userns::Unsupported);
    }

    #[test]
    fn local_save_gate_blocks_only_an_existing_untrusted_config() {
        use trust::TrustState::{Changed, Trusted, Untrusted};
        // absent config → allowed (a `--local` save bootstraps it, then trusts it)
        assert!(local_save_permitted(false, Untrusted));
        // already-trusted config → allowed (sbx's append is the sole delta)
        assert!(local_save_permitted(true, Trusted));
        // existing untrusted/changed config → refused (never silently bless it)
        assert!(!local_save_permitted(true, Untrusted));
        assert!(!local_save_permitted(true, Changed));
    }

    #[test]
    fn short_rev_takes_the_first_seven_hex() {
        assert_eq!(
            short_rev("9ae611a455b90cf061d8f332b977e387bda8e1ca"),
            "9ae611a"
        );
        assert_eq!(short_rev("abc"), "abc"); // shorter than seven is returned whole
    }

    #[test]
    fn format_log_time_renders_local_hh_mm_ss() {
        // Shape is always HH:MM:SS with each field two digits and in range — regardless of the host
        // timezone (so the test is deterministic on any machine).
        let t = format_log_time(1_700_000_000_123);
        let parts: Vec<&str> = t.split(':').collect();
        assert_eq!(parts.len(), 3, "HH:MM:SS: {t}");
        assert!(
            parts
                .iter()
                .all(|p| p.len() == 2 && p.bytes().all(|b| b.is_ascii_digit())),
            "two-digit fields: {t}"
        );
        let (h, m, s): (u32, u32, u32) = (
            parts[0].parse().unwrap(),
            parts[1].parse().unwrap(),
            parts[2].parse().unwrap(),
        );
        assert!(h < 24 && m < 60 && s < 60, "each field in range: {t}");
        // Seconds are timezone-independent (every real UTC offset is a whole number of minutes), so
        // this is exact without pinning `TZ`: 1_700_000_000 mod 60 == 20, and epoch 0 is ...:00.
        assert_eq!(s, 20, "the seconds field is exact across zones: {t}");
        assert!(format_log_time(0).ends_with(":00"), "epoch 0 is HH:MM:00");
    }

    #[test]
    fn egress_write_target_names_the_file_and_the_target_by_scope() {
        // The single source of truth for both the single-rule and the drain summaries. A `--local`
        // app targets the project `.sbx.toml` with an `[app.<name>]` overlay key; an explicit `-c`
        // file targets that path. Both are env-independent (the `--global` app arm resolves the
        // profile path from the config home, so it is covered by the `net pending … --save -g --app`
        // integration test instead). The target string must carry the app itself — a caller adds no
        // separate " under app" suffix.
        use config::manage::Scope;
        let cwd = std::path::Path::new("/some/cwd");

        let (path, key, target) = egress_write_target(&Scope::Local, Some("demo"), cwd).unwrap();
        assert_eq!(path, cwd.join(config::PROJECT_CONFIG));
        assert_eq!(key, Some("demo")); // a project overlay writes `[app.demo.network]`
        assert_eq!(target, "the project config (app `demo`)");

        let (_, key, target) = egress_write_target(&Scope::Local, None, cwd).unwrap();
        assert_eq!(key, None);
        assert_eq!(target, "the project config");

        let explicit = std::path::PathBuf::from("/etc/sbx.toml");
        let (path, key, target) =
            egress_write_target(&Scope::File(explicit.clone()), None, cwd).unwrap();
        assert_eq!(path, explicit);
        assert_eq!(key, None);
        assert_eq!(target, "/etc/sbx.toml");
    }

    #[test]
    fn session_pids_for_app_selects_only_that_apps_live_sessions() {
        use crate::testutil::TmpDir;
        use session::{Kind, Registry, Session, SessionRuntime};

        // Register THIS process (alive, so it survives the registry's liveness pruning) as an
        // `sbx app demo-app` session in a throwaway data dir.
        let data = TmpDir::new();
        let me = Session::current(
            std::path::PathBuf::from("/home/u/proj"),
            Kind::Run,
            SessionRuntime::GlobalApp("demo-app".to_string()),
        )
        .expect("read this process's session identity");
        Registry::at(data.path())
            .register(&me)
            .expect("register the session");

        // The filter returns this app's live pid...
        let pids = session_pids_for_app(data.path(), "demo-app");
        assert!(
            pids.contains(&std::process::id()),
            "the app's live session must be selected: {pids:?}"
        );
        // ...and nothing for a different app, so an `--all -a other` drain excludes this session.
        assert!(
            session_pids_for_app(data.path(), "other").is_empty(),
            "a different app must select no session"
        );
    }

    #[test]
    fn session_pids_for_project_selects_only_this_projects_live_sessions() {
        use crate::testutil::TmpDir;
        use session::{Kind, Registry, Session, SessionRuntime};

        let data = TmpDir::new();
        let proj = TmpDir::new(); // real existing dirs to stand in as project roots
        let other = TmpDir::new();

        // Register THIS process (alive) with the project the launch path WOULD record — exactly
        // `project_identity(cwd).1` — so the test drives the real key on BOTH sides. A mismatch
        // between how the record is written and how the filter resolves the cwd would silently select
        // nothing (the make-or-break fact for `--all --save --local`).
        let (_, canonical) =
            sandbox::project_identity(proj.path()).expect("resolve the project root");
        let me = Session::current(canonical, Kind::Run, SessionRuntime::Project)
            .expect("read this process's session identity");
        Registry::at(data.path())
            .register(&me)
            .expect("register the session");

        // Filtering by the same cwd (resolved the same way) selects this session...
        let here = sandbox::project_identity(proj.path()).unwrap().1;
        assert!(
            session_pids_for_project(data.path(), &here).contains(&std::process::id()),
            "this project's live session must be selected"
        );
        // ...and a different project selects nothing (so a local bulk save there drains zero).
        let elsewhere = sandbox::project_identity(other.path()).unwrap().1;
        assert!(
            session_pids_for_project(data.path(), &elsewhere).is_empty(),
            "a different project must select no session"
        );
    }

    #[test]
    fn split_scope_accepts_the_short_scope_flags() {
        use config::manage::Scope;
        let osv = |parts: &[&str]| -> Vec<OsString> { parts.iter().map(OsString::from).collect() };

        // `-l`/`-g` alias `--local`/`--global`; `-a` aliases `--app`.
        let parsed = split_scope(&osv(&["network", "-g"])).unwrap();
        assert!(matches!(parsed.scope, Scope::Global));
        assert_eq!(parsed.positionals, vec!["network".to_string()]);

        let parsed = split_scope(&osv(&["-l", "network"])).unwrap();
        assert!(matches!(parsed.scope, Scope::Local));

        let parsed = split_scope(&osv(&["-a", "demo", "cmd"])).unwrap();
        assert_eq!(parsed.app.as_deref(), Some("demo"));
        assert_eq!(parsed.positionals, vec!["cmd".to_string()]);

        // `-c <file>` is unchanged and still needs its argument.
        let parsed = split_scope(&osv(&["-c", "/tmp/x.toml", "k"])).unwrap();
        assert!(matches!(parsed.scope, Scope::File(_)));
        assert!(split_scope(&osv(&["-a"])).is_err());
    }
}
