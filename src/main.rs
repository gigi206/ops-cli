//! sbx — sandbox launcher (bubblewrap + daemonless nix).
//!
//! The `doctor` preflight verifies the load-bearing runtime requirements before
//! anything else can run: capability-bearing unprivileged user namespaces (the
//! security boundary everything else rests on), the bubblewrap engine, and the
//! nix binary that drives the user-owned store. A missing load-bearing
//! requirement is a hard failure with remediation — never a silent fallback to
//! a weaker engine, because that would mean no security boundary at all.

// Declared before every other module, and only for that reason: `macro_rules!` are textually
// scoped, so `#[macro_use]` lifts the skip macros into scope for the modules that follow. A module
// declared above this one would not see them.
#[cfg(test)]
#[macro_use]
mod testskip;

mod allowlist;
#[cfg(test)]
mod cage_coverage;
mod cli;
mod config;
mod diag;
#[cfg(test)]
mod docs_coverage;
mod help;
mod notify;
mod observe;
mod open_policy;
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
mod version;

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
        // The spellings other tools answer to, resolved to the verb that carries the page rather
        // than handled here: `version` then reaches the help interception below and the dispatch
        // like any other command, so `sbx --version --help` renders a page and `sbx -V foo`
        // refuses its extra argument by the one rule every verb refuses one by.
        Some("--version" | "-V") => "version",
        Some(name) => name,
    };

    // A known command carrying a help flag shows the page for the deepest command path it
    // names (so `sbx plugins store add --help` lands on that page). `run` (which forwards
    // `--help` after a `--`) and `mise` (a passthrough) handle a leading help flag
    // themselves; an *unknown* command is left to the dispatch below, which names it.
    if help::is_command(name)
        && !matches!(help::canonical(&[], name), "run" | "mise")
        && let Some(code) = help::maybe_help(name, &rest)
    {
        return code;
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
    // Every flag and positional is read through `to_str`, whose `None` **is** the refusal. The
    // alternative — `to_string_lossy` — replaces the offending bytes with `U+FFFD` and hands the
    // result on as though it had been typed that way, so an egress rule arrives mutated, is
    // validated as a rule the caller never wrote, and is reported back under that spelling. A path
    // is the exception and stays an `OsStr`: a filename is not required to be UTF-8 on Linux, and
    // `-c` is the one argument that names one.
    let not_utf8 = |what: &str, arg: &OsString| format!("{what} {arg:?} is not valid UTF-8");
    while let Some(arg) = it.next() {
        let Some(text) = arg.to_str() else {
            return Err(not_utf8("the argument", arg));
        };
        if only_positional {
            positionals.push(text.to_string());
            continue;
        }
        match text {
            "--" => only_positional = true,
            "--local" | "-l" => {
                scope = Scope::Local;
                scope_explicit = true;
            }
            "--global" | "-g" => {
                scope = Scope::Global;
                scope_explicit = true;
            }
            "-c" | "--config" => {
                let file = it
                    .next()
                    .ok_or_else(|| "`-c` needs a file path".to_string())?;
                scope = Scope::File(PathBuf::from(file));
                scope_explicit = true;
            }
            "--app" | "-a" => {
                let name = it
                    .next()
                    .ok_or_else(|| "`--app` needs an app name".to_string())?;
                let Some(name) = name.to_str() else {
                    return Err(not_utf8("the app name", name));
                };
                app = Some(name.to_string());
            }
            "--trust" => trust = true,
            flag if flag.starts_with('-') && flag != "-" => {
                return Err(format!("unknown flag `{flag}`"));
            }
            _ => positionals.push(text.to_string()),
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

/// `--session` (load the rule into the live overlay of the running session(s) instead of a config
/// file) and its `--all` scope widener, lifted out before [`split_scope`], which rejects any flag it
/// does not know. The config-scope flags (`--local`/`--global`/`-c`) and `-a` ride that call.
fn split_session_flags(args: &[OsString]) -> (bool, bool, Vec<OsString>) {
    let session = args.iter().any(|a| a.to_str() == Some("--session"));
    let all = args.iter().any(|a| a.to_str() == Some("--all"));
    let rest = args
        .iter()
        .filter(|a| !matches!(a.to_str(), Some("--session") | Some("--all")))
        .cloned()
        .collect();
    (session, all, rest)
}

/// The single-rule front that `sbx net allow|deny|mute` and `sbx proc allow|deny` share, on both
/// their add and their remove paths: the scope flags split off, exactly one positional, and an app
/// name that must be valid. `namespace` names the command family, for the usage line and for the
/// refusal that names it back.
///
/// The rule comes back as written: `proc` trims it and `net` does not, so that choice stays with the
/// caller rather than being imposed here.
fn split_one_rule(
    namespace: &str,
    verb: &str,
    args: &[OsString],
) -> Result<(ScopeArgs, String), ExitCode> {
    let parsed = match split_scope(args) {
        Ok(p) => p,
        Err(e) => {
            diag::error(&format!("sbx: {e}"));
            return Err(ExitCode::from(2));
        }
    };
    let rule = match parsed.positionals.as_slice() {
        [r] => r.clone(),
        [] => {
            diag::error(&format!(
                "sbx: usage: {}",
                help::synopsis_of(&[namespace, verb])
            ));
            return Err(ExitCode::from(2));
        }
        _ => {
            diag::error(&format!(
                "sbx: {namespace} {verb}: expected exactly one rule"
            ));
            return Err(ExitCode::from(2));
        }
    };
    if let Some(name) = &parsed.app
        && !config::is_valid_app_name(name)
    {
        diag::error(&format!("sbx: invalid app name '{name}'"));
        return Err(ExitCode::from(2));
    }
    Ok((parsed, rule))
}

/// The `--interval` value the watching verbs share: whole seconds, at least one. Shared for the
/// three refusals it carries rather than for its length — a message the user reads, written out
/// once per call site, is a message that drifts between them.
fn interval_seconds(value: Option<&OsString>) -> Result<u64, String> {
    let v = value.ok_or_else(|| "`--interval` needs a value in seconds".to_string())?;
    let secs: u64 = v.to_str().and_then(|s| s.parse().ok()).ok_or_else(|| {
        format!(
            "invalid interval `{}` — expected a whole number of seconds",
            v.to_string_lossy()
        )
    })?;
    if secs == 0 {
        return Err("interval must be at least 1 second".to_string());
    }
    Ok(secs)
}

/// Resolve the working directory, mapping a failure to an error exit. Shared by the verbs.
fn config_cwd() -> Result<PathBuf, ExitCode> {
    std::env::current_dir().map_err(|e| {
        diag::error(&format!("sbx: cannot read the current directory: {e}"));
        ExitCode::FAILURE
    })
}

/// The project id of the current working directory — the name the runtime tree of the project you
/// are standing in carries — so a listing can mark that tree and a removal can refuse it. The cwd is
/// hashed the way a launch hashes its own ([`sandbox::project_id`]), so the two always agree about
/// which tree is this project's. Best-effort: `None` when the cwd cannot be read or canonicalized
/// (deleted mid-run, or no cwd), in which case nothing is marked and nothing is refused.
fn current_project_id() -> Option<String> {
    let cwd = std::env::current_dir().ok()?;
    let canonical = cwd.canonicalize().ok()?;
    Some(sandbox::project_id(&canonical))
}

/// Resolve sbx's on-disk layout, mapping an unresolvable data directory to an error exit. Shared by
/// every verb that reads or writes under the data directory: one condition deserves one sentence,
/// and the remedy — the variables that decide where the directory is — has to be in it.
fn layout_or_fail() -> Result<store::Layout, ExitCode> {
    store::Layout::from_env().ok_or_else(|| {
        diag::error(
            "sbx: cannot resolve the data directory (no $SBX_DATA_DIR, $XDG_DATA_HOME or $HOME).",
        );
        ExitCode::FAILURE
    })
}

/// The live sessions the registry holds, mapping an unreadable registry to an error exit — the read
/// every session-scoped verb (`sbx logs`, `sbx proc`, `sbx session`, `sbx fs`) opens with. Takes the
/// data directory rather than a [`store::Layout`] so the callers that resolved it through
/// [`egress_data_dir`] reach the same failure text, and so the layout stays alive at the call site,
/// which needs it after the read.
fn live_sessions(data_dir: &Path) -> Result<Vec<session::Session>, ExitCode> {
    session::Registry::at(data_dir).list().map_err(|e| {
        diag::error(&format!("sbx: cannot read the session registry: {e}"));
        ExitCode::FAILURE
    })
}

/// Print `view` as a pretty JSON document on stdout, or report that it could not be serialized —
/// the tail every `--json` verb ends with. `verb` tags the refusal (`sbx: app show: cannot
/// serialize: …`), so one condition keeps one wording across the whole CLI. The success exit code
/// stays with the caller: a verb that renders a *refusal* as a document still exits non-zero on it.
fn print_json<T: serde::Serialize>(verb: &str, view: &T) -> Result<(), ExitCode> {
    match serde_json::to_string_pretty(view) {
        Ok(doc) => {
            println!("{doc}");
            Ok(())
        }
        Err(e) => {
            diag::error(&format!("sbx: {verb}: cannot serialize: {e}"));
            Err(ExitCode::FAILURE)
        }
    }
}

/// `sbx path [--json]`: show every on-disk location sbx uses, grouped by XDG base
/// (data, config, state), marking which exist and enumerating the per-project /
/// per-app / per-profile entries actually on disk. Read-only, no trust gate, no
/// network — the layout map that answers "where on disk does sbx put things?".
///
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
    // `from_env` answers `None` for several different reasons, and only one of them is the "this
    // machine has no XDG base" that the view renders as `(no base)`: the rest are refusals — a
    // relative or overlong `$SBX_DATA_DIR`, a relative `$HOME` the lookup reached, a volume that
    // could not be mounted, and a resolved data directory the socket-length check rejects. Each has already printed its own diagnostic and
    // each means sbx cannot operate, so reporting the layout as merely absent and exiting 0 tells a
    // script the opposite of what happened. Which case this is belongs to the store, which owns the
    // guards, not to the render.
    let refused = layout.is_none() && store::data_dir_refused();
    let view = paths::view(layout.as_ref());
    if json {
        if let Err(code) = print_json("path", &view) {
            return code;
        }
        if refused {
            ExitCode::FAILURE
        } else {
            ExitCode::SUCCESS
        }
    } else {
        let pal = style::Palette::for_stream(std::io::stdout().is_terminal());
        print!("{}", paths::render(&view, &pal));
        if refused {
            ExitCode::FAILURE
        } else {
            ExitCode::SUCCESS
        }
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
    //
    // The `=` is found in the bytes, not in a UTF-8 view of the whole token: a token whose *value*
    // half is not text would otherwise fail `to_str()` as a whole and fall through to the
    // next-argument path, which then consumes an unrelated argument as this flag's value. Reaching
    // the refusal below instead is what makes the message name the real mistake.
    {
        use std::os::unix::ffi::OsStrExt;
        let bytes = token.as_os_str().as_bytes();
        if let Some(eq) = bytes.iter().position(|b| *b == b'=') {
            let inline = std::ffi::OsStr::from_bytes(&bytes[eq + 1..]);
            let Some(text) = inline.to_str() else {
                diag::error(&format!(
                    "sbx: {verb}: `{flag}` value is not valid text: {inline:?} — sbx reads \
                     override values as UTF-8"
                ));
                return Err(ExitCode::from(2));
            };
            sink.push(text.to_string());
            return Ok(());
        }
    }
    // `--flag value`: the value is the next argument.
    //
    // Absent and present-but-not-text are answered apart. Folding them — which one `and_then`
    // does — tells a user who supplied a value that they supplied none, and these flags take
    // *paths*: on Linux a path is bytes, which is why the entry point reads `args_os` in the first
    // place. A `--bind` on a directory whose name is not UTF-8 is a legitimate invocation, and the
    // refusal has to name the real reason for it to be actionable.
    match head.first() {
        None => {
            diag::error(&format!("sbx: {verb}: `{flag}` needs a value"));
            Err(ExitCode::from(2))
        }
        Some(raw) => match raw.to_str() {
            Some(v) => {
                let v = v.to_string();
                head.remove(0);
                sink.push(v);
                Ok(())
            }
            None => {
                diag::error(&format!(
                    "sbx: {verb}: `{flag}` value is not valid text: {raw:?} — sbx reads override \
                     values as UTF-8"
                ));
                Err(ExitCode::from(2))
            }
        },
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
        diag::warn_config(w);
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

/// The same directory, mapped to an error exit rather than a message — the form every verb that
/// reaches for a control socket uses, so the one condition keeps the one wording.
fn egress_dir_or_fail() -> Result<PathBuf, ExitCode> {
    egress_data_dir().map_err(|e| {
        diag::error(&format!("sbx: {e}"));
        ExitCode::FAILURE
    })
}

/// The human context of the ask-mode control sockets, cross-referenced from the session registry:
/// `(pid, project root, display label)` per live session. Best-effort — a session not in the
/// registry (a race, or one that failed to register) simply lists without context, and a `--save`
/// for it falls back to the cwd. The registry is keyed by the same pid the control socket filename
/// carries, so the two line up.
fn pending_session_context(data_dir: &Path) -> Vec<(u32, PathBuf, String)> {
    session::Registry::at(data_dir)
        .live()
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
        .live()
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
        .live()
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
        .live()
        .unwrap_or_default()
        .into_iter()
        .filter(|s| s.project == project)
        .map(|s| s.pid)
        .collect()
}

/// The pids one `--session` scope filter selects, or `None` when that filter is not active — the
/// pair [`session_scope_pids`] resolves and [`in_scope`] tests a session against.
type ScopeFilter = Option<std::collections::HashSet<u32>>;

/// The two composing pid filters a `--session` rule load is scoped by: the project the command was
/// run in (unless `--all` widens the load machine-wide) and the app named by `-a`. `None` is "no
/// filter of this kind"; a session must pass every active one to receive the rule, which
/// [`in_scope`] decides.
///
/// Shared by `sbx net allow|deny|mute --session` and `sbx proc allow|deny --session` because the
/// scope is the security-relevant half of those commands: how far `--all` widens a live rule is not
/// a rule two independent copies may come to answer differently.
fn session_scope_pids(
    data_dir: &Path,
    all: bool,
    app: Option<&str>,
    cwd: &Path,
) -> Result<(ScopeFilter, ScopeFilter), ExitCode> {
    let project_pids = if all {
        None
    } else {
        let canonical = sandbox::project_identity(cwd)
            .map(|(_, canonical)| canonical)
            .map_err(|e| {
                diag::error(&format!(
                    "sbx: cannot resolve the current project directory: {e}"
                ));
                ExitCode::FAILURE
            })?;
        Some(session_pids_for_project(data_dir, &canonical))
    };
    let app_pids = app.map(|name| session_pids_for_app(data_dir, name));
    Ok((project_pids, app_pids))
}

/// Whether the live session `pid` is in scope for a `--session` rule load: it must pass every filter
/// [`session_scope_pids`] left active, an absent one selecting everything.
fn in_scope(pid: u32, project_pids: &ScopeFilter, app_pids: &ScopeFilter) -> bool {
    let passes = |filter: &ScopeFilter| filter.as_ref().is_none_or(|p| p.contains(&pid));
    passes(project_pids) && passes(app_pids)
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

/// Why a `--local` save was refused, in the words of the case that refused it.
///
/// The two cases read nothing alike and must not be given one sentence. An existing config that is
/// untrusted (or changed since it was) is a file to review and re-trust. A project with **no**
/// config and a mise file beside it is a bootstrap sbx declines to complete: writing the config
/// would bless the mise file with it, and that file is not sbx's to approve on the user's behalf
/// (see [`local_save_permitted`]). Telling that user their missing file "is not trusted" would name
/// the wrong file and offer a command they cannot run.
fn local_save_refusal(path: &Path, exists: bool) -> String {
    if !exists {
        let names = trust::mise_files_for(path)
            .iter()
            .filter_map(|p| p.file_name())
            .map(|n| n.to_string_lossy().into_owned())
            .collect::<Vec<_>>()
            .join(", ");
        return format!(
            "this project has no {config} yet, and trusting the one a `--local` save would write \
             also trusts {names} beside it — content sbx did not write and you have not \
             reviewed. Create the config (`touch {config}` is enough), review {names}, run \
             `sbx trust \
             {config}`, then retry",
            config = config::PROJECT_CONFIG,
        );
    }
    format!(
        "{} is not trusted — review it and run `sbx trust {}`, then retry",
        path.display(),
        config::PROJECT_CONFIG
    )
}

/// The write-side trust gate for a save that blesses what it writes: an existing-but-untrusted (or
/// changed) config must not be silently blessed, the user reviews and re-trusts it first. An absent
/// config (bootstrap) or an already-trusted one is fine, so sbx's edit is the sole delta from the
/// trusted bytes. Pure on its three inputs, so the refuse/allow matrix is unit-testable without a
/// filesystem.
///
/// **The invariant it states, for every verb that writes and blesses in one step: sbx blesses the
/// delta it authored, never content the user has not approved.** `sbx net allow --local` and
/// `sbx proc allow --local` re-trust unconditionally after writing, so they must be admitted here
/// first; `sbx config set|add|rm|unset --trust` blesses only when asked, so it is admitted only when
/// the flag is passed (see `cli::config::edit::admit_config_write`). The one deliberate exception is
/// `sbx config edit --trust`, where the editor showed the user the file: what you have seen may be
/// blessed.
///
/// `has_mise` is what keeps the bootstrap arm inside that invariant. A project's trust marker
/// covers the `.sbx.toml` **and every mise file beside it** ([`trust::content_hash`]), because the
/// launcher reads those too — and a mise file is inert only until a `.sbx.toml` anchors it
/// (`config::load::mise_status`). So a save into a project that has a mise file and no config yet
/// would write one line of its own and bless a second file entirely, turning content sbx did not
/// author and the user never approved into trusted, honored configuration in one command. The
/// project tree is bound read-write into the cage, which is where such a file can come from, and
/// bootstrapping stays admitted where there is nothing else to bless.
pub(crate) fn local_save_permitted(exists: bool, state: trust::TrustState, has_mise: bool) -> bool {
    match (exists, has_mise) {
        (true, _) => state == trust::TrustState::Trusted,
        (false, false) => true,
        (false, true) => false,
    }
}

/// Pre-flight the trust gate for a `--local` save at `cwd`, *before* any irreversible action (a bulk
/// drain unblocks agents and cannot be undone). Mirrors [`persist_egress_rule`]'s gate exactly — same
/// `scope_path`, same trust-store, same "existing config must be trusted" rule — so a save that would
/// later refuse refuses here instead, with nothing answered. Absent or already-trusted is fine (sbx's
/// append is then the sole delta).
fn precheck_local_save(cwd: &Path) -> Result<(), (u8, String)> {
    use config::manage::{self, Scope};
    let store = trust::default_store_dir().ok_or((
        1,
        "cannot determine the trust store (set XDG_STATE_HOME or HOME) — needed to trust the project \
         config a `--local` save writes; use --global instead"
            .to_string(),
    ))?;
    let path = manage::scope_path(&Scope::Local, cwd).map_err(|e| (1, e.to_string()))?;
    // Read once and handed to both. The gate decides on whether the file is there and the refusal
    // names why, so two reads straddling a file being created or removed would print a reason for a
    // state other than the one that was judged — "there is no config yet" against a path that now
    // has one, or the reverse.
    let exists = path.exists();
    if !local_save_permitted(
        exists,
        trust::state(&store, &path),
        !trust::mise_files_for(&path).is_empty(),
    ) {
        return Err((
            2,
            format!(
                "{} (a `--local` save will not silently bless what you have not approved)",
                local_save_refusal(&path, exists)
            ),
        ));
    }
    Ok(())
}

/// Resolve where an egress-rule write lands and how to name it, shared by the single-rule
/// [`persist_egress_rule`] and the bulk `net_pending_drain_and_save` so the two can never disagree
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

/// An admitted control-plane rule write: where it lands, how to name it, and whether it owes a
/// re-trust. Produced by [`open_rule_write`], which has already refused everything a write can be
/// refused for *before* the file is touched.
struct RuleWrite<'a> {
    /// The config file to edit.
    path: PathBuf,
    /// The in-file app key — `None` writes the top-level table, `Some(name)` an `[app.<name>]`
    /// overlay. See [`egress_write_target`].
    app_key: Option<&'a str>,
    /// How to name the destination to the user; already carries the app, if any.
    target: String,
    /// The trust store, and by its presence the gate itself: `Some` for a `--local` project write
    /// (which must be re-trusted after the edit), `None` for a global config or an app profile,
    /// both trusted by location.
    ///
    /// The re-trust stays with each caller rather than riding along here: the two add paths always
    /// owe one, the removal path owes one only when it actually changed the file (re-trusting a
    /// path that no removal created would fail and turn a no-op into an error), and all three word
    /// a failure differently.
    store: Option<PathBuf>,
}

/// Admit a rule write to the scoped config file, refusing everything that must be refused before
/// anything is written — the shared preamble behind `sbx net allow|deny|mute`, `sbx net unmute` and
/// `sbx proc allow|deny`. `command` and `verb` name the invocation in a refusal (`sbx net allow`),
/// and `no_store` is the sentence for an unresolvable trust store, which the three paths phrase
/// differently and visibly.
///
/// Four refusals, in the order a write meets them:
/// - a `Scope::File` — the vocabulary is local/global/app, and a `-c` write would be silently
///   dropped at launch (neither trusted by location nor on the gated project path), code `2`;
/// - an invalid or reserved app name — it keys a table `resolve_apps` drops at load, so the rule
///   would be silently inert, and on a `--global` app scope it also reaches the filesystem, since a
///   profile path joins the name verbatim; code `2`. The three CLI surfaces reject a bad `--app` as
///   they parse it, so this is the net under the one that does not: `sbx net pending --save`, which
///   passes its parsed app straight through;
/// - no resolvable trust store for a gated write — the rule would be written but could not be
///   trusted, so it would not take effect; operational, code `1`;
/// - an existing-but-untrusted project config — an appended rule must not silently bless it, so the
///   user reviews and trusts it first, code `2`. Absent or already-trusted is fine: sbx's edit is
///   then the sole delta from the trusted bytes.
///
/// `base` is the directory a `--local` scope resolves against: the cwd for `sbx net allow|deny`, or
/// the *answered session's* project for `sbx net pending --save`, so the rule lands in the project
/// the agent runs in rather than wherever the user happens to stand. Global ignores it.
fn open_rule_write<'a>(
    command: &str,
    verb: &str,
    no_store: &str,
    scope: &config::manage::Scope,
    app: Option<&'a str>,
    base: &Path,
) -> Result<RuleWrite<'a>, (u8, String)> {
    use config::manage::Scope;
    if matches!(scope, Scope::File(_)) {
        return Err((
            2,
            format!(
                "`sbx {command} {verb}` does not take `-c <file>` — use --local, --global, or --app"
            ),
        ));
    }
    if let Some(name) = app
        && !config::is_valid_app_name(name)
    {
        return Err((2, format!("`{name}` is not a valid app name")));
    }
    // The file, the in-file table shape, and the human target are resolved together — and shared
    // with the drain path — so the write and the message it prints can never disagree about where
    // the rule landed.
    let (path, app_key, target) = egress_write_target(scope, app, base)?;

    // A write to the project `.sbx.toml` is trust-gated; the global config and the app profiles
    // under `apps/` are trusted by location.
    let store = if matches!(scope, Scope::Local) {
        let store = trust::default_store_dir().ok_or((1, no_store.to_string()))?;
        // One read for the gate and the refusal both, for the reason `precheck_local_save` states.
        let exists = path.exists();
        if !local_save_permitted(
            exists,
            trust::state(&store, &path),
            !trust::mise_files_for(&path).is_empty(),
        ) {
            return Err((2, local_save_refusal(&path, exists)));
        }
        Some(store)
    } else {
        None
    };

    Ok(RuleWrite {
        path,
        app_key,
        target,
        store,
    })
}

/// Why `--session` refuses the config-scope flags: it loads a rule into the live overlay of a
/// running session and writes no file, so a `--local`/`--global`/`-c` the user expected to matter
/// would be silently ignored. Shared by `sbx net allow|deny|mute` and `sbx proc allow|deny`, whose
/// `--session` semantics are identical by design — as is this refusal, so it is written once.
const SESSION_IGNORES_FILE_SCOPE: &str = "sbx: --session loads a live rule and writes no file, so --local/--global/-c do not apply — \
     use -a <app> or --all to scope the session(s)";

/// Why `--all` without `--session` is refused: it widens a *live* load to every session, and a
/// config write targets exactly one file. The egress and proc add paths refuse it identically.
const ALL_NEEDS_SESSION: &str = "sbx: --all only applies with --session (it widens a live rule to every session); a config \
     write targets one file — drop --all";

/// Why a removal verb refuses `--session`/`--all`: it removes a rule from a config file, and the
/// live overlay has no retraction for those flags to aim at (a loaded rule dies with its session).
/// `family` is the command namespace — `net` or `proc` — and `verb` the removal verb as typed.
fn removal_takes_no_session_flags(family: &str, verb: &str) -> String {
    format!(
        "sbx: {family} {verb}: --session/--all do not apply — this removes a rule from a config \
         file"
    )
}

/// Report a rule write's outcome: the success line on stdout through the prose renderer (so its
/// spans land only on a terminal), or the refusal on stderr with the exit code the writer chose.
/// Every `sbx net`/`sbx proc` add and remove path ends here, which is what keeps one persist result
/// from reaching the process differently than another.
fn report_rule_write(result: Result<String, (u8, String)>) -> ExitCode {
    match result {
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

/// What an unresolvable trust store means on an *add* path, where the rule would be written but
/// could not be trusted, so it would not take effect. The removal path states the fact alone; the
/// difference is user-visible and deliberate.
const NO_TRUST_STORE_ON_ADD: &str = "cannot determine the trust store (set XDG_STATE_HOME or HOME); the rule would be written but \
     could not be trusted, so it would not take effect — use --global, or set the trust store";

/// What the layer a rule is about to be written into inherits from below.
///
/// Only an app can inherit one: its profile (or the baseline under it) may declare a filtering
/// posture that the file being written says nothing about. Answering `Nothing` where a posture is
/// in fact inherited is the defect this exists to close — the writer then invents a `mode`, the
/// overlay stops amending and starts replacing, and the rules the user meant to add to are gone.
///
/// Resolving the config costs a load per rule write. That is the price of the writer knowing what
/// the launch will know; the alternative is guessing from one file, which is what it did before.
fn inherited_posture(app: Option<&str>, base: &Path) -> config::manage::Inherited {
    use config::manage::Inherited;
    let Some(name) = app else {
        return Inherited::Nothing;
    };
    let resolved = config::load(base);
    let Some(entry) = resolved.apps.get(name) else {
        return Inherited::Nothing;
    };
    // The app's own posture when a layer set one, else the baseline it runs under. A filtering
    // posture is the one that reads rules at all: `none`/`shared` carry none.
    let effective = entry.network.as_ref().unwrap_or(&resolved.network);
    match effective {
        config::NetworkPolicy::Allowlist(_) => Inherited::FilteringPosture,
        _ => Inherited::Nothing,
    }
}

/// Persist an egress `rule` to the scoped config file, trust-gating a project write and re-trusting
/// it after — the shared writer behind `sbx net allow|deny <rule>` and the `--save` of
/// `sbx net pending allow|deny`. Returns the success line to print, or `(exit-code, message)`: a
/// refusal (a `-c` file scope, an untrusted project config, a posture conflict) is code `2`; an
/// operational failure (no trust store, an unwritable path, a re-trust failure) is code `1`. The
/// admission itself — and every refusal before the write — is [`open_rule_write`]'s.
fn persist_egress_rule(
    list: config::manage::EgressList,
    rule: &str,
    scope: &config::manage::Scope,
    app: Option<&str>,
    base: &Path,
) -> Result<String, (u8, String)> {
    use config::manage::{self, AddOutcome};
    let verb = match list {
        manage::EgressList::Allow => "allow",
        manage::EgressList::Deny => "deny",
        manage::EgressList::Mute => "mute",
    };
    let RuleWrite {
        path,
        app_key,
        target,
        store,
    } = open_rule_write("net", verb, NO_TRUST_STORE_ON_ADD, scope, app, base)?;
    let gated = store.is_some();

    let written = manage::add_egress_rule(&path, app_key, list, rule, inherited_posture(app, base))
        .map_err(|e| (2, e.to_string()))?;

    // Re-trust the project config after the write, attesting to the bytes just written rather than
    // to whatever is on disk now. Ordering is fail-safe against a crash — one between the write and
    // the trust leaves a correct-but-untrusted file, which the next launch drops, so the rule does
    // not take effect — and `trust_written` makes it fail-safe against a concurrent writer too.
    //
    // That second half is not hypothetical: the project tree is bound read-write into the cage, so
    // an in-cage payload racing this command could otherwise have had its own `.sbx.toml` read back
    // and blessed here, and its security fields would apply from the next launch. Hashing what sbx
    // composed means a file changed underneath simply no longer matches its marker — the same
    // fail-safe outcome as the crash, and the one `local_save_permitted`'s gate reads as if it got.
    if let Some(store) = &store {
        trust::trust_written(store, &path, written.text.as_bytes()).map_err(|e| {
            (
                1,
                format!(
                    "wrote the rule but could not re-trust {e} — run `sbx trust {}` so it \
                     takes effect",
                    config::PROJECT_CONFIG
                ),
            )
        })?;
    }

    Ok(match written.outcome {
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
/// unwritable path, a re-trust failure) is code `1`. The admission is shared with the egress path
/// ([`open_rule_write`]); only the list it appends to and the mode it may set differ.
fn persist_proc_rule(
    list: config::manage::ProcList,
    rule: &str,
    scope: &config::manage::Scope,
    app: Option<&str>,
    base: &Path,
) -> Result<String, (u8, String)> {
    use config::manage::{self, AddOutcome, ProcList};
    let verb = match list {
        ProcList::Allow => "allow",
        ProcList::Deny => "deny",
    };
    let RuleWrite {
        path,
        app_key,
        target,
        store,
    } = open_rule_write("proc", verb, NO_TRUST_STORE_ON_ADD, scope, app, base)?;
    let gated = store.is_some();

    let written =
        manage::add_proc_rule(&path, app_key, list, rule).map_err(|e| (2, e.to_string()))?;

    // Re-trust after the write; the ordering is fail-safe (a crash between leaves a correct-but-
    // untrusted file the next launch drops — the rule does not take effect, never a security hole).
    if let Some(store) = &store {
        trust::trust_written(store, &path, written.text.as_bytes()).map_err(|e| {
            (
                1,
                format!(
                    "wrote the rule but could not re-trust {e} — run `sbx trust {}` so it \
                     takes effect",
                    config::PROJECT_CONFIG
                ),
            )
        })?;
    }

    Ok(match written.outcome {
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

/// Remove a rule from the scoped config file, trust-gating a project write and re-trusting it after
/// — the shared writer behind `sbx net unallow|undeny|unmute` and `sbx proc unallow|undeny`. A rule
/// that is not present is a reported no-op: no write, no re-trust. `family` names the command
/// namespace for the admission, `words` is the removal verb and the rule noun exactly as each
/// family's `removal_words` yields them, and `remove` performs the edit — the one step the two
/// families do differently.
///
/// Same scope vocabulary, trust gate and exit codes as the add path ([`persist_egress_rule`]): a
/// `-c <file>` scope or an untrusted project config is code `2`; a trust-store, write or re-trust
/// failure is code `1`. The missing-store sentence is deliberately shorter than the add path's and
/// stays so: it is user-visible, and a removal has no "written but untrusted, so it takes no effect"
/// consequence to explain — a rule that is removed is gone from the file either way.
///
/// The re-trust hashes the text [`config::manage::RemoveOutcome::Removed`] hands back rather than
/// reading the file again, so the verdict is keyed to the bytes sbx wrote. The no-op arm carries no
/// text and takes no re-trust, which is one statement made once: nothing was written.
fn persist_removal<E: std::fmt::Display>(
    family: &str,
    words: (&str, &str),
    rule: &str,
    scope: &config::manage::Scope,
    app: Option<&str>,
    base: &Path,
    remove: impl FnOnce(&Path, Option<&str>) -> Result<config::manage::RemoveOutcome, E>,
) -> Result<String, (u8, String)> {
    use config::manage::RemoveOutcome;
    let (verb, noun) = words;
    let RuleWrite {
        path,
        app_key,
        target,
        store,
    } = open_rule_write(
        family,
        verb,
        "cannot determine the trust store (set XDG_STATE_HOME or HOME)",
        scope,
        app,
        base,
    )?;
    let gated = store.is_some();

    let outcome = remove(&path, app_key).map_err(|e| (2, e.to_string()))?;

    match outcome {
        RemoveOutcome::NotPresent => Ok(format!("{noun} {rule} was not in {target} — no change")),
        RemoveOutcome::Removed { text } => {
            // Re-trust only after an actual change (the file bytes changed). Fail-safe ordering: a
            // crash between the write and the trust leaves a correct-but-untrusted file the next
            // launch drops — never a security hole.
            //
            // Attested from the text `remove` composed, never from a second read of the path — the
            // add path states the reasoning in full at its own `trust_written` call.
            if let Some(store) = &store {
                trust::trust_written(store, &path, text.as_bytes()).map_err(|e| {
                    (
                        1,
                        format!(
                            "removed the rule but could not re-trust {e} — run `sbx trust {}`",
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

/// A short revision for display — the first seven hex characters, like git.
fn short_rev(rev: &str) -> &str {
    // Cut at a character boundary rather than at byte seven. A revision is hex today, so the two
    // are the same cut; the function takes any `&str`, and a byte slice landing inside a multi-byte
    // character is a panic where this is only ever asked for a shorter string.
    match rev.char_indices().nth(7) {
        Some((at, _)) => &rev[..at],
        None => rev,
    }
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

    /// A verb that writes a project config and then re-trusts it must attest to the text it
    /// composed, never to a second read of the path. The project tree is bind-mounted read-write
    /// into the cage, so a payload writing between sbx's write and that read would have its own
    /// config attested and applied at the next launch — the write succeeds either way, which is
    /// what makes the defect invisible at the call site.
    ///
    /// All three writing paths here now hold their own text (the two `Written` add paths and
    /// `RemoveOutcome::Removed`), so this file has no remaining reason to name the re-reading form.
    /// Pinned as a count rather than an absence alone: a fourth verb added later either carries its
    /// text or fails here.
    ///
    /// `sbx trust` and `sbx config edit` legitimately hash the path and live in `cli/`, not here —
    /// there the bytes on disk are exactly what the user is approving.
    #[test]
    fn every_re_trust_in_this_file_attests_to_the_text_it_wrote() {
        // The production half only, cut at the LAST `#[cfg(test)]` rather than the first: the four
        // test-module declarations sit at the top of this file, so splitting on the first would
        // leave twelve lines to search and the assertions below would pass having read nothing.
        let (source, _) = include_str!("main.rs")
            .rsplit_once("#[cfg(test)]")
            .expect("the file has a test module");
        assert_eq!(
            source.matches("trust::trust(").count(),
            0,
            "a re-trust after sbx's own write must hash the composed text, not read the file back"
        );
        assert_eq!(
            source.matches("trust::trust_written(").count(),
            3,
            "the two add paths and the removal path each attest to what they wrote"
        );
    }

    #[test]
    fn read_sysctl_trims_value_and_handles_absence() {
        let dir = TmpDir::new();
        let f = dir.join("val");
        std::fs::write(&f, b"1\n").unwrap();
        assert_eq!(read_sysctl(f.to_str().unwrap()).as_deref(), Some("1"));
        assert_eq!(read_sysctl(dir.join("nope").to_str().unwrap()), None);
    }

    /// A path on Linux is bytes, which is why the entry point reads `args_os`. So a `--bind` on a
    /// directory whose name is not UTF-8 is a legitimate invocation, and both spellings of it have
    /// to be refused by their real reason.
    ///
    /// The inline arm is the one this pins: `--bind=<bytes>` used to fail `to_str()` as a whole
    /// token and fall through to the next-argument path, consuming an unrelated argument as the
    /// value — an observable wrong outcome, and what the middle block asserts. The
    /// separate-argument arm refused before and refuses now; what changed there is only the
    /// message, which goes to stderr and is not reachable from here. It is kept because the two
    /// spellings must not drift apart again.
    #[test]
    fn a_flag_value_that_is_not_text_is_refused_as_such_in_both_spellings() {
        use std::os::unix::ffi::OsStringExt;
        let bad = OsString::from_vec(vec![b'/', 0x80, b'x']);

        // `--bind <value>`: the value is present, so it must not be reported as absent.
        let mut head = vec![OsString::from("--bind"), bad.clone()];
        let mut sink = Vec::new();
        assert!(take_flag_value(&mut head, &mut sink, "run", "--bind").is_err());
        assert!(sink.is_empty(), "nothing is accepted from a refused value");
        assert_eq!(head.len(), 1, "the refused value is left for the report");

        // `--bind=<value>`: the whole token is not text, so the inline branch must still claim it
        // rather than let the next argument stand in for the value.
        let mut inline = OsString::from("--bind=");
        inline.push(&bad);
        let mut head = vec![inline, OsString::from("--unrelated")];
        let mut sink = Vec::new();
        assert!(take_flag_value(&mut head, &mut sink, "run", "--bind").is_err());
        assert!(sink.is_empty());
        assert_eq!(
            head,
            vec![OsString::from("--unrelated")],
            "the following argument must not be consumed as the value"
        );

        // The ordinary text value still goes through, so the guard is not refusing everything.
        let mut head = vec![OsString::from("--bind"), OsString::from("/tmp/x")];
        let mut sink = Vec::new();
        assert!(take_flag_value(&mut head, &mut sink, "run", "--bind").is_ok());
        assert_eq!(sink, vec!["/tmp/x".to_string()]);
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
        // absent config, nothing else beside it → allowed (a `--local` save bootstraps it, then
        // trusts it: sbx's own line is the whole file).
        assert!(local_save_permitted(false, Untrusted, false));
        // already-trusted config → allowed (sbx's append is the sole delta). The mise file beside
        // it is already covered by the marker the user approved, so it changes nothing here.
        assert!(local_save_permitted(true, Trusted, false));
        assert!(local_save_permitted(true, Trusted, true));
        // existing untrusted/changed config → refused (never silently bless it)
        assert!(!local_save_permitted(true, Untrusted, false));
        assert!(!local_save_permitted(true, Changed, false));
        assert!(!local_save_permitted(true, Untrusted, true));
    }

    /// The bootstrap arm is the one that blesses a file sbx did not write: a project's marker covers
    /// every mise file beside the config, and a mise file is inert only until a `.sbx.toml` anchors
    /// it. So creating the config and trusting it in one step would turn an unreviewed
    /// `mise.toml` — which the cage can write, the project tree being bound read-write — into
    /// trusted, honored configuration. Refused, and named as the file it is about.
    #[test]
    fn bootstrapping_a_config_does_not_bless_a_mise_file_beside_it() {
        use trust::TrustState::Untrusted;
        assert!(
            !local_save_permitted(false, Untrusted, true),
            "a save that would bless a mise file the user never approved must be refused"
        );
        // The refusal names the bootstrap, not a trust state of a file that is not there.
        let dir = crate::testutil::TmpDir::new();
        let config = dir.join(config::PROJECT_CONFIG);
        std::fs::write(dir.join("mise.toml"), b"[tools]\n").unwrap();
        let said = local_save_refusal(&config, false);
        assert!(
            said.contains("mise.toml") && said.contains("have not reviewed"),
            "the refusal must name the file it is really about: {said}"
        );
        assert!(
            !said.contains("is not trusted"),
            "a config that does not exist has no trust state to report: {said}"
        );
        // The existing-file arm is unchanged.
        std::fs::write(&config, b"").unwrap();
        assert!(local_save_refusal(&config, true).contains("is not trusted"));
    }

    #[test]
    fn short_rev_takes_the_first_seven_hex() {
        assert_eq!(
            short_rev("9ae611a455b90cf061d8f332b977e387bda8e1ca"),
            "9ae611a"
        );
        assert_eq!(short_rev("abc"), "abc"); // shorter than seven is returned whole
        // Not a revision, but the signature admits it: cutting by byte would panic here rather
        // than answer, and this is the shape that would reach it (a branch or tag name).
        assert_eq!(short_rev("naïve-branché-x"), "naïve-b");
        assert_eq!(short_rev("héllo"), "héllo");
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

    /// An argument that is not UTF-8 is refused, never repaired into one that is.
    ///
    /// `to_string_lossy` would replace the offending bytes with `U+FFFD` and hand the result on as
    /// though it had been typed that way: an egress rule arrives mutated, is validated as a rule
    /// nobody wrote, and is reported back under that spelling — so the caller reads a refusal for a
    /// rule they cannot find in what they typed. A path is the exception and stays an `OsStr`,
    /// because a filename on Linux is not required to be UTF-8 and `-c` is the argument that names
    /// one.
    #[test]
    fn split_scope_refuses_an_argument_that_is_not_utf8() {
        use config::manage::Scope;
        use std::os::unix::ffi::OsStringExt;

        // A lone continuation byte: valid as a path, never valid as text.
        let raw = || OsString::from_vec(vec![b'r', b'u', b'l', b'e', 0x80]);

        // `ScopeArgs` carries no `Debug`, so the refusal is taken by hand rather than through
        // `expect_err`, which would need one.
        let refusal = |args: Vec<OsString>, must: &str| -> String {
            match split_scope(&args) {
                Err(e) => e,
                Ok(_) => panic!("{must}"),
            }
        };

        let err = refusal(vec![raw()], "a positional must be refused, not repaired");
        assert!(err.contains("not valid UTF-8"), "{err}");

        // Past `--`, where the parser stops reading flags, the same rule holds.
        let err = refusal(
            vec![OsString::from("--"), raw()],
            "a trailing positional must be refused too",
        );
        assert!(err.contains("not valid UTF-8"), "{err}");

        let err = refusal(
            vec![OsString::from("-a"), raw()],
            "an app name must be refused, not repaired",
        );
        assert!(
            err.contains("not valid UTF-8") && err.contains("app name"),
            "the refusal must name which argument it is about: {err}"
        );

        // The one argument that may legitimately hold non-UTF-8 bytes still does.
        let parsed = split_scope(&[OsString::from("-c"), raw()])
            .expect("a file path is not required to be UTF-8");
        let Scope::File(p) = parsed.scope else {
            panic!("`-c` must still select a file scope");
        };
        assert_eq!(p.into_os_string(), raw());
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
