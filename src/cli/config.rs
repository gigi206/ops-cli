//! `sbx config` — inspect and edit the resolved configuration.
//!
//! This file is the verb tree itself: the dispatcher, the `config show` and `config show --app`
//! handlers (the only two consumers of the rendering modules), and the usage helper every verb in
//! the family reports a misuse through. The two programs the family holds are children, and the
//! dispatch below is the only edge between them:
//!
//! * [`mod@render`] — the baseline `sbx config show` document, section by section.
//! * [`mod@app_detail`] — the per-app effective view behind `config show --app <name>`.
//! * [`mod@format`] — the line-level formatters and the posture preamble those two share.
//! * [`mod@edit`] — the key-editing verbs and the trust admission behind them.
//!
//! Cross-cutting plumbing that other command families also use — `split_scope`/`ScopeArgs`,
//! `config_cwd`, the transactional confirmation renderers, and `short_rev` — stays at the crate
//! root and is reached from here via `crate::`.

mod app_detail;
mod edit;
mod format;
mod render;

use std::ffi::OsString;
use std::io::IsTerminal;
use std::path::Path;
use std::process::ExitCode;

use crate::{config, diag, help, style};
use crate::{config_cwd, print_json};

use app_detail::render_app_detail;
use edit::{
    ListEdit, config_edit, config_get, config_list_edit, config_path_cmd, config_set, config_unset,
};
use render::render_config;

/// `sbx config [--json]` and the management verbs `get`/`set`/`unset`/`path`. With no verb it
/// shows the resolved configuration for the current project — the layered global + project
/// environment and host binds (each read-only or read-write), after the trust gate has dropped
/// anything an untrusted project may not set. The human form renders a colored document with
/// warnings on stderr;
/// `--json` prints the same resolved model as a JSON document. The verbs read and edit a single
/// raw layer file (the project `.sbx.toml`, the global config, or an explicit path).
pub(crate) fn config_cmd(args: Vec<OsString>) -> ExitCode {
    match args.first().and_then(|a| a.to_str()) {
        Some("show") => config_show(&args[1..]),
        Some("get") => config_get(&args[1..]),
        Some("set") => config_set(&args[1..]),
        Some("add") => config_list_edit(&args[1..], ListEdit::Add),
        Some("rm") => config_list_edit(&args[1..], ListEdit::Remove),
        Some("unset") => config_unset(&args[1..]),
        Some("path") => config_path_cmd(&args[1..]),
        Some("edit") => config_edit(&args[1..]),
        // No subcommand — or an unknown one. Print the config page (which lists the subcommands)
        // to stderr and exit non-zero, so `sbx config` reveals `show`/`get`/… instead of silently
        // doing one of them. Mirrors the no-command usage of bare `sbx`.
        other => {
            match other {
                // The old `sbx config --json` muscle memory: the resolved view (and its --json) is
                // now `show`, so point straight at it. Other flags belong to a specific subcommand
                // (get/set/… take -c/--local, and the verbs that write take --trust), so name no
                // verb and let the page below guide.
                Some("--json") => {
                    diag::error("sbx: config: --json is now `sbx config show --json`")
                }
                Some(tok) if tok.starts_with('-') => diag::error(&format!(
                    "sbx: config: {tok:?} is an option of a subcommand — pick one from the list below"
                )),
                Some(tok) => diag::error(&format!("sbx: config: unknown subcommand {tok:?}")),
                None => {}
            }
            eprint!("{}", help::page_usage(&["config"]).unwrap_or_default());
            ExitCode::from(2)
        }
    }
}

/// Record a chosen single-source `config show` view flag (`--global`/`--local`/`--default`),
/// rejecting a second, conflicting one — two different sources is a user error, not last-wins. The
/// same flag repeated is harmless. On conflict, prints the usage and returns the usage exit code.
fn set_show_source(
    current: &mut Option<(&'static str, config::Source)>,
    flag: &'static str,
    source: config::Source,
) -> Result<(), ExitCode> {
    match current {
        Some((prev, _)) if *prev == flag => Ok(()),
        Some((prev, _)) => {
            diag::error(&format!(
                "sbx: config show: `{flag}` conflicts with `{prev}` (choose one source)"
            ));
            Err(config_usage("show"))
        }
        None => {
            *current = Some((flag, source));
            Ok(())
        }
    }
}

/// `sbx config show [--json]`: show the resolved configuration for the current project — the
/// layered, trust-gated view a launch would use. The human render is colored when stdout is a
/// terminal; `--json` emits the whole resolved model for tooling.
fn config_show(args: &[OsString]) -> ExitCode {
    let mut json = false;
    let mut details = false;
    let mut app: Option<String> = None;
    let mut source: Option<(&'static str, config::Source)> = None;
    let mut it = args.iter();
    while let Some(arg) = it.next() {
        match arg.to_str() {
            Some("--json") => json = true,
            Some("--details") => details = true,
            Some("--app") | Some("-a") => match it.next() {
                Some(name) => app = Some(name.to_string_lossy().into_owned()),
                None => {
                    diag::error("sbx: config show: `--app` needs an app name");
                    return config_usage("show");
                }
            },
            Some("--global") | Some("-g") => {
                if let Err(code) = set_show_source(&mut source, "--global", config::Source::Global)
                {
                    return code;
                }
            }
            Some("--local") | Some("-l") => {
                if let Err(code) = set_show_source(&mut source, "--local", config::Source::Local) {
                    return code;
                }
            }
            Some("--default") | Some("-d") => {
                if let Err(code) =
                    set_show_source(&mut source, "--default", config::Source::Default)
                {
                    return code;
                }
            }
            _ => {
                diag::error(&format!(
                    "sbx: config show: unexpected argument {:?}",
                    arg.to_string_lossy()
                ));
                return config_usage("show");
            }
        }
    }

    // A per-app view is inherently the app's effective configuration over the *full* baseline, so a
    // single-source restriction is meaningless there — reject the combination rather than silently
    // ignoring one flag.
    if app.is_some()
        && let Some((flag, _)) = source
    {
        diag::error(&format!(
            "sbx: config show: `--app` does not combine with `{flag}`"
        ));
        return config_usage("show");
    }

    let cwd = match config_cwd() {
        Ok(d) => d,
        Err(code) => return code,
    };

    // `--app <name>` focuses on one app's *effective* configuration with provenance, instead of the
    // whole resolved baseline.
    if let Some(name) = app {
        return config_show_app(&cwd, &name, json, details);
    }

    // A source flag restricts the view to that one layer (over the built-in defaults); with none,
    // the full layered configuration is shown.
    let view = match source {
        Some((_, src)) => config::view::build_scoped(&cwd, src),
        None => config::view::build(&cwd),
    };

    if json {
        // The whole resolved model, warnings and all, as one JSON document — already exhaustive
        // (every app's rules in full), so `--details` is moot here whatever order the flags came.
        // Nothing goes to stderr — stdout stays pure JSON, the contract a consuming tool relies on.
        if let Err(code) = print_json("config", &view) {
            return code;
        }
        return ExitCode::SUCCESS;
    }

    let pal = style::Palette::for_stream(std::io::stdout().is_terminal());
    print!("{}", render_config(&view, &pal, details));
    // Warnings go to stderr, out of band from the resolved view, so the body stays a clean
    // capturable document and a warning never pollutes a piped human render.
    for w in &view.warnings {
        diag::warn(w);
    }
    ExitCode::SUCCESS
}

/// Render one app's effective configuration with provenance — the `config show --app <name>` path.
/// Errors (listing the declared apps) when no such app exists.
fn config_show_app(cwd: &Path, name: &str, json: bool, details: bool) -> ExitCode {
    let Some(view) = config::view::build_app_detail(cwd, name) else {
        diag::error(&format!("sbx: config show: no app named {name:?}"));
        let declared: Vec<String> = config::view::build(cwd)
            .apps
            .into_iter()
            .map(|a| a.name)
            .collect();
        if declared.is_empty() {
            diag::error("sbx: no apps are declared for this directory");
        } else {
            diag::error(&format!("sbx: declared apps: {}", declared.join(", ")));
        }
        return ExitCode::FAILURE;
    };

    if json {
        if let Err(code) = print_json("config show --app", &view) {
            return code;
        }
        return ExitCode::SUCCESS;
    }

    let pal = style::Palette::for_stream(std::io::stdout().is_terminal());
    print!("{}", render_app_detail(&view, &pal, details));
    ExitCode::SUCCESS
}

/// Print the usage synopsis for a `config` verb and return the usage exit code.
pub(super) fn config_usage(verb: &str) -> ExitCode {
    diag::error(&format!(
        "sbx: usage: {}",
        help::synopsis_of(&["config", verb])
    ));
    ExitCode::from(2)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn set_show_source_rejects_a_conflicting_second_flag() {
        let mut src: Option<(&'static str, config::Source)> = None;
        assert!(set_show_source(&mut src, "--global", config::Source::Global).is_ok());
        // The same flag repeated is harmless (no conflict).
        assert!(set_show_source(&mut src, "--global", config::Source::Global).is_ok());
        // A different source flag is a conflict, not last-wins.
        assert!(set_show_source(&mut src, "--local", config::Source::Local).is_err());
    }
}
