//! `sbx projects [list|show|rm]`: manage the per-project runtime trees under `<data>/projects/`.
//! The reaping primitives it drives are shared with `sbx gc` (which keeps the nix-store side);
//! this is the discoverable front-end over the project-tree lifecycle. Each subcommand parses its
//! own arguments and delegates the work to `sandbox::projects_*`.

use std::ffi::OsString;
use std::io::IsTerminal;
use std::process::ExitCode;

use crate::{diag, help, sandbox, style};

/// `sbx projects` — manage the per-project runtime trees under `<data>/projects/`: `list` (the
/// default) and `rm`. The reaping primitives it drives are shared with `sbx gc` (which keeps the
/// nix-store side); this is the discoverable front-end over the project-tree lifecycle.
pub(crate) fn projects_cmd(args: Vec<OsString>) -> ExitCode {
    if let Some(code) = help::maybe_help("projects", &args) {
        return code;
    }
    match args.first().and_then(|a| a.to_str()) {
        Some("list") | Some("ls") => projects_list_cmd(&args[1..]),
        Some("show") => projects_show_cmd(&args[1..]),
        Some("rm") | Some("remove") => projects_rm_cmd(&args[1..]),
        // Bare `sbx projects`, or only flags (e.g. `--json`) with no subcommand: print the page so
        // its subcommand list guides, like bare `sbx app`/`sbx session`.
        None => {
            eprint!("{}", help::page_usage(&["projects"]).unwrap_or_default());
            ExitCode::from(2)
        }
        Some(flag) if flag.starts_with('-') => {
            eprint!("{}", help::page_usage(&["projects"]).unwrap_or_default());
            ExitCode::from(2)
        }
        Some(other) => {
            diag::error(&format!("sbx: projects: unknown subcommand `{other}`"));
            diag::hint("       run `sbx help projects` for usage.");
            ExitCode::from(2)
        }
    }
}

fn projects_list_cmd(args: &[OsString]) -> ExitCode {
    let mut json = false;
    for a in args {
        match a.to_str() {
            Some("--json") => json = true,
            Some("--help") | Some("-h") => return help::show(&["projects"]),
            Some(other) => {
                diag::error(&format!("sbx: projects: unknown argument `{other}`"));
                diag::hint("       run `sbx help projects` for usage.");
                return ExitCode::from(2);
            }
            None => {
                diag::error("sbx: projects: argument is not valid UTF-8");
                return ExitCode::from(2);
            }
        }
    }
    let pal = style::Palette::for_stream(std::io::stdout().is_terminal());
    sandbox::projects_list(json, &pal)
}

/// `sbx projects show <id>`: the realized-on-disk detail for one runtime tree.
fn projects_show_cmd(args: &[OsString]) -> ExitCode {
    let mut id: Option<&str> = None;
    let mut json = false;
    for a in args {
        match a.to_str() {
            Some("--json") => json = true,
            Some("--help") | Some("-h") => return help::show(&["projects", "show"]),
            Some(flag) if flag.starts_with('-') => {
                diag::error(&format!("sbx: projects show: unknown flag `{flag}`"));
                diag::hint("       run `sbx help projects show` for usage.");
                return ExitCode::from(2);
            }
            Some(other) if id.is_none() => id = Some(other),
            Some(extra) => {
                diag::error(&format!(
                    "sbx: projects show: unexpected extra argument `{extra}`"
                ));
                return ExitCode::from(2);
            }
            None => {
                diag::error("sbx: projects show: argument is not valid UTF-8");
                return ExitCode::from(2);
            }
        }
    }
    let Some(id) = id else {
        diag::error(&format!(
            "sbx: projects show: name a tree id — usage: {}",
            help::synopsis_of(&["projects", "show"])
        ));
        return ExitCode::from(2);
    };
    let pal = style::Palette::for_stream(std::io::stdout().is_terminal());
    sandbox::projects_show(id, json, &pal)
}

fn projects_rm_cmd(args: &[OsString]) -> ExitCode {
    let mut ids: Vec<String> = Vec::new();
    let (mut dead, mut markerless) = (false, false);
    let (mut dry_run, mut yes) = (false, false);
    let (mut do_gc, mut force) = (false, false);
    for a in args {
        match a.to_str() {
            Some("--dead") => dead = true,
            Some("--markerless") => markerless = true,
            Some("-n") | Some("--dry-run") => dry_run = true,
            Some("-y") | Some("--yes") => yes = true,
            Some("--gc") => do_gc = true,
            Some("-f") | Some("--force") => force = true,
            Some("--help") | Some("-h") => return help::show(&["projects"]),
            Some(flag) if flag.starts_with('-') => {
                diag::error(&format!("sbx: projects rm: unknown flag `{flag}`"));
                diag::hint("       run `sbx help projects` for usage.");
                return ExitCode::from(2);
            }
            Some(id) => ids.push(id.to_string()),
            None => {
                diag::error("sbx: projects rm: argument is not valid UTF-8");
                return ExitCode::from(2);
            }
        }
    }
    if ids.is_empty() && !dead && !markerless {
        diag::error(
            "sbx: projects rm: name a project id, or use --dead / --markerless. \
             Run `sbx projects` to list them.",
        );
        return ExitCode::from(2);
    }
    let targeted = !ids.is_empty();
    let bulk = dead || markerless;
    let Some(apply) = sandbox::projects_rm_apply(targeted, bulk, dry_run, yes) else {
        diag::error("sbx: projects rm: `--dry-run` and `--yes` are contradictory — pick one.");
        return ExitCode::from(2);
    };
    let pal = style::Palette::for_stream(std::io::stdout().is_terminal());
    sandbox::projects_rm(&ids, dead, markerless, apply, do_gc, force, &pal)
}
