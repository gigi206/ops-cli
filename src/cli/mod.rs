//! The command-line surface: argument parsing, dispatch, and per-command handlers, one module
//! per command family. `main` parses argv and routes here; each family owns its argument
//! parsing, orchestration, and output rendering.

pub(crate) mod app;
pub(crate) mod config;
pub(crate) mod confirm;
pub(crate) mod doctor;
pub(crate) mod fs;
pub(crate) mod gc;
pub(crate) mod net;
pub(crate) mod plugins;
pub(crate) mod proc;
pub(crate) mod projects;
pub(crate) mod search;
pub(crate) mod session;
pub(crate) mod storage;
pub(crate) mod store;
pub(crate) mod test;
pub(crate) mod trust;
pub(crate) mod upgrade;

use crate::diag;
use std::ffi::OsString;
use std::process::ExitCode;

/// Route a resolved command name to its handler. `main` has already peeled off the help paths
/// (`sbx --help`, `sbx <cmd> --help`) and the no-command usage error, so every name that reaches
/// here is a concrete command plus its remaining arguments; each family owns its parsing from this
/// point. The shared leading-flag helpers (`flag_name`/`take_override_flag`/`build_override`) and
/// the standalone `path` verb live at the crate root, reached via `crate::`.
pub(crate) fn dispatch(name: &str, rest: Vec<OsString>) -> ExitCode {
    // A one-time, terminal-only suggestion to adopt a storage volume, on the first interactive
    // launch of an eligible host. Silent and immediate in every other case — a non-launch verb, a
    // non-terminal (so an agent, a pipe or CI never meets it), an override already set, a host
    // already using a volume, one already offered, or an ineligible host.
    storage::maybe_propose_on_launch(name, &rest);
    match name {
        // Internal: the in-cage exec-enforcement shim. Runs inside the cage (sbx is bound read-only
        // there), installs the seccomp user-notification filter, hands the listener fd to the host
        // supervisor, and execs the real command. Never invoked by a user directly.
        "__proc-shim" => crate::sandbox::proc_enforce::run_shim(&rest),
        // Internal: the network-namespace holder. Runs host-side (never in the cage), pre-creates
        // the cage's network namespace with a black-hole `dummy0` interface so an in-cage browser
        // reports itself online, then execs the real `bwrap …` command. Never invoked by a user
        // directly. `rest` is `[bwrap, bwrap-args…]`; it never returns.
        "__netns-holder" => crate::sandbox::run_holder(&rest),
        "doctor" => doctor::doctor(),
        "session" | "sessions" => session::session_cmd(rest),
        "trust" => trust::trust_cmd(rest),
        "untrust" => trust::untrust_cmd(rest.into_iter().next()),
        "config" => config::config_cmd(rest),
        "upgrade" => upgrade::upgrade_cmd(rest),
        "gc" => gc::run(rest),
        "projects" | "project" => projects::projects_cmd(rest),
        "storage" => storage::storage_cmd(rest),
        "store" => store::store_cmd(rest),
        "path" => crate::path_cmd(&rest),
        "run" => {
            let mut cmd: Vec<OsString> = rest;
            // Leading sbx flags before the command: `--detach` to run in the background, a one-shot
            // override (the whole-schema `--config <toml|@file>` and the typed `--env`/`--net`/
            // `--gui`/`--nixpkgs`/`--bind`/`--limit`/`--package`, each repeatable), `--help`/`-h` for
            // this command's page, and an optional `--` separating sbx's arguments from the
            // command's. The `--` is consumed before scanning the command, so `sbx run -- --detach`
            // (or `-- --help`) runs the literal argument.
            let mut detach = false;
            let mut observe = false;
            let mut cli = crate::config::CliOverrides::default();
            while let Some(raw) = cmd.first().and_then(|a| a.to_str()) {
                match crate::flag_name(raw) {
                    "--detach" => {
                        detach = true;
                        cmd.remove(0);
                    }
                    "--observe" => {
                        observe = true;
                        cmd.remove(0);
                    }
                    "--help" | "-h" => return crate::help::show(&["run"]),
                    "--" => {
                        cmd.remove(0);
                        break;
                    }
                    // A one-shot override flag, or the start of the command.
                    _ => match crate::take_override_flag(&mut cmd, &mut cli, "run") {
                        Some(Ok(())) => {}
                        Some(Err(c)) => return c,
                        None => break,
                    },
                }
            }
            let ov = match crate::build_override(cli) {
                Ok(ov) => ov,
                Err(c) => return c,
            };
            crate::sandbox::run(cmd, detach, observe, ov)
        }
        "mise" => {
            // A passthrough, so a help flag is only sbx's when it leads: `sbx mise --help`
            // shows sbx's page, while `sbx mise help` (and any later `--help`) reaches the
            // in-cage mise's own help.
            if matches!(rest.first().and_then(|a| a.to_str()), Some("--help" | "-h")) {
                return crate::help::show(&["mise"]);
            }
            crate::sandbox::run_mise(rest)
        }
        "app" => app::app_cmd(rest),
        "search" => search::run(rest),
        "test" => test::test_cmd(rest),
        "net" => net::net_cmd(rest),
        "proc" => proc::proc_cmd(rest),
        "fs" => fs::fs_cmd(rest),
        "plugins" => plugins::plugins_cmd(rest),
        other => {
            diag::error(&format!("sbx: unknown command '{other}'"));
            diag::hint("Run `sbx --help` for the list of commands.");
            ExitCode::from(2)
        }
    }
}
