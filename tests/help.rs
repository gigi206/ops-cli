//! Integration tests for `ops --help` / `ops help <command> [subcommand...]` /
//! `ops <command> [subcommand] --help`.
//!
//! These exercise the usage surface only — no sandbox, no nix, no network — so they run
//! everywhere and fast. The load-bearing one is `every_command_and_verb_has_a_page`: it
//! enumerates every command and subcommand the dispatchers accept and asserts each resolves
//! to a help page, defending the single table against a verb added to the dispatch but
//! forgotten in the help (the failure mode the architecture is exposed to).

use std::process::{Command, Output};

fn ops(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_ops"))
        .args(args)
        .output()
        .expect("spawn ops")
}

/// Every top-level command `main` dispatches.
const TOP_LEVEL: &[&str] = &[
    "doctor", "shell", "run", "mise", "app", "search", "test", "plugins", "ps", "attach", "stop",
    "trust", "untrust", "config", "upgrade", "gc",
];

/// Every command path the dispatchers accept (top-level commands and their subcommands). Keep
/// in lockstep with the dispatch in `main.rs` — that lockstep is the point of the guard test.
const PATHS: &[&[&str]] = &[
    &["doctor"],
    &["shell"],
    &["run"],
    &["mise"],
    &["app"],
    &["search"],
    &["test"],
    &["plugins"],
    &["ps"],
    &["attach"],
    &["stop"],
    &["trust"],
    &["untrust"],
    &["config"],
    &["upgrade"],
    &["gc"],
    &["app", "import"],
    &["app", "export"],
    &["app", "rm"],
    &["app", "list"],
    &["test", "net"],
    &["plugins", "list"],
    &["plugins", "info"],
    &["plugins", "install"],
    &["plugins", "rm"],
    &["plugins", "store"],
    &["plugins", "store", "list"],
    &["plugins", "store", "add"],
    &["plugins", "store", "publish"],
    &["plugins", "store", "update"],
    &["plugins", "store", "install"],
    &["plugins", "store", "info"],
    &["plugins", "store", "rm"],
];

#[test]
fn top_level_help_lists_every_command() {
    for invocation in [&["--help"][..], &["-h"][..], &["help"][..]] {
        let out = ops(invocation);
        assert!(out.status.success(), "`ops {invocation:?}` should exit 0");
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert!(
            stdout.contains("Commands:"),
            "missing the command list for {invocation:?}"
        );
        for cmd in TOP_LEVEL {
            assert!(
                stdout.contains(cmd),
                "`ops {invocation:?}` did not list '{cmd}'"
            );
        }
    }
}

#[test]
fn every_command_and_verb_has_a_page() {
    // The guard: a path in the dispatch but missing from the help table fails both `ops help
    // <path>` (no page) and `ops <path> --help` (falls through to "unknown" / runs the command).
    for path in PATHS {
        let header = format!("ops {} —", path.join(" "));

        let mut via_help = vec!["help"];
        via_help.extend_from_slice(path);
        let out = ops(&via_help);
        assert!(
            out.status.success(),
            "`ops help {path:?}` should exit 0 (is it in the table?)"
        );
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert!(
            stdout.contains(&header),
            "`ops help {path:?}` did not render the page"
        );
        assert!(
            stdout.contains("Usage:"),
            "`ops help {path:?}` had no Usage line"
        );

        let mut via_flag = path.to_vec();
        via_flag.push("--help");
        let out = ops(&via_flag);
        assert!(out.status.success(), "`ops {path:?} --help` should exit 0");
        assert!(
            String::from_utf8_lossy(&out.stdout).contains(&header),
            "`ops {path:?} --help` did not render the page"
        );
    }
}

#[test]
fn a_subcommand_help_details_its_options() {
    // `ops app import --help` must reach the import page (not the parent app page) and list its
    // options — the explicit ask ("détaille correctement les options").
    let out = ops(&["app", "import", "--help"]);
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("ops app import —"),
        "should be the import page"
    );
    assert!(stdout.contains("Options:"));
    assert!(stdout.contains("--as"), "should document --as");
    assert!(stdout.contains("--force"), "should document --force");
}

#[test]
fn a_deep_subcommand_path_resolves() {
    // Three levels: both `ops plugins store add --help` and `ops help plugins store add`.
    for out in [
        ops(&["plugins", "store", "add", "--help"]),
        ops(&["help", "plugins", "store", "add"]),
    ] {
        assert!(out.status.success());
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert!(
            stdout.contains("ops plugins store add —"),
            "wrong page: {stdout}"
        );
        assert!(stdout.contains("--key"), "should document --key");
        assert!(stdout.contains("--trust"), "should document --trust");
    }
}

#[test]
fn subcommands_are_listed_alphabetically() {
    let out = ops(&["app", "--help"]);
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    // Within the Subcommands section, the verbs are sorted: export, import, list, rm.
    let section = stdout
        .split("Subcommands:")
        .nth(1)
        .and_then(|s| s.split("Run `ops help").next())
        .expect("an app page has a Subcommands section");
    assert!(
        section.find("export") < section.find("import"),
        "export before import"
    );
    assert!(
        section.find("import") < section.find("list"),
        "import before list"
    );
    assert!(section.find("list") < section.find("rm"), "list before rm");
}

#[test]
fn a_help_flag_after_a_subcommand_path_does_not_run_the_command() {
    // `ops stop --all --help` is help for stop, not an attempt to stop a session called --help.
    let out = ops(&["stop", "--all", "--help"]);
    assert!(out.status.success(), "should be the stop page, exit 0");
    assert!(String::from_utf8_lossy(&out.stdout).contains("ops stop —"));
}

#[test]
fn piped_help_has_no_ansi_escapes() {
    // Color is auto-gated: a captured (non-terminal) stream is plain text — which is also why the
    // substring assertions above hold.
    for args in [&["--help"][..], &["app", "import", "--help"][..]] {
        let out = ops(args);
        assert!(
            !out.stdout.contains(&0x1b),
            "piped `ops {args:?}` must not emit ANSI escapes"
        );
    }
}

#[test]
fn no_command_is_a_usage_error_that_lists_commands() {
    let out = ops(&[]);
    assert_eq!(
        out.status.code(),
        Some(2),
        "no command is a usage error (exit 2)"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("Commands:"),
        "no-command usage should list the commands"
    );
    assert!(
        stderr.contains("doctor"),
        "no-command usage should name a command"
    );
}

#[test]
fn unknown_command_hints_an_unambiguous_subcommand_parent() {
    // The reported bug: `ops import --help` said only "unknown command". Now it points at the
    // real path. `import` has a single parent, so the hint is unambiguous.
    let out = ops(&["import", "--help"]);
    assert_eq!(
        out.status.code(),
        Some(2),
        "an unknown command is a usage error"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("unknown command 'import'"),
        "should name the unknown command"
    );
    assert!(
        stderr.contains("ops app import"),
        "should hint the subcommand parent"
    );
}

#[test]
fn an_ambiguous_subcommand_verb_gets_no_misleading_hint() {
    // `rm` is both `app rm` and `plugins rm` (and `list`/`info`/`install` are multi-parent too):
    // pointing at one parent would misdirect, so there is only the generic pointer.
    let out = ops(&["rm"]);
    assert_eq!(out.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("unknown command 'rm'"));
    assert!(
        !stderr.contains("did you mean"),
        "an ambiguous verb must get no single-parent hint"
    );
    assert!(
        stderr.contains("ops --help"),
        "the generic pointer should remain"
    );
}

#[test]
fn help_for_an_unknown_name_is_a_usage_error() {
    let out = ops(&["help", "bogus"]);
    assert_eq!(
        out.status.code(),
        Some(2),
        "help for an unknown name is a usage error"
    );
    assert!(String::from_utf8_lossy(&out.stderr).contains("no help for"));
}

#[test]
fn run_help_is_the_run_page_and_does_not_launch() {
    // `ops run --help` returns the page before any sandbox work (so this is fast and host-agnostic).
    let out = ops(&["run", "--help"]);
    assert!(out.status.success(), "`ops run --help` should exit 0");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("ops run —"));
    assert!(
        stdout.contains("--detach"),
        "the run page should document --detach"
    );
}

#[test]
fn mise_help_is_ops_page_and_points_at_mises_own_help() {
    // A leading help flag is ops's; the page tells the user how to reach the in-cage mise's help.
    let out = ops(&["mise", "--help"]);
    assert!(out.status.success(), "`ops mise --help` should exit 0");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("ops mise —"));
    assert!(
        stdout.contains("ops mise help"),
        "should point at mise's own help"
    );
}
