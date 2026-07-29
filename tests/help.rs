//! Integration tests for `sbx --help` / `sbx help <command> [subcommand...]` /
//! `sbx <command> [subcommand] --help`.
//!
//! These exercise the usage surface only — no sandbox, no nix, no network — so they run
//! everywhere and fast. The load-bearing one is `every_command_and_verb_has_a_page`: it
//! enumerates every command and subcommand the dispatchers accept and asserts each resolves
//! to a help page, defending the single table against a verb added to the dispatch but
//! forgotten in the help (the failure mode the architecture is exposed to).

use std::process::{Command, Output};

fn sbx(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_sbx"))
        .args(args)
        .output()
        .expect("spawn sbx")
}

/// Every top-level command `main` dispatches.
const TOP_LEVEL: &[&str] = &[
    "doctor", "run", "mise", "app", "search", "test", "net", "proc", "fs", "plugins", "session",
    "trust", "untrust", "config", "upgrade", "gc", "projects", "storage", "store", "bundle",
];

/// Every command path the dispatchers accept (top-level commands and their subcommands). Keep
/// in lockstep with the dispatch in `main.rs` — that lockstep is the point of the guard test.
const PATHS: &[&[&str]] = &[
    &["doctor"],
    &["run"],
    &["mise"],
    &["app"],
    &["search"],
    &["test"],
    &["net"],
    &["bundle"],
    &["bundle", "export"],
    &["bundle", "import"],
    &["plugins"],
    &["session"],
    &["session", "ls"],
    &["session", "logs"],
    &["session", "attach"],
    &["session", "stop"],
    &["trust"],
    &["untrust"],
    &["config"],
    &["config", "show"],
    &["config", "get"],
    &["config", "set"],
    &["config", "unset"],
    &["config", "path"],
    &["config", "edit"],
    &["upgrade"],
    &["gc"],
    &["projects"],
    &["projects", "show"],
    &["storage"],
    &["store"],
    &["app", "run"],
    &["app", "import"],
    &["app", "export"],
    &["app", "rm"],
    &["app", "list"],
    &["app", "show"],
    &["app", "prune"],
    &["test", "net"],
    &["net", "rules"],
    &["net", "allow"],
    &["net", "deny"],
    &["net", "pending"],
    &["net", "pending", "allow"],
    &["net", "pending", "deny"],
    &["proc"],
    &["proc", "ls"],
    &["proc", "live"],
    &["proc", "logs"],
    &["proc", "pending"],
    &["proc", "allow"],
    &["proc", "deny"],
    &["proc", "rules"],
    &["fs"],
    &["fs", "logs"],
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
        let out = sbx(invocation);
        assert!(out.status.success(), "`sbx {invocation:?}` should exit 0");
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert!(
            stdout.contains("Commands:"),
            "missing the command list for {invocation:?}"
        );
        for cmd in TOP_LEVEL {
            assert!(
                stdout.contains(cmd),
                "`sbx {invocation:?}` did not list '{cmd}'"
            );
        }
    }
}

#[test]
fn every_command_and_verb_has_a_page() {
    // The guard: a path in the dispatch but missing from the help table fails both `sbx help
    // <path>` (no page) and `sbx <path> --help` (falls through to "unknown" / runs the command).
    for path in PATHS {
        let header = format!("sbx {} —", path.join(" "));

        let mut via_help = vec!["help"];
        via_help.extend_from_slice(path);
        let out = sbx(&via_help);
        assert!(
            out.status.success(),
            "`sbx help {path:?}` should exit 0 (is it in the table?)"
        );
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert!(
            stdout.contains(&header),
            "`sbx help {path:?}` did not render the page"
        );
        assert!(
            stdout.contains("Usage:"),
            "`sbx help {path:?}` had no Usage line"
        );

        let mut via_flag = path.to_vec();
        via_flag.push("--help");
        let out = sbx(&via_flag);
        assert!(out.status.success(), "`sbx {path:?} --help` should exit 0");
        assert!(
            String::from_utf8_lossy(&out.stdout).contains(&header),
            "`sbx {path:?} --help` did not render the page"
        );
    }
}

#[test]
fn a_subcommand_help_details_its_options() {
    // `sbx app import --help` must reach the import page (not the parent app page) and list its
    // options — the explicit ask ("détaille correctement les options").
    let out = sbx(&["app", "import", "--help"]);
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("sbx app import —"),
        "should be the import page"
    );
    assert!(stdout.contains("Options:"));
    assert!(stdout.contains("--as"), "should document --as");
    assert!(stdout.contains("--force"), "should document --force");
}

#[test]
fn a_deep_subcommand_path_resolves() {
    // Three levels: both `sbx plugins store add --help` and `sbx help plugins store add`.
    for out in [
        sbx(&["plugins", "store", "add", "--help"]),
        sbx(&["help", "plugins", "store", "add"]),
    ] {
        assert!(out.status.success());
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert!(
            stdout.contains("sbx plugins store add —"),
            "wrong page: {stdout}"
        );
        assert!(stdout.contains("--key"), "should document --key");
        assert!(stdout.contains("--trust"), "should document --trust");
    }
}

#[test]
fn subcommands_are_listed_alphabetically() {
    let out = sbx(&["app", "--help"]);
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    // Within the Subcommands section, the verbs are sorted: export, import, list, rm.
    let section = stdout
        .split("Subcommands:")
        .nth(1)
        .and_then(|s| s.split("Run `sbx help").next())
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
    // `sbx session stop --all --help` is help for stop, not an attempt to stop a session
    // called --help.
    let out = sbx(&["session", "stop", "--all", "--help"]);
    assert!(out.status.success(), "should be the stop page, exit 0");
    assert!(String::from_utf8_lossy(&out.stdout).contains("sbx session stop —"));
}

#[test]
fn a_double_dash_passes_help_flags_through_to_the_app_command() {
    // The converse of the test above: `sbx app run <name> -- --help` must NOT show sbx's app-run
    // page — the `--help` after `--` belongs to the launched command (a program's own `--help`, or a
    // resume flag like `-- -c`), not to sbx. The launch path is short-circuited without a sandbox
    // by removing the data-dir env, so it fails fast *after* routing; the point is only that sbx
    // did not intercept the help flag. (The routing itself is unit-tested in help.rs by
    // `maybe_help_stops_at_a_double_dash`.)
    let out = Command::new(env!("CARGO_BIN_EXE_sbx"))
        .args(["app", "run", "demo", "--", "--help"])
        .env_remove("HOME")
        .env_remove("XDG_DATA_HOME")
        .output()
        .expect("spawn sbx");
    let text =
        String::from_utf8_lossy(&out.stdout).into_owned() + &String::from_utf8_lossy(&out.stderr);
    assert!(
        !text.contains("sbx app run —"),
        "`sbx app run <name> -- --help` was intercepted as sbx's help page instead of passing \
         `--help` through to the command: {text}"
    );
}

#[test]
fn piped_help_has_no_ansi_escapes() {
    // Color is auto-gated: a captured (non-terminal) stream is plain text — which is also why the
    // substring assertions above hold.
    for args in [&["--help"][..], &["app", "import", "--help"][..]] {
        let out = sbx(args);
        assert!(
            !out.stdout.contains(&0x1b),
            "piped `sbx {args:?}` must not emit ANSI escapes"
        );
    }
}

#[test]
fn no_command_is_a_usage_error_that_lists_commands() {
    let out = sbx(&[]);
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
fn an_unknown_command_gets_only_the_generic_pointer_no_hint() {
    // An unknown command — including a bare subcommand verb like `import` (which lives under
    // `sbx app`) — names itself and points at `sbx --help`, with no "did you mean" suggestion.
    let out = sbx(&["import", "--help"]);
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
        !stderr.contains("did you mean"),
        "no migration hint: an unknown command gets no single-parent suggestion"
    );
    assert!(
        stderr.contains("sbx --help"),
        "the generic pointer should remain"
    );
}

#[test]
fn help_for_an_unknown_name_is_a_usage_error() {
    let out = sbx(&["help", "bogus"]);
    assert_eq!(
        out.status.code(),
        Some(2),
        "help for an unknown name is a usage error"
    );
    assert!(String::from_utf8_lossy(&out.stderr).contains("no help for"));
}

#[test]
fn run_help_is_the_run_page_and_does_not_launch() {
    // `sbx run --help` returns the page before any sandbox work (so this is fast and host-agnostic).
    let out = sbx(&["run", "--help"]);
    assert!(out.status.success(), "`sbx run --help` should exit 0");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("sbx run —"));
    assert!(
        stdout.contains("--detach"),
        "the run page should document --detach"
    );
}

#[test]
fn mise_help_is_sbx_page_and_points_at_mises_own_help() {
    // A leading help flag is sbx's; the page tells the user how to reach the in-cage mise's help.
    let out = sbx(&["mise", "--help"]);
    assert!(out.status.success(), "`sbx mise --help` should exit 0");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("sbx mise —"));
    assert!(
        stdout.contains("sbx mise help"),
        "should point at mise's own help"
    );
}
