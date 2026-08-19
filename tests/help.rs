//! Integration tests for `sbx --help` / `sbx help <command> [subcommand...]` /
//! `sbx <command> [subcommand] --help`.
//!
//! These exercise the usage surface only — no sandbox, no nix, no network — so they run
//! everywhere and fast. The load-bearing one is `every_command_and_verb_has_a_page`: it walks the
//! command tree the binary declares and asserts each path renders through both help routes.
//!
//! **What that does and does not defend.** The walk comes from the binary's own page table, so it
//! covers every page the moment one lands — no list here to forget. It cannot see the opposite
//! drift: a verb wired into a dispatcher that the table never heard of is absent from the walk, so
//! it is absent from this sweep too. That direction is a property of the dispatch and is answered
//! there, not by a list kept beside it. An earlier version of this file did keep such a list, and
//! it had gone stale by a third of the surface while this header claimed it enumerated all of it.

use std::process::Command;

mod common;
use common::{page_paths, sbx};

#[test]
fn top_level_help_lists_every_command() {
    let paths = page_paths();
    let top: Vec<&str> = paths
        .iter()
        .filter(|p| p.len() == 1)
        .map(|p| p[0].as_str())
        .collect();
    // The precondition, before the property: a walk that found nothing would satisfy every
    // assertion below by having nothing to check. The floor is well under the real count, so it
    // catches a broken walk without needing an edit each time a command lands.
    assert!(
        top.len() >= 20,
        "the walk found only {} top-level commands, so it is not walking",
        top.len()
    );
    for invocation in [&["--help"][..], &["-h"][..], &["help"][..]] {
        let out = sbx(invocation);
        assert!(out.status.success(), "`sbx {invocation:?}` should exit 0");
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert!(
            stdout.contains("Commands:"),
            "missing the command list for {invocation:?}"
        );
        for cmd in &top {
            assert!(
                stdout.contains(cmd),
                "`sbx {invocation:?}` did not list '{cmd}'"
            );
        }
    }
}

#[test]
fn every_command_and_verb_has_a_page() {
    // Both routes to a page, over the whole declared tree: `sbx help <path>` and `sbx <path>
    // --help`. A page reachable through one and not the other is the drift this catches — a verb
    // whose help flag is swallowed by its own argument parsing reads as a working command until
    // someone asks it for help.
    let paths = page_paths();
    assert!(
        paths.len() >= 90,
        "the walk found only {} command paths, so it is not walking",
        paths.len()
    );
    for path in &paths {
        let path: Vec<&str> = path.iter().map(String::as_str).collect();
        let path = path.as_slice();
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

/// Every alternate spelling the dispatchers accept: the words a user types, the canonical path
/// they stand for, and the page header that must come back. Written out here rather than derived
/// from the binary's own alias table, so a wrong entry there fails this test instead of agreeing
/// with it.
const ALIASES: &[(&[&str], &[&str], &str)] = &[
    (&["project"], &["projects"], "sbx projects —"),
    (&["secrets"], &["secret"], "sbx secret —"),
    (&["sessions"], &["session"], "sbx session —"),
    (&["tasks"], &["task"], "sbx task —"),
    (&["app", "ls"], &["app", "list"], "sbx app list —"),
    (&["fs", "log"], &["fs", "logs"], "sbx fs logs —"),
    (&["net", "log"], &["net", "logs"], "sbx net logs —"),
    (
        &["plugins", "ls"],
        &["plugins", "list"],
        "sbx plugins list —",
    ),
    (
        &["plugins", "store", "ls"],
        &["plugins", "store", "list"],
        "sbx plugins store list —",
    ),
    (&["proc", "list"], &["proc", "ls"], "sbx proc ls —"),
    (&["proc", "log"], &["proc", "logs"], "sbx proc logs —"),
    (&["secret", "ls"], &["secret", "list"], "sbx secret list —"),
    (&["session", "list"], &["session", "ls"], "sbx session ls —"),
    (
        &["session", "log"],
        &["session", "logs"],
        "sbx session logs —",
    ),
    (
        &["ssh-agent", "log"],
        &["ssh-agent", "logs"],
        "sbx ssh-agent logs —",
    ),
    (&["task", "ls"], &["task", "list"], "sbx task list —"),
    (&["task", "log"], &["task", "logs"], "sbx task logs —"),
    // An alias below an alias: the namespace is folded before its subcommand is read.
    (
        &["sessions", "list"],
        &["session", "ls"],
        "sbx session ls —",
    ),
    // A verb documented on its parent's page rather than one of its own: the alias must land
    // exactly where the canonical spelling lands, which is that parent page.
    (&["projects", "ls"], &["projects", "list"], "sbx projects —"),
    (
        &["projects", "remove"],
        &["projects", "rm"],
        "sbx projects —",
    ),
];

#[test]
fn an_alias_shows_the_page_of_the_verb_it_stands_for() {
    // `sbx plugins ls -h` used to print the `plugins` namespace page: the help resolver knew only
    // canonical names, so an alias stopped the descent and fell back to the parent. Every accepted
    // spelling must reach the page of the verb it runs.
    for (alias, _, header) in ALIASES {
        for flag in ["--help", "-h"] {
            let mut words = alias.to_vec();
            words.push(flag);
            let out = sbx(&words);
            assert!(out.status.success(), "`sbx {words:?}` should exit 0");
            assert!(
                String::from_utf8_lossy(&out.stdout).contains(header),
                "`sbx {words:?}` did not render `{header}`"
            );
        }
    }
}

#[test]
fn an_alias_is_indistinguishable_from_the_name_it_stands_for() {
    // The stronger property, and the one that covers `sbx help <path>` as well as the help flag:
    // typing an alias produces byte-for-byte what typing the canonical name produces — including
    // when that is a usage error (a verb with no page of its own answers the same way under both
    // spellings).
    // The two ways a page is asked for: a trailing help flag, and the `help` verb.
    fn invocation(path: &[&'static str], via_help_verb: bool) -> Vec<&'static str> {
        let mut words: Vec<&'static str> = if via_help_verb {
            vec!["help"]
        } else {
            Vec::new()
        };
        words.extend_from_slice(path);
        if !via_help_verb {
            words.push("--help");
        }
        words
    }

    for (alias, canonical, _) in ALIASES {
        for via_help_verb in [false, true] {
            let (typed, meant) = (
                invocation(alias, via_help_verb),
                invocation(canonical, via_help_verb),
            );
            let (a, b) = (sbx(&typed), sbx(&meant));
            assert_eq!(
                a.status.code(),
                b.status.code(),
                "`sbx {typed:?}` and `sbx {meant:?}` disagree on the exit code"
            );
            assert_eq!(
                String::from_utf8_lossy(&a.stdout),
                String::from_utf8_lossy(&b.stdout),
                "`sbx {typed:?}` and `sbx {meant:?}` print different pages"
            );
            assert_eq!(
                String::from_utf8_lossy(&a.stderr),
                String::from_utf8_lossy(&b.stderr),
                "`sbx {typed:?}` and `sbx {meant:?}` print different diagnostics"
            );
        }
    }
}

#[test]
fn a_subcommand_help_details_its_options() {
    // `sbx app import --help` must reach the import page (not the parent app page) and list its
    // own options, so a subcommand's flags are discoverable without reading the parent page.
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

/// The three spellings of the version print one identical line and exit 0.
///
/// The expected string is built from `CARGO_PKG_VERSION` rather than pinned, so a release bump does
/// not turn this red for the wrong reason; the shape assertion beside it is the literal that keeps
/// the check from following the code wherever it goes, since a binary printing an empty version
/// would satisfy an equality built the same way it was.
#[test]
fn every_spelling_of_version_prints_the_build_version() {
    let expected = format!("sbx {}\n", env!("CARGO_PKG_VERSION"));
    for spelling in [&["version"][..], &["--version"][..], &["-V"][..]] {
        let out = sbx(spelling);
        assert!(out.status.success(), "`sbx {spelling:?}` should exit 0");
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert_eq!(stdout, expected, "`sbx {spelling:?}` printed {stdout:?}");
        assert!(out.stderr.is_empty(), "the version goes to stdout alone");
    }
    let (name, rest) = expected.trim_end().split_once(' ').expect("two fields");
    assert_eq!(name, "sbx");
    assert!(
        rest.split('.').count() >= 2 && rest.chars().all(|c| c.is_ascii_digit() || c == '.'),
        "the version should be a dotted number, got {rest:?}"
    );
}

/// A help flag on any spelling renders the page instead of printing the version, and an argument
/// the verb does not take is refused against its own synopsis.
///
/// Both are properties of routing `--version` to a page-carrying verb rather than answering it at
/// the root: the page exists to be reached, and the shared refusal has a synopsis to quote.
#[test]
fn version_answers_a_help_flag_with_its_page_and_refuses_an_extra() {
    for spelling in [&["version"][..], &["--version"][..], &["-V"][..]] {
        let mut args = spelling.to_vec();
        args.push("--help");
        let out = sbx(&args);
        assert!(out.status.success(), "`sbx {args:?}` should exit 0");
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert!(
            stdout.contains("sbx version —"),
            "`sbx {args:?}` should render the page, got {stdout:?}"
        );
    }
    let out = sbx(&["version", "bogus"]);
    assert_eq!(out.status.code(), Some(2), "an extra argument is refused");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("version takes no argument 'bogus'"),
        "{stderr}"
    );
    assert!(
        stderr.contains("usage: sbx version"),
        "the refusal should quote the verb's own synopsis, got {stderr}"
    );
}
