//! Integration tests for the session registry and `sbx session ls`.
//!
//! Two properties: `sbx session ls` reports cleanly when there is nothing to show
//! (no sandbox needed), and a second sandbox launched in
//! the same project shares the first's persistent `$HOME`, i.e. "a 2nd terminal
//! in the same env". The shared-env test is skipped, not failed, where the host
//! cannot sandbox.

#[macro_use]
mod common;
use common::fixture::TmpDir;

use std::path::Path;
use std::process::Command;

/// The in-sandbox `$HOME` (a fixed mountpoint inside every sandbox).
const SANDBOX_HOME: &str = "/home/sandbox";

fn sbx() -> Command {
    // Isolate XDG_CONFIG_HOME from the user's real `~/.config/sbx` so an e2e never depends on
    // the developer's global sbx config; default it to a fixed empty dir under the test tree
    // (no test here writes a global config, so a shared empty dir is race-free).
    let cfg = fixture_root().join("isolated-config");
    let _ = std::fs::create_dir_all(&cfg);
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_sbx"));
    cmd.env("XDG_CONFIG_HOME", cfg);
    cmd
}

// The fixtures' root, one definition shared with the unit tests.
include!("../src/testroot.rs");

/// Run `sbx <args...>` in `project` against `data`, returning (success, stdout).
fn run(args: &[&str], project: &Path, data: &Path) -> (bool, String) {
    let out = sbx()
        .args(args)
        .current_dir(project)
        .env("XDG_DATA_HOME", data)
        .output()
        .expect("spawn sbx");
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
    )
}

#[test]
fn ls_reports_no_sessions_on_an_empty_registry() {
    // A fresh data dir holds no records; `sbx session ls` must succeed and say so. Needs
    // no sandbox, so it always runs.
    let data = TmpDir::prefixed("sn", "data");
    let out = sbx()
        .arg("session")
        .arg("ls")
        .env("XDG_DATA_HOME", data.path())
        .output()
        .expect("spawn sbx session ls");
    assert!(
        out.status.success(),
        "sbx ls should succeed on an empty registry"
    );
    assert!(
        String::from_utf8_lossy(&out.stdout).contains("no active"),
        "expected an empty-registry notice"
    );
}

#[test]
fn a_second_sandbox_shares_the_projects_persistent_home() {
    let project = TmpDir::prefixed("sn", "proj");
    let data = TmpDir::prefixed("sn", "data");

    // Skip where the host cannot sandbox (this first run also warms the userland).
    if !run(&["run", "--", "true"], project.path(), data.path()).0 {
        skip_incapable!(
            "skipping shared-home smoke: host cannot sandbox (no userns/bwrap, or the base cache is unreachable)"
        );
        return;
    }

    // First sandbox: create a file in its $HOME.
    let marker = format!("{SANDBOX_HOME}/marker");
    let (ok, _) = run(
        &["run", "--", "touch", &marker],
        project.path(),
        data.path(),
    );
    assert!(ok, "first sandbox could not write its $HOME");

    // Second, independent sandbox in the *same* project + data dir: it must see
    // the first's file, proving both share one persistent per-project $HOME.
    let (ok, listing) = run(
        &["run", "--", "ls", SANDBOX_HOME],
        project.path(),
        data.path(),
    );
    assert!(ok, "second sandbox failed to launch");
    assert!(
        listing.contains("marker"),
        "the second sandbox did not see the first's $HOME (not the same env):\n{listing}"
    );
}
