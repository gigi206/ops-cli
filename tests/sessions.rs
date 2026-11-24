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
use common::{output_ok, stdout_of};

use std::path::Path;
use std::process::Command;

/// The in-sandbox `$HOME` (a fixed mountpoint inside every sandbox).
const SANDBOX_HOME: &str = "/home/sandbox";

fn sbx() -> Command {
    // The global config and the trust store come from fixed empty directories under the test tree
    // ([`common::isolated_sbx`]), so neither test depends on the developer's `~/.config/sbx` or on
    // their trust markers. No test here writes either, so the shared directories are race-free.
    common::isolated_sbx("")
}

/// `sbx <args...>` in `project` against `data`.
fn sbx_in(args: &[&str], project: &Path, data: &Path) -> Command {
    let mut cmd = sbx();
    cmd.args(args)
        .current_dir(project)
        .env("XDG_DATA_HOME", data);
    cmd
}

#[test]
fn ls_reports_no_sessions_on_an_empty_registry() {
    // A fresh data dir holds no records; `sbx session ls` must succeed and say so. Needs
    // no sandbox, so it always runs.
    let data = TmpDir::prefixed("sn", "data");
    let out = output_ok(
        sbx()
            .args(["session", "ls"])
            .env("XDG_DATA_HOME", data.path()),
    );
    // The line alone: a listing printed after it, or a warning beside it, is not an empty registry
    // reported cleanly.
    assert_eq!(stdout_of(&out), "sbx: no active sandbox sessions.\n");
    assert_eq!(String::from_utf8_lossy(&out.stderr), "");
}

#[test]
fn a_second_sandbox_shares_the_projects_persistent_home() {
    let project = TmpDir::prefixed("sn", "proj");
    let data = TmpDir::prefixed("sn", "data");

    // Skip where the host cannot sandbox (this first run also warms the userland).
    probe_or_skip!(
        "shared-home smoke",
        sbx_in(&["run", "--", "true"], project.path(), data.path())
            .output()
            .expect("spawn sbx")
    );

    // First sandbox: create a file in its $HOME.
    let marker = format!("{SANDBOX_HOME}/marker");
    output_ok(&mut sbx_in(
        &["run", "--", "touch", &marker],
        project.path(),
        data.path(),
    ));

    // Second, independent sandbox in the *same* project + data dir: it must see
    // the first's file, proving both share one persistent per-project $HOME.
    let listing = stdout_of(&output_ok(&mut sbx_in(
        &["run", "--", "ls", SANDBOX_HOME],
        project.path(),
        data.path(),
    )));
    assert!(
        listing.lines().any(|entry| entry == "marker"),
        "the second sandbox did not see the first's $HOME (not the same env):\n{listing}"
    );
}
