//! Integration tests for the session registry and `sbx session ls`.
//!
//! Two properties: `sbx session ls` reports cleanly when there is nothing to show
//! (no sandbox needed), and a second sandbox launched in
//! the same project shares the first's persistent `$HOME`, i.e. "a 2nd terminal
//! in the same env". The shared-env test is skipped, not failed, where the host
//! cannot sandbox.

#[macro_use]
mod common;

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU32, Ordering};

/// The in-sandbox `$HOME` (a fixed mountpoint inside every sandbox).
const SANDBOX_HOME: &str = "/home/sandbox";

fn sbx() -> Command {
    // Isolate XDG_CONFIG_HOME from the user's real `~/.config/sbx` so an e2e never depends on
    // the developer's global sbx config; default it to a fixed empty dir under the test tree
    // (no test here writes a global config, so a shared empty dir is race-free).
    let mut cfg = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    cfg.push("target/test-tmp/isolated-config");
    let _ = std::fs::create_dir_all(&cfg);
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_sbx"));
    cmd.env("XDG_CONFIG_HOME", cfg);
    cmd
}

/// Where this suite's throwaway fixtures live: the repo's own test tree, overridable with
/// `SBX_TEST_TMPDIR`.
///
/// Deliberately **not** `std::env::temp_dir()`, which resolves to `/tmp` when `TMPDIR` is unset. A
/// fixture here holds a provisioned nix store, which is inode-heavy. `/tmp` is usually a tmpfs
/// whose inode count is capped machine-wide at about a million, so these fixtures exhaust it and
/// *unrelated* work then fails with "no space left on device" while the disk is nearly empty. The
/// repo's disk has inodes to spare, it matches production (the store lives on disk), and
/// `cargo clean` reclaims it.
///
/// Keep the per-fixture tag short: a launch's egress proxy binds a Unix socket under the data dir,
/// and `sun_path` caps the whole path at 108 bytes, which this tree already spends most of.
fn fixture_root() -> PathBuf {
    if let Some(dir) = std::env::var_os("SBX_TEST_TMPDIR") {
        return PathBuf::from(dir);
    }
    let mut d = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    d.push("target/test-tmp");
    d
}

/// A unique temp dir removed on drop.
struct TmpDir(PathBuf);

impl TmpDir {
    fn new(tag: &str) -> Self {
        static COUNTER: AtomicU32 = AtomicU32::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let mut d = fixture_root();
        d.push(format!("sn-{tag}-{}-{n}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        TmpDir(d)
    }
    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TmpDir {
    fn drop(&mut self) {
        force_remove(&self.0);
    }
}

/// Remove a tree that may contain read-only directories: a provisioned nix store
/// makes its directories `0555`, so add write on the way down before deleting.
fn force_remove(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let Ok(meta) = std::fs::symlink_metadata(path) else {
        return;
    };
    if meta.is_dir() {
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700));
        if let Ok(entries) = std::fs::read_dir(path) {
            for entry in entries.flatten() {
                force_remove(&entry.path());
            }
        }
        let _ = std::fs::remove_dir(path);
    } else {
        let _ = std::fs::remove_file(path);
    }
}

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
    let data = TmpDir::new("data");
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
    let project = TmpDir::new("proj");
    let data = TmpDir::new("data");

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
