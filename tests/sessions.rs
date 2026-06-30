//! Integration tests for the session registry and `ops ls`.
//!
//! Two properties: `ops ls` reports cleanly when there is nothing to show
//! (no sandbox needed), and — the M1.4 headline — a second sandbox launched in
//! the same project shares the first's persistent `$HOME`, i.e. "a 2nd terminal
//! in the same env". The shared-env test is skipped, not failed, where the host
//! cannot sandbox.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU32, Ordering};

/// The in-sandbox `$HOME` (a fixed mountpoint inside every sandbox).
const SANDBOX_HOME: &str = "/home/sandbox";

fn ops() -> Command {
    // Isolate XDG_CONFIG_HOME from the user's real `~/.config/ops` so an e2e never depends on
    // the developer's global ops config; default it to a fixed empty dir under the test tree
    // (no test here writes a global config, so a shared empty dir is race-free).
    let mut cfg = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    cfg.push("target/test-tmp/isolated-config");
    let _ = std::fs::create_dir_all(&cfg);
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_ops"));
    cmd.env("XDG_CONFIG_HOME", cfg);
    cmd
}

/// A unique temp dir removed on drop.
struct TmpDir(PathBuf);

impl TmpDir {
    fn new(tag: &str) -> Self {
        static COUNTER: AtomicU32 = AtomicU32::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let mut d = std::env::temp_dir();
        d.push(format!("ops-sessions-it-{tag}-{}-{n}", std::process::id()));
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

/// Run `ops <args...>` in `project` against `data`, returning (success, stdout).
fn run(args: &[&str], project: &Path, data: &Path) -> (bool, String) {
    let out = ops()
        .args(args)
        .current_dir(project)
        .env("XDG_DATA_HOME", data)
        .output()
        .expect("spawn ops");
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
    )
}

#[test]
fn ls_reports_no_sessions_on_an_empty_registry() {
    // A fresh data dir holds no records; `ops ls` must succeed and say so. Needs
    // no sandbox, so it always runs.
    let data = TmpDir::new("data");
    let out = ops()
        .arg("ls")
        .env("XDG_DATA_HOME", data.path())
        .output()
        .expect("spawn ops ls");
    assert!(
        out.status.success(),
        "ops ls should succeed on an empty registry"
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
        eprintln!("skipping shared-home smoke: host cannot sandbox");
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
