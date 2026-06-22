//! Integration tests for `ops upgrade`, exercising the built binary end to end.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU32, Ordering};

fn ops() -> Command {
    Command::new(env!("CARGO_BIN_EXE_ops"))
}

/// A unique temp dir removed on drop, so the binary's lock writes land in a throwaway
/// location instead of the real `$HOME`.
struct TmpDir(PathBuf);

impl TmpDir {
    fn new() -> Self {
        static COUNTER: AtomicU32 = AtomicU32::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let mut d = std::env::temp_dir();
        d.push(format!("ops-upgrade-it-{}-{n}", std::process::id()));
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

#[test]
fn upgrade_rejects_an_unknown_target() {
    // The target is parsed before anything else, so this needs neither nix nor a data
    // directory.
    let out = ops()
        .args(["upgrade", "bogus"])
        .output()
        .expect("spawn ops upgrade");
    assert_eq!(out.status.code(), Some(2));
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("unknown upgrade target"),
        "stderr:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

/// The revision the per-project flake lock records for `reference`, if any. The lock lives under
/// the single project's directory; each line is `<reference>\t<rev>\t<locked-ref>`.
fn flake_lock_rev(data: &Path, reference: &str) -> Option<String> {
    let projects = data.join("ops").join("projects");
    for entry in std::fs::read_dir(&projects).ok()?.flatten() {
        let lock = entry.path().join("flake-packages.lock");
        if let Ok(text) = std::fs::read_to_string(&lock) {
            for line in text.lines() {
                let parts: Vec<&str> = line.split('\t').collect();
                if parts.first() == Some(&reference) {
                    return parts.get(1).map(|s| s.to_string());
                }
            }
        }
    }
    None
}

#[test]
fn upgrade_flake_pins_and_locks_a_declared_flake_package() {
    // A real resolution of a declared `flake:` package: `ops upgrade flake` resolves the floating
    // reference to its current immutable revision with `nix flake metadata` and writes the
    // per-project flake lock — a host-side lock rewrite (the new pin builds in-cage at the next
    // launch). Teeth: the lock records a 40-hex revision for the declared reference, and a second
    // run moments later re-resolves to the *same* revision ("unchanged" — idempotent). Needs nix
    // and the network (github); skipped (not failed) where the resolution cannot run.
    let data = TmpDir::new();
    let proj = TmpDir::new();
    let state = TmpDir::new();
    let reference = "github:numtide/flake-utils";
    std::fs::write(
        proj.path().join(".ops.toml"),
        format!("[packages]\nfutil = \"flake:{reference}\"\n"),
    )
    .unwrap();

    // The flake package is a trusted-only field, so the project must be trusted to be rolled.
    let trusted = ops()
        .args(["trust", ".ops.toml"])
        .current_dir(proj.path())
        .env("XDG_DATA_HOME", data.path())
        .env("XDG_STATE_HOME", state.path())
        .output()
        .expect("spawn ops trust");
    assert!(
        trusted.status.success(),
        "ops trust failed: {}",
        String::from_utf8_lossy(&trusted.stderr)
    );

    let run = || {
        ops()
            .args(["upgrade", "flake"])
            .current_dir(proj.path())
            .env("XDG_DATA_HOME", data.path())
            .env("XDG_STATE_HOME", state.path())
            .output()
            .expect("spawn ops upgrade flake")
    };

    let first = run();
    let log = format!(
        "{}{}",
        String::from_utf8_lossy(&first.stderr),
        String::from_utf8_lossy(&first.stdout)
    );
    if !first.status.success() || log.contains("re-resolve failed") {
        eprintln!("skipping flake upgrade resolution: {log}");
        return;
    }
    assert!(
        String::from_utf8_lossy(&first.stdout).contains("newly pinned"),
        "a first resolution must pin the flake package:\n{log}"
    );

    let rev1 = flake_lock_rev(data.path(), reference)
        .expect("the flake lock must record a revision for the declared reference");
    assert!(
        rev1.len() == 40 && rev1.bytes().all(|b| b.is_ascii_hexdigit()),
        "the lock revision must be 40-hex, got {rev1}"
    );

    // A second upgrade moments later resolves the same HEAD — an idempotent no-op.
    let again = run();
    assert!(again.status.success());
    assert!(
        String::from_utf8_lossy(&again.stdout).contains("unchanged"),
        "a repeat flake upgrade should be unchanged:\n{}",
        String::from_utf8_lossy(&again.stdout)
    );
    assert_eq!(
        flake_lock_rev(data.path(), reference).unwrap(),
        rev1,
        "an idempotent re-resolution keeps the same revision"
    );
}

#[test]
fn upgrade_resolves_and_locks_the_default_channel() {
    // A real resolution of the rolling channel: needs nix and the network. Skipped
    // (not failed) where the first `ops upgrade` cannot run.
    let data = TmpDir::new();
    let proj = TmpDir::new();
    let run = || {
        ops()
            .args(["upgrade", "nix"])
            .current_dir(proj.path())
            .env("XDG_DATA_HOME", data.path())
            .output()
            .expect("spawn ops upgrade")
    };

    let first = run();
    if !first.status.success() {
        eprintln!(
            "skipping upgrade resolution: {}",
            String::from_utf8_lossy(&first.stderr)
        );
        return;
    }
    let stdout = String::from_utf8_lossy(&first.stdout);
    assert!(stdout.contains("channel"), "stdout:\n{stdout}");
    assert!(
        stdout.contains("first pin"),
        "a first resolution must say so:\n{stdout}"
    );
    // the first resolution writes the global lock
    assert!(
        data.path().join("ops/nixpkgs.lock").is_file(),
        "upgrade must write the global lock"
    );

    // a second upgrade moments later finds the same channel HEAD — an explicit no-op
    let again = run();
    assert!(again.status.success());
    assert!(
        String::from_utf8_lossy(&again.stdout).contains("already at the latest"),
        "a repeat upgrade should be a no-op:\n{}",
        String::from_utf8_lossy(&again.stdout)
    );
}
