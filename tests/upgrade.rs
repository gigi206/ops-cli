//! Integration tests for `sbx upgrade`, exercising the built binary end to end.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU32, Ordering};

fn sbx() -> Command {
    Command::new(env!("CARGO_BIN_EXE_sbx"))
}

/// Where this suite's throwaway fixtures live: the repo's own test tree, overridable with
/// `SBX_TEST_TMPDIR`.
///
/// Deliberately **not** `std::env::temp_dir()`, which resolves to `/tmp` when `TMPDIR` is unset. A
/// fixture here may hold a provisioned nix store, which is inode-heavy enough to exhaust a tmpfs's
/// machine-wide inode budget — surfacing as "no space left on device" in *unrelated* work while the
/// disk is nearly empty. Disk has inodes to spare, it matches production (the store lives on disk),
/// and `cargo clean` reclaims it.
fn fixture_root() -> PathBuf {
    if let Some(dir) = std::env::var_os("SBX_TEST_TMPDIR") {
        return PathBuf::from(dir);
    }
    let mut d = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    d.push("target/test-tmp");
    d
}

/// A unique temp dir removed on drop, so the binary's lock writes land in a throwaway
/// location instead of the real `$HOME`.
struct TmpDir(PathBuf);

impl TmpDir {
    fn new() -> Self {
        static COUNTER: AtomicU32 = AtomicU32::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let mut d = fixture_root();
        d.push(format!("upg-{}-{n}", std::process::id()));
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
    let out = sbx()
        .args(["upgrade", "bogus"])
        .output()
        .expect("spawn sbx upgrade");
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
    let projects = data.join("sbx").join("projects");
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
    // A real resolution of a declared `flake:` package: `sbx upgrade flake` resolves the floating
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
        proj.path().join(".sbx.toml"),
        format!("[packages]\nfutil = \"flake:{reference}\"\n"),
    )
    .unwrap();

    // The flake package is a trusted-only field, so the project must be trusted to be rolled.
    let trusted = sbx()
        .args(["trust", ".sbx.toml"])
        .current_dir(proj.path())
        .env("XDG_DATA_HOME", data.path())
        .env("XDG_STATE_HOME", state.path())
        .output()
        .expect("spawn sbx trust");
    assert!(
        trusted.status.success(),
        "sbx trust failed: {}",
        String::from_utf8_lossy(&trusted.stderr)
    );

    let run = || {
        sbx()
            .args(["upgrade", "flake"])
            .current_dir(proj.path())
            .env("XDG_DATA_HOME", data.path())
            .env("XDG_STATE_HOME", state.path())
            .output()
            .expect("spawn sbx upgrade flake")
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

    // `sbx config show` surfaces the pin the upgrade just wrote — host-side, no nix, no network.
    // This is the make-or-break for the display: the lock key the upgrade wrote must be the
    // locator the view looks up by, or no rev would ever show. The project is trusted, so the
    // flake package is admitted (not withheld).
    let shown = sbx()
        .args(["config", "show"])
        .current_dir(proj.path())
        .env("XDG_DATA_HOME", data.path())
        .env("XDG_STATE_HOME", state.path())
        .output()
        .expect("spawn sbx config show");
    assert!(
        shown.status.success(),
        "sbx config show failed: {}",
        String::from_utf8_lossy(&shown.stderr)
    );
    let out = String::from_utf8_lossy(&shown.stdout);
    let short = &rev1[..7];
    assert!(
        out.contains(&format!("futil -> flake:{reference}"))
            && out.contains(&format!("@ {short}"))
            && out.contains("pinned"),
        "sbx config show must display the pinned flake revision {short}:\n{out}"
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
    // (not failed) where the first `sbx upgrade` cannot run.
    let data = TmpDir::new();
    let proj = TmpDir::new();
    let run = || {
        sbx()
            .args(["upgrade", "nix"])
            .current_dir(proj.path())
            .env("XDG_DATA_HOME", data.path())
            .output()
            .expect("spawn sbx upgrade")
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
        data.path().join("sbx/nixpkgs.lock").is_file(),
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
