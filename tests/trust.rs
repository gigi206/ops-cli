//! Integration tests for `sbx trust` / `sbx untrust`, exercising the built
//! binary end to end against a redirected trust store.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU32, Ordering};

fn sbx() -> Command {
    Command::new(env!("CARGO_BIN_EXE_sbx"))
}

/// Where this suite's throwaway fixtures live: the repo's own test tree, overridable with
/// `SBX_TEST_TMPDIR`.
///
/// Deliberately **not** `std::env::temp_dir()`, which resolves to `/tmp` when `TMPDIR` is unset.
/// These fixtures are small, but the repo's tree is the safe default: a fixture that ends up
/// holding a provisioned nix store is inode-heavy enough to exhaust a tmpfs's machine-wide inode
/// budget, which then surfaces as "no space left on device" in *unrelated* work while the disk is
/// nearly empty. Disk has inodes to spare, and it is reclaimed by removing that tree.
fn fixture_root() -> PathBuf {
    if let Some(dir) = std::env::var_os("SBX_TEST_TMPDIR") {
        return PathBuf::from(dir);
    }
    // Outside the workspace by default, and that is the point rather than an accident: a language
    // server watching the repository spends one inotify watch per directory, one run of this suite
    // leaves hundreds of thousands of them, and the machine's `max_user_watches` is what runs out.
    // Still on disk rather than a tmpfs, whose fixed inode budget a provisioned nix store exhausts.
    // Falls back inside the workspace only when neither variable names a home to use.
    let mut d = std::env::var_os("XDG_CACHE_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".cache")))
        .unwrap_or_else(|| PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("target"));
    d.push("sbx/test-tmp");
    d
}

/// A unique temp dir removed on drop, so the trust store and the project config
/// land in throwaway locations instead of the real `$HOME`/`$XDG_STATE_HOME`.
struct TmpDir(PathBuf);

impl TmpDir {
    fn new() -> Self {
        static COUNTER: AtomicU32 = AtomicU32::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let mut d = fixture_root();
        d.push(format!("trust-{}-{n}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        TmpDir(d)
    }
    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TmpDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Count the marker files under a redirected trust store.
fn marker_count(state_home: &Path) -> usize {
    let trusted = state_home.join("sbx/trusted");
    match std::fs::read_dir(&trusted) {
        Ok(entries) => entries.filter_map(Result::ok).count(),
        Err(_) => 0,
    }
}

#[test]
fn trust_then_untrust_records_and_revokes_a_marker() {
    let state = TmpDir::new();
    let proj = TmpDir::new();
    let cfg = proj.path().join(".sbx.toml");
    std::fs::write(&cfg, b"network = \"isolated\"\n").unwrap();

    assert_eq!(marker_count(state.path()), 0, "no markers before trust");

    let trust = sbx()
        .arg("trust")
        .arg(&cfg)
        .env("XDG_STATE_HOME", state.path())
        .output()
        .expect("spawn sbx trust");
    assert!(
        trust.status.success(),
        "trust failed: {}",
        String::from_utf8_lossy(&trust.stderr)
    );
    assert_eq!(marker_count(state.path()), 1, "one marker after trust");

    let untrust = sbx()
        .arg("untrust")
        .arg(&cfg)
        .env("XDG_STATE_HOME", state.path())
        .output()
        .expect("spawn sbx untrust");
    assert!(untrust.status.success(), "untrust should succeed");
    assert_eq!(marker_count(state.path()), 0, "marker gone after untrust");

    // A second untrust is a no-op success that says so.
    let again = sbx()
        .arg("untrust")
        .arg(&cfg)
        .env("XDG_STATE_HOME", state.path())
        .output()
        .expect("spawn sbx untrust");
    assert!(again.status.success());
    assert!(String::from_utf8_lossy(&again.stdout).contains("was not trusted"));
}

#[test]
fn show_reports_untrusted_then_trusted_then_changed() {
    let state = TmpDir::new();
    let proj = TmpDir::new();
    let cfg = proj.path().join(".sbx.toml");
    std::fs::write(&cfg, b"network = \"isolated\"\n").unwrap();

    let show = |label: &str| {
        let out = sbx()
            .args(["trust", "--show"])
            .arg(&cfg)
            .env("XDG_STATE_HOME", state.path())
            .output()
            .expect("spawn sbx trust --show");
        assert!(
            out.status.success(),
            "{label}: --show should always succeed"
        );
        String::from_utf8_lossy(&out.stdout).into_owned()
    };

    assert!(show("before").contains("untrusted"));

    sbx()
        .arg("trust")
        .arg(&cfg)
        .env("XDG_STATE_HOME", state.path())
        .status()
        .expect("spawn sbx trust");
    assert!(show("after trust").contains("is trusted"));

    std::fs::write(&cfg, b"network = \"isolated\"\nbinds = [\"/etc/ssh\"]\n").unwrap();
    assert!(show("after edit").contains("changed since it was trusted"));
}

#[test]
fn trust_covers_a_sibling_mise_file_and_editing_it_re_arms() {
    let state = TmpDir::new();
    let proj = TmpDir::new();
    let cfg = proj.path().join(".sbx.toml");
    let mise = proj.path().join(".mise.toml");
    std::fs::write(&cfg, b"[env]\nA = \"1\"\n").unwrap();
    std::fs::write(&mise, b"[tools]\nnode = \"20\"\n").unwrap();

    let show = |label: &str| {
        let out = sbx()
            .args(["trust", "--show"])
            .arg(&cfg)
            .env("XDG_STATE_HOME", state.path())
            .output()
            .expect("spawn sbx trust --show");
        assert!(out.status.success(), "{label}: --show should succeed");
        String::from_utf8_lossy(&out.stdout).into_owned()
    };

    sbx()
        .arg("trust")
        .arg(&cfg)
        .env("XDG_STATE_HOME", state.path())
        .status()
        .expect("spawn sbx trust");
    assert!(show("after trust").contains("is trusted"));

    // Editing only the mise file must re-arm the gate: trust is the single
    // authority over both declarative inputs.
    std::fs::write(&mise, b"[tools]\nnode = \"22\"\n").unwrap();
    assert!(show("after mise edit").contains("changed since it was trusted"));
}

#[test]
fn trust_refuses_a_world_writable_mise_file() {
    use std::os::unix::fs::PermissionsExt;
    let state = TmpDir::new();
    let proj = TmpDir::new();
    let cfg = proj.path().join(".sbx.toml");
    let mise = proj.path().join(".mise.toml");
    std::fs::write(&cfg, b"x = 1\n").unwrap();
    std::fs::write(&mise, b"[tools]\nnode = \"20\"\n").unwrap();
    std::fs::set_permissions(&mise, std::fs::Permissions::from_mode(0o666)).unwrap();

    let out = sbx()
        .arg("trust")
        .arg(&cfg)
        .env("XDG_STATE_HOME", state.path())
        .output()
        .expect("spawn sbx trust");
    assert_eq!(
        out.status.code(),
        Some(1),
        "a world-writable mise file must block recording trust"
    );
    assert!(String::from_utf8_lossy(&out.stderr).contains("world-writable"));
    assert_eq!(marker_count(state.path()), 0, "nothing trusted");
}

#[test]
fn trust_refuses_a_world_writable_config() {
    use std::os::unix::fs::PermissionsExt;
    let state = TmpDir::new();
    let proj = TmpDir::new();
    let cfg = proj.path().join(".sbx.toml");
    std::fs::write(&cfg, b"x = 1\n").unwrap();
    std::fs::set_permissions(&cfg, std::fs::Permissions::from_mode(0o666)).unwrap();

    let out = sbx()
        .arg("trust")
        .arg(&cfg)
        .env("XDG_STATE_HOME", state.path())
        .output()
        .expect("spawn sbx trust");
    assert_eq!(
        out.status.code(),
        Some(1),
        "a world-writable config must be refused"
    );
    assert!(String::from_utf8_lossy(&out.stderr).contains("world-writable"));
    assert_eq!(marker_count(state.path()), 0, "nothing trusted");
}

#[test]
fn an_unresolvable_store_is_a_hard_failure() {
    let proj = TmpDir::new();
    let cfg = proj.path().join(".sbx.toml");
    std::fs::write(&cfg, b"x = 1\n").unwrap();

    // A relative XDG_STATE_HOME must be ignored (never resolved against the cwd);
    // with HOME also cleared there is no absolute base, so trust must fail loudly
    // rather than write a marker somewhere unexpected.
    let out = sbx()
        .arg("trust")
        .arg(&cfg)
        .env("XDG_STATE_HOME", "relative/state")
        .env_remove("HOME")
        .output()
        .expect("spawn sbx trust");
    assert_eq!(out.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&out.stderr).contains("cannot locate the trust store"));
}
