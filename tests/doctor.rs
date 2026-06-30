//! Integration tests for `ops doctor`, exercising the built binary end to end.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU32, Ordering};

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

/// A unique temp dir removed on drop, so the binary's store bootstrap lands in a
/// throwaway location instead of the real `$HOME`.
struct TmpDir(PathBuf);

impl TmpDir {
    fn new() -> Self {
        static COUNTER: AtomicU32 = AtomicU32::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let mut d = std::env::temp_dir();
        d.push(format!("ops-it-{}-{n}", std::process::id()));
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
fn doctor_prints_the_preflight_structure() {
    // Redirect ops's data dir to a throwaway location so the asserted store path
    // is deterministic and independent of the real `$HOME`.
    let data = TmpDir::new();
    let out = ops()
        .arg("doctor")
        .env("XDG_DATA_HOME", data.path())
        .output()
        .expect("spawn ops doctor");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("runtime preflight"), "stdout was: {stdout}");
    assert!(stdout.contains("bubblewrap"), "stdout was: {stdout}");
    assert!(stdout.contains("user namespaces"), "stdout was: {stdout}");
    assert!(stdout.contains("nix"), "stdout was: {stdout}");
    // the channel line is present; with a fresh data dir nothing is locked yet
    assert!(stdout.contains("channel"), "stdout was: {stdout}");
    assert!(
        stdout.contains("not yet resolved"),
        "a fresh data dir has no locked channel: {stdout}"
    );

    // the store line points at our redirected data dir; doctor is read-only, so
    // it reports the path without creating it.
    let store_path = data.path().join("ops/store");
    assert!(
        stdout.contains(&*store_path.to_string_lossy()),
        "store line should mention {}; stdout was: {stdout}",
        store_path.display()
    );
    assert!(
        !store_path.exists(),
        "doctor must not create the store (read-only); found {}",
        store_path.display()
    );

    // 0 (all prerequisites OK) or 1 (a hard requirement missing) — both valid
    // depending on the host; anything else is a bug.
    let code = out.status.code().expect("exited normally");
    assert!(code == 0 || code == 1, "unexpected exit code {code}");
}

#[test]
fn doctor_proves_the_boundary_by_a_real_launch_where_supported() {
    // Where the host can actually sandbox, doctor decides the security boundary
    // from a real bwrap launch — not the `unshare` stand-in — and says so. Gate
    // on a real `ops run`: if that succeeds, the engine, the namespace, and nix
    // are all present, so doctor must be fully green. Skipped, not failed,
    // elsewhere.
    let data = TmpDir::new();
    let can_sandbox = ops()
        .args(["run", "--", "true"])
        .env("XDG_DATA_HOME", data.path())
        .status()
        .expect("spawn ops run")
        .success();
    if !can_sandbox {
        eprintln!("skipping doctor launch-proof: host cannot sandbox");
        return;
    }

    let out = ops()
        .arg("doctor")
        .env("XDG_DATA_HOME", data.path())
        .output()
        .expect("spawn ops doctor");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(
        out.status.code(),
        Some(0),
        "doctor should be green on a host that can sandbox; stdout was:\n{stdout}"
    );
    assert!(
        stdout.contains("proven by the launch"),
        "the boundary should be decided by a real launch; stdout was:\n{stdout}"
    );
}

#[test]
fn a_failed_launch_with_a_working_namespace_blames_bubblewrap() {
    // The crux of M1.5: a capability-bearing namespace plus a failed launch means
    // the *engine* is at fault, so doctor must blame bubblewrap and surface its
    // stderr — never the namespace. Force it with a stub bwrap that always fails.
    // Gate on a real sandbox working first (with the unmodified PATH), so the
    // namespace probe is known to say Ok; only then is the stub's failure
    // unambiguously the engine. Skipped, not failed, where the host cannot
    // sandbox.
    let data = TmpDir::new();
    let can_sandbox = ops()
        .args(["run", "--", "true"])
        .env("XDG_DATA_HOME", data.path())
        .status()
        .expect("spawn ops run")
        .success();
    if !can_sandbox {
        eprintln!("skipping bubblewrap-fault attribution: host cannot sandbox");
        return;
    }

    // A stub bwrap, first on PATH, that always fails with a recognizable message.
    let stub_dir = TmpDir::new();
    let stub = stub_dir.path().join("bwrap");
    std::fs::write(&stub, "#!/bin/sh\necho boom >&2\nexit 1\n").expect("write stub bwrap");
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perm = std::fs::metadata(&stub).unwrap().permissions();
        perm.set_mode(0o755);
        std::fs::set_permissions(&stub, perm).unwrap();
    }
    let path = format!(
        "{}:{}",
        stub_dir.path().display(),
        std::env::var("PATH").unwrap_or_default()
    );

    let out = ops()
        .arg("doctor")
        .env("PATH", path)
        .env("XDG_DATA_HOME", data.path())
        .output()
        .expect("spawn ops doctor");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(
        out.status.code(),
        Some(1),
        "a failed launch is a hard failure; stdout was:\n{stdout}"
    );
    assert!(
        stdout.contains("the failure is in bubblewrap"),
        "the fault must be attributed to the engine, not the namespace; stdout was:\n{stdout}"
    );
    assert!(
        stdout.contains("boom"),
        "bwrap's own stderr should be surfaced; stdout was:\n{stdout}"
    );
}

#[test]
fn doctor_reports_the_locked_channel_revision() {
    // With a channel lock present, doctor surfaces its source and revision read-only —
    // closing the gap where doctor was blind to the resolved revision. Seeded directly
    // (doctor never resolves), so this needs no nix.
    let data = TmpDir::new();
    let lock_dir = data.path().join("ops");
    std::fs::create_dir_all(&lock_dir).unwrap();
    let rev = "9ae611a455b90cf061d8f332b977e387bda8e1ca";
    std::fs::write(
        lock_dir.join("nixpkgs.lock"),
        format!("nixos-unstable\n{rev}\n"),
    )
    .unwrap();

    let out = ops()
        .arg("doctor")
        .env("XDG_DATA_HOME", data.path())
        .output()
        .expect("spawn ops doctor");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("nixos-unstable @ 9ae611a"),
        "doctor must show the locked channel revision:\n{stdout}"
    );
}

#[test]
fn no_arguments_is_a_usage_error() {
    let out = ops().output().expect("spawn ops");
    assert_eq!(out.status.code(), Some(2));
    // No command prints the command list to stderr (an error path) and exits non-zero.
    assert!(String::from_utf8_lossy(&out.stderr).contains("Usage:"));
}

#[test]
fn unknown_command_is_rejected() {
    let out = ops().arg("bogus").output().expect("spawn ops bogus");
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out.stderr).contains("unknown command"));
}
