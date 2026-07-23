//! Integration tests for `sbx fs` — the filesystem-observation CLI wiring: session resolution and the
//! error paths for `logs`, plus a cage-backed e2e for the detached file-write ring read over the
//! control socket. The pure error paths run against an isolated (empty) data directory (no sandbox);
//! the cage-backed one skips where the host cannot sandbox.

use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

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
/// Keep the per-fixture name short: a launch's egress proxy binds a Unix socket under the data dir,
/// and `sun_path` caps the whole path at 108 bytes, which this tree already spends most of.
fn fixture_root() -> PathBuf {
    if let Some(dir) = std::env::var_os("SBX_TEST_TMPDIR") {
        return PathBuf::from(dir);
    }
    let mut d = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    d.push("target/test-tmp");
    d
}

struct TmpDir(PathBuf);

impl TmpDir {
    fn new() -> Self {
        static N: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
        let n = N.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let mut d = fixture_root();
        d.push(format!("f-{}-{n}", std::process::id()));
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

/// Remove a tree that may contain read-only directories (a provisioned nix store makes its
/// directories `0555`): add write on the way down before deleting.
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

/// Run `sbx <args>` with an isolated, empty data directory so the session registry is empty and the
/// outcome is deterministic regardless of the host's real sessions.
fn sbx(args: &[&str], data: &Path, cwd: &Path) -> Output {
    Command::new(env!("CARGO_BIN_EXE_sbx"))
        .args(args)
        .current_dir(cwd)
        .env("XDG_DATA_HOME", data)
        .env("LC_ALL", "C.UTF-8")
        .output()
        .expect("run sbx")
}

#[test]
fn fs_logs_with_no_sessions_reports_none_and_exits_2() {
    let (data, proj) = (TmpDir::new(), TmpDir::new());
    let out = sbx(&["fs", "logs"], data.path(), proj.path());
    let err = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(2), "stderr: {err}");
    assert!(err.contains("no active sandbox sessions"), "got: {err}");
}

#[test]
fn fs_logs_rejects_a_second_id() {
    let (data, proj) = (TmpDir::new(), TmpDir::new());
    let out = sbx(&["fs", "logs", "1", "2"], data.path(), proj.path());
    let err = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(2), "stderr: {err}");
    assert!(err.contains("at most one session id"), "got: {err}");
}

#[test]
fn fs_with_no_subcommand_prints_usage() {
    let (data, proj) = (TmpDir::new(), TmpDir::new());
    let out = sbx(&["fs"], data.path(), proj.path());
    let err = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(2), "stderr: {err}");
    assert!(err.contains("sbx fs"), "usage should name `sbx fs`: {err}");
}

#[test]
fn fs_unknown_subcommand_is_an_error() {
    let (data, proj) = (TmpDir::new(), TmpDir::new());
    let out = sbx(&["fs", "bogus"], data.path(), proj.path());
    let err = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(2), "stderr: {err}");
    assert!(err.contains("unknown subcommand"), "got: {err}");
}

/// Read a process's start-time ticks (`/proc/<pid>/stat` field 22) for the fabricated record.
fn read_start_ticks(pid: u32) -> u64 {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).expect("read stat");
    let after = &stat[stat.rfind(')').unwrap() + 1..];
    after.split_whitespace().nth(19).unwrap().parse().unwrap()
}

/// Write the session record `sbx fs logs` resolves, pointing at a live `pid`. A fabricated record (the
/// on-disk format is stable) isolates the property under test — the socket-missing path — from the
/// session-registration machinery, which is exercised elsewhere.
fn write_session_record(data: &Path, pid: u32, project: &Path) {
    use std::os::unix::ffi::OsStrExt;
    let start = read_start_ticks(pid);
    let dir = data.join("sbx").join("sessions");
    std::fs::create_dir_all(&dir).unwrap();
    let hex: String = project
        .as_os_str()
        .as_bytes()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    let rec = format!("kind=run\npid={pid}\nstart={start}\nruntime=project\nproject={hex}\n");
    std::fs::write(dir.join(format!("{pid}-{start}")), rec).unwrap();
}

#[test]
fn fs_logs_reports_an_unobserved_session() {
    // A live session that was NOT launched with observation has no filesystem control socket, so
    // `sbx fs logs` reports it as unobserved (exit 2) rather than showing an empty feed. Fabricate a
    // record pointing at a plain live process (a `sleep`) — no cage, no socket — to isolate the
    // socket-missing path from the launch machinery. No sandbox needed.
    let (data, project) = (TmpDir::new(), TmpDir::new());
    let mut child = Command::new("sleep")
        .arg("30")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn sleep");
    let pid = child.id();
    write_session_record(data.path(), pid, project.path());

    let out = Command::new(env!("CARGO_BIN_EXE_sbx"))
        .args(["fs", "logs", &pid.to_string()])
        .env("XDG_DATA_HOME", data.path())
        .output()
        .expect("run sbx fs logs");
    let _ = child.kill();
    let _ = child.wait();

    let err = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(2), "stderr: {err}");
    assert!(
        err.contains("is not being observed"),
        "an unobserved session should be named as such, not shown empty: {err}"
    );
}

/// A `Command` for the built binary with an isolated global config dir, so the cage-launching e2e
/// never depends on the developer's `~/.config/sbx`.
fn sbx_isolated() -> Command {
    let mut cfg = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    cfg.push("target/test-tmp/fs-isolated-config");
    let _ = std::fs::create_dir_all(&cfg);
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_sbx"));
    cmd.env("XDG_CONFIG_HOME", cfg);
    cmd
}

/// Whether the host can launch a sandbox (also warms the userland cache so the real launch below
/// starts promptly).
fn host_can_sandbox(project: &Path, data: &Path) -> bool {
    sbx_isolated()
        .args(["run", "--", "true"])
        .current_dir(project)
        .env("XDG_DATA_HOME", data)
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Extract the pid from the detached-launch line `sbx: started `run` as detached session <pid> …`.
fn parse_detached_pid(msg: &str) -> Option<u32> {
    let after = msg.split("detached session ").nth(1)?;
    after
        .split(|c: char| !c.is_ascii_digit())
        .find(|s| !s.is_empty())?
        .parse()
        .ok()
}

#[test]
fn detached_observe_records_fs_writes_for_fs_logs() {
    // The load-bearing property of this increment: a DETACHED session — which has no terminal for an
    // inline feed — still records the files it writes in its project tree, readable from a separate
    // process via `sbx fs logs` over the per-session control socket. The cage binds the project
    // read-write at its own host path, so a write the agent makes lands on the same host inode the
    // supervisor's inotify watches — visible across the mount namespace. Launch a detached observed run
    // that writes a recognizable marker into the project, then read the fs ring back and assert the
    // marker appears. This is the ONLY channel a detached session has (no inline feed), and it
    // exercises the whole chain: the synchronous initial inotify watch, force-supervision on the
    // detached path, the fs ring, the bound socket, and the `sbx fs logs` client. Skipped, not failed,
    // where the host cannot sandbox.
    let (project, data) = (TmpDir::new(), TmpDir::new());
    if !host_can_sandbox(project.path(), data.path()) {
        eprintln!("skipping detached fs --observe e2e: host cannot sandbox");
        return;
    }

    // Detached + observed: write a marker into the project (the cage's cwd is the project, bound rw at
    // its own path), then `sleep 30` so the session lives well past our reads.
    let started = sbx_isolated()
        .args([
            "run",
            "--detach",
            "--observe",
            "--",
            "sh",
            "-c",
            "echo hi > marker.txt; sleep 30",
        ])
        .current_dir(project.path())
        .env("XDG_DATA_HOME", data.path())
        .stdin(Stdio::null())
        .output()
        .expect("run --detach --observe");
    let msg = String::from_utf8_lossy(&started.stderr).into_owned();
    assert!(started.status.success(), "detached launch failed:\n{msg}");
    let pid =
        parse_detached_pid(&msg).unwrap_or_else(|| panic!("no detached session pid in:\n{msg}"));

    // Poll `sbx fs logs <pid>` until the marker write appears in the fs ring — read over the socket,
    // the ONLY channel for a detached session. A stunted watcher never converges and the assertion
    // below fires with the last output.
    let deadline = Instant::now() + Duration::from_secs(30);
    let mut last = String::new();
    let mut ok = false;
    while Instant::now() < deadline {
        let out = Command::new(env!("CARGO_BIN_EXE_sbx"))
            .args(["fs", "logs", &pid.to_string()])
            .env("XDG_DATA_HOME", data.path())
            .output()
            .expect("run sbx fs logs");
        last = String::from_utf8_lossy(&out.stdout).into_owned();
        if out.status.code() == Some(0) && last.contains("marker.txt") {
            ok = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(250));
    }

    // Stop the detached session before asserting, so a failure never leaks a background cage.
    let _ = Command::new(env!("CARGO_BIN_EXE_sbx"))
        .args(["session", "stop", &pid.to_string()])
        .env("XDG_DATA_HOME", data.path())
        .output();

    assert!(
        ok,
        "the detached observed session's write to `marker.txt` must appear in `sbx fs logs` (read over \
         the control socket — a detached session has no inline feed). Last output:\n{last}"
    );
}
