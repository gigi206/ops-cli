//! Integration tests for `sbx proc ls` — the process-tree snapshot's CLI wiring: session
//! resolution and the error paths, exercised through the built binary against an isolated (empty)
//! data directory. No sandbox, no nix, no network — the registry read is all this slice needs.

use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

struct TmpDir(PathBuf);

impl TmpDir {
    fn new() -> Self {
        static N: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
        let n = N.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let mut d = std::env::temp_dir();
        d.push(format!("sbx-proc-{}-{n}", std::process::id()));
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

/// Run `sbx <args>` with an isolated, empty data directory so the session registry is empty and
/// the outcome is deterministic regardless of the host's real sessions.
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
fn proc_ls_with_no_sessions_reports_none_and_exits_2() {
    let (data, proj) = (TmpDir::new(), TmpDir::new());
    let out = sbx(&["proc", "ls"], data.path(), proj.path());
    let err = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(2), "stderr: {err}");
    assert!(err.contains("no active sandbox sessions"), "got: {err}");
}

#[test]
fn proc_ls_unknown_pid_is_a_pointed_error() {
    let (data, proj) = (TmpDir::new(), TmpDir::new());
    // A pid above the kernel ceiling cannot name a live session.
    let out = sbx(&["proc", "ls", "4294967295"], data.path(), proj.path());
    let err = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(2), "stderr: {err}");
    assert!(err.contains("no live session '4294967295'"), "got: {err}");
    assert!(
        err.contains("sbx session ls"),
        "should point at the lister: {err}"
    );
}

#[test]
fn proc_ls_rejects_a_second_id() {
    let (data, proj) = (TmpDir::new(), TmpDir::new());
    let out = sbx(&["proc", "ls", "1", "2"], data.path(), proj.path());
    let err = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(2), "stderr: {err}");
    assert!(err.contains("at most one session id"), "got: {err}");
}

#[test]
fn proc_with_no_subcommand_prints_usage() {
    let (data, proj) = (TmpDir::new(), TmpDir::new());
    let out = sbx(&["proc"], data.path(), proj.path());
    let err = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(2), "stderr: {err}");
    assert!(
        err.contains("sbx proc"),
        "usage should name `sbx proc`: {err}"
    );
}

#[test]
fn proc_unknown_subcommand_is_an_error() {
    let (data, proj) = (TmpDir::new(), TmpDir::new());
    let out = sbx(&["proc", "bogus"], data.path(), proj.path());
    let err = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(2), "stderr: {err}");
    assert!(err.contains("unknown subcommand"), "got: {err}");
}

#[test]
fn proc_live_needs_a_terminal_without_json() {
    // Captured stdout is a pipe, not a tty, so the human redraw is refused with a pointer to --json.
    let (data, proj) = (TmpDir::new(), TmpDir::new());
    let out = sbx(&["proc", "live"], data.path(), proj.path());
    let err = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(2), "stderr: {err}");
    assert!(err.contains("needs a terminal"), "got: {err}");
}

#[test]
fn proc_live_json_with_no_session_exits_2() {
    let (data, proj) = (TmpDir::new(), TmpDir::new());
    let out = sbx(&["proc", "live", "--json"], data.path(), proj.path());
    let err = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(2), "stderr: {err}");
    assert!(err.contains("no active sandbox sessions"), "got: {err}");
}

#[test]
fn proc_live_rejects_a_zero_interval() {
    // The interval is parsed before anything else, so a zero busy-loop is refused up front.
    let (data, proj) = (TmpDir::new(), TmpDir::new());
    let out = sbx(
        &["proc", "live", "--json", "-i", "0"],
        data.path(),
        proj.path(),
    );
    let err = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(2), "stderr: {err}");
    assert!(err.contains("at least 1 second"), "got: {err}");
}

/// A `Command` for the built binary with an isolated global config dir, so the cage-launching e2e
/// never depends on the developer's `~/.config/sbx`.
fn sbx_isolated() -> Command {
    let mut cfg = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    cfg.push("target/test-tmp/proc-isolated-config");
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

/// Read a process's start-time ticks (`/proc/<pid>/stat` field 22) for the fabricated record.
fn read_start_ticks(pid: u32) -> u64 {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).expect("read stat");
    let after = &stat[stat.rfind(')').unwrap() + 1..];
    after.split_whitespace().nth(19).unwrap().parse().unwrap()
}

/// Write the session record `proc ls` resolves, pointing at a live cage's `pid`. Using a fabricated
/// record (the on-disk format is stable) isolates the property under test — the `/proc` descendant
/// walk across the cage boundary — from the session-registration machinery, which is exercised
/// elsewhere.
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
fn proc_ls_shows_a_real_cage_process_tree() {
    // The load-bearing property: the `/proc` descendant walk from the recorded session pid reaches
    // the cage's processes ACROSS the pid namespace and the transient systemd scope. Launch a real
    // cage running `sleep` (the exec chain is sbx -> systemd-run --scope -> bwrap -> sleep, and
    // `sleep` is a descendant of the recorded pid in host pid-space), give it a fabricated session
    // record, and assert `sbx proc ls` shows the cage's `sleep`. Teeth: a stunted walk — e.g. if the
    // scope reparented the cage away from the recorded pid — would not contain `sleep`. Skipped, not
    // failed, where the host cannot sandbox; but once `host_can_sandbox` proves it can, a missing
    // `sleep` is a real failure of the walk, not a skip.
    let (project, data) = (TmpDir::new(), TmpDir::new());
    if !host_can_sandbox(project.path(), data.path()) {
        eprintln!(
            "skipping proc-ls cage e2e: host cannot sandbox (no userns/bwrap, or the base cache is unreachable)"
        );
        return;
    }

    let mut cage = sbx_isolated()
        .args(["run", "--", "sleep", "300"])
        .current_dir(project.path())
        .env("XDG_DATA_HOME", data.path())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn sbx run -- sleep");
    let pid = cage.id();
    write_session_record(data.path(), pid, project.path());

    // Poll `sbx proc ls` until the cage has exec-chained into `sleep` (host `/proc` reflects it once
    // bubblewrap starts it), then assert. `proc ls` re-reads `/proc` each call, so a broken walk
    // never converges and the assertion below fires with the last output.
    let deadline = Instant::now() + Duration::from_secs(30);
    let mut last = String::new();
    let mut ok = false;
    while Instant::now() < deadline {
        let out = Command::new(env!("CARGO_BIN_EXE_sbx"))
            .args(["proc", "ls", &pid.to_string()])
            .env("XDG_DATA_HOME", data.path())
            .output()
            .expect("run sbx proc ls");
        last = String::from_utf8_lossy(&out.stdout).into_owned();
        if out.status.code() == Some(0) && last.contains("sleep") {
            ok = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(250));
    }

    let _ = cage.kill();
    let _ = cage.wait();

    assert!(
        ok,
        "the cage's `sleep` must appear in `sbx proc ls` — a stunted walk across the pid-ns/scope \
         boundary would miss it. Last output:\n{last}"
    );
}
