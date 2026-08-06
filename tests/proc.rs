//! Integration tests for `sbx proc` — the process-observation CLI wiring: session resolution and the
//! error paths for `ls`/`live`/`logs`, plus cage-backed e2e for the `/proc` walk (`ls`), the inline
//! `--observe` feed (`run`/`app run`), and the detached exec-event ring read over the control socket
//! (`logs`). The pure error paths run against an isolated (empty) data directory (no sandbox); the
//! cage-backed ones skip where the host cannot sandbox.

use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

/// Where this suite's throwaway fixtures live: the repo's own test tree, overridable with
/// `SBX_TEST_TMPDIR`.
///
/// Deliberately **not** `std::env::temp_dir()`, which resolves to `/tmp` when `TMPDIR` is unset. A
/// fixture here holds a provisioned nix store, which is inode-heavy — one run of this suite peaks
/// near a million inodes. `/tmp` is usually a tmpfs whose inode count is capped machine-wide at
/// about that, so a run exhausts it and *unrelated* work then fails with "no space left on device"
/// while the disk is nearly empty. The repo's disk has inodes to spare, it matches production (the
/// store lives on disk), and `cargo clean` reclaims it.
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

struct TmpDir(PathBuf);

impl TmpDir {
    fn new() -> Self {
        static N: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
        let n = N.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let mut d = fixture_root();
        d.push(format!("p-{}-{n}", std::process::id()));
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
fn proc_logs_with_no_sessions_reports_none_and_exits_2() {
    let (data, proj) = (TmpDir::new(), TmpDir::new());
    let out = sbx(&["proc", "logs"], data.path(), proj.path());
    let err = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(2), "stderr: {err}");
    assert!(err.contains("no active sandbox sessions"), "got: {err}");
}

#[test]
fn proc_logs_rejects_a_second_id() {
    let (data, proj) = (TmpDir::new(), TmpDir::new());
    let out = sbx(&["proc", "logs", "1", "2"], data.path(), proj.path());
    let err = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(2), "stderr: {err}");
    assert!(err.contains("at most one session id"), "got: {err}");
}

#[test]
fn proc_logs_reports_an_unobserved_session() {
    // A live session that was NOT launched with observation has no control socket, so `proc logs`
    // reports it as unobserved (exit 2) rather than showing an empty feed. Fabricate a record
    // pointing at a plain live process (a `sleep`) — no cage, no socket — to isolate the
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
        .args(["proc", "logs", &pid.to_string()])
        .env("XDG_DATA_HOME", data.path())
        .output()
        .expect("run sbx proc logs");
    let _ = child.kill();
    let _ = child.wait();

    let err = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(2), "stderr: {err}");
    assert!(
        err.contains("is not being observed"),
        "an unobserved session should be named as such, not shown empty: {err}"
    );
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
fn detached_observe_records_exec_events_for_proc_logs() {
    // The load-bearing property of this increment: a DETACHED session — which has no terminal for an
    // inline feed — still records exec events, readable from a separate process via `sbx proc logs`
    // over the per-session control socket. Launch a detached observed run that spawns a recognizable
    // child, then read its ring back and assert the child appears. This exercises the whole chain the
    // inline `--observe` feed cannot cover: force-supervision on the detached path, the ring, the
    // bound socket, and the `sbx proc logs` client. Skipped, not failed, where the host cannot
    // sandbox.
    let (project, data) = (TmpDir::new(), TmpDir::new());
    if !host_can_sandbox(project.path(), data.path()) {
        eprintln!("skipping detached --observe e2e: host cannot sandbox");
        return;
    }

    // Detached + observed: spawns `sleep 30`, which lives well past the poll tick and our reads.
    let started = sbx_isolated()
        .args(["run", "--detach", "--observe", "--", "sh", "-c", "sleep 30"])
        .current_dir(project.path())
        .env("XDG_DATA_HOME", data.path())
        .stdin(Stdio::null())
        .output()
        .expect("run --detach --observe");
    let msg = String::from_utf8_lossy(&started.stderr).into_owned();
    assert!(started.status.success(), "detached launch failed:\n{msg}");
    let pid =
        parse_detached_pid(&msg).unwrap_or_else(|| panic!("no detached session pid in:\n{msg}"));

    // Poll `sbx proc logs <pid>` until the spawned `sleep` appears in the ring — read over the socket,
    // the ONLY channel for a detached session. A stunted observer never converges and the assertion
    // below fires with the last output.
    let deadline = Instant::now() + Duration::from_secs(30);
    let mut last = String::new();
    let mut ok = false;
    while Instant::now() < deadline {
        let out = Command::new(env!("CARGO_BIN_EXE_sbx"))
            .args(["proc", "logs", &pid.to_string()])
            .env("XDG_DATA_HOME", data.path())
            .output()
            .expect("run sbx proc logs");
        last = String::from_utf8_lossy(&out.stdout).into_owned();
        if out.status.code() == Some(0) && last.contains("sleep") {
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
        "the detached observed session's spawned `sleep` must appear in `sbx proc logs` (read over \
         the control socket — a detached session has no inline feed). Last output:\n{last}"
    );
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

#[test]
fn run_observe_streams_exec_events() {
    // `sbx run --observe` forces the supervised path and streams a `[sbx:exec]` line to stderr for
    // each process the command spawns. Teeth: the same run WITHOUT `--observe` (the exec-replace
    // path, no observer) emits no feed. Non-interactive (stdin null) so it takes the foreground
    // path, not the pty one. Skipped, not failed, where the host cannot sandbox.
    let (project, data) = (TmpDir::new(), TmpDir::new());
    if !host_can_sandbox(project.path(), data.path()) {
        eprintln!("skipping run --observe e2e: host cannot sandbox");
        return;
    }

    // A command that spawns a recognizable child living well past the ~300ms poll tick.
    let observed = sbx_isolated()
        .args(["run", "--observe", "--", "sh", "-c", "sleep 1"])
        .current_dir(project.path())
        .env("XDG_DATA_HOME", data.path())
        .stdin(Stdio::null())
        .output()
        .expect("run --observe");
    let err = String::from_utf8_lossy(&observed.stderr);
    assert!(
        err.contains("[sbx:exec]"),
        "the observe feed is missing from stderr:\n{err}"
    );
    assert!(
        err.contains("sleep"),
        "the spawned `sleep` should appear in the feed:\n{err}"
    );

    // Teeth: no `--observe`, no feed.
    let plain = sbx_isolated()
        .args(["run", "--", "sh", "-c", "sleep 1"])
        .current_dir(project.path())
        .env("XDG_DATA_HOME", data.path())
        .stdin(Stdio::null())
        .output()
        .expect("run");
    let err2 = String::from_utf8_lossy(&plain.stderr);
    assert!(
        !err2.contains("[sbx:exec]"),
        "a run without --observe must emit no feed:\n{err2}"
    );
}

#[test]
fn enforce_blocks_a_denied_binary_in_a_real_cage() {
    // The headline of the enforcement increment: `[proc] mode = "enforce"` blocks a denied exec
    // target *before the syscall runs*, in a real cage, via the seccomp user-notification shim +
    // supervisor. A trusted project denies `id`; the allowed `echo` runs, but `id` is refused with
    // EPERM and never produces its output. `[proc]` is security-gated, so the project must be trusted
    // (an untrusted config drops it — proven separately). Skipped, not failed, where the host cannot
    // sandbox; once it can, a denied `id` that still runs is a real enforcement failure.
    let (project, data) = (TmpDir::new(), TmpDir::new());
    std::fs::write(
        project.path().join(".sbx.toml"),
        "[proc]\nmode = \"enforce\"\ndeny = [\"id\"]\n",
    )
    .unwrap();
    if !host_can_sandbox(project.path(), data.path()) {
        eprintln!("skipping proc enforce e2e: host cannot sandbox");
        return;
    }

    // Trust the project so the security-gated `[proc]` applies; isolate the trust state alongside the
    // data dir so the run below reads the same marker.
    let trusted = sbx_isolated()
        .args(["trust"])
        .current_dir(project.path())
        .env("XDG_DATA_HOME", data.path())
        .env("XDG_STATE_HOME", data.path())
        .output()
        .expect("sbx trust");
    assert!(
        trusted.status.success(),
        "trust failed: {}",
        String::from_utf8_lossy(&trusted.stderr)
    );

    // Allowed: `echo` is not denied, so it runs and prints.
    let allowed = sbx_isolated()
        .args(["run", "--", "echo", "ENFORCE-OK"])
        .current_dir(project.path())
        .env("XDG_DATA_HOME", data.path())
        .env("XDG_STATE_HOME", data.path())
        .stdin(Stdio::null())
        .output()
        .expect("run echo");
    assert!(
        String::from_utf8_lossy(&allowed.stdout).contains("ENFORCE-OK"),
        "an allowed command must run under enforce; stderr:\n{}",
        String::from_utf8_lossy(&allowed.stderr)
    );

    // Denied: `id` traps to the supervisor, is refused with EPERM (the syscall never runs), so the
    // command fails and its real output (`uid=…`) never appears.
    let denied = sbx_isolated()
        .args(["run", "--", "id"])
        .current_dir(project.path())
        .env("XDG_DATA_HOME", data.path())
        .env("XDG_STATE_HOME", data.path())
        .stdin(Stdio::null())
        .output()
        .expect("run id");
    let out = String::from_utf8_lossy(&denied.stdout);
    let err = String::from_utf8_lossy(&denied.stderr);
    assert!(
        !denied.status.success(),
        "the denied `id` must fail (blocked): stdout={out:?} stderr={err:?}"
    );
    assert!(
        !out.contains("uid="),
        "the denied `id` must never run — its output leaked: {out:?}"
    );
    assert!(
        err.contains("Operation not permitted") || err.contains("cannot execute id"),
        "the block should surface a reason: {err:?}"
    );
}

#[test]
fn an_override_config_proc_enforces_without_trusting_the_project() {
    // The un-ignoring of an override's `[proc]`: a one-shot `--config` blob is trusted *by
    // invocation*, so its `[proc] mode = "enforce"` blocks a denied exec in a real cage **without any
    // `sbx trust`** — the invoker outranks the config layer. Teeth: the control run (no override) runs
    // `id` (it prints `uid=…`), so the block appears *only* because the override reached the cage.
    // Skipped, not failed, where the host cannot sandbox.
    let (project, data) = (TmpDir::new(), TmpDir::new());
    if !host_can_sandbox(project.path(), data.path()) {
        eprintln!("skipping override-proc enforce e2e: host cannot sandbox");
        return;
    }

    // Control: no override, no project `[proc]` → `id` runs and prints its uid.
    let control = sbx_isolated()
        .args(["run", "--", "id"])
        .current_dir(project.path())
        .env("XDG_DATA_HOME", data.path())
        .env("XDG_STATE_HOME", data.path())
        .stdin(Stdio::null())
        .output()
        .expect("run id");
    assert!(
        String::from_utf8_lossy(&control.stdout).contains("uid="),
        "the control `id` must run (no enforcement); stderr:\n{}",
        String::from_utf8_lossy(&control.stderr)
    );

    // Override: a `--config` blob enforces a deny of `id`, with the project untrusted (never
    // `sbx trust`ed) — trusted by invocation. `id` traps to the supervisor and is refused with EPERM.
    let denied = sbx_isolated()
        .args([
            "run",
            "--config",
            "[proc]\nmode = \"enforce\"\ndeny = [\"id\"]\n",
            "--",
            "id",
        ])
        .current_dir(project.path())
        .env("XDG_DATA_HOME", data.path())
        .env("XDG_STATE_HOME", data.path())
        .stdin(Stdio::null())
        .output()
        .expect("run id under override");
    let out = String::from_utf8_lossy(&denied.stdout);
    let err = String::from_utf8_lossy(&denied.stderr);
    assert!(
        !denied.status.success() && !out.contains("uid="),
        "the override must block `id` without trust: stdout={out:?} stderr={err:?}"
    );
    assert!(
        err.contains("Operation not permitted") || err.contains("cannot execute id"),
        "the block should surface a reason: {err:?}"
    );
}

#[test]
fn a_typed_proc_off_override_disables_a_trusted_projects_enforcement() {
    // The typed `--proc` flag, threaded end-to-end with real teeth in the *disable* direction: an
    // invoker may turn off a trusted project's `enforce` for one launch (top authority by invocation,
    // the parity with `--gpu=false`). A trusted project denies `id`; the baseline run blocks it, but
    // `--proc off` lets it run — proving the typed flag reached the cage. Skipped, not failed, where
    // the host cannot sandbox.
    let (project, data) = (TmpDir::new(), TmpDir::new());
    std::fs::write(
        project.path().join(".sbx.toml"),
        "[proc]\nmode = \"enforce\"\ndeny = [\"id\"]\n",
    )
    .unwrap();
    if !host_can_sandbox(project.path(), data.path()) {
        eprintln!("skipping typed-proc-off e2e: host cannot sandbox");
        return;
    }
    let trusted = sbx_isolated()
        .args(["trust"])
        .current_dir(project.path())
        .env("XDG_DATA_HOME", data.path())
        .env("XDG_STATE_HOME", data.path())
        .output()
        .expect("sbx trust");
    assert!(
        trusted.status.success(),
        "trust failed: {}",
        String::from_utf8_lossy(&trusted.stderr)
    );

    // Baseline: the trusted `enforce` blocks `id`.
    let blocked = sbx_isolated()
        .args(["run", "--", "id"])
        .current_dir(project.path())
        .env("XDG_DATA_HOME", data.path())
        .env("XDG_STATE_HOME", data.path())
        .stdin(Stdio::null())
        .output()
        .expect("run id");
    assert!(
        !blocked.status.success() && !String::from_utf8_lossy(&blocked.stdout).contains("uid="),
        "the trusted enforce must block `id`; stderr:\n{}",
        String::from_utf8_lossy(&blocked.stderr)
    );

    // `--proc off` disables enforcement for this one launch → `id` runs and prints its uid.
    let re_enabled = sbx_isolated()
        .args(["run", "--proc", "off", "--", "id"])
        .current_dir(project.path())
        .env("XDG_DATA_HOME", data.path())
        .env("XDG_STATE_HOME", data.path())
        .stdin(Stdio::null())
        .output()
        .expect("run id under --proc off");
    assert!(
        String::from_utf8_lossy(&re_enabled.stdout).contains("uid="),
        "`--proc off` must disable the trusted enforcement so `id` runs; stderr:\n{}",
        String::from_utf8_lossy(&re_enabled.stderr)
    );
}

#[test]
fn app_run_observe_streams_exec_events() {
    // The feed reaches the primary target — agents launched via `sbx app run`. `--observe` threads
    // through the app path the same way, forcing supervision and streaming `[sbx:exec]`. Teeth: the
    // same app run without `--observe` emits no feed. Skipped, not failed, where the host cannot
    // sandbox.
    let (project, data) = (TmpDir::new(), TmpDir::new());
    std::fs::write(
        project.path().join(".sbx.toml"),
        "[app.probe]\ncmd = [\"sh\", \"-c\", \"sleep 1\"]\n",
    )
    .unwrap();
    if !host_can_sandbox(project.path(), data.path()) {
        eprintln!("skipping app run --observe e2e: host cannot sandbox");
        return;
    }

    let observed = sbx_isolated()
        .args(["app", "run", "--observe", "probe"])
        .current_dir(project.path())
        .env("XDG_DATA_HOME", data.path())
        .stdin(Stdio::null())
        .output()
        .expect("app run --observe");
    let err = String::from_utf8_lossy(&observed.stderr);
    assert!(
        err.contains("[sbx:exec]") && err.contains("sleep"),
        "the app's spawned `sleep` should appear in the feed:\n{err}"
    );

    // Teeth: no `--observe`, no feed.
    let plain = sbx_isolated()
        .args(["app", "run", "probe"])
        .current_dir(project.path())
        .env("XDG_DATA_HOME", data.path())
        .stdin(Stdio::null())
        .output()
        .expect("app run");
    assert!(
        !String::from_utf8_lossy(&plain.stderr).contains("[sbx:exec]"),
        "an app run without --observe must emit no feed"
    );
}

/// Run `sbx <args>` for a `[proc]` config-write test: cwd = `proj`, with an isolated trust store,
/// global config, and data dir, so `sbx proc allow|deny` writes and re-trusts against redirected
/// dirs (never the developer's real home). Read-only and host-side: no launch, no nix.
fn sbx_config_write(
    args: &[&str],
    proj: &Path,
    state: &Path,
    config: &Path,
    data: &Path,
) -> Output {
    Command::new(env!("CARGO_BIN_EXE_sbx"))
        .args(args)
        .current_dir(proj)
        .env("XDG_STATE_HOME", state)
        .env("XDG_CONFIG_HOME", config)
        .env("XDG_DATA_HOME", data)
        .output()
        .expect("spawn sbx")
}

#[test]
fn proc_deny_bootstraps_enforce_writes_the_config_and_retrusts() {
    let (proj, state, config, data) = (TmpDir::new(), TmpDir::new(), TmpDir::new(), TmpDir::new());
    let out = sbx_config_write(
        &["proc", "deny", "curl"],
        proj.path(),
        state.path(),
        config.path(),
        data.path(),
    );
    let err = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(0), "stderr: {err}");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("enforce"), "stdout: {stdout}");
    assert!(stdout.contains("re-trusted"), "must re-trust: {stdout}");
    let body = std::fs::read_to_string(proj.path().join(".sbx.toml")).unwrap();
    assert!(body.contains("mode = \"enforce\""), "{body}");
    assert!(body.contains("deny = [\"curl\"]"), "{body}");
    // A second deny appends against the now-trusted config (the trust pre-check must pass).
    let again = sbx_config_write(
        &["proc", "deny", "ssh"],
        proj.path(),
        state.path(),
        config.path(),
        data.path(),
    );
    assert_eq!(again.status.code(), Some(0), "second deny should append");
    let body = std::fs::read_to_string(proj.path().join(".sbx.toml")).unwrap();
    assert!(
        body.contains("\"curl\"") && body.contains("\"ssh\""),
        "{body}"
    );
}

/// The `--local` trust gate covers the proc plane exactly as it covers egress: a pre-existing,
/// never-trusted project config must not be blessed by an appended rule -- the user reviews and
/// trusts it first. Nothing exercised this on the proc side, and the gate is one shared admission
/// now, so this also pins that `sbx proc deny` really goes through it.
#[test]
fn proc_deny_refuses_an_untrusted_existing_project() {
    let (proj, state, config, data) = (TmpDir::new(), TmpDir::new(), TmpDir::new(), TmpDir::new());
    std::fs::write(
        proj.path().join(".sbx.toml"),
        "[proc]\nmode = \"enforce\"\ndeny = [\"ssh\"]\n",
    )
    .unwrap();
    let out = sbx_config_write(
        &["proc", "deny", "curl"],
        proj.path(),
        state.path(),
        config.path(),
        data.path(),
    );
    assert_eq!(out.status.code(), Some(2));
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        err.contains("not trusted") && err.contains("sbx trust"),
        "an untrusted existing config must be refused, pointing at `sbx trust`:\n{err}"
    );
    let body = std::fs::read_to_string(proj.path().join(".sbx.toml")).unwrap();
    assert!(
        !body.contains("curl"),
        "a refused write must not touch the file:\n{body}"
    );
}

#[test]
fn proc_allow_with_no_posture_is_refused_and_writes_nothing() {
    let (proj, state, config, data) = (TmpDir::new(), TmpDir::new(), TmpDir::new(), TmpDir::new());
    let out = sbx_config_write(
        &["proc", "allow", "git"],
        proj.path(),
        state.path(),
        config.path(),
        data.path(),
    );
    let err = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(2), "stderr: {err}");
    assert!(err.contains("ask"), "should point at mode=ask: {err}");
    assert!(
        !proj.path().join(".sbx.toml").exists(),
        "a refused allow must write no config"
    );
}

#[test]
fn proc_deny_session_with_a_config_scope_flag_is_refused() {
    // `--session` writes no file, so a file-scope flag does not apply — refuse rather than silently
    // ignore it (mirrors `sbx net`). No launch needed.
    let (proj, state, config, data) = (TmpDir::new(), TmpDir::new(), TmpDir::new(), TmpDir::new());
    let out = sbx_config_write(
        &["proc", "deny", "curl", "--session", "--local"],
        proj.path(),
        state.path(),
        config.path(),
        data.path(),
    );
    let err = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(2), "stderr: {err}");
    assert!(
        err.contains("--session"),
        "should explain the flag clash: {err}"
    );
}

#[test]
fn proc_deny_session_with_no_live_session_is_reported() {
    // With no enforcing session in scope, a `--session` load has nothing to reach — exit 1 with a
    // pointer to launching one or writing config. Deterministic (empty data dir → empty registry).
    let (proj, state, config, data) = (TmpDir::new(), TmpDir::new(), TmpDir::new(), TmpDir::new());
    let out = sbx_config_write(
        &["proc", "deny", "curl", "--session"],
        proj.path(),
        state.path(),
        config.path(),
        data.path(),
    );
    let err = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(1), "stderr: {err}");
    assert!(
        err.contains("no enforcing session in scope"),
        "should report no session: {err}"
    );
}

#[test]
fn deny_session_loads_a_rule_into_a_running_enforcing_cage() {
    // The `--session` headline: a rule injected through the real binary reaches a *running* enforcing
    // cage's live overlay. A trusted `[proc] mode = "enforce"` detached cage stays alive; injecting a
    // `--session deny` must load into that one session. The decide-reflects-the-overlay property is
    // unit-tested; this proves the CLI → session enumeration → proc control socket → overlay chain
    // end to end. Skipped, not failed, where the host cannot sandbox.
    let (project, data) = (TmpDir::new(), TmpDir::new());
    std::fs::write(
        project.path().join(".sbx.toml"),
        "[proc]\nmode = \"enforce\"\n",
    )
    .unwrap();
    if !host_can_sandbox(project.path(), data.path()) {
        eprintln!("skipping proc --session e2e: host cannot sandbox");
        return;
    }
    let trusted = sbx_isolated()
        .args(["trust"])
        .current_dir(project.path())
        .env("XDG_DATA_HOME", data.path())
        .env("XDG_STATE_HOME", data.path())
        .output()
        .expect("sbx trust");
    assert!(
        trusted.status.success(),
        "trust failed: {}",
        String::from_utf8_lossy(&trusted.stderr)
    );

    // A long-running detached enforce cage: it registers a session and binds its proc control socket.
    let launched = sbx_isolated()
        .args(["run", "--detach", "--", "sleep", "30"])
        .current_dir(project.path())
        .env("XDG_DATA_HOME", data.path())
        .env("XDG_STATE_HOME", data.path())
        .stdin(Stdio::null())
        .output()
        .expect("detached run");
    assert!(
        launched.status.success(),
        "detach failed: {}",
        String::from_utf8_lossy(&launched.stderr)
    );

    // Inject a `--session deny`; poll briefly for the session to be reachable (the socket binds before
    // the detach returns, but allow for scheduling slack).
    let mut loaded = false;
    let mut last = String::new();
    for _ in 0..10 {
        let injected = sbx_isolated()
            .args(["proc", "deny", "curl", "--session"])
            .current_dir(project.path())
            .env("XDG_DATA_HOME", data.path())
            .env("XDG_STATE_HOME", data.path())
            .output()
            .expect("inject");
        last = format!(
            "stdout={} stderr={}",
            String::from_utf8_lossy(&injected.stdout),
            String::from_utf8_lossy(&injected.stderr)
        );
        if injected.status.success()
            && String::from_utf8_lossy(&injected.stdout).contains("loaded deny rule `curl` into 1")
        {
            loaded = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(300));
    }

    // Best-effort teardown before asserting, so a failure does not leave the cage running.
    let _ = sbx_isolated()
        .args(["session", "stop", "--all"])
        .current_dir(project.path())
        .env("XDG_DATA_HOME", data.path())
        .env("XDG_STATE_HOME", data.path())
        .output();

    assert!(
        loaded,
        "the --session deny did not load into the live cage: {last}"
    );
}
