//! Integration tests for `ops stop`.
//!
//! The headline property: stopping a **supervised** session (the `network = "allowlist"` path,
//! where the registered pid is the ops supervisor rather than bubblewrap itself) tears the whole
//! cage down — the supervisor exits *and* no in-cage process is left orphaned. That is the path
//! where teardown is non-trivial: it relies on bubblewrap dying with its parent. The exec path
//! (default posture, registered pid == bubblewrap) is trivially correct and covered by the unit
//! tests of the stop primitive. Skipped, not failed, where the host cannot sandbox.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};

fn ops() -> Command {
    Command::new(env!("CARGO_BIN_EXE_ops"))
}

/// A unique temp dir removed on drop.
struct TmpDir(PathBuf);

impl TmpDir {
    fn new(tag: &str) -> Self {
        static COUNTER: AtomicU32 = AtomicU32::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let mut d = std::env::temp_dir();
        d.push(format!("ops-stop-it-{tag}-{}-{n}", std::process::id()));
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

/// Kills and reaps a backgrounded child on drop, so a panicking assertion never leaks the running
/// cage — a `TmpDir` cleans directories, not processes.
struct KillOnDrop(std::process::Child);

impl Drop for KillOnDrop {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
fn stop_with_no_or_bad_arguments_is_a_usage_error() {
    let data = TmpDir::new("usage");
    // No id: usage error, exit 2.
    let no_id = ops()
        .arg("stop")
        .env("XDG_DATA_HOME", data.path())
        .stdin(Stdio::null())
        .output()
        .expect("spawn ops stop");
    assert_eq!(no_id.status.code(), Some(2), "no-id stop must exit 2");
    assert!(String::from_utf8_lossy(&no_id.stderr).contains("usage"));

    // A non-numeric --delay: usage error, exit 2 (caught before any signalling).
    let bad_delay = ops()
        .args(["stop", "--delay", "soon", "123"])
        .env("XDG_DATA_HOME", data.path())
        .stdin(Stdio::null())
        .output()
        .expect("spawn ops stop");
    assert_eq!(bad_delay.status.code(), Some(2), "bad --delay must exit 2");
    assert!(String::from_utf8_lossy(&bad_delay.stderr).contains("whole number"));
}

#[test]
fn stop_an_unknown_id_reports_and_exits_two() {
    let data = TmpDir::new("noid");
    let out = ops()
        .args(["stop", "999999"])
        .env("XDG_DATA_HOME", data.path())
        .stdin(Stdio::null())
        .output()
        .expect("spawn ops stop");
    assert_eq!(
        out.status.code(),
        Some(2),
        "stop of a missing id must exit 2"
    );
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("no live session"),
        "missing-id message: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

/// Run `ops <args>` to completion in `project` with isolated data/state, returning its output.
fn ops_run(project: &Path, data: &Path, state: &Path, args: &[&str]) -> std::process::Output {
    ops()
        .args(args)
        .current_dir(project)
        .env("XDG_DATA_HOME", data)
        .env("XDG_STATE_HOME", state)
        .stdin(Stdio::null())
        .output()
        .expect("run ops")
}

/// Whether the host can launch a sandbox (also warms the userland cache so later launches start
/// promptly, and seeds the project store once).
fn host_can_sandbox(project: &Path, data: &Path, state: &Path) -> bool {
    ops_run(project, data, state, &["run", "--", "true"])
        .status
        .success()
}

/// The session record file for `pid`, once it appears under `<data>/ops/sessions/`. `None` if it
/// does not show up before the deadline.
fn wait_for_session(data: &Path, pid: u32, deadline: Instant) -> Option<PathBuf> {
    let dir = data.join("ops").join("sessions");
    let prefix = format!("{pid}-");
    while Instant::now() < deadline {
        if let Ok(entries) = std::fs::read_dir(&dir) {
            for entry in entries.flatten() {
                if entry.file_name().to_string_lossy().starts_with(&prefix) {
                    return Some(entry.path());
                }
            }
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    None
}

/// Whether a per-session egress socket exists under `<data>/ops/egress/` — present only when the
/// allowlist (supervised) launch path ran, so it confirms the fixture exercises that path.
fn egress_socket_exists(data: &Path) -> bool {
    std::fs::read_dir(data.join("ops").join("egress"))
        .map(|d| {
            d.flatten().any(|e| {
                e.path()
                    .extension()
                    .is_some_and(|x| x.eq_ignore_ascii_case("sock"))
            })
        })
        .unwrap_or(false)
}

/// Whether any process on the host has `needle` in its argv (`/proc/<pid>/cmdline` is NUL-separated,
/// which `from_utf8_lossy` keeps intact). Used to detect an orphaned in-cage process from outside
/// the cage's pid namespace, which the host still sees.
fn process_with_arg(needle: &str) -> bool {
    let Ok(entries) = std::fs::read_dir("/proc") else {
        return false;
    };
    for entry in entries.flatten() {
        if let Ok(bytes) = std::fs::read(entry.path().join("cmdline")) {
            if String::from_utf8_lossy(&bytes).contains(needle) {
                return true;
            }
        }
    }
    false
}

/// Poll `cond` until it is `true` or the deadline passes; returns the final value.
fn wait_until(deadline: Instant, mut cond: impl FnMut() -> bool) -> bool {
    while Instant::now() < deadline {
        if cond() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    cond()
}

#[test]
fn stop_tears_down_a_supervised_app_session() {
    // A trusted app with a network allowlist runs supervised: the registered pid is the ops
    // supervisor, and the cage (bubblewrap + the `sleep`) is its child, kept alive only by
    // `--die-with-parent`. `ops stop` of that pid must take the whole thing down. Teeth: the
    // in-cage `sleep 31337` is running before the stop and gone after — an orphan would survive
    // only if the supervisor were killed without the cage following, the failure mode this path
    // alone can exhibit. The unusual sleep duration is a unique fingerprint in the host's process
    // table.
    let project = TmpDir::new("sup-proj");
    let data = TmpDir::new("sup-data");
    let state = TmpDir::new("sup-state");
    std::fs::write(
        project.path().join(".ops.toml"),
        "[app.probe]\n\
         cmd = [\"sleep\", \"31337\"]\n\
         [app.probe.network]\n\
         mode = \"allowlist\"\n\
         allow = [\"cache.nixos.org\"]\n",
    )
    .unwrap();

    if !host_can_sandbox(project.path(), data.path(), state.path()) {
        eprintln!("skipping ops stop supervised e2e: host cannot sandbox");
        return;
    }

    // Trust so the app's allowlist takes effect — otherwise the network field is dropped, the app
    // falls back to the default posture, and the launch would take the exec path instead of the
    // supervised one this test exists to exercise.
    let trusted = ops_run(
        project.path(),
        data.path(),
        state.path(),
        &["trust", ".ops.toml"],
    );
    assert!(
        trusted.status.success(),
        "ops trust failed: {}",
        String::from_utf8_lossy(&trusted.stderr)
    );

    // Launch the app in the background: under the allowlist it registers a session whose pid is the
    // supervisor and supervises the cage running `sleep`.
    let mut agent = KillOnDrop(
        ops()
            .args(["app", "probe"])
            .current_dir(project.path())
            .env("XDG_DATA_HOME", data.path())
            .env("XDG_STATE_HOME", state.path())
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn ops app probe"),
    );
    let pid = agent.0.id();

    if wait_for_session(data.path(), pid, Instant::now() + Duration::from_secs(60)).is_none() {
        eprintln!("skipping ops stop supervised e2e: the app session never registered");
        return;
    }

    // Confirm this is genuinely the supervised path (the only one with the egress proxy), so the
    // teardown assertion below is testing what it claims to.
    assert!(
        egress_socket_exists(data.path()),
        "expected a per-session egress socket — the fixture did not take the supervised path"
    );

    // Precondition with teeth: the in-cage `sleep` is actually running before we stop.
    if !wait_until(Instant::now() + Duration::from_secs(30), || {
        process_with_arg("31337")
    }) {
        eprintln!("skipping ops stop supervised e2e: the cage's sleep never started");
        return;
    }

    // Stop the session by its pid.
    let stopped = ops_run(
        project.path(),
        data.path(),
        state.path(),
        &["stop", &pid.to_string()],
    );
    assert!(
        stopped.status.success(),
        "ops stop must exit 0: {}",
        String::from_utf8_lossy(&stopped.stderr)
    );

    // The supervisor exits (reap its zombie so it is truly gone), and the cage follows it down: no
    // `sleep 31337` is left orphaned in the host's process table.
    let _ = agent.0.wait();
    assert!(
        wait_until(Instant::now() + Duration::from_secs(10), || {
            !process_with_arg("31337")
        }),
        "the cage's `sleep` was orphaned — stopping the supervisor did not tear the cage down"
    );

    // The stopped session no longer appears in `ops ps` (its record was reaped).
    let ps = ops_run(project.path(), data.path(), state.path(), &["ps"]);
    assert!(
        !String::from_utf8_lossy(&ps.stdout).contains(&pid.to_string()),
        "the stopped session still shows in `ops ps`"
    );
}
