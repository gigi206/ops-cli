//! Integration tests for `sbx session stop`.
//!
//! The headline property: stopping a **supervised** session (the `network = "deny"` path,
//! where the registered pid is the sbx supervisor rather than bubblewrap itself) tears the whole
//! cage down — the supervisor exits *and* no in-cage process is left orphaned. That is the path
//! where teardown is non-trivial: it relies on bubblewrap dying with its parent. The exec path
//! (default posture, registered pid == bubblewrap) is trivially correct and covered by the unit
//! tests of the stop primitive. Skipped, not failed, where the host cannot sandbox.

#[macro_use]
mod common;

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};

fn sbx() -> Command {
    // Isolate XDG_CONFIG_HOME from the user's real `~/.config/sbx` so an e2e never depends on
    // the developer's global sbx config; default it to a fixed empty dir under the test tree
    // (no test here writes a global config, so a shared empty dir is race-free).
    let cfg = fixture_root().join("isolated-config");
    let _ = std::fs::create_dir_all(&cfg);
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_sbx"));
    cmd.env("XDG_CONFIG_HOME", cfg);
    cmd
}

// The fixtures' root, one definition shared with the unit tests.
include!("../src/testroot.rs");

/// A unique temp dir removed on drop.
struct TmpDir(PathBuf);

impl TmpDir {
    fn new(tag: &str) -> Self {
        static COUNTER: AtomicU32 = AtomicU32::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let mut d = fixture_root();
        d.push(format!("s-{tag}-{}-{n}", std::process::id()));
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

/// Parse the detached session id out of `sbx`'s startup message ("...detached session <pid>...").
fn parse_detach_pid(stderr: &[u8]) -> Option<u32> {
    let text = String::from_utf8_lossy(stderr);
    let after = text.split("detached session ").nth(1)?;
    let digits: String = after.chars().take_while(|c| c.is_ascii_digit()).collect();
    digits.parse().ok()
}

/// Best-effort SIGKILL of any leaked, fingerprinted background process on drop. A detached daemon is
/// reparented to init and cannot be reaped by the test, so a `KillOnDrop` (which holds a `Child`)
/// does not cover it — this sweeps by the unique `sleep` argument instead, as a backstop for when an
/// assertion panics before the stop under test runs.
struct FingerprintCleanup(Vec<&'static str>);

impl Drop for FingerprintCleanup {
    fn drop(&mut self) {
        let Ok(entries) = std::fs::read_dir("/proc") else {
            return;
        };
        for entry in entries.flatten() {
            let Some(pid) = entry
                .file_name()
                .to_str()
                .and_then(|s| s.parse::<i32>().ok())
            else {
                continue;
            };
            let Ok(bytes) = std::fs::read(entry.path().join("cmdline")) else {
                continue;
            };
            let cmdline = String::from_utf8_lossy(&bytes);
            if self.0.iter().any(|fp| cmdline.contains(fp)) {
                // SAFETY: a best-effort SIGKILL of a leaked test process matched by its unique
                // fingerprint; a failure (already gone) is ignored.
                unsafe { libc::kill(pid, libc::SIGKILL) };
            }
        }
    }
}

#[test]
fn stop_with_no_or_bad_arguments_is_a_usage_error() {
    let data = TmpDir::new("usage");
    // No id: usage error, exit 2.
    let no_id = sbx()
        .arg("session")
        .arg("stop")
        .env("XDG_DATA_HOME", data.path())
        .stdin(Stdio::null())
        .output()
        .expect("spawn sbx session stop");
    assert_eq!(no_id.status.code(), Some(2), "no-id stop must exit 2");
    assert!(String::from_utf8_lossy(&no_id.stderr).contains("usage"));

    // A non-numeric --delay: usage error, exit 2 (caught before any signalling).
    let bad_delay = sbx()
        .args(["session", "stop", "--delay", "soon", "123"])
        .env("XDG_DATA_HOME", data.path())
        .stdin(Stdio::null())
        .output()
        .expect("spawn sbx session stop");
    assert_eq!(bad_delay.status.code(), Some(2), "bad --delay must exit 2");
    assert!(String::from_utf8_lossy(&bad_delay.stderr).contains("whole number"));
}

#[test]
fn stop_an_unknown_id_reports_and_exits_two() {
    let data = TmpDir::new("noid");
    let out = sbx()
        .args(["session", "stop", "999999"])
        .env("XDG_DATA_HOME", data.path())
        .stdin(Stdio::null())
        .output()
        .expect("spawn sbx session stop");
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

#[test]
fn stop_all_together_with_an_id_is_a_usage_error() {
    // `--all` and explicit ids are mutually exclusive: passing both is ambiguous, so it is rejected
    // before any signalling (exit 2), not silently resolved one way.
    let data = TmpDir::new("all-and-id");
    let out = sbx()
        .args(["session", "stop", "--all", "123"])
        .env("XDG_DATA_HOME", data.path())
        .stdin(Stdio::null())
        .output()
        .expect("spawn sbx session stop");
    assert_eq!(out.status.code(), Some(2), "--all with an id must exit 2");
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("either explicit ids or --all"),
        "message: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn stop_all_with_no_sessions_is_a_no_op_success() {
    // Stopping every session when there are none is not an error — there is simply nothing to do,
    // like `sbx gc` with nothing to reclaim. No sandbox is needed (the registry is just empty).
    let data = TmpDir::new("all-empty");
    let out = sbx()
        .args(["session", "stop", "--all"])
        .env("XDG_DATA_HOME", data.path())
        .stdin(Stdio::null())
        .output()
        .expect("spawn sbx session stop");
    assert!(
        out.status.success(),
        "stop --all with no sessions must exit 0: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        String::from_utf8_lossy(&out.stdout).contains("no active sessions"),
        "stdout: {}",
        String::from_utf8_lossy(&out.stdout)
    );
}

/// Run `sbx <args>` to completion in `project` with isolated data/state, returning its output.
fn sbx_run(project: &Path, data: &Path, state: &Path, args: &[&str]) -> std::process::Output {
    sbx()
        .args(args)
        .current_dir(project)
        .env("XDG_DATA_HOME", data)
        .env("XDG_STATE_HOME", state)
        .stdin(Stdio::null())
        .output()
        .expect("run sbx")
}

/// Whether the host can launch a sandbox (also warms the userland cache so later launches start
/// promptly, and seeds the project store once).
fn host_can_sandbox(project: &Path, data: &Path, state: &Path) -> bool {
    sbx_run(project, data, state, &["run", "--", "true"])
        .status
        .success()
}

/// The session record file for `pid`, once it appears under `<data>/sbx/sessions/`. `None` if it
/// does not show up before the deadline.
fn wait_for_session(data: &Path, pid: u32, deadline: Instant) -> Option<PathBuf> {
    let dir = data.join("sbx").join("sessions");
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

/// Whether a per-session egress socket exists under `<data>/sbx/egress/` — present only when the
/// allowlist (supervised) launch path ran, so it confirms the fixture exercises that path.
fn egress_socket_exists(data: &Path) -> bool {
    std::fs::read_dir(data.join("sbx").join("egress"))
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
        if let Ok(bytes) = std::fs::read(entry.path().join("cmdline"))
            && String::from_utf8_lossy(&bytes).contains(needle)
        {
            return true;
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
    // A trusted app with a network allowlist runs supervised: the registered pid is the sbx
    // supervisor, and the cage (bubblewrap + the `sleep`) is its child, kept alive only by
    // `--die-with-parent`. `sbx session stop` of that pid must take the whole thing down. Teeth: the
    // in-cage `sleep 31337` is running before the stop and gone after — an orphan would survive
    // only if the supervisor were killed without the cage following, the failure mode this path
    // alone can exhibit. The unusual sleep duration is a unique fingerprint in the host's process
    // table.
    let project = TmpDir::new("sup-proj");
    let data = TmpDir::new("sup-data");
    let state = TmpDir::new("sup-state");
    std::fs::write(
        project.path().join(".sbx.toml"),
        "[app.probe]\n\
         cmd = [\"sleep\", \"31337\"]\n\
         [app.probe.network]\n\
         mode = \"deny\"\n\
         allow = [\"cache.nixos.org\"]\n",
    )
    .unwrap();

    if !host_can_sandbox(project.path(), data.path(), state.path()) {
        skip_incapable!(
            "skipping sbx stop supervised e2e: host cannot sandbox (no userns/bwrap, or the base cache is unreachable)"
        );
        return;
    }

    // Trust so the app's allowlist takes effect — otherwise the network field is dropped, the app
    // falls back to the default posture, and the launch would take the exec path instead of the
    // supervised one this test exists to exercise.
    let trusted = sbx_run(
        project.path(),
        data.path(),
        state.path(),
        &["trust", ".sbx.toml"],
    );
    assert!(
        trusted.status.success(),
        "sbx trust failed: {}",
        String::from_utf8_lossy(&trusted.stderr)
    );

    // Launch the app in the background: under the allowlist it registers a session whose pid is the
    // supervisor and supervises the cage running `sleep`.
    let mut agent = KillOnDrop(
        sbx()
            .args(["app", "run", "probe"])
            .current_dir(project.path())
            .env("XDG_DATA_HOME", data.path())
            .env("XDG_STATE_HOME", state.path())
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn sbx app probe"),
    );
    let pid = agent.0.id();

    if wait_for_session(data.path(), pid, Instant::now() + Duration::from_secs(60)).is_none() {
        skip_incapable!("skipping sbx stop supervised e2e: the app session never registered");
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
        skip_incapable!("skipping sbx stop supervised e2e: the cage's sleep never started");
        return;
    }

    // Stop the session by its pid.
    let stopped = sbx_run(
        project.path(),
        data.path(),
        state.path(),
        &["session", "stop", &pid.to_string()],
    );
    assert!(
        stopped.status.success(),
        "sbx session stop must exit 0: {}",
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

    // The stopped session no longer appears in `sbx session ls` (its record was reaped).
    let ls = sbx_run(
        project.path(),
        data.path(),
        state.path(),
        &["session", "ls"],
    );
    assert!(
        !String::from_utf8_lossy(&ls.stdout).contains(&pid.to_string()),
        "the stopped session still shows in `sbx session ls`"
    );
}

#[test]
fn stop_all_stops_every_session() {
    // `sbx session stop --all` must tear down *every* live session at once, not just one. Two background
    // agents are started with `--detach` (so each is a first-class registry session); a single
    // `sbx session stop --all` must leave neither running. The unusual sleep durations are unique
    // fingerprints in the host's process table. Both apps use the default posture (the exec path),
    // which keeps the fixture to one provisioning and is enough to prove the fan-out — the
    // supervised teardown itself is covered by `stop_tears_down_a_supervised_app_session`.
    let project = TmpDir::new("all-proj");
    let data = TmpDir::new("all-data");
    let state = TmpDir::new("all-state");
    std::fs::write(
        project.path().join(".sbx.toml"),
        "[app.one]\n\
         cmd = [\"sleep\", \"31341\"]\n\
         [app.two]\n\
         cmd = [\"sleep\", \"31342\"]\n",
    )
    .unwrap();

    if !host_can_sandbox(project.path(), data.path(), state.path()) {
        skip_incapable!(
            "skipping sbx stop --all e2e: host cannot sandbox (no userns/bwrap, or the base cache is unreachable)"
        );
        return;
    }
    let trusted = sbx_run(
        project.path(),
        data.path(),
        state.path(),
        &["trust", ".sbx.toml"],
    );
    assert!(
        trusted.status.success(),
        "sbx trust failed: {}",
        String::from_utf8_lossy(&trusted.stderr)
    );

    // Backstop: SIGKILL either agent if an assertion panics before `sbx session stop --all` runs (a detached
    // daemon is reparented to init and cannot be reaped by the test).
    let _cleanup = FingerprintCleanup(vec!["31341", "31342"]);

    // Start two background sessions with `--detach`; each returns once its cage is ready, printing
    // its session pid.
    let mut pids = Vec::new();
    for app in ["one", "two"] {
        let started = sbx_run(
            project.path(),
            data.path(),
            state.path(),
            &["app", "run", app, "--detach"],
        );
        assert!(
            started.status.success(),
            "sbx app run {app} --detach must exit 0: {}",
            String::from_utf8_lossy(&started.stderr)
        );
        let pid = parse_detach_pid(&started.stderr).unwrap_or_else(|| {
            panic!(
                "could not parse the detached session id from: {}",
                String::from_utf8_lossy(&started.stderr)
            )
        });
        pids.push(pid);
    }

    // Both agents are running before the stop.
    assert!(
        wait_until(Instant::now() + Duration::from_secs(30), || {
            process_with_arg("31341") && process_with_arg("31342")
        }),
        "both detached agents should be running before `sbx session stop --all`"
    );

    // `sbx session ls` lists both sessions.
    let ls = sbx_run(
        project.path(),
        data.path(),
        state.path(),
        &["session", "ls"],
    );
    let listing = String::from_utf8_lossy(&ls.stdout);
    for pid in &pids {
        assert!(
            listing.contains(&pid.to_string()),
            "session {pid} should be listed before stop:\n{listing}"
        );
    }

    // One command stops them all.
    let stopped = sbx_run(
        project.path(),
        data.path(),
        state.path(),
        &["session", "stop", "--all"],
    );
    assert!(
        stopped.status.success(),
        "sbx session stop --all must exit 0: {}",
        String::from_utf8_lossy(&stopped.stderr)
    );

    // Neither cage is left running.
    assert!(
        wait_until(Instant::now() + Duration::from_secs(10), || {
            !process_with_arg("31341") && !process_with_arg("31342")
        }),
        "`sbx session stop --all` left an agent running"
    );

    // And `sbx session ls` no longer lists either (records reaped).
    let ls = sbx_run(
        project.path(),
        data.path(),
        state.path(),
        &["session", "ls"],
    );
    let listing = String::from_utf8_lossy(&ls.stdout);
    for pid in &pids {
        assert!(
            !listing.contains(&pid.to_string()),
            "session {pid} still shows in `sbx session ls` after stop --all:\n{listing}"
        );
    }
}
