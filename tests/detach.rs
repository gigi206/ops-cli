//! Integration tests for `ops app --detach` / `ops run --detach`.
//!
//! The headline property is *detachment itself*: the `--detach` command **returns** (the launching
//! shell gets its prompt back) while the agent keeps running in the background — something a
//! foreground launch never does. That is the discriminating assertion here; `ops ls`/`stop` on top
//! only confirm the detached session is a first-class registry citizen. Both launch paths are
//! exercised under one data directory (so the base userland is provisioned once): the supervised
//! path (a network allowlist, where the daemon hosts the filtering proxy thread) and the exec path
//! (the default posture, where the daemon becomes bubblewrap). Skipped, not failed, where the host
//! cannot sandbox.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};

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
        d.push(format!("ops-detach-it-{tag}-{}-{n}", std::process::id()));
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

/// Whether any process on the host has `needle` in its argv. Used to see an in-cage process from
/// outside the cage's pid namespace (the host still sees it).
fn process_with_arg(needle: &str) -> bool {
    proc_pids_with_arg(needle).next().is_some()
}

/// The host pids whose `/proc/<pid>/cmdline` (NUL-separated, kept intact by `from_utf8_lossy`)
/// contains `needle`.
fn proc_pids_with_arg(needle: &str) -> impl Iterator<Item = i32> + '_ {
    let entries = std::fs::read_dir("/proc").ok();
    entries
        .into_iter()
        .flat_map(|d| d.flatten())
        .filter_map(move |entry| {
            let pid: i32 = entry.file_name().to_str()?.parse().ok()?;
            let bytes = std::fs::read(entry.path().join("cmdline")).ok()?;
            String::from_utf8_lossy(&bytes)
                .contains(needle)
                .then_some(pid)
        })
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

/// Parse the detached session id out of `ops`'s startup message ("...detached session <pid>...").
fn parse_detach_pid(stderr: &[u8]) -> Option<u32> {
    let text = String::from_utf8_lossy(stderr);
    let after = text.split("detached session ").nth(1)?;
    let digits: String = after.chars().take_while(|c| c.is_ascii_digit()).collect();
    digits.parse().ok()
}

/// Whether a per-session egress socket exists under `<data>/ops/egress/` — present only when the
/// allowlist (supervised) launch path ran, so it confirms a fixture took that path.
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

/// Best-effort teardown so a panicking assertion never leaks a background daemon — which, unlike a
/// foreground child, is reparented to init and cannot be reaped by the test. On drop it `ops stop`s
/// each known session pid (the clean path, which `--die-with-parent` propagates to the cage) and
/// then SIGKILLs any host process still carrying a fingerprint, as a backstop.
struct Cleanup {
    data: PathBuf,
    state: PathBuf,
    project: PathBuf,
    pids: Vec<u32>,
    fingerprints: Vec<&'static str>,
}

impl Drop for Cleanup {
    fn drop(&mut self) {
        for pid in &self.pids {
            let _ = ops_run(
                &self.project,
                &self.data,
                &self.state,
                &["stop", "--delay", "0", &pid.to_string()],
            );
        }
        for fp in &self.fingerprints {
            for pid in proc_pids_with_arg(fp) {
                // SAFETY: a best-effort SIGKILL of a leaked test process by the unique fingerprint.
                unsafe { libc::kill(pid, libc::SIGKILL) };
            }
        }
    }
}

#[test]
fn detach_runs_an_agent_in_the_background_then_stop_ends_it() {
    // Two apps so both daemon paths run under one provisioning: `sup` has a network allowlist (the
    // supervised path — the daemon hosts the proxy thread, the registered pid is the supervisor),
    // `plain` has none (the exec path — the daemon becomes bubblewrap). The unusual sleep durations
    // are unique fingerprints in the host process table.
    let project = TmpDir::new("proj");
    let data = TmpDir::new("data");
    let state = TmpDir::new("state");
    std::fs::write(
        project.path().join(".ops.toml"),
        "[app.sup]\n\
         cmd = [\"sleep\", \"31337\"]\n\
         [app.sup.network]\n\
         mode = \"allowlist\"\n\
         allow = [\"cache.nixos.org\"]\n\
         [app.plain]\n\
         cmd = [\"sleep\", \"31338\"]\n",
    )
    .unwrap();

    if !host_can_sandbox(project.path(), data.path(), state.path()) {
        eprintln!("skipping ops detach e2e: host cannot sandbox");
        return;
    }

    // Trust so the app's allowlist takes effect — otherwise `sup` falls back to the default posture
    // and would not exercise the supervised path.
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

    let mut cleanup = Cleanup {
        data: data.path().to_path_buf(),
        state: state.path().to_path_buf(),
        project: project.path().to_path_buf(),
        pids: Vec::new(),
        fingerprints: vec!["31337", "31338"],
    };

    // --- The supervised path -------------------------------------------------------------------
    // `ops app sup --detach` must RETURN (the teeth: a foreground launch would block until the
    // agent exits, ~8.7h from now — so the mere fact this call completes proves detachment). It
    // returns only once the cage is ready, so the session is real by the time we get the pid.
    let started = ops_run(
        project.path(),
        data.path(),
        state.path(),
        &["app", "sup", "--detach"],
    );
    assert!(
        started.status.success(),
        "ops app sup --detach must exit 0: {}",
        String::from_utf8_lossy(&started.stderr)
    );
    let sup_pid = parse_detach_pid(&started.stderr).unwrap_or_else(|| {
        panic!(
            "could not parse the detached session id from: {}",
            String::from_utf8_lossy(&started.stderr)
        )
    });
    cleanup.pids.push(sup_pid);

    // It genuinely took the supervised path (the only one with the egress proxy).
    assert!(
        egress_socket_exists(data.path()),
        "expected a per-session egress socket — `sup` did not take the supervised path"
    );

    // The discriminating property: the launch command has already returned, yet the agent runs.
    assert!(
        wait_until(Instant::now() + Duration::from_secs(30), || {
            process_with_arg("31337")
        }),
        "the detached agent never appeared — `--detach` did not start it in the background"
    );

    // It is a first-class session: `ops ls` lists it.
    let ls = ops_run(project.path(), data.path(), state.path(), &["ls"]);
    assert!(
        String::from_utf8_lossy(&ls.stdout).contains(&sup_pid.to_string()),
        "the detached session is not listed by `ops ls`:\n{}",
        String::from_utf8_lossy(&ls.stdout)
    );

    // `ops stop` tears it down: stopping the supervisor takes the cage with it (`--die-with-parent`).
    let stopped = ops_run(
        project.path(),
        data.path(),
        state.path(),
        &["stop", &sup_pid.to_string()],
    );
    assert!(
        stopped.status.success(),
        "ops stop must exit 0: {}",
        String::from_utf8_lossy(&stopped.stderr)
    );
    assert!(
        wait_until(Instant::now() + Duration::from_secs(10), || {
            !process_with_arg("31337")
        }),
        "the supervised cage was orphaned — stopping the supervisor did not tear it down"
    );

    // --- The exec path -------------------------------------------------------------------------
    // The default posture: the daemon exec-replaces into bubblewrap (the registered pid is bwrap,
    // pid 1 of the cage's namespace). Same detachment property, the other branch of the daemon.
    let started = ops_run(
        project.path(),
        data.path(),
        state.path(),
        &["app", "plain", "--detach"],
    );
    assert!(
        started.status.success(),
        "ops app plain --detach must exit 0: {}",
        String::from_utf8_lossy(&started.stderr)
    );
    let plain_pid = parse_detach_pid(&started.stderr).unwrap_or_else(|| {
        panic!(
            "could not parse the detached session id from: {}",
            String::from_utf8_lossy(&started.stderr)
        )
    });
    cleanup.pids.push(plain_pid);

    assert!(
        wait_until(Instant::now() + Duration::from_secs(30), || {
            process_with_arg("31338")
        }),
        "the detached exec-path agent never appeared"
    );
    let stopped = ops_run(
        project.path(),
        data.path(),
        state.path(),
        &["stop", &plain_pid.to_string()],
    );
    assert!(
        stopped.status.success(),
        "ops stop (exec path) must exit 0: {}",
        String::from_utf8_lossy(&stopped.stderr)
    );
    assert!(
        wait_until(Instant::now() + Duration::from_secs(10), || {
            !process_with_arg("31338")
        }),
        "the exec-path cage was orphaned after stop"
    );
}
