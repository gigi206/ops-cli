//! Integration tests for `sbx app --detach` / `sbx run --detach`.
//!
//! The headline property is *detachment itself*: the `--detach` command **returns** (the launching
//! shell gets its prompt back) while the agent keeps running in the background — something a
//! foreground launch never does. That is the discriminating assertion here; `sbx session ls`/`stop` on top
//! only confirm the detached session is a first-class registry citizen. Both launch paths are
//! exercised under one data directory (so the base userland is provisioned once): the supervised
//! path (a network allowlist, where the daemon hosts the filtering proxy thread) and the exec path
//! (the default posture, where the daemon becomes bubblewrap). Skipped, not failed, where the host
//! cannot sandbox.

#[macro_use]
mod common;
use common::fixture::TmpDir;

use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
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
fn sandbox_probe(project: &Path, data: &Path, state: &Path) -> Output {
    sbx_run(project, data, state, &["run", "--", "true"])
}

/// Whether the fingerprinted agent is alive on the host. Used to see an in-cage process from
/// outside the cage's pid namespace (the host still sees it).
fn process_with_arg(needle: &str) -> bool {
    !pids_sleeping_for(needle).is_empty()
}

/// The pids of every process whose argv is exactly `sleep <secs>`, for the fingerprint `secs`.
///
/// Matched argument by argument against a `/proc/<pid>/cmdline` split on its NULs, never as a
/// substring of the whole line. A fingerprint here is a bare number, and a substring test against
/// every command line on the machine matches a port, a pid, a hash prefix or a timestamp that
/// happens to contain those digits. That is a false positive for the liveness assertions and,
/// worse, a SIGKILL of an unrelated process of the developer's in [`Cleanup`].
fn pids_sleeping_for(secs: &str) -> Vec<i32> {
    let Ok(entries) = std::fs::read_dir("/proc") else {
        return Vec::new();
    };
    let mut pids = Vec::new();
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
        let argv: Vec<&[u8]> = bytes.split(|b| *b == 0).filter(|a| !a.is_empty()).collect();
        let [program, arg] = argv[..] else {
            continue;
        };
        if arg == secs.as_bytes()
            && std::path::Path::new(&String::from_utf8_lossy(program).into_owned())
                .file_name()
                .is_some_and(|n| n == "sleep")
        {
            pids.push(pid);
        }
    }
    pids
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

/// Parse the detached session id out of `sbx`'s startup message ("...detached session <pid>...").
fn parse_detach_pid(stderr: &[u8]) -> Option<u32> {
    let text = String::from_utf8_lossy(stderr);
    let after = text.split("detached session ").nth(1)?;
    let digits: String = after.chars().take_while(|c| c.is_ascii_digit()).collect();
    digits.parse().ok()
}

/// Whether a per-session egress socket exists under `<data>/sbx/egress/` — present only when the
/// allowlist (supervised) launch path ran, so it confirms a fixture took that path.
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

/// Best-effort teardown so a panicking assertion never leaks a background daemon — which, unlike a
/// foreground child, is reparented to init and cannot be reaped by the test. On drop it `sbx session stop`s
/// each known session pid (the clean path, which `--die-with-parent` propagates to the cage) and
/// then SIGKILLs any host process still carrying a fingerprint, as a backstop.
///
/// The match is on the whole argv, through [`pids_sleeping_for`]. A substring test against every
/// command line on the machine would sweep far wider than this test's own children: the
/// fingerprints are bare numbers, so any process of the developer's whose command line happened to
/// contain those digits was signalled by a test run.
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
            let _ = sbx_run(
                &self.project,
                &self.data,
                &self.state,
                &["session", "stop", "--delay", "0", &pid.to_string()],
            );
        }
        for fp in &self.fingerprints {
            for pid in pids_sleeping_for(fp) {
                // SAFETY: a best-effort SIGKILL of a leaked test process whose whole argv is
                // `sleep <fingerprint>`; a failure (already gone) is ignored.
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
    // are unique fingerprints in the host process table, and unique across test *binaries* too:
    // cargo runs the suites as concurrent processes, so a duration this file shares with another
    // would make each one's liveness assertions read the other's cage, and each one's cleanup kill
    // it.
    let project = TmpDir::prefixed("d", "proj");
    let data = TmpDir::prefixed("d", "data");
    let state = TmpDir::prefixed("d", "state");
    std::fs::write(
        project.path().join(".sbx.toml"),
        "[app.sup]\n\
         cmd = [\"sleep\", \"31351\"]\n\
         [app.sup.network]\n\
         mode = \"deny\"\n\
         allow = [\"cache.nixos.org\"]\n\
         [app.plain]\n\
         cmd = [\"sleep\", \"31352\"]\n",
    )
    .unwrap();

    probe_or_skip!(
        "sbx detach e2e",
        sandbox_probe(project.path(), data.path(), state.path())
    );

    // Trust so the app's allowlist takes effect — otherwise `sup` falls back to the default posture
    // and would not exercise the supervised path.
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

    let mut cleanup = Cleanup {
        data: data.path().to_path_buf(),
        state: state.path().to_path_buf(),
        project: project.path().to_path_buf(),
        pids: Vec::new(),
        fingerprints: vec!["31351", "31352"],
    };

    // --- The supervised path -------------------------------------------------------------------
    // `sbx app run sup --detach` must RETURN (the teeth: a foreground launch would block until the
    // agent exits, ~8.7h from now — so the mere fact this call completes proves detachment). It
    // returns only once the cage is ready, so the session is real by the time we get the pid.
    let started = sbx_run(
        project.path(),
        data.path(),
        state.path(),
        &["app", "run", "sup", "--detach"],
    );
    assert!(
        started.status.success(),
        "sbx app run sup --detach must exit 0: {}",
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
            process_with_arg("31351")
        }),
        "the detached agent never appeared — `--detach` did not start it in the background"
    );

    // It is a first-class session: `sbx session ls` lists it.
    let ls = sbx_run(
        project.path(),
        data.path(),
        state.path(),
        &["session", "ls"],
    );
    assert!(
        String::from_utf8_lossy(&ls.stdout).contains(&sup_pid.to_string()),
        "the detached session is not listed by `sbx session ls`:\n{}",
        String::from_utf8_lossy(&ls.stdout)
    );

    // `sbx session stop` tears it down: stopping the supervisor takes the cage with it (`--die-with-parent`).
    let stopped = sbx_run(
        project.path(),
        data.path(),
        state.path(),
        &["session", "stop", &sup_pid.to_string()],
    );
    assert!(
        stopped.status.success(),
        "sbx session stop must exit 0: {}",
        String::from_utf8_lossy(&stopped.stderr)
    );
    assert!(
        wait_until(Instant::now() + Duration::from_secs(10), || {
            !process_with_arg("31351")
        }),
        "the supervised cage was orphaned — stopping the supervisor did not tear it down"
    );

    // --- The exec path -------------------------------------------------------------------------
    // The default posture: the daemon exec-replaces into bubblewrap (the registered pid is bwrap,
    // pid 1 of the cage's namespace). Same detachment property, the other branch of the daemon.
    let started = sbx_run(
        project.path(),
        data.path(),
        state.path(),
        &["app", "run", "plain", "--detach"],
    );
    assert!(
        started.status.success(),
        "sbx app run plain --detach must exit 0: {}",
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
            process_with_arg("31352")
        }),
        "the detached exec-path agent never appeared"
    );
    let stopped = sbx_run(
        project.path(),
        data.path(),
        state.path(),
        &["session", "stop", &plain_pid.to_string()],
    );
    assert!(
        stopped.status.success(),
        "sbx session stop (exec path) must exit 0: {}",
        String::from_utf8_lossy(&stopped.stderr)
    );
    assert!(
        wait_until(Instant::now() + Duration::from_secs(10), || {
            !process_with_arg("31352")
        }),
        "the exec-path cage was orphaned after stop"
    );
}
