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
use common::fixture::TmpDir;
use common::procs::{
    FingerprintCleanup, any_sleeping_for, egress_socket_exists, kill_sleeping_for,
    parse_detach_pid, pids_sleeping_for, wait_until,
};

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
    let data = TmpDir::prefixed("s", "usage");
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
    let data = TmpDir::prefixed("s", "noid");
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
    let data = TmpDir::prefixed("s", "all-and-id");
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
    let data = TmpDir::prefixed("s", "all-empty");
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
#[test]
fn stop_takes_the_name_the_listing_leads_with() {
    // The defect: `session ls` printed NAME in its first column, `session stop` matched only the
    // pid, and its refusal sent the reader back to the listing they had copied the name from.
    // The unit tests cover the predicate; this one covers the wiring, because the predicate was
    // right in four places that each had their own copy of the comparison.
    let project = TmpDir::prefixed("s", "byname-proj");
    let data = TmpDir::prefixed("s", "byname-data");
    let state = TmpDir::prefixed("s", "byname-state");
    let _sweep = FingerprintCleanup(vec!["4172"]);

    if !sandbox_probe(project.path(), data.path(), state.path())
        .status
        .success()
    {
        skip_incapable!("skipping stop-by-name e2e: host cannot sandbox");
        return;
    }

    let started = sbx_run(
        project.path(),
        data.path(),
        state.path(),
        &["run", "--detach", "--", "sleep", "4172"],
    );
    assert!(
        started.status.success(),
        "the detached run must start: {}",
        String::from_utf8_lossy(&started.stderr)
    );
    let Some(pid) = parse_detach_pid(&started.stderr) else {
        skip_incapable!("skipping stop-by-name e2e: the detached run printed no session pid");
        return;
    };
    if wait_for_session(data.path(), pid, Instant::now() + Duration::from_secs(20)).is_none() {
        skip_incapable!("skipping stop-by-name e2e: the session never registered");
        return;
    }

    // The name as the operator reads it: the first column of the listing's one data row.
    let listed = sbx_run(
        project.path(),
        data.path(),
        state.path(),
        &["session", "ls"],
    );
    let text = String::from_utf8_lossy(&listed.stdout).to_string();
    let name = text
        .lines()
        .find(|l| l.contains(&pid.to_string()))
        .and_then(|l| l.split_whitespace().next())
        .expect("the listing must carry a row for the session it just registered")
        .to_string();
    assert!(
        name.starts_with("sbx-"),
        "the first column must be the cage name: {name}"
    );

    let stopped = sbx_run(
        project.path(),
        data.path(),
        state.path(),
        &["session", "stop", "--delay", "0", &name],
    );
    assert!(
        stopped.status.success(),
        "stop must accept the name its own listing leads with, got: {}",
        String::from_utf8_lossy(&stopped.stderr)
    );
    assert!(
        !String::from_utf8_lossy(&stopped.stderr).contains("no live session"),
        "the name must resolve, not be refused: {}",
        String::from_utf8_lossy(&stopped.stderr)
    );

    let after = sbx_run(
        project.path(),
        data.path(),
        state.path(),
        &["session", "ls"],
    );
    assert!(
        String::from_utf8_lossy(&after.stdout).contains("no active"),
        "the session must be gone after a stop by name: {}",
        String::from_utf8_lossy(&after.stdout)
    );
}

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

#[test]
fn stop_tears_down_a_supervised_app_session() {
    // A trusted app with a network allowlist runs supervised: the registered pid is the sbx
    // supervisor, and the cage (bubblewrap + the `sleep`) is its child, kept alive only by
    // `--die-with-parent`. `sbx session stop` of that pid must take the whole thing down. Teeth: the
    // in-cage `sleep 31337` is running before the stop and gone after — an orphan would survive
    // only if the supervisor were killed without the cage following, the failure mode this path
    // alone can exhibit. The unusual sleep duration is a unique fingerprint in the host's process
    // table.
    let project = TmpDir::prefixed("s", "sup-proj");
    let data = TmpDir::prefixed("s", "sup-data");
    let state = TmpDir::prefixed("s", "sup-state");
    std::fs::write(
        project.path().join(".sbx.toml"),
        "[app.probe]\n\
         cmd = [\"sleep\", \"31337\"]\n\
         [app.probe.network]\n\
         mode = \"deny\"\n\
         allow = [\"cache.nixos.org\"]\n",
    )
    .unwrap();

    probe_or_skip!(
        "sbx stop supervised e2e",
        sandbox_probe(project.path(), data.path(), state.path())
    );

    // Trust so the app's allowlist takes effect — otherwise the network field is dropped, the app
    // falls back to the default posture, and the launch would take the exec path instead of the
    // supervised one this test exists to exercise.
    let trusted = sbx_run(
        project.path(),
        data.path(),
        state.path(),
        &["trust", "--yes", ".sbx.toml"],
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
        any_sleeping_for("31337")
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
            !any_sleeping_for("31337")
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
    let project = TmpDir::prefixed("s", "all-proj");
    let data = TmpDir::prefixed("s", "all-data");
    let state = TmpDir::prefixed("s", "all-state");
    std::fs::write(
        project.path().join(".sbx.toml"),
        "[app.one]\n\
         cmd = [\"sleep\", \"31341\"]\n\
         [app.two]\n\
         cmd = [\"sleep\", \"31342\"]\n",
    )
    .unwrap();

    probe_or_skip!(
        "sbx stop --all e2e",
        sandbox_probe(project.path(), data.path(), state.path())
    );
    let trusted = sbx_run(
        project.path(),
        data.path(),
        state.path(),
        &["trust", "--yes", ".sbx.toml"],
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
            any_sleeping_for("31341") && any_sleeping_for("31342")
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
            !any_sleeping_for("31341") && !any_sleeping_for("31342")
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

/// The fingerprints are bare numbers, and the sweep matched them as a substring of every command
/// line on the machine: `sleep 131399` contains `31399`, so a test run signalled a process of the
/// developer's that had nothing to do with it, and the liveness assertions read it as one of the
/// cage's agents still running. Matched argument by argument now, against an argv that must be
/// exactly `sleep <fingerprint>`.
///
/// The fingerprint here is its own, shared with no other test in this binary: the harness runs the
/// tests on parallel threads, so a `sleep` spawned under one of the e2e fingerprints would be seen
/// as a surviving agent by that e2e's liveness assertions, and swept by its `FingerprintCleanup`.
#[test]
fn the_fingerprint_sweep_matches_a_whole_argv_and_not_a_substring_of_one() {
    let mut neighbour = std::process::Command::new("sleep")
        .arg("131399")
        .spawn()
        .expect("spawn the neighbour");
    let mut ours = std::process::Command::new("sleep")
        .arg("31399")
        .spawn()
        .expect("spawn the fingerprinted process");
    // Both are up before either is looked for.
    assert!(wait_until(Instant::now() + Duration::from_secs(5), || {
        pids_sleeping_for("31399").contains(&(ours.id() as i32))
    }));

    let matched = pids_sleeping_for("31399");
    assert!(
        matched.contains(&(ours.id() as i32)),
        "the fingerprinted process must be found: {matched:?}"
    );
    assert!(
        !matched.contains(&(neighbour.id() as i32)),
        "a longer number containing the fingerprint is somebody else's process: {matched:?}"
    );

    let _ = ours.kill();
    let _ = neighbour.kill();
    let _ = ours.wait();
    let _ = neighbour.wait();
}

/// The sweep a teardown runs kills the fingerprinted process and spares a neighbour whose argument
/// only contains the fingerprint's digits. Its fingerprint is its own, for the reason the test above
/// gives.
#[test]
fn the_fingerprint_kill_ends_the_fingerprinted_process_and_spares_its_neighbour() {
    use std::os::unix::process::ExitStatusExt;

    let mut neighbour = KillOnDrop(
        Command::new("sleep")
            .arg("131398")
            .spawn()
            .expect("spawn the neighbour"),
    );
    let mut ours = KillOnDrop(
        Command::new("sleep")
            .arg("31398")
            .spawn()
            .expect("spawn the fingerprinted process"),
    );
    let pid = ours.0.id() as i32;
    assert!(
        wait_until(Instant::now() + Duration::from_secs(5), || {
            pids_sleeping_for("31398").contains(&pid)
        }),
        "the fingerprinted process was never listed"
    );

    kill_sleeping_for("31398");

    let mut ended = None;
    assert!(
        wait_until(Instant::now() + Duration::from_secs(5), || {
            ended = ours
                .0
                .try_wait()
                .expect("waiting on the fingerprinted process");
            ended.is_some()
        }),
        "the fingerprinted process outlived the sweep"
    );
    assert_eq!(
        ended.and_then(|status| status.signal()),
        Some(libc::SIGKILL)
    );
    assert!(
        neighbour
            .0
            .try_wait()
            .expect("waiting on the neighbour")
            .is_none(),
        "the sweep killed a process whose argument only contains the fingerprint"
    );
}
