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
use common::procs::{
    any_sleeping_for, egress_socket_exists, finish_within, kill_sleeping_for, lists_pid,
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

/// Best-effort teardown so a panicking assertion never leaks a background daemon — which, unlike a
/// foreground child, is reparented to init and cannot be reaped by the test. On drop it `sbx session stop`s
/// each known session pid (the clean path, which `--die-with-parent` propagates to the cage) and
/// then SIGKILLs any host process still carrying a fingerprint, as a backstop.
///
/// Each stop is bounded and cannot panic, through [`finish_within`]: the drop runs while a failed
/// assertion unwinds, when a second panic aborts the test binary, and a stop that never returned
/// would hold the suite. The sweep is [`kill_sleeping_for`], which signals no process but one of
/// this user's whose whole argv is `sleep <fingerprint>`.
struct Cleanup {
    data: PathBuf,
    state: PathBuf,
    project: PathBuf,
    pids: Vec<u32>,
    fingerprints: Vec<&'static str>,
}

/// How long the teardown waits on one `sbx session stop` before killing it and moving on to the sweep.
const STOP_LIMIT: Duration = Duration::from_secs(30);

impl Drop for Cleanup {
    fn drop(&mut self) {
        for pid in &self.pids {
            let _ = finish_within(
                sbx()
                    .args(["session", "stop", "--delay", "0", &pid.to_string()])
                    .current_dir(&self.project)
                    .env("XDG_DATA_HOME", &self.data)
                    .env("XDG_STATE_HOME", &self.state),
                STOP_LIMIT,
            );
        }
        for fp in &self.fingerprints {
            kill_sleeping_for(fp);
        }
    }
}

#[test]
fn detach_runs_an_agent_in_the_background_then_stop_ends_it() {
    // Two apps so both daemon paths run under one provisioning: `sup` has a network allowlist (the
    // supervised path — the daemon hosts the proxy thread, the registered pid is the supervisor),
    // `plain` has none (the exec path — the daemon becomes bubblewrap). The project sets
    // `git_writable`, since a project without a repository is otherwise watched for one the cage
    // leaves there, which keeps the daemon to look once the cage exits. The unusual sleep durations
    // are unique fingerprints in the host process table, and unique across test *binaries* too:
    // cargo runs the suites as concurrent processes, so a duration this file shares with another
    // would make each one's liveness assertions read the other's cage, and each one's cleanup kill
    // it.
    let project = TmpDir::prefixed("d", "proj");
    let data = TmpDir::prefixed("d", "data");
    let state = TmpDir::prefixed("d", "state");
    std::fs::write(
        project.path().join(".sbx.toml"),
        "[fs]\n\
         git_writable = true\n\
         [app.sup]\n\
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
        &["trust", "--yes", ".sbx.toml"],
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
            any_sleeping_for("31351")
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
        lists_pid(&String::from_utf8_lossy(&ls.stdout), sup_pid),
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
            !any_sleeping_for("31351")
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
            any_sleeping_for("31352")
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
            !any_sleeping_for("31352")
        }),
        "the exec-path cage was orphaned after stop"
    );
}

/// A detached session keeps no descriptor its invoker left open. The daemon forks without an
/// `exec`, so a descriptor only marked close-on-exec would stay open in it for the session's whole
/// life; here the write end of a pipe, handed over as descriptor 9, reads its end once the launch
/// has returned, while the session runs on.
#[test]
fn a_detached_session_keeps_no_descriptor_of_its_invoker() {
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    use std::os::unix::process::CommandExt;

    let project = TmpDir::prefixed("d", "proj");
    let data = TmpDir::prefixed("d", "data");
    let state = TmpDir::prefixed("d", "state");
    probe_or_skip!(
        "detached inherited descriptor e2e",
        sandbox_probe(project.path(), data.path(), state.path())
    );
    let mut cleanup = Cleanup {
        data: data.path().to_path_buf(),
        state: state.path().to_path_buf(),
        project: project.path().to_path_buf(),
        pids: Vec::new(),
        fingerprints: vec!["31353"],
    };

    let mut fds = [0 as libc::c_int; 2];
    // SAFETY: `pipe2` fills the two-element array it is handed.
    assert_eq!(
        unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) },
        0,
        "pipe2: {}",
        std::io::Error::last_os_error()
    );
    // SAFETY: both ends are fresh descriptors this test owns and closes once, through these.
    let (read, write) = unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) };
    let from = write.as_raw_fd();
    // A one-shot allowlist takes the supervised path, where the daemon lives on as a process of
    // its own rather than becoming bubblewrap, whose `exec` would close the descriptor anyway.
    let mut cmd = sbx();
    cmd.args(["run", "--detach", "--net", "allow=example.com", "--"])
        .args(["sleep", "31353"])
        .current_dir(project.path())
        .env("XDG_DATA_HOME", data.path())
        .env("XDG_STATE_HOME", state.path())
        .stdin(Stdio::null());
    // SAFETY: `dup2` is async-signal-safe and allocates nothing. The copy it makes is descriptor 9
    // of the child, without close-on-exec.
    unsafe {
        cmd.pre_exec(move || match libc::dup2(from, 9) {
            -1 => Err(std::io::Error::last_os_error()),
            _ => Ok(()),
        });
    }
    let started = cmd.output().expect("run sbx");
    drop(write);
    assert!(
        started.status.success(),
        "sbx run --detach must exit 0: {}",
        String::from_utf8_lossy(&started.stderr)
    );
    let pid = parse_detach_pid(&started.stderr).unwrap_or_else(|| {
        panic!(
            "could not parse the detached session id from: {}",
            String::from_utf8_lossy(&started.stderr)
        )
    });
    cleanup.pids.push(pid);
    assert!(
        egress_socket_exists(data.path()),
        "expected a per-session egress socket: the launch did not take the supervised path"
    );
    assert!(
        wait_until(Instant::now() + Duration::from_secs(30), || {
            any_sleeping_for("31353")
        }),
        "the detached agent never appeared"
    );

    let mut pfd = libc::pollfd {
        fd: read.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    let ready = loop {
        // SAFETY: one `pollfd`, over a descriptor this test owns.
        let ready = unsafe { libc::poll(&mut pfd, 1, 5_000) };
        if ready >= 0 {
            break ready;
        }
        let e = std::io::Error::last_os_error();
        assert_eq!(
            e.kind(),
            std::io::ErrorKind::Interrupted,
            "polling the pipe: {e}"
        );
    };
    assert!(
        ready == 1 && pfd.revents & libc::POLLHUP != 0,
        "the running session still holds the invoker's descriptor 9 (poll {ready}, revents {:#x})",
        pfd.revents
    );
}

/// The teardown's bounded run kills a command that outlives its limit, and returns the status of
/// one that ends in time. Its fingerprint is its own: the suites run side by side, and a `sleep`
/// under another test's fingerprint would read as that test's agent.
#[test]
fn a_teardown_command_is_killed_at_its_limit() {
    let started = Instant::now();
    let hung = finish_within(
        Command::new("sleep").arg("31354"),
        Duration::from_millis(300),
    );
    assert_eq!(hung, None, "a command past its limit has no status");
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "the bounded run waited {:?}",
        started.elapsed()
    );
    assert!(
        pids_sleeping_for("31354").is_empty(),
        "the command past its limit was left running"
    );
    let done = finish_within(&mut Command::new("true"), Duration::from_secs(5));
    assert!(done.is_some_and(|status| status.success()));
}
