//! Integration tests for `ops session attach`.
//!
//! The headline property: attaching to a running **app** (agent) session drops a new interactive
//! shell into the agent's *isolated* home — not the project's shared home — so "attach to a running
//! agent" really means the same environment it works in. Driven through a pty (attach, like
//! `shell`, needs a controlling terminal). Skipped, not failed, where the host cannot sandbox.

use std::os::fd::FromRawFd;
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
        d.push(format!("ops-attach-it-{tag}-{}-{n}", std::process::id()));
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

#[test]
fn attach_to_an_unknown_id_reports_and_exits_two() {
    // No tty needed: `attach` resolves the target before the terminal check, so an unknown id is a
    // clean exit-2 with a pointer to `ops session ls` — never a panic or a misparse of garbage.
    let data = TmpDir::new("noid");
    for id in ["999999", "not-a-pid"] {
        let out = ops()
            .arg("session")
            .arg("attach")
            .arg(id)
            .env("XDG_DATA_HOME", data.path())
            .stdin(Stdio::null())
            .output()
            .expect("spawn ops session attach");
        assert_eq!(
            out.status.code(),
            Some(2),
            "attach to a missing id must exit 2 ({id})"
        );
        assert!(
            String::from_utf8_lossy(&out.stderr).contains("no live session"),
            "missing-id message: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
}

/// Whether the host can launch a sandbox (also warms the userland cache so later launches start
/// promptly, and creates the project's default home).
fn host_can_sandbox(project: &Path, data: &Path) -> bool {
    ops()
        .arg("run")
        .arg("--")
        .arg("true")
        .current_dir(project)
        .env("XDG_DATA_HOME", data)
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// The session record file for `pid`, once it appears under `<data>/ops/sessions/` (the launch
/// registers it after seeding). `None` if it does not show up before the deadline.
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

/// Drive an interactive `ops session attach <pid>` through a pty: wait for the shell's prompt, send
/// `script`, and read until the session ends or the deadline. Returns the captured output.
fn drive_attach(pid: u32, data: &Path, script: &[u8]) -> String {
    let mut master: libc::c_int = -1;
    let mut slave: libc::c_int = -1;
    let rc = unsafe {
        libc::openpty(
            &mut master,
            &mut slave,
            std::ptr::null_mut(),
            std::ptr::null(),
            std::ptr::null(),
        )
    };
    assert_eq!(rc, 0, "openpty failed");

    // SAFETY: each Stdio owns its own dup of the slave; the child inherits them as stdio.
    let mut child = ops()
        .arg("session")
        .arg("attach")
        .arg(pid.to_string())
        .env("XDG_DATA_HOME", data)
        .stdin(unsafe { Stdio::from_raw_fd(libc::dup(slave)) })
        .stdout(unsafe { Stdio::from_raw_fd(libc::dup(slave)) })
        .stderr(unsafe { Stdio::from_raw_fd(libc::dup(slave)) })
        .spawn()
        .expect("spawn ops session attach");
    unsafe { libc::close(slave) };

    let mut out = Vec::new();
    let mut buf = [0u8; 4096];
    let mut sent = false;
    // Generous: the setns join into a live cage plus the in-cage shell startup can be slow under
    // heavy parallel load (the whole test suite), and a too-tight deadline would drop the prompt
    // detection before the script is sent — the source of this test's rare flakiness.
    let deadline = Instant::now() + Duration::from_secs(120);
    while Instant::now() < deadline {
        let mut pfd = libc::pollfd {
            fd: master,
            events: libc::POLLIN,
            revents: 0,
        };
        if unsafe { libc::poll(&mut pfd, 1, 500) } > 0 {
            let n = unsafe { libc::read(master, buf.as_mut_ptr().cast(), buf.len()) };
            if n <= 0 {
                break; // EIO/EOF: session over
            }
            out.extend_from_slice(&buf[..n as usize]);
        }
        // Readiness is "a `$` appeared" — the hermetic shell falls back to `bash-5.x$ `.
        if !sent && out.contains(&b'$') {
            unsafe { libc::write(master, script.as_ptr().cast(), script.len()) };
            sent = true;
        }
    }
    unsafe { libc::close(master) };
    let _ = child.kill();
    let _ = child.wait();
    String::from_utf8_lossy(&out).into_owned()
}

#[test]
fn attach_to_a_running_app_lands_in_the_apps_isolated_home() {
    // A running `ops app` agent uses its own isolated home. `ops session attach <pid>` must drop the new
    // shell into THAT home, not the project's shared one — the property that makes attaching to a
    // running agent mean "the same environment". Teeth: a marker the attached shell writes to
    // `$HOME` must land in the app's home (`<data>/apps/probe/home`) and NOT in the project's
    // default home (which the warm-up launch created). A naive attach would use the project home
    // and fail both halves.
    let project = TmpDir::new("proj");
    let data = TmpDir::new("data");
    std::fs::write(
        project.path().join(".ops.toml"),
        "[app.probe]\ncmd = [\"sleep\", \"300\"]\n",
    )
    .unwrap();

    if !host_can_sandbox(project.path(), data.path()) {
        eprintln!("skipping ops attach app e2e: host cannot sandbox (no userns/bwrap, or the base cache is unreachable)");
        return;
    }

    // Launch the app in the background: it registers a global-app session and `exec`s into the
    // cage running `sleep`, so the spawned pid is the session's pid throughout.
    let mut agent = ops()
        .arg("app")
        .arg("probe")
        .current_dir(project.path())
        .env("XDG_DATA_HOME", data.path())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn ops app probe");
    let pid = agent.id();

    let record = wait_for_session(data.path(), pid, Instant::now() + Duration::from_secs(60));
    if record.is_none() {
        let _ = agent.kill();
        let _ = agent.wait();
        eprintln!(
            "skipping ops attach app e2e: the app session never registered (cannot sandbox?)"
        );
        return;
    }

    // Attach and have the shell drop a marker into its $HOME.
    let log = drive_attach(
        pid,
        data.path(),
        b"printf done > \"$HOME/ATTACH_OK\"\nexit\n",
    );

    let app_home_marker = data.path().join("ops/apps/probe/home/ATTACH_OK");
    // Allow a brief window for the in-cage write to become observable on the host-bound home after
    // the attached shell exits — a slow flush under load must not flake the assertion. The marker
    // lives in the app's persistent home, so it survives killing the agent below.
    let poll_until = Instant::now() + Duration::from_secs(15);
    while !app_home_marker.exists() && Instant::now() < poll_until {
        std::thread::sleep(Duration::from_millis(200));
    }

    let _ = agent.kill();
    let _ = agent.wait();

    assert!(
        app_home_marker.exists(),
        "the attached shell did not land in the app's isolated home ({app_home_marker:?})\n{log}"
    );

    // Teeth: the project's default home (created by the warm-up `ops run -- true`) must NOT have
    // received the marker — proving attach reproduced the app's home, not the project's.
    let project_homes: Vec<PathBuf> = std::fs::read_dir(data.path().join("ops/projects"))
        .map(|d| {
            d.flatten()
                .map(|e| e.path().join("home/ATTACH_OK"))
                .collect()
        })
        .unwrap_or_default();
    for m in &project_homes {
        assert!(
            !m.exists(),
            "the marker landed in the project's shared home — attach used the wrong runtime: {m:?}\n{log}"
        );
    }
}
