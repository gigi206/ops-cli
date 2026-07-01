//! Integration test for `ops shell`: drive the interactive shell through a pty
//! and assert the *property* that separates it from `ops run` — the sandbox gets
//! a controlling terminal, so job control works (not merely "a command ran").
//! Skipped, not failed, where the host cannot sandbox.
//!
//! On a host with a systemd user session this also exercises the *wrapped* launch
//! chain: the pty supervisor's child becomes the resource-limit scope launcher,
//! which exec-chains into bubblewrap and then the shell. A `CTTY=OK` with no "no
//! job control" warning therefore proves job control survives that whole chain —
//! the load-bearing concern for putting the cage inside a transient scope.

use std::os::fd::FromRawFd;
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
        d.push(format!("ops-shell-it-{tag}-{}-{n}", std::process::id()));
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

/// Remove a tree that may contain read-only directories: a provisioned nix store
/// makes its directories `0555`, so add write on the way down before deleting.
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

/// Whether the host can launch a sandbox (also warms the userland cache so the
/// shell starts promptly).
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

#[test]
fn shell_gives_the_sandbox_a_controlling_terminal() {
    let project = TmpDir::new("proj");
    let data = TmpDir::new("data");
    std::fs::write(project.path().join("MARKER"), b"x").unwrap();

    if !host_can_sandbox(project.path(), data.path()) {
        eprintln!("skipping ops shell smoke: host cannot sandbox (no userns/bwrap, or the base cache is unreachable)");
        return;
    }

    // `ops shell` needs a tty on stdin; give it a pty and drive it through the
    // master end.
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

    // SAFETY: each Stdio owns its own dup of the slave; the child inherits them
    // as stdin/out/err.
    let mut child = ops()
        .arg("shell")
        .current_dir(project.path())
        .env("XDG_DATA_HOME", data.path())
        .stdin(unsafe { Stdio::from_raw_fd(libc::dup(slave)) })
        .stdout(unsafe { Stdio::from_raw_fd(libc::dup(slave)) })
        .stderr(unsafe { Stdio::from_raw_fd(libc::dup(slave)) })
        .spawn()
        .expect("spawn ops shell");
    unsafe { libc::close(slave) };

    // The script. `( : < /dev/tty )` succeeds only when the shell has a
    // controlling terminal — the whole point of the pty supervisor.
    let script =
        b"id -un\n( : < /dev/tty ) 2>/dev/null && echo CTTY=OK || echo CTTY=NO\nls\nexit\n";

    // Wait for the shell's first prompt before sending input: the supervisor
    // flushes pending input when it switches the terminal to raw mode (discarding
    // stale type-ahead), so a real user — and this test — types only once the
    // shell is ready. Readiness is "a `$` appeared" — the hermetic shell has no
    // PS1 so bash falls back to `bash-5.3$ `; a future `$`-less base prompt would
    // make this wait to the deadline (then fail) rather than misfire. Read until
    // the master closes (child exited -> EIO on Linux) or a deadline.
    let mut out = Vec::new();
    let mut buf = [0u8; 4096];
    let mut sent = false;
    let deadline = Instant::now() + Duration::from_secs(30);
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
        if !sent && out.contains(&b'$') {
            unsafe { libc::write(master, script.as_ptr().cast(), script.len()) };
            sent = true;
        }
    }
    unsafe { libc::close(master) };
    let _ = child.kill();
    let _ = child.wait();

    let text = String::from_utf8_lossy(&out);
    assert!(text.contains("sandbox"), "no synthetic identity:\n{text}");
    assert!(
        text.contains("CTTY=OK"),
        "the sandbox has no controlling terminal — job control is broken:\n{text}"
    );
    assert!(
        !text.contains("no job control"),
        "bash reported no job control:\n{text}"
    );
    assert!(text.contains("MARKER"), "project not visible:\n{text}");
}
