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
use std::os::unix::process::CommandExt;
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
        // On the repo's disk, not the system tmpfs: provisioning a nix store copies a large file
        // count, which exhausts a tmpfs's inode budget (making the launch fail and the test skip).
        // Disk has inodes to spare, and it matches production (the store lives on disk). A short
        // prefix keeps any bound socket path under `sun_path`'s 108-byte cap. `cargo clean`
        // reclaims it.
        let mut d = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        d.push("target/test-tmp");
        d.push(format!("sh-{tag}-{}-{n}", std::process::id()));
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

#[test]
fn an_interactive_app_gets_a_controlling_terminal_and_live_resize() {
    // The reported bug: `ops app <name>` launched interactively "stays small" when the terminal
    // goes fullscreen. An interactive app now runs under the pty supervisor, so it must (1) get a
    // private controlling terminal and (2) see a resize propagate live. The faithful proxy for a
    // caching TUI (like claude-code) is not "stty reports the new size" but "the inner process is
    // *notified*" — so the inner shell arms `trap ... WINCH` and we assert the trap fires.
    //
    // Terminal-echo trap: the inner pty (cooked mode) echoes typed commands back, so a marker that
    // appears verbatim in a command (`CTTY=OK`, `GOTWINCH`) would show up from the echo alone and
    // give a false pass on broken code. The markers are therefore assembled at *runtime* from
    // shell variables (`$Y`, `$W`): the echoed command carries `CTTY=$Y` / `WINCH=$W`, while only
    // the executed branch prints the expanded `CTTY=YES` / `WINCH=FIRED`. So the assertions have
    // teeth — they fail on a launch with no controlling terminal or no resize delivery.
    let project = TmpDir::new("appterm-proj");
    let data = TmpDir::new("appterm-data");
    std::fs::write(
        project.path().join(".ops.toml"),
        b"[app.term]\ncmd = [\"bash\", \"--norc\", \"-i\"]\n",
    )
    .unwrap();

    if !host_can_sandbox(project.path(), data.path()) {
        eprintln!("skipping ops app resize smoke: host cannot sandbox (no userns/bwrap, or the base cache is unreachable)");
        return;
    }

    // An outer pty sized 24x80. ops runs on the slave; the test drives the master.
    let mut ws: libc::winsize = unsafe { std::mem::zeroed() };
    ws.ws_row = 24;
    ws.ws_col = 80;
    let mut master: libc::c_int = -1;
    let mut slave: libc::c_int = -1;
    let rc = unsafe {
        libc::openpty(
            &mut master,
            &mut slave,
            std::ptr::null_mut(),
            std::ptr::null(),
            &ws,
        )
    };
    assert_eq!(rc, 0, "openpty failed");

    // Make ops itself own the *outer* pty as its controlling terminal, faithfully reproducing
    // production: in a real run ops holds the launching terminal (Warp's), so resizing that
    // terminal delivers SIGWINCH to ops *naturally* — no explicit signal. A `pre_exec` runs in the
    // forked ops (after its stdio is set to the slave, before exec): `setsid` starts a fresh
    // session, then `ioctl(TIOCSCTTY)` claims fd 0's terminal as ops's ctty. The cage's inner child
    // later gets its own private ctty via `login_tty`, leaving ops the outer pty's foreground group.
    // SAFETY: each Stdio owns its own dup of the slave; the child inherits them as stdin/out/err.
    let mut command = ops();
    command
        .arg("app")
        .arg("term")
        .current_dir(project.path())
        .env("XDG_DATA_HOME", data.path())
        .stdin(unsafe { Stdio::from_raw_fd(libc::dup(slave)) })
        .stdout(unsafe { Stdio::from_raw_fd(libc::dup(slave)) })
        .stderr(unsafe { Stdio::from_raw_fd(libc::dup(slave)) });
    // SAFETY: `setsid` and `ioctl(TIOCSCTTY)` are async-signal-safe; fd 0 is the inherited slave.
    unsafe {
        command.pre_exec(|| {
            if libc::setsid() == -1 {
                return Err(std::io::Error::last_os_error());
            }
            if libc::ioctl(0, libc::TIOCSCTTY, 0) == -1 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let mut child = command.spawn().expect("spawn ops app term");
    unsafe { libc::close(slave) };

    // Arm the resize trap, confirm the controlling terminal, and print the initial size. The
    // markers `$Y`/`$W` expand only when the branch runs (see the echo note above).
    let setup = b"Y=YES; W=FIRED\n\
                  trap 'echo WINCH=$W' WINCH\n\
                  ( : < /dev/tty ) 2>/dev/null && echo CTTY=$Y || echo CTTY=no\n\
                  stty size\n";

    let mut out = Vec::new();
    let mut buf = [0u8; 4096];
    let mut sent_setup = false;
    let mut resized = false;
    // Alternates the resized row so each re-issue is a genuine size *change* (see the post-resize
    // block): a single resize sends one SIGWINCH, which — under job control — a transient foreground
    // `stty` process group can absorb before the shell ever sees it, and the size then never changes
    // again, so the shell's trap would never fire. Re-issuing keeps delivering fresh signals until
    // one lands while the shell idles at its prompt.
    let mut toggle = false;
    // The loop exits the instant both markers appear — the re-issued resize makes that reliable
    // rather than luck-of-the-timing, so this deadline is just a generous backstop (the test
    // completes in well under a minute even with the whole suite in parallel).
    let deadline = Instant::now() + Duration::from_secs(60);
    let mut last_probe = Instant::now();

    while Instant::now() < deadline {
        let mut pfd = libc::pollfd {
            fd: master,
            events: libc::POLLIN,
            revents: 0,
        };
        if unsafe { libc::poll(&mut pfd, 1, 300) } > 0 {
            let n = unsafe { libc::read(master, buf.as_mut_ptr().cast(), buf.len()) };
            if n <= 0 {
                break; // EIO/EOF: session over
            }
            out.extend_from_slice(&buf[..n as usize]);
        }
        let text = String::from_utf8_lossy(&out);

        // Once the shell prompt appears, send the setup block.
        if !sent_setup && text.contains('$') {
            unsafe { libc::write(master, setup.as_ptr().cast(), setup.len()) };
            sent_setup = true;
            continue;
        }

        // After the controlling terminal is confirmed and the initial 24x80 is seen, resize the
        // *outer* pty. Because ops holds it as its ctty (the pre_exec above), the kernel delivers
        // SIGWINCH to ops naturally — the exact production trigger of dragging Warp to fullscreen,
        // not a simulated signal. No explicit `kill`.
        if sent_setup && !resized && text.contains("CTTY=YES") && text.contains("24 80") {
            let mut big: libc::winsize = unsafe { std::mem::zeroed() };
            big.ws_row = 50;
            big.ws_col = 200;
            unsafe { libc::ioctl(master, libc::TIOCSWINSZ, &big) };
            resized = true;
            last_probe = Instant::now();
        }

        // After the resize, confirm the inner size reflects 50x200, then keep the trap fed until it
        // fires. First probe once for the propagated size (a foreground `stty size`). Once 50x200 is
        // seen, stop probing and instead re-issue the resize as a real change (toggle a row) every
        // cycle: this both delivers a fresh SIGWINCH the idle shell can catch — a single one can be
        // absorbed by a transient foreground process group — and, by not spawning more `stty`
        // children, leaves the shell idle at its prompt to receive it. 50x200 stays satisfied (it was
        // captured on the first probe).
        if resized {
            if text.contains("50 200") && text.contains("WINCH=FIRED") {
                break;
            }
            if last_probe.elapsed() >= Duration::from_millis(300) {
                if text.contains("50 200") {
                    toggle = !toggle;
                    let mut sz: libc::winsize = unsafe { std::mem::zeroed() };
                    sz.ws_row = if toggle { 51 } else { 50 };
                    sz.ws_col = 200;
                    unsafe { libc::ioctl(master, libc::TIOCSWINSZ, &sz) };
                } else {
                    unsafe { libc::write(master, b"stty size\n".as_ptr().cast(), 10) };
                }
                last_probe = Instant::now();
            }
        }
    }

    unsafe { libc::write(master, b"exit\n".as_ptr().cast(), 5) };
    unsafe { libc::close(master) };
    let _ = child.kill();
    let _ = child.wait();

    let text = String::from_utf8_lossy(&out);
    assert!(
        text.contains("CTTY=YES"),
        "the interactive app has no controlling terminal:\n{text}"
    );
    assert!(
        text.contains("24 80"),
        "the initial 24x80 window size was not observed:\n{text}"
    );
    assert!(
        text.contains("50 200"),
        "the resize did not propagate to the cage pty:\n{text}"
    );
    assert!(
        text.contains("WINCH=FIRED"),
        "the inner process was not notified of the resize (SIGWINCH not delivered to the cage):\n{text}"
    );
}
