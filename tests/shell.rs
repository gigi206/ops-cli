//! Integration test for the interactive `sbx run` (no command): drive the shell it
//! opens through a pty and assert the *property* that separates it from a plain command
//! launch — the sandbox gets a controlling terminal, so job control works (not merely
//! "a command ran"). Skipped, not failed, where the host cannot sandbox.
//!
//! On a host with a systemd user session this also exercises the *wrapped* launch
//! chain: the pty supervisor's child becomes the resource-limit scope launcher,
//! which exec-chains into bubblewrap and then the shell. A `CTTY=OK` with no "no
//! job control" warning therefore proves job control survives that whole chain —
//! the load-bearing concern for putting the cage inside a transient scope.

#[macro_use]
mod common;

use std::os::fd::FromRawFd;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};

fn sbx() -> Command {
    Command::new(env!("CARGO_BIN_EXE_sbx"))
}

/// Where this suite's throwaway fixtures live: the repo's own test tree, overridable with
/// `SBX_TEST_TMPDIR`.
///
/// On the repo's disk, not the system tmpfs: provisioning a nix store copies a large file count,
/// which exhausts a tmpfs's inode budget (making the launch fail and the test skip). Disk has
/// inodes to spare, it matches production (the store lives on disk), and `cargo clean` reclaims it.
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

/// A unique temp dir removed on drop.
struct TmpDir(PathBuf);

impl TmpDir {
    fn new(tag: &str) -> Self {
        static COUNTER: AtomicU32 = AtomicU32::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let mut d = fixture_root();
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
    sbx()
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
fn an_interactive_run_with_no_command_gives_the_sandbox_a_controlling_terminal() {
    let project = TmpDir::new("proj");
    let data = TmpDir::new("data");
    std::fs::write(project.path().join("MARKER"), b"x").unwrap();

    if !host_can_sandbox(project.path(), data.path()) {
        skip_incapable!(
            "skipping interactive sbx run smoke: host cannot sandbox (no userns/bwrap, or the base cache is unreachable)"
        );
        return;
    }

    // A no-command `sbx run` opens an interactive shell when stdin is a terminal; give it a
    // pty and drive it through the master end.
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
    let mut child = sbx()
        .arg("run")
        .current_dir(project.path())
        .env("XDG_DATA_HOME", data.path())
        .stdin(unsafe { Stdio::from_raw_fd(libc::dup(slave)) })
        .stdout(unsafe { Stdio::from_raw_fd(libc::dup(slave)) })
        .stderr(unsafe { Stdio::from_raw_fd(libc::dup(slave)) })
        .spawn()
        .expect("spawn sbx run");
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
fn an_interactive_observed_run_records_events_for_proc_logs() {
    // Close the one observation assembly the other tests leave uncovered: the interactive pty
    // supervisor WITH `--observe`. On a pty, `sbx run --observe` takes the pty path (not the non-tty
    // foreground path the `--observe` stderr e2e covers, nor the detached one), so its observer must
    // populate the ring + control socket even though nothing echoes to the TUI-owned terminal. Drive
    // the shell to spawn a recognizable `sleep`, then read it back with `sbx proc logs` from this
    // process. Skipped, not failed, where the host cannot sandbox.
    let project = TmpDir::new("obs-proj");
    let data = TmpDir::new("obs-data");
    if !host_can_sandbox(project.path(), data.path()) {
        skip_incapable!(
            "skipping interactive-observe smoke: host cannot sandbox (no userns/bwrap, or the base cache is unreachable)"
        );
        return;
    }

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

    // SAFETY: each Stdio owns its own dup of the slave; the child inherits them as stdin/out/err.
    let mut child = sbx()
        .arg("run")
        .arg("--observe")
        .current_dir(project.path())
        .env("XDG_DATA_HOME", data.path())
        .stdin(unsafe { Stdio::from_raw_fd(libc::dup(slave)) })
        .stdout(unsafe { Stdio::from_raw_fd(libc::dup(slave)) })
        .stderr(unsafe { Stdio::from_raw_fd(libc::dup(slave)) })
        .spawn()
        .expect("spawn sbx run --observe");
    unsafe { libc::close(slave) };
    // The observer roots on, and the control socket is keyed by, this sbx supervisor's pid — the same
    // one `sbx proc logs` resolves the session by.
    let pid = child.id();

    // Wait for the shell prompt, then spawn a long-lived, recognizable child inside the cage.
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
        if unsafe { libc::poll(&mut pfd, 1, 300) } > 0 {
            let n = unsafe { libc::read(master, buf.as_mut_ptr().cast(), buf.len()) };
            if n <= 0 {
                break; // EIO/EOF: session over
            }
            out.extend_from_slice(&buf[..n as usize]);
        }
        if !sent && out.contains(&b'$') {
            unsafe { libc::write(master, b"sleep 20\n".as_ptr().cast(), 9) };
            sent = true;
            break;
        }
    }
    assert!(
        sent,
        "never reached the shell prompt to spawn a child:\n{}",
        String::from_utf8_lossy(&out)
    );

    // Read the ring back from THIS process: the socket must be populated even with no inline feed —
    // the whole point of the interactive path (its terminal belongs to the agent). Poll while `sleep`
    // is still running.
    let logs_deadline = Instant::now() + Duration::from_secs(20);
    let mut ok = false;
    let mut last = String::new();
    while Instant::now() < logs_deadline {
        let o = sbx()
            .arg("proc")
            .arg("logs")
            .arg(pid.to_string())
            .env("XDG_DATA_HOME", data.path())
            .output()
            .expect("run sbx proc logs");
        last = String::from_utf8_lossy(&o.stdout).into_owned();
        if o.status.code() == Some(0) && last.contains("sleep") {
            ok = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(300));
    }

    unsafe { libc::write(master, b"exit\n".as_ptr().cast(), 5) };
    unsafe { libc::close(master) };
    let _ = child.kill();
    let _ = child.wait();

    assert!(
        ok,
        "the interactive observed session's `sleep` must appear in `sbx proc logs` — the ring is \
         populated over the control socket even with no inline feed. Last output:\n{last}"
    );
}

#[test]
fn an_interactive_app_gets_a_controlling_terminal_and_live_resize() {
    // The reported bug: `sbx app <name>` launched interactively "stays small" when the terminal
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
        project.path().join(".sbx.toml"),
        b"[app.term]\ncmd = [\"bash\", \"--norc\", \"-i\"]\n",
    )
    .unwrap();

    if !host_can_sandbox(project.path(), data.path()) {
        skip_incapable!(
            "skipping sbx app resize smoke: host cannot sandbox (no userns/bwrap, or the base cache is unreachable)"
        );
        return;
    }

    // An outer pty sized 24x80. sbx runs on the slave; the test drives the master.
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

    // Make sbx itself own the *outer* pty as its controlling terminal, faithfully reproducing
    // production: in a real run sbx holds the launching terminal (Warp's), so resizing that
    // terminal delivers SIGWINCH to sbx *naturally* — no explicit signal. A `pre_exec` runs in the
    // forked sbx (after its stdio is set to the slave, before exec): `setsid` starts a fresh
    // session, then `ioctl(TIOCSCTTY)` claims fd 0's terminal as sbx's ctty. The cage's inner child
    // later gets its own private ctty via `login_tty`, leaving sbx the outer pty's foreground group.
    // SAFETY: each Stdio owns its own dup of the slave; the child inherits them as stdin/out/err.
    let mut command = sbx();
    command
        .arg("app")
        .arg("run")
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
    let mut child = command.spawn().expect("spawn sbx app term");
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
        // *outer* pty. Because sbx holds it as its ctty (the pre_exec above), the kernel delivers
        // SIGWINCH to sbx naturally — the exact production trigger of dragging Warp to fullscreen,
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
