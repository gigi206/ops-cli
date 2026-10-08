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
use common::fixture::TmpDir;
use common::pty::{Pty, Reaped};

use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

fn sbx() -> Command {
    Command::new(env!("CARGO_BIN_EXE_sbx"))
}

/// A launch that does nothing, run only to find out whether this host can build a cage at all. On
/// a capable host it also warms the userland cache, so the shell starts promptly.
///
/// Hands back the launch's own [`Output`] rather than a verdict, so `probe_or_skip!` can quote
/// what the refusal said: "host cannot sandbox" on its own names no cause, and the cause is the
/// only part a reader of a skipped run does not already know.
fn sandbox_probe(project: &Path, data: &Path) -> Output {
    sbx()
        .arg("run")
        .arg("--")
        .arg("true")
        .current_dir(project)
        .env("XDG_DATA_HOME", data)
        .output()
        .expect("spawn sbx run")
}

/// The terminal's end is reported when its own process ends, though another process was started
/// while it was open: that one holds no copy of either end ([`common::pty`]). A copy it held would
/// keep the session open past its end, and a test reading to that end would wait out its deadline.
#[test]
fn a_terminal_session_ends_with_its_process_though_another_was_started_meanwhile() {
    let mut pty = Pty::open(None);
    let _bystander = Reaped(
        Command::new("sleep")
            .arg("30")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn a bystander"),
    );
    let _child = Reaped(
        Command::new("/bin/sh")
            .args(["-c", "printf ready"])
            .stdin(pty.stdio())
            .stdout(pty.stdio())
            .stderr(pty.stdio())
            .spawn()
            .expect("spawn the terminal's process"),
    );
    pty.release_slave();
    let mut out = Vec::new();
    let started = Instant::now();
    while pty.read_into(&mut out, 300) {
        assert!(
            started.elapsed() < Duration::from_secs(10),
            "the session outlived its process: {}",
            String::from_utf8_lossy(&out)
        );
    }
    assert!(out.ends_with(b"ready"), "{}", String::from_utf8_lossy(&out));
}

#[test]
fn an_interactive_run_with_no_command_gives_the_sandbox_a_controlling_terminal() {
    let project = TmpDir::prefixed("sh", "proj");
    let data = TmpDir::prefixed("sh", "data");
    std::fs::write(project.path().join("MARKER"), b"x").expect("write the project's marker");

    probe_or_skip!(
        "interactive sbx run smoke",
        sandbox_probe(project.path(), data.path())
    );

    // A no-command `sbx run` opens an interactive shell when stdin is a terminal; give it a
    // pty and drive it through the master end.
    let mut pty = Pty::open(None);
    let _child = Reaped(
        sbx()
            .arg("run")
            .current_dir(project.path())
            .env("XDG_DATA_HOME", data.path())
            .stdin(pty.stdio())
            .stdout(pty.stdio())
            .stderr(pty.stdio())
            .spawn()
            .expect("spawn sbx run"),
    );
    pty.release_slave();

    // The script. `( : < /dev/tty )` succeeds only when the shell has a
    // controlling terminal — the whole point of the pty supervisor.
    //
    // Terminal-echo trap: the inner pty (cooked mode) echoes typed commands back, so a marker that
    // appeared verbatim in a command would show up from the echo alone and pass on a launch with no
    // controlling terminal. The marker is therefore assembled at *runtime* from a shell variable
    // (`$Y`): the echoed command carries `CTTY=$Y`, while only the executed branch prints the
    // expanded `CTTY=OK`.
    let script =
        b"Y=OK\nid -un\n( : < /dev/tty ) 2>/dev/null && echo CTTY=$Y || echo CTTY=no\nls\nexit\n";

    // Wait for the shell's first prompt before sending input: the supervisor
    // flushes pending input when it switches the terminal to raw mode (discarding
    // stale type-ahead), so a real user — and this test — types only once the
    // shell is ready. Readiness is the shared prompt predicate, which accepts both
    // characters bash renders `\$` as: the cage keeps the invoking uid, so a root
    // invoker sees the rc's prompt end in `#` where anyone else sees `$`. Then read
    // until the script's `exit` ends the session (the master reads EIO) or a deadline.
    let mut out = Vec::new();
    let deadline = Instant::now() + Duration::from_secs(30);
    assert!(
        pty.read_until(&mut out, deadline, common::shell_prompt_seen),
        "never reached the shell prompt to type the script:\n{}",
        String::from_utf8_lossy(&out)
    );
    pty.send(script);
    pty.read_until(&mut out, deadline, |_| false);

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
    let project = TmpDir::prefixed("sh", "obs-proj");
    let data = TmpDir::prefixed("sh", "obs-data");
    probe_or_skip!(
        "interactive-observe smoke",
        sandbox_probe(project.path(), data.path())
    );

    let mut pty = Pty::open(None);
    let child = Reaped(
        sbx()
            .arg("run")
            .arg("--observe")
            .current_dir(project.path())
            .env("XDG_DATA_HOME", data.path())
            .stdin(pty.stdio())
            .stdout(pty.stdio())
            .stderr(pty.stdio())
            .spawn()
            .expect("spawn sbx run --observe"),
    );
    pty.release_slave();
    // The observer roots on, and the control socket is keyed by, this sbx supervisor's pid — the same
    // one `sbx proc logs` resolves the session by.
    let pid = child.0.id();

    // Wait for the shell prompt, then spawn a recognizable child inside the cage.
    let mut out = Vec::new();
    assert!(
        pty.read_until(
            &mut out,
            Instant::now() + Duration::from_secs(30),
            common::shell_prompt_seen
        ),
        "never reached the shell prompt to spawn a child:\n{}",
        String::from_utf8_lossy(&out)
    );
    pty.send(b"sleep 20\n");

    // Read the ring back from THIS process: the socket must be populated even with no inline feed —
    // the whole point of the interactive path (its terminal belongs to the agent). The feed records
    // the `sleep`'s exec, which stays in it whether or not the `sleep` is still running.
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

    pty.send(b"exit\n");
    drop(pty);
    drop(child);

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
    let project = TmpDir::prefixed("sh", "appterm-proj");
    let data = TmpDir::prefixed("sh", "appterm-data");
    std::fs::write(
        project.path().join(".sbx.toml"),
        b"[app.term]\ncmd = [\"bash\", \"--norc\", \"-i\"]\n",
    )
    .expect("write the app's config");

    probe_or_skip!(
        "sbx app resize smoke",
        sandbox_probe(project.path(), data.path())
    );

    // An outer pty sized 24x80. sbx runs on the slave; the test drives the master.
    let mut pty = Pty::open(Some((24, 80)));

    // Make sbx itself own the *outer* pty as its controlling terminal, faithfully reproducing
    // production: in a real run sbx holds the launching terminal (Warp's), so resizing that
    // terminal delivers SIGWINCH to sbx *naturally* — no explicit signal. A `pre_exec` runs in the
    // forked sbx (after its stdio is set to the slave, before exec): `setsid` starts a fresh
    // session, then `ioctl(TIOCSCTTY)` claims fd 0's terminal as sbx's ctty. The cage's inner child
    // later gets its own private ctty via `login_tty`, leaving sbx the outer pty's foreground group.
    let mut command = sbx();
    command
        .arg("app")
        .arg("run")
        .arg("term")
        .current_dir(project.path())
        .env("XDG_DATA_HOME", data.path())
        .stdin(pty.stdio())
        .stdout(pty.stdio())
        .stderr(pty.stdio());
    // SAFETY: `setsid` and `ioctl(TIOCSCTTY)` are async-signal-safe. The spawn has moved the slave
    // onto the standard streams before `pre_exec` runs, so standard input is the slave.
    unsafe {
        command.pre_exec(|| {
            if libc::setsid() == -1 {
                return Err(std::io::Error::last_os_error());
            }
            if libc::ioctl(libc::STDIN_FILENO, libc::TIOCSCTTY, 0) == -1 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let child = Reaped(command.spawn().expect("spawn sbx app term"));
    pty.release_slave();

    // Arm the resize trap, confirm the controlling terminal, and print the initial size. The
    // markers `$Y`/`$W` expand only when the branch runs (see the echo note above).
    let setup = b"Y=YES; W=FIRED\n\
                  trap 'echo WINCH=$W' WINCH\n\
                  ( : < /dev/tty ) 2>/dev/null && echo CTTY=$Y || echo CTTY=no\n\
                  stty size\n";

    let mut out = Vec::new();
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
        if !pty.read_into(&mut out, 300) {
            break; // EIO/EOF: session over
        }
        let text = String::from_utf8_lossy(&out);

        // Once the shell prompt appears, send the setup block.
        if !sent_setup && common::shell_prompt_seen(&out) {
            pty.send(setup);
            sent_setup = true;
            continue;
        }

        // After the controlling terminal is confirmed and the initial 24x80 is seen, resize the
        // *outer* pty. Because sbx holds it as its ctty (the pre_exec above), the kernel delivers
        // SIGWINCH to sbx naturally — the exact production trigger of dragging Warp to fullscreen,
        // not a simulated signal. No explicit `kill`.
        if sent_setup && !resized && text.contains("CTTY=YES") && text.contains("24 80") {
            pty.resize(50, 200);
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
                    pty.resize(if toggle { 51 } else { 50 }, 200);
                } else {
                    pty.send(b"stty size\n");
                }
                last_probe = Instant::now();
            }
        }
    }

    pty.send(b"exit\n");
    drop(pty);
    drop(child);

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
