//! Launching a sandbox: turning a [`SandboxSpec`] into a running bubblewrap
//! process.
//!
//! Two launch models, by terminal policy:
//! - **non-interactive** (`sbx run` with a piped/non-tty stdin, or `--detach`): it execs
//!   bwrap and lets it *replace* the sbx process, so the command inherits the real stdio
//!   and its exit status becomes sbx's. The spec uses [`TerminalPolicy::NewSession`].
//! - **interactive** (`sbx run` on a real terminal — a shell when no command is given, or
//!   an interactive command): sbx stays alive as a **pty supervisor**. It
//!   gives the sandbox a private controlling terminal (so job control works
//!   inside) and relays bytes to and from the real terminal (which the sandbox
//!   therefore cannot reach). The spec uses [`TerminalPolicy::PrivateTty`], which
//!   omits `--new-session` — bubblewrap's `setsid` would `setsid` away from that
//!   private terminal.
//!
//! The supervisor also relays terminal resizes: it catches `SIGWINCH` on the real
//! terminal and pushes the new window size onto the pty master, so the kernel
//! delivers `SIGWINCH` to the cage's foreground process group and an interactive
//! TUI reflows live. Interactive `sbx app` launches ride this same supervisor.
//!
//! Known gaps in the supervisor (named, not silent):
//! - terminal-state restore is a RAII guard, so it covers normal/error/panic
//!   exits but not a `SIGTERM`/`SIGHUP` kill;
//! - the relay is single-threaded with a blocking `write_all` to the master, so a
//!   pathological simultaneous flood (the inner shell not draining its input while
//!   also flooding output) could stall it. Humans don't trigger it and `script(1)`
//!   shares the limitation; a split-direction or non-blocking relay is the fix.

use super::binds::{self, Userland};
use super::broker;
use super::egress;
use super::forward;
use super::pty::{RawMode, WinchRelay, copy_winsize, pump};
use super::spec::{NetPolicy, SandboxSpec, TerminalPolicy};
use super::sshagent;
use crate::session::{self, Kind, RecordGuard, Session};
use crate::store::Layout;
use std::ffi::{CString, OsString};
use std::fs::File;
use std::io;
use std::io::IsTerminal;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::io::{AsRawFd, FromRawFd};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};
use std::sync::{Arc, RwLock};
use std::time::Duration;

/// The hard prerequisites and per-launch resolution shared by `run` and `shell`:
/// the engine, sbx's store layout, the current directory, the resolved
/// configuration, the effective nixpkgs reference for this launch, and the base
/// userland (provisioned against that same reference).
///
/// A single effective reference drives the **whole** sandbox — both the base
/// userland and the project's tools. They must share it: the base glibc is exported
/// on `LD_LIBRARY_PATH` (for foreign binaries) and is searched before a tool's own
/// `RUNPATH`, so a tool resolved against a *different* glibc would load the base
/// `libc.so.6` under its own loader and crash on a `GLIBC_PRIVATE` skew. One channel
/// per launch keeps base, tools, and `LD_LIBRARY_PATH` on one glibc.
struct Prepared {
    bwrap: PathBuf,
    nix: PathBuf,
    /// The `nix-store` command, used to seed and register the per-project store the
    /// cage's writable `/nix` is backed by.
    nix_store: PathBuf,
    layout: Layout,
    cwd: PathBuf,
    cfg: crate::config::Resolved,
    /// The effective reference for this launch: a project pin when one is set,
    /// otherwise the global channel. Drives the base userland (its OS substrate) and
    /// the project's tools. **Not** the reference for the mise engine — see `engine`.
    nixpkgs: String,
    /// The reference for the mise engine, from its dedicated lock (it tracks the global
    /// channel but rolls independently via `sbx upgrade mise`). mise runs in its own
    /// store view, free of the one-channel rule, so it may sit on a different revision
    /// than `nixpkgs`. Drives both the in-cage mise (the base userland) and the
    /// host-side `[env]` driver.
    engine_ref: String,
    userland: Userland,
    /// Suppress the per-launch "equipping app packages in-cage" informational line. Set on the batch
    /// `sbx upgrade` path, where it repeats for every app and buries the one thing that matters —
    /// which app actually rolled; left `false` for an ordinary launch, where it tells the user what
    /// is being equipped.
    quiet_equip: bool,
}

/// `sbx run [--] [<cmd>]`: run a command inside the project sandbox, or — with no command — open
/// the project shell. The launch mode follows stdin: a real terminal (and not `--detach`) runs
/// interactively under the pty supervisor, so a shell or a TUI gets a private controlling terminal
/// with job control; a piped/non-tty stdin, or `--detach`, keeps the exec-replace / supervised path
/// (stdio inherited, exit status propagated).
pub(crate) fn run(
    cmd: Vec<OsString>,
    detach: bool,
    observe: bool,
    ov: crate::config::Override,
) -> ExitCode {
    // With no command, `sbx run` opens the project shell — which needs a terminal, so a detached
    // no-command launch is refused rather than started into the void.
    if cmd.is_empty() && detach {
        crate::diag::error(
            "sbx: `sbx run --detach` needs a command (a detached shell has no terminal).",
        );
        return ExitCode::from(2);
    }
    let mut prep = match prepare_with(&ov, None) {
        Ok(p) => p,
        Err(code) => return code,
    };
    // The override is the authoritative final word over the resolved baseline (`sbx run` has no app
    // overlay, so here is that final point).
    if let Err(code) = apply_launch_override(&mut prep.cfg, ov) {
        return code;
    }

    // SAFETY: `isatty` only inspects fd 0.
    let interactive = !detach && unsafe { libc::isatty(0) } == 1;

    // Observation runs on any path where a parent sbx survives the cage. Its inline stderr feed rides
    // only the non-tty foreground path under a non-enforcing `[proc]` mode; the launches that take it
    // away are told so, and pointed at `sbx proc logs`/`sbx proc live` for the same events.
    warn_observe_feed_absent(observe, interactive, &prep.cfg.proc);

    if cmd.is_empty() {
        // No command: open the project shell. Interactive gets the full pty shell (mise activation
        // and the `(sbx-<slug>)` prompt via the synthetic rc); a piped stdin runs a non-interactive
        // shell reading its script from stdin, reaching activated tools through the shims on PATH.
        return if interactive {
            launch_interactive_shell(&prep, binds::Runtime::ProjectDefault, observe)
        } else {
            let shell = vec![prep.userland.shell_bin.clone().into_os_string()];
            launch(
                prep,
                binds::Runtime::ProjectDefault,
                Kind::Shell,
                shell,
                false,
                "run",
                observe,
            )
        };
    }

    if interactive {
        launch_pty_supervised(
            &prep,
            binds::Runtime::ProjectDefault,
            Kind::Run,
            cmd,
            observe,
        )
    } else {
        launch(
            prep,
            binds::Runtime::ProjectDefault,
            Kind::Run,
            cmd,
            detach,
            "run",
            observe,
        )
    }
}

/// Which observation lenses a launch runs, from its resolved `[proc]` policy and the `--observe` flag.
/// The poll exec lens runs when observation is asked for but enforcement is **not** in effect — an
/// enforcing launch (`enforce`/`ask`) uses the seccomp user-notification supervisor as its exec source
/// instead, and that supervisor already owns the proc control socket, so the poll observer must not
/// also bind it. The inotify fs lens follows the `--observe` flag. Returns `(exec_poll, fs)`.
fn observation_flags(proc: &crate::proc_policy::ProcPolicy, observe: bool) -> (bool, bool) {
    let exec_poll = !proc.enforcing()
        && (observe || matches!(proc.mode, crate::proc_policy::ProcMode::Observe));
    (exec_poll, observe)
}

/// Why `--observe`'s inline `[sbx:exec]` feed will not appear, or `None` when it will.
///
/// The feed rides one path only: a non-tty foreground launch whose exec observation is the poller.
/// Two things take it away, and both otherwise leave the flag reading as applied — the launch
/// accepts it, prints nothing, and streams nothing:
///
/// - an interactive terminal, where the feed would fight the command's own screen;
/// - an enforcing `[proc]` mode, where the exec lens is the seccomp supervisor rather than the
///   poller ([`observation_flags`] clears `exec_poll` for exactly this set of modes), so nothing
///   feeds the inline stream.
///
/// The enforcing case is worth stating plainly rather than implying a loss: the lens then sees
/// *more* than the poller ever does, intercepting every `execve` including processes far too
/// short-lived to appear in a sampled snapshot of `/proc`. The events exist; only the inline path is
/// missing. Both cases therefore point at the same place to read them.
///
/// Separated from the printing so the decision can be asserted without capturing stderr, and so the
/// two launch paths that warn cannot drift apart.
fn observe_feed_absent_reason(
    observe: bool,
    interactive: bool,
    proc: &crate::proc_policy::ProcPolicy,
) -> Option<&'static str> {
    if !observe {
        return None;
    }
    if proc.enforcing() {
        return Some(
            "an enforcing `[proc]` mode watches every exec through the seccomp lens instead of the \
             inline feed",
        );
    }
    interactive.then_some("the inline feed is not shown for an interactive terminal")
}

/// Warn that `--observe`'s inline stderr feed is not shown for an interactive terminal (it would
/// fight a TUI for the screen), pointing at the out-of-band viewers instead. Observation itself still
/// runs — the ring and its control socket are populated so `sbx proc logs`/`sbx proc live` can watch
/// this session from another terminal; only the inline echo is suppressed, and that decision is made
/// per launch path where the observer is started (interactive/detached never echo inline). Shared by
/// `run`/`app`.
fn warn_observe_feed_absent(
    observe: bool,
    interactive: bool,
    proc: &crate::proc_policy::ProcPolicy,
) {
    if let Some(reason) = observe_feed_absent_reason(observe, interactive, proc) {
        crate::diag::warn(&format!(
            "--observe: {reason} — watch this session with `sbx proc logs`/`sbx proc live`"
        ));
    }
}

/// Apply the (non-channel) part of a one-shot override to a prepared config, aborting the launch
/// with a pointed error (exit 2) when it sets an invalid scalar security value — there is no safe
/// baseline fallback for one, so it is refused rather than run at the wrong posture. Shared by
/// `run`/`shell`/`app`, each applying the override at its own final point (after any app overlay).
fn apply_launch_override(
    cfg: &mut crate::config::Resolved,
    ov: crate::config::Override,
) -> Result<(), ExitCode> {
    cfg.apply_override(ov).map_err(|errs| {
        for e in errs {
            crate::diag::error(&format!("sbx: {e}"));
        }
        ExitCode::from(2)
    })
}

/// Build the cage, register it, and run it — either in the foreground (this process becomes or
/// supervises the cage) or detached into a background daemon. The single seam `run`, `app`, and
/// the mise passthrough share, so the build → register → launch sequence is identical on both
/// paths and lives in one place. `label` names the session in the detached startup message.
#[allow(clippy::too_many_arguments)]
fn launch(
    prep: Prepared,
    runtime: binds::Runtime,
    kind: Kind,
    cmd: Vec<OsString>,
    detach: bool,
    label: &str,
    observe: bool,
) -> ExitCode {
    if detach {
        warn_ask_under_detach(&prep.cfg.network);
        launch_detached(prep, runtime, kind, cmd, label, observe)
    } else {
        launch_foreground(prep, runtime, kind, cmd, observe)
    }
}

/// Warn when an `ask`-posture launch is detached with no timeout. A background session has no
/// terminal to surface the park notice, so an undecided request waits indefinitely (the default).
/// The launch still proceeds — the user chose both `ask` and `--detach` — but the footgun is named,
/// with the two ways out. A configured `ask_timeout`, or a non-ask posture, is silent.
fn warn_ask_under_detach(network: &crate::config::NetworkPolicy) {
    use crate::allowlist::DefaultAction;
    if let crate::config::NetworkPolicy::Allowlist(policy) = network
        && policy.default_action() == DefaultAction::Ask
        && policy.ask_timeout().is_none()
    {
        crate::diag::warn(
            "`ask` egress under --detach with no `ask_timeout`: a background session has no \
                 terminal to prompt, so an undecided request parks indefinitely. Set \
                 `[network] ask_timeout`, or answer it with `sbx net pending`.",
        );
    }
}

/// Run the cage in the foreground: this process becomes the cage (exec) or supervises it
/// (allowlist), and its exit status becomes sbx's.
fn launch_foreground(
    prep: Prepared,
    runtime: binds::Runtime,
    kind: Kind,
    cmd: Vec<OsString>,
    observe: bool,
) -> ExitCode {
    let (spec, guard) = match build(&prep, runtime, cmd) {
        Ok(v) => v,
        Err(code) => return code,
    };

    register(prep.layout.data_dir(), &spec, kind, runtime, false);

    match guard {
        // The default postures with no observation: exec-replace, so the command's exit status
        // becomes sbx's. The pid and its start time survive the exec, so the registry record keeps
        // matching the sandbox and is reclaimed by liveness pruning once it exits.
        None if !observe => {
            // On success this never returns; reaching past it means exec itself failed.
            let err = exec(&prep.bwrap, &spec, &prep.cfg.limits);
            crate::diag::error(&format!("sbx: failed to launch the sandbox: {err}"));
            ExitCode::FAILURE
        }
        // Supervise instead of exec-replace — fork bwrap, wait, propagate the exit status — whenever
        // a host-side thing must outlive the cage. That is a guard (a network allowlist's filtering
        // proxy, a forward forwarder, a filtered D-Bus proxy, or an in-cage portal whose runtime dir
        // must be cleaned up), OR observation: the observer runs in a host thread that needs a live
        // parent for the cage's lifetime, so observation forces supervision even with no guard. The
        // observer roots on this supervisor's own pid — the cage is its descendant in host pid-space —
        // and its socket + poll thread are torn down on drop, before the guard is released. `inline`
        // is true here: this is the non-tty foreground path, the one place the `[sbx:exec]` feed
        // streams to stderr (as well as into the ring `sbx proc logs` reads).
        maybe_guard => {
            let (exec_poll, fs) = observation_flags(&prep.cfg.proc, observe);
            let observer = (exec_poll || fs).then(|| {
                super::observe_feed::Observation::start(
                    prep.layout.data_dir(),
                    &spec.workdir,
                    exec_poll,
                    fs,
                    true,
                )
            });
            let code = run_supervised(&prep.bwrap, &spec, &prep.cfg.limits);
            drop(observer);
            drop(maybe_guard);
            code
        }
    }
}

/// The byte the detached child writes to the readiness pipe once the cage is built, registered,
/// and its log is open — the parent treats any other outcome (a closed pipe, no byte) as failure.
const DETACH_READY: u8 = 1;

/// Launch the cage as a background daemon and return to the caller's shell once it is ready.
///
/// The work is split across a `fork` for one structural reason: under a network allowlist the
/// cage's host filtering proxy runs on a thread, and a thread does not survive `fork` — only the
/// forking thread does. So the daemon must call [`build`] (which spawns that thread) *itself*,
/// after the fork. The process is single-threaded at this point (nothing before [`build`] spawns
/// a thread), which is what makes it safe for the child to run arbitrary code before `exec`.
///
/// A readiness pipe makes the handoff honest rather than blind: the child reports success only
/// after the cage is built, registered, and its log opened, so the parent returns a real session
/// id — not "started" for a daemon that then failed to provision with no terminal to show it. Any
/// setup error is printed to the caller's terminal (the child keeps it until success) before the
/// daemon redirects its output to the log.
fn launch_detached(
    prep: Prepared,
    runtime: binds::Runtime,
    kind: Kind,
    cmd: Vec<OsString>,
    label: &str,
    observe: bool,
) -> ExitCode {
    let mut fds = [0 as libc::c_int; 2];
    // SAFETY: `pipe2` fills the two-element array; `O_CLOEXEC` so neither end leaks into the
    // eventual `exec` of bwrap.
    if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
        crate::diag::error(&format!(
            "sbx: cannot create the detach pipe: {}",
            io::Error::last_os_error()
        ));
        return ExitCode::FAILURE;
    }
    let (read_fd, write_fd) = (fds[0], fds[1]);

    // SAFETY: the process is single-threaded here, so the child may safely run code (allocate,
    // build the cage, spawn the proxy thread) before any `exec`.
    match unsafe { libc::fork() } {
        -1 => {
            unsafe {
                libc::close(read_fd);
                libc::close(write_fd);
            }
            crate::diag::error(&format!(
                "sbx: cannot start the detached session: {}",
                io::Error::last_os_error()
            ));
            ExitCode::FAILURE
        }
        0 => {
            // Child: the parent's read end is not ours.
            unsafe { libc::close(read_fd) };
            detached_child(prep, runtime, kind, cmd, write_fd, observe)
        }
        child => {
            // Parent: the child's write end is not ours.
            unsafe { libc::close(write_fd) };
            detach_parent(read_fd, child, prep.layout.data_dir(), label)
        }
    }
}

/// The daemon body. Detaches from the controlling terminal, builds and registers the cage with
/// its output still on the terminal (so setup errors are visible), signals readiness, then
/// redirects to the session log and runs the cage. Never returns: every path ends in `exec`
/// (which replaces the process) or [`std::process::exit`], so the parent's tail logic can never
/// run a second time in the child. With `observe`, it also stands up the process observer — which,
/// like a guard, forces the supervised (fork+wait) path so a live parent outlives the cage.
fn detached_child(
    prep: Prepared,
    runtime: binds::Runtime,
    kind: Kind,
    cmd: Vec<OsString>,
    write_fd: libc::c_int,
    observe: bool,
) -> ! {
    // A new session with no controlling terminal: closing the launching terminal will not SIGHUP
    // the daemon, and it is no longer in that terminal's foreground process group.
    // SAFETY: `setsid` in the freshly forked child.
    unsafe { libc::setsid() };
    // The daemon reads no input; take stdin off the terminal now. stdout/stderr stay on the
    // terminal through build/register so provisioning progress and any error are seen live.
    redirect_stdin_to_null();

    let (spec, guard) = match build(&prep, runtime, cmd) {
        Ok(v) => v,
        // `build` already printed the cause to the terminal; close the pipe (no readiness byte)
        // so the parent reports failure.
        Err(_) => fail_detached(write_fd),
    };
    register(prep.layout.data_dir(), &spec, kind, runtime, true);

    // Open the session log before signalling ready: a daemon whose output we cannot capture is
    // not ready. Its name is keyed by this process's pid — the session id the parent reports.
    let log_path = detach_log_path(prep.layout.data_dir(), std::process::id());
    let log = match open_detach_log(&log_path) {
        Ok(f) => f,
        Err(e) => {
            crate::diag::error(&format!(
                "sbx: cannot open the session log {}: {e}",
                log_path.display()
            ));
            fail_detached(write_fd);
        }
    };

    // What the trust gate dropped went to the launching terminal, which this session is about to
    // lose. Note it in the log while the warnings are still in hand and before the agent's own
    // output starts, so the record survives the terminal that carried the announcement.
    note_trust_drops(
        &log,
        &prep.cfg.warnings,
        guard.as_ref().and_then(|g| g.notify_sink.as_deref()),
    );

    // Ready: tell the parent, then hand stdout/stderr to the log and drop the pipe.
    signal_detach_ready(write_fd);
    redirect_to_log(&log);
    unsafe { libc::close(write_fd) };
    // The log fd is now duplicated onto 1/2; the owning handle is no longer needed.
    drop(log);

    // Enable process observation (best-effort). A detached session has no terminal for an inline
    // feed, so the ring + control socket `sbx proc logs` reads are the ONLY way to watch it — and,
    // like a guard, the observer needs a live parent, so it forces the supervised path below even
    // with no guard (a would-be exec-replace becomes fork+wait). `inline` is false: nothing streams
    // to the redirected stderr (the session log).
    let (exec_poll, fs) = observation_flags(&prep.cfg.proc, observe);
    let observer = (exec_poll || fs).then(|| {
        super::observe_feed::Observation::start(
            prep.layout.data_dir(),
            &spec.workdir,
            exec_poll,
            fs,
            false,
        )
    });

    match guard {
        None if !observe => {
            // exec-replace: bwrap (pid 1 of the cage's namespace) inherits the redirected stdio.
            let err = exec(&prep.bwrap, &spec, &prep.cfg.limits);
            crate::diag::error(&format!("sbx: failed to launch the sandbox: {err}"));
            std::process::exit(1);
        }
        maybe_guard => {
            // Supervise: this daemon is the long-lived parent the proxy/forwarder threads, the
            // observer, and bwrap (`--die-with-parent`) hang from. Drop the guard and observer
            // explicitly before exiting — a bare `process::exit` runs no destructors, so their
            // sockets would otherwise leak even on a clean exit.
            let code = run_status(&prep.bwrap, &spec, &prep.cfg.limits);
            drop(observer);
            drop(maybe_guard);
            std::process::exit(code);
        }
    }
}

/// Wait for the daemon's readiness byte, then report. On success the daemon is reparented to init
/// and runs on; the parent must *not* `waitpid` it (that would block until the agent exits and
/// defeat detaching). On failure the daemon has already exited after printing its error, so reap
/// it to avoid a zombie.
fn detach_parent(
    read_fd: libc::c_int,
    child: libc::pid_t,
    data_dir: &Path,
    label: &str,
) -> ExitCode {
    // A `File` over the owned read end: its `read` retries `EINTR`, and dropping it closes the fd.
    // SAFETY: `read_fd` is a fresh fd we own and do not use elsewhere.
    let mut pipe = unsafe { File::from_raw_fd(read_fd) };
    let mut byte = [0u8; 1];
    use std::io::Read;
    if matches!(pipe.read(&mut byte), Ok(1) if byte[0] == DETACH_READY) {
        let log = detach_log_path(data_dir, child as u32);
        crate::diag::error(&format!(
            "sbx: started `{label}` as detached session {child} (logs: {})",
            log.display()
        ));
        // `sbx session logs` takes the id explicitly and the registry drops a session's record the
        // moment it dies, so this line is the one place the id and the way to read its output
        // appear together — name the log verb here or a session that fails overnight leaves the
        // user with a path they must reconstruct by hand.
        crate::diag::hint(&format!(
            "sbx: `sbx session logs {child}` shows its output (`-f` to follow), \
             `sbx session attach {child}` opens a shell inside its live cage, \
             `sbx session stop {child}` ends it; `sbx session ls` lists it."
        ));
        ExitCode::SUCCESS
    } else {
        // The daemon closed the pipe without signalling success: it failed before launch (the
        // error is already on this terminal). Reap it.
        // SAFETY: `waitpid` on our own child.
        unsafe { libc::waitpid(child, std::ptr::null_mut(), 0) };
        crate::diag::error("sbx: the detached session failed to start (see the error above).");
        ExitCode::FAILURE
    }
}

/// The detached session's log file: `<data>/logs/<pid>.log`, keyed by the daemon's pid (the
/// session id). The one derivation shared by every party: the daemon that writes it, the parent
/// that reports its path, and `sbx session logs` that reads it — so a reader can never look
/// somewhere the writer does not write.
pub(crate) fn detach_log_path(data_dir: &Path, pid: u32) -> PathBuf {
    data_dir.join("logs").join(format!("{pid}.log"))
}

/// The opening and closing text of a session header line, written once per detached launch:
/// `=== sbx session <pid> started=<epoch-seconds> ===`.
///
/// The log is opened in append mode, so a pid the kernel later reuses writes into the file its
/// predecessor left behind. This line is what separates the two, letting a reader show only the
/// current session's output by default rather than presenting a dead session's as this one's.
const SESSION_LOG_HEADER_OPEN: &str = "=== sbx session ";
const SESSION_LOG_HEADER_CLOSE: &str = " ===";

/// The opening text of a trust-drop note, written into a detached session's log once per security
/// field the trust gate dropped: `=== sbx trust-drop: <warning> ===`.
///
/// It closes on [`SESSION_LOG_HEADER_CLOSE`] and opens on something a session header can never
/// start with, so [`parse_session_header`] rejects it and a note can never be mistaken for the line
/// that splits one session's output from the next.
const SESSION_LOG_TRUST_DROP_OPEN: &str = "=== sbx trust-drop: ";

/// One session header line, as [`open_detach_log`] writes it.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct SessionHeader {
    pub(crate) pid: u32,
    /// Wall-clock start of that session, in seconds since the epoch.
    pub(crate) started: u64,
}

/// Parse a session header line, or `None` for any other line.
///
/// Deliberately placed beside the writer rather than with the reader that calls it: the two halves
/// share one format, and splitting them across modules is how a change to the `writeln!` above
/// silently stops matching — leaving a reader that quietly attributes an old session's output to
/// the current one instead of failing loudly.
///
/// Every field must parse, so an agent line that merely resembles a header is not mistaken for
/// one. The converse is not defended and cannot be: the log holds the agent's own output, so an
/// agent that prints a well-formed header hides its earlier output from the default view. That is
/// self-concealment within its own log, not a boundary — `--all` still shows the whole file.
pub(crate) fn parse_session_header(line: &[u8]) -> Option<SessionHeader> {
    let text = std::str::from_utf8(line).ok()?;
    let rest = text
        .strip_prefix(SESSION_LOG_HEADER_OPEN)?
        .strip_suffix(SESSION_LOG_HEADER_CLOSE)?;
    let (pid, started) = rest.split_once(" started=")?;
    Some(SessionHeader {
        pid: pid.parse().ok()?,
        started: started.parse().ok()?,
    })
}

/// Open (creating, owner-only, appending) the detached session's log, making `<data>/logs` if
/// absent, and mark the start of this session's output with a header line.
///
/// Append rather than truncate so a reused pid's log is added to rather than destroying a
/// still-relevant one; the header is what keeps that append unambiguous. Writing it here, in the
/// same function that opens the file, is deliberate — a header written by a separate caller could
/// be forgotten on a new launch path, and a log whose incarnations cannot be told apart is worse
/// than one with no header at all (the reader would silently attribute old output to this session).
fn open_detach_log(path: &Path) -> io::Result<File> {
    use std::fs::{DirBuilder, OpenOptions};
    use std::io::Write as _;
    use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
    if let Some(parent) = path.parent() {
        DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(parent)?;
    }
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .open(path)?;
    let started = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    // Best-effort: a header that cannot be written costs the reader its session split, which is a
    // degraded listing — never a reason to refuse a session that is otherwise ready to run.
    let _ = writeln!(
        file,
        "{SESSION_LOG_HEADER_OPEN}{} started={started}{SESSION_LOG_HEADER_CLOSE}",
        std::process::id()
    );
    Ok(file)
}

/// Note in a detached session's log what the trust gate dropped from its launch.
///
/// [`build`] already put these warnings on the launching terminal, and that ordering is deliberate:
/// stdout/stderr stay there through build and register so provisioning progress and any startup
/// error are seen live, and [`redirect_to_log`] only runs afterwards. The cost is that a detached
/// launch states its dropped security fields to a terminal it is about to lose, and keeps no record
/// — which is the one warning whose symptom arrives much later and in disguise, as a cage that is
/// not shaped the way its config plainly reads. A foreground launch needs none of this: its
/// warnings go to a stderr its invoker owns.
///
/// `needles` redacts the note the way [`super::notify_sink`] redacts the very same string on its way
/// to the desktop. No producer of a trust-drop warning interpolates agent-chosen text today — they
/// carry a layer label, a caller-spelled field phrase, a bind count, plugin table names and a nix
/// tool name — so this is a no-op on every string it currently sees. It is here for the producer
/// added later: [`crate::config::is_trust_drop`] matches on the remedy rather than on any one
/// reason's wording, so a new one flows into this writer without anyone revisiting it. A launch that
/// needs no guard carries no needle set, and then the note goes out as the terminal already had it.
///
/// Best-effort, like the header above it: a note that cannot be written costs a reader context,
/// never a session that is otherwise ready to run.
fn note_trust_drops(
    log: &File,
    warnings: &[String],
    wiring: Option<&super::notify_sink::NotifyWiring>,
) {
    use std::io::Write as _;
    let needles = wiring.and_then(|w| w.needles.read().ok());
    let mut sink = log;
    for warning in warnings.iter().filter(|w| crate::config::is_trust_drop(w)) {
        let note = match needles.as_deref() {
            Some(n) => {
                super::redact::redact_string(warning, n, &super::redact::Placeholder::Plain).0
            }
            None => warning.clone(),
        };
        let _ = writeln!(
            sink,
            "{SESSION_LOG_TRUST_DROP_OPEN}{note}{SESSION_LOG_HEADER_CLOSE}"
        );
    }
}

/// Close the readiness pipe without a success byte and exit non-zero — the daemon failed to set
/// up. The parent sees the pipe close as failure.
fn fail_detached(write_fd: libc::c_int) -> ! {
    unsafe { libc::close(write_fd) };
    std::process::exit(1);
}

/// Write the readiness byte to the pipe. A short or failed write is non-fatal: the parent then
/// observes the pipe close as failure, which is the safe interpretation.
fn signal_detach_ready(write_fd: libc::c_int) {
    let byte = [DETACH_READY];
    // SAFETY: writing one byte to a pipe end we own.
    unsafe {
        libc::write(write_fd, byte.as_ptr() as *const libc::c_void, 1);
    }
}

/// Point stdin at `/dev/null` (best-effort): the daemon reads no input.
fn redirect_stdin_to_null() {
    // SAFETY: open `/dev/null` read-only and dup it onto fd 0; a failure leaves the inherited fd.
    unsafe {
        let null = libc::open(c"/dev/null".as_ptr(), libc::O_RDONLY);
        if null >= 0 {
            libc::dup2(null, 0);
            if null != 0 {
                libc::close(null);
            }
        }
    }
}

/// Point stdout and stderr at the open log file: the daemon's runtime output goes there.
fn redirect_to_log(log: &File) {
    let fd = log.as_raw_fd();
    // SAFETY: dup the log fd onto stdout and stderr.
    unsafe {
        libc::dup2(fd, 1);
        libc::dup2(fd, 2);
    }
}

/// The result of an `sbx app <name>` launch: the exit code, plus — for a `--net-learn` run — the
/// rules synthesized from the egress the run was refused. The caller (`app_cmd`) writes them to the
/// chosen profile (or prints them under `--dry-run`); keeping the write in `main` keeps the trust
/// gating and re-trust out of the sandbox module.
pub(crate) struct AppOutcome {
    pub(crate) code: ExitCode,
    pub(crate) learned: Option<super::Synthesis>,
}

impl AppOutcome {
    fn plain(code: ExitCode) -> Self {
        AppOutcome {
            code,
            learned: None,
        }
    }
}

/// The shells whose `-c` binds the *next* argv element to `$0`. All four are POSIX-family and
/// agree on it, so the rule is theirs, not a per-shell quirk.
const ARGV0_SHELLS: [&str; 4] = ["bash", "sh", "zsh", "dash"];

/// Whether `cmd` ends in `<shell> -<flags>c <script>` — the shape whose trailing element is a
/// script, not a program, so anything appended after it starts at `$0`.
///
/// The script must be *last*: an argv that already carries an element after it has its `$0`, and a
/// profile that wrote one is saying which name its script should report. The shell is matched on
/// its file name so an absolute `/bin/bash` counts, and the flag must *end* in `c` because that is
/// what makes the following element the script (`-c`, `-lc`, `-euc`); a flag with anything after
/// the `c` consumes it differently and is left alone.
fn ends_with_shell_payload(cmd: &[OsString]) -> bool {
    let [shell, flag, _script] = &cmd[cmd.len().saturating_sub(3)..] else {
        return false;
    };
    let is_shell = Path::new(shell)
        .file_name()
        .is_some_and(|s| ARGV0_SHELLS.iter().any(|k| s == *k));
    let is_c_flag = flag.to_str().is_some_and(|f| {
        f.strip_prefix('-')
            .is_some_and(|rest| rest.ends_with('c') && rest.bytes().all(|b| b.is_ascii_lowercase()))
    });
    is_shell && is_c_flag
}

/// `sbx app <name>`: launch the named application profile — the project sandbox baseline
/// plus the app's gated overlay, running the command the app declares. Apps run in the same
/// locked-down posture as `sbx run`; the overlay's security fields took effect only if their
/// source was trusted (the global config or a trusted project), so launching an app on
/// untrusted code is as safe as `sbx run` there.
#[allow(clippy::too_many_arguments)]
pub(crate) fn app(
    name: &str,
    detach: bool,
    observe: bool,
    extra: Vec<OsString>,
    ov: crate::config::Override,
    net_learn: Option<super::Granularity>,
) -> AppOutcome {
    // The configuration is read before the engines are probed, because both refusals below are
    // answers about the *project*, not about the host: an app the project does not declare is
    // undeclared on a machine with no bubblewrap too, and saying so is more use to the caller than
    // being told to install a sandbox engine they were not about to reach.
    let mut pc = match launch_cwd().and_then(|cwd| prepare_config(cwd, &ov)) {
        Ok(p) => p,
        Err(code) => return AppOutcome::plain(code),
    };
    let Some(app) = pc.cfg.apps.remove(name) else {
        crate::diag::error(&format!(
            "sbx: no app named `{name}`.{}",
            available_apps(&pc.cfg)
        ));
        return AppOutcome::plain(ExitCode::from(2));
    };
    if app.cmd.is_empty() {
        // Both declaration shapes are named, because only one of them is a table. A hand-written
        // profile file reaches here (`sbx app import` refuses a `cmd`-less one, a file dropped into
        // the directory is simply read), and telling its author to add an `[app.<name>]` table
        // would ask for the very wrapper `validate_profile` tells them to remove.
        crate::diag::error(&format!(
            "sbx: app `{name}` declares no command — add a `cmd` to its declaration (at the top \
             level of `apps/{name}.toml`, or in the `[app.{name}]` table of a project config)."
        ));
        return AppOutcome::plain(ExitCode::FAILURE);
    }
    // The argv and the home scope are owned by the app; read them before the overlay is folded
    // in (which moves the app but does not touch them). The scope keys this app's persistent
    // home: one shared across projects (`Global`) or one per project (`Project`). Any trailing
    // `sbx app <name> -- <args>` are appended to the declared `cmd`, so the caller can pass a flag
    // to the launched program (e.g. `-c` to resume) without editing the profile.
    let mut cmd: Vec<OsString> = app.cmd.iter().map(OsString::from).collect();
    if !extra.is_empty() && ends_with_shell_payload(&cmd) {
        // The shell's own `$0`, so the caller's first argument lands on `$1`. `<shell> -c <script>`
        // binds the element right after the script to `$0`, not to `$1`: without this filler the
        // append above silently eats one argument, and the profile sees a short `"$@"`. The app's
        // name is the filler because `$0` is what the shell prints in its own diagnostics.
        //
        // Only when there is something to append: with no trailing arguments nothing can be eaten,
        // and leaving the argv untouched keeps `$0` at whatever the shell defaults to.
        cmd.push(OsString::from(name));
    }
    cmd.extend(extra);
    // A bundle's install step and a declared service both run BEFORE the app's command, in this same
    // cage — same posture, same allowlist, same environment — and never in its place: the app's
    // command stays its identity. Both are composed in `build`, once the app overlay and any
    // one-shot override have been folded in, so the whole start-up is written in one place and one
    // order rather than by whichever wrapper happened to be applied first.
    let runtime = match app.home_scope {
        crate::config::AppHomeScope::Global => binds::Runtime::GlobalApp(name),
        crate::config::AppHomeScope::Project => binds::Runtime::ProjectApp(name),
    };
    // The host's half, now that every answer that belongs to the project has been given: the
    // engines, the user namespace, and the channel this app's own lock resolves against.
    let mut prep = match prepare_engines(pc, Some(name)) {
        Ok(p) => p,
        Err(code) => return AppOutcome::plain(code),
    };
    crate::diag::hint(&format!("sbx: launching app `{name}`"));
    prep.cfg.merge_app(app);
    // The override is the authoritative final word — applied *after* the app overlay so a one-shot
    // `sbx app <name> --config …`/`SBX_*` beats the app's own posture, not the other way round.
    if let Err(code) = apply_launch_override(&mut prep.cfg, ov) {
        return AppOutcome::plain(code);
    }

    // SAFETY: `isatty` only inspects fd 0.
    let interactive = !detach && unsafe { libc::isatty(0) } == 1;
    warn_observe_feed_absent(observe, interactive, &prep.cfg.proc);

    // `--net-learn`: run the app under its real (unchanged) posture, capture the egress it was
    // refused for lack of a rule, and hand the synthesized rules back for the caller to write. It is
    // foreground-only (the parser refuses `--detach`) and needs a filtering posture — a `shared` or
    // `none` app has no proxy logging egress, so there is nothing to learn.
    if let Some(gran) = net_learn {
        let policy = match &prep.cfg.network {
            crate::config::NetworkPolicy::Allowlist(p) => p.clone(),
            other => {
                crate::diag::error(&format!(
                    "sbx: --net-learn needs a filtering network posture (mode allow/deny/ask); \
                     app `{name}` has `{}` — nothing logs egress to learn from.",
                    network_posture_name(other)
                ));
                return AppOutcome::plain(ExitCode::from(2));
            }
        };
        // A build failure (a provisioning error, a host that cannot sandbox) must NOT be reported as
        // "nothing to learn": return it as a plain failure so its code propagates and the caller
        // never enters the write path. Only a cage that actually ran yields events to learn from —
        // an empty log from a real run (the app was refused nothing) is a genuine "no new rules".
        let (code, events) =
            match launch_foreground_learning(&prep, runtime, Kind::Run, cmd, interactive) {
                Ok(v) => v,
                Err(code) => return AppOutcome::plain(code),
            };
        // Subsume against the SAME effective policy the proxy enforced — the config allowlist unioned
        // with the always-on built-in allow-set — so a built-in-allowed host is never re-proposed.
        let effective = super::union_with_builtin(policy);
        let learned = super::netlearn::synthesize(&events, &effective, gran);
        return AppOutcome {
            code,
            learned: Some(learned),
        };
    }

    // An interactive foreground launch (a real terminal on stdin) runs under the pty supervisor:
    // the agent's TUI gets a private controlling terminal and live terminal-resize propagation
    // (the same isolation an interactive `sbx run` uses — the real terminal stays unreachable). A detached
    // agent has no terminal, and a piped/non-tty invocation must not be handed one, so both keep
    // the exec-replace / supervised `NewSession` path.
    let code = if interactive {
        launch_pty_supervised(&prep, runtime, Kind::Run, cmd, observe)
    } else {
        launch(prep, runtime, Kind::Run, cmd, detach, name, observe)
    };
    AppOutcome::plain(code)
}

/// The posture name for a `--net-learn` refusal message — the config vocabulary, not the internal
/// `NetworkPolicy` variant.
fn network_posture_name(network: &crate::config::NetworkPolicy) -> &'static str {
    match network {
        crate::config::NetworkPolicy::Shared => "shared",
        crate::config::NetworkPolicy::Isolated => "none",
        crate::config::NetworkPolicy::Allowlist(_) => "allowlist",
    }
}

/// Run an `sbx app` launch in the foreground and return the egress it logged, for `--net-learn`.
/// Interactive launches use the pty supervisor (a private controlling terminal, like an interactive `sbx run`);
/// a non-tty one supervises directly. Either way the egress guard is held for the whole run, then
/// its log is snapshotted before the guard is dropped — so the returned events are the run's full
/// record. A `build()` failure is `Err(code)`, distinct from a clean run with no denials (`Ok` with
/// an empty log): the caller must not treat a failed build as "nothing to learn".
fn launch_foreground_learning(
    prep: &Prepared,
    runtime: binds::Runtime,
    kind: Kind,
    cmd: Vec<OsString>,
    interactive: bool,
) -> Result<(ExitCode, Vec<super::control::LogEvent>), ExitCode> {
    let (spec, guard) = match build(prep, runtime, cmd) {
        Ok((s, g)) if interactive => (s.with_private_tty(), g),
        Ok((s, g)) => (s, g),
        Err(code) => return Err(code),
    };

    // A pty session unlinks its record on exit (RecordGuard); a supervised one persists it
    // (liveness-pruned), matching `launch_pty_supervised` and `launch_foreground` respectively.
    let record = register(prep.layout.data_dir(), &spec, kind, runtime, false);
    let _record = interactive.then(|| record.map(RecordGuard::new));

    let code = if interactive {
        let gui = matches!(prep.cfg.gui, crate::config::GuiPolicy::Wayland);
        match supervise(&prep.bwrap, &spec, &prep.cfg.limits, gui) {
            Ok(c) => ExitCode::from(c as u8),
            Err(e) => {
                crate::diag::error(&format!("sbx: sandbox session failed: {e}"));
                ExitCode::FAILURE
            }
        }
    } else {
        run_supervised(&prep.bwrap, &spec, &prep.cfg.limits)
    };

    let events = guard
        .as_ref()
        .map(LaunchGuard::observed_events)
        .unwrap_or_default();
    drop(guard);
    Ok((code, events))
}

/// A suffix for the "no such app" error: " (available: a, b)" listing the configured app
/// names, or a note that none are configured — so a typo or an unconfigured name points at
/// what exists.
fn available_apps(cfg: &crate::config::Resolved) -> String {
    if cfg.apps.is_empty() {
        " No apps are configured.".to_string()
    } else {
        let names: Vec<&str> = cfg.apps.keys().map(String::as_str).collect();
        format!(" (available: {})", names.join(", "))
    }
}

/// `sbx mise [args...]`: run mise inside the project's open cage, where it can
/// self-equip the project's `nix:` tools (`sbx mise install nix:<pkg>`) into the
/// project's own writable store. Sugar over `sbx run -- mise [args...]`: mise is
/// present in every cage with the `nix:` backend plugin registered, so the only
/// thing this adds is sparing the `run --` prefix.
///
/// A tool the agent *activates* (`mise use [-g] nix:<pkg>`) is on PATH in later
/// launches — through the shims dir on PATH for `sbx run`, and `mise activate` for the
/// an interactive `sbx run` — and persists in the project's store. A bare `mise install` (not
/// activated) persists too and `mise exec`/`mise which` resolve it, but it is not on
/// PATH, matching mise's own install-vs-use split. This path is intentionally open — it
/// works whether or not the project is trusted, the agent-self-equip posture — unlike
/// `sbx run`'s host-side `nix:` provisioning, which stays trusted-only and is a parallel
/// path that does not share state with what mise installs here.
pub(crate) fn run_mise(args: Vec<OsString>) -> ExitCode {
    let mut cmd = vec![OsString::from("mise")];
    cmd.extend(args);
    // `sbx mise` is a passthrough — every argument is mise's, so it takes no one-shot override.
    run(cmd, false, false, crate::config::Override::none())
}

/// Which persistent home a `mise:` package group is equipped in, owning its app name so a
/// group can outlive the config it was derived from. Mirrors [`binds::Runtime`], which borrows
/// the name; [`GroupHome::runtime`] rebuilds the borrowing form at launch.
enum GroupHome {
    /// The project's default shell home — where `sbx run` equip baseline tools.
    ProjectDefault,
    /// An app's home shared across projects (`home_scope = "global"`).
    GlobalApp(String),
    /// An app's per-project home (`home_scope = "project"`).
    ProjectApp(String),
}

impl GroupHome {
    fn runtime(&self) -> binds::Runtime<'_> {
        match self {
            GroupHome::ProjectDefault => binds::Runtime::ProjectDefault,
            GroupHome::GlobalApp(name) => binds::Runtime::GlobalApp(name),
            GroupHome::ProjectApp(name) => binds::Runtime::ProjectApp(name),
        }
    }

    fn label(&self) -> String {
        match self {
            GroupHome::ProjectDefault => "project".to_string(),
            GroupHome::GlobalApp(name) | GroupHome::ProjectApp(name) => format!("app: {name}"),
        }
    }

    /// The bare display name for the report column and the recap list — the app name, or `project`
    /// for the baseline. Unlike [`GroupHome::label`] it carries no `app:` prefix, so a run of them
    /// aligns cleanly.
    fn name(&self) -> String {
        match self {
            GroupHome::ProjectDefault => "project".to_string(),
            GroupHome::GlobalApp(name) | GroupHome::ProjectApp(name) => name.clone(),
        }
    }
}

/// One in-cage `mise:` roll: the home that equips these tokens, the merged config to launch it
/// with, and the tokens to advance.
struct MiseGroup {
    home: GroupHome,
    cfg: crate::config::Resolved,
    tokens: Vec<String>,
}

/// The `mise:` `[packages]` groups to roll forward — generic over every declared group: the
/// project baseline (equipped in its default home by `sbx run`) and each app
/// (equipped in its own home, keyed by `home_scope`), each with its merged trusted `mise:`
/// token set. A group with no trusted `mise:` token — and an app with no command — is omitted,
/// so a project or app without any produces no cage, and no app is special-cased. Trusted-only
/// by construction, since [`super::packages::mise_packages`] keeps only trusted tokens. Pure
/// over the resolved config (it clones to merge each app), so the grouping is unit-tested
/// without launching a cage.
fn mise_package_groups(cfg: &crate::config::Resolved, only: Option<&str>) -> Vec<MiseGroup> {
    let mut groups = Vec::new();

    // The project baseline, equipped in the default shell home. Dropped under `--app`: the
    // baseline is not an app, so keeping it would make the selector roll project-wide work.
    let baseline = super::packages::mise_packages(&cfg.packages);
    if !baseline.is_empty() && only.is_none() {
        groups.push(MiseGroup {
            home: GroupHome::ProjectDefault,
            cfg: cfg.clone(),
            tokens: baseline,
        });
    }

    // Each app, in its own home. Merging folds the baseline packages in (an app's cage equips
    // both layers), so the token set is exactly the one the app's launch equips.
    for (name, app) in &cfg.apps {
        if only.is_some_and(|want| want != name) {
            continue;
        }
        if app.cmd.is_empty() {
            continue; // an unlaunchable app never equips anything
        }
        let home = match app.home_scope {
            crate::config::AppHomeScope::Global => GroupHome::GlobalApp(name.clone()),
            crate::config::AppHomeScope::Project => GroupHome::ProjectApp(name.clone()),
        };
        let mut merged = cfg.clone();
        merged.merge_app(app.clone());
        let tokens = super::packages::mise_packages(&merged.packages);
        if tokens.is_empty() {
            continue;
        }
        groups.push(MiseGroup {
            home,
            cfg: merged,
            tokens,
        });
    }
    groups
}

/// How many declared `mise:` packages are withheld for being untrusted — across the project
/// baseline and each app's own overlay. Only a count: the per-package withholding reason is
/// already warned on the launch path, so `sbx upgrade` just needs to not read as "none declared".
fn withheld_mise_packages(cfg: &crate::config::Resolved, only: Option<&str>) -> usize {
    let untrusted_mise = |pkgs: &[crate::config::Package]| {
        pkgs.iter()
            .filter(|p| {
                matches!(p.backend, crate::config::Backend::Mise(_))
                    && p.state != crate::trust::TrustState::Trusted
            })
            .count()
    };
    // Under `--app`, count what that app's cage would have equipped and nothing else — both its own
    // packages and the baseline it folds in. Reporting the project's total there would attribute
    // another app's withheld package to this roll.
    let baseline = untrusted_mise(&cfg.packages);
    match only {
        Some(name) => match cfg.apps.get(name) {
            Some(app) => baseline + untrusted_mise(&app.packages),
            None => 0,
        },
        None => {
            baseline
                + cfg
                    .apps
                    .values()
                    .map(|app| untrusted_mise(&app.packages))
                    .sum::<usize>()
        }
    }
}

/// The mise invocation that equips an app's `[packages] mise:` tools, and the one that rolls them.
///
/// They are a pair and are kept side by side because neither is correct alone: `--pin` freezes the
/// cage's config at the installed version (without it the tool's shim re-resolves on every exec and
/// the app stops launching the day upstream publishes), and `--bump` is what still advances an
/// exact pin (a plain `upgrade` keeps the config's range, and after a pin that range is one
/// version, so the roll would report everything up to date and move nothing). Named constants
/// rather than literals at the call sites, so the pairing is one thing a test can hold.
const MISE_EQUIP_VERB: &str = "use -g --pin";
const MISE_ROLL_FLAG: &str = "--bump";

/// The line a launch prints before equipping an app's `mise:` tools.
///
/// Built here rather than formatted at the call site so the announcement and the invocation read
/// from the same constant: a launch that names one command and runs another sends whoever reads the
/// transcript looking for the wrong thing, and that is precisely what a hand-written copy of the
/// verb drifts into.
fn equip_announcement(tokens: &[String]) -> String {
    format!(
        "sbx: equipping app packages in-cage via mise {MISE_EQUIP_VERB}: {}",
        tokens.join(", ")
    )
}

/// The `mise upgrade <tokens>` command for one roll group. The rolled tokens are the group's
/// `[packages] mise:` tools, which for a **global app** live in the app-global home pool (Lane-1
/// `mise use -g` pins them there). The cage's ambient primary for a global app is the *per-project*
/// pool, which does not hold them, so a plain `mise upgrade` there would find nothing and silently
/// roll nothing — a regression of a shipped command. So for a global app the roll is pinned to the
/// app-global pool via a bash `MISE_DATA_DIR=<app-global>` prefix; the tokens ride `"$@"`
/// positionally (no shell injection — only the sbx-owned mise path and fixed cage data dir are
/// interpolated), and `exec` keeps the roll the cage's main process. Other runtimes have a single
/// pool (the home), already the ambient primary, so the plain command runs unwrapped.
///
/// `--bump` is the other half of the launch's `use -g --pin`. A plain `mise upgrade` keeps whatever
/// range the config states, and after a pin that range is one exact version: the roll would report
/// every tool as already up to date and move nothing, which is a shipped command going quiet.
///
/// `--bump` takes the latest and rewrites the pin, so the version advances here and only here —
/// which is the whole contract. Measured against a config still saying `latest` (every app before
/// its first launch on this code): `--bump` behaves exactly as the plain form did, so the change
/// carries no regression for a pool that has not been pinned yet.
fn mise_upgrade_cmd(
    runtime: binds::Runtime,
    mise: &Path,
    bash: &Path,
    tokens: &[String],
) -> Vec<OsString> {
    if matches!(runtime, binds::Runtime::GlobalApp(_)) {
        let data_dir = binds::mise_app_global_data_dir();
        let script = format!(
            "MISE_DATA_DIR='{data_dir}' exec {mise} upgrade {MISE_ROLL_FLAG} \"$@\"",
            mise = mise.to_string_lossy(),
        );
        let mut cmd = vec![
            bash.as_os_str().to_os_string(),
            OsString::from("-c"),
            OsString::from(script),
            // `$0` — a label; the tokens are `$1..$n`.
            OsString::from("sbx-mise-upgrade"),
        ];
        cmd.extend(tokens.iter().map(OsString::from));
        cmd
    } else {
        let mut cmd = vec![
            mise.as_os_str().to_os_string(),
            OsString::from("upgrade"),
            OsString::from(MISE_ROLL_FLAG),
        ];
        cmd.extend(tokens.iter().map(OsString::from));
        cmd
    }
}

/// Roll the project's and its apps' `mise:` `[packages]` forward, in-cage. A `mise:` package is
/// equipped by `mise use -g --pin <token>` at launch and is frozen there at the installed version —
/// frozen *because* of the pin, which writes the resolved version into the cage's config so a later
/// launch has nothing left to resolve. A floating request would not have held: the tool on the PATH
/// is a mise shim that re-resolves it on every exec. So advancing the version means running
/// `mise upgrade --bump <token>` in the same cage — the equip environment,
/// so the fetch rides the app's egress allowlist. Generic over [`mise_package_groups`]: the
/// project baseline (its default home) and each app (its own home), no app special-cased.
///
/// Trusted-only by construction. Returns whether every group rolled cleanly; a group that fails
/// makes this `false` but never aborts the others.
///
/// Unlike the host-side lock rewrites (`nix:`, the engine, `nix:` tools), the roll needs the
/// sandbox — but only when there is something to roll: the groups are computed from the
/// already-resolved `cfg` first, so a project with no `mise:` package costs nothing here and
/// `sbx upgrade nix`/`all` keeps its cheap, sandbox-free common path. With work to do, a host
/// that cannot sandbox warns and rolls nothing rather than failing (best-effort, like the
/// cgroup limits).
pub(crate) fn upgrade_mise_packages(
    cwd: &Path,
    cfg: &crate::config::Resolved,
    pal: &crate::style::Palette,
    only: Option<&str>,
) -> bool {
    let (h, warn, dim, r, ok_c) = (pal.head, pal.warn, pal.dim, pal.reset, pal.ok);
    println!("{h}sbx upgrade — mise packages{r}");
    let groups = mise_package_groups(cfg, only);
    // Surface withheld (untrusted) `mise:` packages so an untrusted project does not silently
    // read as "nothing declared" — parity with the `nix:` tools path, which warns the same.
    let withheld = withheld_mise_packages(cfg, only);
    if withheld > 0 {
        println!(
            "{}",
            crate::style::prose(
                &format!(
                    "  {warn}{withheld} mise: package(s) withheld (untrusted){r} — not rolled; run `sbx trust`."
                ),
                pal
            )
        );
    }
    // The declared operations' own tool pool rolls here too: it is filled by `mise use -g`, which
    // records a spec the launch then short-circuits on, so without this pass a pool tool would be
    // frozen at whatever the first fill resolved.
    let pool_tokens: Vec<String> = cfg
        .tasks
        .iter()
        .flat_map(|t| t.packages.iter().cloned())
        .fold(Vec::new(), |mut acc, t| {
            if !acc.contains(&t) {
                acc.push(t);
            }
            acc
        });

    if groups.is_empty() && pool_tokens.is_empty() {
        if withheld == 0 {
            println!("  {dim}no mise: packages to roll.{r}");
        }
        return true;
    }

    // Only now, with something to roll, take on the sandbox prerequisites — against `cwd`, the
    // project being upgraded, so `--project` builds the roll cage in that project's store and home
    // rather
    // than wherever the command was invoked.
    let mut prep = match prepare_in(cwd.to_path_buf(), &crate::config::Override::none(), only) {
        Ok(p) => p,
        Err(_) => {
            // prepare_in already printed the pointed reason (missing bwrap/userns/nix).
            crate::diag::warn("mise packages: skipped — no usable sandbox; see `sbx doctor`");
            return true;
        }
    };

    // In this batch context the per-app "equipping app packages in-cage" line `build` prints repeats
    // for every app and buries the roll result — silence it (the report names each app anyway).
    prep.quiet_equip = true;

    // Every group name is known up front, so the result lines are dot-leader aligned to one column
    // even though each prints live (as its cage finishes) to keep progress visible over a long
    // multi-app roll. A closing recap then names exactly which apps advanced.
    let width = groups
        .iter()
        .map(|g| g.home.name().chars().count())
        .max()
        .unwrap_or(0);

    let mut ok = true;
    let mut rolled: Vec<String> = Vec::new();
    let (mut up_to_date, mut skipped, mut failed) = (0usize, 0usize, 0usize);

    for group in groups {
        let MiseGroup { home, cfg, tokens } = group;
        let name = home.name();
        // `network = "none"` cannot fetch — the launch skips the equip there — so skip the roll
        // too (the tool stays at its persisted version). Not a failure: it is the declared posture.
        if matches!(cfg.network, crate::config::NetworkPolicy::Isolated) {
            println!(
                "{}",
                roll_line(
                    &name,
                    width,
                    &format!("{dim}network \"none\" — skipped{r}"),
                    pal
                )
            );
            skipped += 1;
            continue;
        }

        // Launch a cage in this group's home with its merged config so `build` sees the right
        // network/packages/home. The baseline warnings were already surfaced by `upgrade_cmd`,
        // so clear them to avoid one repeat per cage. The command is `mise upgrade <tokens>`; the
        // launch's own `mise use -g` equip wrap runs first (a warm no-op once installed, or a
        // fresh equip if the app was never launched), then the upgrade rolls the version.
        let runtime = home.runtime();
        let mut cfg = cfg;
        cfg.warnings.clear();
        prep.cfg = cfg;

        let cmd = mise_upgrade_cmd(
            runtime,
            &prep.userland.mise_bin,
            &prep.userland.shell_bin,
            &tokens,
        );

        let (spec, guard) = match build(&prep, runtime, cmd) {
            Ok(v) => v,
            Err(_) => {
                println!(
                    "{}",
                    roll_line(&name, width, &format!("{warn}failed to launch{r}"), pal)
                );
                failed += 1;
                ok = false;
                continue;
            }
        };
        // Fork-and-wait (never exec-replace) so the next group can run; the guard, if any, is
        // held across the wait so the proxy/forwarder serves the fetch, then dropped as the group
        // ends (unlinks the sockets and CA). The cage's output is captured (not streamed): on a
        // clean roll only mise's own version-transition summary is surfaced; the install/progress
        // noise is shown only when the roll fails, so its cause is visible.
        let (code, out) = run_captured(&prep.bwrap, &spec, &prep.cfg.limits);
        drop(guard);
        if code == 0 {
            match mise_transitions(&out).as_slice() {
                [] if mise_up_to_date(&out) => {
                    println!(
                        "{}",
                        roll_line(&name, width, &format!("{dim}up to date{r}"), pal)
                    );
                    up_to_date += 1;
                }
                [] => {
                    println!(
                        "{}",
                        roll_line(&name, width, &format!("{ok_c}upgraded{r}"), pal)
                    );
                    rolled.push(name);
                }
                [only] => {
                    // The token is redundant with the name column, so show just the version delta.
                    let delta = only.split_once(' ').map_or(*only, |(_, v)| v);
                    println!(
                        "{}",
                        roll_line(&name, width, &format!("{ok_c}{delta}{r}"), pal)
                    );
                    rolled.push(name);
                }
                many => {
                    // A group that rolled several tokens: a count on the aligned line, then each
                    // full `<token> <old> → <new>` transition indented below it.
                    println!(
                        "{}",
                        roll_line(
                            &name,
                            width,
                            &format!("{ok_c}{} tools rolled{r}", many.len()),
                            pal
                        )
                    );
                    for t in many {
                        println!("       {ok_c}{t}{r}");
                    }
                    rolled.push(name);
                }
            }
        } else {
            println!(
                "{}",
                roll_line(
                    &name,
                    width,
                    &format!("{warn}mise upgrade exited {code}{r}"),
                    pal
                )
            );
            crate::diag::warn(&format!("`{}`: mise upgrade exited {code}", home.label()));
            for line in out.lines() {
                eprintln!("       {line}");
            }
            failed += 1;
            ok = false;
        }
    }

    // The task tool pool, rolled host-side rather than in a cage (that is where it is filled). Its
    // own line, because it belongs to the declared operations, not to any app.
    if !pool_tokens.is_empty() {
        // Counted into the same tallies the apps use, so the closing recap can never read
        // "nothing to roll" one line under a pool that rolled.
        match roll_task_pool(cwd, &mut prep, cfg) {
            Ok(true) => {
                println!(
                    "{}",
                    roll_line("task pool", width.max(9), &format!("{ok_c}rolled{r}"), pal)
                );
                rolled.push("task pool".to_string());
            }
            Ok(false) => {
                println!(
                    "{}",
                    roll_line(
                        "task pool",
                        width.max(9),
                        &format!("{dim}nothing to roll{r}"),
                        pal
                    )
                );
                up_to_date += 1;
            }
            Err(e) => {
                println!(
                    "{}",
                    roll_line("task pool", width.max(9), &format!("{warn}{e}{r}"), pal)
                );
                failed += 1;
                ok = false;
            }
        }
    }

    // Close with the one line that answers "what changed?": each rolled app — and the task tool
    // pool, when it rolled — by name, plus a tally of the rest, coloured by outcome (a failure
    // paints it a warning, a clean no-op dims).
    let recap = mise_roll_recap(&rolled, up_to_date, skipped, failed);
    let hue = if failed > 0 {
        warn
    } else if rolled.is_empty() {
        dim
    } else {
        ok_c
    };
    println!("  {hue}{recap}{r}");
    ok
}

/// One in-cage provision roll: the app whose bundles carry install steps, the merged config to
/// launch it with, and the steps to re-run.
struct ProvisionGroup {
    home: GroupHome,
    cfg: crate::config::Resolved,
    steps: Vec<crate::config::BundleProvision>,
}

/// The apps whose `use`d bundles carry an install step. Only apps: a `provision` is a bundle's
/// field, and a bundle only ever folds into an app, so there is no project-baseline group here —
/// the shape [`mise_package_groups`] needs. An app with no command is omitted (it can never
/// launch, so nothing installs for it), and the fold has already dropped the steps of an untrusted
/// layer, so this is trusted-only by construction. Pure over the resolved config, so the grouping
/// is unit-tested without launching a cage.
fn provision_groups(cfg: &crate::config::Resolved, only: Option<&str>) -> Vec<ProvisionGroup> {
    let mut groups = Vec::new();
    for (name, app) in &cfg.apps {
        if only.is_some_and(|want| want != name) {
            continue;
        }
        if app.cmd.is_empty() || app.provisions.is_empty() {
            continue;
        }
        let home = match app.home_scope {
            crate::config::AppHomeScope::Global => GroupHome::GlobalApp(name.clone()),
            crate::config::AppHomeScope::Project => GroupHome::ProjectApp(name.clone()),
        };
        let steps = app.provisions.clone();
        let mut merged = cfg.clone();
        merged.merge_app(app.clone());
        groups.push(ProvisionGroup {
            home,
            cfg: merged,
            steps,
        });
    }
    groups
}

/// Re-run each app's bundle install steps with `SBX_UPGRADE` raised — the roll for an agent that
/// rides no `[packages]` backend.
///
/// A `nix:`/`mise:`/`deb:` package advances by re-resolving a lock; an agent its bundle *installs*
/// (a clone and a build, a vendor script) has no lock to rewrite, so what advances it is running
/// that install again. The step already carries its own "already installed" guard — that is what
/// keeps a launch from re-installing every time — so the roll raises `SBX_UPGRADE=1` in the cage
/// and the step's guard is written to yield to it. A step that ignores the variable simply reports
/// as up to date, which is honest: nothing moved.
///
/// The cage is the app's own (its home, packages, egress, environment), so what the roll installs
/// is exactly what the next launch finds. The app's command never runs: the install is the point,
/// and launching the agent would make a version roll a launch. Returns whether every group ran
/// cleanly; a group that fails makes this `false` but never aborts the others.
pub(crate) fn upgrade_provision_steps(
    cwd: &Path,
    cfg: &crate::config::Resolved,
    pal: &crate::style::Palette,
    only: Option<&str>,
) -> bool {
    let (h, warn, dim, r, ok_c) = (pal.head, pal.warn, pal.dim, pal.reset, pal.ok);
    println!("{h}sbx upgrade — bundle install steps{r}");
    let groups = provision_groups(cfg, only);
    if groups.is_empty() {
        println!("  {dim}no bundle install steps to re-run.{r}");
        return true;
    }

    // Only now, with work to do, take on the sandbox prerequisites — against `cwd`, so `--project`
    // retargets these cages the way it retargets every other roll.
    let mut prep = match prepare_in(cwd.to_path_buf(), &crate::config::Override::none(), only) {
        Ok(p) => p,
        Err(_) => {
            // prepare_in already printed the pointed reason (missing bwrap/userns/nix).
            crate::diag::warn("install steps: skipped — no usable sandbox; see `sbx doctor`");
            return true;
        }
    };
    prep.quiet_equip = true;

    let width = groups
        .iter()
        .map(|g| g.home.name().chars().count())
        .max()
        .unwrap_or(0);
    let mut ok = true;
    let (mut ran, mut skipped, mut failed) = (Vec::new(), 0usize, 0usize);

    for group in groups {
        let ProvisionGroup { home, cfg, steps } = group;
        let name = home.name();
        // An isolated cage cannot fetch, and every install step fetches something. Skipping is the
        // declared posture, not a failure — the same call `upgrade_mise_packages` makes.
        if matches!(cfg.network, crate::config::NetworkPolicy::Isolated) {
            println!(
                "{}",
                roll_line(
                    &name,
                    width,
                    &format!("{dim}network \"none\" — skipped{r}"),
                    pal
                )
            );
            skipped += 1;
            continue;
        }

        let runtime = home.runtime();
        let mut cfg = cfg;
        cfg.warnings.clear();
        // The signal the steps' guards read. It rides the app's `[env]` layer, so it reaches the
        // cage the way every other declared variable does — never on the bwrap argv.
        cfg.env.push(("SBX_UPGRADE".to_string(), "1".to_string()));
        prep.cfg = cfg;

        let (spec, guard) = match build(&prep, runtime, provision_only_cmd(&steps)) {
            Ok(v) => v,
            Err(_) => {
                println!(
                    "{}",
                    roll_line(&name, width, &format!("{warn}failed to launch{r}"), pal)
                );
                failed += 1;
                ok = false;
                continue;
            }
        };
        // Fork-and-wait so the next group runs; the guard holds the proxy/forwarder across the
        // fetch. The output is captured and shown only on failure — an install is verbose, and on
        // a clean run the line above already says what happened.
        let (code, out) = run_captured(&prep.bwrap, &spec, &prep.cfg.limits);
        drop(guard);
        if code == 0 {
            let bundles = step_bundles(&steps);
            println!(
                "{}",
                roll_line(
                    &name,
                    width,
                    &format!("{ok_c}re-installed ({bundles}){r}"),
                    pal
                )
            );
            ran.push(name);
        } else {
            println!(
                "{}",
                roll_line(
                    &name,
                    width,
                    &format!("{warn}install step exited {code}{r}"),
                    pal
                )
            );
            crate::diag::warn(&format!("`{}`: install step exited {code}", home.label()));
            for line in out.lines() {
                eprintln!("       {line}");
            }
            failed += 1;
            ok = false;
        }
    }

    let recap = provision_roll_recap(&ran, skipped, failed);
    let hue = if failed > 0 {
        warn
    } else if ran.is_empty() {
        dim
    } else {
        ok_c
    };
    println!("  {hue}{recap}{r}");
    ok
}

/// The bundles a group's steps came from, named in order and each named once — an app may `use`
/// several bundles that install, and the roll line is where a reader learns which ran.
fn step_bundles(steps: &[crate::config::BundleProvision]) -> String {
    let mut names: Vec<&str> = Vec::new();
    for step in steps {
        if !names.contains(&step.bundle.as_str()) {
            names.push(&step.bundle);
        }
    }
    names.join(", ")
}

/// The closing line of a provision roll: which apps re-installed, and a tally of the rest.
fn provision_roll_recap(ran: &[String], skipped: usize, failed: usize) -> String {
    let mut parts: Vec<String> = Vec::new();
    if ran.is_empty() {
        parts.push("nothing re-installed".to_string());
    } else {
        parts.push(format!("re-installed: {}", ran.join(", ")));
    }
    if skipped > 0 {
        parts.push(format!("{skipped} skipped"));
    }
    if failed > 0 {
        parts.push(format!("{failed} failed"));
    }
    parts.join(" · ")
}

/// The programs the in-cage task client is written against: the **cage's** shell, its `socat`, and
/// coreutils' `head`.
///
/// All three are store paths as the cage resolves them, never the host's copies — the client runs
/// inside, where a host path would either be absent or name a different build than the one the cage
/// has. `head` is not carried on the userland directly; it sits beside the `env` that is.
fn task_client_programs(userland: &binds::Userland) -> (PathBuf, PathBuf, PathBuf) {
    (
        userland.shell_bin.clone(),
        userland.socat_bin.clone(),
        userland.env_bin.with_file_name("head"),
    )
}

/// Roll the declared operations' tool pool forward. Returns whether anything was rolled, or the
/// reason it could not run.
///
/// The pool is filled and rolled **host-side**, so unlike an app's `mise:` packages this needs no
/// launch — only a spec to derive the task cage's skeleton from, which is what a pool tool runs
/// against. The spec is built for a command that never executes: `build` is the one place that
/// assembles the cage, and reproducing it here would be a second implementation of the thing whose
/// whole point is to be the same.
fn roll_task_pool(
    cwd: &Path,
    prep: &mut Prepared,
    cfg: &crate::config::Resolved,
) -> Result<bool, String> {
    let id = super::binds::project_runtime_id(cwd).map_err(|e| format!("no project tree ({e})"))?;
    // The per-app loop above leaves `prep.cfg` on whichever app it rolled last. The pool belongs to
    // the project's declared operations, not to any app, so restore the baseline before deriving a
    // cage from it.
    prep.cfg = cfg.clone();
    let (spec, guard) = build(
        prep,
        binds::Runtime::ProjectDefault,
        vec![OsString::from("/bin/true")],
    )
    .map_err(|_| "cannot assemble a cage".to_string())?;
    let engine = super::task::TaskEngine::from_cage(
        &prep.bwrap,
        &spec,
        &prep.layout,
        cwd,
        cwd,
        cfg.tasks.clone(),
        cfg.limits.clone(),
        spec.cage_slug(),
        Some(prep.userland.ca_bundle_src.as_path()),
        super::task::CageForwarder {
            socat: prep.userland.socat_bin.clone(),
            shell: prep.userland.shell_bin.clone(),
        },
        cfg.redact_min_len,
    )
    .with_pool(
        super::taskpool::pool_dir(prep.layout.data_dir(), &id),
        prep.userland.mise_bin.clone(),
    );
    let outcome = engine.upgrade_pool().map_err(|e| e.to_string());
    // Dropped only now: the guard holds the launch's runtime files, and the roll runs against the
    // spec derived from them.
    drop(guard);
    match outcome? {
        None => Ok(false),
        Some(run) if run.ok => Ok(true),
        Some(run) => Err(format!(
            "mise upgrade failed: {}",
            String::from_utf8_lossy(&run.stderr)
                .trim()
                .lines()
                .last()
                .unwrap_or("no output")
        )),
    }
}

/// Provision one optional host-side layer, or degrade to `None` with a warning.
///
/// The five GUI/hardware holes — fonts, GUI data, mesa, the audio userspace, certutil — share one
/// doctrine and one shape: each is wanted only under some posture, each is fetched by a
/// `provision(nix, layout, nixpkgs)` of the same signature, and none of them may fail a launch. A
/// hole that cannot be provisioned costs the feature it serves, never the process the user asked
/// for; `explain` says which feature, in the terms of the posture that asked for it.
///
/// Written once so that doctrine is stated once. The desktop portal is deliberately not routed
/// through here: it shares the callee signature but not the shape, since its site also creates a
/// host directory, starts two relays, and warns on a second condition of its own.
fn optional_layer<T>(
    prep: &Prepared,
    wanted: bool,
    provision: fn(&Path, &Layout, &str) -> io::Result<T>,
    explain: impl FnOnce(&io::Error) -> String,
) -> Option<T> {
    if !wanted {
        return None;
    }
    match provision(&prep.nix, &prep.layout, &prep.nixpkgs) {
        Ok(layer) => Some(layer),
        Err(e) => {
            crate::diag::warn(&explain(&e));
            None
        }
    }
}

/// `sbx gc [--all] [--prune]`: reclaim sbx's store space.
///
/// By default it sweeps the **current** project's store (see [`sweep_current`]). With `--all` it
/// also, across all projects: reaps whole runtime trees whose project directory is gone (see
/// `reap_dead_trees` in [`mod@super::projects`]), then garbage-collects the **shared** store — the
/// channel revisions left
/// behind by `sbx upgrade` and the tools of reaped projects (see [`shared_store_gc`]). A dry run
/// by default; `--prune` is the destructive form.
///
/// **The current-project sweep runs first, and the shared collection last.** The sweep provisions
/// this project's declared tools to re-root them, and that provisioning re-materializes the pinned
/// channel's flake source in the shared store. Collecting the shared store *before* the sweep
/// therefore measured a state the same command went on to invalidate: the sweep put back the source
/// the collection had just taken, so the run left an orphan behind and the next `sbx gc --all`
/// reported the very same reclaimable bytes — it took two passes to converge. Sweeping first means
/// the shared collection sees the final state.
///
/// The cross-project passes stay independent of the sandbox/nix prerequisites the sweep needs, so
/// they run **whatever the sweep did** — `sbx gc --all` still reclaims from a directory that is not
/// a project, or on a host that has lost its sandbox capability.
pub(crate) fn gc(prune: bool, all: bool, optimise: bool, pal: &crate::style::Palette) -> ExitCode {
    let swept = sweep_current(prune, optimise, pal);

    if all {
        match crate::store::Layout::from_env() {
            Some(layout) => {
                // Prune stale session records, then collect the shared store. Reaping whole
                // per-project runtime *trees* is `sbx projects rm`; `--all` here is purely the
                // nix-store side — the shared store's orphaned closures across every project.
                let _ = session_housekeeping(&layout, pal);
                runtime_housekeeping(&layout, prune, pal);
                shared_store_gc(&layout, prune, optimise, pal);
            }
            None => crate::diag::error(
                "sbx gc: cannot locate sbx's data directory; skipping the shared-store housekeeping.",
            ),
        }
    }

    match swept {
        Ok(()) => ExitCode::SUCCESS,
        // Under `--all` the shared-store collection ran regardless, so a current-project sweep that
        // could not run (the host cannot sandbox, nix is unavailable) — or that hit an error — must
        // not fail the whole command. Its own message is already printed above; only the exit code
        // is flattened.
        Err(_) if all => {
            crate::diag::error(
                "sbx gc: the current project's store was not swept (see above); the shared-store collection ran.",
            );
            ExitCode::SUCCESS
        }
        Err(code) => code,
    }
}

/// Prune dead session records and report it (the dedicated housekeeping pass the registry deferred:
/// an `sbx run` record with no post-exec hook lingered until the next `sbx session ls`). Returns the ids of
/// projects with a *live* session — hashing each recorded canonical path — so the dead-tree reap
/// can skip a tree a session still holds without scanning the registry a second time.
pub(super) fn session_housekeeping(
    layout: &crate::store::Layout,
    pal: &crate::style::Palette,
) -> std::collections::BTreeSet<String> {
    match session::Registry::at(layout.data_dir()).housekeep() {
        Ok((live, pruned)) => {
            if pruned > 0 {
                println!(
                    "{}sbx:{} pruned {}{pruned}{} stale session record(s); {} live.",
                    pal.head,
                    pal.reset,
                    pal.name,
                    pal.reset,
                    live.len()
                );
            }
            // Hash the stored path directly rather than re-canonicalise: a live session's recorded
            // path is already canonical, so its hash matches the id its tree is keyed by.
            live.iter().map(|s| binds::project_id(&s.project)).collect()
        }
        Err(e) => {
            crate::diag::error(&format!(
                "sbx gc: cannot read the session registry ({e}); skipping session housekeeping."
            ));
            std::collections::BTreeSet::new()
        }
    }
}

/// Reclaim — or, in a dry run, count — the per-launch runtime files left behind by launches that
/// are gone: the egress MITM CA and its sockets, the inbound forwarder's and in-cage portal's
/// runtime directories, the process-observation sockets. Every launch already sweeps these, so this
/// is for the data directory of someone who has stopped launching; it is pure host-side filesystem
/// work (no sandbox, no nix), and stays silent when there is nothing to reclaim.
fn runtime_housekeeping(layout: &crate::store::Layout, prune: bool, pal: &crate::style::Palette) {
    let (h, n, r) = (pal.head, pal.name, pal.reset);
    // Reported apart from the sweep below because it is a different event: these counters are added
    // into the file that replaces them, not discarded. `sbx net stats` answers the same afterwards.
    let folded = super::gc::fold_egress_counters(layout.data_dir(), prune);
    if !folded.is_empty() {
        let verb = if prune { "folded" } else { "would be folded" };
        println!(
            "{h}sbx gc:{r} egress counters — {n}{}{r} finished session file(s) {verb} into one per \
             project; nothing is discarded (`sbx net stats --reset` is what discards).",
            folded.len()
        );
    }
    let stale = super::gc::sweep_runtime_dirs(layout.data_dir(), prune);
    if stale.is_empty() {
        return;
    }
    if prune {
        println!(
            "{h}sbx gc:{r} runtime files — removed {n}{}{r} left by launches that are gone.",
            stale.len()
        );
    } else {
        println!(
            "{h}sbx gc:{r} runtime files — {n}{}{r} left by launches that are gone would be removed.",
            stale.len()
        );
    }
}

/// Garbage-collect the **shared** store: drop the gc roots of channel revisions no longer locked
/// and of reaped projects, then `nix-store --gc` the shared store. Runs *after* the dead-tree reap,
/// so a reaped project's pin no longer keeps its channel revision alive. Held under the exclusive
/// shared-store lock for the whole prune + collection, so a concurrent seed's reflink copy (which
/// holds the same lock shared) can never race the deletion. Best-effort: a missing `nix-store`, or
/// an unlockable store, skips with a note rather than failing the command — like the reap, it is
/// independent of the current-project sweep.
///
/// Concurrency scope, precisely: the lock closes the one corruption window — the seeder's direct
/// copy versus this collector deleting mid-copy. It does **not** cover a launch *provisioning* a
/// brand-new revision (the `nix build --out-link` and the lock write happen outside it), so a
/// launch first-resolving a fresh revision concurrent with a `--prune` can have that revision's
/// just-created gc root pruned (it was not in the live-set snapshot) and its closure collected,
/// after which the launch's seed cache-misses or fails. That is **recoverable** — a re-run
/// re-provisions, and nix's own gc lock still stops the build itself from racing the collector, so
/// it is never corruption. Widening the sbx lock to cover provisioning would make this collector
/// wait behind minutes-long builds, so the narrow lock plus this named residual is the deliberate
/// trade.
pub(super) fn shared_store_gc(
    layout: &crate::store::Layout,
    prune: bool,
    optimise: bool,
    pal: &crate::style::Palette,
) {
    let (h, r) = (pal.head, pal.reset);
    let Some(nix_store) = crate::store::resolve_nix_store(Some(layout)) else {
        eprintln!("sbx gc: nix-store not found; skipping the shared-store gc.");
        return;
    };

    // Exclusive across the whole prune + `nix-store --gc`: it waits for in-flight seeds to release
    // their shared hold, and blocks new seeds until the collection finishes.
    let _lock = match super::projectstore::lock_exclusive(layout) {
        Ok(guard) => guard,
        Err(e) => {
            eprintln!("sbx gc: cannot lock the shared store ({e}); skipping the shared-store gc.");
            return;
        }
    };

    // Read the live revisions *after* acquiring the lock, so the snapshot reflects every lock
    // written before the exclusive acquire settled (no read-then-lock gap).
    let live_base = crate::store::live_base_revisions(layout);
    let live_mise = crate::store::live_mise_revisions(layout);

    let stale = super::gc::prune_shared_gcroots(
        &layout.data_dir().join("gcroots"),
        &layout.data_dir().join("projects"),
        &live_base,
        &live_mise,
        prune,
    );

    let report = match super::gc::collect(&nix_store, &layout.store_dir(), prune) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("sbx gc: shared-store gc failed: {e}");
            return;
        }
    };

    if prune {
        println!(
            "{h}sbx gc:{r} shared store — dropped {} stale gc root(s), collected {} store path(s), freed {}.",
            stale.len(),
            report.paths,
            super::gc::human_bytes(report.bytes)
        );
    } else {
        // On a dry run the stale roots are not dropped, so their closures are still rooted and not
        // yet counted as collectable; the count of stale roots is the signal, and `--prune` frees
        // their closures on top of the orphans reported here (a lower bound).
        println!(
            "{}",
            crate::style::prose(
                &format!(
                    "{h}sbx gc:{r} shared store — {} stale gc root(s) would be dropped; \
                     {} orphaned path(s) reclaimable now ({}). Run `sbx gc --all --prune` to \
                     drop the roots and reclaim their closures.",
                    stale.len(),
                    report.paths,
                    super::gc::human_bytes(report.bytes)
                ),
                pal
            )
        );
    }

    // After the collection, so nothing about to be deleted is deduplicated first. Still under the
    // exclusive lock, which is what keeps a concurrent seed from reading a file mid-relink.
    if optimise {
        report_optimise(&nix_store, &layout.store_dir(), "shared store", pal);
    }
}

/// Deduplicate one store and report the gain, naming which store it was. Best-effort: a failure is
/// reported and does not fail the surrounding collection, since nothing was reclaimed either way.
fn report_optimise(
    nix_store: &std::path::Path,
    store_dir: &std::path::Path,
    label: &str,
    pal: &crate::style::Palette,
) {
    let (h, r, ok) = (pal.head, pal.reset, pal.ok);
    match super::gc::optimise(nix_store, store_dir) {
        Ok(report) if report.inodes_freed == 0 && report.bytes_freed == 0 => {
            println!("{h}sbx gc:{r} {label} — already deduplicated, nothing to reclaim.");
        }
        Ok(report) => println!(
            "{h}sbx gc:{r} {label} — {ok}deduplicated{r}: freed {} across {} inode(s).",
            super::gc::human_bytes(report.bytes_freed),
            report.inodes_freed,
        ),
        Err(e) => eprintln!("sbx gc: {label} — deduplication failed: {e}"),
    }
}

/// Reclaim the current project's own writable store.
///
/// The agent self-equips into a per-project store — `flake:` builds, in-cage installs — and over
/// time a flake revision rolled forward by `sbx upgrade flake` (or a package removed outright)
/// leaves the previous build behind. This reclaims it. Everything the project still needs is
/// gc-rooted by a **host-resolvable** root (one whose target is a `/nix/store/<hash>` path, which
/// the relocated store reads both in-cage and host-side): the seeded base and `nix:` tools are
/// rooted at seed time, mise installs root themselves the same way, and each `flake:` build
/// registers a root keyed by package name that a roll re-points — so the current build survives and
/// the rolled-away one, now unrooted, is collected. A removed package's lingering root (which a
/// roll's overwrite cannot reach) is dropped first, by name, against the set the current config
/// still declares across every runtime. A plain host-side `nix-store --gc` then does the rest with
/// no per-home enumeration: the rooting lives in the store, keyed by build, not in any home — which
/// is why a `flake:` package in an app's own `$HOME` needs no special handling.
///
/// A dry run by default — it reports what would be freed and changes nothing; `--prune` sweeps the
/// dead paths. It refuses while a live sandbox holds the project (its store is in use). Like a
/// launch it provisions the current tools and re-seeds first, which re-establishes the base/tool
/// roots on a store seeded before rooting existed, so a sweep can never delete the unrooted base.
/// Returns `Err(code)` when it cannot run (not a project, no sandbox capability, a nix failure),
/// which the caller treats as fatal — except under `--all`, where the reap has already run.
///
/// Limitation (a follow-up): a build the agent roots only by an in-cage path — a raw `nix build
/// --out-link <non-store-path>` it runs itself, outside the supported self-equip paths (`sbx mise`,
/// `nix profile`, declared `flake:` packages) — is not seen host-side and would be collected. The
/// supported self-equip paths all root by store path, so they survive.
fn sweep_current(prune: bool, optimise: bool, pal: &crate::style::Palette) -> Result<(), ExitCode> {
    let (h, n, dim, r) = (pal.head, pal.name, pal.dim, pal.reset);

    // A project that was never launched has no store to reclaim — and finding that out must not
    // cost anything, so the check runs **before** `prepare()`. Preparing provisions the base
    // userland, so on a cold data directory it downloads an entire toolchain only to then report
    // that there is nothing to reclaim. Its two inputs are exactly the ones `prepare` derives (the
    // process's directory and the data-directory layout), so the identity is the same either way;
    // where either is unavailable the check is skipped and `prepare` below reports that failure in
    // its own words rather than this path second-guessing it. This is also what makes `sbx gc
    // --all` safe to run from any directory: a non-project cwd is skipped, never provisioned.
    let early = std::env::current_dir()
        .ok()
        .zip(Layout::from_env())
        .and_then(|(cwd, layout)| Some((layout, binds::project_identity(&cwd).ok()?)));
    if let Some((layout, (id, project))) = &early
        && !super::projectstore::store_exists(layout, id)
    {
        println!(
            "{h}sbx gc{r} — {n}{}{r}: {dim}no per-project store yet, nothing to reclaim.{r}",
            project.display()
        );
        return Ok(());
    }

    let prep = prepare()?;

    let (id, project) = match binds::project_identity(&prep.cwd) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("sbx gc: cannot resolve the project directory: {e}");
            return Err(ExitCode::FAILURE);
        }
    };

    // Refuse if a live sandbox holds this project: collecting a store a running cage reads and
    // writes could drop a path it still needs. The registry list prunes dead records as it goes.
    if let Ok(sessions) = session::Registry::at(prep.layout.data_dir()).list()
        && sessions.iter().any(|s| s.project == project)
    {
        crate::diag::error(
            "sbx gc: a sandbox is running in this project — stop it first (see `sbx session ls`).",
        );
        return Err(ExitCode::FAILURE);
    }

    // Surface what the trust gate dropped or withheld, exactly as a launch would.
    for warning in &prep.cfg.warnings {
        crate::diag::warn(warning);
    }

    // Provision the project's declared tools and seed its store: the seed gc-roots the base and
    // every `nix:` tool, so the sweep keeps them and collects only orphans — and this re-roots a
    // store seeded before rooting existed. The `flake:` builds carry their own roots from launch.
    let store = equip_for_gc(&prep)?;
    let store_dir = store.store_dir().to_path_buf();

    // Drop the in-cage `sbx-flake-<name>` roots of removed inline `[flakes.<name>]` flakes. Only an
    // inline flake builds in-cage and registers this root (a remote `flake:` is provisioned host-side
    // and carries a data-dir out-link, pruned by `prune_project_package_roots` below); the root is
    // name-keyed and overwritten each launch, so an edit self-cleans, but a removal leaves it pointing
    // at an unwanted build — this prunes those so the sweep reclaims them. The current set spans every
    // runtime — the baseline and each app's merged packages — so an inline flake declared only in an
    // app keeps its root.
    let flake_root_names = |pkgs: &[crate::config::Package]| {
        super::packages::flake_inline_packages(pkgs)
            .into_iter()
            .map(|(name, _, _)| name)
    };
    let mut flake_names: std::collections::BTreeSet<String> =
        flake_root_names(&prep.cfg.packages).collect();
    // The host-provisioned data-dir out-links a removed package leaks: `<data>/gcroots/projects/<id>/
    // <name>` (bare `<name>` for `nix:`, `deb-`/`appimage-`/`tarball-<name>` for a prebuilt) is
    // add-only, so a package no longer declared keeps its out-link — which reads into the keep-set
    // below and holds its per-project store copy forever. Collect the currently-declared set across
    // the same runtimes as the flake names (declared, not trusted: a still-declared package whose
    // trust has merely lapsed must keep its heavy build — see `packages::project_gcroot_names`).
    let mut package_names: std::collections::BTreeSet<String> =
        super::packages::project_gcroot_names(&prep.cfg.packages)
            .into_iter()
            .collect();
    for app in prep.cfg.apps.values() {
        let mut merged = prep.cfg.clone();
        merged.merge_app(app.clone());
        flake_names.extend(flake_root_names(&merged.packages));
        package_names.extend(super::packages::project_gcroot_names(&merged.packages));
    }
    let data_gcroots = prep.layout.data_dir().join("gcroots");
    // Drop the removed packages' roots — flake (inside the project store) and host-provisioned (in the
    // data dir) — *before* the keep-set is read below, so a dropped data-dir out-link no longer holds
    // its per-project seed copy and this same pass reclaims it.
    let pruned = super::gc::prune_flake_roots(&store_dir, &flake_names, prune).len()
        + super::gc::prune_project_package_roots(&data_gcroots, &id, &package_names, prune).len();

    // Reconcile the seed roots too. `gcroot_roots` is add-only, so a superseded build — an old base
    // revision, a rebuilt tool, an app version rolled forward — keeps a permanent direct root and
    // `nix-store --gc` never collects it: the store otherwise accumulates every version ever
    // provisioned. Drop the seed roots whose build no current out-link references so the sweep
    // reclaims them. The keep-set is the union of every out-link family, which only gc (never a
    // single launch's seed) sees.
    // Read off the reference this launch actually resolved, not a second derivation of it: `prep`
    // already holds it, and re-deciding the channel here would have to know which app this is — a
    // fact the sweep has no reason to carry, and would get wrong the day it went stale.
    let base_rev = crate::store::revision_of(&prep.nixpkgs);
    let mise_revs = crate::store::live_mise_revisions(&prep.layout);
    // Prune only when the base *and* mise out-links for the current revisions are present: those two
    // families root the irreducible userland (mise on its own revision, not the base one), so without
    // them the keep-set could omit a current core build and the sweep would delete it. A missing
    // family means we cannot safely tell superseded from sole-current, so skip — a re-provision on
    // the next launch is cheap, a wrongful wipe is not. This out-link check is the whole guard: the
    // revision itself is always known here (the launch resolved it above), so there is no
    // "unknown revision" case to fall through, and pretending there is would hide which condition
    // actually protects the sweep.
    let superseded = if data_gcroots.join("base").join(base_rev).is_dir()
        && mise_revs
            .iter()
            .any(|m| data_gcroots.join("mise").join(m).is_dir())
    {
        // `id` is `project_identity(cwd).0` — the very value `project_runtime_id` returns and the
        // provisioning path keys `<data>/gcroots/projects/<id>/` on — so the projects family of the
        // keep-set cannot drift from where a project's app builds are actually rooted.
        let keep = super::gc::project_keep_roots(&data_gcroots, &id, base_rev, &mise_revs);
        super::gc::prune_superseded_roots(&store_dir, &keep, prune).len()
    } else {
        0
    };

    println!("{h}sbx gc{r} — {n}{}{r}", project.display());
    let report = match super::gc::collect(&prep.nix_store, &store_dir, prune) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("sbx gc: {e}");
            return Err(ExitCode::FAILURE);
        }
    };
    if prune {
        // The dropped roots' builds were unrooted before the sweep, so they are already counted in
        // `report.paths`; name how many roots this pass dropped — removed-package flakes plus
        // superseded seed builds — to explain where the collection came from.
        println!(
            "  {}collected{} {} store path(s) ({} from removed package(s), {} superseded build(s)), freed {}.",
            pal.ok,
            r,
            report.paths,
            pruned,
            superseded,
            super::gc::human_bytes(report.bytes)
        );
    } else {
        // A dry run cannot size the roots it would drop (their builds are still held, so not yet in
        // the dead set), so report their counts separately from the currently-dead total.
        println!(
            "  {}",
            crate::style::dim_prose(
                &format!(
                    "{} store path(s) collectable now, {} would be freed — run `sbx gc --prune` to reclaim.",
                    report.paths,
                    super::gc::human_bytes(report.bytes)
                ),
                pal
            )
        );
        if pruned > 0 || superseded > 0 {
            println!(
                "  {dim}and {pruned} removed-package build(s) + {superseded} superseded build(s) would also be reclaimed.{r}"
            );
        }
    }

    // After the collection, so nothing about to be deleted is deduplicated first. This is the store
    // where deduplication pays: a seeded per-project store arrives as fresh inodes by construction.
    //
    // Unlike the shared store's pass this takes no exclusive lock — a per-project store has none.
    // What guards it is the live-session refusal above: the sweep already declines to touch a store
    // a running cage holds, and this rides that same check, with the same window between it and the
    // work that `--prune` already has here.
    if optimise {
        report_optimise(&prep.nix_store, &store_dir, "this project's store", pal);
    }
    Ok(())
}

/// After an `sbx upgrade` roll, surface — cheaply and best-effort — how many superseded builds the
/// current project's store already holds, pointing at `sbx gc --prune` to reclaim them. A roll is
/// what eventually supersedes a build, so upgrade is the natural moment to remind. Pure filesystem
/// reads: it reuses the gc keep-set derivation over the existing store without provisioning or
/// invoking nix, so it adds no weight to upgrade. Silent when there is no store, when the keep-set
/// guard (the base and mise out-links for the current revisions) cannot be met, or when nothing is
/// superseded — the same guard [`sweep_current`] prunes under, so the count never over-reports (a
/// just-rolled revision whose build is still deferred to the next launch fails the guard, so the
/// hint waits until the superseded state is real).
///
/// `app` is the roll's `--app` selector, so the revision this measures is the one that roll
/// actually moved: an app with its own lock is on its own revision, and reading the project's here
/// would count against a base the app is not on.
pub(crate) fn superseded_reclaimable_hint(
    layout: &Layout,
    cwd: &Path,
    cfg: &crate::config::Resolved,
    app: Option<&str>,
    pal: &crate::style::Palette,
) {
    let Ok(id) = binds::project_runtime_id(cwd) else {
        return;
    };
    if !super::projectstore::store_exists(layout, &id) {
        return;
    }
    let Some(rev) = effective_lock_target(cwd, layout, cfg, app)
        .ok()
        .and_then(|t| t.locked_revision())
    else {
        return;
    };
    let data_gcroots = layout.data_dir().join("gcroots");
    let mise_revs = crate::store::live_mise_revisions(layout);
    if !data_gcroots.join("base").join(&rev).is_dir()
        || !mise_revs
            .iter()
            .any(|m| data_gcroots.join("mise").join(m).is_dir())
    {
        return;
    }
    let store_dir = super::projectstore::store_dir_for(layout, &id);
    let keep = super::gc::project_keep_roots(&data_gcroots, &id, &rev, &mise_revs);
    let n = super::gc::prune_superseded_roots(&store_dir, &keep, false).len();
    if n > 0 {
        println!(
            "  {}",
            crate::style::dim_prose(
                &format!(
                    "{n} superseded build(s) in this project's store are reclaimable — run `sbx gc --prune`."
                ),
                pal
            )
        );
    }
}

/// The context this project's prebuilt (`deb:`/`appimage:`/`tarball:`) packages are provisioned in.
/// See [`super::prebuilt::Ctx`].
fn prebuilt_ctx(prep: &Prepared) -> super::prebuilt::Ctx<'_> {
    super::prebuilt::Ctx {
        nix: &prep.nix,
        layout: &prep.layout,
        project: &prep.cwd,
        nixpkgs: &prep.nixpkgs,
        allow_insecure_http: prep.cfg.allow_insecure_http,
    }
}

/// Provision the project's declared tools and seed its store, returning the store. Mirrors
/// the provisioning a launch does — native `[packages]`, `nix:` tools, and (under the GUI
/// hole) fonts — so the seed gc-roots the same set a launch would, but stops at the seed: gc
/// needs the rooted store, not a runnable cage.
///
/// It inherits a launch's strictness — a withheld (untrusted) tool only warns, but an admitted
/// tool that cannot be realised is fatal — so gc shares a launch's provisioning (and its
/// network need). For protecting the base only the base roots matter, and those come from
/// `prep.userland` without provisioning; re-provisioning the rest keeps gc's rooted set in
/// lockstep with a launch's at the cost of that coupling — an accepted trade for a single
/// source of the project's root set.
fn equip_for_gc(prep: &Prepared) -> Result<super::projectstore::ProjectStore, ExitCode> {
    let mut packages = super::packages::provision(
        &prep.nix,
        &prep.layout,
        &prep.cwd,
        &prep.nixpkgs,
        &prep.cfg.packages,
    )
    .map_err(|e| {
        eprintln!("sbx gc: {e}");
        ExitCode::FAILURE
    })?;
    for warning in &packages.warnings {
        crate::diag::warn(warning);
    }

    // The prebuilt backends are host-side like `nix:`, so their roots must be part of the gc seed
    // too — otherwise the per-project store copy would be collected and re-provisioned every launch.
    // When warm (pinned + built) this is a fast no-op; it mirrors the launch path's provisioning.
    let ctx = prebuilt_ctx(prep);
    for kind in super::prebuilt::DIRECT_ORDER {
        for (name, url) in kind.packages(&prep.cfg.packages) {
            let libs = super::prebuilt::libs_of(&prep.cfg.packages, &name);
            match super::prebuilt::provision(kind, &ctx, &name, &url, &libs) {
                Ok((_, root)) => packages.roots.push(root),
                Err(e) => {
                    crate::diag::error(&format!(
                        "sbx gc: cannot provision {} package `{name}` ({url}): {e}",
                        kind.name()
                    ));
                    return Err(ExitCode::FAILURE);
                }
            }
        }
    }

    // A `<backend>:resolve` package: build from its EXISTING pin only — gc must never run the resolve
    // command or touch the network. An unpinned package (never launched) has nothing built to keep,
    // so it is skipped rather than resolved.
    for kind in super::prebuilt::RESOLVE_ORDER {
        for (name, _command) in kind.resolve_packages(&prep.cfg.packages) {
            let libs = super::prebuilt::libs_of(&prep.cfg.packages, &name);
            match super::prebuilt::provision_resolve_pinned(kind, &ctx, &name, &libs) {
                Ok(Some((_, root))) => packages.roots.push(root),
                Ok(None) => {}
                Err(e) => {
                    crate::diag::error(&format!(
                        "sbx gc: cannot build the pinned {} resolver package `{name}`: {e}",
                        kind.name()
                    ));
                    return Err(ExitCode::FAILURE);
                }
            }
        }
    }

    let tools = mise_tools(prep)?;
    for warning in &tools.warnings {
        crate::diag::warn(warning);
    }

    let font_layer = if prep.cfg.gui.renders() {
        super::fonts::provision(&prep.nix, &prep.layout, &prep.nixpkgs).ok()
    } else {
        None
    };
    let mut gui_roots: Vec<PathBuf> = font_layer
        .as_ref()
        .map_or_else(Vec::new, |l| l.roots.clone());

    // mesa driver roots under `gpu = true`, so gc keeps the built output rather than collecting and
    // re-provisioning it each launch — mirroring the launch path's GPU provisioning and the fonts.
    if prep.cfg.gpu
        && let Ok(layer) = super::gpu::provision(&prep.nix, &prep.layout, &prep.nixpkgs)
    {
        gui_roots.push(layer.root);
    }

    // audio userspace roots under `audio = true`, same reason: gc keeps the client libraries and
    // ALSA shim rather than collecting and re-provisioning them each launch.
    if prep.cfg.audio
        && let Ok(layer) = super::audio::provision(&prep.nix, &prep.layout, &prep.nixpkgs)
    {
        gui_roots.extend(layer.roots);
    }

    // GUI data root (GSettings schemas + GTK themes) under `gui = "wayland"`, same reason: gc keeps
    // the provisioned output.
    if matches!(prep.cfg.gui, crate::config::GuiPolicy::Wayland)
        && let Ok(layer) = super::guidata::provision(&prep.nix, &prep.layout, &prep.nixpkgs)
    {
        gui_roots.push(layer.root);
    }

    // In-cage portal roots under `gui = "wayland"` + `dbus = true`: gc keeps the portal closure.
    if prep.cfg.dbus
        && matches!(prep.cfg.gui, crate::config::GuiPolicy::Wayland)
        && let Ok(p) = super::portal::provision(&prep.nix, &prep.layout, &prep.nixpkgs)
    {
        gui_roots.extend(p.roots);
    }

    seed_project_store(prep, &packages.roots, &tools.roots, &gui_roots).map_err(|e| {
        eprintln!("sbx gc: cannot prepare the project's store: {e}");
        ExitCode::FAILURE
    })
}

/// Launch an interactive shell in the cage for `runtime`, under a pty supervisor so job control
/// works — the shared body of `sbx run` with no command (the project's default home) and `sbx
/// session attach` (which reproduces a session's home, including an app's isolated one). The command
/// is the resolved interactive shell started with `--rcfile` at the synthetic in-cage rc, which
/// activates mise so the project's activated tools (`mise use`) manage PATH/env in the interactive
/// shell — mise's documented interactive mechanism. (A non-interactive `sbx run` instead reaches
/// activated tools through the shims dir on PATH, with no shell to hook.) Assumes stdin is a terminal
/// (the callers check).
fn launch_interactive_shell(prep: &Prepared, runtime: binds::Runtime, observe: bool) -> ExitCode {
    let cmd = vec![
        prep.userland.shell_bin.clone().into_os_string(),
        OsString::from("--rcfile"),
        OsString::from(binds::SHELL_RC_INCAGE),
    ];
    launch_pty_supervised(prep, runtime, Kind::Shell, cmd, observe)
}

/// Launch `cmd` under the pty supervisor: the cage gets a *private* controlling terminal (so job
/// control and terminal-resize propagation work inside), while the real launching terminal stays
/// unreachable — sbx holds the pty master and never execs. Shared by an interactive `sbx run`, `sbx session attach`,
/// and interactive `sbx app`.
///
/// The session is registered and its record held by a [`RecordGuard`] that unlinks it when the
/// session ends (sbx stays alive as the supervisor, so the record is cleaned promptly rather than
/// left for liveness pruning). The egress guard is held for the whole session too: under a network
/// allowlist the host filtering proxy runs on a thread alongside the supervisor, and the guard
/// unlinks its socket and CA on exit.
fn launch_pty_supervised(
    prep: &Prepared,
    runtime: binds::Runtime,
    kind: Kind,
    cmd: Vec<OsString>,
    observe: bool,
) -> ExitCode {
    // A graphical app's real interface is its window, not this terminal — Ctrl+C is forwarded
    // faithfully but a GUI app may ignore it — so note how to stop it. Only for a foreground app
    // launch (`Kind::Run`) with a display; a shell (an interactive `sbx run`/`sbx session attach`, `Kind::Shell`) uses
    // Ctrl+C normally and needs no hint. Computed before `cmd`/`runtime` move into `build`.
    let stop_hint = (matches!(kind, Kind::Run)
        && matches!(prep.cfg.gui, crate::config::GuiPolicy::Wayland))
    .then(|| launch_display_name(&runtime, &cmd));

    let (spec, guard) = match build(prep, runtime, cmd) {
        Ok((s, g)) => (s.with_private_tty(), g),
        Err(code) => return code,
    };

    let _record =
        register(prep.layout.data_dir(), &spec, kind, runtime, false).map(RecordGuard::new);
    // Hold the guard (egress proxy / forward forwarder threads) for the whole pty session.
    let _guard = guard;
    // With observation on, populate the exec ring + control socket so `sbx proc logs`/`sbx proc live`
    // can watch this interactive session from another terminal; held for the whole pty session and
    // torn down on exit. Never inline — this terminal belongs to the agent's TUI.
    let (exec_poll, fs) = observation_flags(&prep.cfg.proc, observe);
    let _observer = (exec_poll || fs).then(|| {
        super::observe_feed::Observation::start(
            prep.layout.data_dir(),
            &spec.workdir,
            exec_poll,
            fs,
            false,
        )
    });

    // The registered pid is this supervisor's own (`Session::current` records `std::process::id()`),
    // which is exactly what `sbx session ls` shows and `sbx session stop` accepts, so the hint names the real id.
    if let Some(name) = stop_hint {
        let epal = crate::style::Palette::for_stream(io::stderr().is_terminal());
        eprintln!("{}", render_gui_stop_hint(&name, std::process::id(), &epal));
    }

    let gui = matches!(prep.cfg.gui, crate::config::GuiPolicy::Wayland);
    match supervise(&prep.bwrap, &spec, &prep.cfg.limits, gui) {
        Ok(code) => ExitCode::from(code as u8),
        Err(e) => {
            eprintln!("sbx: sandbox session failed: {e}");
            ExitCode::FAILURE
        }
    }
}

/// Render the line `sbx session attach` prints before entering a live cage (stderr). Attaching is an
/// announcement, not a completed change, so the verb stays plain; the session pid and label are the
/// identifier (cyan) and the parenthetical is secondary detail (dim).
fn render_attaching(pid: u32, label: &str, pal: &crate::style::Palette) -> String {
    let (n, r) = (pal.name, pal.reset);
    format!(
        "sbx: attaching to session {n}{pid}{r} ({n}{label}{r}) {}",
        crate::style::dim_prose(
            "(a shell in its live cage — type `exit` to leave the agent running)",
            pal
        )
    )
}

/// The name a launch shows in the graphical-app stop hint: the app name for an `sbx app`, else the
/// program's own basename for a plain `sbx run` into a GUI project. Falls back to a generic word if
/// the command is somehow empty, so the hint is always well-formed.
fn launch_display_name(runtime: &binds::Runtime, cmd: &[OsString]) -> String {
    match runtime {
        binds::Runtime::GlobalApp(name) | binds::Runtime::ProjectApp(name) => (*name).to_string(),
        binds::Runtime::ProjectDefault => cmd
            .first()
            .map(|c| {
                Path::new(c)
                    .file_name()
                    .unwrap_or(c.as_os_str())
                    .to_string_lossy()
                    .into_owned()
            })
            .unwrap_or_else(|| "the app".to_string()),
    }
}

/// The line a foreground graphical launch prints (stderr) so the user knows how to stop it: its UI
/// is the window, and a single Ctrl+C — though forwarded — is ignored by a GUI app (and a tray-backed
/// window may not quit on close), so the escape hatches are named: a double Ctrl+C force-quits the
/// session, and `sbx session stop <pid>` works from any other terminal. The app name is the identifier
/// (cyan); the rest is plain, matching the restraint of the attach announcements.
fn render_gui_stop_hint(name: &str, pid: u32, pal: &crate::style::Palette) -> String {
    let (n, r) = (pal.name, pal.reset);
    format!(
        "sbx: {n}{name}{r} {}",
        crate::style::prose(
            &format!(
                "is graphical — press Ctrl+C twice here to quit (closing its window may only \
                 hide it — a tray app keeps running); `sbx session stop {pid}` also stops it."
            ),
            pal
        )
    )
}

/// `sbx session attach <id> [-- command [args...]]`: join a *running* session's cage and either
/// open an interactive shell **inside** it or run one command there — the agent's live processes,
/// its real `/tmp`, its network — the way `docker exec` / `docker exec -it` works. `<id>` is the
/// PID `sbx session ls` shows. With no command it opens the interactive rc shell (needs a terminal);
/// with `-- command` it runs that command, driven through a pty when stdin is a terminal (so an
/// interactive tool keeps job control) or through inherited stdio when it is a pipe/script (so bytes
/// pass through clean for scripting). Unlike a launch, this enters namespaces bubblewrap already
/// built (via `setns`), so it provisions nothing and re-resolves no config; it re-applies the cage's
/// confinement (seccomp denylist + `no_new_privs` + capability drop) so the joined process is
/// confined at least as tightly as the agent. See [`mod@super::attach`] for the mechanism and its
/// one inherent residual (the command binary comes from the agent's own mount namespace).
pub(crate) fn attach(id: &str, cmd: Vec<OsString>) -> ExitCode {
    let Some(layout) = Layout::from_env() else {
        eprintln!(
            "sbx: cannot resolve the data directory (no $SBX_DATA_DIR, $XDG_DATA_HOME or $HOME)."
        );
        return ExitCode::FAILURE;
    };
    let sessions = match session::Registry::at(layout.data_dir()).list() {
        Ok(s) => s,
        Err(e) => {
            eprintln!("sbx session attach: cannot read the session registry: {e}");
            return ExitCode::FAILURE;
        }
    };
    // A pid is unique among live processes, so this is a 0-or-1 match. Resolve the target before
    // the terminal check, so an unknown id is reported even without a tty.
    let Some(target) = sessions.into_iter().find(|s| s.pid.to_string() == id) else {
        crate::diag::error(&format!(
            "sbx session attach: no live session '{id}' — run `sbx session ls` to list them."
        ));
        return ExitCode::from(2);
    };
    // SAFETY: `isatty` only inspects fd 0. A bare attach opens an interactive shell, which needs a
    // real terminal (like `shell`); a command drives its terminal setup from this — a pty when it
    // has one, inherited stdio otherwise — so it imposes no terminal requirement.
    let stdin_tty = unsafe { libc::isatty(0) } == 1;
    if cmd.is_empty() && !stdin_tty {
        crate::diag::error(
            "sbx: `sbx session attach` needs a terminal on stdin (or pass `-- command`).",
        );
        return ExitCode::from(2);
    }

    // Locate a live process inside the cage (the session pid is the cage's host-side anchor). A
    // `None` here means the cage has no in-namespace process left — it exited between `sbx session ls` and
    // now, or the host has no user namespaces (then it never had a cage).
    let Some(cage_pid) = super::attach::find_cage_pid(target.pid) else {
        crate::diag::error(&format!(
            "sbx session attach: session '{id}' has no live process to enter — it may have just exited \
             (run `sbx session ls`)."
        ));
        return ExitCode::FAILURE;
    };
    let cage = match super::attach::open_cage_handle(cage_pid) {
        Ok(h) => h,
        Err(e) => {
            eprintln!("sbx session attach: cannot open a handle to session '{id}''s cage: {e}");
            return ExitCode::FAILURE;
        }
    };
    let environ = super::attach::read_environ(cage_pid);

    // The in-cage argv: the interactive rc shell for a bare attach, or the command run through
    // `bash -c 'exec "$@"'` so bash resolves it on the cage PATH and execs it in place.
    let argv_owned = match attach_argv(&cmd) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("sbx session attach: {e}");
            return ExitCode::FAILURE;
        }
    };

    // Only the interactive shell announces itself ("type `exit` to leave"); a command is silent
    // like `sbx run`, so its stdout/stderr are exactly the command's.
    if cmd.is_empty() {
        let epal = crate::style::Palette::for_stream(io::stderr().is_terminal());
        eprintln!("{}", render_attaching(target.pid, &target.label(), &epal));
    }

    // A terminal on stdin drives the command through a pty (interactive, job control); a pipe or
    // script through inherited stdio (clean bytes). A bare shell always takes the pty path — it is
    // gated to a terminal above, so `stdin_tty` holds here.
    let result = if stdin_tty {
        supervise_attach(cage, &environ, &argv_owned)
    } else {
        run_attach_direct(cage, &environ, &argv_owned)
    };
    match result {
        Ok(code) => ExitCode::from(code as u8),
        Err(e) => {
            eprintln!("sbx: attach session failed: {e}");
            ExitCode::FAILURE
        }
    }
}

/// Build the in-cage argv for an attach. With no command this is the interactive shell reading the
/// in-cage rc (mise activation + the `(sbx-<slug>)` prompt), exactly like an interactive `sbx run`. With a
/// command it is `bash -c 'exec "$@"' bash <cmd> [args…]`: bash resolves `<cmd>` on the cage PATH
/// (from the cage environment passed as its `envp`) and execs it **in place**, so the command's
/// exit status propagates; the command is passed **positionally** (`"$@"`), so no argument is ever
/// interpreted as shell syntax — zero injection surface. `/bin/bash` and the rc are absolute cage
/// paths that resolve in the cage's own mount namespace once the child has entered it.
fn attach_argv(cmd: &[OsString]) -> io::Result<Vec<CString>> {
    if cmd.is_empty() {
        return Ok(vec![
            cstring(binds::SANDBOX_BASH.as_bytes())?,
            cstring(b"--rcfile")?,
            cstring(binds::SHELL_RC_INCAGE.as_bytes())?,
        ]);
    }
    let mut argv = vec![
        cstring(binds::SANDBOX_BASH.as_bytes())?,
        cstring(b"-c")?,
        cstring(b"exec \"$@\"")?,
        cstring(b"bash")?,
    ];
    for arg in cmd {
        argv.push(cstring(arg.as_bytes())?);
    }
    Ok(argv)
}

/// Supervise a real attach: open a pty, fork a child that joins the cage's namespaces and execs the
/// confined `argv_owned` inside it, and relay the terminal — the same pty machinery as
/// [`supervise`], but the child enters an *existing* cage rather than launching a new one, so there
/// is no bwrap argv, no cgroup scope, and no session record (the attach guest is a transient guest
/// of the agent's cage, not a session of its own). Used for a bare interactive shell and for a
/// command run from a terminal (so an interactive tool keeps job control).
fn supervise_attach(
    cage: super::attach::CageHandle,
    environ: &[u8],
    argv_owned: &[CString],
) -> io::Result<i32> {
    // The baseline mandatory denylist — never a project's `[seccomp] allow` relaxation — so the
    // joined process is confined at least as tightly as the agent. Compiled before the fork.
    let filters = super::seccomp::filter_bytes(&super::seccomp::SeccompPolicy::default());

    // argv: prebuilt by `attach_argv` (the interactive rc shell, or `bash -c 'exec "$@"' …`),
    // resolving in the cage's own mount namespace once the child has entered it.
    let mut argv: Vec<*const libc::c_char> = argv_owned.iter().map(|c| c.as_ptr()).collect();
    argv.push(std::ptr::null());

    // envp: the agent's own cage environment (its PATH, proxy, and CA settings), with TERM set to
    // the attaching terminal's so rendering and resize match.
    let term = std::env::var("TERM").ok();
    let envp_owned = super::attach::build_env(environ, term.as_deref());
    let mut envp: Vec<*const libc::c_char> = envp_owned.iter().map(|c| c.as_ptr()).collect();
    envp.push(std::ptr::null());

    // Carry the real terminal's window size onto the pty so the inner shell wraps correctly from
    // the start (as `supervise` does).
    let mut ws: libc::winsize = unsafe { std::mem::zeroed() };
    let winp = if unsafe { libc::ioctl(0, libc::TIOCGWINSZ, &mut ws) } == 0 {
        &ws as *const libc::winsize
    } else {
        std::ptr::null()
    };
    let mut master: libc::c_int = -1;
    let mut slave: libc::c_int = -1;
    if unsafe {
        libc::openpty(
            &mut master,
            &mut slave,
            std::ptr::null_mut(),
            std::ptr::null(),
            winp,
        )
    } != 0
    {
        return Err(io::Error::last_os_error());
    }
    // The master must never reach the cage; the parent keeps it and never execs.
    unsafe {
        let flags = libc::fcntl(master, libc::F_GETFD);
        libc::fcntl(master, libc::F_SETFD, flags | libc::FD_CLOEXEC);
    }

    // SAFETY: between fork and exec the child calls only async-signal-safe code — `close`, then
    // `attach::enter_and_exec`, which uses only raw syscalls — and argv/envp/filters/pidfd are all
    // prebuilt above. The parent is single-threaded here (attach starts no egress proxy thread).
    let child = unsafe { libc::fork() };
    if child < 0 {
        let e = io::Error::last_os_error();
        unsafe {
            libc::close(master);
            libc::close(slave);
        }
        return Err(e);
    }
    if child == 0 {
        unsafe {
            libc::close(master);
            super::attach::enter_and_exec(
                &cage,
                &filters,
                super::attach::TtyMode::Pty(slave),
                argv.as_ptr(),
                envp.as_ptr(),
            );
        }
    }

    // Parent: drop the slave and the cage handle (the child holds its own copies across the fork),
    // keep the master, go raw, relay — identical to `supervise`'s tail (no GUI double-Ctrl+C here).
    unsafe { libc::close(slave) };
    drop(cage);
    let _raw = RawMode::enable(0)?;
    let winch = WinchRelay::install().ok();
    if winch.is_some() {
        copy_winsize(0, master);
    }
    let winch_fd = winch.as_ref().map_or(-1, WinchRelay::read_fd);
    let status = pump(master, child, winch_fd, false);
    drop(winch);
    unsafe { libc::close(master) };
    status
}

/// Run an attach command with **inherited** stdio (no pty): fork a child that joins the cage's
/// namespaces and execs the confined `argv_owned` inside it, keeping sbx's own stdin/stdout/stderr,
/// then wait and mirror its exit status. This is the pipe/script path — bytes pass through clean
/// (no pty `\n`→`\r\n` translation), so `sbx session attach <id> -- cmd` composes with pipes and
/// redirection. Only reached when stdin is not a terminal (a command from a terminal takes the pty
/// path in [`supervise_attach`] for interactive job control).
fn run_attach_direct(
    cage: super::attach::CageHandle,
    environ: &[u8],
    argv_owned: &[CString],
) -> io::Result<i32> {
    // The same baseline denylist the pty path installs — the command is confined at least as
    // tightly as the agent, never a project's `[seccomp] allow` relaxation. Compiled before the fork.
    let filters = super::seccomp::filter_bytes(&super::seccomp::SeccompPolicy::default());

    let mut argv: Vec<*const libc::c_char> = argv_owned.iter().map(|c| c.as_ptr()).collect();
    argv.push(std::ptr::null());

    // envp: the agent's own cage environment (PATH/proxy/CA), TERM carried through from sbx.
    let term = std::env::var("TERM").ok();
    let envp_owned = super::attach::build_env(environ, term.as_deref());
    let mut envp: Vec<*const libc::c_char> = envp_owned.iter().map(|c| c.as_ptr()).collect();
    envp.push(std::ptr::null());

    // SAFETY: between fork and exec the child touches only async-signal-safe code
    // (`attach::enter_and_exec` — raw syscalls only) with the prebuilt argv/envp/filters/pidfd. The
    // parent is single-threaded here (attach starts no egress proxy thread). The child inherits
    // sbx's stdin/stdout/stderr (`TtyMode::Inherit`), so the command's I/O passes through clean.
    let child = unsafe { libc::fork() };
    if child < 0 {
        return Err(io::Error::last_os_error());
    }
    if child == 0 {
        unsafe {
            super::attach::enter_and_exec(
                &cage,
                &filters,
                super::attach::TtyMode::Inherit,
                argv.as_ptr(),
                envp.as_ptr(),
            );
        }
    }

    // Parent: the child holds its own copy of the cage handle across the fork, so drop ours.
    drop(cage);
    // Reap the child (the `enter_and_exec` intermediary), which has already normalized its
    // grandchild's exit into a plain status (`128 + signo` for a signal death, `126`/`127` on a
    // setup failure), so `WEXITSTATUS` alone carries the command's exit code.
    let mut status: libc::c_int = 0;
    loop {
        if unsafe { libc::waitpid(child, &mut status, 0) } >= 0 {
            break;
        }
        let e = io::Error::last_os_error();
        if e.raw_os_error() != Some(libc::EINTR) {
            return Err(e);
        }
    }
    if libc::WIFEXITED(status) {
        Ok(libc::WEXITSTATUS(status))
    } else if libc::WIFSIGNALED(status) {
        Ok(128 + libc::WTERMSIG(status))
    } else {
        Ok(126)
    }
}

/// Render the `sbx session stop --all` line for an empty registry (stdout): nothing to stop is a no-op
/// success, so the message is secondary detail (dim).
fn render_no_active_sessions(pal: &crate::style::Palette) -> String {
    let (dim, r) = (pal.dim, pal.reset);
    format!("sbx session stop: {dim}no active sessions to stop.{r}")
}

/// `sbx session stop <id>...` / `sbx session stop --all`: stop running sessions. With ids, stop the named ones (the
/// pids `sbx session ls` shows); with `all`, stop every live session. Each session is sent SIGTERM, then
/// SIGKILL if it has not exited within `grace`. Targets are resolved through the same
/// liveness-validated registry `attach` uses, so a stale or reused pid is never signalled. For ids,
/// reports each and exits 2 if any matched no live session, else 0; for `--all`, stopping nothing is
/// a no-op success (there is simply nothing to do). A session the host refused a *handle* on — not
/// the same thing as one that had already exited — is reported and exits 1 under either form: it
/// may still be running, which outranks a name that matched nothing.
///
/// Residuals (named, not fixed here), both because a signal terminates a supervisor without running
/// its RAII drops:
/// - the `network = "deny"` supervisor leaves its per-session egress socket and CA under
///   `<data>/egress/` on disk — the same leak any crash or `SIGKILL` of that process already
///   produces; a future sweep of stale egress artefacts (alongside the session housekeeping) is the
///   clean fix.
/// - stopping an interactive `sbx run` session signals its pty supervisor, whose terminal-state restore is
///   also a RAII guard, so the owner's terminal (where that an interactive `sbx run` runs) is left in raw mode
///   and needs a `reset`. Stopping a backgrounded agent — the verb's purpose — is unaffected; this
///   only bites the unusual case of stopping an interactive shell from another terminal. `--all`
///   targets *every* session, interactive shells included (a deliberate choice — "all" means all,
///   matching how `sbx session stop <id>` already treats a shell), so it can trip this residual on a shell
///   open elsewhere; stop a single agent by pid to avoid it.
pub(crate) fn stop(ids: &[&str], grace: Duration, all: bool) -> ExitCode {
    let Some(layout) = crate::store::Layout::from_env() else {
        eprintln!(
            "sbx: cannot resolve the data directory (no $SBX_DATA_DIR, $XDG_DATA_HOME or $HOME)."
        );
        return ExitCode::FAILURE;
    };
    let registry = session::Registry::at(layout.data_dir());
    let sessions = match registry.list() {
        Ok(s) => s,
        Err(e) => {
            eprintln!("sbx session stop: cannot read the session registry: {e}");
            return ExitCode::FAILURE;
        }
    };

    // The outcome lines go to stderr, so they take their hue from stderr — built once, not per
    // session in the `--all` loop.
    let epal = crate::style::Palette::for_stream(io::stderr().is_terminal());

    if all {
        if sessions.is_empty() {
            let pal = crate::style::Palette::for_stream(io::stdout().is_terminal());
            println!("{}", render_no_active_sessions(&pal));
            return ExitCode::SUCCESS;
        }
        // Sessions are independent cages (separate pid namespaces), so they are torn down one after
        // another — never interfering. A well-behaved agent exits on SIGTERM well before its grace
        // window elapses, so this is not grace-per-session in practice.
        let mut all_accounted = true;
        for target in &sessions {
            all_accounted &= stop_session(&registry, target, grace, &epal);
        }
        return ExitCode::from(stop_exit_code(!all_accounted, false));
    }

    let mut any_missing = false;
    let mut any_unstopped = false;
    for id in ids {
        let Some(target) = sessions.iter().find(|s| s.pid.to_string() == *id) else {
            crate::diag::error(&format!(
                "sbx session stop: no live session '{id}' — run `sbx session ls` to list them."
            ));
            any_missing = true;
            continue;
        };
        any_unstopped |= !stop_session(&registry, target, grace, &epal);
    }

    ExitCode::from(stop_exit_code(any_unstopped, any_missing))
}

/// Render one session's stop outcome (stderr): a clean SIGTERM stop is a real change (green
/// `stopped`), an already-exited session is a no-op (dim), and a forced SIGKILL is the caution hue
/// (yellow). The pid and label identify the session (cyan).
fn render_stop_outcome(
    pid: u32,
    label: &str,
    outcome: &session::StopOutcome,
    grace: Duration,
    pal: &crate::style::Palette,
) -> String {
    let (n, ok, warn, err, dim, r) = (pal.name, pal.ok, pal.warn, pal.err, pal.dim, pal.reset);
    match outcome {
        session::StopOutcome::AlreadyGone => {
            format!(
                "sbx session stop: session {n}{pid}{r} ({n}{label}{r}) {dim}had already exited{r}."
            )
        }
        session::StopOutcome::Terminated => {
            format!("sbx session stop: {ok}stopped{r} session {n}{pid}{r} ({n}{label}{r}).")
        }
        session::StopOutcome::Killed => {
            format!(
                "sbx session stop: session {n}{pid}{r} ({n}{label}{r}) did not exit within {}s — \
                 {warn}sent SIGKILL{r}.",
                grace.as_secs()
            )
        }
        session::StopOutcome::NotSignalled(errno) => {
            format!(
                "sbx session stop: {err}cannot stop{r} session {n}{pid}{r} ({n}{label}{r}): {} — \
                 it was not signalled and may still be running.",
                io::Error::from_raw_os_error(*errno)
            )
        }
    }
}

/// Stop one resolved session and, when it is accounted for, reap its record: SIGTERM, then
/// SIGKILL after `grace`, report the outcome by pid and label, and drop the record so
/// `sbx session ls` is clean at once rather than waiting for the killed process to stop reading as
/// a zombie.
///
/// Returns whether the session is accounted for — stopped, or already gone. The one case that is
/// neither keeps its record: when the host refused a handle on the process, nothing was signalled
/// and the cage may still be up, so the record is what still names it to a listing and to a second
/// attempt. Dropping it there would trade a stop that failed for a cage nothing can address.
fn stop_session(
    registry: &session::Registry,
    target: &session::Session,
    grace: Duration,
    pal: &crate::style::Palette,
) -> bool {
    let outcome = target.stop(grace);
    eprintln!(
        "{}",
        render_stop_outcome(target.pid, &target.label(), &outcome, grace, pal)
    );
    if matches!(outcome, session::StopOutcome::NotSignalled(_)) {
        return false;
    }
    registry.reap(target);
    true
}

/// The exit code a `stop` run reports, from what its loops observed — one definition for both
/// forms of the verb, so `--all` and a list of ids answer a caller the same way.
///
/// A session that was never signalled outranks an id that matched nothing: both are failures, and
/// the one that leaves a cage running is the one the caller must act on — the other is a typo.
fn stop_exit_code(any_unstopped: bool, any_missing: bool) -> u8 {
    if any_unstopped {
        1
    } else if any_missing {
        2
    } else {
        0
    }
}

/// Hard prerequisites + per-launch resolution shared by `run` and `shell`. Returns
/// a [`Prepared`] or an `ExitCode` to return after a clean, pointed error.
///
/// The configuration is loaded here (once, infallibly) because its `nixpkgs` field
/// chooses the channel the **whole** launch resolves against — base userland and
/// tools alike (see [`Prepared`] for why they must be one).
fn prepare() -> Result<Prepared, ExitCode> {
    prepare_with(&crate::config::Override::none(), None)
}

/// [`prepare`] with a one-shot override applied. The override's **nixpkgs channel** is applied to
/// the loaded config *before* the lock target is chosen (the channel decides which lock the whole
/// launch resolves against), so a `-o nixpkgs=…` / `SBX_CONFIG` channel takes effect. The rest of
/// the override (env, binds, network, gui, limits, secret) is applied by the caller with
/// [`crate::config::Resolved::apply_override`] — after any app overlay merges, so it beats that too.
///
/// `app` names the app this launch is for, when it is one. It arrives here — before the app's
/// overlay is even looked up — because the channel is resolved here, and an app resolves against
/// its own lock ([`effective_lock_target`]). It is only ever the *identity* of the launch: nothing
/// of the app's configuration is read at this point, and nothing here can be influenced by it.
fn prepare_with(ov: &crate::config::Override, app: Option<&str>) -> Result<Prepared, ExitCode> {
    prepare_in(launch_cwd()?, ov, app)
}

/// The project directory a launch invoked without an explicit one is built from.
fn launch_cwd() -> Result<PathBuf, ExitCode> {
    std::env::current_dir().map_err(|e| {
        eprintln!("sbx: cannot read the current directory: {e}");
        ExitCode::FAILURE
    })
}

/// [`prepare_with`] against an explicit project directory instead of the process's current
/// directory. The whole cage — its per-project store, home, and resolved config — is built from
/// `cwd`, so a caller that retargets another project (`sbx upgrade --project <path>`) drives the
/// in-cage roll against *that* project, not wherever the command happened to be invoked.
fn prepare_in(
    cwd: PathBuf,
    ov: &crate::config::Override,
    app: Option<&str>,
) -> Result<Prepared, ExitCode> {
    prepare_engines(prepare_config(cwd, ov)?, app)
}

/// The half of a launch's preparation that needs no engine: where sbx keeps its data, and the
/// project's configuration with the one-shot override applied and validated.
///
/// It is a separate step because **the answers it gives do not depend on the host being able to
/// sandbox**. A mistyped `--config network=…` is the caller's own error whether or not bubblewrap
/// is installed, and it exits 2 either way; an app the project does not declare is not declared on
/// a host with no engines either. Deciding those before [`prepare_engines`] is what keeps the
/// diagnosis pointed at what the caller can fix, and keeps the documented exit code from depending
/// on what the machine happens to have installed.
struct PreparedConfig {
    layout: Layout,
    cwd: PathBuf,
    cfg: crate::config::Resolved,
}

fn prepare_config(cwd: PathBuf, ov: &crate::config::Override) -> Result<PreparedConfig, ExitCode> {
    // The data directory is resolved first: it is where sbx looks for (and, under the
    // bundled features, materializes) the engines it owns, so `resolve_bwrap` needs it.
    let Some(layout) = Layout::from_env() else {
        eprintln!(
            "sbx: cannot resolve the data directory (no $SBX_DATA_DIR, $XDG_DATA_HOME or $HOME)."
        );
        return Err(ExitCode::FAILURE);
    };
    let mut cfg = crate::config::load(&cwd);
    // The override's nixpkgs channel must land before the lock target is chosen. A set-but-invalid
    // channel is a hard error (no safe baseline fallback for a supply-chain field).
    if let Err(e) = cfg.apply_override_channel(ov) {
        eprintln!("sbx: {e}");
        return Err(ExitCode::from(2));
    }
    // Reject a mistyped scalar security value (network/gui/limits) now — before the engines are
    // probed and before the expensive channel/userland resolution — so a typo aborts fast rather
    // than after a provision. The full override (this plus the additive fields) is applied at the
    // launch's final point.
    if let Err(errs) = cfg.validate_override(ov) {
        for e in errs {
            eprintln!("sbx: {e}");
        }
        return Err(ExitCode::from(2));
    }
    Ok(PreparedConfig { layout, cwd, cfg })
}

/// The half that needs the host to be able to sandbox: the engines, the user namespace, and the
/// channel/userland resolution they drive.
///
/// `app` is the launch's identity only — it selects which lock the resolution runs against
/// ([`effective_lock_target`]), and nothing of the app's configuration is read here. A caller that
/// has already taken the app out of the configuration (as [`app`] does, to refuse an undeclared one
/// before reaching this point) therefore loses nothing by doing so.
fn prepare_engines(pc: PreparedConfig, app: Option<&str>) -> Result<Prepared, ExitCode> {
    let PreparedConfig { layout, cwd, cfg } = pc;
    let Some(bwrap) = crate::store::resolve_bwrap(Some(&layout)).map(|c| c.path) else {
        return Err(missing("bubblewrap (the sandbox engine)"));
    };
    if !matches!(crate::probe_userns(), crate::Userns::Ok) {
        crate::diag::error(
            "sbx: no capability-bearing user namespace — the sandbox cannot run. See `sbx doctor`.",
        );
        return Err(ExitCode::FAILURE);
    }
    // A cage is going to run, so this is where the scopes of the cages that already finished are
    // reclaimed. Every launch path reaches this function, and the sweep runs once per process.
    super::cgroup::sweep_stale_scopes();
    let Some(nix) = crate::store::resolve_nix(Some(&layout)) else {
        return Err(missing("nix (the store engine)"));
    };
    let Some(nix_store) = crate::store::resolve_nix_store(Some(&layout)) else {
        return Err(missing("nix-store (the store database tool)"));
    };

    let nixpkgs = match effective_lock_target(&cwd, &layout, &cfg, app)
        .and_then(|t| t.resolve(&nix, &layout))
    {
        Ok(r) => r,
        Err(e) => {
            eprintln!("sbx: cannot resolve the nixpkgs channel: {e}");
            return Err(ExitCode::FAILURE);
        }
    };
    // The mise engine resolves against its own dedicated lock (the global channel source,
    // rolled independently by `sbx upgrade mise`), never this launch's possibly-pinned
    // base reference. Resolved *after* the base so its lock can be seeded from the base's
    // on first use (no network, and a binary update never bumps the engine — see
    // `resolve_engine_ref`). Threaded to both mise consumers: the in-cage engine (the base
    // userland) and the host-side `[env]` driver.
    let engine_ref =
        match crate::store::resolve_engine_ref(&nix, &layout, cfg.nixpkgs_global.as_deref()) {
            Ok(r) => r,
            Err(e) => {
                eprintln!("sbx: cannot resolve the mise engine channel: {e}");
                return Err(ExitCode::FAILURE);
            }
        };
    let userland = match super::fhs::resolve_userland(&nix, &layout, &nixpkgs, &engine_ref) {
        Ok(u) => u,
        Err(e) => {
            eprintln!("sbx: cannot resolve the sandbox userland: {e}");
            return Err(ExitCode::FAILURE);
        }
    };
    Ok(Prepared {
        bwrap,
        nix,
        nix_store,
        layout,
        cwd,
        cfg,
        nixpkgs,
        engine_ref,
        userland,
        quiet_equip: false,
    })
}

/// The single channel decision for a launch — the one place that picks "which source, which lock",
/// so the launch (resolve), `sbx upgrade` (refresh), and `sbx config` (display) all act on the same
/// lock and can never drift.
///
/// Three branches, in this order:
///
/// - **A trusted per-project `nixpkgs` pin wins, app or no app.** An app launch inherits the
///   baseline's packages (`Resolved::merge_app` overrides by name, it does not replace the list),
///   so the project's declared tools build in that launch too — and they must build from the
///   pinned revision or the pin promises nothing. This is also the one-channel rule: one launch,
///   one revision, base userland and tools alike.
/// - **Otherwise an app resolves against its own lock** ([`crate::store::LockTarget::app`]), so
///   `sbx upgrade nix --app <name>` moves one app and a global roll leaves it where it is. The
///   *source* is still not the app's to choose — `nixpkgs` under an app is a refused key — only the
///   resolution is frozen per app.
/// - **Otherwise the global channel**: a global-config override, else the default.
///
/// Only the pinned case canonicalises the project to derive its lock path, so the common no-pin
/// path does no extra work and a per-project lock is never even named without a current pin.
pub(crate) fn effective_lock_target(
    cwd: &Path,
    layout: &Layout,
    cfg: &crate::config::Resolved,
    app: Option<&str>,
) -> io::Result<crate::store::LockTarget> {
    match (cfg.nixpkgs_project.as_deref(), app) {
        (Some(source), _) => {
            let id = binds::project_runtime_id(cwd)?;
            Ok(crate::store::LockTarget::project(layout, &id, source))
        }
        (None, Some(name)) => {
            crate::store::LockTarget::app(layout, name, cfg.nixpkgs_global.as_deref())
        }
        (None, None) => Ok(crate::store::LockTarget::global(
            layout,
            cfg.nixpkgs_global.as_deref(),
        )),
    }
}

/// Establish the mountpoint-chain pins that protect sbx's control plane: create each pin's host
/// path (they are sbx's own directories — creating a not-yet-existent root here is what stops the
/// agent pre-creating it unpinned) and turn it into the extra bind that freezes it. On the first
/// path that cannot be created, return the error so the caller can fail the launch closed: a pin
/// that cannot be established would leave the containing read-write bind unprotected.
fn establish_control_plane_pins(pins: &[crate::config::Bind]) -> io::Result<Vec<binds::ExtraBind>> {
    pins.iter()
        .map(|pin| {
            std::fs::create_dir_all(&pin.path)
                .map_err(|e| io::Error::new(e.kind(), format!("{}: {e}", pin.path.display())))?;
            Ok(binds::ExtraBind {
                src: pin.path.clone(),
                dest: pin.path.clone(),
                writable: pin.writable,
            })
        })
        .collect()
}

/// The host-side resources a launch must keep alive for the whole session — a filtering egress
/// proxy, an forward loopback forwarder, or both — returned by [`build`] and held by the
/// supervisor paths ([`run_supervised`], the `--detach` child) so the proxy/forwarder threads
/// outlive the cage. `None` means no such resource: the launcher exec-replaces (the command's
/// exit status becomes sbx's). Dropping the guard drops both, unlinking the on-disk artifacts and
/// closing the listeners; the threads are detached and exit when their listener closes.
pub(crate) struct LaunchGuard {
    pub(crate) egress: Option<egress::Egress>,
    /// The filtering ssh-agent broker (`[ssh_agent] allow`), when one is running. Its accept loop is
    /// a detached host thread that must outlive the cage; this owns the socket file, unlinked when
    /// the launch ends.
    pub(crate) ssh_agent: Option<sshagent::SshAgent>,
    /// The broker plugins standing in front of a host resource (`[broker.<name>]`), one guard per
    /// binding. Same reason as the agent's: each owns a socket file and a detached accept loop that
    /// must outlive the cage, and dropping it unlinks the socket. Holding these in a local would
    /// unlink them before the cage is even built.
    pub(crate) brokers: Vec<broker::Broker>,
    /// The reader's end of the brokers' shared decision record, when this launch declared any. Held
    /// here for the same reason the brokers themselves are, and one more: it belongs to the session
    /// rather than to any one broker, so it must outlive the first of them to be torn down.
    pub(crate) broker_feed: Option<broker::BrokerFeed>,
    /// The reader's end of the signer record, when this launch declared a signer. Shared by the
    /// agent's proxy and every per-invocation proxy a declared operation stands up, so it outlives
    /// all of them.
    pub(crate) signer_feed: Option<super::signer_control::SignerFeed>,
    pub(crate) forward: Option<forward::Forwarder>,
    /// The in-cage desktop-notifications relay (`dbus = true`), when one is running. It runs on a
    /// host thread bridging the private bus to the host notifications daemon, so it must outlive the
    /// cage; dropping it stops the thread. Dropped before `portal`, so it disconnects from the private
    /// bus before the portal's host directory (and its socket) is removed.
    pub(crate) notify: Option<super::notify_relay::NotifyRelay>,
    /// The in-cage live-theme relay (`dbus = true`), when one is running. It runs on a host thread
    /// mirroring host light/dark changes into the cage's GSettings keyfile, so it must outlive the
    /// cage; dropping it stops the thread. It writes only a host-side file (no private-bus dependency),
    /// so its drop order relative to `portal` is not load-bearing.
    pub(crate) theme: Option<super::theme_relay::ThemeRelay>,
    /// The in-cage portal's host runtime directory (`dbus = true`), when one is bound. The
    /// private bus socket lives under it on the host, so it must be cleaned up when the launch ends
    /// rather than leaked by an exec — its presence forces the supervised path; dropping it removes
    /// the directory (socket and generated config).
    pub(crate) portal: Option<super::portal::HostDir>,
    /// The refusal notifier (`[notify]`), held for as long as any lens can still refuse something.
    /// Dropping the guard stops delivery and reports whatever the queue could not hold — explicitly,
    /// rather than leaving that to whichever `Arc` happens to fall last.
    pub(crate) notify_sink: Option<Arc<super::notify_sink::NotifyWiring>>,
    /// The exec-enforcement supervisor (`[proc] mode = enforce|ask`), when one is running. Its
    /// receive loop is a host thread deciding every notified `execve`, so it must outlive the cage;
    /// its presence forces the supervised path (a live parent). Dropping it stops the supervisor and
    /// unlinks the handoff socket.
    pub(crate) proc_enforce: Option<super::proc_enforce::ProcEnforce>,
    /// The task control plane (`[task.*]` declared), when one is serving. Its two listeners are host
    /// threads — one reachable from the cage to invoke a task, one host-only carrying the invocation
    /// log — so it must outlive the cage; its presence forces the supervised path (a live parent, and
    /// an exec-replaced launch would leave nobody serving). Dropping it removes both sockets.
    pub(crate) task: Option<super::task_control::TaskPlane>,
}

impl LaunchGuard {
    /// The egress decisions this launch logged, or empty when there is no filtering proxy (a
    /// `shared`/`none` posture, or a forward-only guard). Snapshotted after the run for
    /// `--net-learn`.
    fn observed_events(&self) -> Vec<super::control::LogEvent> {
        self.egress
            .as_ref()
            .map(|e| e.observed_events())
            .unwrap_or_default()
    }
}

impl Drop for LaunchGuard {
    fn drop(&mut self) {
        // The inner guards' Drops unlink the proxy/forwarder artifacts and close the listeners.
        // Taking them here runs those Drops explicitly (and reads the fields, so the RAII holds
        // are not flagged as unused — their whole purpose is to stay alive until this drop).
        // First: stop announcing and say what was dropped. Before the lenses below are torn down,
        // so a refusal decided in the last moments still finds a live delivery thread.
        if let Some(notify) = self.notify_sink.take() {
            notify.notifier.finish();
        }
        if let Some(egress) = self.egress.take() {
            drop(egress);
        }
        if let Some(forward) = self.forward.take() {
            drop(forward);
        }
        if let Some(ssh_agent) = self.ssh_agent.take() {
            drop(ssh_agent);
        }
        // Beside the agent, and for the same reason: each unlinks its socket, and closing the
        // listener ends the detached accept loop. Taken as a whole so a launch running several
        // brokers tears them all down.
        for broker in std::mem::take(&mut self.brokers) {
            drop(broker);
        }
        // Then the record they shared, which outlives every one of them: a reader following it
        // sees the last decision of the last broker before the socket goes.
        if let Some(feed) = self.broker_feed.take() {
            drop(feed);
        }
        // The signer record, after the proxy that pushed into it: `egress` above is gone by now, so
        // nothing can still be signing when the socket goes.
        if let Some(feed) = self.signer_feed.take() {
            drop(feed);
        }
        // Before the portal directory: the relay must disconnect from the private bus before its
        // socket is removed.
        if let Some(notify) = self.notify.take() {
            drop(notify);
        }
        if let Some(theme) = self.theme.take() {
            drop(theme);
        }
        if let Some(portal) = self.portal.take() {
            drop(portal);
        }
        if let Some(proc_enforce) = self.proc_enforce.take() {
            drop(proc_enforce);
        }
        // Last: the task plane's Drop unlinks both sockets, and an invocation may still have been
        // running when the cage ended.
        if let Some(task) = self.task.take() {
            drop(task);
        }
    }
}

/// Which zone name this cage was asked for: whatever `TZ` will finally read, and the `timezone`
/// field when nothing set `TZ`.
///
/// The variable comes first *because* it wins. The assembler sets a structural `TZ` from the zone
/// and every overlay layer upserts over it, so a `[env] TZ` (or a one-shot `--env TZ=`) decides what
/// the cage's clock reads whether or not its author thought of it as choosing a zone. Deriving the
/// `/etc/localtime` link from the same value is what keeps the two halves from disagreeing —
/// otherwise the clock moves and the link stays, and an FHS resolver answers the old zone with no
/// error anywhere. `env` is layered lowest-first, so the winning entry is the last one.
///
/// This grants nothing: `timezone` is a free field, so a layer that can write `[env] TZ` could
/// already have written the zone directly.
fn declared_zone<'a>(env: &'a [(String, String)], field: Option<&'a str>) -> Option<&'a str> {
    env.iter()
        .rev()
        .find(|(k, _)| k == "TZ")
        .map(|(_, v)| v.as_str())
        .or(field)
}

/// The IANA zone this cage runs in: the one a config named, when the provisioned database carries
/// it, and [`binds::DEFAULT_ZONE`] otherwise.
///
/// The existence check is here, not in the config layer, for the reason the config layer says: only
/// the launcher has a database to hold a name against. A name it does not carry is a **warning, not
/// a refusal** — a cage that will not start because a zone was misspelled trades a wrong clock for
/// no session at all, and the fallback is a zone that resolves.
///
/// The shape check is [`crate::config::is_zone_name`], the same rule the config validator applies,
/// called again rather than assumed: the name is about to be joined onto the database path and
/// written as a link target, and this is the join site.
fn cage_timezone(declared: Option<&str>, zoneinfo_src: &Path) -> String {
    let fallback = || binds::DEFAULT_ZONE.to_string();
    let Some(zone) = declared else {
        return fallback();
    };
    if !crate::config::is_zone_name(zone) {
        return fallback();
    }
    if zoneinfo_src.join(zone).is_file() {
        return zone.to_string();
    }
    crate::diag::warn(&format!(
        "the zone database carries no `{zone}` — the cage's clock reads {} instead",
        binds::DEFAULT_ZONE
    ));
    fallback()
}

/// Build the spec for `cmd`, reporting a clean error as an `ExitCode`. The
/// configuration resolved in [`prepare`] drives this: a trust-gated `.sbx.toml` adds
/// environment and host binds — read-only, or read-write with `mode = "rw"` (its security
/// fields honored only once trusted)
/// and provisions its declared tools onto `PATH`. Whatever the gate dropped or
/// withheld is surfaced as a warning; a declared tool that fails to realise is fatal,
/// since it is a stated requirement.
fn build(
    prep: &Prepared,
    runtime: binds::Runtime,
    cmd: Vec<OsString>,
) -> Result<(SandboxSpec, Option<LaunchGuard>), ExitCode> {
    for warning in &prep.cfg.warnings {
        crate::diag::warn(warning);
    }

    // Reclaim the per-launch runtime files of launches that are gone, before standing up our own.
    // Their RAII guards unlink on a clean exit, but a cage normally ends on a signal (Ctrl-C,
    // `sbx session stop`, a detached session killed later) and a `Drop` does not run then — so each
    // cage tidies up after its predecessors. Silent and best-effort: routine housekeeping, and a
    // live launch's files are never touched (its pid still reads as live). The same self-healing
    // doctrine the session registry applies to its records.
    //
    // This sits in `build` — the one function that actually stands up a cage — rather than in
    // `prepare`, which `sbx gc` also calls: a gc *dry run* must touch nothing, and sweeping from
    // there would have deleted these files while reporting them as merely reclaimable.
    super::gc::sweep_runtime_dirs(prep.layout.data_dir(), true);
    super::gc::fold_egress_counters(prep.layout.data_dir(), true);

    // Provision the project's declared tools into sbx's store, against the project's
    // effective nixpkgs reference; their bin dirs are prepended to PATH below. A
    // withheld (untrusted) tool only warns; an admitted tool that fails to realise is
    // fatal.
    let mut packages = match super::packages::provision(
        &prep.nix,
        &prep.layout,
        &prep.cwd,
        &prep.nixpkgs,
        &prep.cfg.packages,
    ) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("sbx: {e}");
            return Err(ExitCode::FAILURE);
        }
    };
    for warning in &packages.warnings {
        crate::diag::warn(warning);
    }

    // Provision a trusted project's `nix:` mise tools — the exact-pinned dev toolchain.
    // Their bin dirs go ahead of the native `[packages]` ones, so a project's pinned
    // tool wins over the coarser package layer on a name clash.
    let tools = mise_tools(prep)?;
    for warning in &tools.warnings {
        crate::diag::warn(warning);
    }
    let mut bin_paths = tools.bins;
    bin_paths.extend(packages.bins);

    // The prebuilt backends — `deb:`, `appimage:`, `tarball:` — are provisioned host-side (like
    // `nix:` and a remote `flake:`, not in-cage like an inline `[flakes.<name>]`): sbx resolves
    // each declared locator to a hash (pinned in the
    // per-project lock), builds the generated unpack+autoPatchelf derivation into sbx's store,
    // prepends its bin to PATH, and seeds its closure (its root joins `packages.roots`). All three
    // unpack at *build* time — an AppImage's squashfs is never self-mounted at runtime, which the
    // seccomp cage forbids anyway. A declared package is a requirement: a provisioning failure aborts
    // the launch naming it, never runs without it.
    let ctx = prebuilt_ctx(prep);
    for kind in super::prebuilt::DIRECT_ORDER {
        for (name, url) in kind.packages(&prep.cfg.packages) {
            let libs = super::prebuilt::libs_of(&prep.cfg.packages, &name);
            match super::prebuilt::provision(kind, &ctx, &name, &url, &libs) {
                Ok((bin, root)) => {
                    bin_paths.push(bin);
                    packages.roots.push(root);
                }
                Err(e) => {
                    crate::diag::error(&format!(
                        "sbx: cannot provision {} package `{name}` ({url}): {e}",
                        kind.name()
                    ));
                    return Err(ExitCode::FAILURE);
                }
            }
        }
    }

    // The `<backend>:resolve` packages are the auto-upgrade form: sbx runs the profile's resolve
    // command in a hermetic sandbox to discover the newest download URL, then resolves+builds it
    // exactly like the direct form (same per-project lock and gcroot). A warm launch reuses the pin
    // offline and does NOT run the command. The command runs with sbx's base tools plus the app's own
    // `nix:` bins and every direct package's bin on PATH (so a command that needs e.g. `jq` declares
    // it), and sbx's own store + CA bundle bound. The cage is built once, here: a resolver never sees
    // another resolver's bin, only the direct layer's.
    let resolve_cage = {
        let mut bins = prep.userland.bin_paths.clone();
        bins.extend(bin_paths.iter().cloned());
        super::resolve::ResolveCage {
            bwrap: prep.bwrap.as_path(),
            store_src: crate::store::physical_path(&prep.layout, std::path::Path::new("/nix")),
            shell_bin: prep.userland.shell_bin.as_path(),
            ca_bundle: prep.userland.ca_bundle_src.as_path(),
            bins,
        }
    };
    for kind in super::prebuilt::RESOLVE_ORDER {
        for (name, command) in kind.resolve_packages(&prep.cfg.packages) {
            let libs = super::prebuilt::libs_of(&prep.cfg.packages, &name);
            match super::prebuilt::provision_resolve(
                kind,
                &ctx,
                &name,
                &command,
                &resolve_cage,
                &libs,
            ) {
                Ok((bin, root)) => {
                    bin_paths.push(bin);
                    packages.roots.push(root);
                }
                Err(e) => {
                    crate::diag::error(&format!(
                        "sbx: cannot provision {} resolver package `{name}`: {e}",
                        kind.name()
                    ));
                    return Err(ExitCode::FAILURE);
                }
            }
        }
    }

    // A remote `flake:` package is built host-side into the shared store and seeded per project (see
    // `packages::provision`), so it lands once and is reused everywhere like a `nix:` tool — its `bin/`
    // is already on PATH via the provisioned package bins. Only inline `[flakes.<name>]` flakes still
    // build in-cage here: an inline flake is local content the user staged, and building local content
    // host-side is exactly what `is_valid_flake_ref` refuses for a remote ref, so the inline case stays
    // contained in the cage. Their out-link `bin` directories join PATH now, ahead of the base like
    // every other declared tool, and need not exist yet: the in-cage `nix build` creates each one
    // before the command runs, exactly as the mise shims dir is on PATH before mise populates it.
    // Each quad carries the build ref, the content-hash-keyed build *target*
    // out-link, the stable *good* out-link PATH resolves through (kept at the last good build on a
    // failure), and the flake name.
    let mut flake_pairs: Vec<(String, PathBuf, PathBuf, String)> = Vec::new();
    let mut inline_flake_names: Vec<String> = Vec::new();

    // Inline `[flakes.<name>]` flakes: stage each `flake.nix` to a content-keyed directory on disk,
    // bind it read-only into the cage at `/opt/sbx/flakes/<name>`, and build `path:<dir>#<attr>`
    // through the *same* in-cage wrap as a `flake:` package (appended to `flake_pairs`). The out-link
    // is keyed by the source's content hash, so editing the flake in the config rebuilds at the next
    // launch — a fresh hash the warm short-circuit misses — while an unchanged flake reuses the warm
    // build. Trusted-only, like `flake_packages`. Best-effort: a staging failure warns and skips that
    // one flake rather than failing the launch.
    let mut inline_flake_binds: Vec<binds::ExtraBind> = Vec::new();
    for (name, content, attr) in super::packages::flake_inline_packages(&prep.cfg.packages) {
        let (dir, hash) = match super::flake_inline::stage(prep.layout.data_dir(), &content) {
            Ok(v) => v,
            Err(e) => {
                crate::diag::warn(&format!(
                    "inline flake `{name}` could not be staged ({e}) — skipping it"
                ));
                continue;
            }
        };
        let incage = binds::flake_inline_incage(&name);
        let build_ref = format!("path:{}#{attr}", incage.display());
        // The content-hash-keyed target rebuilds when the inline flake is edited; the name-only good
        // out-link is the stable PATH entry the wrap keeps at the last good build on a failure.
        let target = binds::flake_out_link_hash(&name, &hash);
        let good = binds::flake_out_link(&name);
        inline_flake_binds.push(binds::ExtraBind {
            src: dir,
            dest: incage,
            writable: false,
        });
        bin_paths.push(good.join("bin"));
        inline_flake_names.push(name.clone());
        flake_pairs.push((build_ref, target, good, name));
    }

    // Under `gui = "wayland"`, provision the GUI font set host-side so the cage renders text
    // rather than boxes. Provisioned here — before the seed — so its store roots join the
    // project store and the cage reads the fonts through `/nix`. Best-effort, like the display
    // socket below: a font fetch that fails (no network on a first launch) warns and the app
    // runs without fonts rather than failing the launch.
    let font_layer = optional_layer(prep, prep.cfg.gui.renders(), super::fonts::provision, |e| {
        format!(
            "this `gui` posture renders but the font set could not be provisioned \
                 ({e}) — text may not render"
        )
    });
    let font_roots: &[PathBuf] = font_layer.as_ref().map_or(&[], |l| l.roots.as_slice());

    // Under `gui = "wayland"`, provision the GUI data set (GSettings schemas + GTK themes)
    // host-side. A GTK dialog (the file chooser Electron falls back to without a desktop portal)
    // aborts FATAL without the schemas (`No GSettings schemas are installed`); the themes let the
    // in-cage portal's file dialog render in the host light/dark theme. Provisioned here — before
    // the seed — so its store root joins the project store. Best-effort like the fonts: a fetch
    // that fails warns and the app runs (a GTK dialog will still crash, but the rest is unaffected).
    let guidata_layer = optional_layer(
        prep,
        matches!(prep.cfg.gui, crate::config::GuiPolicy::Wayland),
        super::guidata::provision,
        |e| {
            format!(
                "`gui = \"wayland\"` but the GUI data (GSettings schemas + themes) could not \
                 be provisioned ({e}) — a GTK dialog (file chooser) may crash"
            )
        },
    );

    // In-cage desktop portal: under `gui = "wayland"` AND `dbus = true`, provision the portal
    // stack (dbus + xdg-desktop-portal + the GTK backend) host-side — before the seed, so its roots
    // join the project store — and read the host theme, best-effort, to seed the cage's light/dark
    // scheme at launch. The wrap that starts the private bus is applied after every other command
    // wrap (below), so the bus is up before the app. Best-effort: a provisioning failure warns and
    // the app runs without an in-cage portal (its file chooser then falls back to its own dialog).
    // Requires the Wayland display (the GTK backend renders through the compositor), so it is gated
    // on both. Unlike the filtered host bus, the private bus touches no host socket, so the network
    // posture does not gate it.
    // The portal's host-side runtime directory, bound into the cage so the in-cage dbus-daemon's
    // socket is reachable from the host (the notifications relay attaches there). Created alongside
    // the provision so `portal` being `Some` implies the directory exists; a create failure drops the
    // portal (fail-closed: no bus rather than a broken one). Held until the launch ends by the guard.
    let mut portal_host: Option<super::portal::HostDir> = None;
    let mut notify_relay: Option<super::notify_relay::NotifyRelay> = None;
    let mut theme_relay: Option<super::theme_relay::ThemeRelay> = None;
    let portal = if prep.cfg.dbus && matches!(prep.cfg.gui, crate::config::GuiPolicy::Wayland) {
        match super::portal::provision(&prep.nix, &prep.layout, &prep.nixpkgs) {
            Ok(p) => match super::portal::HostDir::create(&prep.layout) {
                Ok(hd) => {
                    // Start the desktop-notifications relay against the private-bus socket the portal
                    // exposes on the host. It waits for the in-cage dbus-daemon to create the socket,
                    // then owns `org.freedesktop.Notifications` on the private bus and forwards to the
                    // host daemon (re-emitting its signals back). Best-effort: no host bus or a socket
                    // that never appears just leaves the app without notifications — the in-cage picker
                    // and at-launch theme are unaffected.
                    notify_relay = Some(super::notify_relay::NotifyRelay::start(hd.socket()));
                    // Start the live-theme relay: it mirrors later host light/dark switches into the
                    // in-cage GSettings keyfile (through the home bind), so the in-cage portal
                    // re-emits SettingChanged and the app follows the change live. The home is
                    // derived exactly as `build_spec` binds it, so both target the same file — and it
                    // is handed over unjoined because the relay walks the rest of the way itself,
                    // refusing a symlink at every cage-writable component.
                    // Best-effort: a home path that cannot be resolved just leaves the at-launch theme.
                    if let Ok(home) = binds::home_src(prep.layout.data_dir(), &prep.cwd, runtime) {
                        theme_relay = Some(super::theme_relay::ThemeRelay::start(home));
                    }
                    portal_host = Some(hd);
                    Some(p)
                }
                Err(e) => {
                    crate::diag::warn(&format!(
                        "`dbus = true` but the portal runtime directory could not be created \
                         ({e}) — running without an in-cage file chooser"
                    ));
                    None
                }
            },
            Err(e) => {
                crate::diag::warn(&format!(
                    "`dbus = true` but the in-cage portal could not be provisioned ({e}) — \
                     running without an in-cage file chooser"
                ));
                None
            }
        }
    } else if prep.cfg.dbus {
        // `dbus = true` without a display: the in-cage portal's GTK backend renders on the
        // compositor, so it cannot stand up. Warn rather than silently doing nothing.
        crate::diag::warn(
            "`dbus = true` needs `gui = \"wayland\"` (the in-cage portal renders on the \
             compositor) — running without a desktop portal",
        );
        None
    } else {
        None
    };
    // The host light/dark preference, read host-side (best-effort) to seed the cage theme. Read
    // over the session bus directly rather than by running a provisioned `dbus-send`: a binary in
    // sbx's relocated store names an interpreter under a `/nix` the host does not have, so it
    // could not be executed here at all.
    let portal_scheme = portal
        .as_ref()
        .and_then(|_| super::theme_relay::read_host_color_scheme());

    // CA trust for a Chromium/Electron engine under a filtering posture: Chromium ignores the
    // CA-file env vars sbx sets and reads its own NSS db, so under the egress MITM it rejects
    // sbx's per-session CA and every page fails to load. When the cage BOTH renders (`gui =
    // "wayland"` for a window, `"offscreen"` for a headless browser) AND filters egress,
    // provision `certutil` (part of the rendering hole, like the fonts) so the command wrap below
    // can import the bound CA into the cage's NSS db. Gated to exactly those cages — a plain CLI
    // tool needs nothing (its env-reading TLS already trusts the CA), and `shared`/`none` has no
    // MITM CA. Best-effort: a provisioning failure warns and the app runs (and fails its own
    // HTTPS) rather than blocking the launch.
    let ca_trust = optional_layer(
        prep,
        prep.cfg.gui.renders()
            && matches!(prep.cfg.network, crate::config::NetworkPolicy::Allowlist(_)),
        super::catrust::provision,
        |e| {
            format!(
                "this `gui` posture renders under a network allowlist but certutil could not \
                 be provisioned ({e}) — a Chromium/Electron engine will not trust the egress \
                 proxy"
            )
        },
    );

    // Under `gpu = true`, provision mesa's DRI drivers host-side so the cage can render with
    // hardware acceleration. Provisioned here — before the seed — so mesa's store root joins the
    // project store and the cage reads the drivers through `/nix`; the env pointing libgbm/libEGL
    // at them is applied in the launch block below. Best-effort, like the fonts: a fetch that fails
    // warns and the app runs (falling back to software rendering) rather than failing the launch.
    let gpu_layer = optional_layer(prep, prep.cfg.gpu, super::gpu::provision, |e| {
        format!(
            "`gpu = true` but the mesa drivers could not be provisioned \
                 ({e}) — rendering may fall back to software"
        )
    });

    // Under `audio = true`, provision the PulseAudio client library (`libpulse.so.0`) host-side so
    // the cage can open capture/playback streams. Provisioned here — before the seed — so its store
    // root joins the project store and the cage reads the library through `/nix`; the env pointing
    // the app's loader at it (and the socket bind) is applied in the launch block below. Best-effort,
    // like the fonts and mesa: a fetch that fails warns and the app runs (without audio).
    let audio_layer = optional_layer(prep, prep.cfg.audio, super::audio::provision, |e| {
        format!(
            "`audio = true` but the audio userspace could not be provisioned \
                 ({e}) — the app runs without audio"
        )
    });

    // The GUI-hole store roots to seed: the fonts plus (when present) certutil, mesa, and
    // libpulseaudio, so the cage reads them all through `/nix`.
    let mut gui_roots: Vec<PathBuf> = font_roots.to_vec();
    if let Some(ct) = &ca_trust {
        gui_roots.push(ct.root.clone());
    }
    if let Some(layer) = &gpu_layer {
        gui_roots.push(layer.root.clone());
    }
    if let Some(layer) = &audio_layer {
        gui_roots.extend(layer.roots.iter().cloned());
    }
    if let Some(layer) = &guidata_layer {
        gui_roots.push(layer.root.clone());
    }
    if let Some(p) = &portal {
        gui_roots.extend(p.roots.iter().cloned());
    }

    // Seed the project's own writable store with the closure of everything the cage
    // resolves through `/nix` — the base userland, every provisioned tool, and (under the
    // GUI hole) the fonts and certutil — then back `/nix` with it read-write. The cage reads and
    // writes only its own store, so an agent that installs a toolchain writes into the project's
    // copy and the shared store is never in the cage. Which store backs `/nix` is sbx's
    // decision, not a configurable field, so an untrusted project cannot keep the shared
    // store mounted or widen its access.
    let project_store = match seed_project_store(prep, &packages.roots, &tools.roots, &gui_roots) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("sbx: cannot prepare the project's store: {e}");
            return Err(ExitCode::FAILURE);
        }
    };
    let nix_mount = {
        let src = project_store.store_dir().join("nix");
        // Probed here (host-side, real path) so assembly stays pure: a btrfs-backed
        // store makes the in-cage nix leave the inherited `btrfs.compression`
        // attribute in place, else its canonicalisation aborts a build.
        let on_btrfs = crate::storage::on_btrfs(&src);
        binds::NixMount {
            src,
            writable: true,
            on_btrfs,
        }
    };

    // Mise-backed tools are equipped in-cage at launch rather than host-provisioned, in two
    // distinct lanes. The app's `[packages] mise:` tools are durable, trusted-only declarations,
    // equipped **globally** (`mise use -g`, written to the home's global mise config). The
    // project's local `.mise.toml` non-`nix:` tools (an `aqua:`/`npm:`/registry backend) are the
    // **open** self-equip toolchain, equipped **locally** (`mise install`) with the in-cage mise
    // told to trust the project config so they resolve through the shims on PATH. Both fetch, so
    // both wrap the command *before* the egress wrap below — under an allowlist the forwarder is
    // up before either install — and both are skipped under `network = "none"`.
    // The wraps each block below contributes. They are nested by `WrapLayer`, not by the order the
    // blocks run in, so a block may register its wrap wherever the value it needs becomes available.
    let mut wraps: Vec<(WrapLayer, CommandWrap)> = Vec::new();

    // Exec enforcement (`[proc] mode = enforce|ask`): stand up the seccomp user-notification
    // supervisor and wrap the command with the in-cage shim, **innermost** — so only the agent
    // command and its children are filtered, not the provisioning/egress plumbing wrapped around it
    // below. Its guard forces the supervised path (a live parent for the supervisor thread).
    // Fail-closed: if the supervisor cannot be stood up, the launch is refused rather than running the
    // command unenforced.
    // The refusal notifier (`[notify]`), stood up before the first lens that can refuse anything and
    // held for the whole launch. The credential set it redacts against is filled in below, once the
    // egress proxy has resolved this launch's secrets — the exec supervisor needs the notifier before
    // that resolution happens, and nothing can be refused in between.
    let notify_needles: super::notify_sink::Needles = Arc::new(RwLock::new(Vec::new()));
    // Which sandbox every announcement names. The pid is this launcher's — the one `sbx session ls`
    // lists and `sbx attach`/`sbx stop` take — so a notification points at something to act on.
    let notify_origin = crate::notify::Origin {
        app: match runtime {
            binds::Runtime::GlobalApp(name) | binds::Runtime::ProjectApp(name) => name.to_string(),
            binds::Runtime::ProjectDefault => String::new(),
        },
        project: prep
            .cwd
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default(),
        pid: std::process::id(),
    };
    let notify_wiring = Arc::new(super::notify_sink::NotifyWiring {
        notifier: Arc::new(super::notify_sink::Notifier::start(
            prep.cfg.notify,
            Arc::clone(&notify_needles),
            &notify_origin,
        )),
        needles: notify_needles,
    });

    // The trust lens: a security field this project declared and sbx dropped, because the config
    // carrying it is not trusted. Announced here, once the notifier exists, because the symptom
    // otherwise arrives much later and in disguise — a cage that is not shaped the way its config
    // plainly reads, with the explanation buried in the launch's warning list.
    for warning in prep
        .cfg
        .warnings
        .iter()
        .filter(|w| crate::config::is_trust_drop(w))
    {
        notify_wiring.notifier.block(crate::notify::Block {
            event: crate::notify::NotifyEvent::Trust,
            subject: warning.clone(),
            reason: "not-trusted".to_string(),
            detail: String::new(),
            fix: "sbx trust".to_string(),
        });
    }

    let mut proc_enforce_guard = None;
    let mut proc_binds: Vec<binds::ExtraBind> = Vec::new();
    // The content lens rides the same supervisor as exec enforcement — it is the same notification
    // listener, read for a different syscall. So `[fs] scan` brings the supervisor up on its own:
    // making it depend on `[proc]` would tie one guarantee to an unrelated one.
    let content_lens = if prep.cfg.fs.scan.is_empty() {
        None
    } else {
        let ceiling = prep
            .cfg
            .fs
            .scan_max_kb
            .and_then(|kb| usize::try_from(kb.saturating_mul(1024)).ok())
            .unwrap_or(crate::open_policy::MAX_SCAN_DEFAULT);
        match crate::open_policy::OpenPolicy::compile(&prep.cfg.fs.scan, ceiling) {
            Ok(policy) => policy.map(|policy| {
                // Canonical, because the bound is applied to paths the kernel has resolved.
                let root = std::fs::canonicalize(&prep.cwd).unwrap_or_else(|_| prep.cwd.clone());
                (policy, root)
            }),
            Err(e) => {
                // Refused rather than dropped: a launch that ran with a scan it could not build
                // would report a protection it does not have.
                eprintln!("sbx: cannot build the `[fs] scan` content scanner: {e}");
                return Err(ExitCode::FAILURE);
            }
        }
    };
    if prep.cfg.proc.enforcing() || content_lens.is_some() {
        // The shim is sbx's own embedded binary, laid down under the data directory. Refusing when
        // it cannot be placed is the point: the alternative would be binding some other executable
        // into the cage, which is the exposure the dedicated shim exists to remove.
        let shim_bin = crate::store::ensure_proc_shim(&prep.layout).map_err(|e| {
            eprintln!("sbx: cannot place the exec-enforcement shim: {e}");
            ExitCode::FAILURE
        })?;
        // With `[proc]` off, the exec side is a denylist with nothing on it: every `execve` is
        // notified and allowed, which is what the shim's filter produces anyway. The lens is what
        // this launch asked for.
        let exec_policy = if prep.cfg.proc.enforcing() {
            prep.cfg.proc.clone()
        } else {
            crate::proc_policy::ProcPolicy::new(crate::proc_policy::ProcMode::Enforce, &[], &[])
        };
        let (guard, wiring) = super::proc_enforce::start(
            prep.layout.data_dir(),
            &shim_bin,
            exec_policy,
            content_lens,
            Arc::clone(&notify_wiring.notifier),
        )
        .map_err(|e| {
            eprintln!("sbx: cannot start exec enforcement: {e}");
            ExitCode::FAILURE
        })?;
        // The flag rides in the closure so the filter the cage installs matches the lens the
        // supervisor was started with — the two are decided once, together.
        let open_lens = wiring.open_lens;
        wraps.push((
            WrapLayer::ProcEnforce,
            Box::new(move |cmd| super::proc_enforce::wrap_command(cmd, open_lens)),
        ));
        proc_binds = wiring.binds;
        proc_enforce_guard = Some(guard);
    }

    let mut autoequip_env: Vec<(String, String)> = Vec::new();
    let global_mise = super::packages::mise_packages(&prep.cfg.packages);
    let auto_equip = auto_equip_tokens(&prep.cfg);
    // A global app's Lane-1 `mise use -g` must install an app `[packages] mise:` tool into the
    // app-global home pool (installed once, shared across projects, and where `sbx app show`/`list`/
    // `gc` read), not the ambient per-project primary. Pin the equip step there for a global app;
    // for `sbx run`/a per-project app the ambient primary is already the app-global home, so no pin.
    let app_global_mise_dir =
        matches!(runtime, binds::Runtime::GlobalApp(_)).then(binds::mise_app_global_data_dir);
    if !global_mise.is_empty() || !auto_equip.is_empty() {
        if matches!(prep.cfg.network, crate::config::NetworkPolicy::Isolated) {
            // `network = "none"`: a mise tool cannot be fetched, so skip the equip (it would only
            // fail). An already-equipped tool still resolves through its persisted shim, so this
            // is a warning, not a hard error.
            let declared: Vec<&str> = global_mise
                .iter()
                .chain(auto_equip.iter())
                .map(String::as_str)
                .collect();
            crate::diag::warn(&format!(
                "mise tools [{}] are declared but `network = \"none\"` — they \
                 cannot be fetched and will be absent unless already equipped",
                declared.join(", ")
            ));
        } else {
            if !auto_equip.is_empty() {
                if !prep.quiet_equip {
                    eprintln!(
                        "sbx: equipping non-nix tools in-cage via mise: {} (each backend's host \
                         must be in [network].allow under an allowlist)",
                        auto_equip.join(", ")
                    );
                }
                wraps.push((
                    WrapLayer::MiseEquip,
                    Box::new(move |cmd| {
                        wrap_mise_equip(
                            &prep.userland.mise_bin,
                            &prep.userland.shell_bin,
                            // `install`, and deliberately no `--pin` here: this lane equips the
                            // tools the PROJECT's own `.mise.toml` asks for, and that file belongs
                            // to the user. `install` reads it and writes nothing; pinning would
                            // rewrite a version the project chose to leave floating, in a file sbx
                            // does not own. The pin belongs to lane 1 below, whose config file is
                            // the cage's own and is sbx's to write.
                            "install",
                            &auto_equip,
                            // Lane 2 (project `.mise.toml` tools) runs under the ambient primary —
                            // the per-project pool for a global app, which is where these belong.
                            None,
                            cmd,
                        )
                    }),
                ));
                // Tell the in-cage mise to trust the project config so the installed tools
                // resolve. This applies for the whole launch, so an agent's own `sbx mise` in a
                // project that declares non-`nix:` tools also trusts the project config — a
                // conscious, slightly wider reach than autoequip alone, and consistent with the
                // open self-equip posture. A distinct key, so its position in the env layering is
                // immaterial; a trusted config could still override it (self-harm only).
                autoequip_env.push((
                    "MISE_TRUSTED_CONFIG_PATHS".to_string(),
                    prep.cwd.to_string_lossy().into_owned(),
                ));
            }
            if !global_mise.is_empty() {
                if !prep.quiet_equip {
                    eprintln!("{}", equip_announcement(&global_mise));
                }
                wraps.push((
                    WrapLayer::MiseEquip,
                    Box::new(move |cmd| {
                        wrap_mise_equip(
                            &prep.userland.mise_bin,
                            &prep.userland.shell_bin,
                            // `--pin` writes the RESOLVED version into the cage's mise config
                            // instead of the floating request. Without it the config keeps saying
                            // `latest`, and the tool on the cage PATH is a shim — a symlink back to
                            // mise — which re-resolves that request on every exec: the day upstream
                            // publishes a version the pool does not hold, the shim refuses to run
                            // and the app stops launching, with nothing about the cage having
                            // changed. Pinning is what actually freezes a launch at the installed
                            // version. Its other half is `--bump` on the roll (see
                            // [`mise_upgrade_cmd`]): an exact pin is a range `mise upgrade` would
                            // consider already satisfied, so without it the roll would go quiet.
                            // Neither half works alone.
                            MISE_EQUIP_VERB,
                            &global_mise,
                            // Pin the install to the app-global home pool for a global app (see
                            // above); None for other runtimes, where the ambient primary is already
                            // app-global.
                            app_global_mise_dir.as_deref(),
                            cmd,
                        )
                    }),
                ));
            }
        }
    }

    // Inline `[flakes.<name>]` flakes are built in-cage with `nix build --out-link` — the local
    // content the user staged is contained by the cage, never built host-side (which
    // `is_valid_flake_ref` refuses for a remote ref; a remote `flake:` package is built host-side by
    // `packages::provision`). The build fetches its inputs, so (like the mise equip) it wraps the
    // command *before* the egress wrap and is skipped under `network = "none"`. The wrap
    // short-circuits when the out-link is already realised in the project's store, so a warm launch is
    // a no-op and an already-built flake runs offline.
    if !flake_pairs.is_empty() {
        if matches!(prep.cfg.network, crate::config::NetworkPolicy::Isolated) {
            crate::diag::warn(&format!(
                "inline flakes [{}] are declared but `network = \"none\"` — they \
                 cannot be built and will be absent unless already present",
                inline_flake_names.join(", ")
            ));
        } else {
            eprintln!(
                "sbx: building inline flakes in-cage via nix build: {} (each flake's fetch \
                 host must be in [network].allow under an allowlist)",
                inline_flake_names.join(", ")
            );
            wraps.push((
                WrapLayer::FlakeEquip,
                Box::new(|cmd| {
                    wrap_flake_equip(
                        &prep.userland.nix_bin,
                        &prep.userland.shell_bin,
                        &binds::flake_roots_dir(),
                        &flake_pairs,
                        cmd,
                    )
                }),
            ));
        }
    }

    // A network allowlist runs the Model-B egress path: stand up the host filtering
    // proxy on a per-launch socket, wire the cage to reach it (the bound socket, the
    // CA it trusts, the proxy environment) and wrap the command so the cage starts the
    // forwarder before running it. The cage's netns is empty (`net_policy` maps the
    // allowlist to isolation), so this bound socket is the only egress. The guard keeps
    // the proxy's artifacts until the launch ends; the proxy thread outlives the cage
    // because the launcher supervises rather than exec-replacing (see `run`). Other
    // postures never touch any of this.
    let mut egress_guard = None;
    let mut egress_binds: Vec<binds::ExtraBind> = Vec::new();
    let mut egress_env: Vec<(String, String)> = Vec::new();

    // Forwarder loopback forward ports: a declared `forward` opens a host loopback port and
    // bridges it into the cage, so a host process (an OAuth `localhost:<port>` callback, or a
    // dev server) can reach a service the agent started inside the empty-netns cage. Applied
    // *before* the egress wrap below, so under an allowlist both forwarders are up before the
    // command runs (the egress wrap is the outermost, backgrounds its socat, execs the inner
    // which backgrounds the forward socats, execs the real command). Skipped under
    // `network = "shared"`: the cage shares the host netns, so a cage loopback service is already
    // on host loopback and the forwarder is a redundant no-op (noted, not wired). A port already
    // in use fails the launch closed inside `forward::start`.
    let mut forward_guard = None;
    let mut forward_binds: Vec<binds::ExtraBind> = Vec::new();
    if !prep.cfg.forward.is_empty() {
        if matches!(prep.cfg.network, crate::config::NetworkPolicy::Shared) {
            crate::diag::warn(&format!(
                "forward ports {} declared but `network = \"shared\"` already exposes the \
                 cage loopback to the host — no forwarder needed",
                prep.cfg
                    .forward
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join(",")
            ));
        } else {
            let (guard, wiring) =
                forward::start(&prep.layout, prep.cfg.forward.clone()).map_err(|e| {
                    eprintln!("sbx: {e}");
                    ExitCode::FAILURE
                })?;
            let forwards = wiring.forwards;
            wraps.push((
                WrapLayer::Forward,
                Box::new(move |cmd| {
                    forward::wrap_command(
                        &prep.userland.socat_bin,
                        &prep.userland.shell_bin,
                        &forwards,
                        cmd,
                    )
                }),
            ));
            forward_binds = wiring.binds;
            forward_guard = Some(guard);
        }
    }
    // Broker plugins: the same shape as the ssh-agent broker below, for a protocol sbx does not
    // implement itself. Each `[broker.<name>]` pairs an installed plugin with the host resource
    // the global config bound it to; sbx serves the socket, holds the host connection, and the
    // plugin only ever answers verdicts about frames.
    //
    // Ahead of the egress proxy, and that order is load-bearing rather than incidental: a resolver
    // plugin may be given a broker (`[sandbox] brokers`), and the proxy resolves this launch's
    // secrets as it starts. A broker stood up afterwards would not exist at the moment the resolver
    // that needs it runs.
    //
    // Every failure here degrades to *no broker* rather than to an unfenced one, and says so: a
    // cage without a broker is a cage that cannot reach that resource, which is the fail-closed
    // direction. Only standing up a broker the config did ask for and could otherwise have is
    // fatal, like the egress proxy's and the agent's.
    let mut broker_guards: Vec<broker::Broker> = Vec::new();
    let mut brokers: Vec<broker::Reachable> = Vec::new();
    // The reader's end of the shared record, held for the launch's lifetime. `None` until a config
    // that declares a broker stands it up, and `None` too when that could not be done.
    let mut broker_feed: Option<broker::BrokerFeed> = None;
    if !prep.cfg.brokers.is_empty() {
        // The perimeter every plugin's trust rests on, established before the first plugin runs —
        // a resolver is run only because it sits under `<data>/plugins`, a tree a project cannot
        // write, and that rests on `<data>` being owner-only. The egress proxy opens with the same
        // call for the same reason; standing brokers up ahead of it moved the first plugin-backed
        // resolution in this process to here.
        if let Err(e) = crate::store::ensure(&prep.layout) {
            eprintln!("sbx: cannot prepare the data directory: {e}");
            return Err(ExitCode::FAILURE);
        }
        let mut plugin_warnings = Vec::new();
        let registry =
            crate::plugins::PluginRegistry::load(&prep.layout.plugins_dir(), &mut plugin_warnings);
        for w in &plugin_warnings {
            crate::diag::warn(w);
        }
        // The session's decision record, stood up once and shared by every broker below — one ring
        // and one socket, whatever the config declares. The guard lives as long as the brokers do,
        // so a reader's `--follow` ends with the launch rather than with whichever broker was torn
        // down first.
        let (ring, feed) = broker::stand_up_feed(&prep.layout);
        broker_feed = Some(feed);
        for binding in &prep.cfg.brokers {
            let name = &binding.name;
            let Some(plugin) = registry.broker(name) else {
                // Told apart, because the remedy differs: an ambiguous name is fixed by removing a
                // plugin, a missing one by installing it.
                match registry.name_conflict(name) {
                    Some(claimants) => crate::diag::warn(&format!(
                        "`[broker.{name}]` names a broker claimed by more than one installed \
                         plugin ({}) — they are all disabled, so the cage gets no broker",
                        crate::plugins::quoted_list(claimants)
                    )),
                    None => crate::diag::warn(&format!(
                        "`[broker.{name}]` names no installed broker plugin — install one with \
                         `sbx plugins install`, or drop the table. The cage gets no broker."
                    )),
                }
                continue;
            };
            // Two checks, and the second is the one that keeps a single answer to "where may this
            // cage go".
            match &binding.socket {
                // A Unix socket has to be there *now*: a broker in front of nothing would accept
                // the cage's connections and fail every frame, which reads as the resource
                // misbehaving rather than as a configuration that does not hold.
                crate::config::BrokerTarget::Unix(path) if !path.exists() => {
                    crate::diag::warn(&format!(
                        "`[broker.{name}] socket` names {}, which does not exist — the cage gets \
                         no broker",
                        path.display()
                    ));
                    continue;
                }
                crate::config::BrokerTarget::Unix(_) => {}
                // A protocol whose clients compute the socket's path has no path to compute when
                // the resource is an endpoint: the two declarations are answering different
                // questions, and standing the broker up anyway would put it where nothing looks.
                crate::config::BrokerTarget::Tcp { .. } if plugin.broker.at_host_path => {
                    crate::diag::warn(&format!(
                        "`[broker.{name}] socket` names a tcp:// endpoint, but the plugin's clients \
                         find the socket at a fixed path (`at_host_path`) — a tcp:// target has \
                         none, so the cage gets no broker"
                    ));
                    continue;
                }
                // A TCP target is a way out of the cage, so it is admitted only where the network
                // allowlist already admits it — decided by the very function the proxy and
                // `sbx test net` decide through, so the three cannot drift apart. Without this
                // there would be two different answers to what the cage may reach, and the one a
                // reader checks would not be the one that decides.
                crate::config::BrokerTarget::Tcp { host, port } => {
                    let admitted = match &prep.cfg.network {
                        crate::config::NetworkPolicy::Allowlist(policy) => matches!(
                            policy.l4_decision(host, *port),
                            crate::allowlist::L4Decision::Splice(_)
                        ),
                        _ => false,
                    };
                    if !admitted {
                        crate::diag::warn(&format!(
                            "`[broker.{name}] socket` names tcp://{host}:{port}, which the \
                             network allowlist does not admit — add `tcp://{host}:{port}` to \
                             `[network] allow`, or the cage gets no broker"
                        ));
                        continue;
                    }
                }
            }
            // The credential is resolved host-side, here, before anything is stood up: a broker
            // that was promised one and cannot get it must not run, or it would put an
            // unauthenticated connection in front of the cage and look like the resource refusing
            // it. The plugin never receives this value — only a marker standing in for it.
            let secret = if binding.secret.is_empty() {
                None
            } else if !plugin.broker.uses_secret {
                // The grant is the manifest's to make: a credential is not handed to a plugin that
                // was not written to place one, whatever the config says.
                crate::diag::warn(&format!(
                    "`[broker.{name}] secret` names a credential, but the plugin's manifest does \
                     not declare `uses_secret` — the broker runs without it"
                ));
                None
            } else {
                // Resolved with **no** broker wired, which is what keeps the graph acyclic: a
                // broker's own credential cannot be read through a broker, least of all through the
                // one being stood up. A resolver that needs one fails here on its own terms, so say
                // which declaration made it impossible rather than leaving the tool's error to
                // stand for it.
                for source in &binding.secret {
                    if let crate::config::SecretSource::Plugin { plugin, .. } = source
                        && !plugin.sandbox.brokers.is_empty()
                    {
                        crate::diag::warn(&format!(
                            "`[broker.{name}] secret` resolves through the `{}` plugin, which needs \
                             the {} broker — a broker's own credential is resolved before any \
                             broker is standing, so that grant is not answered here",
                            plugin.scheme,
                            crate::plugins::quoted_list(&plugin.sandbox.brokers)
                        ));
                    }
                }
                match egress::resolve_chain(&binding.secret, name, &prep.cwd, &prep.bwrap, &[]) {
                    Ok(value) => {
                        // Said once, at the launch that decided it, rather than per connection: a
                        // credential under the redaction floor is placed on the wire but not
                        // watched on the way back, and that is a fact about this config.
                        if value.len() < prep.cfg.redact_min_len {
                            crate::diag::warn(&format!(
                                "the credential for the `{name}` broker is {} bytes, under the \
                                 {}-byte `[redact] min_len` floor — it is placed on the wire, but \
                                 a reply carrying it back is not blocked (a scan that short \
                                 refuses innocent traffic more often than it catches a leak)",
                                value.len(),
                                prep.cfg.redact_min_len
                            ));
                        }
                        Some((value, prep.cfg.redact_min_len))
                    }
                    Err(e) => {
                        eprintln!("sbx: cannot resolve the secret for the `{name}` broker: {e}");
                        return Err(ExitCode::FAILURE);
                    }
                }
            };
            // What this host answers the plugin, from `[plugin.<name>]`. Applied to a copy rather
            // than to the registry's instance, which is shared and read-only here: the config
            // validated the table against this very manifest, and the copy is what runs.
            let mut plugin = plugin.clone();
            plugin.host = binding.host.clone();
            match broker::start(
                &prep.layout,
                binding,
                &plugin,
                &prep.bwrap,
                secret,
                ring.clone(),
            ) {
                Ok((guard, reachable)) => {
                    crate::diag::note(&format!(
                        "broker: `{name}` stands in front of {}{}",
                        binding.socket.describe(),
                        match binding.allow.len() {
                            0 => String::new(),
                            n => format!(" ({n} allow entr{})", if n == 1 { "y" } else { "ies" }),
                        }
                    ));
                    // Two brokers claiming one variable would silently last-wins, leaving a client
                    // pointed at whichever was stood up second and a broker serving nobody. Named
                    // instead, like the secrets layer names a duplicated destination header.
                    for (key, _) in &reachable.env {
                        if brokers
                            .iter()
                            .any(|b: &broker::Reachable| b.env.iter().any(|(k, _)| k == key))
                        {
                            crate::diag::warn(&format!(
                                "broker `{name}` and an earlier broker both set ${key} in the cage \
                                 — the later one wins, so one of them is unreachable"
                            ));
                        }
                    }
                    brokers.push(reachable);
                    broker_guards.push(guard);
                }
                Err(e) => {
                    eprintln!("sbx: cannot start the `{name}` broker: {e}");
                    return Err(ExitCode::FAILURE);
                }
            }
        }
        // Nothing stood up, so nothing has decisions to record. Dropping the feed unlinks its socket
        // and takes this launch back to what it would have been without the block: a launch with no
        // broker, which needs no live parent and can exec-replace. Held any longer, a bound socket
        // with no owner would force the supervised path on a config whose brokers all fell away.
        if brokers.is_empty() {
            broker_feed = None;
        }
    }

    // Where each `tcp://` destination lives inside the cage. Computed before the launch because two
    // things need it: the preamble's listeners, and the `/etc/hosts` entries that make the
    // declaration's own host name resolve to them.
    let mut tcp_plan = egress::TcpPlan::default();
    if let crate::config::NetworkPolicy::Allowlist(policy) = &prep.cfg.network {
        tcp_plan = egress::tcp_destinations(policy);
        for skipped in &tcp_plan.skipped {
            crate::diag::warn(&format!(
                "no in-cage listener for {skipped} — the rule still governs the proxy, but a client \
                 that cannot speak an HTTP CONNECT proxy will have to tunnel itself"
            ));
        }
        // An inspected rule naming a loopback host is permitted by the policy and taken by nothing:
        // the cage exempts those hosts from its proxy, and only a `tcp://` rule earns a listener. A
        // warning, not a note — the rule reads as allowed on every surface that reports a verdict,
        // so an author who is not told concludes the host's loopback is out of reach.
        for rule in egress::unreachable_loopback_rules(policy) {
            crate::diag::warn(&format!(
                "`{rule}` allows a host the cage reaches through no client: {exempt} are exempt \
                 from the cage's proxy (`no_proxy`, so the agent's own in-cage services stay \
                 intra-cage), and only a `tcp://` rule gets an in-cage listener — declare \
                 `tcp://<host>:<port>` to reach the service on YOUR loopback",
                exempt = egress::PROXY_EXEMPT_HOSTS.join(", ")
            ));
        }
        // A privileged port has no listener either, but ssh is wired for it — so this is a note,
        // not a warning: what an author must know is that *ssh* works as written while another
        // client on such a port still has to ask the proxy itself.
        for dest in &tcp_plan.connect_only {
            let ports: Vec<String> = dest.ports.iter().map(u16::to_string).collect();
            crate::diag::note(&format!(
                "tcp://{}:{} is a privileged port, which the cage cannot listen on — ssh reaches it \
                 through the cage's CONNECT proxy (wired in /etc/ssh/ssh_config); another client \
                 has to ask for that CONNECT itself",
                dest.host,
                ports.join(",")
            ));
        }
    }
    // The session's signer record, stood up when a signer is named anywhere this launch will run
    // one: a `[[secret]]` the agent's own proxy resolves, or a `[task.<name>.inject]` a declared
    // operation's proxy will. One ring and one socket for all of them, like the notifier — a proxy
    // that built its own would record where no reader can look.
    //
    // The task half reads the same `prep.cfg.tasks` the engine below is built from, in this one
    // function, off an immutable `prep`. So the set scanned here and the set that can actually
    // invoke a signer are the same set, whatever layer contributed a task — there is no ordering
    // to get wrong, and a late-arriving declaration cannot slip past the feed.
    let signs = prep.cfg.secrets.iter().any(|s| s.signer.is_some())
        || prep
            .cfg
            .tasks
            .iter()
            .any(|t| t.injections.iter().any(|i| i.signer.is_some()));
    let (signer_ring, signer_feed) = match signs {
        true => {
            let (ring, feed) = super::signer_control::stand_up_feed(&prep.layout);
            (Some(ring), feed)
        }
        false => (None, None),
    };

    if let crate::config::NetworkPolicy::Allowlist(policy) = &prep.cfg.network {
        // An `sbx app <name>` launch tags its egress stats with the app, so `sbx net stats --app`
        // can scope to it; a plain `run`/`shell` records under the project with no app tag.
        let app = match &runtime {
            binds::Runtime::GlobalApp(name) | binds::Runtime::ProjectApp(name) => Some(*name),
            binds::Runtime::ProjectDefault => None,
        };
        let (guard, wiring) = egress::start(
            &prep.layout,
            policy.clone(),
            &prep.cfg.secrets,
            &prep.cwd,
            &prep.bwrap,
            app,
            prep.cfg.egress_stats,
            // The base roots to pair the per-session MITM CA with, for a policy that lets a client
            // reach a server this proxy does not stand in for. Which policies those are, and what the
            // pairing costs when it buys nothing, is decided where the file is written.
            Some(prep.userland.ca_bundle_src.as_path()),
            // The session's own proxy: a launch stands up exactly one, so the pid already names it.
            "",
            Some(&notify_wiring),
            prep.cfg.redact_min_len,
            &brokers,
            signer_ring.clone(),
        )
        .map_err(|e| {
            eprintln!("sbx: cannot start the egress filtering proxy: {e}");
            ExitCode::FAILURE
        })?;
        // The wrap owns its copy: `tcp_plan` is read again further down, when the same destinations
        // become the cage's `/etc/hosts` entries.
        let destinations = tcp_plan.destinations.clone();
        wraps.push((
            WrapLayer::Egress,
            Box::new(move |cmd| {
                egress::wrap_command(
                    &prep.userland.socat_bin,
                    &prep.userland.shell_bin,
                    cmd,
                    &destinations,
                )
            }),
        ));
        // For a GUI cage, import sbx's MITM CA into the cage's NSS db before the app runs, so a
        // Chromium/Electron app trusts the egress proxy (it ignores the CA-file env vars). It sits
        // outside the egress wrap — it runs, then execs the egress-wrapped command. Only present
        // when `ca_trust` was provisioned (gui = "wayland" under this allowlist).
        if let Some(ct) = &ca_trust {
            wraps.push((
                WrapLayer::CaTrust,
                Box::new(|cmd| {
                    super::catrust::wrap(
                        &ct.certutil,
                        &prep.userland.shell_bin,
                        egress::CAGE_CA,
                        cmd,
                    )
                }),
            ));
        }
        egress_binds = wiring.binds;
        egress_env = wiring.env;
        egress_guard = Some(guard);
    }

    // The ssh-agent broker: a filtering agent socket in front of the host's own, so the cage can
    // sign with the keys `[ssh_agent] allow` names and do nothing else — not list the rest, not add
    // a key, not wipe the set. Independent of the network posture: it rides a bound Unix socket, so
    // the empty netns is untouched. Where a signature is then *spent* is the egress allowlist's
    // business: a `git push` also needs a `tcp://<host>:22` rule, and — since a capability-less cage
    // cannot bind a privileged port — an explicit `CONNECT` to reach it.
    //
    // A grant that resolves to nothing is a warning and no agent, never a silent partial: the two
    // ways that happens — no agent running, no held key matching — are both a mistake worth naming
    // at the moment it is made. Only a failure to *stand up* the broker is fatal, like the egress
    // proxy's: the user asked for it and it cannot be provided.
    let mut sshagent_guard = None;
    let mut sshagent_binds: Vec<binds::ExtraBind> = Vec::new();
    let mut sshagent_env: Vec<(String, String)> = Vec::new();
    if !prep.cfg.ssh_agent.is_empty() {
        let grant = prep.cfg.ssh_agent.join(", ");
        match sshagent::host_socket() {
            None => crate::diag::warn(&format!(
                "`[ssh_agent] allow` names {grant} but no agent is running on the host \
                 (`$SSH_AUTH_SOCK` is unset) — the cage gets no agent"
            )),
            Some(host_sock) => {
                let filter = sshagent::Filter::new(&prep.cfg.ssh_agent);
                match sshagent::admission(&host_sock, &filter) {
                    Err(e) => crate::diag::warn(&format!(
                        "cannot reach the host ssh-agent at {} ({e}) — the cage gets no agent",
                        host_sock.display()
                    )),
                    Ok(a) if a.admitted.is_empty() => crate::diag::warn(&format!(
                        "no key the host agent holds matches `[ssh_agent] allow` ({grant}) — the \
                         cage gets no agent. `ssh-add -l` prints the fingerprint and comment an \
                         entry may name."
                    )),
                    // `confirm` asks for a prompt on every signature, which takes an askpass helper
                    // on the host. Resolved once, before anything is stood up, so the decision to
                    // refuse and the wiring that follows it cannot be answered by two searches.
                    Ok(a) => match sshagent::confirmation(
                        prep.cfg.ssh_agent_confirm,
                        sshagent::Confirmer::askpass(),
                    ) {
                        // The absence of a helper refuses the grant: running the broker anyway
                        // would hand the cage a key *and* silently drop the one condition the
                        // grant was made under.
                        sshagent::Confirmation::NoHelper => crate::diag::warn(&format!(
                            "`[ssh_agent] confirm` asks for a prompt on every signature, but no \
                             askpass helper was found on the host (`$SSH_ASKPASS`, `ssh-askpass` on \
                             PATH, or OpenSSH's own) — the cage gets no agent rather than a grant \
                             whose confirmation would never appear. Install one (e.g. the \
                             `ssh-askpass` package), or drop `confirm`. Grant: {}",
                            a.admitted.join(", ")
                        )),
                        confirmation => {
                            let (guard, wiring) = sshagent::start(
                                &prep.layout,
                                &prep.cfg.ssh_agent,
                                &host_sock,
                                confirmation.helper(),
                                Arc::clone(&notify_wiring.notifier),
                            )
                            .map_err(|e| {
                                eprintln!("sbx: cannot start the ssh-agent broker: {e}");
                                ExitCode::FAILURE
                            })?;
                            crate::diag::note(&format!(
                                "ssh-agent: the cage may sign with {}{}{}",
                                a.admitted.join(", "),
                                match a.withheld {
                                    0 => String::new(),
                                    1 => " (1 other key withheld)".to_string(),
                                    n => format!(" ({n} other keys withheld)"),
                                },
                                if prep.cfg.ssh_agent_confirm {
                                    " — each signature asks you first"
                                } else {
                                    ""
                                }
                            ));
                            sshagent_binds = wiring.binds;
                            sshagent_env = wiring.env;
                            sshagent_guard = Some(guard);
                        }
                    },
                }
            }
        }
    }

    // GUI hole: under `gui = "wayland"`, bind the host's Wayland compositor socket read-only so a
    // graphical app can map a window. The cage runs same-uid, so a read-only bind suffices to
    // connect(). Only the socket *file* is bound, never `$XDG_RUNTIME_DIR` itself — that directory
    // also holds the dbus session bus, pulse, and the gpg/ssh agents, which binding the directory
    // would hand to the cage. Best-effort: with no compositor socket found, warn and run without
    // it (the app fails on its own) — not binding is the fail-closed direction for a display hole.
    // The cage env (`WAYLAND_DISPLAY`/`XDG_RUNTIME_DIR`) is fixed here by sbx; an untrusted
    // `[env]` could only mispoint a client at a nonexistent socket (self-DoS), never redirect the
    // bind, whose source path is set by sbx — so these keys need no denylist entry.
    let mut gui_binds: Vec<binds::ExtraBind> = Vec::new();
    let mut gui_env: Vec<(String, String)> = Vec::new();

    // Fonts: bind the generated fontconfig configuration read-only and name it to the cage's
    // fontconfig. The font *files* were provisioned and seeded above; this points fontconfig at
    // them so text renders rather than boxes — and a browser engine renders nothing at all
    // without it (it dies mid-page), which is why this is wired for every posture that draws,
    // `offscreen` included, not only for a windowed one. Independent of the compositor socket
    // below and best-effort (a staging failure warns, the app runs without fonts).
    // `FONTCONFIG_FILE` is fixed by sbx; a project `[env]` could override it (highest
    // precedence), but that only re-points the agent's own in-cage fontconfig at its own config —
    // self-sabotage, not an escape (it already controls what runs in the cage) — so the key needs
    // no denylist entry, exactly like `WAYLAND_DISPLAY`.
    if let Some(layer) = &font_layer {
        let conf = super::fonts::fonts_conf_for(layer);
        match super::fonts::stage(prep.layout.data_dir(), &conf) {
            Ok(path) => {
                gui_binds.push(binds::ExtraBind {
                    src: path,
                    dest: PathBuf::from(super::fonts::FONTS_CONF_INCAGE),
                    writable: false,
                });
                gui_env.push((
                    "FONTCONFIG_FILE".to_string(),
                    super::fonts::FONTS_CONF_INCAGE.to_string(),
                ));
            }
            Err(e) => crate::diag::warn(&format!(
                "this `gui` posture renders but the font configuration could not be \
                 staged ({e}) — text may not render"
            )),
        }
    }

    if matches!(prep.cfg.gui, crate::config::GuiPolicy::Wayland) {
        let display = std::env::var("WAYLAND_DISPLAY").ok();
        let runtime_dir = std::env::var("XDG_RUNTIME_DIR").ok();
        match resolve_wayland_hole(display.as_deref(), runtime_dir.as_deref()) {
            Ok((socket, env)) if socket.exists() => {
                gui_binds.push(binds::ExtraBind {
                    src: socket.clone(),
                    dest: socket,
                    writable: false,
                });
                gui_env.extend(env);
            }
            Ok((socket, _)) => crate::diag::warn(&format!(
                "`gui = \"wayland\"` but the compositor socket `{}` does not exist — \
                 running without a display",
                socket.display()
            )),
            Err(reason) => crate::diag::warn(&format!(
                "`gui = \"wayland\"` but {reason} — running without a display"
            )),
        }

        // GUI data: point the cage's glib/GTK at the provisioned, seeded schemas + themes via one
        // `XDG_DATA_DIRS` entry, so a GTK dialog finds `org.gtk.Settings.FileChooser` (else it
        // aborts) and the in-cage portal's file dialog finds the named `Adwaita-dark` theme. An
        // app's own launcher prepends its GTK data dirs, so sbx's entry (carrying the themes) stays
        // reachable at the tail. `XDG_DATA_DIRS` is a data path, not a code-load path (unlike the
        // mesa driver vars), so it needs no untrusted-`[env]` denylist entry — a project that
        // re-points it only sabotages its own cage's schema/theme lookup.
        if let Some(layer) = &guidata_layer {
            gui_env.extend(layer.env.iter().cloned());
        }

        // In-cage portal: point the app's D-Bus/portal client at the private bus and the GTK
        // backend (the bus itself is started by the outermost command wrap, below). The `XDG_*`
        // keys are data paths, not code-load paths, so — like `WAYLAND_DISPLAY` — a project `[env]`
        // that re-points them only self-DoSes its own cage's portal lookup and needs no denylist.
        if let Some(p) = &portal {
            gui_env.extend(super::portal::env(&p.gtk_root));
            // Bind the portal's host runtime directory (read-write) at the cage path the bus config,
            // env, and command wrap all reference, so the in-cage dbus-daemon writes its config and
            // creates its socket there — and the socket is reachable from the host for the relay.
            if let Some(hd) = &portal_host {
                gui_binds.push(binds::ExtraBind {
                    src: hd.dir().to_path_buf(),
                    dest: PathBuf::from(super::portal::CAGE_DIR),
                    writable: true,
                });
            }
        }
    }

    // GPU: when `gpu = true`, point the cage's libgbm/libEGL at mesa's own drivers (provisioned and
    // seeded above) and read-only-bind the minimal `/sys` DRM subtree the driver reads to enumerate
    // the device. The render node itself is granted through the device-bind mechanism below. Mostly
    // best-effort: a failed mesa provision or an absent render node degrades to software rendering.
    // The `/sys` paths are checked for existence at enumeration (`drm_sys_paths`) and bound firmly —
    // the same firm-`--ro-bind`-after-`.exists()` shape the Wayland socket uses — so a device
    // vanishing between enumeration and exec (a GPU hot-unplug) would fail the launch, an accepted
    // rarity, not "never fails".
    // The driver-path env vars mesa `dlopen`s from are sbx-controlled *and* reserved against an
    // untrusted `[env]` (they load code, so `is_reserved_env_key` denylists them alongside `LD_*`);
    // a *trusted* config may still override them — self-harm on its own cage, not an escape.
    if prep.cfg.gpu {
        if let Some(layer) = &gpu_layer {
            gui_env.extend(layer.env.iter().cloned());
        }
        for path in super::gpu::drm_sys_paths() {
            gui_binds.push(binds::ExtraBind {
                src: path.clone(),
                dest: path,
                writable: false,
            });
        }
    }

    // Audio: when `audio = true`, bind the host PulseAudio socket read-only at the fixed cage path
    // and point the app's loader at the provisioned libpulse (both provisioned/seeded above). Both
    // pieces must be present — no host socket, or a failed provision, means no audio (best-effort, a
    // warning, never a failed launch). The socket bind is read-only: same-uid, so a `connect()` still
    // works (exactly like the Wayland socket). `PULSE_SERVER` is a data path (an untrusted `[env]`
    // only self-DoSes its own cage's audio), so it needs no denylist entry; `LD_LIBRARY_PATH` is
    // already reserved against an untrusted `[env]` (a code-load path, alongside `LD_*`).
    if prep.cfg.audio {
        let host_socket =
            super::audio::host_socket(std::env::var("XDG_RUNTIME_DIR").ok().as_deref());
        match host_socket {
            Some(sock) if sock.exists() => {
                // The socket bind + `PULSE_SERVER` are firm (independent of the userspace provision);
                // the client libraries, the ALSA→pulse shim's `asound.conf`, and its env are added
                // only when the userspace was provisioned (best-effort — a failed provision already
                // warned, and the app then simply finds no audio).
                gui_binds.push(binds::ExtraBind {
                    src: sock,
                    dest: PathBuf::from(super::audio::CAGE_SOCK),
                    writable: false,
                });
                if let Some(alsa) = audio_layer.as_ref().and_then(|l| l.alsa.as_ref()) {
                    gui_binds.push(binds::ExtraBind {
                        src: alsa.asound_conf.clone(),
                        dest: PathBuf::from(super::audio::ASOUND_CONF_INCAGE),
                        writable: false,
                    });
                }
                // The `find_library` shim directory (for a Python PortAudio tool), bound read-only and
                // placed on `PYTHONPATH` by `audio::env`. Present only when PortAudio provisioned.
                if let Some(pyshim) = audio_layer.as_ref().and_then(|l| l.pyshim.as_ref()) {
                    gui_binds.push(binds::ExtraBind {
                        src: pyshim.clone(),
                        dest: PathBuf::from(super::audio::PYSHIM_INCAGE),
                        writable: false,
                    });
                }
                // Pass the base C++/glibc runtime dirs (the same set as NIX_LD_LIBRARY_PATH) so a
                // voice speech-to-text engine's `dlopen`ed native library (ctranslate2/onnxruntime)
                // finds `libstdc++.so.6` — `dlopen` consults LD_LIBRARY_PATH, not NIX_LD_LIBRARY_PATH.
                gui_env.extend(super::audio::env(
                    audio_layer.as_ref(),
                    &prep.userland.foreign_lib_paths,
                ));
            }
            _ => crate::diag::warn(
                "`audio = true` but no PulseAudio socket was found at \
                 `$XDG_RUNTIME_DIR/pulse/native` — the app runs without audio",
            ),
        }
    }

    // In-cage portal: wrap the command so the private session bus is stood up before the app runs.
    // The **outermost** layer, so its preamble (`dbus-daemon --fork`, which blocks until the socket
    // is ready) runs first, then execs the rest of the wrapped command. Only present under
    // `gui = "wayland"` + `dbus = true` with a successful provision.
    if let Some(p) = &portal {
        wraps.push((
            WrapLayer::Portal,
            Box::new(|cmd| {
                super::portal::wrap_command(
                    &prep.userland.shell_bin,
                    &p.dbus_daemon,
                    &p.xdp_root,
                    &p.gtk_root,
                    &p.update_desktop_db,
                    portal_scheme.as_deref(),
                    cmd,
                )
            }),
        ));
    }

    // The launcher's extra binds, emitted after the structural mounts: the egress machinery
    // (socket + CA) and the GUI socket. Their destinations are sbx's or the host's, never a
    // project path, so they neither shadow nor are shadowed by a structural mount.
    let mut extra_binds = egress_binds;
    extra_binds.extend(sshagent_binds);
    extra_binds.extend(brokers.iter().map(broker::Reachable::bind));
    extra_binds.extend(forward_binds);
    extra_binds.extend(gui_binds);
    extra_binds.extend(inline_flake_binds);
    extra_binds.extend(proc_binds);

    // Close the project paths `[fs]` names. Emitted among the launcher's extra binds — that is,
    // *after* the structural mounts — because a mask emitted before the project's own mount would
    // be covered by it, which is exactly why a `binds` entry aimed inside the project masks nothing
    // today. Unlike the rest of this block their destinations *are* project paths, which is the
    // point: they are the only binds here meant to land on one.
    let fs_masks = super::fsmask::expand(&prep.cwd, &prep.cfg.fs);
    for warning in &fs_masks.warnings {
        crate::diag::warn(warning);
    }
    if let Some(reason) = &fs_masks.refused {
        eprintln!("sbx: {reason}");
        return Err(ExitCode::FAILURE);
    }
    let fs_decoys = if fs_masks.is_empty() {
        None
    } else {
        let dir = super::fsmask::mask_dir(prep.layout.data_dir(), std::process::id());
        match super::fsmask::stage_decoys(&dir) {
            Ok(decoys) => {
                extra_binds.extend(super::fsmask::agent_binds(&fs_masks, &decoys));
                Some(decoys)
            }
            Err(e) => {
                // Fail closed: without the decoys nothing masks those paths, and a session that
                // ran anyway would leave open exactly the files the config asked to close.
                eprintln!(
                    "sbx: cannot stage the `[fs]` masks ({e}) — the paths they name would stay open"
                );
                return Err(ExitCode::FAILURE);
            }
        }
    };

    // Pin sbx's own control plane in place whenever a read-write bind contains it: each root's host
    // path is frozen as a mountpoint chain (read-write intermediates, a read-only leaf), so in-cage
    // code cannot rename a writable parent to move a control-plane root aside and recreate a forged
    // one at the same path — which sbx would otherwise read or `execve` on its next run. The bind
    // stays read-write; only these specific host paths are protected. Emitted after the structural
    // mounts — the containing read-write bind has to be in place before the pin lands on it. Binds
    // are appended after this block (the task control plane below); the rule they have to respect
    // is stated on `control_plane_pins`, and it is about their destination, not their position.
    //
    // Interdependency: the protection assumes in-cage code cannot `umount` a pin. That holds because
    // bwrap drops all capabilities (no `CAP_SYS_ADMIN` in the cage's user namespace) and the seccomp
    // filter denies `umount2`/`unshare`/`mount` — a change loosening either would silently break it.
    match establish_control_plane_pins(&crate::config::control_plane_pins(&prep.cfg.binds)) {
        Ok(pins) => extra_binds.extend(pins),
        Err(e) => {
            // Fail closed: if a pin cannot be established the containing read-write bind would be
            // unprotected, so abort the launch rather than run with a gap. An extreme case — a
            // mkdir failing in sbx's own data/config tree.
            eprintln!(
                "sbx: cannot protect sbx's control plane ({e}) — a read-write bind contains it"
            );
            return Err(ExitCode::FAILURE);
        }
    }

    // Declared operations: when this session has any, the task control socket crosses into the cage
    // and a generated client is bound read-only beside it, so an in-cage caller can list and invoke
    // a task. Both paths are derived here (before the spec) and both are created below (before the
    // launch), so bwrap finds them present. This is the ONE control plane that crosses — its surface
    // is three commands, and the invocation log lives on a second, host-only socket that the
    // recorded party cannot read.
    let mut task_env: Vec<(String, String)> = Vec::new();
    let task_socket = (!prep.cfg.tasks.is_empty()).then(|| {
        let path = super::task_control::task_dir(prep.layout.data_dir(), std::process::id())
            .join("control.sock");
        extra_binds.push(binds::ExtraBind {
            src: path.clone(),
            // Writable so a connect is never refused on a permission subtlety; the *file* is bound,
            // never its directory, so in-cage code cannot unlink it and serve its own listener at
            // the same path.
            dest: PathBuf::from(super::task_control::CAGE_TASK_UDS),
            writable: true,
        });
        task_env.push((
            super::task_control::TASK_SOCKET_ENV.to_string(),
            super::task_control::CAGE_TASK_UDS.to_string(),
        ));
        // The client is a generated script, never sbx itself: the cage must not hold a binary able
        // to act on sbx's own state, and "it cannot because nothing it needs is mounted" is a
        // property no test could hold onto. See `task_shim`.
        extra_binds.push(binds::ExtraBind {
            src: super::task_control::shim_path(prep.layout.data_dir(), std::process::id()),
            dest: PathBuf::from(super::task_control::TASK_SHIM_INCAGE),
            writable: false,
        });
        task_env.push((
            "SBX_TASK_CLI".to_string(),
            super::task_control::TASK_SHIM_INCAGE.to_string(),
        ));
        // Where an `output`-declaring task's artifacts become readable. Bound **read-only**, and only
        // when some task declares `output` — an agent that can write here could plant the input a
        // credential-bearing command later reads back, which is the one thing the direction of this
        // mount has to prevent.
        //
        // The *parent* is bound, because a cage's mounts are fixed when it is built and no
        // invocation can add one afterwards: each task's directory then appears inside it as it is
        // created, since a bind mount shows the tree rather than a copy of it.
        if prep.cfg.tasks.iter().any(|t| t.output) {
            let root = super::task::output_root_for(&prep.layout, &prep.cwd)
                .and_then(|root| std::fs::create_dir_all(&root).map(|()| root));
            if let Err(e) = &root {
                crate::diag::warn(&format!(
                    "cannot create this project's task output directory ({e}) — an operation \
                     declaring `output` will refuse rather than run"
                ));
            } else if let Ok(root) = root {
                extra_binds.push(binds::ExtraBind {
                    src: root,
                    dest: PathBuf::from(super::task::TASK_OUT_AGENT),
                    writable: false,
                });
            }
        }
        path
    });

    // Environment. Each source is tagged with where it belongs, and `EnvLayer` — not this list's
    // order — decides which one wins a shared key. The structural HOME/PATH/... are added by the
    // assembler, which upserts all of these over them. An untrusted config has already lost its
    // reserved keys upstream — including the proxy and CA keys — so it can neither redirect the
    // egress nor swap the CA; a trusted config overriding them only harms its own cage.
    let extra_env = extra_cage_env(vec![
        (EnvLayer::Passthrough, passthrough_env()),
        (EnvLayer::Cacert, binds::cacert_env()),
        (EnvLayer::Gui, gui_env),
        (EnvLayer::AutoEquip, autoequip_env),
        (EnvLayer::Mise, mise_env(prep)?),
        (EnvLayer::Egress, egress_env),
        (EnvLayer::SshAgent, sshagent_env),
        (
            EnvLayer::Broker,
            brokers.iter().flat_map(|b| b.env.clone()).collect(),
        ),
        (EnvLayer::Task, task_env),
        (EnvLayer::Config, prep.cfg.env.clone()),
    ]);

    // The cage's zone, checked against the database that will actually be bound — assembly is pure,
    // so this is the last place a name can be held against something real. Read off the assembled
    // environment, not off the field alone: see `declared_zone`.
    let timezone = cage_timezone(
        declared_zone(&extra_env, prep.cfg.timezone.as_deref()),
        &prep.userland.zoneinfo_src,
    );
    // Resolved from the post-`merge_app` config, so the app's names and its bundles' are already
    // unioned onto the baseline's and each is held against the package set this cage actually
    // equips — a name whose package another project declares resolves to nothing here.
    let fresh_release_tokens =
        super::packages::fresh_release_tokens(&prep.cfg.packages, &prep.cfg.accepts_fresh_releases);
    let overlay = binds::Overlay {
        env: &extra_env,
        binds: &prep.cfg.binds,
        bin_paths: &bin_paths,
        timezone: &timezone,
        fresh_release_tokens: &fresh_release_tokens,
    };
    // Generate the in-cage contract from the resolved (post-`merge_app`) config, so a process
    // inside the cage can see which hosts it can reach, why a direct connection or `ping` fails,
    // and which declared operations it may invoke. The tasks are the gated ones — the same list the
    // task plane serves — so the file never advertises an operation the socket would refuse to run.
    // Informational only; bound read-only by `build_spec`.
    let egress_contract = super::contract::cage_contract(&prep.cfg.network, &prep.cfg.tasks);
    // The device grant: the resolved `[devices]` plus, under `gpu = true`, the render node
    // directory (`/dev/dri`), so the cage can reach the GPU. Both become `--dev-bind-try` mounts.
    // Deduped: a trusted `[devices] allow = ["/dev/dri"]` alongside `gpu = true` must not emit the
    // bind twice (harmless to bwrap, but tidy).
    let mut devices = prep.cfg.devices.clone();
    let dri = PathBuf::from(super::gpu::DRI_DIR);
    if prep.cfg.gpu && !devices.contains(&dri) {
        devices.push(dri);
    }
    // A command with nothing declared ahead of it is passed through untouched, so the ordinary
    // launch keeps the process it would have had — the same pid, the same signals, the same exit
    // status — and only a launch that actually declared something gains a shell above it.
    let nothing_to_compose = prep.cfg.provisions.is_empty() && prep.cfg.service.is_empty();
    let startup_cmd = if cmd.is_empty() || nothing_to_compose {
        cmd
    } else {
        compose_startup_cmd(&prep.cfg.provisions, &prep.cfg.service, &extra_env, cmd)
    };

    // Every wrap this launch contributed, nested by `WrapLayer` rather than by the order the blocks
    // above happened to run in — and nested **around the composed startup**, which is the whole
    // point of doing it here rather than before the composition.
    //
    // An install step is not a peer of the command; it is the thing that finishes making the command
    // runnable, so it needs everything the command needs. Wrapped the other way round the step ran
    // *outside* every layer: before the mise equip lanes, so a step asking `mise where` about a
    // package found nothing and failed the launch before the equip that would have installed it; and
    // before the egress forwarder, so a step that downloads got its `https_proxy` pointed at a port
    // with nothing listening yet. `provision`'s own documentation already says a step runs "in the
    // same cage, under the same posture and allowlist" as the command, and this is what makes that
    // true.
    //
    // `WrapLayer`'s ordering is unchanged: this moves the composed startup to where the app's bare
    // command already was, so every pairwise constraint the enum documents holds exactly as before.
    let startup_cmd = wrap_cage_command(startup_cmd, wraps);
    let spec = binds::build_spec(
        prep.layout.data_dir(),
        &prep.cwd,
        runtime,
        &prep.userland,
        &nix_mount,
        &overlay,
        &extra_binds,
        net_policy(&prep.cfg.network),
        &egress_contract,
        // The `tcp://` destinations get `/etc/hosts` entries pointing at the addresses the preamble
        // above listens on, so a declaration reads the same inside the cage as outside it — and the
        // ones whose port is privileged, which can have no such listener, get a generated ssh
        // `ProxyCommand` toward the cage's CONNECT proxy instead.
        &tcp_plan,
        // The trusted seccomp relaxation from the resolved (post-`merge_app`) config, so an app's
        // `[seccomp] allow` union is in effect for `sbx app`, exactly like its limits.
        prep.cfg.seccomp.clone(),
        // The trusted device grant from the resolved (post-`merge_app`) config, plus the GPU
        // render node under `gpu = true`, so an app's `[devices]` union is in effect for `sbx app`,
        // exactly like its seccomp relaxation.
        &devices,
        // The URI handlers from the resolved (post-`merge_app`) config, so an app's `[open]` folds
        // over the baseline's for `sbx app` the way its packages and environment do.
        &prep.cfg.open,
        // The command, with the launch's whole start-up composed ahead of it: the app's bundle
        // install steps, then its services. Composed here — the one function that stands up a cage —
        // so every path reaching a cage gets the same start-up in the same order, and so both read
        // the config *after* the app overlay and any one-shot override have had their say.
        startup_cmd,
    )
    .map_err(|e| {
        eprintln!("sbx: cannot prepare the sandbox: {e}");
        ExitCode::FAILURE
    })?;
    // A graphical cage under an isolated network namespace (any filtering posture — the namespace
    // is empty but for loopback) reads as *offline* to an in-cage browser: Chromium decides
    // `navigator.onLine` from the presence of a non-loopback interface, not from real reachability,
    // so a graphical agent panel freezes on "No internet" even though proxy egress works. Route the
    // launch through the netns holder (see `super::netns`), which pre-creates the namespace with a
    // black-hole `dummy0` interface so the browser reports online — no egress is opened (the dummy
    // has no route; all traffic still goes through the proxy on loopback). Gated to the rendering
    // postures, the only ones running a browser engine (a headless `offscreen` engine reads
    // `navigator.onLine` the same way a windowed one does), and only when sbx's own path is
    // resolvable, so the launch never falls back to a cage without `--unshare-net` (which would
    // share the host network).
    let spec = if prep.cfg.gui.renders() && spec.net == NetPolicy::Isolated {
        match std::env::current_exe() {
            Ok(exe) => spec.with_netns_dummy(super::spec::NetnsDummy {
                uid: unsafe { libc::getuid() },
                gid: unsafe { libc::getgid() },
                holder_exe: exe,
            }),
            Err(e) => {
                eprintln!(
                    "sbx: netns holder unavailable ({e}); the cage runs without an online signal"
                );
                spec
            }
        }
    } else {
        spec
    };
    // Stand the task plane up now: the spec is final (so a task cage can be derived from it) and the
    // launch has not happened yet (so bwrap finds the bound socket present). A failure here aborts
    // the launch rather than running a cage whose declared operations silently do not exist — the
    // agent would keep trying and never learn why.
    let task_plane = match &task_socket {
        None => None,
        Some(_) => {
            let engine = super::task::TaskEngine::from_cage(
                &prep.bwrap,
                &spec,
                &prep.layout,
                &prep.cwd,
                // A relative `sops://` file resolves against the config's directory, exactly as it
                // does for a wire injection.
                &prep.cwd,
                prep.cfg.tasks.clone(),
                prep.cfg.limits.clone(),
                spec.cage_slug(),
                Some(prep.userland.ca_bundle_src.as_path()),
                super::task::CageForwarder {
                    socat: prep.userland.socat_bin.clone(),
                    shell: prep.userland.shell_bin.clone(),
                },
                prep.cfg.redact_min_len,
            )
            .with_notifier(Arc::clone(&notify_wiring))
            .with_brokers(brokers.clone())
            .with_signer_log(signer_ring.clone());
            // Carry the session's `[fs]` masks into every task cage, so a denied path is closed
            // there too unless the task's own `unmask` names it. The decoys are the ones this
            // launch already staged: a task cage is derived from the agent's, and pointing it at a
            // second set would be two answers to one question.
            let engine = match (&fs_decoys, fs_masks.is_empty()) {
                (Some(decoys), false) => engine.with_fs_masks(fs_masks.clone(), decoys.clone()),
                _ => engine,
            };
            // The task tool pool, when any task declares a `mise:` tool. Filled host-side now — a
            // cold fill is minutes long, so it belongs at launch where the user is watching, not
            // inside the first invocation. Best-effort, unlike the `nix:` package path: a pool tool
            // that will not install is one task's problem, and aborting the whole session over it
            // would take the agent down with it. The task then fails naming the missing tool, and
            // `sbx task list` flags it before it is ever invoked.
            let engine = match super::binds::project_runtime_id(&prep.cwd) {
                Ok(id) => engine.with_pool(
                    super::taskpool::pool_dir(prep.layout.data_dir(), &id),
                    prep.userland.mise_bin.clone(),
                ),
                Err(e) => {
                    if prep.cfg.tasks.iter().any(|t| !t.packages.is_empty()) {
                        crate::diag::warn(&format!(
                            "the task tool pool has no home for this project ({e}) — tasks \
                             declaring `packages` will not find their tools"
                        ));
                    }
                    engine
                }
            };
            if let Err(e) = engine.ensure_pool() {
                crate::diag::warn(&format!("the task tool pool could not be prepared: {e}"));
            }
            let (bash, socat, head) = task_client_programs(&prep.userland);
            let client = super::task_control::ClientPrograms {
                bash: &bash,
                socat: &socat,
                head: &head,
            };
            match super::task_control::start(
                prep.layout.data_dir(),
                std::process::id(),
                engine,
                &client,
            ) {
                Ok(plane) => Some(plane),
                Err(e) => {
                    eprintln!("sbx: cannot start the task control plane: {e}");
                    return Err(ExitCode::FAILURE);
                }
            }
        }
    };

    let guard = if egress_guard.is_some()
        || sshagent_guard.is_some()
        || !broker_guards.is_empty()
        || broker_feed.is_some()
        || signer_feed.is_some()
        || forward_guard.is_some()
        || portal_host.is_some()
        || proc_enforce_guard.is_some()
        || task_plane.is_some()
    {
        Some(LaunchGuard {
            notify_sink: Some(Arc::clone(&notify_wiring)),
            egress: egress_guard,
            ssh_agent: sshagent_guard,
            brokers: broker_guards,
            broker_feed,
            signer_feed,
            forward: forward_guard,
            notify: notify_relay,
            theme: theme_relay,
            portal: portal_host,
            proc_enforce: proc_enforce_guard,
            task: task_plane,
        })
    } else {
        None
    };
    Ok((spec, guard))
}

/// Translate the resolved configuration's network posture into the cage's net
/// policy. The two enums are kept separate on purpose: the config vocabulary
/// (`none`/`shared`/`deny`/`allow`/`ask`) is the user's, while the cage's posture type is the
/// sandbox's. A filtering posture maps to an **isolated** (empty) namespace by
/// design — that is the Model-B foundation: with no route of its own, the cage's only
/// egress is the bound socket `build` wires to the host filtering proxy. So the netns
/// is identical to `none`; the filtering lives in the proxy on top, not in the netns.
fn net_policy(network: &crate::config::NetworkPolicy) -> NetPolicy {
    match network {
        crate::config::NetworkPolicy::Shared => NetPolicy::Shared,
        crate::config::NetworkPolicy::Isolated => NetPolicy::Isolated,
        crate::config::NetworkPolicy::Allowlist(_) => NetPolicy::Isolated,
    }
}

/// Resolve the host's Wayland compositor socket and the cage environment that points a
/// graphical app at it, from the host `WAYLAND_DISPLAY`/`XDG_RUNTIME_DIR`. Pure: the impure
/// existence check and the bind are the caller's, so the path/env computation is unit-tested.
///
/// Per the Wayland convention an absolute `WAYLAND_DISPLAY` is the socket path verbatim;
/// otherwise it is a name resolved under `XDG_RUNTIME_DIR`. The returned path is always the
/// socket **file** — never the runtime directory, which also holds the dbus session bus, pulse,
/// and the gpg/ssh agents; the caller binds exactly this file read-only, so none of those is
/// exposed (the whole point of gating the GUI hole trusted-only). The returned env carries
/// `WAYLAND_DISPLAY` and, when known, `XDG_RUNTIME_DIR`, so the in-cage client finds the same
/// socket at the same path (the cage runs same-uid, so a read-only bind is enough to connect).
fn resolve_wayland_hole(
    display: Option<&str>,
    runtime_dir: Option<&str>,
) -> Result<(PathBuf, Vec<(String, String)>), String> {
    let display = display.ok_or("WAYLAND_DISPLAY is unset")?;
    if display.is_empty() {
        return Err("WAYLAND_DISPLAY is empty".to_string());
    }
    let mut env = vec![("WAYLAND_DISPLAY".to_string(), display.to_string())];
    if Path::new(display).is_absolute() {
        // An absolute display is the socket path itself; XDG_RUNTIME_DIR is not needed to
        // locate it, but pass it through when set (some clients still read it).
        if let Some(dir) = runtime_dir {
            env.push(("XDG_RUNTIME_DIR".to_string(), dir.to_string()));
        }
        Ok((PathBuf::from(display), env))
    } else {
        let dir =
            runtime_dir.ok_or("XDG_RUNTIME_DIR is unset (needed to locate the Wayland socket)")?;
        env.push(("XDG_RUNTIME_DIR".to_string(), dir.to_string()));
        Ok((Path::new(dir).join(display), env))
    }
}

/// Seed (or top up) the project's own writable store with the closure of everything
/// the cage reads through `/nix`: the base userland, the native `[packages]`, and the
/// `nix:` tools. The roots are collected from the provisioners and handed as the single
/// source the seed copies and registers, so the cage runs from its own store and an
/// agent's writes land only there.
fn seed_project_store(
    prep: &Prepared,
    pkg_roots: &[PathBuf],
    tool_roots: &[PathBuf],
    font_roots: &[PathBuf],
) -> io::Result<super::projectstore::ProjectStore> {
    let (id, canonical) = binds::project_identity(&prep.cwd)?;
    let roots = collect_roots(&prep.userland, pkg_roots, tool_roots, font_roots);
    let store = super::projectstore::prepare(&prep.nix_store, &prep.layout, &id, &roots)?;
    // Record the project's canonical path so a later `sbx gc` can recognise this tree and reclaim
    // it once the project is gone. Best-effort: a housekeeping marker must never fail a launch.
    if let Err(e) = super::projectstore::write_marker(&prep.layout, &id, &canonical) {
        crate::diag::warn(&format!("could not record the project marker: {e}"));
    }
    Ok(store)
}

/// The complete set of logical store roots the cage resolves through `/nix`: the base
/// userland's roots, then the native `[packages]`, the `nix:` tools, and (under the GUI
/// hole) the fonts. Collected from the provisioners (never reconstructed by stripping
/// sub-paths), so the seed carries every closure the cage needs — a forgotten source would
/// silently make the cage re-fetch it. Pure, so the collection is unit-tested.
fn collect_roots(
    userland: &Userland,
    pkg_roots: &[PathBuf],
    tool_roots: &[PathBuf],
    font_roots: &[PathBuf],
) -> Vec<PathBuf> {
    let mut roots = userland.base_roots.clone();
    roots.extend(pkg_roots.iter().cloned());
    roots.extend(tool_roots.iter().cloned());
    roots.extend(font_roots.iter().cloned());
    roots
}

/// Resolve a trusted project's mise `[env]` into environment entries. Empty when
/// the project declares no mise file, or it is withheld — an untrusted or changed
/// mise file only warns (its `[env]` is held back, like its security fields).
///
/// mise is provisioned via nix and driven from sbx's store against the **engine**
/// channel — never this launch's possibly-pinned base reference (mise runs in its own
/// store view, free of the one-channel rule; see [`Prepared::engine_ref`]). The files
/// it reads are materialized from the bytes trust validated, outside any writable
/// mount, so it sees exactly the authorized, hashed inputs. A trusted `[env]` that
/// cannot be resolved is fatal, like a declared tool that fails to realise.
fn mise_env(prep: &Prepared) -> Result<Vec<(String, String)>, ExitCode> {
    let Some(mise_cfg) = &prep.cfg.mise else {
        return Ok(Vec::new());
    };
    if mise_cfg.state != crate::trust::TrustState::Trusted {
        crate::diag::warn(&format!(
            "mise file `{}` withheld ({}): its `[env]` is not applied",
            mise_cfg.name,
            crate::config::untrusted_reason(mise_cfg.state)
        ));
        return Ok(Vec::new());
    }

    // The same engine reference the in-cage mise uses, already resolved in `prepare`.
    let mise_root = super::mise::provision_engine(&prep.nix, &prep.layout, &prep.engine_ref)
        .map_err(|e| {
            eprintln!("sbx: cannot provision the mise engine: {e}");
            ExitCode::FAILURE
        })?;
    let mise_bin = super::mise::bin(&mise_root);
    // Stage the authorized files in a per-project directory that sits outside every
    // writable mount (a sibling of the writable home, like the synthetic identity).
    let id = binds::project_runtime_id(&prep.cwd).map_err(|e| {
        eprintln!("sbx: cannot identify the project: {e}");
        ExitCode::FAILURE
    })?;
    let stage = prep
        .layout
        .data_dir()
        .join("projects")
        .join(id)
        .join("mise-config");
    super::mise::resolve_env(
        &prep.bwrap,
        &prep.layout,
        &mise_bin,
        &mise_cfg.files,
        &stage,
    )
    .map_err(|e| {
        eprintln!("sbx: mise [env] resolution failed: {e}");
        ExitCode::FAILURE
    })
}

/// Provision a trusted project's declared `nix:` mise tools into sbx's store and report
/// the `bin` directories to prepend to PATH, plus warnings. Empty when the project
/// declares no mise file. An untrusted project's `nix:` tools are withheld (warned); a tool
/// for another backend is auto-equipped in-cage instead (see [`auto_equip_tokens`]), not
/// host-provisioned here. A declared, admitted `nix:` tool that fails to resolve or realise
/// is fatal, like a native `[packages]` tool. Resolution is cached per project, so nixhub is
/// queried once per `(tool, version)` rather than on every launch.
fn mise_tools(prep: &Prepared) -> Result<super::packages::Provisioned, ExitCode> {
    let Some(mise_cfg) = &prep.cfg.mise else {
        return Ok(super::packages::Provisioned {
            bins: Vec::new(),
            roots: Vec::new(),
            warnings: Vec::new(),
        });
    };
    super::nixhub::provision(
        &prep.nix,
        &prep.layout,
        &prep.cwd,
        &mise_cfg.files,
        mise_cfg.state == crate::trust::TrustState::Trusted,
        &super::nixhub::current_system(),
    )
    .map_err(|e| {
        eprintln!("sbx: {e}");
        ExitCode::FAILURE
    })
}

/// The `<token>@<version>` install specs for the project's non-`nix:` mise tools — the tools
/// the launcher auto-equips in-cage rather than host-provisioning. Empty when the project
/// declares no mise file. A pure re-parse of the already-loaded mise files, independent of
/// the host-side `nix:` path, and trust-independent: this is the open self-equip path, so the
/// tools are equipped whether or not the project is trusted (the egress allowlist is the
/// control over where they may be fetched from).
fn auto_equip_tokens(cfg: &crate::config::Resolved) -> Vec<String> {
    cfg.mise
        .as_ref()
        .map(|m| {
            super::nixhub::parse_nix_tools(&m.files)
                .non_nix
                .into_iter()
                .map(|t| format!("{}@{}", t.token, t.version))
                .collect()
        })
        .unwrap_or_default()
}

/// Wrap `cmd` so the cage equips a set of mise tools before running it: a static bash that runs
/// `mise <verb> <tokens>` (its stdout redirected to stderr so a piped command's stdout stays
/// clean) and then `exec`s the real command — which therefore stays the cage's main process,
/// leaving an interactive `sbx run`'s pty job control unchanged. The `verb` is an sbx-chosen literal
/// (`install` for the project's local `.mise.toml` tools, `use -g` for the app's `[packages]
/// mise:` ones); the tokens and the command ride `"$@"` positionally, so only the absolute mise
/// path, the sbx-chosen verb, and the integer token count are interpolated into the script — a
/// token from an untrusted config can never inject shell. Best-effort: a failed equip does not
/// abort the command (the missing tool surfaces when it is used), matching the self-equip
/// posture rather than the host `nix:` hard-fail guarantee.
///
/// `mise_data_dir`, when `Some`, pins **only the equip step's** `MISE_DATA_DIR` (the exec'd command
/// keeps the cage's ambient value). This is how a global app's Lane-1 `mise use -g` installs an app
/// package into the app-global home pool while the ambient primary is the per-project pool: the
/// value is an sbx-owned fixed cage path ([`binds::mise_app_global_data_dir`]), so single-quoting it
/// in the assignment is injection-safe.
fn wrap_mise_equip(
    mise: &Path,
    bash: &Path,
    verb: &str,
    tokens: &[String],
    mise_data_dir: Option<&str>,
    cmd: Vec<OsString>,
) -> Vec<OsString> {
    let n = tokens.len();
    let data_dir_prefix = match mise_data_dir {
        Some(dir) => format!("MISE_DATA_DIR='{dir}' "),
        None => String::new(),
    };
    let script = format!(
        "{data_dir_prefix}{mise} {verb} \"${{@:1:{n}}}\" 1>&2; shift {n}; exec \"$@\"",
        mise = mise.to_string_lossy(),
    );
    let mut out = vec![
        bash.as_os_str().to_os_string(),
        OsString::from("-c"),
        OsString::from(script),
        // `$0` — a label; the tokens are `$1..$n`, the command is what remains after `shift`.
        OsString::from("sbx-mise-equip"),
    ];
    out.extend(tokens.iter().map(OsString::from));
    out.extend(cmd);
    out
}

/// Wrap `cmd` so the cage builds a set of flake packages before running it: a static bash
/// that, for each `(ref, out-link, key)` triple, runs `nix build <ref> --no-write-lock-file
/// --out-link <out-link>` unless the out-link is already realised, registers a host-resolvable gc
/// root for the build,
/// then `exec`s the real command (which stays the cage's main process, leaving an interactive `sbx run`'s pty
/// job control unchanged). Only the absolute `nix` path, the out-link parent directory, and the
/// integer triple count are interpolated into the script — the refs, out-links, and keys ride
/// `"$@"` positionally, so a value from config can never inject shell. The short-circuit
/// `[ -e "$out/bin" ]` dereferences the out-link symlink into the cage's `/nix` (the per-project
/// store): a path already present skips the build (a warm no-op that also works offline), while a
/// dangling cross-project out-link (the `home_scope = "global"` residual) rebuilds.
///
/// The gc root is the same pattern mise's plugin uses for its installs: a symlink under
/// `/nix/var/nix/gcroots/` whose target is the build's `/nix/store/<hash>` path — host-resolvable
/// (the relocated store reads it both in-cage and host-side), unlike the in-cage `--out-link`
/// indirect root nix also creates, whose `/home/sandbox/…` target dangles host-side. Keyed by the
/// **package name** and overwritten (`ln -sfn`) every launch: a roll re-points the one root to the
/// new build, dropping the old store path, so a host-side `sbx gc` keeps the current build and
/// collects the rolled-away one with no per-home enumeration. Written unconditionally (warm or
/// fresh) so an older store missing the root self-heals. Best-effort: a failed build leaves no
/// out-link, so the `readlink` yields nothing and no root is written (the missing tool surfaces
/// when it is used), matching the in-cage self-equip posture. `mkdir`/`ln`/`readlink` are invoked
/// by name (the base coreutils); a persisted tool shadowing one on PATH is a trusted layer harming
/// its own cage — the self-equip self-harm class already accepted, never a cross-tenant concern.
fn wrap_flake_equip(
    nix: &Path,
    bash: &Path,
    flake_dir: &Path,
    quads: &[(String, PathBuf, PathBuf, String)],
    cmd: Vec<OsString>,
) -> Vec<OsString> {
    let n = quads.len();
    // Per package (`$1` ref, `$2` build target, `$3` good out-link, `$4` key): build the target if
    // it is neither warm nor already known-failed (a `<target>.failed` marker, so a broken pin is
    // retried once per revision, not on every launch, and a new pin — a new rev-keyed target — is
    // attempted afresh). On success the good out-link (what PATH resolves through) is promoted to the
    // fresh build and any marker cleared; on failure it is left at the last good build so the app
    // still runs, with a loud notice. Only the target/good pair is marked (never a floating package,
    // whose target *is* its good — it has no revision to clear the marker, so it retries as before).
    // The hard-fail (exit 1) is reserved for the case where no prior good build exists at all.
    let script = format!(
        "mkdir -p '{dir}'\n\
         n={n}\n\
         while [ \"$n\" -gt 0 ]; do\n\
         ref=\"$1\"; target=\"$2\"; good=\"$3\"; key=\"$4\"\n\
         if [ ! -e \"$target/bin\" ] && [ ! -e \"$target.failed\" ]; then\n\
         '{nix}' build \"$ref\" --no-write-lock-file --out-link \"$target\" 1>&2\n\
         [ -e \"$target/bin\" ] || [ \"$target\" = \"$good\" ] || touch \"$target.failed\"\n\
         fi\n\
         if [ -e \"$target/bin\" ]; then\n\
         rm -f \"$target.failed\"\n\
         sp=$(readlink -f \"$target\")\n\
         [ \"$target\" != \"$good\" ] && ln -sfn \"$sp\" \"$good\"\n\
         elif [ -e \"$good/bin\" ]; then\n\
         sp=$(readlink -f \"$good\")\n\
         echo \"sbx: flake '$key': build failed — falling back to the last good build; a new revision (or, for an inline flake, an edit) triggers a fresh build\" 1>&2\n\
         else\n\
         echo \"sbx: flake '$key': the build failed and there is no prior build to fall back to\" 1>&2\n\
         exit 1\n\
         fi\n\
         [ -n \"$sp\" ] && mkdir -p /nix/var/nix/gcroots \
         && ln -sfn \"$sp\" \"/nix/var/nix/gcroots/sbx-flake-$key\"\n\
         shift 4\n\
         n=$((n - 1))\n\
         done\n\
         exec \"$@\"",
        dir = flake_dir.to_string_lossy(),
        nix = nix.to_string_lossy(),
    );
    let mut out = vec![
        bash.as_os_str().to_os_string(),
        OsString::from("-c"),
        OsString::from(script),
        // `$0` — a label; the quads are `$1..$4n`, the command is what remains after the shifts.
        OsString::from("sbx-flake-equip"),
    ];
    for (reference, target, good, key) in quads {
        out.push(OsString::from(reference));
        out.push(target.as_os_str().to_os_string());
        out.push(good.as_os_str().to_os_string());
        out.push(OsString::from(key));
    }
    out.extend(cmd);
    out
}

/// Record this sandbox in the on-disk registry so `sbx session ls` can list it. Best
/// effort: the registry is observability, not a security control, so a failure to
/// register degrades visibility but never blocks the sandbox. The session is keyed
/// on `spec.workdir` — the canonical project root, the same identity the runtime
/// layout derives from. Returns the record's path (to hand to a [`RecordGuard`])
/// when it was written.
///
/// `detached` records where this session's output went, which is the one thing a listing cannot
/// infer from the other fields: a detached session's stdout/stderr is redirected to
/// [`detach_log_path`], a foreground one's stays on the launching terminal. Only
/// [`detached_child`] passes `true`.
fn register(
    data_dir: &Path,
    spec: &SandboxSpec,
    kind: Kind,
    runtime: binds::Runtime,
    detached: bool,
) -> Option<PathBuf> {
    let session = Session::current(spec.workdir.clone(), kind, session_runtime(runtime)).ok()?;
    let session = if detached {
        session.detached()
    } else {
        session
    };
    session::Registry::at(data_dir).register(&session).ok()
}

/// The owned [`session::SessionRuntime`] for a launch's borrowing [`binds::Runtime`], so the
/// record can outlive the launch and let `sbx session attach` reproduce the same home.
fn session_runtime(runtime: binds::Runtime) -> session::SessionRuntime {
    match runtime {
        binds::Runtime::ProjectDefault => session::SessionRuntime::Project,
        binds::Runtime::GlobalApp(name) => session::SessionRuntime::GlobalApp(name.to_string()),
        binds::Runtime::ProjectApp(name) => session::SessionRuntime::ProjectApp(name.to_string()),
    }
}

/// Run the cage as a child and propagate its exit status, keeping sbx alive for the
/// whole session. Required by the network-allowlist posture, whose host filtering proxy
/// runs on a thread that an exec-replace would discard; `run` uses this exactly when an
/// egress guard is present. `Command::status` forks, waits, and yields the child's code;
/// the proxy thread was already spawned (by `egress::start`) before the launch.
fn run_supervised(bwrap: &Path, spec: &SandboxSpec, limits: &super::cgroup::Limits) -> ExitCode {
    ExitCode::from(run_status(bwrap, spec, limits) as u8)
}

/// Fork the cage, wait, and return its exit status code (shell convention). The fork-and-wait
/// core of [`run_supervised`], shared with the multi-cage upgrade roll: both run a series of
/// cages and need the code of each rather than exec-replacing the launcher. A failure to
/// prepare or spawn surfaces a pointed error and yields `1`, matching the supervised path.
fn run_status(bwrap: &Path, spec: &SandboxSpec, limits: &super::cgroup::Limits) -> i32 {
    let (argv, _seccomp) = match seccomp_argv(spec) {
        Ok(v) => v,
        Err(e) => {
            // Not only the filter: this step also builds the descriptor carrying the cage's
            // environment, and naming the wrong one would send a reader looking at `[seccomp]`.
            eprintln!("sbx: cannot prepare the sandbox: {e}");
            return 1;
        }
    };
    // For a graphical isolated cage, route the launch through the netns holder so the namespace
    // carries a `dummy0` interface (see `super::netns`); a no-op `(bwrap, argv)` otherwise.
    let (holder_prog, holder_argv) =
        super::netns::holder_wrap(bwrap, argv, spec.netns_dummy.as_ref());
    let (prog, args) = super::cgroup::wrap(&holder_prog, holder_argv, limits, &spec.cage_slug);
    match Command::new(prog).args(args).status() {
        Ok(status) => status_code(status),
        Err(e) => {
            eprintln!("sbx: failed to launch the sandbox: {e}");
            1
        }
    }
}

/// Fork-and-wait like [`run_status`], but **capture** the cage's stdout and stderr instead of
/// inheriting the terminal, returning `(exit code, combined output)`. Reserved for `sbx upgrade`,
/// where a clean per-app summary is shown on success and the captured output is surfaced only on
/// failure — never on the interactive/detached launch paths, which need live inherited stdio. The
/// two streams are concatenated (stdout then stderr) because mise splits its output across both: a
/// roll's `X → Y` summary goes to stdout, its `up to date` line to stderr.
fn run_captured(bwrap: &Path, spec: &SandboxSpec, limits: &super::cgroup::Limits) -> (i32, String) {
    let (argv, _seccomp) = match seccomp_argv(spec) {
        Ok(v) => v,
        Err(e) => return (1, format!("cannot prepare the sandbox: {e}")),
    };
    // For a graphical isolated cage, route the launch through the netns holder so the namespace
    // carries a `dummy0` interface (see `super::netns`); a no-op `(bwrap, argv)` otherwise.
    let (holder_prog, holder_argv) =
        super::netns::holder_wrap(bwrap, argv, spec.netns_dummy.as_ref());
    let (prog, args) = super::cgroup::wrap(&holder_prog, holder_argv, limits, &spec.cage_slug);
    match Command::new(prog).args(args).output() {
        Ok(out) => {
            let mut combined = String::from_utf8_lossy(&out.stdout).into_owned();
            combined.push_str(&String::from_utf8_lossy(&out.stderr));
            (status_code(out.status), combined)
        }
        Err(e) => (1, format!("failed to launch the sandbox: {e}")),
    }
}

/// The version-transition lines mise prints for a successful roll — `<token> <from> → <to>`, one per
/// upgraded tool — extracted from captured (non-TTY) output. The ` → ` (U+2192, space-padded) marker
/// is unique to these lines; mise's install/download progress and the `mise use -g` equip preamble
/// carry no arrow. Empty when nothing rolled (see [`mise_up_to_date`]). Pure — unit-tested against
/// real mise output.
fn mise_transitions(captured: &str) -> Vec<&str> {
    captured
        .lines()
        .map(str::trim)
        .filter(|l| l.contains(" → "))
        .collect()
}

/// Whether mise reported nothing to do. mise prints `All tools are up to date` (to stderr) when a
/// roll finds every tool already current. Pure — unit-tested against real mise output.
fn mise_up_to_date(captured: &str) -> bool {
    captured.contains("up to date")
}

/// One dot-leader-aligned result line for the `mise:` roll report: the group `name`, a run of dots
/// filling toward `width`, then the caller's already-styled `status`. Pure formatting — the dots
/// carry `width - name` + a 3-dot minimum so even the widest name keeps a small gap.
fn roll_line(name: &str, width: usize, status: &str, pal: &crate::style::Palette) -> String {
    let dots = ".".repeat(width.saturating_sub(name.chars().count()) + 3);
    format!(
        "  {}{name}{} {}{dots}{} {status}",
        pal.name, pal.reset, pal.dim, pal.reset
    )
}

/// The one line that closes the `mise:` roll report and answers "which apps changed?": the rolled
/// groups by name, then a parenthesised tally of the rest. Plain text (the caller colours it by
/// outcome); pure, so it is unit-tested. With nothing rolled and nothing wrong it collapses to a
/// single reassuring line rather than "0 apps rolled".
fn mise_roll_recap(rolled: &[String], up_to_date: usize, skipped: usize, failed: usize) -> String {
    let mut tail = Vec::new();
    if up_to_date > 0 {
        tail.push(format!("{up_to_date} up to date"));
    }
    if skipped > 0 {
        tail.push(format!("{skipped} skipped"));
    }
    if failed > 0 {
        tail.push(format!("{failed} failed"));
    }
    let tally = if tail.is_empty() {
        String::new()
    } else {
        format!(" ({})", tail.join(", "))
    };

    if rolled.is_empty() {
        if !tail.is_empty() && skipped == 0 && failed == 0 {
            format!("all {up_to_date} up to date.")
        } else if tail.is_empty() {
            "nothing to roll.".to_string()
        } else {
            format!("nothing rolled{tally}.")
        }
    } else {
        // No noun: the names are an app's most of the time, but the declared operations' tool pool
        // rolls under this same recap and is not an app. Counting them without naming a kind keeps
        // the line accurate for both rather than mislabelling one.
        format!("{} rolled: {}{tally}.", rolled.len(), rolled.join(", "))
    }
}

/// The bwrap argv with the mandatory seccomp filters prepended. Returns the
/// backing memfds the caller must keep alive until bwrap has read them — they are
/// not close-on-exec, and dropping a `File` early would close the descriptor
/// bwrap is told to read. Seccomp is loaded on every launch path the same way the
/// namespace hardening is emitted unconditionally by `to_argv`.
pub(super) fn seccomp_argv(spec: &SandboxSpec) -> io::Result<(Vec<OsString>, Vec<File>)> {
    let mut memfds = super::seccomp::memfds(&spec.seccomp)?;
    let mut argv = super::seccomp::argv_prefix(&memfds);
    let (spec_argv, env) = super::argv::compose(spec)?;
    argv.extend(spec_argv);
    // The environment's descriptor joins the filters' in the same vector, because they have the same
    // lifetime requirement: bwrap must still be able to read all of them at the exec.
    memfds.extend(env);
    Ok((argv, memfds))
}

/// A process's exit code in the shell convention: its own code, or 128 + the signal that
/// killed it (matching the pty supervisor's `pump`).
pub(super) fn status_code(status: std::process::ExitStatus) -> i32 {
    use std::os::unix::process::ExitStatusExt;
    status
        .code()
        .unwrap_or_else(|| status.signal().map(|s| 128 + s).unwrap_or(1))
}

/// Replace the current process with bubblewrap running `spec`. A successful
/// `exec` never returns, so this returns *only* on failure.
fn exec(bwrap: &Path, spec: &SandboxSpec, limits: &super::cgroup::Limits) -> io::Error {
    // Defense in depth: a private-tty spec relies on a controlling terminal that
    // only the pty supervisor provides. Exec-replace would leave it inheriting
    // the launching terminal, so refuse it here rather than weaken isolation.
    if spec.terminal == TerminalPolicy::PrivateTty {
        return io::Error::other(
            "internal error: a private-tty sandbox must be launched through the pty supervisor",
        );
    }
    let (argv, _seccomp) = match seccomp_argv(spec) {
        Ok(v) => v,
        Err(e) => return e,
    };
    // `_seccomp` stays alive until the exec replaces this process (or, on failure,
    // until this returns), so bwrap can read the inherited filter descriptors.
    // For a graphical isolated cage, route the launch through the netns holder so the namespace
    // carries a `dummy0` interface (see `super::netns`); a no-op `(bwrap, argv)` otherwise.
    let (holder_prog, holder_argv) =
        super::netns::holder_wrap(bwrap, argv, spec.netns_dummy.as_ref());
    let (prog, args) = super::cgroup::wrap(&holder_prog, holder_argv, limits, &spec.cage_slug);
    Command::new(prog).args(args).exec()
}

/// Run `spec` under a pty supervisor and return its exit status code. sbx opens
/// a pty, launches bwrap with the *slave* as its controlling terminal (via
/// `login_tty`), keeps the *master* itself, puts the real terminal in raw mode,
/// and relays bytes both ways until the session ends.
fn supervise(
    bwrap: &Path,
    spec: &SandboxSpec,
    limits: &super::cgroup::Limits,
    gui: bool,
) -> io::Result<i32> {
    // Build the bwrap argv (seccomp prefix + the hardened spec), then wrap it in
    // the resource-limit scope: the program may become `systemd-run` with bwrap
    // spliced in after `--`. Compose as C strings *before* forking — nothing
    // between fork and exec may allocate.
    //
    // The anonymous files behind it — the seccomp filters and the cage's environment — are created
    // here, *before* the fork, so the child inherits their descriptors; the parent holds them alive
    // through `pump` so bwrap can still read them after the exec.
    let (bwrap_argv, _keep_open) = seccomp_argv(spec)?;
    // Route a graphical isolated cage through the netns holder (dummy interface; see `super::netns`);
    // a no-op passthrough otherwise.
    let (holder_prog, holder_argv) =
        super::netns::holder_wrap(bwrap, bwrap_argv, spec.netns_dummy.as_ref());
    let (program, full_argv) =
        super::cgroup::wrap(&holder_prog, holder_argv, limits, &spec.cage_slug);
    let program_c = cstring(program.as_os_str().as_bytes())?;
    let mut argv_owned = vec![program_c.clone()];
    for arg in &full_argv {
        argv_owned.push(cstring(arg.as_bytes())?);
    }
    let mut argv: Vec<*const libc::c_char> = argv_owned.iter().map(|c| c.as_ptr()).collect();
    argv.push(std::ptr::null());

    // Carry the real terminal's window size onto the pty so the inner shell
    // wraps correctly from the start.
    let mut ws: libc::winsize = unsafe { std::mem::zeroed() };
    let winp = if unsafe { libc::ioctl(0, libc::TIOCGWINSZ, &mut ws) } == 0 {
        &ws as *const libc::winsize
    } else {
        std::ptr::null()
    };

    let mut master: libc::c_int = -1;
    let mut slave: libc::c_int = -1;
    // SAFETY: out-params are valid; name/termios are null (defaults), winp is
    // null or a valid winsize.
    if unsafe {
        libc::openpty(
            &mut master,
            &mut slave,
            std::ptr::null_mut(),
            std::ptr::null(),
            winp,
        )
    } != 0
    {
        return Err(io::Error::last_os_error());
    }

    // The master must never reach the sandbox: with it the sandbox could read or
    // inject its own terminal stream. The parent keeps it (and never execs), so
    // close-on-exec is exactly right; `login_tty` handles the slave.
    unsafe {
        let flags = libc::fcntl(master, libc::F_GETFD);
        libc::fcntl(master, libc::F_SETFD, flags | libc::FD_CLOEXEC);
    }

    // SAFETY: between fork and exec the child calls only async-signal-safe
    // functions (`close`, `login_tty`, `execv`, `_exit`); the argv is prebuilt.
    let child = unsafe { libc::fork() };
    if child < 0 {
        let e = io::Error::last_os_error();
        unsafe {
            libc::close(master);
            libc::close(slave);
        }
        return Err(e);
    }
    if child == 0 {
        unsafe {
            libc::close(master);
            // login_tty: setsid + make the slave our controlling terminal +
            // dup it onto stdin/out/err. This is what gives the sandbox a
            // controlling terminal (and thus job control).
            if libc::login_tty(slave) == 0 {
                libc::execv(program_c.as_ptr(), argv.as_ptr());
            }
            // only reached if login_tty or execv failed
            libc::_exit(127);
        }
    }

    // Parent: keep the master, drop the slave, go raw, relay.
    unsafe { libc::close(slave) };
    let _raw = RawMode::enable(0)?;
    // Install the resize relay *after* the fork so the child never inherits the handler. sbx keeps
    // the real controlling terminal (only the child `setsid`'d, via `login_tty`), so it receives
    // `SIGWINCH` from the launching terminal naturally; the handler wakes `pump` to copy the new
    // size onto the pty master. Best effort: if it cannot be installed the session still runs, only
    // without dynamic resize (the startup size is already set by `openpty`).
    let winch = WinchRelay::install().ok();
    if winch.is_some() {
        // Close a resize that raced startup (between `openpty` and now).
        copy_winsize(0, master);
    }
    let winch_fd = winch.as_ref().map_or(-1, WinchRelay::read_fd);
    let status = pump(master, child, winch_fd, gui);
    drop(winch);
    unsafe { libc::close(master) };
    status
}

/// `CString` from raw bytes, mapping an interior NUL to an I/O error.
fn cstring(bytes: &[u8]) -> io::Result<CString> {
    CString::new(bytes).map_err(|_| io::Error::other("argument contains an interior NUL byte"))
}

/// Host variables worth carrying through the cleared environment for a usable
/// session. Secrets are never passed this way. `LANG`/`LC_ALL` carry the host's locale so the
/// cage renders text in the user's language; the base userland builds a matching locale archive
/// (see `fhs::host_locales`), and both upsert over the structural `LANG=C.UTF-8` floor.
fn passthrough_env() -> Vec<(String, String)> {
    keep_passthrough(
        ["TERM", "LANG", "LC_ALL"]
            .iter()
            .filter_map(|k| std::env::var(k).ok().map(|v| ((*k).to_string(), v))),
    )
}

/// Drop a `LANG`/`LC_ALL` whose value is the non-UTF-8 `C`/`POSIX` builtin, so a host that
/// selects it (a developer forcing deterministic tooling on the host) cannot override the cage's
/// structural `LANG=C.UTF-8` floor and byte-escape accented text — almost never the intent inside
/// an agent cage, and a config `[env]` remains the explicit escape hatch. Every other value — a
/// real locale, or `C.UTF-8` itself — is kept and upserts over the floor; `TERM` and any
/// non-locale key pass unconditionally. Pure, so the rule is unit-tested without the environment.
fn keep_passthrough(vars: impl IntoIterator<Item = (String, String)>) -> Vec<(String, String)> {
    vars.into_iter()
        .filter(|(k, v)| {
            !matches!(k.as_str(), "LANG" | "LC_ALL")
                || (!v.eq_ignore_ascii_case("C") && !v.eq_ignore_ascii_case("POSIX"))
        })
        .collect()
}

/// Where a command wrap sits in the nesting a launch builds around the cage's command, innermost
/// first.
///
/// Every wrap prepends a preamble that starts something inside the cage and then `exec`s what it
/// wraps, so the **last** one applied is the outermost and its preamble runs **first**. The
/// constraints the wraps have on each other are pairwise (a forwarder up before the fetch that needs
/// it, a CA imported after the proxy whose CA it is), and each variant below carries the one it is
/// subject to. Ordering by this enum is what keeps those constraints from depending on where in
/// [`build`] each block happens to sit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum WrapLayer {
    /// The exec-enforcement shim. Innermost, so it filters the agent command and its children and
    /// not the provisioning and egress plumbing wrapped around it.
    ProcEnforce,
    /// A mise equip lane. Both lanes fetch, so they sit inside the egress wrap: under an allowlist
    /// the forwarder is up before either install runs.
    MiseEquip,
    /// The inline `[flakes.<name>]` build. Fetches its inputs, so it sits inside the egress wrap for
    /// the same reason as [`WrapLayer::MiseEquip`].
    FlakeEquip,
    /// The loopback forwarders. Inside the egress wrap, so under an allowlist both forwarders are up
    /// before the command runs.
    Forward,
    /// The egress forwarder.
    Egress,
    /// The MITM CA's import into the cage's NSS db, for a Chromium/Electron app that ignores the
    /// CA-file environment. Outside the egress wrap, since it is that proxy's per-session CA it
    /// imports.
    CaTrust,
    /// The in-cage portal's private session bus. Outermost, so `dbus-daemon --fork` — which blocks
    /// until its socket is ready — has finished before anything else in the cage starts.
    Portal,
}

/// One contributed wrap: it takes the command built so far and returns it wrapped.
type CommandWrap<'a> = Box<dyn FnOnce(Vec<OsString>) -> Vec<OsString> + 'a>;

/// Nest the wraps a launch contributed around `cmd`, innermost [`WrapLayer`] first.
///
/// The caller registers them wherever its blocks happen to run; the nesting is this function's, not
/// the caller's. The sort is stable, so two wraps of the same layer — the two mise equip lanes —
/// nest in the order they were registered.
fn wrap_cage_command(
    cmd: Vec<OsString>,
    mut wraps: Vec<(WrapLayer, CommandWrap<'_>)>,
) -> Vec<OsString> {
    wraps.sort_by_key(|(layer, _)| *layer);
    wraps.into_iter().fold(cmd, |cmd, (_, wrap)| wrap(cmd))
}

/// Where a source of cage environment sits in the precedence order, lowest first. The assembler
/// upserts these over the structural defaults and takes the last occurrence of a key, so a later
/// variant wins.
///
/// The order lives in this declaration rather than in the order a caller happens to list its
/// layers. Every layer is a `Vec<(String, String)>`, so two of them swapped at a call site would
/// compile in silence and change which CA the cage trusts; sorting by this enum makes the
/// precedence a property of one documented place instead of a property of an argument list.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum EnvLayer {
    /// The host variables carried through unchanged. Lowest on purpose: passthrough is a separate
    /// channel, not filtered by the untrusted-config denylist, so a host CA variable must not be
    /// able to clobber sbx's hermetic bundle.
    Passthrough,
    /// sbx's hermetic CA bundle.
    Cacert,
    /// The Wayland GUI hole. Its keys (`WAYLAND_DISPLAY`/`XDG_RUNTIME_DIR`) collide with nothing
    /// else, so the position is immaterial; it sits here to keep one documented order.
    Gui,
    /// The non-`nix:` auto-equip variable.
    AutoEquip,
    /// A trusted project's mise `[env]`.
    Mise,
    /// The egress machinery: the proxy variables and the per-session MITM CA, which must beat
    /// [`EnvLayer::Cacert`] so a cage under an allowlist trusts the proxy standing in for its
    /// servers.
    Egress,
    /// The ssh-agent broker's socket.
    SshAgent,
    /// A broker plugin's socket, under whichever names its manifest declared. Beside the
    /// first-party broker above, and after it: the two never name the same variable, since a
    /// manifest cannot claim a reserved key and `SSH_AUTH_SOCK` is sbx's to set.
    Broker,
    /// The task plane's discovery handles.
    Task,
    /// The `.sbx.toml` `[env]`: the sbx-native config has the final say. An untrusted one has
    /// already lost its reserved keys upstream, so overriding here is self-harm only.
    Config,
}

/// The install steps as one `&&` chain, without the app's command.
///
/// Each step is itself an argv, rendered through `shell_quote` so a step's own arguments survive
/// the shell that chains them: an argument holding a space, a quote or a `$` is data, and a shell
/// that re-parsed it would read it as syntax. `&&` carries the same fail-closed rule in both
/// callers — a step that exits non-zero stops the chain.
fn provision_chain(provisions: &[crate::config::BundleProvision]) -> String {
    provisions
        .iter()
        .map(|step| {
            step.argv
                .iter()
                .map(|a| shell_quote(a))
                .collect::<Vec<_>>()
                .join(" ")
        })
        .collect::<Vec<_>>()
        .join(" && ")
}

/// Where a service's output goes, inside the cage's own home: `~/.sbx-service-<name>.log`.
///
/// A service outlives the call that started it and shares the terminal with the app, so its output
/// cannot stay there — a chatty daemon would bury the app's own. The file is never rotated; it is
/// the first place to look when an app starts but the thing beside it never answers.
fn service_log_path(name: &str) -> String {
    format!("\"${{HOME:-/tmp}}\"/.sbx-service-{name}.log")
}

/// Render one argv element for the start-up script, expanding a leading `~/` against the cage's home.
///
/// The expansion is the one substitution a service's argv gets, and it exists because a service is
/// declared where the home's path is not knowable — `~/chroma-data` is the only way to name a
/// directory under a home whose location sbx chooses. Everything else is quoted verbatim: a `$VAR`
/// stays four characters, because the argv is data and a shell that re-read it would find syntax.
fn service_arg(arg: &str) -> String {
    match arg.strip_prefix("~/") {
        Some(rest) => format!("\"${{HOME}}\"/{}", shell_quote(rest)),
        None => shell_quote(arg),
    }
}

/// The start-up script's lines for one service: the launch, and the readiness wait.
///
/// The launch is a subshell redirected to the service's log and backgrounded — the same shape the
/// hand-written `nohup … &` had, and for the same reason (the cage ships no `setsid`). It is not
/// supervised: if it dies, it stays dead, and the app is not told. What the readiness gate buys is
/// only that the app does not *race* it.
///
/// A service whose `enable` condition does not hold never reaches here: it is left out of the script
/// entirely, decided against the environment the launch composed rather than by a shell test in the
/// cage. See [`compose_startup_cmd`].
fn service_lines(name: &str, svc: &crate::config::ServiceSpec) -> String {
    let mut out = String::new();
    let argv = svc
        .argv
        .iter()
        .map(|a| service_arg(a))
        .collect::<Vec<_>>()
        .join(" ");
    let log = service_log_path(name);
    out.push_str(&format!("( {argv} ) >>{log} 2>&1 </dev/null &\n"));
    if let Some(ready) = svc.ready {
        // A tenth-of-the-budget poll on bash's own `/dev/tcp`, so the wait needs no tool the base
        // userland might not carry. The connection is opened in a subshell and dropped immediately:
        // the question is whether anything accepts, and a fd left open in the launch would outlive
        // the answer. On expiry the launch goes on — a gate that failed here would turn a slow
        // auxiliary process into a broken app, which is the outcome it exists to avoid.
        let attempts = ready.timeout.as_millis().div_ceil(500).max(1);
        let port = ready.tcp;
        out.push_str(&format!(
            "sbx_ready=0\n\
             for _ in $(seq 1 {attempts}); do\n\
             \x20 if ( exec 3<>/dev/tcp/127.0.0.1/{port} ) 2>/dev/null; then sbx_ready=1; break; fi\n\
             \x20 sleep 0.5\n\
             done\n\
             if [ \"$sbx_ready\" != 1 ]; then\n\
             \x20 echo \"sbx: service {name} did not answer on port {port} within {}s — starting anyway; see {log}\" >&2\n\
             fi\n",
            ready.timeout.as_secs().max(1)
        ));
    }
    out
}

/// Compose the cage's whole start-up ahead of the command it was launched to run: the app's install
/// steps, then its services, then the command itself.
///
/// One script rather than nested wrappers, because the order is the point and nesting decides it by
/// accident: an install that puts a program on `PATH` must run before a service that starts it. The
/// install chain keeps its fail-closed `&&` — a step that exits non-zero stops everything, so no
/// service and no command runs after a broken install. The services do not: one that fails to start
/// is a degraded app, not a failed launch, which is the trade every hand-written `nohup` here
/// already made.
///
/// The command's argv is passed as positional parameters rather than pasted in: an element holding a
/// quote, a space or a `$` is data, and a shell that re-parsed it would read it as syntax.
///
/// A service's `enable` condition is answered **here**, against `env` — the environment this launch
/// composed for the cage — and a service that fails it is simply not written into the script. sbx
/// builds that environment itself, from a cleared one, so the answer is knowable at the moment the
/// script is written; emitting a shell `if` instead would push a decision sbx has already made into
/// a language the field is not.
fn compose_startup_cmd(
    provisions: &[crate::config::BundleProvision],
    services: &std::collections::BTreeMap<String, crate::config::ServiceSpec>,
    env: &[(String, String)],
    cmd: Vec<OsString>,
) -> Vec<OsString> {
    let mut script = String::new();
    if !provisions.is_empty() {
        script.push_str(&provision_chain(provisions));
        script.push_str(" || exit $?\n");
    }
    for (name, svc) in services {
        if svc.enable.iter().all(|cond| cond.holds(env)) {
            script.push_str(&service_lines(name, svc));
        }
    }
    script.push_str("exec \"$@\"\n");
    let mut out: Vec<OsString> = vec![
        OsString::from("bash"),
        OsString::from("-c"),
        OsString::from(script),
        // `$0` for the composed script; the command's argv follows as `$1 …`.
        OsString::from("sbx"),
    ];
    out.extend(cmd);
    out
}

/// The install steps alone, as a cage command — what `sbx upgrade provision` runs.
///
/// The same chain the launch composes, minus the `exec "$@"` tail: the point of an upgrade run is
/// the install, and running the agent afterwards would turn a version roll into a launch. The steps
/// see the app's own cage (its home, packages, egress and environment), so what they install is
/// what the next launch finds; `SBX_UPGRADE` is what tells them to re-install rather than honor
/// their own "already installed" guard, and it is set by the caller, not here.
fn provision_only_cmd(provisions: &[crate::config::BundleProvision]) -> Vec<OsString> {
    vec![
        OsString::from("bash"),
        OsString::from("-c"),
        OsString::from(provision_chain(provisions)),
        // `$0` — a label; the chain takes no positional arguments.
        OsString::from("sbx-provision"),
    ]
}

/// Quote one argv element for the shell that chains the install steps: single quotes, with an
/// embedded single quote closed and re-opened around an escaped one.
fn shell_quote(arg: &str) -> String {
    format!("'{}'", arg.replace('\'', "'\\''"))
}

/// Layer the cage's extra environment by [`EnvLayer`] precedence, lowest first.
///
/// The caller may list its layers in any order — they are sorted here. Two entries carrying the
/// same layer keep the order they were given, since the sort is stable.
fn extra_cage_env(mut layers: Vec<(EnvLayer, Vec<(String, String)>)>) -> Vec<(String, String)> {
    layers.sort_by_key(|(layer, _)| *layer);
    layers.into_iter().flat_map(|(_, env)| env).collect()
}

fn missing(what: &str) -> ExitCode {
    crate::diag::error(&format!(
        "sbx: {what} not found — the sandbox cannot run. See `sbx doctor`."
    ));
    ExitCode::FAILURE
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::Origin;
    use crate::testutil::TmpDir;
    use std::path::PathBuf;

    /// The zone a cage ends up in, held against a database that really is on disk.
    ///
    /// The config layer already refused the shapes that are not zone names; what only this side can
    /// decide is whether the database *carries* the zone, so the cases here are the ones that turn
    /// on a file existing.
    #[test]
    fn a_zone_the_database_does_not_carry_falls_back_to_the_default() {
        // The database sits one level inside the fixture, so the traversal case below resolves to a
        // sibling the fixture owns rather than to a name outside the tree this test may write.
        let base = TmpDir::new();
        let db = base.path().join("zoneinfo");
        std::fs::create_dir_all(db.join("Europe")).unwrap();
        std::fs::write(db.join("Europe/Paris"), b"TZif").unwrap();
        std::fs::write(db.join("UTC"), b"TZif").unwrap();

        // Nothing declared: the built-in zone, which is a zone and not an absence.
        assert_eq!(cage_timezone(None, &db), "UTC");
        // Declared and present: taken.
        assert_eq!(cage_timezone(Some("Europe/Paris"), &db), "Europe/Paris");
        // Declared and absent: the default, not a refused launch — a misspelled zone costs a wrong
        // clock, never the session.
        assert_eq!(cage_timezone(Some("Europe/Pariss"), &db), "UTC");
        // A directory inside the database is not a zone: `Europe` resolves to something that
        // exists, so only the is-a-file test tells the two apart.
        assert_eq!(cage_timezone(Some("Europe"), &db), "UTC");
        // The shape rule is applied here too, at the join site: a traversal that would otherwise
        // resolve to a real file outside the database never becomes a link target.
        std::fs::write(base.path().join("escaped"), b"x").unwrap();
        assert_eq!(cage_timezone(Some("../escaped"), &db), "UTC");
        // And a database that is not there at all still yields a launchable cage.
        assert_eq!(
            cage_timezone(Some("Europe/Paris"), Path::new("/nonexistent-zoneinfo")),
            "UTC"
        );
    }

    /// Which of the two ways to name a zone decides the link. The property under test is not a
    /// precedence preference, it is that **one** value drives both halves: `TZ` is what the cage's
    /// clock will read, so the link has to follow it or the two answer differently with no error.
    #[test]
    fn the_link_follows_whatever_tz_will_finally_read() {
        let env = |pairs: &[(&str, &str)]| -> Vec<(String, String)> {
            pairs
                .iter()
                .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
                .collect()
        };

        // Neither: nothing is declared, and the caller falls back to the built-in zone.
        assert_eq!(declared_zone(&env(&[("LANG", "C.UTF-8")]), None), None);
        // The field alone.
        assert_eq!(
            declared_zone(&env(&[]), Some("Europe/Paris")),
            Some("Europe/Paris")
        );
        // `TZ` alone — the case that used to move the clock and leave the link behind.
        assert_eq!(
            declared_zone(&env(&[("TZ", "Asia/Tokyo")]), None),
            Some("Asia/Tokyo")
        );
        // Both, disagreeing: `TZ` wins, because `TZ` is what the cage will actually read.
        assert_eq!(
            declared_zone(&env(&[("TZ", "Asia/Tokyo")]), Some("Europe/Paris")),
            Some("Asia/Tokyo")
        );
        // Two layers both setting it: the later one wins, exactly as the assembler's upsert does.
        assert_eq!(
            declared_zone(&env(&[("TZ", "Asia/Tokyo"), ("TZ", "UTC")]), None),
            Some("UTC")
        );
    }

    /// Which argv shapes take an `$0` filler before the caller's `-- <args>` are appended, and
    /// which must be left exactly as the profile wrote them.
    ///
    /// Every case is a literal argv, never one assembled by the code under test: the whole point
    /// is to pin the shape from the outside, so a detector that drifts has nothing to agree with.
    #[test]
    fn only_a_trailing_shell_script_takes_an_argv0_filler() {
        let argv = |v: &[&str]| -> Vec<OsString> { v.iter().map(OsString::from).collect() };

        // The shape that eats an argument: the script is the last element, so whatever follows
        // becomes the shell's `$0`.
        assert!(ends_with_shell_payload(&argv(&["bash", "-c", "exec foo"])));
        // Combined short flags still end in `c`, so the script still follows.
        assert!(ends_with_shell_payload(&argv(&["bash", "-lc", "exec foo"])));
        assert!(ends_with_shell_payload(&argv(&["sh", "-euc", "exec foo"])));
        // The shell is matched on its file name, so an absolute path counts.
        assert!(ends_with_shell_payload(&argv(&[
            "/bin/dash",
            "-c",
            "exec foo"
        ])));
        assert!(ends_with_shell_payload(&argv(&["zsh", "-c", "exec foo"])));
        // A leading wrapper does not hide the shape — only the last three elements decide.
        assert!(ends_with_shell_payload(&argv(&[
            "env", "-i", "bash", "-c", "exec foo"
        ])));

        // Already carries its own `$0`: the profile said which name its script reports, and the
        // append lands on `$1` unaided. Touching this would rename the script.
        assert!(!ends_with_shell_payload(&argv(&[
            "bash", "-c", "exec foo", "foo"
        ])));
        // A plain argv: the appended arguments are the program's own, with nothing to shift.
        assert!(!ends_with_shell_payload(&argv(&["foo", "--flag", "value"])));
        // Not a shell whose `-c` binds `$0` this way.
        assert!(!ends_with_shell_payload(&argv(&[
            "python3", "-c", "print(1)"
        ])));
        // A flag that does not end in `c` does not make the next element a script.
        assert!(!ends_with_shell_payload(&argv(&["bash", "-i", "exec foo"])));
        assert!(!ends_with_shell_payload(&argv(&[
            "bash", "-ci", "exec foo"
        ])));
        // Too short to carry the shape at all — must not panic on the slice.
        assert!(!ends_with_shell_payload(&argv(&["bash", "-c"])));
        assert!(!ends_with_shell_payload(&argv(&["foo"])));
        assert!(!ends_with_shell_payload(&argv(&[])));
    }

    const REV: &str = "9ae611a455b90cf061d8f332b977e387bda8e1ca";

    /// `--observe` is accepted on every launch, but its inline feed is emitted on one path only.
    /// Every launch that takes the feed away has to say so, because a flag that prints nothing and
    /// streams nothing is indistinguishable from one that worked.
    ///
    /// The enforcing case is the one this was written for: it is not one mode but three, and a check
    /// that named `enforce` alone would leave `ask` and `confine` silently featureless. The pairing
    /// with [`observation_flags`] is asserted rather than assumed — the warning has to fire exactly
    /// when the poller that feeds the stream is off, or the two drift apart.
    #[test]
    fn a_launch_that_cannot_show_the_observe_feed_says_so() {
        use crate::proc_policy::{ProcMode, ProcPolicy};

        let with = |mode| ProcPolicy {
            mode,
            ..ProcPolicy::default()
        };

        // The path the feed rides: asked for, no terminal to fight, a mode that leaves the poller on.
        for mode in [ProcMode::Off, ProcMode::Observe] {
            let policy = with(mode);
            assert_eq!(
                observe_feed_absent_reason(true, false, &policy),
                None,
                "{mode:?}: the feed is emitted here, so there is nothing to warn about"
            );
            assert!(
                observation_flags(&policy, true).0,
                "{mode:?}: and the poller that feeds it is on"
            );
        }

        // Every enforcing mode, not just the obvious one.
        for mode in [ProcMode::Enforce, ProcMode::Ask, ProcMode::Confine] {
            let policy = with(mode);
            let reason = observe_feed_absent_reason(true, false, &policy)
                .unwrap_or_else(|| panic!("{mode:?}: no feed and no warning is the silent case"));
            assert!(
                reason.contains("seccomp lens"),
                "{mode:?}: the reason names where the events are instead: {reason}"
            );
            assert!(
                !observation_flags(&policy, true).0,
                "{mode:?}: the warning fires exactly when the poller is off"
            );
        }

        // A terminal takes the inline feed away too, and keeps its own reason.
        let interactive = observe_feed_absent_reason(true, true, &with(ProcMode::Observe))
            .expect("an interactive terminal has no inline feed either");
        assert!(interactive.contains("interactive terminal"));

        // Enforcement is named first: it is the reason that holds whether or not there is a
        // terminal, and the one a reader would otherwise not guess.
        assert_eq!(
            observe_feed_absent_reason(true, true, &with(ProcMode::Enforce)),
            observe_feed_absent_reason(true, false, &with(ProcMode::Enforce))
        );

        // And nothing is said to a launch that never asked.
        for mode in [ProcMode::Off, ProcMode::Observe, ProcMode::Enforce] {
            assert_eq!(observe_feed_absent_reason(false, true, &with(mode)), None);
        }
    }

    /// Nothing a cage's environment carries may reach bubblewrap's **argument list**:
    /// `/proc/<pid>/cmdline` is mode `444`, so every uid on the machine could read it for as long as
    /// the cage runs, while `/proc/<pid>/environ` is `400`. Measured on a live invocation before
    /// this existed — the sentinel was sitting there next to `--setenv`.
    ///
    /// This asserts on the production function, so the property holds for whatever a spec is built
    /// from rather than for one hand-written argv.
    #[test]
    fn no_variable_reaches_the_world_readable_argument_list() {
        use std::io::Read;
        const SENTINEL: &str = "s3nt1nel-v4lue-xyz";
        const WRITTEN: &str = "hardcoded-in-a-config";

        let spec = SandboxSpec::new(
            PathBuf::from("/w"),
            Vec::new(),
            vec![
                ("PATH".to_string(), "/bin".to_string()),
                ("API_TOKEN".to_string(), WRITTEN.to_string()),
            ],
            NetPolicy::Isolated,
            vec![OsString::from("/bin/true")],
        )
        .expect("spec")
        .with_secret_env(vec![("PGPASSWORD".to_string(), SENTINEL.to_string())]);

        let (argv, files) = seccomp_argv(&spec).expect("argv");
        let flat: Vec<String> = argv
            .iter()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        for hidden in [SENTINEL, WRITTEN] {
            assert!(
                !flat.iter().any(|a| a.contains(hidden)),
                "no value may be in the argument list: {flat:?}"
            );
        }
        for name in ["PGPASSWORD", "API_TOKEN"] {
            assert!(
                !flat.iter().any(|a| a == name),
                "nor a name, which would say which variable to go and read: {flat:?}"
            );
        }
        assert!(
            !flat.iter().any(|a| a == "--setenv"),
            "the whole environment travels on the descriptor: {flat:?}"
        );

        // It reaches bwrap on a descriptor instead, spliced where the placeholder was — after
        // `--clearenv`, which would otherwise wipe everything it sets.
        let at = flat.iter().position(|a| a == "--args").expect("--args");
        let fd: i32 = flat[at + 1]
            .parse()
            .expect("a descriptor number, not the placeholder");
        assert!(
            flat.iter()
                .position(|a| a == "--clearenv")
                .expect("--clearenv")
                < at,
            "spliced before the clear, its variables would be wiped: {flat:?}"
        );

        let mut carried = String::new();
        files
            .iter()
            .find(|f| f.as_raw_fd() == fd)
            .expect("the descriptor the argv names is one of the files kept alive")
            .try_clone()
            .expect("clone")
            .read_to_string(&mut carried)
            .expect("read");
        // Credentials first, so a variable named after the cage's own plumbing wins over one that
        // took its name. bwrap reads NUL-separated arguments.
        assert_eq!(
            carried,
            format!(
                "--setenv\0PGPASSWORD\0{SENTINEL}\0--setenv\0PATH\0/bin\0--setenv\0API_TOKEN\0{WRITTEN}\0"
            )
        );
    }

    /// A cage that sets no variables at all gains no descriptor — an unused mechanism leaves no
    /// trace to explain.
    #[test]
    fn a_spec_with_no_environment_gains_no_descriptor() {
        let spec = SandboxSpec::new(
            PathBuf::from("/w"),
            Vec::new(),
            Vec::new(),
            NetPolicy::Isolated,
            vec![OsString::from("/bin/true")],
        )
        .expect("spec");
        let (argv, _files) = seccomp_argv(&spec).expect("argv");
        assert!(
            !argv.iter().any(|a| a == "--args"),
            "an unused mechanism must leave no trace in the argv"
        );
    }

    #[test]
    fn establish_control_plane_pins_creates_each_pin_and_preserves_its_mode() {
        // A pin's host path is created (so a not-yet-existent control-plane root is present to be
        // frozen) and turned into a same-path extra bind that carries the pin's mode: a read-write
        // intermediate, a read-only leaf.
        let tmp = TmpDir::new();
        let inter = tmp.path().join("chain/intermediate");
        let leaf = tmp.path().join("chain/intermediate/root");
        let pins = vec![
            crate::config::Bind {
                path: inter.clone(),
                writable: true,
            },
            crate::config::Bind {
                path: leaf.clone(),
                writable: false,
            },
        ];
        let binds = establish_control_plane_pins(&pins).expect("pins establish");
        assert!(inter.is_dir() && leaf.is_dir(), "each pin path is created");
        assert_eq!(binds.len(), 2);
        assert_eq!(binds[0].src, inter);
        assert_eq!(binds[0].dest, inter);
        assert!(binds[0].writable, "the intermediate is read-write");
        assert_eq!(binds[1].dest, leaf);
        assert!(!binds[1].writable, "the leaf is read-only");
    }

    #[test]
    fn establish_control_plane_pins_fails_closed_when_a_pin_cannot_be_created() {
        // If a pin's path cannot be established (here a file sits where a parent directory must be),
        // the helper errors rather than returning a partial set — so the launch aborts instead of
        // running with the containing read-write bind left unprotected. The failure names the path.
        let tmp = TmpDir::new();
        let blocker = tmp.path().join("blocker");
        std::fs::write(&blocker, b"a file, not a directory").unwrap();
        let pins = vec![crate::config::Bind {
            // Under a regular file, so `create_dir_all` cannot succeed.
            path: blocker.join("root"),
            writable: false,
        }];
        let err = establish_control_plane_pins(&pins).expect_err("a blocked pin must fail closed");
        assert!(
            err.to_string().contains("blocker"),
            "the failure names the unestablishable path: {err}"
        );
    }

    #[test]
    fn mise_transitions_extracts_the_version_rolls_from_captured_output() {
        // The exact shape a captured (non-TTY) `mise upgrade` produces: the `X → Y` summary goes to
        // stdout under an "Upgraded N tool:" header, the install/uninstall progress to stderr — this
        // fixture concatenates both, as `run_captured` does. Only the transition line is surfaced.
        let captured = "\
\nUpgraded 1 tool:\n  shfmt 3.7.0 → 3.13.1\n\
mise shfmt@3.13.1    [1/2] install\n\
mise shfmt@3.13.1  ✓ installed\n\
mise uninstall shfmt@3.7.0 ✓ done\n";
        assert_eq!(mise_transitions(captured), vec!["shfmt 3.7.0 → 3.13.1"]);

        // A group that rolls several tokens surfaces one transition line each; the full-token form
        // (as an `aqua:`/`pipx:` roll prints) is kept verbatim.
        let multi = "\
Upgraded 2 tools:\n  aqua:example/demo-tool 0.144.4 → 0.144.5\n  pipx:demo-agent 2.20.0 → 2.21.0\n";
        assert_eq!(
            mise_transitions(multi),
            vec![
                "aqua:example/demo-tool 0.144.4 → 0.144.5",
                "pipx:demo-agent 2.20.0 → 2.21.0"
            ]
        );

        // No roll (the progress/equip preamble carries no ` → `) → nothing surfaced, so the caller
        // falls through to the up-to-date / generic branch.
        let none = "mise ~/.config/mise/config.toml tools: npm:demo-tool@3.0.40\nadded 3 packages in 617ms\n";
        assert!(mise_transitions(none).is_empty());
    }

    #[test]
    fn mise_up_to_date_detects_the_no_op_roll() {
        // mise prints this to stderr when a roll finds every tool already current.
        assert!(mise_up_to_date("mise All tools are up to date\n"));
        assert!(!mise_up_to_date(
            "Upgraded 1 tool:\n  shfmt 3.7.0 → 3.13.1\n"
        ));
    }

    #[test]
    fn mise_roll_recap_names_what_rolled_and_tallies_the_rest() {
        // The headline case: two advanced out of many — the recap names them and tallies the
        // untouched majority, so "what is concerned?" reads at a glance. No noun on the count: the
        // names are usually apps, but the task tool pool rolls under this same recap and is not one.
        assert_eq!(
            mise_roll_recap(&["demo-app".into(), "other-app".into()], 15, 0, 0),
            "2 rolled: demo-app, other-app (15 up to date)."
        );
        // Nothing advanced, everything current — collapse to one reassuring line, not "0 rolled".
        assert_eq!(mise_roll_recap(&[], 17, 0, 0), "all 17 up to date.");
        // A mixed tally (skips + failures) still surfaces.
        assert_eq!(
            mise_roll_recap(&["demo-app".into()], 0, 1, 2),
            "1 rolled: demo-app (1 skipped, 2 failed)."
        );
        // Nothing rolled but not a clean no-op — say what got in the way.
        assert_eq!(
            mise_roll_recap(&[], 10, 2, 1),
            "nothing rolled (10 up to date, 2 skipped, 1 failed)."
        );
        // Degenerate empty run (no groups reached the loop).
        assert_eq!(mise_roll_recap(&[], 0, 0, 0), "nothing to roll.");
    }

    #[test]
    fn session_runtime_maps_each_launch_runtime_to_its_owned_form() {
        // The owned record runtime `sbx session attach` reads back must mirror the launch-side runtime, so
        // an app session is reproduced in the app's home rather than the project's default.
        assert_eq!(
            session_runtime(binds::Runtime::ProjectDefault),
            session::SessionRuntime::Project
        );
        assert_eq!(
            session_runtime(binds::Runtime::GlobalApp("demo-app")),
            session::SessionRuntime::GlobalApp("demo-app".to_string())
        );
        assert_eq!(
            session_runtime(binds::Runtime::ProjectApp("agent")),
            session::SessionRuntime::ProjectApp("agent".to_string())
        );
    }

    #[test]
    fn session_verb_confirmations_are_plain_text_when_uncolored() {
        // A plain palette must leave every confirmation byte-for-byte plain, so a captured stream
        // (and the existing `sbx session stop --all` substring assertion) stays unchanged.
        let p = crate::style::Palette::plain();
        let grace = Duration::from_secs(10);
        assert_eq!(
            render_attaching(4242, "app:demo-app", &p),
            "sbx: attaching to session 4242 (app:demo-app) \
             (a shell in its live cage — type `exit` to leave the agent running)"
        );
        assert_eq!(
            render_no_active_sessions(&p),
            "sbx session stop: no active sessions to stop."
        );
        assert_eq!(
            render_gui_stop_hint("demo-app", 4242, &p),
            "sbx: demo-app is graphical — press Ctrl+C twice here to quit (closing its window may only \
             hide it — a tray app keeps running); `sbx session stop 4242` also stops it."
        );
        assert_eq!(
            render_stop_outcome(4242, "run", &session::StopOutcome::Terminated, grace, &p),
            "sbx session stop: stopped session 4242 (run)."
        );
        assert_eq!(
            render_stop_outcome(
                7,
                "app:agent",
                &session::StopOutcome::AlreadyGone,
                grace,
                &p
            ),
            "sbx session stop: session 7 (app:agent) had already exited."
        );
        assert_eq!(
            render_stop_outcome(9, "shell", &session::StopOutcome::Killed, grace, &p),
            "sbx session stop: session 9 (shell) did not exit within 10s — sent SIGKILL."
        );
        // A refused handle must not read like the no-op above: it names the reason and says the
        // session may still be running, because nothing was signalled.
        assert_eq!(
            render_stop_outcome(
                11,
                "app:agent",
                &session::StopOutcome::NotSignalled(libc::EINVAL),
                grace,
                &p
            ),
            "sbx session stop: cannot stop session 11 (app:agent): Invalid argument (os error 22) \
             — it was not signalled and may still be running."
        );
    }

    #[test]
    fn a_stop_that_left_something_running_outranks_an_id_that_matched_nothing() {
        // Nothing wrong is a plain success; an id that named no live session is the long-standing
        // 2; a session the host refused a handle on is 1 — and when both happened in one run it is
        // still 1, because a cage that may still be up is what the caller has to act on.
        assert_eq!(stop_exit_code(false, false), 0);
        assert_eq!(stop_exit_code(false, true), 2);
        assert_eq!(stop_exit_code(true, false), 1);
        assert_eq!(stop_exit_code(true, true), 1);
    }

    #[test]
    fn a_stop_that_signalled_nothing_keeps_the_session_record() {
        // The reap is what makes `sbx session ls` clean the moment a stop lands. Applied to a stop
        // that did *not* land, it would delete the only handle on a cage that is still up: the
        // session would vanish from every listing and no second `sbx session stop <pid>` could
        // name it. So the record survives exactly one outcome, and this test is the contrast —
        // same call, same registry, two records that differ only in why their pid has no handle.
        let data = TmpDir::new();
        let reg = session::Registry::at(data.path());
        let pal = crate::style::Palette::plain();
        let sessions = data.path().join("sessions");
        let record_at = |pid: u32| session::Session {
            project: PathBuf::from("/work/probe"),
            pid,
            start_ticks: 1,
            kind: session::Kind::Run,
            runtime: session::SessionRuntime::Project,
            detached: false,
        };
        let count = || {
            std::fs::read_dir(&sessions)
                .map(|d| d.filter_map(Result::ok).count())
                .unwrap_or(0)
        };

        // Pid 0 is not a pid a process can hold: `pidfd_open` refuses it with `EINVAL`, which says
        // nothing about a process being alive — the stop reports it and keeps the record.
        let refused = record_at(0);
        reg.register(&refused).unwrap();
        assert!(!stop_session(&reg, &refused, Duration::from_secs(0), &pal));
        assert_eq!(count(), 1, "an unsignalled session must stay addressable");

        // A pid above the kernel's ceiling cannot exist, so the same call answers `ESRCH` — truly
        // gone — and the record goes with it.
        let gone = record_at(1 << 30);
        reg.register(&gone).unwrap();
        assert!(stop_session(&reg, &gone, Duration::from_secs(0), &pal));
        assert_eq!(count(), 1, "only the unsignalled record is left");
    }

    #[test]
    fn launch_display_name_prefers_the_app_then_the_program_basename() {
        // An `sbx app` launch names the app; a plain `sbx run` into a GUI project names the
        // program by its basename (never a store path); an empty command falls back cleanly.
        assert_eq!(
            launch_display_name(&binds::Runtime::GlobalApp("demo-app"), &[]),
            "demo-app"
        );
        assert_eq!(
            launch_display_name(&binds::Runtime::ProjectApp("agent"), &[]),
            "agent"
        );
        let cmd = vec![
            OsString::from("/nix/store/abc-foo/bin/foo"),
            OsString::from("--flag"),
        ];
        assert_eq!(
            launch_display_name(&binds::Runtime::ProjectDefault, &cmd),
            "foo"
        );
        assert_eq!(
            launch_display_name(&binds::Runtime::ProjectDefault, &[]),
            "the app"
        );
    }

    #[test]
    fn session_verb_confirmations_color_their_outcome_and_identifier_spans() {
        // The hue carries the meaning: a clean stop is a real change (green), a forced kill is the
        // caution hue (yellow), a stop that could not happen is the error hue (red), a no-op is
        // dim, and an identifier is cyan. The verb of an attach announcement stays plain (it is not
        // a completed state change).
        let p = crate::style::Palette::colored();
        let grace = Duration::from_secs(10);

        let stopped =
            render_stop_outcome(4242, "run", &session::StopOutcome::Terminated, grace, &p);
        assert!(stopped.contains(&format!("{}stopped{}", p.ok, p.reset)));
        assert!(stopped.contains(&format!("{}4242{}", p.name, p.reset)));

        let gone = render_stop_outcome(
            7,
            "app:agent",
            &session::StopOutcome::AlreadyGone,
            grace,
            &p,
        );
        assert!(gone.contains(&format!("{}had already exited{}", p.dim, p.reset)));

        let killed = render_stop_outcome(9, "shell", &session::StopOutcome::Killed, grace, &p);
        assert!(killed.contains(&format!("{}sent SIGKILL{}", p.warn, p.reset)));

        let refused = render_stop_outcome(
            11,
            "app:agent",
            &session::StopOutcome::NotSignalled(libc::EMFILE),
            grace,
            &p,
        );
        assert!(refused.contains(&format!("{}cannot stop{}", p.err, p.reset)));
        // Not the dim of a no-op: this one did not happen, it is not a state that was already
        // reached.
        assert!(!refused.contains(&format!("{}cannot stop", p.dim)));

        let attach = render_attaching(4242, "app:demo-app", &p);
        assert!(attach.contains(&format!("{}4242{}", p.name, p.reset)));
        assert!(attach.contains(&format!("{}app:demo-app{}", p.name, p.reset)));
        // The announcement verb is not green — only a completed change earns that.
        assert!(!attach.contains(&format!("{}attaching", p.ok)));

        // The graphical stop hint colors only its app-name identifier (cyan) and names the pid.
        let hint = render_gui_stop_hint("demo-app", 4242, &p);
        assert!(hint.contains(&format!("{}demo-app{}", p.name, p.reset)));
        assert!(hint.contains("sbx session stop 4242"));

        assert!(render_no_active_sessions(&p).contains(p.dim));
    }

    /// A minimal resolved config carrying only the channel choices the builder reads.
    ///
    /// A config whose only interesting fields are the two `nixpkgs` pins these tests vary.
    fn resolved(global: Option<&str>, project: Option<&str>) -> crate::config::Resolved {
        let mut cfg = crate::testutil::resolved(vec![], vec![]);
        cfg.nixpkgs_global = global.map(String::from);
        cfg.nixpkgs_project = project.map(String::from);
        cfg
    }

    fn mise_pkg(name: &str, token: &str, trusted: bool) -> crate::config::Package {
        crate::config::Package {
            name: name.into(),
            backend: crate::config::Backend::Mise(token.into()),
            state: if trusted {
                crate::trust::TrustState::Trusted
            } else {
                crate::trust::TrustState::Untrusted
            },
            libs: Vec::new(),
        }
    }

    fn nix_pkg(name: &str, attr: &str) -> crate::config::Package {
        crate::config::Package {
            name: name.into(),
            backend: crate::config::Backend::Nix(attr.into()),
            state: crate::trust::TrustState::Trusted,
            libs: Vec::new(),
        }
    }

    fn app_overlay(
        cmd: &[&str],
        scope: crate::config::AppHomeScope,
        packages: Vec<crate::config::Package>,
    ) -> crate::config::ResolvedApp {
        crate::config::ResolvedApp {
            accepts_fresh_releases: Default::default(),
            provisions: Vec::new(),
            open: Default::default(),
            service: Default::default(),
            fs: Default::default(),
            fs_origin: crate::config::Provenance::Default,
            notify: None,
            notify_origin: Default::default(),
            ssh_agent_confirm: false,
            ssh_agent_origin: Default::default(),
            ssh_agent: Vec::new(),
            cmd: cmd.iter().map(|s| s.to_string()).collect(),
            home_scope: scope,
            env: vec![],
            binds: vec![],
            packages,
            network: None,
            gui: None,
            gpu: None,
            allow_insecure_http: None,
            audio: None,
            dbus: None,
            limits: Default::default(),
            forward: vec![],
            secrets: vec![],
            tasks: vec![],
            default_methods: crate::allowlist::Methods::Unspecified,
            cmd_origin: Default::default(),
            network_origin: Default::default(),
            gui_origin: Default::default(),
            gpu_origin: Default::default(),
            allow_insecure_http_origin: Default::default(),
            audio_origin: Default::default(),
            dbus_origin: Default::default(),
            forward_origin: Default::default(),
            limits_origin: Default::default(),
            seccomp: Default::default(),
            seccomp_origin: Default::default(),
            devices: Vec::new(),
            devices_origin: Default::default(),
            proc: None,
            proc_origin: Default::default(),
            home_scope_origin: None,
            warnings: vec![],
        }
    }

    /// The roll's unit of work: only apps, only those whose bundles install, each in the home its
    /// launch would use. A `provision` is a bundle's field and a bundle only folds into an app, so
    /// unlike the `mise:` roll there is no project-baseline group to find here.
    #[test]
    fn provision_groups_takes_only_the_apps_whose_bundles_install() {
        use crate::config::{AppHomeScope, BundleProvision};
        let step = |bundle: &str| BundleProvision {
            bundle: bundle.into(),
            argv: vec!["bash".into(), "-c".into(), "install".into()],
        };
        let mut cfg = resolved(None, None);
        let mut apps = std::collections::BTreeMap::new();

        let mut installs = app_overlay(&["alpha"], AppHomeScope::Global, vec![]);
        installs.provisions = vec![step("alpha-bundle")];
        apps.insert("alpha".to_string(), installs);

        // Rides a backend: nothing to re-run.
        apps.insert(
            "beta".to_string(),
            app_overlay(&["beta"], AppHomeScope::Project, vec![]),
        );

        // Declares a step but has no command: never launchable, so nothing installs for it.
        let mut unlaunchable = app_overlay(&[], AppHomeScope::Global, vec![]);
        unlaunchable.provisions = vec![step("ghost")];
        apps.insert("gamma".to_string(), unlaunchable);

        // Two bundles that install, in `use` order, in a per-project home.
        let mut two = app_overlay(&["delta"], AppHomeScope::Project, vec![]);
        two.provisions = vec![step("first"), step("second")];
        apps.insert("delta".to_string(), two);
        cfg.apps = apps;

        let groups = provision_groups(&cfg, None);
        assert_eq!(groups.len(), 2, "only alpha and delta install");
        assert!(matches!(&groups[0].home, GroupHome::GlobalApp(n) if n == "alpha"));
        assert_eq!(groups[0].steps.len(), 1);
        assert!(matches!(&groups[1].home, GroupHome::ProjectApp(n) if n == "delta"));
        assert_eq!(
            groups[1].steps.len(),
            2,
            "both bundles' steps, in use order"
        );
        assert_eq!(step_bundles(&groups[1].steps), "first, second");
        // A bundle named twice contributes one name to the line, not two.
        assert_eq!(step_bundles(&[step("dup"), step("dup")]), "dup");

        // `--app <name>` narrows the roll to that app's cage and takes nothing else with it.
        let only = provision_groups(&cfg, Some("delta"));
        assert_eq!(only.len(), 1, "the selector takes one app, not two");
        assert!(matches!(&only[0].home, GroupHome::ProjectApp(n) if n == "delta"));
        assert_eq!(only[0].steps.len(), 2, "that app keeps all of its steps");
        // A name the selector matches but that has nothing to roll still yields no group here; the
        // CLI is what refuses it by name, so this stays a plain filter.
        assert!(provision_groups(&cfg, Some("beta")).is_empty());
        assert!(provision_groups(&cfg, Some("nope")).is_empty());
    }

    /// The roll runs the install and stops there: chaining the app's command onto it would make a
    /// version roll a launch. The steps are quoted for the same reason the launch quotes them.
    #[test]
    fn an_install_roll_runs_the_steps_alone_and_never_the_app() {
        use crate::config::BundleProvision;
        let steps = vec![
            BundleProvision {
                bundle: "alpha".into(),
                argv: vec!["bash".into(), "-c".into(), "first $HOME".into()],
            },
            BundleProvision {
                bundle: "beta".into(),
                argv: vec!["installer".into(), "it's here".into()],
            },
        ];
        let cmd = provision_only_cmd(&steps);
        assert_eq!(cmd[0], OsString::from("bash"));
        assert_eq!(cmd[1], OsString::from("-c"));
        let script = cmd[2].to_string_lossy().to_string();
        assert!(
            !script.contains("exec"),
            "the app's command must not be chained on: {script}"
        );
        assert!(
            script.contains("'first $HOME'") && script.contains(r#"'it'\''s here'"#),
            "each argument stays data, not shell syntax: {script}"
        );
        assert_eq!(
            script.matches("&&").count(),
            1,
            "two steps, one `&&` — a failed step stops the chain: {script}"
        );
        assert_eq!(cmd.len(), 4, "a label for $0 and nothing positional");
    }

    #[test]
    fn the_install_roll_recap_names_what_ran_and_tallies_the_rest() {
        assert_eq!(
            provision_roll_recap(&["trae".to_string(), "odysseus".to_string()], 0, 0),
            "re-installed: trae, odysseus"
        );
        assert_eq!(
            provision_roll_recap(&[], 2, 1),
            "nothing re-installed · 2 skipped · 1 failed"
        );
    }

    #[test]
    fn mise_package_groups_covers_the_baseline_and_each_app_generically() {
        use crate::config::AppHomeScope;
        let mut cfg = resolved(None, None);
        cfg.packages = vec![
            mise_pkg("other-tool", "other-tool", true),
            nix_pkg("jq", "jq"), // a nix package is not a mise token
            mise_pkg("evil", "aqua:attacker/x", false), // untrusted: dropped
        ];
        let mut apps = std::collections::BTreeMap::new();
        // An app with its own mise: package, in a shared (global) home.
        apps.insert(
            "alpha".to_string(),
            app_overlay(
                &["alpha"],
                AppHomeScope::Global,
                vec![mise_pkg("foo", "aqua:foo", true)],
            ),
        );
        // An app with only a nix: package — no mise: group.
        apps.insert(
            "beta".to_string(),
            app_overlay(
                &["beta"],
                AppHomeScope::Project,
                vec![nix_pkg("rg", "ripgrep")],
            ),
        );
        // An app with a mise: package but no command — never launchable, so skipped.
        apps.insert(
            "gamma".to_string(),
            app_overlay(
                &[],
                AppHomeScope::Global,
                vec![mise_pkg("g", "aqua:g", true)],
            ),
        );
        cfg.apps = apps;

        let groups = mise_package_groups(&cfg, None);
        // Three groups: the project baseline plus each launchable app — beta inherits the
        // baseline `mise:` tool (an app's cage equips both layers), so even a nix-only app gets
        // a group. gamma has no command, so it is skipped.
        assert_eq!(groups.len(), 3);

        // The baseline group rolls only the trusted mise token, in the default home.
        let base = &groups[0];
        assert!(matches!(base.home, GroupHome::ProjectDefault));
        assert_eq!(base.tokens, vec!["other-tool".to_string()]);

        // alpha rolls in its own (global) home; its tokens are the merged set (baseline + app).
        let alpha = groups
            .iter()
            .find(|g| matches!(&g.home, GroupHome::GlobalApp(n) if n == "alpha"))
            .expect("alpha has a global-home group");
        assert!(alpha.tokens.contains(&"other-tool".to_string()));
        assert!(alpha.tokens.contains(&"aqua:foo".to_string()));

        // beta rolls in its own per-project home, inheriting only the baseline mise tool.
        let beta = groups
            .iter()
            .find(|g| matches!(&g.home, GroupHome::ProjectApp(n) if n == "beta"))
            .expect("beta inherits the baseline mise tool in its per-project home");
        assert_eq!(beta.tokens, vec!["other-tool".to_string()]);

        // The command-less app produced no group.
        assert!(!groups.iter().any(|g| g.home.label().contains("gamma")));

        // `--app <name>` narrows to that app's cage AND drops the project baseline, which is not
        // an app: keeping it would make a per-app flag roll project-wide work. The app's own group
        // still carries the merged token set, since its cage equips both layers.
        let only = mise_package_groups(&cfg, Some("alpha"));
        assert_eq!(only.len(), 1, "one app, and no baseline group beside it");
        assert!(matches!(&only[0].home, GroupHome::GlobalApp(n) if n == "alpha"));
        assert!(only[0].tokens.contains(&"other-tool".to_string()));
        assert!(only[0].tokens.contains(&"aqua:foo".to_string()));
        assert!(mise_package_groups(&cfg, Some("gamma")).is_empty());
        assert!(mise_package_groups(&cfg, Some("nope")).is_empty());

        // The withheld count follows the selector: a roll narrowed to one app must not report a
        // package withheld from a different one, or the line contradicts what the roll just did.
        // The fixture's untrusted `mise:` package is the project baseline's, which every app's
        // cage folds in — so it counts for an app, and once, not once per app.
        assert_eq!(withheld_mise_packages(&cfg, None), 1);
        assert_eq!(withheld_mise_packages(&cfg, Some("alpha")), 1);
        assert_eq!(
            withheld_mise_packages(&cfg, Some("nope")),
            0,
            "a name no app carries withholds nothing"
        );
    }

    #[test]
    fn no_pin_targets_the_global_lock_ignoring_any_stale_project_lock() {
        // Without a current pin the decision is the global channel, so the per-project
        // lock is never even named — a stale one left on disk cannot resurface. The
        // common path also does not canonicalise the cwd, so an arbitrary path is fine.
        let data = TmpDir::new();
        let layout = crate::store::Layout::under(data.path());
        std::fs::create_dir_all(layout.data_dir()).unwrap();
        std::fs::write(
            layout.data_dir().join("nixpkgs.lock"),
            format!("nixos-unstable\n{REV}\n"),
        )
        .unwrap();

        let target = effective_lock_target(
            Path::new("/nonexistent"),
            &layout,
            &resolved(None, None),
            None,
        )
        .expect("global target needs no canonicalisation");
        assert_eq!(target.origin(), Origin::Default);
        assert_eq!(target.source(), "nixos-unstable");
        // it reads the global lock, never a per-project one
        assert_eq!(target.locked_revision().as_deref(), Some(REV));
    }

    #[test]
    fn a_global_override_targets_the_global_lock_under_that_source() {
        let data = TmpDir::new();
        let layout = crate::store::Layout::under(data.path());
        let target = effective_lock_target(
            Path::new("/nonexistent"),
            &layout,
            &resolved(Some("nixos-23.11"), None),
            None,
        )
        .expect("global override needs no canonicalisation");
        assert_eq!(target.origin(), Origin::Global);
        assert_eq!(target.source(), "nixos-23.11");
    }

    #[test]
    fn a_trusted_pin_targets_a_per_project_lock() {
        // A pin canonicalises the cwd to key its own lock; resolving a revision pin
        // (no nix needed) records it there, not in the global lock.
        let data = TmpDir::new();
        let proj = TmpDir::new();
        let layout = crate::store::Layout::under(data.path());

        let target = effective_lock_target(proj.path(), &layout, &resolved(None, Some(REV)), None)
            .expect("canonicalise the project");
        assert_eq!(target.origin(), Origin::ProjectPin);
        assert_eq!(target.source(), REV);

        target
            .resolve(Path::new("/nonexistent-nix"), &layout)
            .expect("a revision pin resolves without nix");
        // the global lock stays untouched; a per-project lock was written instead
        assert!(!layout.data_dir().join("nixpkgs.lock").exists());
        let projects = layout.data_dir().join("projects");
        let has_lock = std::fs::read_dir(&projects)
            .map(|e| e.flatten().any(|d| d.path().join("nixpkgs.lock").is_file()))
            .unwrap_or(false);
        assert!(has_lock, "a trusted pin must record a per-project lock");
    }

    #[test]
    fn an_app_without_a_pin_targets_its_own_lock() {
        // The app branch: no project pin, so the app resolves against a lock keyed by its name and
        // sitting beside its state. The source is still the global one — an app cannot choose a
        // channel — so what is per-app here is the revision, nothing else.
        let data = TmpDir::new();
        let layout = crate::store::Layout::under(data.path());

        let target = effective_lock_target(
            Path::new("/nonexistent"),
            &layout,
            &resolved(None, None),
            Some("demo-app"),
        )
        .expect("the app branch needs no canonicalisation either");
        assert_eq!(target.origin(), Origin::Default);
        assert_eq!(target.source(), "nixos-unstable");

        // Resolving a fixed pin needs no nix, and records the revision in the app's own lock —
        // never the global one, which is what makes `sbx upgrade nix` leave this app alone.
        let pinned = effective_lock_target(
            Path::new("/nonexistent"),
            &layout,
            &resolved(Some(REV), None),
            Some("demo-app"),
        )
        .unwrap();
        pinned
            .resolve(Path::new("/nonexistent-nix"), &layout)
            .expect("a revision source resolves without nix");
        assert!(
            layout
                .data_dir()
                .join("apps/demo-app/nixpkgs.lock")
                .is_file(),
            "the revision lands in the app's own lock"
        );
        assert!(!layout.data_dir().join("nixpkgs.lock").exists());
    }

    #[test]
    fn a_project_pin_wins_over_an_app_lock() {
        // The precedence that keeps the one-channel rule true: an app launch also builds the
        // project's declared packages (`merge_app` overrides by name, it does not replace the
        // list), so under a trusted pin those tools must come from the pinned revision. The app's
        // own lock is therefore not even named here.
        let data = TmpDir::new();
        let proj = TmpDir::new();
        let layout = crate::store::Layout::under(data.path());

        let target = effective_lock_target(
            proj.path(),
            &layout,
            &resolved(None, Some(REV)),
            Some("demo-app"),
        )
        .expect("canonicalise the project");
        assert_eq!(target.origin(), Origin::ProjectPin);
        assert_eq!(target.source(), REV);

        target
            .resolve(Path::new("/nonexistent-nix"), &layout)
            .expect("a revision pin resolves without nix");
        assert!(
            !layout.data_dir().join("apps/demo-app").exists(),
            "under a pin, no app lock is written"
        );
    }

    #[test]
    fn keep_passthrough_drops_bare_c_locale_but_keeps_real_ones() {
        let out = keep_passthrough([
            ("TERM".to_string(), "xterm".to_string()),
            ("LANG".to_string(), "C".to_string()),
            ("LC_ALL".to_string(), "fr_FR.UTF-8".to_string()),
        ]);
        // TERM always passes; a bare `C` LANG is dropped so it cannot break the UTF-8 floor;
        // a real locale is kept
        assert!(out.iter().any(|(k, v)| k == "TERM" && v == "xterm"));
        assert!(!out.iter().any(|(k, _)| k == "LANG"));
        assert!(out.iter().any(|(k, v)| k == "LC_ALL" && v == "fr_FR.UTF-8"));

        // `POSIX` is dropped too (case-insensitive), while `C.UTF-8` — a real UTF-8 locale — passes
        let out = keep_passthrough([
            ("LC_ALL".to_string(), "posix".to_string()),
            ("LANG".to_string(), "C.UTF-8".to_string()),
        ]);
        assert!(!out.iter().any(|(k, _)| k == "LC_ALL"));
        assert!(out.iter().any(|(k, v)| k == "LANG" && v == "C.UTF-8"));
    }

    // The in-cage task client is a script, so the programs its shebang and its body name must be the
    // ones the CAGE resolves. Naming the host's would produce a client that cannot run where it is
    // bound — and the tests that exercise the client run it with the host's, so this is what pins
    // the shipped pairing.
    #[test]
    fn the_task_client_is_written_against_the_cages_own_programs() {
        let userland = Userland {
            base_roots: vec![],
            interp_src: PathBuf::from("/store/nix-ld"),
            interp_dest: PathBuf::from("/lib64/ld-linux-x86-64.so.2"),
            ca_bundle_src: PathBuf::from("/store/cacert/etc/ssl/certs/ca-bundle.crt"),
            base_loader: PathBuf::from("/nix/store/glibc/lib/ld"),
            foreign_lib_paths: vec![],
            bin_paths: vec![],
            shell_bin: PathBuf::from("/nix/store/bash/bin/bash"),
            env_bin: PathBuf::from("/nix/store/coreutils/bin/env"),
            socat_bin: PathBuf::from("/nix/store/socat/bin/socat"),
            mise_bin: PathBuf::from("/nix/store/mise/bin/mise"),
            nix_bin: PathBuf::from("/nix/store/nix/bin/nix"),
            locale_archive: PathBuf::from("/nix/store/locales/lib/locale/locale-archive"),
            zoneinfo_src: PathBuf::from("/nix/store/tzdata/share/zoneinfo"),
        };
        let (bash, socat, head) = task_client_programs(&userland);
        assert_eq!(bash, PathBuf::from("/nix/store/bash/bin/bash"));
        assert_eq!(socat, PathBuf::from("/nix/store/socat/bin/socat"));
        assert_eq!(
            head,
            PathBuf::from("/nix/store/coreutils/bin/head"),
            "`head` comes from the same coreutils the cage already has"
        );
    }

    #[test]
    fn collect_roots_unions_base_then_packages_then_tools_then_fonts() {
        // The seed's completeness rides on this collection: every provisioner's roots
        // must reach it. The order is base, then packages, then tools, then fonts.
        let userland = Userland {
            base_roots: vec![
                PathBuf::from("/nix/store/glibc"),
                PathBuf::from("/nix/store/bash"),
            ],
            interp_src: PathBuf::from("/store/nix-ld"),
            interp_dest: PathBuf::from("/lib64/ld-linux-x86-64.so.2"),
            ca_bundle_src: PathBuf::from("/store/cacert/etc/ssl/certs/ca-bundle.crt"),
            base_loader: PathBuf::from("/nix/store/glibc/lib/ld"),
            foreign_lib_paths: vec![],
            bin_paths: vec![],
            shell_bin: PathBuf::from("/nix/store/bash/bin/bash"),
            env_bin: PathBuf::from("/nix/store/coreutils/bin/env"),
            socat_bin: PathBuf::from("/nix/store/socat/bin/socat"),
            mise_bin: PathBuf::from("/nix/store/mise/bin/mise"),
            nix_bin: PathBuf::from("/nix/store/nix/bin/nix"),
            locale_archive: PathBuf::from("/nix/store/locales/lib/locale/locale-archive"),
            zoneinfo_src: PathBuf::from("/nix/store/tzdata/share/zoneinfo"),
        };
        let pkg_roots = [PathBuf::from("/nix/store/jq")];
        let tool_roots = [PathBuf::from("/nix/store/nodejs")];
        let font_roots = [PathBuf::from("/nix/store/dejavu")];

        assert_eq!(
            collect_roots(&userland, &pkg_roots, &tool_roots, &font_roots),
            vec![
                PathBuf::from("/nix/store/glibc"),
                PathBuf::from("/nix/store/bash"),
                PathBuf::from("/nix/store/jq"),
                PathBuf::from("/nix/store/nodejs"),
                PathBuf::from("/nix/store/dejavu"),
            ]
        );

        // teeth: dropping a source loses exactly its roots — a launch that forgot to
        // forward the tools' (or packages', or fonts') roots would seed an incomplete
        // closure, and the cage would silently re-fetch the missing one.
        assert!(
            !collect_roots(&userland, &pkg_roots, &[], &font_roots)
                .contains(&PathBuf::from("/nix/store/nodejs"))
        );
        assert!(
            !collect_roots(&userland, &[], &tool_roots, &font_roots)
                .contains(&PathBuf::from("/nix/store/jq"))
        );
        assert!(
            !collect_roots(&userland, &pkg_roots, &tool_roots, &[])
                .contains(&PathBuf::from("/nix/store/dejavu"))
        );
    }

    #[test]
    fn egress_ca_overrides_the_structural_cacert() {
        // The assembler upserts the overlay env on last-occurrence, so the winner for a key is
        // its last entry in this layering. Under a network allowlist the cage must trust the
        // egress proxy's per-session CA, not sbx's root bundle: egress is layered after cacert,
        // so it wins. A trusted config, layered last, still has the final say (self-harm only).
        let winner = |env: &[(String, String)]| {
            env.iter()
                .rev()
                .find(|(k, _)| k == "SSL_CERT_FILE")
                .map(|(_, v)| v.clone())
        };

        let cacert = || {
            vec![(
                "SSL_CERT_FILE".to_string(),
                "/etc/ssl/certs/ca-bundle.crt".to_string(),
            )]
        };
        let egress = || {
            vec![(
                "SSL_CERT_FILE".to_string(),
                "/opt/sbx/egress-ca.pem".to_string(),
            )]
        };

        let env = extra_cage_env(vec![
            (EnvLayer::Cacert, cacert()),
            (EnvLayer::Egress, egress()),
        ]);
        assert_eq!(
            winner(&env).as_deref(),
            Some("/opt/sbx/egress-ca.pem"),
            "egress CA must override the structural cacert"
        );

        let cfg = vec![("SSL_CERT_FILE".to_string(), "/cfg/ca.pem".to_string())];
        let env = extra_cage_env(vec![
            (EnvLayer::Cacert, cacert()),
            (EnvLayer::Egress, egress()),
            (EnvLayer::Config, cfg),
        ]);
        assert_eq!(
            winner(&env).as_deref(),
            Some("/cfg/ca.pem"),
            "a trusted config has the final say over the CA"
        );

        // with no egress (shared/isolated posture) the structural cacert stands
        let env = extra_cage_env(vec![(EnvLayer::Cacert, cacert())]);
        assert_eq!(
            winner(&env).as_deref(),
            Some("/etc/ssl/certs/ca-bundle.crt"),
            "without egress the hermetic cacert is the trust anchor"
        );
    }

    /// The nesting is the enum's, not the order the blocks in `build` happen to run in.
    ///
    /// Each marker wrap prepends its own name, so the composed argv reads outermost first — which is
    /// also the order the preambles run in. Registering them shuffled and still getting that order
    /// is what the layer tag buys: the four constraints below used to hold only because their blocks
    /// The composed startup is what the wraps nest around, not a peer of it.
    ///
    /// `build` takes a `&Prepared`, so no unit test can reach it, and this ordering lives nowhere
    /// else: [`wrap_cage_command`] cannot tell a bare command from a composed one, and every test of
    /// [`compose_startup_cmd`] hands it a `cmd` directly. So the check is on the source, the way the
    /// cage-suite and docs guards are, because the alternative is no check at all.
    ///
    /// What it protects is not a style preference. An install step finishes making the command
    /// runnable, so it needs everything the command needs. Composed *after* the wraps it ran outside
    /// every layer: before the mise equip lanes, so a step asking `mise where` about a package found
    /// nothing and aborted the launch before the equip that would have installed it; and before the
    /// egress forwarder, so a step that downloads got `https_proxy` pointed at a port with nothing
    /// listening. Measured on three shipped bundles whose step does exactly that.
    #[test]
    fn the_wraps_nest_around_the_composed_startup_and_not_the_bare_command() {
        let source = include_str!("launch.rs");
        // The test module below calls both helpers too, so only `build`'s own body is read.
        // Anchored on the test module itself, not on the first `#[cfg(test)]`: this file carries a
        // test-only helper thousands of lines above it, and cutting there yields a body that ends
        // before `build` begins. That mistake fails loudly here — the `expect` below fires — but it
        // fails for the wrong reason, reporting a missing call where the real fault is the reader.
        let body = &source[..source
            .find("\n#[cfg(test)]\nmod tests {")
            .expect("the test module is where this file's non-production code ends")];
        let compose = body
            .find("compose_startup_cmd(&prep.cfg.provisions")
            .expect("`build` composes the startup from the resolved provisions");
        let wrap = body
            .find("wrap_cage_command(startup_cmd, wraps)")
            .expect("`build` nests the wraps around the composed startup, by that name");
        assert!(
            compose < wrap,
            "`build` applies its wraps at byte {wrap} and composes the startup at {compose}: the \
             composition has moved back outside the nesting, so every bundle's install step runs \
             before the mise equip lanes and before the egress forwarder is up"
        );
        // The bare command must no longer be wrapped anywhere: a second call site would reinstate
        // the old order for whichever branch reached it first.
        assert!(
            !body.contains("wrap_cage_command(cmd, wraps)"),
            "`build` still wraps the bare command somewhere, so a launch can take the old order"
        );
    }

    /// sat in the right places, hundreds of lines apart, and nothing checked it.
    #[test]
    fn the_wraps_nest_by_layer_however_the_blocks_registered_them() {
        let marker = |name: &'static str| -> CommandWrap<'static> {
            Box::new(move |cmd: Vec<OsString>| {
                let mut out = vec![OsString::from(name)];
                out.extend(cmd);
                out
            })
        };

        // Deliberately not in layer order, and with the two mise lanes registered in the order
        // `build` registers them: lane 2 (`install`) then lane 1 (`use -g`).
        let wraps = vec![
            (WrapLayer::Portal, marker("portal")),
            (WrapLayer::MiseEquip, marker("mise-install")),
            (WrapLayer::Egress, marker("egress")),
            (WrapLayer::ProcEnforce, marker("proc")),
            (WrapLayer::MiseEquip, marker("mise-use-g")),
            (WrapLayer::CaTrust, marker("catrust")),
            (WrapLayer::FlakeEquip, marker("flake")),
            (WrapLayer::Forward, marker("forward")),
        ];
        let out = wrap_cage_command(vec![OsString::from("the-command")], wraps);

        assert_eq!(
            out,
            [
                "portal",
                "catrust",
                "egress",
                "forward",
                "flake",
                "mise-use-g",
                "mise-install",
                "proc",
                "the-command",
            ]
            .map(OsString::from)
        );
    }

    /// A launch that contributes nothing runs its command bare — no preamble, no shell.
    #[test]
    fn a_launch_with_no_wraps_leaves_the_command_untouched() {
        let cmd = vec![OsString::from("jq"), OsString::from("--version")];
        assert_eq!(wrap_cage_command(cmd.clone(), vec![]), cmd);
    }

    /// The precedence is the enum's, not the caller's. Listing the layers backwards must produce
    /// exactly the same environment as listing them in order — that is the whole reason the sources
    /// carry a tag instead of riding an argument list, where two of them swapped would compile in
    /// silence and change which CA the cage trusts.
    #[test]
    fn the_layer_decides_precedence_not_the_order_the_caller_lists_them_in() {
        let key = "SSL_CERT_FILE".to_string();
        let in_order = vec![
            (EnvLayer::Passthrough, vec![(key.clone(), "/host".into())]),
            (EnvLayer::Cacert, vec![(key.clone(), "/hermetic".into())]),
            (EnvLayer::Egress, vec![(key.clone(), "/mitm".into())]),
            (EnvLayer::Config, vec![(key.clone(), "/cfg".into())]),
        ];
        let mut backwards = in_order.clone();
        backwards.reverse();

        assert_eq!(extra_cage_env(in_order.clone()), extra_cage_env(backwards));
        assert_eq!(
            extra_cage_env(in_order).last().map(|(_, v)| v.clone()),
            Some("/cfg".to_string()),
            "the config layer stays last however the caller lists it"
        );
    }

    /// A caller contributing one layer in two pieces must keep the pieces in the order it gave
    /// them: within a layer there is no precedence to derive, so only a stable sort is correct.
    #[test]
    fn two_pieces_of_one_layer_keep_the_order_they_were_given() {
        let env = extra_cage_env(vec![
            (EnvLayer::Gui, vec![("WAYLAND_DISPLAY".into(), "a".into())]),
            (
                EnvLayer::Cacert,
                vec![("SSL_CERT_FILE".into(), "ca".into())],
            ),
            (EnvLayer::Gui, vec![("WAYLAND_DISPLAY".into(), "b".into())]),
        ]);
        let seen: Vec<&str> = env
            .iter()
            .filter(|(k, _)| k == "WAYLAND_DISPLAY")
            .map(|(_, v)| v.as_str())
            .collect();
        assert_eq!(seen, ["a", "b"]);
    }

    #[test]
    fn auto_equip_tokens_formats_non_nix_tools_and_ignores_trust() {
        // no mise file → nothing to equip
        assert!(auto_equip_tokens(&resolved(None, None)).is_empty());

        // a mise file mixing a `nix:` tool (host-provisioned), a backend-prefixed tool, and a
        // plain registry tool: only the non-`nix:` ones become `token@version` install specs.
        // The state is Untrusted on purpose — auto-equip is the open self-equip path, so it is
        // independent of the project's trust verdict (the egress allowlist is the control).
        let mut cfg = resolved(None, None);
        cfg.mise = Some(crate::config::MiseConfig {
            name: "mise.toml".into(),
            state: crate::trust::TrustState::Untrusted,
            files: vec![(
                "mise.toml".into(),
                b"[tools]\n\"nix:jq\" = \"latest\"\n\"aqua:BurntSushi/ripgrep\" = \"latest\"\nnode = \"20\"\n"
                    .to_vec(),
            )],
        });
        assert_eq!(
            auto_equip_tokens(&cfg),
            vec![
                "aqua:BurntSushi/ripgrep@latest".to_string(),
                "node@20".to_string(),
            ]
        );
    }

    #[test]
    fn wrap_autoequip_passes_tokens_and_command_positionally() {
        // The install tokens and the real command both ride `"$@"`, so a token from an
        // untrusted project config can never inject shell: only the absolute mise path and
        // the integer count ever reach the script string.
        let mise = PathBuf::from("/nix/store/mise/bin/mise");
        let bash = PathBuf::from("/nix/store/bash/bin/bash");
        let tokens = vec![
            "aqua:BurntSushi/ripgrep@latest".to_string(),
            // a hostile token must stay a single positional arg, never reach the script
            "node@20; rm -rf /".to_string(),
        ];
        let cmd = vec![OsString::from("demo-app"), OsString::from("--print")];

        let argv = wrap_mise_equip(&mise, &bash, "install", &tokens, None, cmd);

        assert_eq!(argv[0], OsString::from("/nix/store/bash/bin/bash"));
        assert_eq!(argv[1], OsString::from("-c"));
        let script = argv[2].to_string_lossy();
        // mise by absolute path; the slice/shift use the count, not the tokens; the command
        // is exec'd (so it stays the cage's main process) after the tokens are shifted off.
        assert!(script.contains("/nix/store/mise/bin/mise install \"${@:1:2}\""));
        assert!(script.contains("shift 2;"));
        assert!(script.trim_end().ends_with("exec \"$@\""));
        assert!(
            !script.contains("rm -rf"),
            "a hostile token must never be interpolated into the script: {script}"
        );
        // label, then the tokens, then the command — all positional
        assert_eq!(argv[3], OsString::from("sbx-mise-equip"));
        assert_eq!(argv[4], OsString::from("aqua:BurntSushi/ripgrep@latest"));
        assert_eq!(argv[5], OsString::from("node@20; rm -rf /"));
        assert_eq!(argv[6], OsString::from("demo-app"));
        assert_eq!(argv[7], OsString::from("--print"));
    }

    #[test]
    fn wrap_mise_equip_uses_the_global_verb_for_app_packages() {
        // The app's `[packages] mise:` tools are equipped globally (`mise use -g`), so the verb
        // is interpolated literally (an sbx-chosen constant, never config) while the token stays
        // positional — proving the same no-shell-injection shape for the global lane.
        let mise = PathBuf::from("/nix/store/mise/bin/mise");
        let bash = PathBuf::from("/nix/store/bash/bin/bash");
        let tokens = vec!["aqua:example/demo-tool".to_string()];
        let cmd = vec![OsString::from("demo-app")];

        let argv = wrap_mise_equip(&mise, &bash, "use -g", &tokens, None, cmd);

        let script = argv[2].to_string_lossy();
        assert!(script.contains("/nix/store/mise/bin/mise use -g \"${@:1:1}\""));
        assert!(script.contains("shift 1;"));
        // no data-dir override: the equip runs under the ambient primary
        assert!(!script.contains("MISE_DATA_DIR="));
        // the token is a positional arg, never in the script
        assert_eq!(argv[4], OsString::from("aqua:example/demo-tool"));
        assert_eq!(argv[5], OsString::from("demo-app"));
    }

    /// The launch freezes a `mise:` package at its installed version and the roll is what moves it.
    /// Both halves are needed and each breaks the other's guarantee when removed, so they are
    /// asserted together rather than one per test.
    #[test]
    fn a_mise_package_is_pinned_at_equip_and_only_a_bump_roll_moves_it() {
        // Equip: the resolved version is written into the cage's config. Without this the config
        // keeps the floating request, the tool's mise shim re-resolves it on every exec, and the
        // app stops launching as soon as upstream publishes a version the pool does not hold.
        assert!(
            MISE_EQUIP_VERB.contains("--pin"),
            "the equip must pin, or a launch re-resolves: {MISE_EQUIP_VERB}"
        );
        assert!(
            MISE_EQUIP_VERB.starts_with("use -g"),
            "the app lane equips globally: {MISE_EQUIP_VERB}"
        );

        // Roll: an exact pin is a range a plain `mise upgrade` treats as already satisfied, so
        // without `--bump` the shipped roll would report every tool up to date and move nothing.
        let mise = PathBuf::from("/nix/store/mise/bin/mise");
        let bash = PathBuf::from("/nix/store/bash/bin/bash");
        let tokens = vec!["aqua:example/demo-tool".to_string()];

        let plain = mise_upgrade_cmd(binds::Runtime::ProjectDefault, &mise, &bash, &tokens);
        assert_eq!(plain[1], OsString::from("upgrade"));
        assert_eq!(
            plain[2],
            OsString::from("--bump"),
            "a pinned tool only advances with --bump"
        );
        assert_eq!(plain[3], OsString::from("aqua:example/demo-tool"));

        // The same on the global-app lane, where the roll runs through a shell to pin the pool.
        let global = mise_upgrade_cmd(binds::Runtime::GlobalApp("demo-app"), &mise, &bash, &tokens);
        assert!(
            global[2]
                .to_string_lossy()
                .contains("upgrade --bump \"$@\""),
            "the global lane bumps too: {}",
            global[2].to_string_lossy()
        );
    }

    /// What the launch says it is about to do is what it does.
    ///
    /// The announcement carried a hand-written copy of the verb, so it kept saying `mise use -g`
    /// after the equip started pinning: a reader who reproduced the printed command by hand got a
    /// floating install and no hint that the two had parted. Reading both from one constant is the
    /// fix; this holds it there.
    #[test]
    fn the_equip_line_names_the_invocation_it_runs() {
        let line = equip_announcement(&[
            "aqua:example/demo-tool".to_string(),
            "npm:demo-cli".to_string(),
        ]);

        assert!(
            line.contains(&format!("mise {MISE_EQUIP_VERB}:")),
            "the printed verb must be the one the equip uses: {line}"
        );
        // The tools are named too, and separately: this line is how a user learns which package a
        // slow launch is fetching.
        assert!(
            line.contains("aqua:example/demo-tool, npm:demo-cli"),
            "{line}"
        );
    }

    #[test]
    fn wrap_mise_equip_pins_the_app_global_data_dir_for_the_global_lane() {
        // For a global app, Lane-1 `mise use -g` is pinned to the app-global home pool so the app
        // tool installs there (shared across projects, read by `sbx app show`/`gc`) while the
        // ambient primary stays the per-project pool. The pin applies to the equip step only — the
        // exec'd command keeps the ambient value — and the value is single-quoted (injection-safe,
        // an sbx-owned fixed path).
        let mise = PathBuf::from("/nix/store/mise/bin/mise");
        let bash = PathBuf::from("/nix/store/bash/bin/bash");
        let tokens = vec!["aqua:example/demo-tool".to_string()];
        let cmd = vec![OsString::from("demo-app")];
        let data_dir = crate::sandbox::binds::mise_app_global_data_dir();

        let argv = wrap_mise_equip(&mise, &bash, "use -g", &tokens, Some(&data_dir), cmd);

        let script = argv[2].to_string_lossy();
        // the equip's MISE_DATA_DIR is pinned to the app-global home, single-quoted, before mise
        assert!(
            script.contains(&format!(
                "MISE_DATA_DIR='{data_dir}' /nix/store/mise/bin/mise use -g"
            )),
            "the global lane must pin the app-global data dir: {script}"
        );
        // the pin is only on the equip command, not the exec'd command
        assert!(script.trim_end().ends_with("exec \"$@\""));
        // the token still rides positionally
        assert_eq!(argv[4], OsString::from("aqua:example/demo-tool"));
    }

    #[test]
    fn mise_upgrade_cmd_pins_the_app_global_pool_only_for_a_global_app() {
        // `sbx upgrade mise` rolls `[packages] mise:` tools, which for a global app live in the
        // app-global home pool. The cage's ambient primary for a global app is the per-project pool
        // (the split), which does not hold them, so the roll must be pinned to the app-global pool —
        // else `mise upgrade` finds nothing and silently rolls nothing (a shipped-command regression).
        let mise = PathBuf::from("/nix/store/mise/bin/mise");
        let bash = PathBuf::from("/nix/store/bash/bin/bash");
        let tokens = vec!["aqua:example/demo-tool".to_string()];
        let data_dir = crate::sandbox::binds::mise_app_global_data_dir();

        // global app: pinned to the app-global pool via a bash MISE_DATA_DIR prefix
        let g = mise_upgrade_cmd(binds::Runtime::GlobalApp("cc"), &mise, &bash, &tokens);
        assert_eq!(g[0], OsString::from("/nix/store/bash/bin/bash"));
        let script = g[2].to_string_lossy();
        assert!(
            script.contains(&format!(
                "MISE_DATA_DIR='{data_dir}' exec /nix/store/mise/bin/mise upgrade"
            )),
            "the global-app roll must pin the app-global data dir: {script}"
        );
        assert_eq!(g[4], OsString::from("aqua:example/demo-tool")); // token positional

        // sbx run / a per-project app: single pool (the ambient primary), plain unwrapped command
        for rt in [
            binds::Runtime::ProjectDefault,
            binds::Runtime::ProjectApp("cc"),
        ] {
            let c = mise_upgrade_cmd(rt, &mise, &bash, &tokens);
            assert_eq!(c[0], OsString::from("/nix/store/mise/bin/mise"));
            assert_eq!(c[1], OsString::from("upgrade"));
            // `--bump` sits between the verb and the tokens on this lane too: the launch pins the
            // config at the installed version, and a pinned range is one a plain roll would call
            // already satisfied.
            assert_eq!(c[2], OsString::from("--bump"));
            assert_eq!(c[3], OsString::from("aqua:example/demo-tool"));
        }
    }

    #[test]
    fn wrap_flake_equip_passes_quads_and_command_positionally() {
        // Each (ref, target, good, key) rides `"$@"`, so a value from an untrusted-but-trusted-app
        // config can never inject shell: only the absolute nix path, the out-link parent, and the
        // integer quad count reach the script string. The per-quad build, the good-out-link
        // promotion, the fallback branch, the `<target>.failed` marker, and the host-resolvable gc
        // root (keyed by package name, the `$key` positional, never interpolated) are all present.
        let nix = PathBuf::from("/nix/store/nix/bin/nix");
        let bash = PathBuf::from("/nix/store/bash/bin/bash");
        let dir = PathBuf::from("/home/sandbox/.local/state/sbx/flake");
        let quads = vec![
            (
                "github:example/flake-tool#tui".to_string(),
                PathBuf::from("/home/sandbox/.local/state/sbx/flake/flake-tool-rev"),
                PathBuf::from("/home/sandbox/.local/state/sbx/flake/flake-tool"),
                "flake-tool".to_string(),
            ),
            // a hostile ref must stay a single positional arg, never reach the script
            (
                "github:evil/x#bin; rm -rf /".to_string(),
                PathBuf::from("/home/sandbox/.local/state/sbx/flake/evil-rev"),
                PathBuf::from("/home/sandbox/.local/state/sbx/flake/evil"),
                "evil".to_string(),
            ),
        ];
        let cmd = vec![OsString::from("flake-tool"), OsString::from("-z")];

        let argv = wrap_flake_equip(&nix, &bash, &dir, &quads, cmd);

        assert_eq!(argv[0], OsString::from("/nix/store/bash/bin/bash"));
        assert_eq!(argv[1], OsString::from("-c"));
        let script = argv[2].to_string_lossy();
        // nix by absolute path; the quad count drives the loop, not the refs; the command is exec'd
        // after the quads are shifted.
        assert!(script.contains("n=2"));
        assert!(script.contains(
            "'/nix/store/nix/bin/nix' build \"$ref\" --no-write-lock-file --out-link \"$target\""
        ));
        assert!(script.contains("mkdir -p '/home/sandbox/.local/state/sbx/flake'"));
        // the fallback machinery: the per-revision failed-marker, the promotion of the good
        // out-link on success, and the loud notice when a pinned build fails.
        assert!(script.contains("touch \"$target.failed\""));
        assert!(script.contains("ln -sfn \"$sp\" \"$good\""));
        assert!(script.contains("falling back to the last good build"));
        assert!(script.contains("there is no prior build to fall back to"));
        // the gc root is keyed by the `$key` positional (the package name), targeting the used
        // build's store path resolved by `readlink -f` — host-resolvable, overwritten each launch
        assert!(script.contains("ln -sfn \"$sp\" \"/nix/var/nix/gcroots/sbx-flake-$key\""));
        assert!(script.contains("shift 4"));
        assert!(script.trim_end().ends_with("exec \"$@\""));
        assert!(
            !script.contains("rm -rf"),
            "a hostile ref must never be interpolated into the script: {script}"
        );
        // label, then interleaved (ref, target, good, key) quads, then the command — all positional
        assert_eq!(argv[3], OsString::from("sbx-flake-equip"));
        assert_eq!(argv[4], OsString::from("github:example/flake-tool#tui"));
        assert_eq!(
            argv[5],
            OsString::from("/home/sandbox/.local/state/sbx/flake/flake-tool-rev")
        );
        assert_eq!(
            argv[6],
            OsString::from("/home/sandbox/.local/state/sbx/flake/flake-tool")
        );
        assert_eq!(argv[7], OsString::from("flake-tool"));
        assert_eq!(argv[8], OsString::from("github:evil/x#bin; rm -rf /"));
        assert_eq!(
            argv[9],
            OsString::from("/home/sandbox/.local/state/sbx/flake/evil-rev")
        );
        assert_eq!(
            argv[10],
            OsString::from("/home/sandbox/.local/state/sbx/flake/evil")
        );
        assert_eq!(argv[11], OsString::from("evil"));
        assert_eq!(argv[12], OsString::from("flake-tool"));
        assert_eq!(argv[13], OsString::from("-z"));
    }

    /// Write `body` to `path` as an executable file (a stub used to drive the flake-equip script).
    #[cfg(test)]
    fn write_exec(path: &Path, body: &str) {
        use std::os::unix::fs::PermissionsExt;
        std::fs::write(path, body).unwrap();
        let mut perms = std::fs::metadata(path).unwrap().permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(path, perms).unwrap();
    }

    #[test]
    fn wrap_flake_equip_falls_back_to_the_last_good_build_when_a_pinned_build_fails() {
        // The headline of the fallback feature, run for real: when the pinned (rev-keyed) build
        // fails, the launch must run the last good build instead of breaking — and must not
        // re-attempt the doomed build on the next launch (the `<target>.failed` marker).
        let tmp = crate::testutil::TmpDir::new();
        let flake = tmp.path().join("flake");
        std::fs::create_dir_all(&flake).unwrap();

        // A `nix` that always fails the build, recording each call so we can prove the marker
        // stops the second attempt.
        let calls = tmp.path().join("nixcalls");
        let fake_nix = tmp.path().join("nix");
        write_exec(
            &fake_nix,
            &format!("#!/bin/sh\necho call >> '{}'\nexit 1\n", calls.display()),
        );

        // A pre-existing good build (the previous version) the fallback resolves to.
        let good_store = tmp.path().join("goodstore");
        std::fs::create_dir_all(good_store.join("bin")).unwrap();
        let good = flake.join("tool");
        std::os::unix::fs::symlink(&good_store, &good).unwrap();
        let target = flake.join("tool-deadbeef"); // rev-keyed, does not exist

        let quads = vec![(
            "github:o/tool#default".to_string(),
            target.clone(),
            good.clone(),
            "tool".to_string(),
        )];
        // The command the wrap execs once equip is done — reaching it proves we did NOT exit 1.
        let cmd = vec![OsString::from("echo"), OsString::from("FELL-BACK")];
        let argv = wrap_flake_equip(&fake_nix, &PathBuf::from("bash"), &flake, &quads, cmd);

        let run = || {
            std::process::Command::new(&argv[0])
                .args(&argv[1..])
                .output()
                .expect("run the flake-equip script")
        };

        // First launch: build fails → fall back to the good build, exec the command, mark the failure.
        let out1 = run();
        assert!(out1.status.success(), "must fall back, not exit 1");
        assert!(
            String::from_utf8_lossy(&out1.stdout).contains("FELL-BACK"),
            "the command must run off the good build after a failed pinned build"
        );
        assert!(
            String::from_utf8_lossy(&out1.stderr).contains("falling back to the last good build"),
            "the fallback must be announced loudly on stderr"
        );
        assert!(
            flake.join("tool-deadbeef.failed").exists(),
            "a failed pinned build must be marked so it is not re-attempted every launch"
        );
        assert_eq!(
            std::fs::read_to_string(&calls).unwrap().lines().count(),
            1,
            "the failing build is attempted exactly once"
        );

        // Second launch: the marker short-circuits the doomed rebuild — still falls back, no new call.
        let out2 = run();
        assert!(out2.status.success());
        assert!(String::from_utf8_lossy(&out2.stdout).contains("FELL-BACK"));
        assert_eq!(
            std::fs::read_to_string(&calls).unwrap().lines().count(),
            1,
            "the marker must stop a second attempt at the same failing revision"
        );
    }

    #[test]
    fn wrap_flake_equip_hard_fails_when_a_build_fails_and_no_good_build_exists() {
        // With no prior good build to fall back to, a failed build is a hard error (exit 1) — the
        // app cannot run, and that must surface, not be masked.
        let tmp = crate::testutil::TmpDir::new();
        let flake = tmp.path().join("flake");
        std::fs::create_dir_all(&flake).unwrap();
        let fake_nix = tmp.path().join("nix");
        write_exec(&fake_nix, "#!/bin/sh\nexit 1\n");

        let good = flake.join("tool"); // does NOT exist
        let target = flake.join("tool-deadbeef");
        let quads = vec![(
            "github:o/tool#default".to_string(),
            target,
            good,
            "tool".to_string(),
        )];
        let cmd = vec![OsString::from("echo"), OsString::from("SHOULD-NOT-RUN")];
        let argv = wrap_flake_equip(&fake_nix, &PathBuf::from("bash"), &flake, &quads, cmd);

        let out = std::process::Command::new(&argv[0])
            .args(&argv[1..])
            .output()
            .expect("run the flake-equip script");
        assert!(!out.status.success(), "no good build → must hard-fail");
        assert!(
            !String::from_utf8_lossy(&out.stdout).contains("SHOULD-NOT-RUN"),
            "the command must not run when there is nothing to fall back to"
        );
        assert!(String::from_utf8_lossy(&out.stderr).contains("no prior build to fall back to"));
    }

    #[test]
    fn net_policy_maps_the_config_posture_to_the_cage_posture() {
        // the cheap, total map between the two posture vocabularies — the one place
        // a `network = "none"` config becomes an isolated cage.
        assert_eq!(
            net_policy(&crate::config::NetworkPolicy::Shared),
            NetPolicy::Shared
        );
        assert_eq!(
            net_policy(&crate::config::NetworkPolicy::Isolated),
            NetPolicy::Isolated
        );
        // an allowlist posture maps to an isolated (empty) namespace by design — the Model-B
        // foundation: the cage's only egress is the bound socket to the host filtering proxy,
        // never the shared host network.
        assert_eq!(
            net_policy(&crate::config::NetworkPolicy::Allowlist(
                crate::allowlist::EgressPolicy::default()
            )),
            NetPolicy::Isolated
        );
    }

    #[test]
    fn resolve_wayland_hole_binds_the_socket_file_never_the_runtime_dir() {
        // The load-bearing invariant of the GUI hole: a relative display resolves under
        // XDG_RUNTIME_DIR to the socket *file*, never the runtime directory — which also holds the
        // dbus session bus, pulse, and the gpg/ssh agents a directory bind would leak.
        let (socket, env) =
            resolve_wayland_hole(Some("wayland-0"), Some("/run/user/1000")).unwrap();
        assert_eq!(socket, PathBuf::from("/run/user/1000/wayland-0"));
        assert_ne!(
            socket,
            PathBuf::from("/run/user/1000"),
            "the bind target must be the socket file, never the runtime directory"
        );
        assert_eq!(socket.file_name().unwrap(), "wayland-0");
        assert!(env.contains(&("WAYLAND_DISPLAY".to_string(), "wayland-0".to_string())));
        assert!(env.contains(&("XDG_RUNTIME_DIR".to_string(), "/run/user/1000".to_string())));

        // An absolute display is the socket path verbatim (XDG_RUNTIME_DIR is not needed to
        // locate it, per the Wayland convention).
        let (socket, env) =
            resolve_wayland_hole(Some("/tmp/wl.sock"), Some("/run/user/1000")).unwrap();
        assert_eq!(socket, PathBuf::from("/tmp/wl.sock"));
        assert!(env.contains(&("WAYLAND_DISPLAY".to_string(), "/tmp/wl.sock".to_string())));

        // No display, an empty display, or a relative display with no runtime dir cannot be
        // located → error, so the caller warns and runs without a display (fail-closed — it
        // never binds a wrong or guessed path).
        assert!(resolve_wayland_hole(None, Some("/run/user/1000")).is_err());
        assert!(resolve_wayland_hole(Some(""), Some("/run/user/1000")).is_err());
        assert!(resolve_wayland_hole(Some("wayland-0"), None).is_err());
    }

    #[test]
    fn exec_refuses_a_private_tty_spec() {
        // a private-tty spec must go through the pty supervisor; exec-replace has
        // no pty to offer, so it must refuse *before* actually exec'ing anything.
        let spec = SandboxSpec::new(
            PathBuf::from("/work"),
            vec![],
            vec![],
            NetPolicy::Shared,
            vec![OsString::from("/bin/true")],
        )
        .unwrap()
        .with_private_tty();

        let err = exec(
            Path::new("/bin/true"),
            &spec,
            &super::super::cgroup::Limits::default(),
        );
        assert!(
            err.to_string().contains("pty supervisor"),
            "exec must refuse a private-tty spec; got: {err}"
        );
    }

    #[test]
    fn detach_log_path_is_keyed_by_pid_under_logs() {
        // The daemon, the reporting parent and `sbx session logs` must agree on the log location;
        // all three derive it from the session pid, so this is the single source of that name.
        let path = detach_log_path(Path::new("/var/lib/sbx"), 4242);
        assert_eq!(path, PathBuf::from("/var/lib/sbx/logs/4242.log"));
    }

    #[test]
    fn the_header_open_detach_log_writes_is_the_one_the_parser_reads() {
        // The writer/parser seam. Both halves live in this file precisely so a change to one is
        // caught here: a header the parser no longer recognises does not fail loudly, it makes
        // `sbx session logs` silently replay a *previous* session's output as the current one's.
        // So this drives the real writer and parses what actually landed on disk.
        let dir = crate::testutil::TmpDir::new();
        let path = dir.join("logs").join("nested.log");
        let before = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let file = open_detach_log(&path).expect("open the session log");
        drop(file);

        let bytes = std::fs::read(&path).expect("read the session log back");
        let first = bytes.split(|&b| b == b'\n').next().expect("a first line");
        let header = parse_session_header(first).expect("the written header must parse");
        assert_eq!(
            header.pid,
            std::process::id(),
            "the header must name the session whose output follows it"
        );
        assert!(
            header.started >= before,
            "started={} must be the wall clock at open (>= {before})",
            header.started
        );

        // Appending a second session's header is what a reused pid does; both must parse, so the
        // reader can tell the two apart rather than running them together.
        let file = open_detach_log(&path).expect("reopen the session log");
        drop(file);
        let bytes = std::fs::read(&path).expect("read back after the second open");
        let headers = bytes
            .split(|&b| b == b'\n')
            .filter_map(parse_session_header)
            .count();
        assert_eq!(headers, 2, "each open must mark its own session");
    }

    #[test]
    fn a_detached_log_notes_the_trust_drops_and_nothing_else() {
        // The record that outlives the launching terminal a detached session is about to lose.
        // Three properties hold it up, and each fails silently if it breaks: only a trust drop is
        // noted, the warning survives verbatim (a reader has to be able to act on it), and a note
        // can never be read as a session boundary — which would hide every line before it.
        let dir = crate::testutil::TmpDir::new();
        let path = dir.join("logs").join("notes.log");
        let file = open_detach_log(&path).expect("open the session log");
        note_trust_drops(
            &file,
            &[
                ".sbx.toml: ignoring `gpu` posture (untrusted — run `sbx trust`)".to_string(),
                ".sbx.toml: ignoring malformed nixpkgs source `nope`".to_string(),
            ],
            None,
        );
        drop(file);

        let text = std::fs::read_to_string(&path).expect("read the session log back");
        assert!(
            text.contains(
                "=== sbx trust-drop: .sbx.toml: ignoring `gpu` posture \
                 (untrusted — run `sbx trust`) ==="
            ),
            "the dropped security field must survive the terminal that announced it: {text}"
        );
        assert!(
            !text.contains("malformed nixpkgs"),
            "a warning that is not a trust drop is not this record's business: {text}"
        );

        let notes: Vec<&str> = text
            .lines()
            .filter(|l| l.starts_with("=== sbx trust-drop: "))
            .collect();
        assert_eq!(notes.len(), 1, "one note per dropped field: {text}");
        for note in notes {
            assert!(
                parse_session_header(note.as_bytes()).is_none(),
                "a note must not read as a session boundary: {note}"
            );
        }

        // A pid the kernel reuses appends a second session to this same file, and each note must
        // land on its own session's side of the boundary. A reader shows only what follows the
        // last header, so a note written before it would be attributed to the session that ended.
        let file = open_detach_log(&path).expect("reopen the session log");
        note_trust_drops(
            &file,
            &[".sbx.toml: ignoring `forward` ports (untrusted — run `sbx trust`)".to_string()],
            None,
        );
        drop(file);

        let text = std::fs::read_to_string(&path).expect("read back after the second open");
        let shape: Vec<&str> = text
            .lines()
            .map(|l| {
                if parse_session_header(l.as_bytes()).is_some() {
                    "header"
                } else if l.starts_with("=== sbx trust-drop: ") {
                    "note"
                } else {
                    "other"
                }
            })
            .collect();
        assert_eq!(
            shape,
            ["header", "note", "header", "note"],
            "each note must follow its own session's header: {text}"
        );
    }

    #[test]
    fn a_session_header_needs_every_field_to_parse() {
        // A line an agent prints that merely resembles a header must not be taken for one, or its
        // output would be read as a session boundary and hide everything before it.
        assert!(parse_session_header(b"=== sbx session 12 started=99 ===").is_some());
        for lookalike in [
            &b"=== sbx session 12 started=later ==="[..],
            &b"=== sbx session twelve started=99 ==="[..],
            &b"=== sbx session 12 ==="[..],
            &b"=== sbx session 12 started=99"[..],
            &b"plain agent output"[..],
        ] {
            assert!(
                parse_session_header(lookalike).is_none(),
                "must not parse: {}",
                String::from_utf8_lossy(lookalike)
            );
        }
    }

    /// The C strings an `attach_argv` result carries, as UTF-8 for assertion.
    fn argv_strings(argv: &[CString]) -> Vec<String> {
        argv.iter()
            .map(|c| c.to_str().unwrap().to_string())
            .collect()
    }

    #[test]
    fn attach_argv_with_no_command_is_the_interactive_rc_shell() {
        // A bare attach reuses the same rc shell as an interactive `sbx run`, so the joined shell gets mise
        // activation and the `(sbx-<slug>)` prompt.
        let argv = attach_argv(&[]).expect("shell argv builds");
        assert_eq!(
            argv_strings(&argv),
            vec![
                binds::SANDBOX_BASH.to_string(),
                "--rcfile".to_string(),
                binds::SHELL_RC_INCAGE.to_string(),
            ]
        );
    }

    #[test]
    fn install_steps_run_in_order_ahead_of_the_command_and_stop_the_chain_on_failure() {
        // The composition is what makes a bundle's install step reach a launch, and three
        // properties of it are the contract: the steps run in the order they were folded, the app's
        // command runs last and as `exec` (so the app keeps the process, its signals and its exit
        // status), and `&&` joins them so a step that fails never reaches the command.
        let steps = vec![
            crate::config::BundleProvision {
                bundle: "alpha".into(),
                argv: vec!["bash".into(), "-c".into(), "first-step".into()],
            },
            crate::config::BundleProvision {
                bundle: "beta".into(),
                argv: vec!["second-step".into()],
            },
        ];
        let cmd: Vec<OsString> = ["agent", "--flag"].iter().map(OsString::from).collect();

        let out = compose_startup_cmd(&steps, &Default::default(), &[], cmd);
        let script = out[2].to_string_lossy().to_string();
        assert_eq!(out[0], OsString::from("bash"));
        assert_eq!(out[1], OsString::from("-c"));
        assert!(
            script.starts_with("'bash' '-c' 'first-step' && 'second-step' || exit $?\n"),
            "steps run in fold order, each still its own argv, and a failure ends the launch: \
             {script}"
        );
        assert!(
            script.ends_with("exec \"$@\"\n"),
            "the app's command runs last, and as exec: {script}"
        );
        // The app's argv is positional, never pasted into the script: `$0` then the command.
        assert_eq!(
            out[3..],
            [
                OsString::from("sbx"),
                OsString::from("agent"),
                OsString::from("--flag")
            ]
        );
    }

    #[test]
    fn an_install_step_argument_is_data_not_shell_syntax() {
        // A step's own arguments reach the chaining shell as one word each, whatever they contain.
        // Without quoting, a step carrying a space would split into two commands and one carrying a
        // `$` or a backtick would be evaluated — a bundle author writing an argv would be writing
        // shell by accident.
        let steps = vec![crate::config::BundleProvision {
            bundle: "quoting".into(),
            argv: vec![
                "installer".into(),
                "--dir=/opt/a b".into(),
                "$(whoami)".into(),
                "it's".into(),
            ],
        }];
        let out = compose_startup_cmd(
            &steps,
            &Default::default(),
            &[],
            vec![OsString::from("agent")],
        );
        let script = out[2].to_string_lossy().to_string();
        assert!(
            script.starts_with("'installer' '--dir=/opt/a b' '$(whoami)' 'it'\\''s' || exit $?"),
            "every element is one quoted word, an interior quote closed and reopened: {script}"
        );
    }

    /// A `[service]` entry with just an argv, for the start-up composition tests.
    fn service(argv: &[&str]) -> crate::config::ServiceSpec {
        crate::config::ServiceSpec {
            argv: argv.iter().map(|s| (*s).to_string()).collect(),
            enable: Vec::new(),
            ready: None,
        }
    }

    #[test]
    fn a_service_starts_after_the_install_and_before_the_command() {
        // The order is the whole reason install steps and services are composed by one function: a
        // service started before the install that puts its program on PATH would fail on a first
        // launch, and nesting two wrappers would settle that order by accident.
        let steps = vec![crate::config::BundleProvision {
            bundle: "alpha".into(),
            argv: vec!["install-it".into()],
        }];
        let mut services = std::collections::BTreeMap::new();
        services.insert("chroma".to_string(), service(&["chroma", "run"]));

        let out = compose_startup_cmd(&steps, &services, &[], vec![OsString::from("agent")]);
        let script = out[2].to_string_lossy().to_string();
        let install = script.find("install-it").expect("the install step runs");
        let start = script.find("'chroma' 'run'").expect("the service starts");
        let exec = script.find("exec \"$@\"").expect("the command runs");
        assert!(
            install < start && start < exec,
            "install, then service, then command: {script}"
        );
        assert!(
            script.contains(
                "( 'chroma' 'run' ) >>\"${HOME:-/tmp}\"/.sbx-service-chroma.log 2>&1 </dev/null &"
            ),
            "a service is backgrounded with its output in its own log, off the app's terminal: \
             {script}"
        );
    }

    #[test]
    fn a_failed_service_does_not_fail_the_launch_but_a_failed_install_does() {
        // The two are joined differently on purpose. An install that did not finish must never
        // reach the app (it would run against a half-equipped cage); a service that will not start
        // leaves a degraded app, which is the trade the hand-written `nohup` already made — and the
        // app is the thing the person asked for.
        let steps = vec![crate::config::BundleProvision {
            bundle: "alpha".into(),
            argv: vec!["install-it".into()],
        }];
        let mut services = std::collections::BTreeMap::new();
        services.insert("gateway".to_string(), service(&["gateway", "run"]));

        let script = compose_startup_cmd(&steps, &services, &[], vec![OsString::from("agent")])[2]
            .to_string_lossy()
            .to_string();
        assert!(
            script.contains("'install-it' || exit $?"),
            "the install chain ends the launch on failure: {script}"
        );
        let after_install = &script[script.find("|| exit $?").unwrap()..];
        assert!(
            !after_install.contains("exit $?") || after_install.matches("exit $?").count() == 1,
            "nothing after the install chain aborts the launch: {script}"
        );
    }

    #[test]
    fn a_service_argument_is_data_except_a_leading_home_tilde() {
        // One expansion and one only. `~/` is expanded because a service is declared where the
        // home's path cannot be known; everything else stays the characters it was written as, or a
        // profile author writing an argv would be writing shell without meaning to.
        let mut services = std::collections::BTreeMap::new();
        services.insert(
            "chroma".to_string(),
            service(&["chroma", "--path", "~/chroma-data", "--tag", "$(whoami)"]),
        );

        let script = compose_startup_cmd(&[], &services, &[], vec![OsString::from("agent")])[2]
            .to_string_lossy()
            .to_string();
        assert!(
            script.contains("'--path' \"${HOME}\"/'chroma-data'"),
            "a leading `~/` becomes the cage's home, the rest still one quoted word: {script}"
        );
        assert!(
            script.contains("'$(whoami)'"),
            "a `$` is data, not a substitution: {script}"
        );
    }

    /// A `[service]` entry gated on an environment condition.
    fn gated(argv: &[&str], var: &str, equals: bool, value: &str) -> crate::config::ServiceSpec {
        crate::config::ServiceSpec {
            argv: argv.iter().map(|s| (*s).to_string()).collect(),
            enable: vec![crate::config::EnvCondition {
                var: var.to_string(),
                equals,
                values: vec![value.to_string()],
            }],
            ready: None,
        }
    }

    #[test]
    fn an_enable_condition_decides_before_the_script_is_written_not_inside_it() {
        // The runtime switch the field exists for: `--env NAME=value` turns a declared service off
        // for one launch, without editing the profile. It is answered against the environment this
        // launch composed — sbx builds that from a cleared one, so the answer is already known — and
        // a service that fails leaves no trace in the script at all, rather than a shell `if` around
        // a decision that was made before the shell existed.
        let mut services = std::collections::BTreeMap::new();
        services.insert("on-by-default".to_string(), gated(&["a"], "GW", false, "0"));
        services.insert("opt-in".to_string(), gated(&["b"], "EXTRA", true, "on"));

        // Nothing set: an unset variable compares as empty, which is what makes `!= 0` the on-by-
        // default form and `== on` the opt-in one, without anyone setting anything.
        let script = compose_startup_cmd(&[], &services, &[], vec![OsString::from("agent")])[2]
            .to_string_lossy()
            .to_string();
        assert!(
            script.contains("( 'a' )"),
            "`!= 0` is on by default: {script}"
        );
        assert!(
            !script.contains("( 'b' )"),
            "`== on` is off by default: {script}"
        );
        assert!(
            !script.contains("if ["),
            "no condition survives into the script: {script}"
        );

        // Both variables set to flip both conditions, as a `--env` pair would.
        let env = [
            ("GW".to_string(), "0".to_string()),
            ("EXTRA".to_string(), "on".to_string()),
        ];
        let script = compose_startup_cmd(&[], &services, &env, vec![OsString::from("agent")])[2]
            .to_string_lossy()
            .to_string();
        assert!(!script.contains("( 'a' )"), "`!= 0` is off now: {script}");
        assert!(script.contains("( 'b' )"), "`== on` is on now: {script}");
        assert!(
            script.ends_with("exec \"$@\"\n"),
            "a gated-out service changes nothing else about the launch: {script}"
        );
    }

    #[test]
    fn a_list_of_conditions_is_an_and_and_one_failure_is_enough() {
        // What a list promises: every condition holds, or the service does not start. The failing
        // case is the one worth pinning, because a conjunction that started on a partial match
        // would be indistinguishable from an `or` on the profiles that use one condition.
        let mut services = std::collections::BTreeMap::new();
        services.insert(
            "svc".to_string(),
            crate::config::ServiceSpec {
                argv: vec!["daemon".into()],
                enable: vec![
                    crate::config::EnvCondition {
                        var: "A".into(),
                        equals: false,
                        values: vec!["0".into()],
                    },
                    crate::config::EnvCondition {
                        var: "B".into(),
                        equals: true,
                        values: vec!["1".into()],
                    },
                ],
                ready: None,
            },
        );
        let script = |env: &[(String, String)]| {
            compose_startup_cmd(&[], &services, env, vec![OsString::from("agent")])[2]
                .to_string_lossy()
                .to_string()
        };
        let set = |k: &str, v: &str| (k.to_string(), v.to_string());

        assert!(
            script(&[set("B", "1")]).contains("'daemon'"),
            "both hold (A unset compares as empty, which is not `0`)"
        );
        assert!(
            !script(&[]).contains("'daemon'"),
            "the second fails: B is unset, which is not `1`"
        );
        assert!(
            !script(&[set("A", "0"), set("B", "1")]).contains("'daemon'"),
            "the first fails, and one failure is enough"
        );
    }

    #[test]
    fn a_repeated_environment_key_is_answered_with_the_value_the_cage_will_see() {
        // The launch upserts its environment layers in order, so a key set twice reaches the cage
        // with the LAST value. A condition answered from the first would gate on a value that was
        // overwritten before the cage ever started — the `--env` override being exactly the layer
        // that comes last.
        let mut services = std::collections::BTreeMap::new();
        services.insert("svc".to_string(), gated(&["a"], "GW", false, "0"));
        let env = [
            ("GW".to_string(), "1".to_string()),
            ("GW".to_string(), "0".to_string()),
        ];

        let script = compose_startup_cmd(&[], &services, &env, vec![OsString::from("agent")])[2]
            .to_string_lossy()
            .to_string();
        assert!(
            !script.contains("( 'a' )"),
            "the overriding value decides: {script}"
        );
    }

    #[test]
    fn a_readiness_gate_waits_for_the_port_then_starts_the_app_regardless() {
        // The gate exists so the app does not race the service. It must not become a way for a slow
        // auxiliary process to prevent the app from running at all, so expiry is a message on
        // stderr and the launch goes on — which is what the hand-written probe it replaces did.
        let mut services = std::collections::BTreeMap::new();
        services.insert(
            "chroma".to_string(),
            crate::config::ServiceSpec {
                argv: vec!["chroma".into()],
                enable: Vec::new(),
                ready: Some(crate::config::ServiceReady {
                    tcp: 8100,
                    timeout: std::time::Duration::from_secs(15),
                }),
            },
        );

        let script = compose_startup_cmd(&[], &services, &[], vec![OsString::from("agent")])[2]
            .to_string_lossy()
            .to_string();
        assert!(
            script.contains("for _ in $(seq 1 30); do"),
            "the wait polls twice a second for the declared budget: {script}"
        );
        assert!(
            script.contains("if ( exec 3<>/dev/tcp/127.0.0.1/8100 ) 2>/dev/null; then"),
            "readiness is a TCP connect on the cage loopback, needing no extra tool: {script}"
        );
        assert!(
            script.contains("did not answer on port 8100 within 15s — starting anyway"),
            "expiry names the service and continues: {script}"
        );
        assert!(
            script.ends_with("exec \"$@\"\n"),
            "the command still runs after an expired gate: {script}"
        );
    }

    #[test]
    fn attach_argv_with_a_command_runs_it_positionally_through_bash() {
        // The command is passed positionally after `bash -c 'exec "$@"' bash`, so bash resolves it
        // on the cage PATH and execs it in place — and no argument is ever interpreted as shell
        // syntax (the injection guard: a value like `; rm -rf /` is one literal argv element).
        let cmd = vec![
            OsString::from("grep"),
            OsString::from("-n"),
            OsString::from("; rm -rf /"),
        ];
        let argv = attach_argv(&cmd).expect("command argv builds");
        assert_eq!(
            argv_strings(&argv),
            vec![
                binds::SANDBOX_BASH.to_string(),
                "-c".to_string(),
                "exec \"$@\"".to_string(),
                "bash".to_string(),
                "grep".to_string(),
                "-n".to_string(),
                "; rm -rf /".to_string(),
            ]
        );
    }

    #[test]
    fn attach_argv_rejects_a_command_argument_with_an_interior_nul() {
        // A NUL cannot be a C-string argument; it must fail closed rather than truncate the argv.
        use std::os::unix::ffi::OsStrExt;
        let cmd = vec![
            OsString::from("echo"),
            std::ffi::OsStr::from_bytes(b"a\0b").to_os_string(),
        ];
        assert!(attach_argv(&cmd).is_err());
    }
}
