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
use super::egress;
use super::forward;
use super::spec::{NetPolicy, SandboxSpec, TerminalPolicy};
use crate::session::{self, Kind, RecordGuard, Session};
use crate::store::Layout;
use std::collections::BTreeMap;
use std::ffi::{CString, OsString};
use std::fs::File;
use std::io;
use std::io::IsTerminal;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::io::{AsRawFd, FromRawFd};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};
use std::sync::atomic::{AtomicI32, Ordering};
use std::time::{Duration, Instant};

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
        eprintln!("sbx: `sbx run --detach` needs a command (a detached shell has no terminal).");
        return ExitCode::from(2);
    }
    let mut prep = match prepare_with(&ov) {
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
    // only the non-tty foreground path; an interactive terminal (which would fight a TUI for the
    // screen) is warned and watched out-of-band with `sbx proc logs`/`sbx proc live` instead.
    warn_observe_interactive(observe, interactive);

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

/// Warn that `--observe`'s inline stderr feed is not shown for an interactive terminal (it would
/// fight a TUI for the screen), pointing at the out-of-band viewers instead. Observation itself still
/// runs — the ring and its control socket are populated so `sbx proc logs`/`sbx proc live` can watch
/// this session from another terminal; only the inline echo is suppressed, and that decision is made
/// per launch path where the observer is started (interactive/detached never echo inline). Shared by
/// `run`/`app`.
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

fn warn_observe_interactive(observe: bool, interactive: bool) {
    if observe && interactive {
        crate::diag::warn(
            "--observe's inline feed is not shown for an interactive terminal — watch this session \
             with `sbx proc logs`/`sbx proc live` from another terminal",
        );
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
            eprintln!("sbx: {e}");
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
    if let crate::config::NetworkPolicy::Allowlist(policy) = network {
        if policy.default_action() == DefaultAction::Ask && policy.ask_timeout().is_none() {
            crate::diag::warn(
                "`ask` egress under --detach with no `ask_timeout`: a background session has no \
                 terminal to prompt, so an undecided request parks indefinitely. Set \
                 `[network] ask_timeout`, or answer it with `sbx net pending`.",
            );
        }
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

    register(prep.layout.data_dir(), &spec, kind, runtime);

    match guard {
        // The default postures with no observation: exec-replace, so the command's exit status
        // becomes sbx's. The pid and its start time survive the exec, so the registry record keeps
        // matching the sandbox and is reclaimed by liveness pruning once it exits.
        None if !observe => {
            // On success this never returns; reaching past it means exec itself failed.
            let err = exec(&prep.bwrap, &spec, &prep.cfg.limits);
            eprintln!("sbx: failed to launch the sandbox: {err}");
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
        eprintln!(
            "sbx: cannot create the detach pipe: {}",
            io::Error::last_os_error()
        );
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
            eprintln!(
                "sbx: cannot start the detached session: {}",
                io::Error::last_os_error()
            );
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
    register(prep.layout.data_dir(), &spec, kind, runtime);

    // Open the session log before signalling ready: a daemon whose output we cannot capture is
    // not ready. Its name is keyed by this process's pid — the session id the parent reports.
    let log_path = detach_log_path(prep.layout.data_dir(), std::process::id());
    let log = match open_detach_log(&log_path) {
        Ok(f) => f,
        Err(e) => {
            eprintln!(
                "sbx: cannot open the session log {}: {e}",
                log_path.display()
            );
            fail_detached(write_fd);
        }
    };

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
            eprintln!("sbx: failed to launch the sandbox: {err}");
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
        eprintln!(
            "sbx: started `{label}` as detached session {child} (logs: {})",
            log.display()
        );
        eprintln!(
            "sbx: `sbx session ls` lists it, `sbx session attach {child}` opens a shell inside its live cage, \
             `sbx session stop {child}` ends it."
        );
        ExitCode::SUCCESS
    } else {
        // The daemon closed the pipe without signalling success: it failed before launch (the
        // error is already on this terminal). Reap it.
        // SAFETY: `waitpid` on our own child.
        unsafe { libc::waitpid(child, std::ptr::null_mut(), 0) };
        eprintln!("sbx: the detached session failed to start (see the error above).");
        ExitCode::FAILURE
    }
}

/// The detached session's log file: `<data>/logs/<pid>.log`, keyed by the daemon's pid (the
/// session id). Shared by the daemon (which writes it) and the parent (which reports its path).
fn detach_log_path(data_dir: &Path, pid: u32) -> PathBuf {
    data_dir.join("logs").join(format!("{pid}.log"))
}

/// Open (creating, owner-only, appending) the detached session's log, making `<data>/logs` if
/// absent. Append so a reused pid's log is added to rather than truncating a still-relevant one.
fn open_detach_log(path: &Path) -> io::Result<File> {
    use std::fs::{DirBuilder, OpenOptions};
    use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
    if let Some(parent) = path.parent() {
        DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(parent)?;
    }
    OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .open(path)
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

/// `sbx app <name>`: launch the named application profile — the project sandbox baseline
/// plus the app's gated overlay, running the command the app declares. Apps run in the same
/// locked-down posture as `sbx run`; the overlay's security fields took effect only if their
/// source was trusted (the global config or a trusted project), so launching an app on
/// untrusted code is as safe as `sbx run` there.
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

#[allow(clippy::too_many_arguments)]
pub(crate) fn app(
    name: &str,
    detach: bool,
    observe: bool,
    extra: Vec<OsString>,
    ov: crate::config::Override,
    net_learn: Option<super::Granularity>,
) -> AppOutcome {
    let mut prep = match prepare_with(&ov) {
        Ok(p) => p,
        Err(code) => return AppOutcome::plain(code),
    };
    let Some(app) = prep.cfg.apps.remove(name) else {
        eprintln!("sbx: no app named `{name}`.{}", available_apps(&prep.cfg));
        return AppOutcome::plain(ExitCode::from(2));
    };
    if app.cmd.is_empty() {
        eprintln!(
            "sbx: app `{name}` declares no command — add a `cmd` to its `[app.{name}]` table."
        );
        return AppOutcome::plain(ExitCode::FAILURE);
    }
    // The argv and the home scope are owned by the app; read them before the overlay is folded
    // in (which moves the app but does not touch them). The scope keys this app's persistent
    // home: one shared across projects (`Global`) or one per project (`Project`). Any trailing
    // `sbx app <name> -- <args>` are appended to the declared `cmd`, so the caller can pass a flag
    // to the launched program (e.g. `-c` to resume) without editing the profile.
    let mut cmd: Vec<OsString> = app.cmd.iter().map(OsString::from).collect();
    cmd.extend(extra);
    let runtime = match app.home_scope {
        crate::config::AppHomeScope::Global => binds::Runtime::GlobalApp(name),
        crate::config::AppHomeScope::Project => binds::Runtime::ProjectApp(name),
    };
    eprintln!("sbx: launching app `{name}`");
    prep.cfg.merge_app(app);
    // The override is the authoritative final word — applied *after* the app overlay so a one-shot
    // `sbx app <name> --config …`/`SBX_*` beats the app's own posture, not the other way round.
    if let Err(code) = apply_launch_override(&mut prep.cfg, ov) {
        return AppOutcome::plain(code);
    }

    // SAFETY: `isatty` only inspects fd 0.
    let interactive = !detach && unsafe { libc::isatty(0) } == 1;
    warn_observe_interactive(observe, interactive);

    // `--net-learn`: run the app under its real (unchanged) posture, capture the egress it was
    // refused for lack of a rule, and hand the synthesized rules back for the caller to write. It is
    // foreground-only (the parser refuses `--detach`) and needs a filtering posture — a `shared` or
    // `none` app has no proxy logging egress, so there is nothing to learn.
    if let Some(gran) = net_learn {
        let policy = match &prep.cfg.network {
            crate::config::NetworkPolicy::Allowlist(p) => p.clone(),
            other => {
                eprintln!(
                    "sbx: --net-learn needs a filtering network posture (mode allow/deny/ask); \
                     app `{name}` has `{}` — nothing logs egress to learn from.",
                    network_posture_name(other)
                );
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
    let record = register(prep.layout.data_dir(), &spec, kind, runtime);
    let _record = interactive.then(|| record.map(RecordGuard::new));

    let code = if interactive {
        let gui = matches!(prep.cfg.gui, crate::config::GuiPolicy::Wayland);
        match supervise(&prep.bwrap, &spec, &prep.cfg.limits, gui) {
            Ok(c) => ExitCode::from(c as u8),
            Err(e) => {
                eprintln!("sbx: sandbox session failed: {e}");
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
fn mise_package_groups(cfg: &crate::config::Resolved) -> Vec<MiseGroup> {
    let mut groups = Vec::new();

    // The project baseline, equipped in the default shell home.
    let baseline = super::packages::mise_packages(&cfg.packages);
    if !baseline.is_empty() {
        groups.push(MiseGroup {
            home: GroupHome::ProjectDefault,
            cfg: cfg.clone(),
            tokens: baseline,
        });
    }

    // Each app, in its own home. Merging folds the baseline packages in (an app's cage equips
    // both layers), so the token set is exactly the one the app's launch equips.
    for (name, app) in &cfg.apps {
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
fn withheld_mise_packages(cfg: &crate::config::Resolved) -> usize {
    let untrusted_mise = |pkgs: &[crate::config::Package]| {
        pkgs.iter()
            .filter(|p| {
                matches!(p.backend, crate::config::Backend::Mise(_))
                    && p.state != crate::trust::TrustState::Trusted
            })
            .count()
    };
    untrusted_mise(&cfg.packages)
        + cfg
            .apps
            .values()
            .map(|app| untrusted_mise(&app.packages))
            .sum::<usize>()
}

/// Roll the project's and its apps' `mise:` `[packages]` forward, in-cage. A `mise:` package is
/// equipped by `mise use -g <token>` at launch and then frozen at the installed version (the
/// floating `latest` request stays satisfied, so a later launch does not re-resolve), so
/// advancing it means running `mise upgrade <token>` in the same cage — the equip environment,
/// so the fetch rides the app's egress allowlist. Generic over [`mise_package_groups`]: the
/// project baseline (its default home) and each app (its own home), no app special-cased.
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
    cfg: &crate::config::Resolved,
    pal: &crate::style::Palette,
) -> bool {
    let (h, n, warn, dim, r) = (pal.head, pal.name, pal.warn, pal.dim, pal.reset);
    println!("{h}sbx upgrade — mise packages{r}");
    let groups = mise_package_groups(cfg);
    // Surface withheld (untrusted) `mise:` packages so an untrusted project does not silently
    // read as "nothing declared" — parity with the `nix:` tools path, which warns the same.
    let withheld = withheld_mise_packages(cfg);
    if withheld > 0 {
        println!(
            "  {warn}{withheld} mise: package(s) withheld (untrusted){r} — not rolled; run `sbx trust`."
        );
    }
    if groups.is_empty() {
        if withheld == 0 {
            println!("  {dim}no mise: packages to roll.{r}");
        }
        return true;
    }

    // Only now, with groups to roll, take on the sandbox prerequisites.
    let mut prep = match prepare() {
        Ok(p) => p,
        Err(_) => {
            // prepare() already printed the pointed reason (missing bwrap/userns/nix).
            crate::diag::warn("mise packages: skipped — no usable sandbox; see `sbx doctor`");
            return true;
        }
    };

    let mut ok = true;
    for group in groups {
        let MiseGroup { home, cfg, tokens } = group;
        let label = home.label();
        // `network = "none"` cannot fetch — the launch skips the equip there — so skip the roll
        // too (the tool stays at its persisted version). Not a failure: it is the declared posture.
        if matches!(cfg.network, crate::config::NetworkPolicy::Isolated) {
            println!("  [{n}{label}{r}] network = \"none\" — cannot fetch, {dim}skipped.{r}");
            continue;
        }
        println!("  [{n}{label}{r}] mise upgrade {n}{}{r}", tokens.join(", "));

        // Launch a cage in this group's home with its merged config so `build` sees the right
        // network/packages/home. The baseline warnings were already surfaced by `upgrade_cmd`,
        // so clear them to avoid one repeat per cage. The command is `mise upgrade <tokens>`; the
        // launch's own `mise use -g` equip wrap runs first (a warm no-op once installed, or a
        // fresh equip if the app was never launched), then the upgrade rolls the version.
        let runtime = home.runtime();
        let mut cfg = cfg;
        cfg.warnings.clear();
        prep.cfg = cfg;

        let mut cmd = vec![
            prep.userland.mise_bin.clone().into_os_string(),
            OsString::from("upgrade"),
        ];
        cmd.extend(tokens.iter().map(OsString::from));

        let (spec, guard) = match build(&prep, runtime, cmd) {
            Ok(v) => v,
            Err(_) => {
                ok = false;
                continue;
            }
        };
        // Fork-and-wait (never exec-replace) so the next group can run; the guard, if any, is
        // held across the wait so the proxy/forwarder serves the fetch, then dropped as the group
        // ends (unlinks the sockets and CA).
        let code = run_status(&prep.bwrap, &spec, &prep.cfg.limits);
        drop(guard);
        if code != 0 {
            crate::diag::warn(&format!("`{label}`: mise upgrade exited {code}"));
            ok = false;
        }
    }
    ok
}

/// `sbx gc [--all] [--prune]`: reclaim sbx's store space.
///
/// By default it sweeps the **current** project's store (see [`sweep_current`]). With `--all` it
/// also, across all projects: reaps whole runtime trees whose project directory is gone (see
/// [`reap_dead_trees`]), then garbage-collects the **shared** store — the channel revisions left
/// behind by `sbx upgrade` and the tools of reaped projects (see [`shared_store_gc`]). The
/// cross-project passes run **first** and are independent of the sandbox/nix prerequisites the
/// current-project sweep needs — so `sbx gc --all` reclaims even from a directory that is not a
/// project, or on a host that has lost its sandbox capability. A dry run by default; `--prune` is
/// the destructive form.
pub(crate) fn gc(prune: bool, all: bool, pal: &crate::style::Palette) -> ExitCode {
    if all {
        match crate::store::Layout::from_env() {
            Some(layout) => {
                // Prune stale session records, then collect the shared store. Reaping whole
                // per-project runtime *trees* is `sbx projects rm`; `--all` here is purely the
                // nix-store side — the shared store's orphaned closures across every project.
                let _ = session_housekeeping(&layout, pal);
                shared_store_gc(&layout, prune, pal);
            }
            None => eprintln!(
                "sbx gc: cannot locate sbx's data directory; skipping the shared-store housekeeping."
            ),
        }
    }
    match sweep_current(prune, pal) {
        Ok(()) => ExitCode::SUCCESS,
        // Under `--all` the shared-store collection above already ran, so a current-project sweep
        // that could not run (the host cannot sandbox, nix is unavailable) — or that hit an error —
        // must not fail the whole command. Its own message is already printed above; only the exit
        // code is flattened.
        Err(_) if all => {
            eprintln!(
                "sbx gc: the current project's store was not swept (see above); the shared-store collection ran."
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
fn session_housekeeping(
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
            eprintln!(
                "sbx gc: cannot read the session registry ({e}); skipping session housekeeping."
            );
            std::collections::BTreeSet::new()
        }
    }
}

/// Reap — or, in a dry run, list — the runtime trees under `<data>/projects/` whose project
/// directory is gone, plus surface any markerless legacy trees. A tree is reclaimed only when it
/// carries a `project` marker, that path is absent while its parent directory still exists (a cheap
/// guard, not a reliable unmount check — the dry-run default is the backstop there), and no live
/// session holds it. Markerless trees (their project path unknown) are listed for a manual decision
/// by default; `prune_unidentified` opts into reaping them without a deadness proof (the
/// `--markerless` escape hatch). Pure host-side filesystem work — no sandbox, no nix. This drives
/// the bulk `sbx projects rm --dead` / `--markerless` sweeps.
fn reap_dead_trees(
    layout: &crate::store::Layout,
    live_ids: &std::collections::BTreeSet<String>,
    prune: bool,
    prune_unidentified: bool,
    pal: &crate::style::Palette,
) {
    let (h, n, ok, warn, dim, r) = (pal.head, pal.name, pal.ok, pal.warn, pal.dim, pal.reset);
    let projects_dir = layout.data_dir().join("projects");
    let report = super::gc::reap_dead_projects(&projects_dir, live_ids, prune, prune_unidentified);
    if report.dead.is_empty()
        && report.unidentified.is_empty()
        && report.reaped_unidentified.is_empty()
    {
        println!("{h}sbx projects rm:{r} {dim}no dead project trees to reclaim.{r}");
        return;
    }

    let mut freed = 0u64;
    for tree in &report.dead {
        freed += tree.bytes;
        // Done (green) when actually reclaimed; a dry-run "reclaimable" is dim (nothing changed).
        let verb = if prune {
            format!("{ok}reclaimed{r}")
        } else {
            format!("{dim}reclaimable{r}")
        };
        println!(
            "  {verb}: {n}{}{r} ({})",
            tree.path.display(),
            super::gc::human_bytes(tree.bytes)
        );
    }
    if !report.dead.is_empty() {
        if prune {
            println!(
                "{h}sbx projects rm:{r} reclaimed {} dead project tree(s), freed up to {}.",
                report.dead.len(),
                super::gc::human_bytes(freed)
            );
        } else {
            println!(
                "{h}sbx projects rm:{r} {} dead project tree(s) reclaimable (up to {}) — \
                 run `sbx projects rm --dead --yes` to reclaim.",
                report.dead.len(),
                super::gc::human_bytes(freed)
            );
        }
    }

    // Markerless trees reaped under the `--markerless` opt-in. Their deadness was NOT verified
    // (the marker is absent, so the project path is unknown) — the caller accepted that risk. They
    // are gone now, so report them as reclaimed rather than as candidates.
    let mut ufreed = 0u64;
    for tree in &report.reaped_unidentified {
        ufreed += tree.bytes;
        println!(
            "  {ok}reclaimed{r} {warn}(no marker, deadness unverified){r}: {n}{}{r} ({})",
            tree.dir.display(),
            super::gc::human_bytes(tree.bytes)
        );
    }
    if !report.reaped_unidentified.is_empty() {
        println!(
            "{h}sbx projects rm --markerless:{r} reclaimed {} markerless tree(s), freed up to {}.",
            report.reaped_unidentified.len(),
            super::gc::human_bytes(ufreed)
        );
    }

    // Markerless trees not reaped (no opt-in, or a dry run): surfaced for a manual decision. The
    // hint adapts to whether the user is using the `--markerless` hatch — a dry run of it points
    // at the apply form, the default still points at a by-hand removal (the fail-closed stance).
    for tree in &report.unidentified {
        let hint = if prune_unidentified {
            "run `sbx projects rm --markerless --yes` to reclaim (no deadness proof)"
        } else {
            "remove by hand if unwanted"
        };
        println!(
            "  {warn}unidentified{r} (no marker, project path unknown): {n}{}{r} ({}) — {hint}",
            tree.dir.display(),
            super::gc::human_bytes(tree.bytes)
        );
    }
}

/// One per-project runtime tree, classified and sized, for `sbx projects [list]`.
#[derive(serde::Serialize)]
struct ProjectTreeView {
    /// The tree's directory name under `<data>/projects/` — the id `sbx projects rm` takes.
    id: String,
    /// `live` (a running session holds it), `idle` (its project still exists), `dead` (the project
    /// directory is gone), or `markerless` (a legacy tree pre-dating marker recording).
    state: &'static str,
    /// On-disk size in bytes (an upper bound — reflinked content shared with another tree counts
    /// per file).
    bytes: u64,
    /// The `bytes` figure rendered human-readably (the text listing shows this).
    size: String,
    /// `YYYY-MM-DD` of the last launch (the marker's mtime), else the tree directory's mtime.
    last_used: String,
    /// The canonical project path the tree belongs to, when it carries a marker.
    project: Option<String>,
    /// Whether this tree is the current working directory's project (marked `*` in the listing).
    current: bool,
}

/// The project id of the current working directory, so the tree you are standing in can be marked
/// `*` in the listing and guarded against an accidental `sbx projects rm <that-id>`. Best-effort:
/// `None` when the cwd cannot be read or canonicalized. Hashed the way a launch hashes its cwd, so
/// the value matches the runtime tree's directory name.
fn current_tree_id() -> Option<String> {
    let cwd = std::env::current_dir().ok()?;
    let canonical = cwd.canonicalize().ok()?;
    Some(binds::project_id(&canonical))
}

/// Gather the per-project runtime trees under `<data>/projects/`, classified and sized, sorted by
/// id — the shared core of `sbx projects [list]` (text or JSON). Live ids come from the session
/// registry (the same self-healing housekeep `sbx session ls` runs), so a tree in use reads `live`. Pure
/// host-side filesystem work — no sandbox, no nix.
fn collect_project_trees(
    layout: &crate::store::Layout,
    pal: &crate::style::Palette,
) -> Vec<ProjectTreeView> {
    let live_ids = session_housekeeping(layout, pal);
    let current = current_tree_id();
    let projects_dir = layout.data_dir().join("projects");
    let mut rows: Vec<ProjectTreeView> = match std::fs::read_dir(&projects_dir) {
        Ok(rd) => rd
            .flatten()
            .filter(|e| e.file_type().map(|t| t.is_dir()).unwrap_or(false))
            .map(|e| {
                let dir = e.path();
                let id = e.file_name().to_string_lossy().into_owned();
                let class = super::gc::classify_tree(&dir, &live_ids);
                let bytes = super::gc::tree_size(&dir);
                ProjectTreeView {
                    current: current.as_deref() == Some(id.as_str()),
                    id,
                    state: class.state.label(),
                    bytes,
                    size: super::gc::human_bytes(bytes),
                    last_used: crate::paths::civil_date(class.last_used),
                    project: class.project_path.map(|p| p.display().to_string()),
                }
            })
            .collect(),
        Err(_) => Vec::new(),
    };
    rows.sort_by(|a, b| a.id.cmp(&b.id));
    rows
}

/// The realized nix store roots of a project tree, grouped by backend, for `sbx projects show`.
#[derive(serde::Serialize, Default)]
struct StoreRootsView {
    /// `nix:` packages and hole provisions — the gcroot names that are not a prebuilt build output.
    nix: Vec<String>,
    /// `deb:` build outputs (the `deb-` gcroots, prefix stripped).
    deb: Vec<String>,
    /// `appimage:` build outputs (the `appimage-` gcroots, prefix stripped).
    appimage: Vec<String>,
}

/// A mise tool realized in the project's own home, for `sbx projects show`.
#[derive(serde::Serialize)]
struct ProjToolView {
    /// The on-disk (munged) tool directory name.
    name: String,
    versions: Vec<String>,
}

/// A declared item the project has not realized yet — `sbx projects show`'s "declared but not built"
/// section — distinguishing an untrusted `withheld` item (a launch would not provision it) from a
/// trusted one simply not built yet (an offline first launch equips it).
#[derive(serde::Serialize)]
struct UnbuiltView {
    /// `nix`/`deb`/`appimage`/`flake`/`mise` for a `[packages]` backend, or `nix tool`/`mise tool`
    /// for a mise `[tools]` entry.
    kind: String,
    locator: String,
    withheld: bool,
}

/// The nixpkgs channel/revision a project resolves against, for `sbx projects show`.
#[derive(serde::Serialize)]
struct NixpkgsView {
    source: String,
    rev: String,
    /// `true` when the tree carries its own pin, `false` when it tracks the global channel.
    per_project: bool,
}

/// The `sbx projects show` model — serialized directly for `--json`.
#[derive(serde::Serialize)]
struct ProjectShowView {
    id: String,
    state: &'static str,
    /// The canonical project path the tree belongs to, when it carries a marker.
    project: Option<String>,
    last_used: String,
    total_bytes: u64,
    store_bytes: u64,
    home_bytes: u64,
    other_bytes: u64,
    nixpkgs: Option<NixpkgsView>,
    store_roots: StoreRootsView,
    mise_tools: Vec<ProjToolView>,
    unbuilt: Vec<UnbuiltView>,
    /// Whether the project directory still exists, so its declared config could be read (a dead tree
    /// shows realized state only — there is nothing left to compare against).
    config_available: bool,
}

/// Show one project runtime tree's realized-on-disk detail — `sbx projects show <id>`. Reports the
/// tree's state and size (broken down store/home/other), the nixpkgs pin it resolves against, the
/// store roots realized in its (shared) store grouped by backend, the mise tools in its own home,
/// and — when the project directory still exists — the project's declared packages/tools that are
/// **not** built yet (an untrusted one flagged `withheld`). Read-only: no sandbox, no nix, no
/// network. The counterpart of `sbx app show` for a project rather than an app.
pub(crate) fn projects_show(id: &str, json: bool, pal: &crate::style::Palette) -> ExitCode {
    use crate::config::Backend;

    let Some(layout) = crate::store::Layout::from_env() else {
        eprintln!("sbx projects show: cannot locate sbx's data directory.");
        return ExitCode::FAILURE;
    };
    let data = layout.data_dir();
    let dir = data.join("projects").join(id);
    if !dir.is_dir() {
        eprintln!(
            "sbx projects show: no runtime tree `{id}` — run `sbx projects list` to see them."
        );
        return ExitCode::FAILURE;
    }

    let live_ids = session_housekeeping(&layout, pal);
    let class = super::gc::classify_tree(&dir, &live_ids);

    let total_bytes = super::gc::tree_size(&dir);
    let store_bytes = super::gc::tree_size(&dir.join("store"));
    let home_bytes = super::gc::tree_size(&dir.join("home"));
    let other_bytes = total_bytes
        .saturating_sub(store_bytes)
        .saturating_sub(home_bytes);

    // Realized signals, read once from the tree.
    let gcroots = super::inspect::gcroot_names(data, id);
    let gcroot_set: std::collections::BTreeSet<&str> = gcroots.iter().map(String::as_str).collect();
    let tools_locked = super::inspect::nix_tools_locked(&dir);
    let home_tools = super::inspect::mise_installed(&dir.join("home"));
    let nixpkgs =
        super::inspect::nixpkgs_pin(&dir, data).map(|(source, rev, per_project)| NixpkgsView {
            source,
            rev,
            per_project,
        });

    // Group the store roots: `deb-`/`appimage-` are prebuilt build outputs; everything else is a
    // `nix:` package (or a hole provision realized into the shared store).
    let mut store_roots = StoreRootsView::default();
    for name in &gcroots {
        if let Some(rest) = name.strip_prefix("deb-") {
            store_roots.deb.push(rest.to_string());
        } else if let Some(rest) = name.strip_prefix("appimage-") {
            store_roots.appimage.push(rest.to_string());
        } else {
            store_roots.nix.push(name.clone());
        }
    }

    let mise_tools: Vec<ProjToolView> = home_tools
        .iter()
        .map(|t| ProjToolView {
            name: t.label().to_string(),
            versions: super::inspect::concrete_versions(t),
        })
        .collect();

    // "Declared but not built": the project's own declared packages + mise tools that no realized
    // signal accounts for. Only computable when the project directory still exists (a dead tree has
    // no config to read). Untrusted declarations read `withheld` — a launch would not provision them.
    let project = class.project_path.as_ref().map(|p| p.display().to_string());
    let config_available = class
        .project_path
        .as_deref()
        .map(Path::is_dir)
        .unwrap_or(false);
    let mut unbuilt = Vec::new();
    if let Some(ppath) = class.project_path.as_deref().filter(|p| p.is_dir()) {
        let resolved = crate::config::load(ppath);
        for pkg in &resolved.packages {
            let realized = match &pkg.backend {
                Backend::Mise(token) => home_tools.iter().any(|t| t.is(token)),
                Backend::Nix(_) => gcroot_set.contains(pkg.name.as_str()),
                Backend::Deb(_) => gcroot_set.contains(format!("deb-{}", pkg.name).as_str()),
                Backend::AppImage(_) => {
                    gcroot_set.contains(format!("appimage-{}", pkg.name).as_str())
                }
                Backend::Tarball(_) => {
                    gcroot_set.contains(format!("tarball-{}", pkg.name).as_str())
                }
                // A `flake:` build lands in the project home (like mise), not the store — and a
                // floating flake has no lock — so the warm out-link is its realized signal.
                Backend::Flake(_) => {
                    super::inspect::flake_built(&dir.join("home"), &pkg.name).is_some()
                }
                Backend::FlakeInline { .. } => gcroot_set.contains(pkg.name.as_str()),
            };
            if !realized {
                unbuilt.push(UnbuiltView {
                    kind: pkg.backend.label().to_string(),
                    locator: format!("{} = {}", pkg.name, pkg.backend.locator()),
                    withheld: pkg.state != crate::trust::TrustState::Trusted,
                });
            }
        }
        // Declared mise `[tools]`: a `nix:` tool is host-provisioned (trusted-only), recorded in
        // tools.lock; any other backend is auto-equipped in-cage into the project home. A withheld
        // `nix:` tool is one the (untrusted) mise config would not have provisioned.
        if let Some(mise) = resolved.mise.as_ref() {
            let mise_trusted = mise.state == crate::trust::TrustState::Trusted;
            let declared = super::nixhub::parse_nix_tools(&mise.files);
            for tool in &declared.nix {
                if !tools_locked.contains_key(&tool.pkg) {
                    unbuilt.push(UnbuiltView {
                        kind: "nix tool".to_string(),
                        locator: format!("nix:{} = {}", tool.pkg, tool.version),
                        withheld: !mise_trusted,
                    });
                }
            }
            for tool in &declared.non_nix {
                if !home_tools.iter().any(|t| t.is(&tool.token)) {
                    unbuilt.push(UnbuiltView {
                        kind: "mise tool".to_string(),
                        locator: format!("{} = {}", tool.token, tool.version),
                        withheld: false,
                    });
                }
            }
        }
    }

    let view = ProjectShowView {
        id: id.to_string(),
        state: class.state.label(),
        project,
        last_used: crate::paths::civil_date(class.last_used),
        total_bytes,
        store_bytes,
        home_bytes,
        other_bytes,
        nixpkgs,
        store_roots,
        mise_tools,
        unbuilt,
        config_available,
    };

    if json {
        return match serde_json::to_string_pretty(&view) {
            Ok(doc) => {
                println!("{doc}");
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("sbx projects show: failed to serialize: {e}");
                ExitCode::FAILURE
            }
        };
    }
    print!("{}", render_project_show(&view, pal));
    ExitCode::SUCCESS
}

/// Render the `sbx projects show` model — a pure presenter (every color span is empty under a
/// non-terminal, so captured output is the plain text the tests pin).
fn render_project_show(v: &ProjectShowView, pal: &crate::style::Palette) -> String {
    use std::fmt::Write;
    let (h, n, ok, warn, dim, r) = (pal.head, pal.name, pal.ok, pal.warn, pal.dim, pal.reset);
    let mut s = String::new();
    let _ = writeln!(s, "{h}project{r} {n}{}{r}  {}", v.id, v.state);
    match &v.project {
        Some(p) => {
            let _ = writeln!(s, "  path:     {p}");
        }
        None => {
            let _ = writeln!(s, "  path:     {dim}(no marker — project path unknown){r}");
        }
    }
    let _ = writeln!(s, "  last:     {dim}{}{r}", v.last_used);
    let _ = writeln!(
        s,
        "  disk:     {}  {dim}(store {} · home {} · other {}){r}",
        super::gc::human_bytes(v.total_bytes),
        super::gc::human_bytes(v.store_bytes),
        super::gc::human_bytes(v.home_bytes),
        super::gc::human_bytes(v.other_bytes),
    );
    match &v.nixpkgs {
        Some(np) => {
            let scope = if np.per_project {
                "per-project pin"
            } else {
                "global channel"
            };
            let _ = writeln!(
                s,
                "  nixpkgs:  {} @ {}  {dim}({scope}){r}",
                np.source, np.rev
            );
        }
        None => {
            let _ = writeln!(s, "  nixpkgs:  {dim}(no lock recorded){r}");
        }
    }
    // Store roots realized in the (shared) per-project store.
    let roots_empty = v.store_roots.nix.is_empty()
        && v.store_roots.deb.is_empty()
        && v.store_roots.appimage.is_empty();
    if roots_empty {
        let _ = writeln!(s, "  store roots: {dim}none{r}");
    } else {
        let _ = writeln!(
            s,
            "  store roots {dim}(built in this project's store, shared by its apps):{r}"
        );
        let mut row = |label: &str, items: &[String]| {
            if !items.is_empty() {
                let _ = writeln!(s, "    {label:<9} {n}{}{r}", items.join(", "));
            }
        };
        row("nix", &v.store_roots.nix);
        row("deb", &v.store_roots.deb);
        row("appimage", &v.store_roots.appimage);
    }
    // mise tools in the project's own home.
    if !v.mise_tools.is_empty() {
        let _ = writeln!(s, "  mise tools {dim}(project home):{r}");
        for t in &v.mise_tools {
            let versions = t.versions.join(", ");
            let suffix = if versions.is_empty() {
                String::new()
            } else {
                format!("  {dim}{versions}{r}")
            };
            let _ = writeln!(s, "    {n}{}{r}{suffix}", t.name);
        }
    }
    // Declared-but-not-built (the useful direction of declared-vs-installed).
    if !v.config_available {
        let _ = writeln!(
            s,
            "  {dim}(project directory is gone — showing realized state only){r}"
        );
    } else if v.unbuilt.is_empty() {
        let _ = writeln!(
            s,
            "  declared: {ok}all declared packages/tools are built{r}"
        );
    } else {
        let _ = writeln!(s, "  declared but not built:");
        for u in &v.unbuilt {
            let (tag, hue) = if u.withheld {
                ("withheld (untrusted — run `sbx trust`)", warn)
            } else {
                ("not built yet", dim)
            };
            let _ = writeln!(s, "    {n}{}{r} {}  {hue}{tag}{r}", u.kind, u.locator);
        }
    }
    s
}

/// List the per-project runtime trees — `sbx projects` / `sbx projects list`. A read-only overview
/// (richer than `sbx path`'s projects section: it adds each tree's on-disk size), in aligned text
/// or `--json`.
pub(crate) fn projects_list(json: bool, pal: &crate::style::Palette) -> ExitCode {
    let Some(layout) = crate::store::Layout::from_env() else {
        eprintln!("sbx projects: cannot locate sbx's data directory.");
        return ExitCode::FAILURE;
    };
    let rows = collect_project_trees(&layout, pal);

    if json {
        return match serde_json::to_string_pretty(&rows) {
            Ok(s) => {
                println!("{s}");
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("sbx projects: failed to serialize: {e}");
                ExitCode::FAILURE
            }
        };
    }

    let (h, n, dim, r) = (pal.head, pal.name, pal.dim, pal.reset);
    if rows.is_empty() {
        println!("{h}sbx projects{r} {dim}— no per-project runtime trees.{r}");
        return ExitCode::SUCCESS;
    }
    let total: u64 = rows.iter().map(|row| row.bytes).sum();
    println!(
        "{h}sbx projects{r} {dim}({} tree(s), {}){r}",
        rows.len(),
        super::gc::human_bytes(total)
    );
    let state_w = rows.iter().map(|row| row.state.len()).max().unwrap_or(0);
    let size_w = rows.iter().map(|row| row.size.len()).max().unwrap_or(0);
    for row in &rows {
        let state = format!("{:<state_w$}", row.state);
        let size = format!("{:>size_w$}", row.size);
        let mark = if row.current {
            format!("  {n}*{r}")
        } else {
            String::new()
        };
        let path = row.project.as_deref().unwrap_or("(no marker)");
        println!(
            "  {n}{id}{r}  {state}  {size}  {dim}{last}{r}  {path}{mark}",
            id = row.id,
            last = row.last_used,
        );
    }
    println!(
        "{dim}remove one with `sbx projects rm <id>`; sweep dead trees with `sbx projects rm --dead --yes`.{r}"
    );
    ExitCode::SUCCESS
}

/// Decide whether `sbx projects rm` applies the removal or only previews it. A *targeted* removal
/// (ids named, no bulk selector) applies immediately — naming the id is the intent, like `rm`; a
/// *bulk* selector (`--dead`/`--markerless`) previews by default and requires `--yes`. `--dry-run`
/// forces a preview, `--yes` forces apply; the two together are contradictory (`None`).
pub(crate) fn rm_apply(targeted: bool, bulk: bool, dry_run: bool, yes: bool) -> Option<bool> {
    if dry_run && yes {
        return None;
    }
    if dry_run {
        return Some(false);
    }
    if yes {
        return Some(true);
    }
    Some(targeted && !bulk)
}

/// Whether `sbx projects rm <id>` must refuse `id` because it is the tree of the current working
/// directory — deleting the store and home you are standing in — unless `--force` overrides it.
/// `current` is [`current_tree_id`]; `None` (cwd unresolvable) never guards.
fn rm_refuses_current(id: &str, current: Option<&str>, force: bool) -> bool {
    !force && current == Some(id)
}

/// Remove named project trees and/or sweep the dead/markerless ones — `sbx projects rm`. Each named
/// id is reaped through the shared [`super::gc::reap_one`] (no deadness proof — naming the id is the
/// proof), the bulk selectors through [`reap_dead_trees`]; a live-held tree is always refused, and
/// the current project is refused without `--force`. `apply` gates the actual deletion (a preview
/// otherwise). With `--gc`, the shared-store collection runs after a real removal to reclaim the
/// now-orphaned closures. Pure host-side filesystem work (bar the optional `--gc`) — no sandbox.
#[allow(clippy::too_many_arguments)]
pub(crate) fn projects_rm(
    ids: &[String],
    dead: bool,
    markerless: bool,
    apply: bool,
    do_gc: bool,
    force: bool,
    pal: &crate::style::Palette,
) -> ExitCode {
    let (h, n, ok, dim, r) = (pal.head, pal.name, pal.ok, pal.dim, pal.reset);
    let Some(layout) = crate::store::Layout::from_env() else {
        eprintln!("sbx projects rm: cannot locate sbx's data directory.");
        return ExitCode::FAILURE;
    };
    let live_ids = session_housekeeping(&layout, pal);
    let current = current_tree_id();
    let projects_dir = layout.data_dir().join("projects");
    let mut had_error = false;

    for id in ids {
        if !super::gc::is_safe_tree_id(id) {
            eprintln!(
                "sbx projects rm: invalid project id `{id}` — expected a single tree name \
                 (an id `sbx projects` lists), not a path."
            );
            had_error = true;
            continue;
        }
        // Guard the tree you are standing in: an idle current project is not `Live`, so naming its
        // exact id would delete the store and home of this very directory. `--force` is the opt-in.
        if rm_refuses_current(id, current.as_deref(), force) {
            eprintln!(
                "sbx projects rm: {n}{id}{r} is the current project — refusing without {n}--force{r}."
            );
            had_error = true;
            continue;
        }
        match super::gc::reap_one(&projects_dir, id, &live_ids, apply) {
            super::gc::ReapOneOutcome::NotFound => {
                eprintln!(
                    "sbx projects rm: no project tree for id `{id}` under {}.",
                    projects_dir.display()
                );
                had_error = true;
            }
            super::gc::ReapOneOutcome::Live => {
                eprintln!(
                    "sbx projects rm: project tree {n}{id}{r} is held by a live session — \
                     stop it first with {n}sbx stop{r}, then `sbx projects rm {id}`."
                );
                had_error = true;
            }
            super::gc::ReapOneOutcome::Tree { dir, bytes } => {
                let verb = if apply {
                    format!("{ok}removed{r}")
                } else {
                    format!("{dim}removable{r}")
                };
                println!(
                    "  {verb}: {n}{}{r} ({})",
                    dir.display(),
                    super::gc::human_bytes(bytes)
                );
                if !apply {
                    println!(
                        "{h}sbx projects rm:{r} {n}{id}{r} removable ({}) — \
                         run `sbx projects rm {id}` (without `--dry-run`) to remove.",
                        super::gc::human_bytes(bytes)
                    );
                }
            }
        }
    }

    if dead || markerless {
        reap_dead_trees(&layout, &live_ids, apply && dead, apply && markerless, pal);
    }

    if do_gc {
        if apply {
            shared_store_gc(&layout, true, pal);
        } else {
            eprintln!(
                "sbx projects rm: {dim}--gc runs the shared-store collection only when the removal \
                 is applied (add --yes, or drop --dry-run).{r}"
            );
        }
    }

    if had_error {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    }
}

#[cfg(test)]
mod projects_rm_tests {
    use super::{rm_apply, rm_refuses_current};

    #[test]
    fn a_named_id_applies_immediately_but_a_bulk_selector_previews() {
        // Pure targeted: apply now.
        assert_eq!(rm_apply(true, false, false, false), Some(true));
        // Bulk selector present: preview by default (needs --yes).
        assert_eq!(rm_apply(false, true, false, false), Some(false));
        assert_eq!(rm_apply(true, true, false, false), Some(false));
    }

    #[test]
    fn dry_run_and_yes_override_the_default_and_conflict_together() {
        assert_eq!(rm_apply(true, false, true, false), Some(false)); // --dry-run wins over targeted
        assert_eq!(rm_apply(false, true, false, true), Some(true)); // --yes applies a bulk sweep
        assert_eq!(rm_apply(true, false, true, true), None); // contradictory
    }

    #[test]
    fn the_current_project_tree_is_refused_unless_forced() {
        // The id matches the cwd's tree: refuse without --force, allow with it.
        assert!(rm_refuses_current("abc", Some("abc"), false));
        assert!(!rm_refuses_current("abc", Some("abc"), true));
        // A different tree, or an unresolvable cwd, never guards.
        assert!(!rm_refuses_current("abc", Some("def"), false));
        assert!(!rm_refuses_current("abc", None, false));
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
fn shared_store_gc(layout: &crate::store::Layout, prune: bool, pal: &crate::style::Palette) {
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
            "{h}sbx gc:{r} shared store — {} stale gc root(s) would be dropped; {} orphaned path(s) \
             reclaimable now ({}). Run `sbx gc --all --prune` to drop the roots and reclaim their closures.",
            stale.len(),
            report.paths,
            super::gc::human_bytes(report.bytes)
        );
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
fn sweep_current(prune: bool, pal: &crate::style::Palette) -> Result<(), ExitCode> {
    let (h, n, dim, r) = (pal.head, pal.name, pal.dim, pal.reset);
    let prep = prepare()?;

    let (id, project) = match binds::project_identity(&prep.cwd) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("sbx gc: cannot resolve the project directory: {e}");
            return Err(ExitCode::FAILURE);
        }
    };

    // A project that was never launched has no store to reclaim. Seeding one here — just to gc it —
    // would be a heavy, possibly networked side effect, so skip instead. This is what makes
    // `sbx gc --all` safe to run from any directory: a non-project cwd is skipped, never seeded.
    if !super::projectstore::store_exists(&prep.layout, &id) {
        println!(
            "{h}sbx gc{r} — {n}{}{r}: {dim}no per-project store yet, nothing to reclaim.{r}",
            project.display()
        );
        return Ok(());
    }

    // Refuse if a live sandbox holds this project: collecting a store a running cage reads and
    // writes could drop a path it still needs. The registry list prunes dead records as it goes.
    if let Ok(sessions) = session::Registry::at(prep.layout.data_dir()).list() {
        if sessions.iter().any(|s| s.project == project) {
            eprintln!(
                "sbx gc: a sandbox is running in this project — stop it first (see `sbx session ls`)."
            );
            return Err(ExitCode::FAILURE);
        }
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

    // Drop the `sbx-flake-<name>` roots of removed packages. A roll self-cleans (its root is
    // overwritten onto the new build), but a removal leaves the root pointing at an unwanted build;
    // this prunes those so the sweep reclaims them. The current set spans every runtime — the
    // baseline and each app's merged packages — so a flake package declared only in an app keeps
    // its root.
    // Inline `[flakes.<name>]` flakes register the same `sbx-flake-<name>` gcroot as a `flake:`
    // package, so their names belong in the keep-set too, or the sweep would prune a live inline
    // flake's root.
    let flake_root_names = |pkgs: &[crate::config::Package]| {
        super::packages::flake_packages(pkgs)
            .into_iter()
            .map(|(name, _)| name)
            .chain(
                super::packages::flake_inline_packages(pkgs)
                    .into_iter()
                    .map(|(name, _, _)| name),
            )
    };
    let mut flake_names: std::collections::BTreeSet<String> =
        flake_root_names(&prep.cfg.packages).collect();
    for app in prep.cfg.apps.values() {
        let mut merged = prep.cfg.clone();
        merged.merge_app(app.clone());
        flake_names.extend(flake_root_names(&merged.packages));
    }
    let pruned = super::gc::prune_flake_roots(&store_dir, &flake_names, prune).len();

    // Reconcile the seed roots too. `gcroot_roots` is add-only, so a superseded build — an old base
    // revision, a rebuilt tool, an app version rolled forward — keeps a permanent direct root and
    // `nix-store --gc` never collects it: the store otherwise accumulates every version ever
    // provisioned. Drop the seed roots whose build no current out-link references so the sweep
    // reclaims them. The keep-set is the union of every out-link family, which only gc (never a
    // single launch's seed) sees.
    let data_gcroots = prep.layout.data_dir().join("gcroots");
    let base_rev = effective_lock_target(&prep.cwd, &prep.layout, &prep.cfg)
        .ok()
        .and_then(|t| t.locked_revision());
    let mise_revs = crate::store::live_mise_revisions(&prep.layout);
    let superseded = match &base_rev {
        // Prune only when the base *and* mise out-links for the current revisions are present: those
        // two families root the irreducible userland (mise on its own revision, not the base one), so
        // without them the keep-set could omit a current core build and the sweep would delete it. A
        // missing family means we cannot safely tell superseded from sole-current, so skip — a
        // re-provision on the next launch is cheap, a wrongful wipe is not.
        Some(rev)
            if data_gcroots.join("base").join(rev).is_dir()
                && mise_revs
                    .iter()
                    .any(|m| data_gcroots.join("mise").join(m).is_dir()) =>
        {
            // `id` is `project_identity(cwd).0` — the very value `project_runtime_id` returns and the
            // provisioning path keys `<data>/gcroots/projects/<id>/` on — so the projects family of the
            // keep-set cannot drift from where a project's app builds are actually rooted.
            let keep = super::gc::project_keep_roots(&data_gcroots, &id, rev, &mise_revs);
            super::gc::prune_superseded_roots(&store_dir, &keep, prune).len()
        }
        _ => 0,
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
            "  {dim}{} store path(s) collectable now, {} would be freed — run `sbx gc --prune` to reclaim.{r}",
            report.paths,
            super::gc::human_bytes(report.bytes)
        );
        if pruned > 0 || superseded > 0 {
            println!(
                "  {dim}and {pruned} removed-package flake build(s) + {superseded} superseded build(s) would also be reclaimed.{r}"
            );
        }
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
pub(crate) fn superseded_reclaimable_hint(
    layout: &Layout,
    cwd: &Path,
    cfg: &crate::config::Resolved,
    pal: &crate::style::Palette,
) {
    let Ok(id) = binds::project_runtime_id(cwd) else {
        return;
    };
    if !super::projectstore::store_exists(layout, &id) {
        return;
    }
    let Some(rev) = effective_lock_target(cwd, layout, cfg)
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
            "  {}{} superseded build(s) in this project's store are reclaimable — run `sbx gc --prune`.{}",
            pal.dim, n, pal.reset,
        );
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

    // `deb:` packages are host-side like `nix:`, so their roots must be part of the gc seed too —
    // otherwise the per-project store copy would be collected and re-provisioned every launch. When
    // warm (pinned + built) this is a fast no-op; it mirrors the launch path's deb provisioning.
    for (name, url) in super::packages::deb_packages(&prep.cfg.packages) {
        match super::deb::provision(
            &prep.nix,
            &prep.layout,
            &prep.cwd,
            &prep.nixpkgs,
            &name,
            &url,
        ) {
            Ok((_, root)) => packages.roots.push(root),
            Err(e) => {
                eprintln!("sbx gc: cannot provision deb package `{name}` ({url}): {e}");
                return Err(ExitCode::FAILURE);
            }
        }
    }

    // `appimage:` packages are host-side like `deb:`/`nix:`, so their roots join the gc seed too.
    for (name, url) in super::packages::appimage_packages(&prep.cfg.packages) {
        match super::appimage::provision(
            &prep.nix,
            &prep.layout,
            &prep.cwd,
            &prep.nixpkgs,
            &name,
            &url,
        ) {
            Ok((_, root)) => packages.roots.push(root),
            Err(e) => {
                eprintln!("sbx gc: cannot provision appimage package `{name}` ({url}): {e}");
                return Err(ExitCode::FAILURE);
            }
        }
    }

    for (name, url) in super::packages::tarball_packages(&prep.cfg.packages) {
        match super::tarball::provision(
            &prep.nix,
            &prep.layout,
            &prep.cwd,
            &prep.nixpkgs,
            &name,
            &url,
        ) {
            Ok((_, root)) => packages.roots.push(root),
            Err(e) => {
                eprintln!("sbx gc: cannot provision tarball package `{name}` ({url}): {e}");
                return Err(ExitCode::FAILURE);
            }
        }
    }

    let tools = mise_tools(prep)?;
    for warning in &tools.warnings {
        crate::diag::warn(warning);
    }

    let font_layer = if matches!(prep.cfg.gui, crate::config::GuiPolicy::Wayland) {
        super::fonts::provision(&prep.nix, &prep.layout, &prep.nixpkgs).ok()
    } else {
        None
    };
    let mut gui_roots: Vec<PathBuf> = font_layer
        .as_ref()
        .map_or_else(Vec::new, |l| l.roots.clone());

    // mesa driver roots under `gpu = true`, so gc keeps the built output rather than collecting and
    // re-provisioning it each launch — mirroring the launch path's GPU provisioning and the fonts.
    if prep.cfg.gpu {
        if let Ok(layer) = super::gpu::provision(&prep.nix, &prep.layout, &prep.nixpkgs) {
            gui_roots.push(layer.root);
        }
    }

    // audio userspace roots under `audio = true`, same reason: gc keeps the client libraries and
    // ALSA shim rather than collecting and re-provisioning them each launch.
    if prep.cfg.audio {
        if let Ok(layer) = super::audio::provision(&prep.nix, &prep.layout, &prep.nixpkgs) {
            gui_roots.extend(layer.roots);
        }
    }

    // GUI data root (GSettings schemas + GTK themes) under `gui = "wayland"`, same reason: gc keeps
    // the provisioned output.
    if matches!(prep.cfg.gui, crate::config::GuiPolicy::Wayland) {
        if let Ok(layer) = super::guidata::provision(&prep.nix, &prep.layout, &prep.nixpkgs) {
            gui_roots.push(layer.root);
        }
    }

    // In-cage portal roots under `gui = "wayland"` + `dbus = true`: gc keeps the portal closure.
    if prep.cfg.dbus && matches!(prep.cfg.gui, crate::config::GuiPolicy::Wayland) {
        if let Ok(p) = super::portal::provision(&prep.nix, &prep.layout, &prep.nixpkgs) {
            gui_roots.extend(p.roots);
        }
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

    let _record = register(prep.layout.data_dir(), &spec, kind, runtime).map(RecordGuard::new);
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
    let (n, dim, r) = (pal.name, pal.dim, pal.reset);
    format!(
        "sbx: attaching to session {n}{pid}{r} ({n}{label}{r}) {dim}\
         (a shell in its live cage — type `exit` to leave the agent running){r}"
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
        "sbx: {n}{name}{r} is graphical — press Ctrl+C twice here to quit (closing its window may only \
         hide it — a tray app keeps running); `sbx session stop {pid}` also stops it."
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
/// confined at least as tightly as the agent. See [`super::attach`] for the mechanism and its one
/// inherent residual (the command binary comes from the agent's own mount namespace).
pub(crate) fn attach(id: &str, cmd: Vec<OsString>) -> ExitCode {
    let Some(layout) = Layout::from_env() else {
        eprintln!("sbx: cannot resolve the data directory (no $HOME or $XDG_DATA_HOME).");
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
        eprintln!(
            "sbx session attach: no live session '{id}' — run `sbx session ls` to list them."
        );
        return ExitCode::from(2);
    };
    // SAFETY: `isatty` only inspects fd 0. A bare attach opens an interactive shell, which needs a
    // real terminal (like `shell`); a command drives its terminal setup from this — a pty when it
    // has one, inherited stdio otherwise — so it imposes no terminal requirement.
    let stdin_tty = unsafe { libc::isatty(0) } == 1;
    if cmd.is_empty() && !stdin_tty {
        eprintln!("sbx: `sbx session attach` needs a terminal on stdin (or pass `-- command`).");
        return ExitCode::from(2);
    }

    // Locate a live process inside the cage (the session pid is the cage's host-side anchor). A
    // `None` here means the cage has no in-namespace process left — it exited between `sbx session ls` and
    // now, or the host has no user namespaces (then it never had a cage).
    let Some(cage_pid) = super::attach::find_cage_pid(target.pid) else {
        eprintln!(
            "sbx session attach: session '{id}' has no live process to enter — it may have just exited \
             (run `sbx session ls`)."
        );
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
/// a no-op success (there is simply nothing to do).
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
        eprintln!("sbx: cannot resolve the data directory (no $HOME or $XDG_DATA_HOME).");
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
        for target in &sessions {
            stop_session(&registry, target, grace, &epal);
        }
        return ExitCode::SUCCESS;
    }

    let mut any_missing = false;
    for id in ids {
        let Some(target) = sessions.iter().find(|s| s.pid.to_string() == *id) else {
            eprintln!(
                "sbx session stop: no live session '{id}' — run `sbx session ls` to list them."
            );
            any_missing = true;
            continue;
        };
        stop_session(&registry, target, grace, &epal);
    }

    if any_missing {
        ExitCode::from(2)
    } else {
        ExitCode::SUCCESS
    }
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
    let (n, ok, warn, dim, r) = (pal.name, pal.ok, pal.warn, pal.dim, pal.reset);
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
    }
}

/// Stop one resolved session and reap its record: SIGTERM, then SIGKILL after `grace`, report the
/// outcome by pid and label, and drop the record so `sbx session ls` is clean at once rather than waiting
/// for the killed process to stop reading as a zombie.
fn stop_session(
    registry: &session::Registry,
    target: &session::Session,
    grace: Duration,
    pal: &crate::style::Palette,
) {
    let outcome = target.stop(grace);
    eprintln!(
        "{}",
        render_stop_outcome(target.pid, &target.label(), &outcome, grace, pal)
    );
    registry.reap(target);
}

/// Hard prerequisites + per-launch resolution shared by `run` and `shell`. Returns
/// a [`Prepared`] or an `ExitCode` to return after a clean, pointed error.
///
/// The configuration is loaded here (once, infallibly) because its `nixpkgs` field
/// chooses the channel the **whole** launch resolves against — base userland and
/// tools alike (see [`Prepared`] for why they must be one).
fn prepare() -> Result<Prepared, ExitCode> {
    prepare_with(&crate::config::Override::none())
}

/// [`prepare`] with a one-shot override applied. The override's **nixpkgs channel** is applied to
/// the loaded config *before* the lock target is chosen (the channel decides which lock the whole
/// launch resolves against), so a `-o nixpkgs=…` / `SBX_CONFIG` channel takes effect. The rest of
/// the override (env, binds, network, gui, limits, secret) is applied by the caller with
/// [`crate::config::Resolved::apply_override`] — after any app overlay merges, so it beats that too.
fn prepare_with(ov: &crate::config::Override) -> Result<Prepared, ExitCode> {
    // The data directory is resolved first: it is where sbx looks for (and, under the
    // bundled features, materializes) the engines it owns, so `resolve_bwrap` below needs it.
    let Some(layout) = Layout::from_env() else {
        eprintln!("sbx: cannot resolve the data directory (no $HOME or $XDG_DATA_HOME).");
        return Err(ExitCode::FAILURE);
    };
    let Some(bwrap) = crate::store::resolve_bwrap(Some(&layout)).map(|c| c.path) else {
        return Err(missing("bubblewrap (the sandbox engine)"));
    };
    if !matches!(crate::probe_userns(), crate::Userns::Ok) {
        eprintln!(
            "sbx: no capability-bearing user namespace — the sandbox cannot run. See `sbx doctor`."
        );
        return Err(ExitCode::FAILURE);
    }
    let Some(nix) = crate::store::resolve_nix(Some(&layout)) else {
        return Err(missing("nix (the store engine)"));
    };
    let Some(nix_store) = crate::store::resolve_nix_store(Some(&layout)) else {
        return Err(missing("nix-store (the store database tool)"));
    };
    let cwd = match std::env::current_dir() {
        Ok(d) => d,
        Err(e) => {
            eprintln!("sbx: cannot read the current directory: {e}");
            return Err(ExitCode::FAILURE);
        }
    };
    let mut cfg = crate::config::load(&cwd);
    // The override's nixpkgs channel must land before the lock target is chosen below. A set-but-
    // invalid channel is a hard error (no safe baseline fallback for a supply-chain field).
    if let Err(e) = cfg.apply_override_channel(ov) {
        eprintln!("sbx: {e}");
        return Err(ExitCode::from(2));
    }
    // Reject a mistyped scalar security value (network/gui/limits) now — before the expensive
    // channel/userland resolution below — so a typo aborts fast rather than after a provision. The
    // full override (this plus the additive fields) is applied at the launch's final point.
    if let Err(errs) = cfg.validate_override(ov) {
        for e in errs {
            eprintln!("sbx: {e}");
        }
        return Err(ExitCode::from(2));
    }

    let nixpkgs =
        match effective_lock_target(&cwd, &layout, &cfg).and_then(|t| t.resolve(&nix, &layout)) {
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
    })
}

/// The single channel decision for the current directory — the one place that picks
/// "which source, which lock", so the launch (resolve), `sbx upgrade` (refresh), and
/// `sbx config` (display) all act on the same lock and can never drift.
///
/// A trusted per-project `nixpkgs` pin takes precedence (its own lock); otherwise the
/// global channel — a global-config override, else the default. Only the pinned case
/// canonicalises the project to derive its lock path, so the common no-pin path does
/// no extra work and a per-project lock is never even named without a current pin.
pub(crate) fn effective_lock_target(
    cwd: &Path,
    layout: &Layout,
    cfg: &crate::config::Resolved,
) -> io::Result<crate::store::LockTarget> {
    match cfg.nixpkgs_project.as_deref() {
        Some(source) => {
            let id = binds::project_runtime_id(cwd)?;
            Ok(crate::store::LockTarget::project(layout, &id, source))
        }
        None => Ok(crate::store::LockTarget::global(
            layout,
            cfg.nixpkgs_global.as_deref(),
        )),
    }
}

/// Build the spec for `cmd`, reporting a clean error as an `ExitCode`. The
/// configuration resolved in [`prepare`] drives this: a trust-gated `.sbx.toml` adds
/// environment and host binds — read-only, or read-write with `mode = "rw"` (its security
/// fields honored only once trusted)
/// and provisions its declared tools onto `PATH`. Whatever the gate dropped or
/// withheld is surfaced as a warning; a declared tool that fails to realise is fatal,
/// since it is a stated requirement.
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
    /// The exec-enforcement supervisor (`[proc] mode = enforce|ask`), when one is running. Its
    /// receive loop is a host thread deciding every notified `execve`, so it must outlive the cage;
    /// its presence forces the supervised path (a live parent). Dropping it stops the supervisor and
    /// unlinks the handoff socket.
    pub(crate) proc_enforce: Option<super::proc_enforce::ProcEnforce>,
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
        if let Some(egress) = self.egress.take() {
            drop(egress);
        }
        if let Some(forward) = self.forward.take() {
            drop(forward);
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
    }
}

fn build(
    prep: &Prepared,
    runtime: binds::Runtime,
    cmd: Vec<OsString>,
) -> Result<(SandboxSpec, Option<LaunchGuard>), ExitCode> {
    for warning in &prep.cfg.warnings {
        crate::diag::warn(warning);
    }

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

    // `deb:` packages are provisioned host-side too (like `nix:`, not in-cage like `flake:`): sbx
    // resolves the `.deb` URL to a hash (pinned in the per-project lock), builds the generated
    // unpack+autoPatchelf derivation into sbx's store, prepends its bin to PATH, and seeds its
    // closure (its root joins `packages.roots`). A declared package is a requirement — a
    // provisioning failure aborts the launch naming it, never runs without it.
    for (name, url) in super::packages::deb_packages(&prep.cfg.packages) {
        match super::deb::provision(
            &prep.nix,
            &prep.layout,
            &prep.cwd,
            &prep.nixpkgs,
            &name,
            &url,
        ) {
            Ok((bin, root)) => {
                bin_paths.push(bin);
                packages.roots.push(root);
            }
            Err(e) => {
                eprintln!("sbx: cannot provision deb package `{name}` ({url}): {e}");
                return Err(ExitCode::FAILURE);
            }
        }
    }

    // `appimage:` packages are provisioned host-side too (the exact `deb:` shape — the AppImage's
    // squashfs is extracted at build time, never self-mounted at runtime, which the seccomp cage
    // forbids): resolve the URL to a hash (pinned in the per-project lock), build the generated
    // extract+autoPatchelf derivation into sbx's store, prepend its bin to PATH, and seed its
    // closure. A declared package is a requirement — a provisioning failure aborts the launch.
    for (name, url) in super::packages::appimage_packages(&prep.cfg.packages) {
        match super::appimage::provision(
            &prep.nix,
            &prep.layout,
            &prep.cwd,
            &prep.nixpkgs,
            &name,
            &url,
        ) {
            Ok((bin, root)) => {
                bin_paths.push(bin);
                packages.roots.push(root);
            }
            Err(e) => {
                eprintln!("sbx: cannot provision appimage package `{name}` ({url}): {e}");
                return Err(ExitCode::FAILURE);
            }
        }
    }

    // `tarball:` packages are provisioned host-side too (the exact `deb:`/`appimage:` shape — a plain
    // `.tar.gz` is extracted at build time, never self-mounted at runtime): resolve the URL to a hash
    // (pinned in the per-project lock), build the generated extract+autoPatchelf derivation into sbx's
    // store, prepend its bin to PATH, and seed its closure. A declared package is a requirement — a
    // provisioning failure aborts the launch.
    for (name, url) in super::packages::tarball_packages(&prep.cfg.packages) {
        match super::tarball::provision(
            &prep.nix,
            &prep.layout,
            &prep.cwd,
            &prep.nixpkgs,
            &name,
            &url,
        ) {
            Ok((bin, root)) => {
                bin_paths.push(bin);
                packages.roots.push(root);
            }
            Err(e) => {
                eprintln!("sbx: cannot provision tarball package `{name}` ({url}): {e}");
                return Err(ExitCode::FAILURE);
            }
        }
    }

    // `flake:` packages are built in-cage at launch (below), not host-provisioned, but their
    // out-link `bin` directories join PATH now — ahead of the base, like every other declared
    // tool. The out-link need not exist yet: the in-cage `nix build` creates it before the
    // command runs, exactly as the mise shims dir is on PATH before mise populates it. Each
    // out-link is keyed by the (validated) package name under the persistent home.
    let flake_pkgs = super::packages::flake_packages(&prep.cfg.packages);
    // Consult the per-project flake lock: a pinned package builds its locked (immutable) ref into
    // an out-link keyed by that revision, so an `sbx upgrade flake` that moved the pin rebuilds at
    // this launch (the rev-keyed path does not yet exist). An unpinned package floats — it builds
    // the declared ref into a name-keyed out-link, the v1 behaviour kept for a project that never
    // ran `sbx upgrade flake`.
    let flake_lock = read_flake_lock(prep, &flake_pkgs);
    // Each triple carries the build ref, the out-link, and the package name — the name keys the
    // host-resolvable gc root the build registers, so a roll re-points one root and a host-side
    // `sbx gc` keeps the current build while collecting the rolled-away one.
    let mut flake_pairs: Vec<(String, PathBuf, String)> = Vec::with_capacity(flake_pkgs.len());
    for (name, reference) in &flake_pkgs {
        // A pinned package builds its locked (immutable) ref; an unpinned one the declared ref.
        let build_ref = match flake_lock.get(reference) {
            Some(pin) => pin.locked_ref.clone(),
            None => reference.clone(),
        };
        let out_link = flake_out_link_for(name, reference, &flake_lock);
        bin_paths.push(out_link.join("bin"));
        flake_pairs.push((build_ref, out_link, name.clone()));
    }

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
        let out_link = binds::flake_out_link_hash(&name, &hash);
        inline_flake_binds.push(binds::ExtraBind {
            src: dir,
            dest: incage,
            writable: false,
        });
        bin_paths.push(out_link.join("bin"));
        flake_pairs.push((build_ref, out_link, name));
    }

    // Under `gui = "wayland"`, provision the GUI font set host-side so the cage renders text
    // rather than boxes. Provisioned here — before the seed — so its store roots join the
    // project store and the cage reads the fonts through `/nix`. Best-effort, like the display
    // socket below: a font fetch that fails (no network on a first launch) warns and the app
    // runs without fonts rather than failing the launch.
    let font_layer = if matches!(prep.cfg.gui, crate::config::GuiPolicy::Wayland) {
        match super::fonts::provision(&prep.nix, &prep.layout, &prep.nixpkgs) {
            Ok(layer) => Some(layer),
            Err(e) => {
                crate::diag::warn(&format!(
                    "`gui = \"wayland\"` but the font set could not be provisioned \
                     ({e}) — text may not render"
                ));
                None
            }
        }
    } else {
        None
    };
    let font_roots: &[PathBuf] = font_layer.as_ref().map_or(&[], |l| l.roots.as_slice());

    // Under `gui = "wayland"`, provision the GUI data set (GSettings schemas + GTK themes)
    // host-side. A GTK dialog (the file chooser Electron falls back to without a desktop portal)
    // aborts FATAL without the schemas (`No GSettings schemas are installed`); the themes let the
    // in-cage portal's file dialog render in the host light/dark theme. Provisioned here — before
    // the seed — so its store root joins the project store. Best-effort like the fonts: a fetch
    // that fails warns and the app runs (a GTK dialog will still crash, but the rest is unaffected).
    let guidata_layer = if matches!(prep.cfg.gui, crate::config::GuiPolicy::Wayland) {
        match super::guidata::provision(&prep.nix, &prep.layout, &prep.nixpkgs) {
            Ok(layer) => Some(layer),
            Err(e) => {
                crate::diag::warn(&format!(
                    "`gui = \"wayland\"` but the GUI data (GSettings schemas + themes) could not \
                     be provisioned ({e}) — a GTK dialog (file chooser) may crash"
                ));
                None
            }
        }
    } else {
        None
    };

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
                    // re-emits SettingChanged and the app follows the change live. The keyfile's home
                    // is derived exactly as `build_spec` binds it, so both target the same file.
                    // Best-effort: a home path that cannot be resolved just leaves the at-launch theme.
                    if let Ok(home) = binds::home_src(prep.layout.data_dir(), &prep.cwd, runtime) {
                        theme_relay = Some(super::theme_relay::ThemeRelay::start(
                            home.join(super::portal::KEYFILE_REL),
                        ));
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
    // The host light/dark preference, read host-side (best-effort) to seed the cage theme.
    let portal_scheme = portal.as_ref().and_then(|p| {
        super::portal::read_host_color_scheme(&crate::store::physical_path(
            &prep.layout,
            &p.dbus_send,
        ))
    });

    // CA trust for a Chromium/Electron GUI app under a filtering posture: Chromium ignores the
    // CA-file env vars sbx sets and reads its own NSS db, so under the egress MITM it rejects
    // sbx's per-session CA and a graphical app's UI cannot load. When the cage is BOTH `gui =
    // "wayland"` AND a filtering allowlist, provision `certutil` (part of the GUI hole, like the
    // fonts) so the command wrap below can import the bound CA into the cage's NSS db. Gated to
    // exactly those cages — a CLI tool needs nothing (its env-reading TLS already trusts the CA),
    // and `shared`/`none` has no MITM CA. Best-effort: a provisioning failure warns and the app
    // runs (and fails its own HTTPS) rather than blocking the launch.
    let ca_trust = if matches!(prep.cfg.gui, crate::config::GuiPolicy::Wayland)
        && matches!(prep.cfg.network, crate::config::NetworkPolicy::Allowlist(_))
    {
        match super::catrust::provision(&prep.nix, &prep.layout, &prep.nixpkgs) {
            Ok(ct) => Some(ct),
            Err(e) => {
                crate::diag::warn(&format!(
                    "`gui = \"wayland\"` under a network allowlist but certutil could not be \
                     provisioned ({e}) — a Chromium/Electron app may not trust the egress proxy"
                ));
                None
            }
        }
    } else {
        None
    };

    // Under `gpu = true`, provision mesa's DRI drivers host-side so the cage can render with
    // hardware acceleration. Provisioned here — before the seed — so mesa's store root joins the
    // project store and the cage reads the drivers through `/nix`; the env pointing libgbm/libEGL
    // at them is applied in the launch block below. Best-effort, like the fonts: a fetch that fails
    // warns and the app runs (falling back to software rendering) rather than failing the launch.
    let gpu_layer = if prep.cfg.gpu {
        match super::gpu::provision(&prep.nix, &prep.layout, &prep.nixpkgs) {
            Ok(layer) => Some(layer),
            Err(e) => {
                crate::diag::warn(&format!(
                    "`gpu = true` but the mesa drivers could not be provisioned \
                     ({e}) — rendering may fall back to software"
                ));
                None
            }
        }
    } else {
        None
    };

    // Under `audio = true`, provision the PulseAudio client library (`libpulse.so.0`) host-side so
    // the cage can open capture/playback streams. Provisioned here — before the seed — so its store
    // root joins the project store and the cage reads the library through `/nix`; the env pointing
    // the app's loader at it (and the socket bind) is applied in the launch block below. Best-effort,
    // like the fonts and mesa: a fetch that fails warns and the app runs (without audio).
    let audio_layer = if prep.cfg.audio {
        match super::audio::provision(&prep.nix, &prep.layout, &prep.nixpkgs) {
            Ok(layer) => Some(layer),
            Err(e) => {
                crate::diag::warn(&format!(
                    "`audio = true` but the audio userspace could not be provisioned \
                     ({e}) — the app runs without audio"
                ));
                None
            }
        }
    } else {
        None
    };

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
    let nix_mount = binds::NixMount {
        src: project_store.store_dir().join("nix"),
        writable: true,
    };

    // Mise-backed tools are equipped in-cage at launch rather than host-provisioned, in two
    // distinct lanes. The app's `[packages] mise:` tools are durable, trusted-only declarations,
    // equipped **globally** (`mise use -g`, written to the home's global mise config). The
    // project's local `.mise.toml` non-`nix:` tools (an `aqua:`/`npm:`/registry backend) are the
    // **open** self-equip toolchain, equipped **locally** (`mise install`) with the in-cage mise
    // told to trust the project config so they resolve through the shims on PATH. Both fetch, so
    // both wrap the command *before* the egress wrap below — under an allowlist the forwarder is
    // up before either install — and both are skipped under `network = "none"`.
    let mut cmd = cmd;

    // Exec enforcement (`[proc] mode = enforce|ask`): stand up the seccomp user-notification
    // supervisor and wrap the command with the in-cage shim, **innermost** — so only the agent
    // command and its children are filtered, not the provisioning/egress plumbing wrapped around it
    // below. Its guard forces the supervised path (a live parent for the supervisor thread).
    // Fail-closed: if the supervisor cannot be stood up, the launch is refused rather than running the
    // command unenforced.
    let mut proc_enforce_guard = None;
    let mut proc_binds: Vec<binds::ExtraBind> = Vec::new();
    if prep.cfg.proc.enforcing() {
        let sbx_exe = std::env::current_exe().map_err(|e| {
            eprintln!("sbx: cannot locate the sbx binary for exec enforcement: {e}");
            ExitCode::FAILURE
        })?;
        let (guard, wiring) =
            super::proc_enforce::start(prep.layout.data_dir(), &sbx_exe, prep.cfg.proc.clone())
                .map_err(|e| {
                    eprintln!("sbx: cannot start exec enforcement: {e}");
                    ExitCode::FAILURE
                })?;
        cmd = super::proc_enforce::wrap_command(cmd);
        proc_binds = wiring.binds;
        proc_enforce_guard = Some(guard);
    }

    let mut autoequip_env: Vec<(String, String)> = Vec::new();
    let global_mise = super::packages::mise_packages(&prep.cfg.packages);
    let auto_equip = auto_equip_tokens(&prep.cfg);
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
                eprintln!(
                    "sbx: equipping non-nix tools in-cage via mise: {} (each backend's host must \
                     be in [network].allow under an allowlist)",
                    auto_equip.join(", ")
                );
                cmd = wrap_mise_equip(
                    &prep.userland.mise_bin,
                    &prep.userland.shell_bin,
                    "install",
                    &auto_equip,
                    cmd,
                );
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
                eprintln!(
                    "sbx: equipping app packages in-cage via mise use -g: {}",
                    global_mise.join(", ")
                );
                cmd = wrap_mise_equip(
                    &prep.userland.mise_bin,
                    &prep.userland.shell_bin,
                    "use -g",
                    &global_mise,
                    cmd,
                );
            }
        }
    }

    // `flake:` packages are built in-cage with `nix build --out-link` — an uncurated
    // third-party flake is contained by the cage, not built host-side like a curated `nix:`
    // attribute. The build fetches, so (like the mise equip) it wraps the command *before* the
    // egress wrap and is skipped under `network = "none"`. The wrap short-circuits when the
    // out-link is already realised in the project's store, so a warm launch is a no-op and an
    // already-built tool runs offline.
    if !flake_pairs.is_empty() {
        if matches!(prep.cfg.network, crate::config::NetworkPolicy::Isolated) {
            let names: Vec<&str> = flake_pkgs.iter().map(|(n, _)| n.as_str()).collect();
            crate::diag::warn(&format!(
                "flake packages [{}] are declared but `network = \"none\"` — they \
                 cannot be built and will be absent unless already present",
                names.join(", ")
            ));
        } else {
            eprintln!(
                "sbx: building flake packages in-cage via nix build: {} (each flake's fetch \
                 host must be in [network].allow under an allowlist)",
                flake_pkgs
                    .iter()
                    .map(|(n, r)| format!("{n} ({r})"))
                    .collect::<Vec<_>>()
                    .join(", ")
            );
            cmd = wrap_flake_equip(
                &prep.userland.nix_bin,
                &prep.userland.shell_bin,
                &binds::flake_roots_dir(),
                &flake_pairs,
                cmd,
            );
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
                    .map(u16::to_string)
                    .collect::<Vec<_>>()
                    .join(",")
            ));
        } else {
            let (guard, wiring) =
                forward::start(&prep.layout, prep.cfg.forward.clone()).map_err(|e| {
                    eprintln!("sbx: {e}");
                    ExitCode::FAILURE
                })?;
            cmd = forward::wrap_command(
                &prep.userland.socat_bin,
                &prep.userland.shell_bin,
                &wiring.forwards,
                cmd,
            );
            forward_binds = wiring.binds;
            forward_guard = Some(guard);
        }
    }
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
            // Pair the per-session MITM CA with the base root bundle so the injected CA file is a full,
            // ordinary bundle (a lone cert trips tools that heuristically reject a "too small" CA).
            Some(prep.userland.ca_bundle_src.as_path()),
        )
        .map_err(|e| {
            eprintln!("sbx: cannot start the egress filtering proxy: {e}");
            ExitCode::FAILURE
        })?;
        cmd = egress::wrap_command(&prep.userland.socat_bin, &prep.userland.shell_bin, cmd);
        // For a GUI cage, import sbx's MITM CA into the cage's NSS db before the app runs, so a
        // Chromium/Electron app trusts the egress proxy (it ignores the CA-file env vars). This
        // is the outermost wrap — it runs, then execs the egress-wrapped command. Only present
        // when `ca_trust` was provisioned (gui = "wayland" under this allowlist).
        if let Some(ct) = &ca_trust {
            cmd =
                super::catrust::wrap(&ct.certutil, &prep.userland.shell_bin, egress::CAGE_CA, cmd);
        }
        egress_binds = wiring.binds;
        egress_env = wiring.env;
        egress_guard = Some(guard);
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
                gui_env = env;
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

        // Fonts: bind the generated fontconfig configuration read-only and name it to the
        // cage's fontconfig. The font *files* were provisioned and seeded above; this points
        // fontconfig at them so text renders rather than boxes. Independent of the socket
        // above (a missing display already warned; the fonts are harmless either way) and
        // best-effort (a staging failure warns, the app runs without fonts). `FONTCONFIG_FILE`
        // is fixed by sbx; a project `[env]` could override it (highest precedence), but that
        // only re-points the agent's own in-cage fontconfig at its own config — self-sabotage,
        // not an escape (it already controls what runs in the cage) — so the key needs no
        // denylist entry, exactly like `WAYLAND_DISPLAY`.
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
                    "`gui = \"wayland\"` but the font configuration could not be \
                     staged ({e}) — text may not render"
                )),
            }
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
    // This is the **outermost** wrap — applied after every other command wrap (mise/flake/forward/
    // egress/catrust) — so its preamble (`dbus-daemon --fork`, which blocks until the socket is
    // ready) runs first, then execs the rest of the wrapped command. Only present under
    // `gui = "wayland"` + `dbus = true` with a successful provision.
    if let Some(p) = &portal {
        cmd = super::portal::wrap_command(
            &prep.userland.shell_bin,
            &p.dbus_daemon,
            &p.xdp_root,
            &p.gtk_root,
            portal_scheme.as_deref(),
            cmd,
        );
    }

    // The launcher's extra binds, emitted after the structural mounts: the egress machinery
    // (socket + CA) and the GUI socket. Their destinations are sbx's or the host's, never a
    // project path, so they neither shadow nor are shadowed by a structural mount.
    let mut extra_binds = egress_binds;
    extra_binds.extend(forward_binds);
    extra_binds.extend(gui_binds);
    extra_binds.extend(inline_flake_binds);
    extra_binds.extend(proc_binds);

    // Pin sbx's own control plane in place whenever a read-write bind contains it: each root's host
    // path is frozen as a mountpoint chain (read-write intermediates, a read-only leaf), so in-cage
    // code cannot rename a writable parent to move a control-plane root aside and recreate a forged
    // one at the same path — which sbx would otherwise read or `execve` on its next run. The bind
    // stays read-write; only these specific host paths are protected. Appended last, so the pins
    // are the final word on those paths (nothing structural touches them).
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

    // Environment, lowest precedence first: host passthrough, then sbx's hermetic CA bundle, then
    // the Wayland GUI keys, then the non-nix auto-equip variable, then a trusted project's mise
    // `[env]`, then the egress machinery (proxy + CA), then the `.sbx.toml` `[env]` (the sbx-native
    // config has the final say). The structural
    // HOME/PATH/... are added by the assembler, which upserts all of these over them. An
    // untrusted config has already lost its reserved keys upstream — including the proxy and
    // CA keys — so it can neither redirect the egress nor swap the CA; a trusted config
    // overriding them only harms its own cage.
    let extra_env = extra_cage_env(
        passthrough_env(),
        binds::cacert_env(),
        gui_env,
        autoequip_env,
        mise_env(prep)?,
        egress_env,
        &prep.cfg.env,
    );

    let overlay = binds::Overlay {
        env: &extra_env,
        binds: &prep.cfg.binds,
        bin_paths: &bin_paths,
    };
    // Generate the in-cage egress contract from the resolved (post-`merge_app`) network
    // posture, so a process inside the cage can see which hosts it can reach and why a
    // direct connection or `ping` fails. Informational only; bound read-only by `build_spec`.
    let egress_contract = super::contract::egress_contract(&prep.cfg.network);
    // The device grant: the resolved `[devices]` plus, under `gpu = true`, the render node
    // directory (`/dev/dri`), so the cage can reach the GPU. Both become `--dev-bind-try` mounts.
    // Deduped: a trusted `[devices] allow = ["/dev/dri"]` alongside `gpu = true` must not emit the
    // bind twice (harmless to bwrap, but tidy).
    let mut devices = prep.cfg.devices.clone();
    let dri = PathBuf::from(super::gpu::DRI_DIR);
    if prep.cfg.gpu && !devices.contains(&dri) {
        devices.push(dri);
    }
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
        // The trusted seccomp relaxation from the resolved (post-`merge_app`) config, so an app's
        // `[seccomp] allow` union is in effect for `sbx app`, exactly like its limits.
        prep.cfg.seccomp.clone(),
        // The trusted device grant from the resolved (post-`merge_app`) config, plus the GPU
        // render node under `gpu = true`, so an app's `[devices]` union is in effect for `sbx app`,
        // exactly like its seccomp relaxation.
        &devices,
        cmd,
    )
    .map_err(|e| {
        eprintln!("sbx: cannot prepare the sandbox: {e}");
        ExitCode::FAILURE
    })?;
    let guard = if egress_guard.is_some()
        || forward_guard.is_some()
        || portal_host.is_some()
        || proc_enforce_guard.is_some()
    {
        Some(LaunchGuard {
            egress: egress_guard,
            forward: forward_guard,
            notify: notify_relay,
            theme: theme_relay,
            portal: portal_host,
            proc_enforce: proc_enforce_guard,
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

/// Read the project's flake lock, but only when a `flake:` package is declared — the common
/// launch reads no lock and derives no project id. An unreadable id or absent lock yields an
/// empty map (every package floats), the v1 behaviour.
fn read_flake_lock(
    prep: &Prepared,
    flake_pkgs: &[(String, String)],
) -> BTreeMap<String, super::flake::FlakePin> {
    if flake_pkgs.is_empty() {
        return BTreeMap::new();
    }
    match binds::project_runtime_id(&prep.cwd) {
        Ok(id) => super::flake::pins(&prep.layout, &id),
        Err(_) => BTreeMap::new(),
    }
}

/// The out-link a `flake:` package builds into, given the project's flake lock: a pinned
/// package's revision-keyed path, an unpinned one's name-keyed path. The single place that
/// choice is made, so the launch (which builds the out-link) and `sbx gc` (which decides
/// whether an out-link on disk is a current root or a rolled-away leftover) never diverge.
fn flake_out_link_for(
    name: &str,
    reference: &str,
    lock: &BTreeMap<String, super::flake::FlakePin>,
) -> PathBuf {
    match lock.get(reference) {
        Some(pin) => binds::flake_out_link_rev(name, &pin.rev),
        None => binds::flake_out_link(name),
    }
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
fn wrap_mise_equip(
    mise: &Path,
    bash: &Path,
    verb: &str,
    tokens: &[String],
    cmd: Vec<OsString>,
) -> Vec<OsString> {
    let n = tokens.len();
    let script = format!(
        "{mise} {verb} \"${{@:1:{n}}}\" 1>&2; shift {n}; exec \"$@\"",
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
    triples: &[(String, PathBuf, String)],
    cmd: Vec<OsString>,
) -> Vec<OsString> {
    let n = triples.len();
    let script = format!(
        "mkdir -p '{dir}'\n\
         n={n}\n\
         while [ \"$n\" -gt 0 ]; do\n\
         out=\"$2\"\n\
         [ -e \"$out/bin\" ] || '{nix}' build \"$1\" --no-write-lock-file --out-link \"$out\" 1>&2\n\
         sp=$(readlink -f \"$out\" 2>/dev/null)\n\
         [ -n \"$sp\" ] && mkdir -p /nix/var/nix/gcroots \
         && ln -sfn \"$sp\" \"/nix/var/nix/gcroots/sbx-flake-$3\"\n\
         shift 3\n\
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
        // `$0` — a label; the triples are `$1..$3n`, the command is what remains after the shifts.
        OsString::from("sbx-flake-equip"),
    ];
    for (reference, out_link, key) in triples {
        out.push(OsString::from(reference));
        out.push(out_link.as_os_str().to_os_string());
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
fn register(
    data_dir: &Path,
    spec: &SandboxSpec,
    kind: Kind,
    runtime: binds::Runtime,
) -> Option<PathBuf> {
    let session = Session::current(spec.workdir.clone(), kind, session_runtime(runtime)).ok()?;
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
            eprintln!("sbx: failed to prepare the seccomp filter: {e}");
            return 1;
        }
    };
    let (prog, args) = super::cgroup::wrap(bwrap, argv, limits, &spec.cage_slug);
    match Command::new(prog).args(args).status() {
        Ok(status) => status_code(status),
        Err(e) => {
            eprintln!("sbx: failed to launch the sandbox: {e}");
            1
        }
    }
}

/// The bwrap argv with the mandatory seccomp filters prepended. Returns the
/// backing memfds the caller must keep alive until bwrap has read them — they are
/// not close-on-exec, and dropping a `File` early would close the descriptor
/// bwrap is told to read. Seccomp is loaded on every launch path the same way the
/// namespace hardening is emitted unconditionally by `to_argv`.
fn seccomp_argv(spec: &SandboxSpec) -> io::Result<(Vec<OsString>, Vec<File>)> {
    let memfds = super::seccomp::memfds(&spec.seccomp)?;
    let mut argv = super::seccomp::argv_prefix(&memfds);
    argv.extend(super::argv::to_argv(spec));
    Ok((argv, memfds))
}

/// A process's exit code in the shell convention: its own code, or 128 + the signal that
/// killed it (matching the pty supervisor's `pump`).
fn status_code(status: std::process::ExitStatus) -> i32 {
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
    let (prog, args) = super::cgroup::wrap(bwrap, argv, limits, &spec.cage_slug);
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
    // The seccomp filters are loaded into anonymous files *before* the fork so the
    // child inherits their descriptors; the parent holds `seccomp` alive through
    // `pump` so the descriptors stay open until bwrap has read them.
    let seccomp = super::seccomp::memfds(&spec.seccomp)?;

    // Build the bwrap argv (seccomp prefix + the hardened spec), then wrap it in
    // the resource-limit scope: the program may become `systemd-run` with bwrap
    // spliced in after `--`. Compose as C strings *before* forking — nothing
    // between fork and exec may allocate.
    let mut bwrap_argv = super::seccomp::argv_prefix(&seccomp);
    bwrap_argv.extend(super::argv::to_argv(spec));
    let (program, full_argv) = super::cgroup::wrap(bwrap, bwrap_argv, limits, &spec.cage_slug);
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

/// Relay bytes between the real terminal and the pty master until the session
/// ends, then reap the child and return its exit status code. `winch_fd` is the read
/// end of the resize relay's self-pipe (or `-1` when it could not be installed — `poll`
/// ignores a negative fd), readable when a `SIGWINCH` has arrived.
/// A second Ctrl+C within this window force-quits a graphical session (see the stdin relay below).
const DOUBLE_CTRL_C_WINDOW: Duration = Duration::from_secs(2);

/// What a chunk of graphical-session stdin means for the double-Ctrl+C escape hatch.
#[derive(Debug, PartialEq, Eq)]
enum CtrlC {
    /// No Ctrl+C in the chunk — forward it unchanged.
    None,
    /// The first Ctrl+C (or one after the window lapsed) — forward it, and arm the window.
    Arm,
    /// A second Ctrl+C within the window (across reads, or two buffered in one read) — force-quit.
    Escalate,
}

/// Decide, purely, what a stdin `chunk` means for the double-Ctrl+C force-quit: escalate when a
/// Ctrl+C (`0x03`) follows a prior one still inside [`DOUBLE_CTRL_C_WINDOW`] (`last` → `now`), or when
/// two arrive buffered in the same chunk; arm on the first; otherwise nothing. Kept side-effect-free
/// so the timing/threshold logic is unit-testable without a live pty.
fn classify_ctrl_c(chunk: &[u8], last: Option<Instant>, now: Instant) -> CtrlC {
    let count = chunk.iter().filter(|&&b| b == 0x03).count();
    if count == 0 {
        return CtrlC::None;
    }
    let armed = last.is_some_and(|t| now.duration_since(t) < DOUBLE_CTRL_C_WINDOW);
    if armed || count >= 2 {
        CtrlC::Escalate
    } else {
        CtrlC::Arm
    }
}

fn pump(
    master: libc::c_int,
    child: libc::pid_t,
    winch_fd: libc::c_int,
    gui: bool,
) -> io::Result<i32> {
    let mut fds = [
        libc::pollfd {
            fd: 0,
            events: libc::POLLIN,
            revents: 0,
        },
        libc::pollfd {
            fd: master,
            events: libc::POLLIN,
            revents: 0,
        },
        libc::pollfd {
            fd: winch_fd,
            events: libc::POLLIN,
            revents: 0,
        },
    ];
    let mut buf = [0u8; 8192];
    let mut stdin_open = true;
    // For a GUI cage: the instant of the last unescalated Ctrl+C, so a second within the window
    // force-quits (a graphical app ignores the forwarded SIGINT). `None` outside a GUI cage.
    let mut last_ctrl_c: Option<Instant> = None;

    loop {
        let r = unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, -1) };
        if r < 0 {
            let e = io::Error::last_os_error();
            if e.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(e);
        }

        // A resize arrived: drain the self-pipe and copy the real terminal's window size
        // onto the pty. Handled before stdin so a resize delivered alongside input takes
        // effect before that input reaches the inner program.
        if fds[2].revents != 0 {
            drain_and_resize(winch_fd, master);
        }

        // master -> stdout. Quit when the master closes (the child exited), which
        // on Linux surfaces as EIO rather than a clean EOF.
        if fds[1].revents != 0 {
            let n = unsafe { libc::read(master, buf.as_mut_ptr().cast(), buf.len()) };
            if n > 0 {
                write_all(1, &buf[..n as usize])?;
            } else if n == 0 {
                break;
            } else {
                let e = io::Error::last_os_error();
                if e.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                break; // EIO: end of session
            }
        }

        // stdin -> master. When the user's stdin ends, stop forwarding it but
        // keep relaying the master until the child exits.
        if stdin_open && fds[0].revents != 0 {
            let n = unsafe { libc::read(0, buf.as_mut_ptr().cast(), buf.len()) };
            if n > 0 {
                let chunk = &buf[..n as usize];
                // A graphical app ignores the forwarded SIGINT, so a single Ctrl+C does nothing and
                // closing a tray-backed window may not terminate it. Offer a deterministic escape
                // hatch on a GUI cage only: a second Ctrl+C within the window force-quits the cage.
                // The first is still forwarded, so a non-GUI shell's own SIGINT stays untouched (the
                // relay never intercepts Ctrl+C there — `gui` is false).
                if gui {
                    let now = Instant::now();
                    match classify_ctrl_c(chunk, last_ctrl_c, now) {
                        CtrlC::Escalate => {
                            let _ = write_all(2, b"\r\nsbx: force-quitting the session.\r\n");
                            return terminate_and_reap(child);
                        }
                        CtrlC::Arm => {
                            last_ctrl_c = Some(now);
                            let _ = write_all(
                                2,
                                b"\r\nsbx: press Ctrl+C again to force-quit this graphical session.\r\n",
                            );
                        }
                        CtrlC::None => {}
                    }
                }
                // best-effort: if the child is gone, the master read above ends us
                let _ = write_all(master, chunk);
            } else if n == 0 || io::Error::last_os_error().kind() != io::ErrorKind::Interrupted {
                stdin_open = false;
                fds[0].fd = -1; // poll ignores a negative fd
            }
        }
    }

    let mut status: libc::c_int = 0;
    loop {
        let r = unsafe { libc::waitpid(child, &mut status, 0) };
        if r < 0 && io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
            continue;
        }
        break;
    }
    Ok(exit_code(status))
}

/// Translate a `waitpid` status into the process exit-code convention (`128 + signal` for a
/// signalled child), shared by the pty relay's normal reap and its force-quit path.
fn exit_code(status: libc::c_int) -> i32 {
    if libc::WIFEXITED(status) {
        libc::WEXITSTATUS(status)
    } else if libc::WIFSIGNALED(status) {
        128 + libc::WTERMSIG(status)
    } else {
        1
    }
}

/// Force-terminate a supervised cage and reap it, returning its exit-status code — `SIGTERM`, a
/// brief grace for a clean shutdown, then `SIGKILL`, the same escalation `sbx session stop` uses. Invoked
/// from the pty relay when a graphical session is force-quit with a double Ctrl+C.
fn terminate_and_reap(child: libc::pid_t) -> io::Result<i32> {
    unsafe { libc::kill(child, libc::SIGTERM) };
    // Poll for a graceful exit for up to ~2s before the hard kill.
    for _ in 0..40 {
        let mut status: libc::c_int = 0;
        let r = unsafe { libc::waitpid(child, &mut status, libc::WNOHANG) };
        if r == child {
            return Ok(exit_code(status));
        }
        if r < 0 && io::Error::last_os_error().kind() != io::ErrorKind::Interrupted {
            return Ok(1); // already reaped / gone
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    unsafe { libc::kill(child, libc::SIGKILL) };
    let mut status: libc::c_int = 0;
    loop {
        let r = unsafe { libc::waitpid(child, &mut status, 0) };
        if r < 0 && io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
            continue;
        }
        break;
    }
    Ok(exit_code(status))
}

/// Write the whole buffer, retrying short writes and interrupts.
fn write_all(fd: libc::c_int, mut buf: &[u8]) -> io::Result<()> {
    while !buf.is_empty() {
        let n = unsafe { libc::write(fd, buf.as_ptr().cast(), buf.len()) };
        if n < 0 {
            let e = io::Error::last_os_error();
            if e.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(e);
        }
        buf = &buf[n as usize..];
    }
    Ok(())
}

/// The write end of the resize relay's self-pipe, read by the `SIGWINCH` handler. A process-wide
/// atomic because a signal handler cannot capture state; `-1` when no relay is installed. Only one
/// pty supervisor runs per process, so there is a single writer.
static WINCH_WRITE_FD: AtomicI32 = AtomicI32::new(-1);

/// `SIGWINCH` handler: nudge the supervisor by writing one byte to the self-pipe. Async-signal-safe
/// — it does nothing but a single `write` of a constant byte to a non-blocking fd read from an
/// atomic (no allocation, no locks). A full pipe (`EAGAIN`) or absent relay is ignored: the
/// supervisor coalesces, so a dropped nudge only means an already-pending resize is still pending.
extern "C" fn winch_handler(_sig: libc::c_int) {
    let fd = WINCH_WRITE_FD.load(Ordering::Relaxed);
    if fd >= 0 {
        let byte = [1u8];
        unsafe { libc::write(fd, byte.as_ptr().cast(), 1) };
    }
}

/// Relays terminal resizes onto the pty master for the life of a supervised session. Installs a
/// `SIGWINCH` self-pipe handler on construction and restores the previous disposition (and closes
/// the pipe) on drop, so the handler is live only while the supervisor is pumping.
struct WinchRelay {
    read_fd: libc::c_int,
    write_fd: libc::c_int,
    previous: libc::sigaction,
}

impl WinchRelay {
    /// Create the self-pipe and install the `SIGWINCH` handler, saving the previous disposition to
    /// restore on drop. Both ends are `O_CLOEXEC` (never inherited by bwrap); the read end is
    /// `O_NONBLOCK` so draining it in the poll loop cannot block.
    fn install() -> io::Result<Self> {
        let mut fds = [0 as libc::c_int; 2];
        // SAFETY: `pipe2` fills the two-element array.
        if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC | libc::O_NONBLOCK) } != 0 {
            return Err(io::Error::last_os_error());
        }
        let (read_fd, write_fd) = (fds[0], fds[1]);
        WINCH_WRITE_FD.store(write_fd, Ordering::Relaxed);

        // SAFETY: `act` is zeroed then fully initialized before use; `previous` receives the old
        // disposition. The handler is async-signal-safe (see `winch_handler`).
        let mut act: libc::sigaction = unsafe { std::mem::zeroed() };
        act.sa_sigaction = winch_handler as *const () as libc::sighandler_t;
        unsafe { libc::sigemptyset(&mut act.sa_mask) };
        // No `SA_RESTART`: a resize should interrupt the blocking `poll` (the self-pipe is the
        // primary wakeup; the `EINTR` is a harmless second one the loop already handles).
        act.sa_flags = 0;
        let mut previous: libc::sigaction = unsafe { std::mem::zeroed() };
        if unsafe { libc::sigaction(libc::SIGWINCH, &act, &mut previous) } != 0 {
            let e = io::Error::last_os_error();
            WINCH_WRITE_FD.store(-1, Ordering::Relaxed);
            unsafe {
                libc::close(read_fd);
                libc::close(write_fd);
            }
            return Err(e);
        }
        Ok(WinchRelay {
            read_fd,
            write_fd,
            previous,
        })
    }

    fn read_fd(&self) -> libc::c_int {
        self.read_fd
    }
}

impl Drop for WinchRelay {
    fn drop(&mut self) {
        // Restore the previous handler *first*, so `winch_handler` can no longer run, before
        // clearing the fd it reads and closing the pipe — no signal can then touch a closed fd.
        unsafe { libc::sigaction(libc::SIGWINCH, &self.previous, std::ptr::null_mut()) };
        WINCH_WRITE_FD.store(-1, Ordering::Relaxed);
        unsafe {
            libc::close(self.read_fd);
            libc::close(self.write_fd);
        }
    }
}

/// Drain the resize self-pipe (coalescing however many `SIGWINCH`s queued) and copy the real
/// terminal's window size onto the pty master. Setting the master's size makes the kernel deliver
/// `SIGWINCH` to the pty's foreground process group — the cage's interactive program.
fn drain_and_resize(pipe_fd: libc::c_int, master: libc::c_int) {
    let mut sink = [0u8; 64];
    // The read end is non-blocking, so this stops at `EAGAIN`.
    while unsafe { libc::read(pipe_fd, sink.as_mut_ptr().cast(), sink.len()) } > 0 {}
    copy_winsize(0, master);
}

/// Copy `src`'s window size onto `dst` (`TIOCGWINSZ` → `TIOCSWINSZ`). Best effort: if `src` has no
/// size (not a terminal), `dst` is left unchanged.
fn copy_winsize(src: libc::c_int, dst: libc::c_int) {
    let mut ws: libc::winsize = unsafe { std::mem::zeroed() };
    if unsafe { libc::ioctl(src, libc::TIOCGWINSZ, &mut ws) } == 0 {
        unsafe { libc::ioctl(dst, libc::TIOCSWINSZ, &ws) };
    }
}

/// Put a terminal into raw mode, restoring the original settings on drop (covers
/// normal return, `?`, and panic — but not a `SIGKILL`/`SIGTERM`).
struct RawMode {
    fd: libc::c_int,
    original: libc::termios,
}

impl RawMode {
    fn enable(fd: libc::c_int) -> io::Result<Self> {
        let mut original: libc::termios = unsafe { std::mem::zeroed() };
        if unsafe { libc::tcgetattr(fd, &mut original) } != 0 {
            return Err(io::Error::last_os_error());
        }
        let mut raw = original;
        unsafe { libc::cfmakeraw(&mut raw) };
        if unsafe { libc::tcsetattr(fd, libc::TCSAFLUSH, &raw) } != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(RawMode { fd, original })
    }
}

impl Drop for RawMode {
    fn drop(&mut self) {
        unsafe { libc::tcsetattr(self.fd, libc::TCSAFLUSH, &self.original) };
    }
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

/// Layer the cage's extra environment, lowest precedence first: host passthrough, then sbx's
/// hermetic CA bundle, then the Wayland GUI hole, then the non-`nix:` auto-equip variable, then a
/// trusted project's mise `[env]`, then the egress machinery, then the `.sbx.toml` `[env]`. The
/// assembler upserts these over the structural defaults and takes the last occurrence of a key,
/// so a later layer wins: the egress proxy's per-session CA overrides the structural cacert under
/// an allowlist, and a trusted config has the final say (self-harm only). The CA bundle sits
/// above passthrough on purpose — passthrough is a separate channel, not filtered by the
/// untrusted-config denylist, so a host CA variable could otherwise clobber sbx's hermetic
/// bundle. The GUI keys (`WAYLAND_DISPLAY`/`XDG_RUNTIME_DIR`) collide with nothing else, so their
/// position is immaterial; they sit here for a single, documented precedence order.
fn extra_cage_env(
    passthrough: Vec<(String, String)>,
    cacert: Vec<(String, String)>,
    gui: Vec<(String, String)>,
    autoequip: Vec<(String, String)>,
    mise: Vec<(String, String)>,
    egress: Vec<(String, String)>,
    config: &[(String, String)],
) -> Vec<(String, String)> {
    let mut env = passthrough;
    env.extend(cacert);
    env.extend(gui);
    env.extend(autoequip);
    env.extend(mise);
    env.extend(egress);
    env.extend(config.iter().cloned());
    env
}

fn missing(what: &str) -> ExitCode {
    eprintln!("sbx: {what} not found — the sandbox cannot run. See `sbx doctor`.");
    ExitCode::FAILURE
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::Origin;
    use crate::testutil::TmpDir;
    use std::path::PathBuf;

    const REV: &str = "9ae611a455b90cf061d8f332b977e387bda8e1ca";

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
            render_gui_stop_hint("opencode-desktop", 4242, &p),
            "sbx: opencode-desktop is graphical — press Ctrl+C twice here to quit (closing its window may only \
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
    }

    #[test]
    fn launch_display_name_prefers_the_app_then_the_program_basename() {
        // An `sbx app` launch names the app; a plain `sbx run` into a GUI project names the
        // program by its basename (never a store path); an empty command falls back cleanly.
        assert_eq!(
            launch_display_name(&binds::Runtime::GlobalApp("opencode-desktop"), &[]),
            "opencode-desktop"
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
        // caution hue (yellow), a no-op is dim, and an identifier is cyan. The verb of an attach
        // announcement stays plain (it is not a completed state change).
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

    #[test]
    fn double_ctrl_c_escalates_only_within_the_window() {
        let now = Instant::now();
        // Ordinary keystrokes carry no Ctrl+C.
        assert_eq!(classify_ctrl_c(b"ls -la\r", None, now), CtrlC::None);
        // The first Ctrl+C arms the window but does not force-quit.
        assert_eq!(classify_ctrl_c(b"\x03", None, now), CtrlC::Arm);
        // A second Ctrl+C while the window is still open escalates.
        let recent = now - Duration::from_millis(500);
        assert_eq!(classify_ctrl_c(b"\x03", Some(recent), now), CtrlC::Escalate);
        // A second after the window lapsed only re-arms (no force-quit on a stale first press).
        let stale = now - (DOUBLE_CTRL_C_WINDOW + Duration::from_millis(1));
        assert_eq!(classify_ctrl_c(b"\x03", Some(stale), now), CtrlC::Arm);
        // Two Ctrl+C buffered in a single read (a fast double-tap) escalate immediately.
        assert_eq!(classify_ctrl_c(b"\x03\x03", None, now), CtrlC::Escalate);
        // An armed window plus a chunk with no Ctrl+C is still nothing (a real keystroke can pass).
        assert_eq!(classify_ctrl_c(b"y\r", Some(recent), now), CtrlC::None);
    }

    #[test]
    fn exit_code_maps_clean_and_signalled_children() {
        // waitpid encodes a clean exit in the high byte; code 7 -> 7.
        assert_eq!(exit_code(7 << 8), 7);
        // A signalled child is 128 + signo — the SIGKILL the force-quit escalates to.
        assert_eq!(exit_code(libc::SIGKILL), 128 + libc::SIGKILL);
    }

    /// A minimal resolved config carrying only the channel choices the builder reads.
    fn resolved(global: Option<&str>, project: Option<&str>) -> crate::config::Resolved {
        crate::config::Resolved {
            env: vec![],
            env_layer: Default::default(),
            binds: vec![],
            bind_layer: Default::default(),
            packages: vec![],
            nixpkgs_global: global.map(String::from),
            nixpkgs_project: project.map(String::from),
            mise: None,
            network: crate::config::NetworkPolicy::default(),
            network_origin: Default::default(),
            egress_stats: true,
            gui: crate::config::GuiPolicy::default(),
            gui_origin: Default::default(),
            proc: Default::default(),
            proc_origin: Default::default(),
            gpu: false,
            audio: false,
            dbus: false,
            gpu_origin: Default::default(),
            audio_origin: Default::default(),
            dbus_origin: Default::default(),
            forward: vec![],
            forward_origin: Default::default(),
            limits: Default::default(),
            limits_origin: Default::default(),
            secrets: vec![],
            seccomp: Default::default(),
            seccomp_origin: Default::default(),
            devices: Vec::new(),
            devices_origin: Default::default(),
            declared_secrets: vec![],
            apps: std::collections::BTreeMap::new(),
            warnings: vec![],
        }
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
        }
    }

    fn nix_pkg(name: &str, attr: &str) -> crate::config::Package {
        crate::config::Package {
            name: name.into(),
            backend: crate::config::Backend::Nix(attr.into()),
            state: crate::trust::TrustState::Trusted,
        }
    }

    fn app_overlay(
        cmd: &[&str],
        scope: crate::config::AppHomeScope,
        packages: Vec<crate::config::Package>,
    ) -> crate::config::ResolvedApp {
        crate::config::ResolvedApp {
            cmd: cmd.iter().map(|s| s.to_string()).collect(),
            home_scope: scope,
            env: vec![],
            binds: vec![],
            packages,
            network: None,
            gui: None,
            gpu: None,
            audio: None,
            dbus: None,
            limits: Default::default(),
            forward: vec![],
            secrets: vec![],
            default_methods: crate::allowlist::Methods::Unspecified,
            cmd_origin: Default::default(),
            network_origin: Default::default(),
            gui_origin: Default::default(),
            gpu_origin: Default::default(),
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

        let groups = mise_package_groups(&cfg);
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

        let target =
            effective_lock_target(Path::new("/nonexistent"), &layout, &resolved(None, None))
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

        let target = effective_lock_target(proj.path(), &layout, &resolved(None, Some(REV)))
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
        assert!(!collect_roots(&userland, &pkg_roots, &[], &font_roots)
            .contains(&PathBuf::from("/nix/store/nodejs")));
        assert!(!collect_roots(&userland, &[], &tool_roots, &font_roots)
            .contains(&PathBuf::from("/nix/store/jq")));
        assert!(!collect_roots(&userland, &pkg_roots, &tool_roots, &[])
            .contains(&PathBuf::from("/nix/store/dejavu")));
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

        let cacert = vec![(
            "SSL_CERT_FILE".into(),
            "/etc/ssl/certs/ca-bundle.crt".into(),
        )];
        let egress = vec![("SSL_CERT_FILE".into(), "/opt/sbx/egress-ca.pem".into())];
        let env = extra_cage_env(
            vec![],
            cacert.clone(),
            vec![],
            vec![],
            vec![],
            egress.clone(),
            &[],
        );
        assert_eq!(
            winner(&env).as_deref(),
            Some("/opt/sbx/egress-ca.pem"),
            "egress CA must override the structural cacert"
        );

        let cfg = vec![("SSL_CERT_FILE".into(), "/cfg/ca.pem".into())];
        let env = extra_cage_env(vec![], cacert, vec![], vec![], vec![], egress, &cfg);
        assert_eq!(
            winner(&env).as_deref(),
            Some("/cfg/ca.pem"),
            "a trusted config has the final say over the CA"
        );

        // with no egress (shared/isolated posture) the structural cacert stands
        let cacert = vec![(
            "SSL_CERT_FILE".into(),
            "/etc/ssl/certs/ca-bundle.crt".into(),
        )];
        let env = extra_cage_env(vec![], cacert, vec![], vec![], vec![], vec![], &[]);
        assert_eq!(
            winner(&env).as_deref(),
            Some("/etc/ssl/certs/ca-bundle.crt"),
            "without egress the hermetic cacert is the trust anchor"
        );
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

        let argv = wrap_mise_equip(&mise, &bash, "install", &tokens, cmd);

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

        let argv = wrap_mise_equip(&mise, &bash, "use -g", &tokens, cmd);

        let script = argv[2].to_string_lossy();
        assert!(script.contains("/nix/store/mise/bin/mise use -g \"${@:1:1}\""));
        assert!(script.contains("shift 1;"));
        // the token is a positional arg, never in the script
        assert_eq!(argv[4], OsString::from("aqua:example/demo-tool"));
        assert_eq!(argv[5], OsString::from("demo-app"));
    }

    #[test]
    fn wrap_flake_equip_passes_refs_and_command_positionally_and_short_circuits() {
        // Each (ref, out-link, key) rides `"$@"`, so a value from an untrusted-but-trusted-app
        // config can never inject shell: only the absolute nix path, the out-link parent, and
        // the integer triple count reach the script string. The short-circuit, the per-triple
        // `nix build`, and the host-resolvable gc root (keyed by package name, the `$3`
        // positional, never interpolated) are all present.
        let nix = PathBuf::from("/nix/store/nix/bin/nix");
        let bash = PathBuf::from("/nix/store/bash/bin/bash");
        let dir = PathBuf::from("/home/sandbox/.local/state/sbx/flake");
        let triples = vec![
            (
                "github:example/flake-tool#tui".to_string(),
                PathBuf::from("/home/sandbox/.local/state/sbx/flake/flake-tool"),
                "flake-tool".to_string(),
            ),
            // a hostile ref must stay a single positional arg, never reach the script
            (
                "github:evil/x#bin; rm -rf /".to_string(),
                PathBuf::from("/home/sandbox/.local/state/sbx/flake/evil"),
                "evil".to_string(),
            ),
        ];
        let cmd = vec![OsString::from("flake-tool"), OsString::from("-z")];

        let argv = wrap_flake_equip(&nix, &bash, &dir, &triples, cmd);

        assert_eq!(argv[0], OsString::from("/nix/store/bash/bin/bash"));
        assert_eq!(argv[1], OsString::from("-c"));
        let script = argv[2].to_string_lossy();
        // nix by absolute path; the triple count drives the loop, not the refs; the out-link
        // presence short-circuits the build; the command is exec'd after the triples are shifted.
        assert!(script.contains("n=2"));
        assert!(script.contains(
            "[ -e \"$out/bin\" ] || '/nix/store/nix/bin/nix' build \"$1\" \
             --no-write-lock-file --out-link \"$out\""
        ));
        assert!(script.contains("mkdir -p '/home/sandbox/.local/state/sbx/flake'"));
        // the gc root is keyed by the `$3` positional (the package name), targeting the build's
        // store path resolved by `readlink -f` — host-resolvable, overwritten each launch
        assert!(script.contains("ln -sfn \"$sp\" \"/nix/var/nix/gcroots/sbx-flake-$3\""));
        assert!(script.contains("shift 3"));
        assert!(script.trim_end().ends_with("exec \"$@\""));
        assert!(
            !script.contains("rm -rf"),
            "a hostile ref must never be interpolated into the script: {script}"
        );
        // label, then interleaved (ref, out-link, key) triples, then the command — all positional
        assert_eq!(argv[3], OsString::from("sbx-flake-equip"));
        assert_eq!(argv[4], OsString::from("github:example/flake-tool#tui"));
        assert_eq!(
            argv[5],
            OsString::from("/home/sandbox/.local/state/sbx/flake/flake-tool")
        );
        assert_eq!(argv[6], OsString::from("flake-tool"));
        assert_eq!(argv[7], OsString::from("github:evil/x#bin; rm -rf /"));
        assert_eq!(
            argv[8],
            OsString::from("/home/sandbox/.local/state/sbx/flake/evil")
        );
        assert_eq!(argv[9], OsString::from("evil"));
        assert_eq!(argv[10], OsString::from("flake-tool"));
        assert_eq!(argv[11], OsString::from("-z"));
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
        // The daemon and the reporting parent must agree on the log location; both derive it from
        // the session pid, so this is the single source of that name.
        let path = detach_log_path(Path::new("/var/lib/sbx"), 4242);
        assert_eq!(path, PathBuf::from("/var/lib/sbx/logs/4242.log"));
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
