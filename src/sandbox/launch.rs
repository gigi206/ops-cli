//! Launching a sandbox: turning a [`SandboxSpec`] into a running bubblewrap
//! process.
//!
//! Two launch models, by terminal policy:
//! - `ops run` is non-interactive: it execs bwrap and lets it *replace* the ops
//!   process, so the command inherits the real stdio and its exit status becomes
//!   ops's. The spec uses [`TerminalPolicy::NewSession`].
//! - `ops shell` is interactive: ops stays alive as a **pty supervisor**. It
//!   gives the sandbox a private controlling terminal (so job control works
//!   inside) and relays bytes to and from the real terminal (which the sandbox
//!   therefore cannot reach). The spec uses [`TerminalPolicy::PrivateTty`], which
//!   omits `--new-session` — bubblewrap's `setsid` would `setsid` away from that
//!   private terminal.
//!
//! The supervisor also relays terminal resizes: it catches `SIGWINCH` on the real
//! terminal and pushes the new window size onto the pty master, so the kernel
//! delivers `SIGWINCH` to the cage's foreground process group and an interactive
//! TUI reflows live. Interactive `ops app` launches ride this same supervisor.
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
use std::time::Duration;

/// The hard prerequisites and per-launch resolution shared by `run` and `shell`:
/// the engine, ops's store layout, the current directory, the resolved
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
    /// channel but rolls independently via `ops upgrade mise`). mise runs in its own
    /// store view, free of the one-channel rule, so it may sit on a different revision
    /// than `nixpkgs`. Drives both the in-cage mise (the base userland) and the
    /// host-side `[env]` driver.
    engine_ref: String,
    userland: Userland,
}

/// `ops run [--] <cmd>`: run a command inside the project sandbox, replacing the
/// ops process so the command's exit status becomes ops's.
pub(crate) fn run(cmd: Vec<OsString>, detach: bool, ov: crate::config::Override) -> ExitCode {
    if cmd.is_empty() {
        eprintln!("ops: usage: {}", crate::help::synopsis("run"));
        return ExitCode::from(2);
    }
    let mut prep = match prepare_with(&ov) {
        Ok(p) => p,
        Err(code) => return code,
    };
    // The override is the authoritative final word over the resolved baseline (`ops run`/`ops
    // shell` have no app overlay, so here is that final point).
    if let Err(code) = apply_launch_override(&mut prep.cfg, ov) {
        return code;
    }
    launch(
        prep,
        binds::Runtime::ProjectDefault,
        Kind::Run,
        cmd,
        detach,
        "run",
    )
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
            eprintln!("ops: {e}");
        }
        ExitCode::from(2)
    })
}

/// Build the cage, register it, and run it — either in the foreground (this process becomes or
/// supervises the cage) or detached into a background daemon. The single seam `run`, `app`, and
/// the mise passthrough share, so the build → register → launch sequence is identical on both
/// paths and lives in one place. `label` names the session in the detached startup message.
fn launch(
    prep: Prepared,
    runtime: binds::Runtime,
    kind: Kind,
    cmd: Vec<OsString>,
    detach: bool,
    label: &str,
) -> ExitCode {
    if detach {
        warn_ask_under_detach(&prep.cfg.network);
        launch_detached(prep, runtime, kind, cmd, label)
    } else {
        launch_foreground(prep, runtime, kind, cmd)
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
                 `[network] ask_timeout`, or answer it with `ops net pending`.",
            );
        }
    }
}

/// Run the cage in the foreground: this process becomes the cage (exec) or supervises it
/// (allowlist), and its exit status becomes ops's.
fn launch_foreground(
    prep: Prepared,
    runtime: binds::Runtime,
    kind: Kind,
    cmd: Vec<OsString>,
) -> ExitCode {
    let (spec, guard) = match build(&prep, runtime, cmd) {
        Ok(v) => v,
        Err(code) => return code,
    };

    register(prep.layout.data_dir(), &spec, kind, runtime);

    match guard {
        // The default postures: exec-replace, so the command's exit status becomes ops's.
        // The pid and its start time survive the exec, so the registry record keeps matching
        // the sandbox and is reclaimed by liveness pruning once it exits.
        None => {
            // On success this never returns; reaching past it means exec itself failed.
            let err = exec(&prep.bwrap, &spec, &prep.cfg.limits);
            eprintln!("ops: failed to launch the sandbox: {err}");
            ExitCode::FAILURE
        }
        // A network allowlist or an forward forwarder: ops cannot exec-replace, because a host
        // thread (the filtering proxy and/or the forward accept pumps) must outlive the cage.
        // Supervise instead — fork bwrap, wait, propagate the exit status — keeping the thread(s)
        // alive and the guard (which unlinks the sockets and CA) held for the whole session.
        Some(guard) => {
            let code = run_supervised(&prep.bwrap, &spec, &prep.cfg.limits);
            drop(guard);
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
) -> ExitCode {
    let mut fds = [0 as libc::c_int; 2];
    // SAFETY: `pipe2` fills the two-element array; `O_CLOEXEC` so neither end leaks into the
    // eventual `exec` of bwrap.
    if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
        eprintln!(
            "ops: cannot create the detach pipe: {}",
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
                "ops: cannot start the detached session: {}",
                io::Error::last_os_error()
            );
            ExitCode::FAILURE
        }
        0 => {
            // Child: the parent's read end is not ours.
            unsafe { libc::close(read_fd) };
            detached_child(prep, runtime, kind, cmd, write_fd)
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
/// run a second time in the child.
fn detached_child(
    prep: Prepared,
    runtime: binds::Runtime,
    kind: Kind,
    cmd: Vec<OsString>,
    write_fd: libc::c_int,
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
                "ops: cannot open the session log {}: {e}",
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

    match guard {
        None => {
            // exec-replace: bwrap (pid 1 of the cage's namespace) inherits the redirected stdio.
            let err = exec(&prep.bwrap, &spec, &prep.cfg.limits);
            eprintln!("ops: failed to launch the sandbox: {err}");
            std::process::exit(1);
        }
        Some(guard) => {
            // Supervise: this daemon is the long-lived parent the proxy/forwarder threads and
            // bwrap (`--die-with-parent`) hang from. Drop the guard explicitly before exiting — a
            // bare `process::exit` runs no destructors, so the sockets and CA would otherwise leak
            // even on a clean exit.
            let code = run_status(&prep.bwrap, &spec, &prep.cfg.limits);
            drop(guard);
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
            "ops: started `{label}` as detached session {child} (logs: {})",
            log.display()
        );
        eprintln!(
            "ops: `ops ls` lists it, `ops attach {child}` opens a shell beside it, \
             `ops stop {child}` ends it."
        );
        ExitCode::SUCCESS
    } else {
        // The daemon closed the pipe without signalling success: it failed before launch (the
        // error is already on this terminal). Reap it.
        // SAFETY: `waitpid` on our own child.
        unsafe { libc::waitpid(child, std::ptr::null_mut(), 0) };
        eprintln!("ops: the detached session failed to start (see the error above).");
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

/// `ops app <name>`: launch the named application profile — the project sandbox baseline
/// plus the app's gated overlay, running the command the app declares. Apps run in the same
/// locked-down posture as `ops run`; the overlay's security fields took effect only if their
/// source was trusted (the global config or a trusted project), so launching an app on
/// untrusted code is as safe as `ops run` there.
/// The result of an `ops app <name>` launch: the exit code, plus — for a `--net-learn` run — the
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

pub(crate) fn app(
    name: &str,
    detach: bool,
    extra: Vec<OsString>,
    ov: crate::config::Override,
    net_learn: Option<super::Granularity>,
) -> AppOutcome {
    let mut prep = match prepare_with(&ov) {
        Ok(p) => p,
        Err(code) => return AppOutcome::plain(code),
    };
    let Some(app) = prep.cfg.apps.remove(name) else {
        eprintln!("ops: no app named `{name}`.{}", available_apps(&prep.cfg));
        return AppOutcome::plain(ExitCode::from(2));
    };
    if app.cmd.is_empty() {
        eprintln!(
            "ops: app `{name}` declares no command — add a `cmd` to its `[app.{name}]` table."
        );
        return AppOutcome::plain(ExitCode::FAILURE);
    }
    // The argv and the home scope are owned by the app; read them before the overlay is folded
    // in (which moves the app but does not touch them). The scope keys this app's persistent
    // home: one shared across projects (`Global`) or one per project (`Project`). Any trailing
    // `ops app <name> -- <args>` are appended to the declared `cmd`, so the caller can pass a flag
    // to the launched program (e.g. `-c` to resume) without editing the profile.
    let mut cmd: Vec<OsString> = app.cmd.iter().map(OsString::from).collect();
    cmd.extend(extra);
    let runtime = match app.home_scope {
        crate::config::AppHomeScope::Global => binds::Runtime::GlobalApp(name),
        crate::config::AppHomeScope::Project => binds::Runtime::ProjectApp(name),
    };
    eprintln!("ops: launching app `{name}`");
    prep.cfg.merge_app(app);
    // The override is the authoritative final word — applied *after* the app overlay so a one-shot
    // `ops app <name> --config …`/`OPS_*` beats the app's own posture, not the other way round.
    if let Err(code) = apply_launch_override(&mut prep.cfg, ov) {
        return AppOutcome::plain(code);
    }

    // SAFETY: `isatty` only inspects fd 0.
    let interactive = !detach && unsafe { libc::isatty(0) } == 1;

    // `--net-learn`: run the app under its real (unchanged) posture, capture the egress it was
    // refused for lack of a rule, and hand the synthesized rules back for the caller to write. It is
    // foreground-only (the parser refuses `--detach`) and needs a filtering posture — a `shared` or
    // `none` app has no proxy logging egress, so there is nothing to learn.
    if let Some(gran) = net_learn {
        let policy = match &prep.cfg.network {
            crate::config::NetworkPolicy::Allowlist(p) => p.clone(),
            other => {
                eprintln!(
                    "ops: --net-learn needs a filtering network posture (mode allow/deny/ask); \
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
    // (the same isolation `ops shell` uses — the real terminal stays unreachable). A detached
    // agent has no terminal, and a piped/non-tty invocation must not be handed one, so both keep
    // the exec-replace / supervised `NewSession` path.
    let code = if interactive {
        launch_pty_supervised(&prep, runtime, Kind::Run, cmd)
    } else {
        launch(prep, runtime, Kind::Run, cmd, detach, name)
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

/// Run an `ops app` launch in the foreground and return the egress it logged, for `--net-learn`.
/// Interactive launches use the pty supervisor (a private controlling terminal, like `ops shell`);
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
        match supervise(&prep.bwrap, &spec, &prep.cfg.limits) {
            Ok(c) => ExitCode::from(c as u8),
            Err(e) => {
                eprintln!("ops: sandbox session failed: {e}");
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

/// `ops mise [args...]`: run mise inside the project's open cage, where it can
/// self-equip the project's `nix:` tools (`ops mise install nix:<pkg>`) into the
/// project's own writable store. Sugar over `ops run -- mise [args...]`: mise is
/// present in every cage with the `nix:` backend plugin registered, so the only
/// thing this adds is sparing the `run --` prefix.
///
/// A tool the agent *activates* (`mise use [-g] nix:<pkg>`) is on PATH in later
/// launches — through the shims dir on PATH for `ops run`, and `mise activate` for the
/// `ops shell` — and persists in the project's store. A bare `mise install` (not
/// activated) persists too and `mise exec`/`mise which` resolve it, but it is not on
/// PATH, matching mise's own install-vs-use split. This path is intentionally open — it
/// works whether or not the project is trusted, the agent-self-equip posture — unlike
/// `ops run`'s host-side `nix:` provisioning, which stays trusted-only and is a parallel
/// path that does not share state with what mise installs here.
pub(crate) fn run_mise(args: Vec<OsString>) -> ExitCode {
    let mut cmd = vec![OsString::from("mise")];
    cmd.extend(args);
    // `ops mise` is a passthrough — every argument is mise's, so it takes no one-shot override.
    run(cmd, false, crate::config::Override::none())
}

/// Which persistent home a `mise:` package group is equipped in, owning its app name so a
/// group can outlive the config it was derived from. Mirrors [`binds::Runtime`], which borrows
/// the name; [`GroupHome::runtime`] rebuilds the borrowing form at launch.
enum GroupHome {
    /// The project's default shell home — where `ops run`/`ops shell` equip baseline tools.
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
/// project baseline (equipped in its default home by `ops run`/`ops shell`) and each app
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
/// already warned on the launch path, so `ops upgrade` just needs to not read as "none declared".
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
/// `ops upgrade nix`/`all` keeps its cheap, sandbox-free common path. With work to do, a host
/// that cannot sandbox warns and rolls nothing rather than failing (best-effort, like the
/// cgroup limits).
pub(crate) fn upgrade_mise_packages(
    cfg: &crate::config::Resolved,
    pal: &crate::style::Palette,
) -> bool {
    let (h, n, warn, dim, r) = (pal.head, pal.name, pal.warn, pal.dim, pal.reset);
    println!("{h}ops upgrade — mise packages{r}");
    let groups = mise_package_groups(cfg);
    // Surface withheld (untrusted) `mise:` packages so an untrusted project does not silently
    // read as "nothing declared" — parity with the `nix:` tools path, which warns the same.
    let withheld = withheld_mise_packages(cfg);
    if withheld > 0 {
        println!(
            "  {warn}{withheld} mise: package(s) withheld (untrusted){r} — not rolled; run `ops trust`."
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
            crate::diag::warn("mise packages: skipped — no usable sandbox; see `ops doctor`");
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

/// `ops gc [--all] [--prune]`: reclaim ops's store space.
///
/// By default it sweeps the **current** project's store (see [`sweep_current`]). With `--all` it
/// also, across all projects: reaps whole runtime trees whose project directory is gone (see
/// [`reap_dead_trees`]), then garbage-collects the **shared** store — the channel revisions left
/// behind by `ops upgrade` and the tools of reaped projects (see [`shared_store_gc`]). The
/// cross-project passes run **first** and are independent of the sandbox/nix prerequisites the
/// current-project sweep needs — so `ops gc --all` reclaims even from a directory that is not a
/// project, or on a host that has lost its sandbox capability. A dry run by default; `--prune` is
/// the destructive form.
pub(crate) fn gc(
    prune: bool,
    all: bool,
    prune_unidentified: bool,
    pal: &crate::style::Palette,
) -> ExitCode {
    if all {
        match crate::store::Layout::from_env() {
            Some(layout) => {
                let live_ids = session_housekeeping(&layout, pal);
                reap_dead_trees(&layout, &live_ids, prune, prune_unidentified, pal);
                shared_store_gc(&layout, prune, pal);
            }
            None => eprintln!(
                "ops gc: cannot locate ops's data directory; skipping the cross-project housekeeping."
            ),
        }
    }
    match sweep_current(prune, pal) {
        Ok(()) => ExitCode::SUCCESS,
        // Under `--all` the reap above already ran, so a current-project sweep that could not run
        // (the host cannot sandbox, nix is unavailable) — or that hit an error — must not fail the
        // whole command. Its own message is already printed above; only the exit code is flattened.
        Err(_) if all => {
            eprintln!(
                "ops gc: the current project's store was not swept (see above); the cross-project reap ran."
            );
            ExitCode::SUCCESS
        }
        Err(code) => code,
    }
}

/// Prune dead session records and report it (the dedicated housekeeping pass the registry deferred:
/// an `ops run` record with no post-exec hook lingered until the next `ops ls`). Returns the ids of
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
                    "{}ops gc --all:{} pruned {}{pruned}{} stale session record(s); {} live.",
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
                "ops gc: cannot read the session registry ({e}); skipping session housekeeping."
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
/// `--unidentified` escape hatch). Pure host-side filesystem work — no sandbox, no nix.
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
        println!("{h}ops gc --all:{r} {dim}no dead project trees to reclaim.{r}");
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
                "{h}ops gc --all:{r} reclaimed {} dead project tree(s), freed up to {}.",
                report.dead.len(),
                super::gc::human_bytes(freed)
            );
        } else {
            println!(
                "{h}ops gc --all:{r} {} dead project tree(s) reclaimable (up to {}) — \
                 run `ops gc --all --prune` to reclaim.",
                report.dead.len(),
                super::gc::human_bytes(freed)
            );
        }
    }

    // Markerless trees reaped under the `--unidentified` opt-in. Their deadness was NOT verified
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
            "{h}ops gc --all --unidentified:{r} reclaimed {} markerless tree(s), freed up to {}.",
            report.reaped_unidentified.len(),
            super::gc::human_bytes(ufreed)
        );
    }

    // Markerless trees not reaped (no opt-in, or a dry run): surfaced for a manual decision. The
    // hint adapts to whether the user is using the `--unidentified` hatch — a dry run of it points
    // at the prune form, the default still points at a by-hand removal (the fail-closed stance).
    for tree in &report.unidentified {
        let hint = if prune_unidentified {
            "run `ops gc --all --unidentified --prune` to reclaim (no deadness proof)"
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

/// Reap — or, in a dry run, measure — one named project tree (`ops gc --id <id>`). The caller
/// supplies the id, so this needs no deadness proof and no marker: it works on markerless trees
/// too, and on trees a marker would call idle. The live-session guard still holds — a tree a
/// running session holds is refused, with a pointer at `ops stop`. Pure host-side filesystem
/// work — no sandbox, no nix — so it runs even where the broad reap cannot.
pub(crate) fn gc_one_tree(id: &str, prune: bool, pal: &crate::style::Palette) -> ExitCode {
    let (h, n, ok, dim, r) = (pal.head, pal.name, pal.ok, pal.dim, pal.reset);
    // Reject a traversal/absolute id before any work: it is joined onto `projects/` and reaches a
    // recursive delete, so only a single path component is allowed (a real id is a 16-hex hash the
    // `ops path` listing shows). `reap_one` re-checks at the sink; this gives the clearer message.
    if !super::gc::is_safe_tree_id(id) {
        eprintln!(
            "ops gc: invalid project id `{id}` — expected a single tree name \
             (the directory name `ops path` lists under projects/), not a path."
        );
        return ExitCode::from(2);
    }
    let Some(layout) = crate::store::Layout::from_env() else {
        eprintln!("ops gc: cannot locate ops's data directory; cannot reap a project tree.");
        return ExitCode::FAILURE;
    };
    let live_ids = session_housekeeping(&layout, pal);
    let projects_dir = layout.data_dir().join("projects");
    match super::gc::reap_one(&projects_dir, id, &live_ids, prune) {
        super::gc::ReapOneOutcome::NotFound => {
            eprintln!(
                "ops gc: no project tree for id `{id}` under {}.",
                projects_dir.display()
            );
            ExitCode::FAILURE
        }
        super::gc::ReapOneOutcome::Live => {
            eprintln!(
                "ops gc: project tree {n}{id}{r} is held by a live session — \
                 stop it first with {n}ops stop{r} (then `ops gc --id {id} --prune`)."
            );
            ExitCode::FAILURE
        }
        super::gc::ReapOneOutcome::Tree { dir, bytes } => {
            let verb = if prune {
                format!("{ok}reclaimed{r}")
            } else {
                format!("{dim}reclaimable{r}")
            };
            println!(
                "  {verb}: {n}{}{r} ({})",
                dir.display(),
                super::gc::human_bytes(bytes)
            );
            if prune {
                println!(
                    "{h}ops gc --id:{r} reclaimed project tree {n}{id}{r}, freed up to {}.",
                    super::gc::human_bytes(bytes)
                );
            } else {
                println!(
                    "{h}ops gc --id:{r} {n}{id}{r} reclaimable ({}) — \
                     run `ops gc --id {id} --prune` to reclaim.",
                    super::gc::human_bytes(bytes)
                );
            }
            ExitCode::SUCCESS
        }
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
/// it is never corruption. Widening the ops lock to cover provisioning would make this collector
/// wait behind minutes-long builds, so the narrow lock plus this named residual is the deliberate
/// trade.
fn shared_store_gc(layout: &crate::store::Layout, prune: bool, pal: &crate::style::Palette) {
    let (h, r) = (pal.head, pal.reset);
    let Some(nix_store) = crate::store::resolve_nix_store(Some(layout)) else {
        eprintln!("ops gc: nix-store not found; skipping the shared-store gc.");
        return;
    };

    // Exclusive across the whole prune + `nix-store --gc`: it waits for in-flight seeds to release
    // their shared hold, and blocks new seeds until the collection finishes.
    let _lock = match super::projectstore::lock_exclusive(layout) {
        Ok(guard) => guard,
        Err(e) => {
            eprintln!("ops gc: cannot lock the shared store ({e}); skipping the shared-store gc.");
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
            eprintln!("ops gc: shared-store gc failed: {e}");
            return;
        }
    };

    if prune {
        println!(
            "{h}ops gc --all:{r} shared store — dropped {} stale gc root(s), collected {} store path(s), freed {}.",
            stale.len(),
            report.paths,
            super::gc::human_bytes(report.bytes)
        );
    } else {
        // On a dry run the stale roots are not dropped, so their closures are still rooted and not
        // yet counted as collectable; the count of stale roots is the signal, and `--prune` frees
        // their closures on top of the orphans reported here (a lower bound).
        println!(
            "{h}ops gc --all:{r} shared store — {} stale gc root(s) would be dropped; {} orphaned path(s) \
             reclaimable now ({}). Run `ops gc --all --prune` to drop the roots and reclaim their closures.",
            stale.len(),
            report.paths,
            super::gc::human_bytes(report.bytes)
        );
    }
}

/// Reclaim the current project's own writable store.
///
/// The agent self-equips into a per-project store — `flake:` builds, in-cage installs — and over
/// time a flake revision rolled forward by `ops upgrade flake` (or a package removed outright)
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
/// --out-link <non-store-path>` it runs itself, outside the supported self-equip paths (`ops mise`,
/// `nix profile`, declared `flake:` packages) — is not seen host-side and would be collected. The
/// supported self-equip paths all root by store path, so they survive.
fn sweep_current(prune: bool, pal: &crate::style::Palette) -> Result<(), ExitCode> {
    let (h, n, dim, r) = (pal.head, pal.name, pal.dim, pal.reset);
    let prep = prepare()?;

    let (id, project) = match binds::project_identity(&prep.cwd) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("ops gc: cannot resolve the project directory: {e}");
            return Err(ExitCode::FAILURE);
        }
    };

    // A project that was never launched has no store to reclaim. Seeding one here — just to gc it —
    // would be a heavy, possibly networked side effect, so skip instead. This is what makes
    // `ops gc --all` safe to run from any directory: a non-project cwd is skipped, never seeded.
    if !super::projectstore::store_exists(&prep.layout, &id) {
        println!(
            "{h}ops gc{r} — {n}{}{r}: {dim}no per-project store yet, nothing to reclaim.{r}",
            project.display()
        );
        return Ok(());
    }

    // Refuse if a live sandbox holds this project: collecting a store a running cage reads and
    // writes could drop a path it still needs. The registry list prunes dead records as it goes.
    if let Ok(sessions) = session::Registry::at(prep.layout.data_dir()).list() {
        if sessions.iter().any(|s| s.project == project) {
            eprintln!(
                "ops gc: a sandbox is running in this project — stop it first (see `ops ls`)."
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

    // Drop the `ops-flake-<name>` roots of removed packages. A roll self-cleans (its root is
    // overwritten onto the new build), but a removal leaves the root pointing at an unwanted build;
    // this prunes those so the sweep reclaims them. The current set spans every runtime — the
    // baseline and each app's merged packages — so a flake package declared only in an app keeps
    // its root.
    let mut flake_names: std::collections::BTreeSet<String> =
        super::packages::flake_packages(&prep.cfg.packages)
            .into_iter()
            .map(|(name, _)| name)
            .collect();
    for app in prep.cfg.apps.values() {
        let mut merged = prep.cfg.clone();
        merged.merge_app(app.clone());
        flake_names.extend(
            super::packages::flake_packages(&merged.packages)
                .into_iter()
                .map(|(name, _)| name),
        );
    }
    let pruned = super::gc::prune_flake_roots(&store_dir, &flake_names, prune).len();

    println!("{h}ops gc{r} — {n}{}{r}", project.display());
    let report = match super::gc::collect(&prep.nix_store, &store_dir, prune) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("ops gc: {e}");
            return Err(ExitCode::FAILURE);
        }
    };
    if prune {
        // The pruned roots' builds were unrooted before the sweep, so they are already counted in
        // `report.paths`; name how many removed-package builds that included.
        println!(
            "  {}collected{} {} store path(s) ({} from removed package(s)), freed {}.",
            pal.ok,
            r,
            report.paths,
            pruned,
            super::gc::human_bytes(report.bytes)
        );
    } else {
        // A dry run cannot size the removed-package builds (their roots still hold them, so they are
        // not yet in the dead set), so report their count separately from the currently-dead total.
        println!(
            "  {dim}{} store path(s) collectable now, {} would be freed — run `ops gc --prune` to reclaim.{r}",
            report.paths,
            super::gc::human_bytes(report.bytes)
        );
        if pruned > 0 {
            println!(
                "  {dim}and {pruned} removed-package flake build(s) would also be reclaimed.{r}"
            );
        }
    }
    Ok(())
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
    let packages = super::packages::provision(
        &prep.nix,
        &prep.layout,
        &prep.cwd,
        &prep.nixpkgs,
        &prep.cfg.packages,
    )
    .map_err(|e| {
        eprintln!("ops gc: {e}");
        ExitCode::FAILURE
    })?;
    for warning in &packages.warnings {
        crate::diag::warn(warning);
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
    let font_roots: &[PathBuf] = font_layer.as_ref().map_or(&[], |l| l.roots.as_slice());

    seed_project_store(prep, &packages.roots, &tools.roots, font_roots).map_err(|e| {
        eprintln!("ops gc: cannot prepare the project's store: {e}");
        ExitCode::FAILURE
    })
}

/// `ops shell`: an interactive shell inside the project sandbox, under a pty
/// supervisor so job control works.
pub(crate) fn shell(ov: crate::config::Override) -> ExitCode {
    // SAFETY: `isatty` only inspects fd 0. An interactive shell needs a real
    // terminal to make raw; refuse cleanly rather than corrupt a pipe.
    if unsafe { libc::isatty(0) } != 1 {
        eprintln!(
            "ops: `ops shell` needs a terminal on stdin (use `ops run` for non-interactive use)."
        );
        return ExitCode::from(2);
    }
    let mut prep = match prepare_with(&ov) {
        Ok(p) => p,
        Err(code) => return code,
    };
    if let Err(code) = apply_launch_override(&mut prep.cfg, ov) {
        return code;
    }
    launch_interactive_shell(&prep, binds::Runtime::ProjectDefault)
}

/// Launch an interactive shell in the cage for `runtime`, under a pty supervisor so job control
/// works — the shared body of `ops shell` (the project's default home) and `ops attach` (which
/// reproduces a session's home, including an app's isolated one). The command is the resolved
/// interactive shell started with `--rcfile` at the synthetic in-cage rc, which activates mise so
/// the project's activated tools (`mise use`) manage PATH/env in the interactive shell — mise's
/// documented interactive mechanism. (`ops run` instead reaches activated tools through the shims
/// dir on PATH, with no shell to hook.) Assumes stdin is a terminal (the callers check).
fn launch_interactive_shell(prep: &Prepared, runtime: binds::Runtime) -> ExitCode {
    let cmd = vec![
        prep.userland.shell_bin.clone().into_os_string(),
        OsString::from("--rcfile"),
        OsString::from(binds::SHELL_RC_INCAGE),
    ];
    launch_pty_supervised(prep, runtime, Kind::Shell, cmd)
}

/// Launch `cmd` under the pty supervisor: the cage gets a *private* controlling terminal (so job
/// control and terminal-resize propagation work inside), while the real launching terminal stays
/// unreachable — ops holds the pty master and never execs. Shared by `ops shell`, `ops attach`,
/// and interactive `ops app`.
///
/// The session is registered and its record held by a [`RecordGuard`] that unlinks it when the
/// session ends (ops stays alive as the supervisor, so the record is cleaned promptly rather than
/// left for liveness pruning). The egress guard is held for the whole session too: under a network
/// allowlist the host filtering proxy runs on a thread alongside the supervisor, and the guard
/// unlinks its socket and CA on exit.
fn launch_pty_supervised(
    prep: &Prepared,
    runtime: binds::Runtime,
    kind: Kind,
    cmd: Vec<OsString>,
) -> ExitCode {
    let (spec, guard) = match build(prep, runtime, cmd) {
        Ok((s, g)) => (s.with_private_tty(), g),
        Err(code) => return code,
    };

    let _record = register(prep.layout.data_dir(), &spec, kind, runtime).map(RecordGuard::new);
    // Hold the guard (egress proxy / forward forwarder threads) for the whole pty session.
    let _guard = guard;

    match supervise(&prep.bwrap, &spec, &prep.cfg.limits) {
        Ok(code) => ExitCode::from(code as u8),
        Err(e) => {
            eprintln!("ops: sandbox session failed: {e}");
            ExitCode::FAILURE
        }
    }
}

/// Render the line `ops attach` prints before opening a second terminal in a plain session's
/// project (stderr). Attaching is an announcement, not a completed change, so the verb stays plain;
/// the project path is the identifier (cyan) and the parenthetical is secondary detail (dim).
fn render_attaching_project(project: &Path, pal: &crate::style::Palette) -> String {
    let (n, dim, r) = (pal.name, pal.dim, pal.reset);
    format!(
        "ops: attaching a shell to {n}{}{r} {dim}(a second terminal in the same sandbox){r}",
        project.display()
    )
}

/// Render the line `ops attach` prints before opening a shell in an app's isolated environment
/// (stderr). Same restraint as [`render_attaching_project`]: the app name is the identifier (cyan),
/// the parenthetical secondary (dim), the verb plain.
fn render_attaching_app(name: &str, pal: &crate::style::Palette) -> String {
    let (n, dim, r) = (pal.name, pal.dim, pal.reset);
    format!("ops: attaching a shell to app `{n}{name}{r}` {dim}(its isolated home and posture){r}")
}

/// `ops attach <id>`: open an interactive shell in a running session's environment — a second
/// terminal sharing that session's persistent home and store (the deterministic per-project
/// runtime), **not** a join of the running process (there is no setns). `<id>` is the PID `ops ls`
/// shows. For a plain `ops run`/`ops shell` session that is the project's default home; for an
/// `ops app` agent it is the app's isolated home plus the app's current posture (its egress
/// allowlist, packages, and injected secrets), so attaching to a running agent drops you into the
/// same environment it works in.
pub(crate) fn attach(id: &str) -> ExitCode {
    let Some(layout) = crate::store::Layout::from_env() else {
        eprintln!("ops: cannot resolve the data directory (no $HOME or $XDG_DATA_HOME).");
        return ExitCode::FAILURE;
    };
    let sessions = match session::Registry::at(layout.data_dir()).list() {
        Ok(s) => s,
        Err(e) => {
            eprintln!("ops attach: cannot read the session registry: {e}");
            return ExitCode::FAILURE;
        }
    };
    // A pid is unique among live processes, so this is a 0-or-1 match. Resolve the target before
    // the terminal check, so an unknown id is reported even without a tty.
    let Some(target) = sessions.into_iter().find(|s| s.pid.to_string() == id) else {
        eprintln!("ops attach: no live session '{id}' — run `ops ls` to list them.");
        return ExitCode::from(2);
    };
    // SAFETY: `isatty` only inspects fd 0. The attached shell needs a real terminal, like `shell`.
    if unsafe { libc::isatty(0) } != 1 {
        eprintln!("ops: `ops attach` needs a terminal on stdin.");
        return ExitCode::from(2);
    }
    let project = target.project;
    let runtime = target.runtime;

    // A new cage in the session's project: changing directory makes the launch resolve that
    // project (and its config), exactly as if the user had `cd`'d there.
    if let Err(e) = std::env::set_current_dir(&project) {
        eprintln!(
            "ops attach: the session's project is no longer reachable ({}): {e}",
            project.display()
        );
        return ExitCode::FAILURE;
    }
    let prep = match prepare() {
        Ok(p) => p,
        Err(code) => return code,
    };
    match runtime {
        session::SessionRuntime::Project => {
            let epal = crate::style::Palette::for_stream(io::stderr().is_terminal());
            eprintln!("{}", render_attaching_project(&project, &epal));
            launch_interactive_shell(&prep, binds::Runtime::ProjectDefault)
        }
        session::SessionRuntime::GlobalApp(name) => attach_app_shell(prep, &name, true),
        session::SessionRuntime::ProjectApp(name) => attach_app_shell(prep, &name, false),
    }
}

/// Render the `ops stop --all` line for an empty registry (stdout): nothing to stop is a no-op
/// success, so the message is secondary detail (dim).
fn render_no_active_sessions(pal: &crate::style::Palette) -> String {
    let (dim, r) = (pal.dim, pal.reset);
    format!("ops stop: {dim}no active sessions to stop.{r}")
}

/// `ops stop <id>...` / `ops stop --all`: stop running sessions. With ids, stop the named ones (the
/// pids `ops ls` shows); with `all`, stop every live session. Each session is sent SIGTERM, then
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
/// - stopping an `ops shell` session signals its pty supervisor, whose terminal-state restore is
///   also a RAII guard, so the owner's terminal (where that `ops shell` runs) is left in raw mode
///   and needs a `reset`. Stopping a backgrounded agent — the verb's purpose — is unaffected; this
///   only bites the unusual case of stopping an interactive shell from another terminal. `--all`
///   targets *every* session, interactive shells included (a deliberate choice — "all" means all,
///   matching how `ops stop <id>` already treats a shell), so it can trip this residual on a shell
///   open elsewhere; stop a single agent by pid to avoid it.
pub(crate) fn stop(ids: &[&str], grace: Duration, all: bool) -> ExitCode {
    let Some(layout) = crate::store::Layout::from_env() else {
        eprintln!("ops: cannot resolve the data directory (no $HOME or $XDG_DATA_HOME).");
        return ExitCode::FAILURE;
    };
    let registry = session::Registry::at(layout.data_dir());
    let sessions = match registry.list() {
        Ok(s) => s,
        Err(e) => {
            eprintln!("ops stop: cannot read the session registry: {e}");
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
            eprintln!("ops stop: no live session '{id}' — run `ops ls` to list them.");
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
            format!("ops stop: session {n}{pid}{r} ({n}{label}{r}) {dim}had already exited{r}.")
        }
        session::StopOutcome::Terminated => {
            format!("ops stop: {ok}stopped{r} session {n}{pid}{r} ({n}{label}{r}).")
        }
        session::StopOutcome::Killed => {
            format!(
                "ops stop: session {n}{pid}{r} ({n}{label}{r}) did not exit within {}s — \
                 {warn}sent SIGKILL{r}.",
                grace.as_secs()
            )
        }
    }
}

/// Stop one resolved session and reap its record: SIGTERM, then SIGKILL after `grace`, report the
/// outcome by pid and label, and drop the record so `ops ls` is clean at once rather than waiting
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

/// Open an interactive shell in app `name`'s environment: its isolated home — kept by the
/// session's recorded scope (`global_home`), where the agent's state actually lives — plus the
/// app's current overlay posture (egress, packages, secrets), folded in by re-resolving the app
/// from the project's config. Refuses if the app is no longer configured for this project, since
/// its posture could not then be reproduced.
///
/// Residual: the posture is reproduced from the **current** config and trust, so if the project was
/// untrusted or its config edited since the agent launched, the attach shell can get a different
/// posture than the running agent (e.g. a since-dropped `network` allowlist). That is inherent to
/// reproducing from current config; any security field the trust gate drops on re-resolution is
/// surfaced as a warning by [`build`], so a weaker shell is never silent.
fn attach_app_shell(mut prep: Prepared, name: &str, global_home: bool) -> ExitCode {
    let Some(app) = prep.cfg.apps.remove(name) else {
        eprintln!(
            "ops attach: app `{name}` is no longer configured for this project — cannot reproduce \
             its environment."
        );
        return ExitCode::FAILURE;
    };
    // The home is keyed by the record's scope (where the agent runs); the overlay — network,
    // packages, secrets — comes from the app's current resolution.
    prep.cfg.merge_app(app);
    let runtime = if global_home {
        binds::Runtime::GlobalApp(name)
    } else {
        binds::Runtime::ProjectApp(name)
    };
    let epal = crate::style::Palette::for_stream(io::stderr().is_terminal());
    eprintln!("{}", render_attaching_app(name, &epal));
    launch_interactive_shell(&prep, runtime)
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
/// launch resolves against), so a `-o nixpkgs=…` / `OPS_CONFIG` channel takes effect. The rest of
/// the override (env, binds, network, gui, limits, secret) is applied by the caller with
/// [`crate::config::Resolved::apply_override`] — after any app overlay merges, so it beats that too.
fn prepare_with(ov: &crate::config::Override) -> Result<Prepared, ExitCode> {
    // The data directory is resolved first: it is where ops looks for (and, under the
    // bundled features, materializes) the engines it owns, so `resolve_bwrap` below needs it.
    let Some(layout) = Layout::from_env() else {
        eprintln!("ops: cannot resolve the data directory (no $HOME or $XDG_DATA_HOME).");
        return Err(ExitCode::FAILURE);
    };
    let Some(bwrap) = crate::store::resolve_bwrap(Some(&layout)).map(|c| c.path) else {
        return Err(missing("bubblewrap (the sandbox engine)"));
    };
    if !matches!(crate::probe_userns(), crate::Userns::Ok) {
        eprintln!(
            "ops: no capability-bearing user namespace — the sandbox cannot run. See `ops doctor`."
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
            eprintln!("ops: cannot read the current directory: {e}");
            return Err(ExitCode::FAILURE);
        }
    };
    let mut cfg = crate::config::load(&cwd);
    // The override's nixpkgs channel must land before the lock target is chosen below. A set-but-
    // invalid channel is a hard error (no safe baseline fallback for a supply-chain field).
    if let Err(e) = cfg.apply_override_channel(ov) {
        eprintln!("ops: {e}");
        return Err(ExitCode::from(2));
    }
    // Reject a mistyped scalar security value (network/gui/limits) now — before the expensive
    // channel/userland resolution below — so a typo aborts fast rather than after a provision. The
    // full override (this plus the additive fields) is applied at the launch's final point.
    if let Err(errs) = cfg.validate_override(ov) {
        for e in errs {
            eprintln!("ops: {e}");
        }
        return Err(ExitCode::from(2));
    }

    let nixpkgs =
        match effective_lock_target(&cwd, &layout, &cfg).and_then(|t| t.resolve(&nix, &layout)) {
            Ok(r) => r,
            Err(e) => {
                eprintln!("ops: cannot resolve the nixpkgs channel: {e}");
                return Err(ExitCode::FAILURE);
            }
        };
    // The mise engine resolves against its own dedicated lock (the global channel source,
    // rolled independently by `ops upgrade mise`), never this launch's possibly-pinned
    // base reference. Resolved *after* the base so its lock can be seeded from the base's
    // on first use (no network, and a binary update never bumps the engine — see
    // `resolve_engine_ref`). Threaded to both mise consumers: the in-cage engine (the base
    // userland) and the host-side `[env]` driver.
    let engine_ref =
        match crate::store::resolve_engine_ref(&nix, &layout, cfg.nixpkgs_global.as_deref()) {
            Ok(r) => r,
            Err(e) => {
                eprintln!("ops: cannot resolve the mise engine channel: {e}");
                return Err(ExitCode::FAILURE);
            }
        };
    let userland = match super::fhs::resolve_userland(&nix, &layout, &nixpkgs, &engine_ref) {
        Ok(u) => u,
        Err(e) => {
            eprintln!("ops: cannot resolve the sandbox userland: {e}");
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
/// "which source, which lock", so the launch (resolve), `ops upgrade` (refresh), and
/// `ops config` (display) all act on the same lock and can never drift.
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
/// configuration resolved in [`prepare`] drives this: a trust-gated `.ops.toml` adds
/// environment and host binds — read-only, or read-write with `mode = "rw"` (its security
/// fields honored only once trusted)
/// and provisions its declared tools onto `PATH`. Whatever the gate dropped or
/// withheld is surfaced as a warning; a declared tool that fails to realise is fatal,
/// since it is a stated requirement.
/// Establish the mountpoint-chain pins that protect ops's control plane: create each pin's host
/// path (they are ops's own directories — creating a not-yet-existent root here is what stops the
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
/// exit status becomes ops's). Dropping the guard drops both, unlinking the on-disk artifacts and
/// closing the listeners; the threads are detached and exit when their listener closes.
pub(crate) struct LaunchGuard {
    pub(crate) egress: Option<egress::Egress>,
    pub(crate) forward: Option<forward::Forwarder>,
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

    // Provision the project's declared tools into ops's store, against the project's
    // effective nixpkgs reference; their bin dirs are prepended to PATH below. A
    // withheld (untrusted) tool only warns; an admitted tool that fails to realise is
    // fatal.
    let packages = match super::packages::provision(
        &prep.nix,
        &prep.layout,
        &prep.cwd,
        &prep.nixpkgs,
        &prep.cfg.packages,
    ) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("ops: {e}");
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

    // `flake:` packages are built in-cage at launch (below), not host-provisioned, but their
    // out-link `bin` directories join PATH now — ahead of the base, like every other declared
    // tool. The out-link need not exist yet: the in-cage `nix build` creates it before the
    // command runs, exactly as the mise shims dir is on PATH before mise populates it. Each
    // out-link is keyed by the (validated) package name under the persistent home.
    let flake_pkgs = super::packages::flake_packages(&prep.cfg.packages);
    // Consult the per-project flake lock: a pinned package builds its locked (immutable) ref into
    // an out-link keyed by that revision, so an `ops upgrade flake` that moved the pin rebuilds at
    // this launch (the rev-keyed path does not yet exist). An unpinned package floats — it builds
    // the declared ref into a name-keyed out-link, the v1 behaviour kept for a project that never
    // ran `ops upgrade flake`.
    let flake_lock = read_flake_lock(prep, &flake_pkgs);
    // Each triple carries the build ref, the out-link, and the package name — the name keys the
    // host-resolvable gc root the build registers, so a roll re-points one root and a host-side
    // `ops gc` keeps the current build while collecting the rolled-away one.
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

    // Seed the project's own writable store with the closure of everything the cage
    // resolves through `/nix` — the base userland, every provisioned tool, and (under the
    // GUI hole) the fonts — then back `/nix` with it read-write. The cage reads and writes
    // only its own store, so an agent that installs a toolchain writes into the project's
    // copy and the shared store is never in the cage. Which store backs `/nix` is ops's
    // decision, not a configurable field, so an untrusted project cannot keep the shared
    // store mounted or widen its access.
    let project_store = match seed_project_store(prep, &packages.roots, &tools.roots, font_roots) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("ops: cannot prepare the project's store: {e}");
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
                    "ops: equipping non-nix tools in-cage via mise: {} (each backend's host must \
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
                // resolve. This applies for the whole launch, so an agent's own `ops mise` in a
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
                    "ops: equipping app packages in-cage via mise use -g: {}",
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
                "ops: building flake packages in-cage via nix build: {} (each flake's fetch \
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
                    eprintln!("ops: {e}");
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
        // An `ops app <name>` launch tags its egress stats with the app, so `ops net stats --app`
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
        )
        .map_err(|e| {
            eprintln!("ops: cannot start the egress filtering proxy: {e}");
            ExitCode::FAILURE
        })?;
        cmd = egress::wrap_command(&prep.userland.socat_bin, &prep.userland.shell_bin, cmd);
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
    // The cage env (`WAYLAND_DISPLAY`/`XDG_RUNTIME_DIR`) is fixed here by ops; an untrusted
    // `[env]` could only mispoint a client at a nonexistent socket (self-DoS), never redirect the
    // bind, whose source path is set by ops — so these keys need no denylist entry.
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
        // is fixed by ops; a project `[env]` could override it (highest precedence), but that
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
    }

    // The launcher's extra binds, emitted after the structural mounts: the egress machinery
    // (socket + CA) and the GUI socket. Their destinations are ops's or the host's, never a
    // project path, so they neither shadow nor are shadowed by a structural mount.
    let mut extra_binds = egress_binds;
    extra_binds.extend(forward_binds);
    extra_binds.extend(gui_binds);

    // Pin ops's own control plane in place whenever a read-write bind contains it: each root's host
    // path is frozen as a mountpoint chain (read-write intermediates, a read-only leaf), so in-cage
    // code cannot rename a writable parent to move a control-plane root aside and recreate a forged
    // one at the same path — which ops would otherwise read or `execve` on its next run. The bind
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
            // mkdir failing in ops's own data/config tree.
            eprintln!(
                "ops: cannot protect ops's control plane ({e}) — a read-write bind contains it"
            );
            return Err(ExitCode::FAILURE);
        }
    }

    // Environment, lowest precedence first: host passthrough, then ops's hermetic CA bundle, then
    // the Wayland GUI keys, then the non-nix auto-equip variable, then a trusted project's mise
    // `[env]`, then the egress machinery (proxy + CA), then the `.ops.toml` `[env]` (the ops-native
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
        // `[seccomp] allow` union is in effect for `ops app`, exactly like its limits.
        prep.cfg.seccomp.clone(),
        cmd,
    )
    .map_err(|e| {
        eprintln!("ops: cannot prepare the sandbox: {e}");
        ExitCode::FAILURE
    })?;
    let guard = if egress_guard.is_some() || forward_guard.is_some() {
        Some(LaunchGuard {
            egress: egress_guard,
            forward: forward_guard,
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
    // Record the project's canonical path so a later `ops gc` can recognise this tree and reclaim
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
/// choice is made, so the launch (which builds the out-link) and `ops gc` (which decides
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
/// mise is provisioned via nix and driven from ops's store against the **engine**
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
            eprintln!("ops: cannot provision the mise engine: {e}");
            ExitCode::FAILURE
        })?;
    let mise_bin = super::mise::bin(&mise_root);
    // Stage the authorized files in a per-project directory that sits outside every
    // writable mount (a sibling of the writable home, like the synthetic identity).
    let id = binds::project_runtime_id(&prep.cwd).map_err(|e| {
        eprintln!("ops: cannot identify the project: {e}");
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
        eprintln!("ops: mise [env] resolution failed: {e}");
        ExitCode::FAILURE
    })
}

/// Provision a trusted project's declared `nix:` mise tools into ops's store and report
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
        eprintln!("ops: {e}");
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
/// leaving `ops shell`'s pty job control unchanged. The `verb` is an ops-chosen literal
/// (`install` for the project's local `.mise.toml` tools, `use -g` for the app's `[packages]
/// mise:` ones); the tokens and the command ride `"$@"` positionally, so only the absolute mise
/// path, the ops-chosen verb, and the integer token count are interpolated into the script — a
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
        OsString::from("ops-mise-equip"),
    ];
    out.extend(tokens.iter().map(OsString::from));
    out.extend(cmd);
    out
}

/// Wrap `cmd` so the cage builds a set of `flake:` packages before running it: a static bash
/// that, for each `(ref, out-link, key)` triple, runs `nix build <ref> --out-link <out-link>`
/// unless the out-link is already realised, registers a host-resolvable gc root for the build,
/// then `exec`s the real command (which stays the cage's main process, leaving `ops shell`'s pty
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
/// new build, dropping the old store path, so a host-side `ops gc` keeps the current build and
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
         [ -e \"$out/bin\" ] || '{nix}' build \"$1\" --out-link \"$out\" 1>&2\n\
         sp=$(readlink -f \"$out\" 2>/dev/null)\n\
         [ -n \"$sp\" ] && mkdir -p /nix/var/nix/gcroots \
         && ln -sfn \"$sp\" \"/nix/var/nix/gcroots/ops-flake-$3\"\n\
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
        OsString::from("ops-flake-equip"),
    ];
    for (reference, out_link, key) in triples {
        out.push(OsString::from(reference));
        out.push(out_link.as_os_str().to_os_string());
        out.push(OsString::from(key));
    }
    out.extend(cmd);
    out
}

/// Record this sandbox in the on-disk registry so `ops ls` can list it. Best
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
/// record can outlive the launch and let `ops attach` reproduce the same home.
fn session_runtime(runtime: binds::Runtime) -> session::SessionRuntime {
    match runtime {
        binds::Runtime::ProjectDefault => session::SessionRuntime::Project,
        binds::Runtime::GlobalApp(name) => session::SessionRuntime::GlobalApp(name.to_string()),
        binds::Runtime::ProjectApp(name) => session::SessionRuntime::ProjectApp(name.to_string()),
    }
}

/// Run the cage as a child and propagate its exit status, keeping ops alive for the
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
            eprintln!("ops: failed to prepare the seccomp filter: {e}");
            return 1;
        }
    };
    let (prog, args) = super::cgroup::wrap(bwrap, argv, limits, &spec.cage_slug);
    match Command::new(prog).args(args).status() {
        Ok(status) => status_code(status),
        Err(e) => {
            eprintln!("ops: failed to launch the sandbox: {e}");
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

/// Run `spec` under a pty supervisor and return its exit status code. ops opens
/// a pty, launches bwrap with the *slave* as its controlling terminal (via
/// `login_tty`), keeps the *master* itself, puts the real terminal in raw mode,
/// and relays bytes both ways until the session ends.
fn supervise(bwrap: &Path, spec: &SandboxSpec, limits: &super::cgroup::Limits) -> io::Result<i32> {
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
    // Install the resize relay *after* the fork so the child never inherits the handler. ops keeps
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
    let status = pump(master, child, winch_fd);
    drop(winch);
    unsafe { libc::close(master) };
    status
}

/// Relay bytes between the real terminal and the pty master until the session
/// ends, then reap the child and return its exit status code. `winch_fd` is the read
/// end of the resize relay's self-pipe (or `-1` when it could not be installed — `poll`
/// ignores a negative fd), readable when a `SIGWINCH` has arrived.
fn pump(master: libc::c_int, child: libc::pid_t, winch_fd: libc::c_int) -> io::Result<i32> {
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
                // best-effort: if the child is gone, the master read above ends us
                let _ = write_all(master, &buf[..n as usize]);
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
    let code = if libc::WIFEXITED(status) {
        libc::WEXITSTATUS(status)
    } else if libc::WIFSIGNALED(status) {
        128 + libc::WTERMSIG(status)
    } else {
        1
    };
    Ok(code)
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

/// Layer the cage's extra environment, lowest precedence first: host passthrough, then ops's
/// hermetic CA bundle, then the Wayland GUI hole, then the non-`nix:` auto-equip variable, then a
/// trusted project's mise `[env]`, then the egress machinery, then the `.ops.toml` `[env]`. The
/// assembler upserts these over the structural defaults and takes the last occurrence of a key,
/// so a later layer wins: the egress proxy's per-session CA overrides the structural cacert under
/// an allowlist, and a trusted config has the final say (self-harm only). The CA bundle sits
/// above passthrough on purpose — passthrough is a separate channel, not filtered by the
/// untrusted-config denylist, so a host CA variable could otherwise clobber ops's hermetic
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
    eprintln!("ops: {what} not found — the sandbox cannot run. See `ops doctor`.");
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
        // The owned record runtime `ops attach` reads back must mirror the launch-side runtime, so
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
        // (and the existing `ops stop --all` substring assertion) stays unchanged.
        let p = crate::style::Palette::plain();
        let grace = Duration::from_secs(10);
        assert_eq!(
            render_attaching_project(Path::new("/home/me/proj"), &p),
            "ops: attaching a shell to /home/me/proj (a second terminal in the same sandbox)"
        );
        assert_eq!(
            render_attaching_app("demo-app", &p),
            "ops: attaching a shell to app `demo-app` (its isolated home and posture)"
        );
        assert_eq!(
            render_no_active_sessions(&p),
            "ops stop: no active sessions to stop."
        );
        assert_eq!(
            render_stop_outcome(4242, "run", &session::StopOutcome::Terminated, grace, &p),
            "ops stop: stopped session 4242 (run)."
        );
        assert_eq!(
            render_stop_outcome(
                7,
                "app:agent",
                &session::StopOutcome::AlreadyGone,
                grace,
                &p
            ),
            "ops stop: session 7 (app:agent) had already exited."
        );
        assert_eq!(
            render_stop_outcome(9, "shell", &session::StopOutcome::Killed, grace, &p),
            "ops stop: session 9 (shell) did not exit within 10s — sent SIGKILL."
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

        let attach = render_attaching_app("demo-app", &p);
        assert!(attach.contains(&format!("{}demo-app{}", p.name, p.reset)));
        // The announcement verb is not green — only a completed change earns that.
        assert!(!attach.contains(&format!("{}attaching", p.ok)));

        assert!(render_no_active_sessions(&p).contains(p.dim));
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
            forward: vec![],
            forward_origin: Default::default(),
            limits: Default::default(),
            limits_origin: Default::default(),
            secrets: vec![],
            seccomp: Default::default(),
            seccomp_origin: Default::default(),
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
            limits: Default::default(),
            forward: vec![],
            secrets: vec![],
            default_methods: crate::allowlist::Methods::Unspecified,
            cmd_origin: Default::default(),
            network_origin: Default::default(),
            gui_origin: Default::default(),
            forward_origin: Default::default(),
            limits_origin: Default::default(),
            seccomp: Default::default(),
            seccomp_origin: Default::default(),
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
        // egress proxy's per-session CA, not ops's root bundle: egress is layered after cacert,
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
        let egress = vec![("SSL_CERT_FILE".into(), "/opt/ops/egress-ca.pem".into())];
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
            Some("/opt/ops/egress-ca.pem"),
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
        assert_eq!(argv[3], OsString::from("ops-mise-equip"));
        assert_eq!(argv[4], OsString::from("aqua:BurntSushi/ripgrep@latest"));
        assert_eq!(argv[5], OsString::from("node@20; rm -rf /"));
        assert_eq!(argv[6], OsString::from("demo-app"));
        assert_eq!(argv[7], OsString::from("--print"));
    }

    #[test]
    fn wrap_mise_equip_uses_the_global_verb_for_app_packages() {
        // The app's `[packages] mise:` tools are equipped globally (`mise use -g`), so the verb
        // is interpolated literally (an ops-chosen constant, never config) while the token stays
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
        let dir = PathBuf::from("/home/sandbox/.local/state/ops/flake");
        let triples = vec![
            (
                "github:example/flake-tool#tui".to_string(),
                PathBuf::from("/home/sandbox/.local/state/ops/flake/flake-tool"),
                "flake-tool".to_string(),
            ),
            // a hostile ref must stay a single positional arg, never reach the script
            (
                "github:evil/x#bin; rm -rf /".to_string(),
                PathBuf::from("/home/sandbox/.local/state/ops/flake/evil"),
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
            "[ -e \"$out/bin\" ] || '/nix/store/nix/bin/nix' build \"$1\" --out-link \"$out\""
        ));
        assert!(script.contains("mkdir -p '/home/sandbox/.local/state/ops/flake'"));
        // the gc root is keyed by the `$3` positional (the package name), targeting the build's
        // store path resolved by `readlink -f` — host-resolvable, overwritten each launch
        assert!(script.contains("ln -sfn \"$sp\" \"/nix/var/nix/gcroots/ops-flake-$3\""));
        assert!(script.contains("shift 3"));
        assert!(script.trim_end().ends_with("exec \"$@\""));
        assert!(
            !script.contains("rm -rf"),
            "a hostile ref must never be interpolated into the script: {script}"
        );
        // label, then interleaved (ref, out-link, key) triples, then the command — all positional
        assert_eq!(argv[3], OsString::from("ops-flake-equip"));
        assert_eq!(argv[4], OsString::from("github:example/flake-tool#tui"));
        assert_eq!(
            argv[5],
            OsString::from("/home/sandbox/.local/state/ops/flake/flake-tool")
        );
        assert_eq!(argv[6], OsString::from("flake-tool"));
        assert_eq!(argv[7], OsString::from("github:evil/x#bin; rm -rf /"));
        assert_eq!(
            argv[8],
            OsString::from("/home/sandbox/.local/state/ops/flake/evil")
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
        let path = detach_log_path(Path::new("/var/lib/ops"), 4242);
        assert_eq!(path, PathBuf::from("/var/lib/ops/logs/4242.log"));
    }
}
