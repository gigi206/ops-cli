//! Turning a finished [`SandboxSpec`] into a running process, and recording that it ran.
//!
//! One command is assembled here and four things are done with it: replace this process with it,
//! fork and wait for its status, fork and capture what it printed, or supervise it through a
//! private terminal. The assembly is stated once — the argument list with its seccomp filters, the
//! netns holder and the cgroup wrap, in that order — because a path that composed them differently
//! would be a launch that ran under weaker confinement than the others, and nothing would say so.
//! The filters are not a step here: they belong to [`crate::sandbox::argv::compose`], so a path
//! that never reaches this module still cannot produce an unfiltered cage.
//!
//! The memfds backing the seccomp filters and the cage's environment travel inside the command
//! ([`crate::sandbox::argv::CageCommand`]), which keeps them open until its exec and hands them to
//! that exec alone: closing one early would close the descriptor bubblewrap was told to read.
//!
//! This is the part of a launch that the rest of the sandbox reaches into — the task engine, the
//! task pool and the resolver each build a spec of their own and run it through the same argv.

#![allow(
    clippy::expect_used,
    reason = "`stdout`/`stderr` are taken from a child this function spawned with `Stdio::piped()` for both, and nothing takes them first -- the handle is `None` only if the pipe was never requested"
)]

use super::*;

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
/// the `--detach` child in [`mod@super::detach`] passes `true`.
///
/// `store_lock` is the project's store lock [`super::build()`] took: let go once the record is
/// written, and not before, so an `sbx gc` of the project that waited on it finds this session and
/// refuses rather than collecting a store this cage is about to use. A record that could not be
/// written lets it go all the same.
pub(super) fn register(
    data_dir: &Path,
    spec: &SandboxSpec,
    kind: Kind,
    runtime: binds::Runtime,
    detached: bool,
    store_lock: Option<crate::sandbox::projectstore::ProjectStoreLock>,
) -> Option<PathBuf> {
    let recorded = Session::current(spec.workdir.clone(), kind, session_runtime(runtime))
        .ok()
        .and_then(|session| {
            let session = if detached {
                session.detached()
            } else {
                session
            };
            crate::session::Registry::at(data_dir)
                .register(&session)
                .ok()
        });
    // Let go only now: an `sbx gc` of the project waiting on it finds this session and refuses.
    drop(store_lock);
    recorded
}

/// The owned [`crate::session::SessionRuntime`] for a launch's borrowing [`binds::Runtime`], so the
/// record can outlive the launch and let `sbx session attach` reproduce the same home.
fn session_runtime(runtime: binds::Runtime) -> crate::session::SessionRuntime {
    match runtime {
        binds::Runtime::ProjectDefault => crate::session::SessionRuntime::Project,
        binds::Runtime::GlobalApp(name) => {
            crate::session::SessionRuntime::GlobalApp(name.to_string())
        }
        binds::Runtime::ProjectApp(name) => {
            crate::session::SessionRuntime::ProjectApp(name.to_string())
        }
    }
}

/// Run the cage as a child and propagate its exit status, keeping sbx alive for the
/// whole session. Required by the network-allowlist posture, whose host filtering proxy
/// runs on a thread that an exec-replace would discard; `run` uses this exactly when an
/// egress guard is present. `Command::status` forks, waits, and yields the child's code;
/// the proxy thread was already spawned (by `egress::start`) before the launch.
pub(super) fn run_supervised(
    bwrap: &Path,
    spec: &SandboxSpec,
    limits: &crate::sandbox::cgroup::Limits,
) -> ExitCode {
    ExitCode::from(run_status(bwrap, spec, limits) as u8)
}

/// Fork the cage, wait, and return its exit status code (shell convention). The fork-and-wait
/// core of [`run_supervised`], shared with the detached session's daemon: both keep sbx alive
/// beside the cage rather than exec-replacing the launcher. A failure to prepare or spawn
/// surfaces a pointed error and yields `1`, matching the supervised path.
pub(super) fn run_status(
    bwrap: &Path,
    spec: &SandboxSpec,
    limits: &crate::sandbox::cgroup::Limits,
) -> i32 {
    try_run_status(bwrap, spec, limits, None).unwrap_or(1)
}

/// A cage the launcher could not start: nothing ran in it, and the cause is already on stderr.
#[derive(Debug, PartialEq, Eq)]
pub(super) struct NotStarted;

/// What bubblewrap says, on `--json-status-fd`, about whether it set a cage up: the pipe a runner
/// hands it ([`try_run_status`], [`supervise`]) and reads once the cage has been reaped.
///
/// bubblewrap writes `exit-code` only when its setup reached the `execvp` of the cage's argv and
/// that call succeeded; a setup it refused, and a program it could not run, end in its own `die`
/// with no such line ([`crate::sandbox::argv::compose_with`]). That is the one signal on the host
/// side that tells a cage bubblewrap never finished from a command that ran and failed: both end in
/// a code the command could have chosen.
pub(super) struct SetupReport {
    read: std::fs::File,
    write: std::fs::File,
}

impl SetupReport {
    /// A fresh pipe, both ends close-on-exec. The read end is non-blocking: it is read once the
    /// cage is reaped, and never to its end, since this process keeps a copy of the write end, and
    /// so does any process that forked while it was open.
    pub(super) fn new() -> io::Result<SetupReport> {
        use std::os::fd::FromRawFd;
        let mut ends = [0 as libc::c_int; 2];
        // SAFETY: `pipe2` fills the two-element array it is handed.
        if unsafe { libc::pipe2(ends.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: both ends were just opened here, and each `File` takes over one of them.
        let (read, write) = unsafe {
            (
                std::fs::File::from_raw_fd(ends[0]),
                std::fs::File::from_raw_fd(ends[1]),
            )
        };
        // SAFETY: `fcntl` on the read end this value owns, with integer arguments only.
        let flags = unsafe { libc::fcntl(ends[0], libc::F_GETFL) };
        // SAFETY: as above.
        if flags < 0 || unsafe { libc::fcntl(ends[0], libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok(SetupReport { read, write })
    }

    /// The end bubblewrap is handed.
    pub(super) fn write_end(&self) -> &std::fs::File {
        &self.write
    }

    /// Whether bubblewrap set the cage up, read after the cage was reaped: `Some(true)` when it
    /// reported an `exit-code`, `Some(false)` when it reported none, `None` when the pipe could not
    /// be read and so says nothing either way.
    pub(super) fn finished_setup(&self) -> Option<bool> {
        use std::io::Read as _;
        // Far above the two short lines bubblewrap writes, and a bound on a pipe anything could fill.
        const MAX: u64 = 64 * 1024;
        let mut text = Vec::new();
        match (&self.read).take(MAX).read_to_end(&mut text) {
            Ok(_) => {}
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
            Err(_) => return None,
        }
        Some(reports_exit_code(&String::from_utf8_lossy(&text)))
    }
}

/// Whether bubblewrap's `--json-status-fd` output holds the `exit-code` it writes only for a cage it
/// set up. Its other line (`child-pid`, written as soon as the child is cloned) says nothing about
/// the setup.
fn reports_exit_code(status: &str) -> bool {
    status.lines().any(|line| line.contains("\"exit-code\""))
}

/// [`run_status`], telling a cage that never started from one that ran: [`NotStarted`] when the
/// sandbox could not be prepared or spawned, the cage's own code otherwise.
///
/// A learning run needs the difference, which `1` erases: only a cage that ran has anything to
/// learn from, and one that never started must not be reported as having been refused nothing.
///
/// `status` asks bubblewrap to say whether it set the cage up ([`SetupReport`]).
pub(super) fn try_run_status(
    bwrap: &Path,
    spec: &SandboxSpec,
    limits: &crate::sandbox::cgroup::Limits,
    status: Option<&std::fs::File>,
) -> Result<i32, NotStarted> {
    let mut command = match cage_command_with(bwrap, spec, limits, status) {
        Ok(cage) => cage.into_command(),
        Err(e) => {
            // Not only the filter: this step also builds the descriptor carrying the cage's
            // environment, and naming the wrong one would send a reader looking at `[seccomp]`.
            crate::diag::error(&format!("sbx: cannot prepare the sandbox: {e}"));
            return Err(NotStarted);
        }
    };
    match command.status() {
        Ok(status) => Ok(status_code(status)),
        Err(e) => {
            crate::diag::error(&format!("sbx: failed to launch the sandbox: {e}"));
            Err(NotStarted)
        }
    }
}

/// How much of one captured stream is kept. The report parses a handful of summary lines out of
/// it and shows the rest only when the run failed, so a quarter of a megabyte per stream is far
/// past anything useful — but it is a ceiling, and the reason there has to be one is that the bytes
/// are the cage's: `Command::output()` grows a host-side buffer to whatever the cage decides to
/// print, and neither the cgroup limits (which govern the cage, not this supervisor) nor anything
/// else on this path bounds it.
const CAPTURED_CAP: usize = 256 * 1024;

/// The wall-clock ceiling on one captured cage run. Deliberately generous — a group's cold
/// re-install of a whole toolchain legitimately takes many minutes — but present, so a wedged
/// registry connection or a command that never exits ends the run with a diagnostic instead of
/// hanging `sbx upgrade` with nothing to break it. Fixed, not a configurable knob: it bounds sbx's
/// own supervisor, so a project must not be able to widen it.
const CAPTURED_TIMEOUT: Duration = Duration::from_secs(1800);

/// How often the captured run checks for exit while enforcing [`CAPTURED_TIMEOUT`]. Coarse: an
/// upgrade is a minutes-long operation, so quarter-second granularity costs nothing and spins far
/// less.
const CAPTURED_POLL: Duration = Duration::from_millis(250);

/// Fork-and-wait like [`run_status`], but **capture** the cage's stdout and stderr instead of
/// inheriting the terminal, returning `(exit code, combined output)`. Reserved for `sbx upgrade`,
/// where a clean per-app summary is shown on success and the captured output is surfaced only on
/// failure — never on the interactive/detached launch paths, which need live inherited stdio. The
/// two streams are concatenated (stdout then stderr) because mise splits its output across both: a
/// roll's `X → Y` summary goes to stdout, its `up to date` line to stderr.
///
/// Both bounds the run holds — [`CAPTURED_CAP`] per stream and [`CAPTURED_TIMEOUT`] on the wall
/// clock — are here because the process being read is the cage. `Command::output()` reads both
/// pipes to EOF with no ceiling and no deadline, which hands a hostile or merely broken cage the
/// supervisor's memory and its liveness; the runners that already face the same output — the task
/// engine and the pool install — cap and time-bound it for exactly this reason. Each stream is
/// still drained past the cap on its own thread, so the cage is never blocked on a full pipe and
/// neither stream can starve the other; only the kept bytes are bounded, and the caller is told in
/// the output itself when something was cut or killed.
pub(super) fn run_captured(
    bwrap: &Path,
    spec: &SandboxSpec,
    limits: &crate::sandbox::cgroup::Limits,
) -> (i32, String) {
    let mut command = match cage_command(bwrap, spec, limits) {
        Ok(cage) => cage.into_command(),
        Err(e) => return (1, format!("cannot prepare the sandbox: {e}")),
    };
    command
        // No stdin, as `output()` gave it: this path is non-interactive, and the terminal it
        // reports to is the operator's.
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    let mut child = match command.spawn() {
        Ok(child) => child,
        Err(e) => return (1, format!("failed to launch the sandbox: {e}")),
    };
    let mut out_pipe = child.stdout.take().expect("stdout piped");
    let mut err_pipe = child.stderr.take().expect("stderr piped");
    let out_reader = std::thread::spawn(move || drain_capped(&mut out_pipe, CAPTURED_CAP));
    let err_reader = std::thread::spawn(move || drain_capped(&mut err_pipe, CAPTURED_CAP));

    let deadline = std::time::Instant::now() + CAPTURED_TIMEOUT;
    let (status, timed_out) =
        match crate::sandbox::cagewait::wait_capped(&mut child, deadline, CAPTURED_POLL) {
            Ok(waited) => waited,
            Err(e) => return (1, format!("cannot wait for the sandbox: {e}")),
        };
    // A reader thread that panicked leaves no bytes rather than taking the upgrade down: the exit
    // status is the part the report most needs, and losing a stream is the safe direction.
    let (stdout, out_cut) = out_reader.join().unwrap_or_default();
    let (stderr, err_cut) = err_reader.join().unwrap_or_default();
    let mut combined = String::from_utf8_lossy(&stdout).into_owned();
    combined.push_str(&String::from_utf8_lossy(&stderr));
    // Said in the output rather than only in the exit code, because the output is what the report
    // shows a reader when the run failed — and a truncated tail otherwise reads as a command that
    // simply stopped talking. Neither note carries the ` → ` marker [`mise_transitions`] keys on,
    // so neither can be mistaken for a version roll.
    if out_cut || err_cut {
        combined.push_str(&format!(
            "\n(sbx: the cage's output passed its {CAPTURED_CAP}-byte ceiling and was truncated)\n"
        ));
    }
    if timed_out {
        combined.push_str(&format!(
            "\n(sbx: the run passed its {}s ceiling and was killed)\n",
            CAPTURED_TIMEOUT.as_secs()
        ));
    }
    (status_code(status), combined)
}

/// Read `pipe` to EOF keeping at most `cap` bytes, reporting whether anything was dropped.
///
/// Reading continues past the cap so the writer is never blocked on a full pipe — a cage held there
/// would never exit, which is the hang the cap exists to prevent. Only the kept bytes are bounded.
/// The task engine's own reader has the same shape plus a margin for its redaction scanner, which
/// this path has no use for: nothing here is scanned for credentials.
fn drain_capped(pipe: &mut impl io::Read, cap: usize) -> (Vec<u8>, bool) {
    let mut kept = Vec::new();
    let mut cut = false;
    let mut buf = [0u8; 8192];
    loop {
        match pipe.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                if kept.len() < cap {
                    let take = (cap - kept.len()).min(n);
                    kept.extend_from_slice(&buf[..take]);
                    cut |= take < n;
                } else {
                    cut = true;
                }
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            // A read error leaves what was already kept: the caller's report is better off with a
            // partial capture than with none.
            Err(_) => break,
        }
    }
    (kept, cut)
}

/// Echo a cage's captured output to the launching terminal, one indented line at a time.
///
/// Reserved for the `sbx upgrade` report — the one path that interleaves sbx's own lines (a trust
/// warning, a failure verdict) with bytes the cage produced. Those bytes are chosen inside the
/// cage: mise's own diagnostics, but also the output of whatever third-party installer its
/// registry, `aqua:` and `npm:` backends fetched and ran. Each line goes through
/// [`crate::sandbox::sanitize`], so an escape sequence among them cannot erase the lines sbx
/// printed above it or drive the operator's terminal. Line-wise rather than over the whole buffer,
/// because `sanitize` replaces every control character — the newlines included — with a space.
pub(super) fn echo_cage_output(out: &str) {
    for line in out.lines().map(cage_output_line) {
        errln!("{line}");
    }
}

/// One line of [`echo_cage_output`]'s report: the cage's bytes, sanitised, under the report's
/// indent. Pure formatting, so what the filter lets through is unit-tested without a cage.
fn cage_output_line(line: &str) -> String {
    format!("       {}", crate::sandbox::sanitize(line))
}

/// The runnable command for `spec`: the bwrap argv with its seccomp prefix, routed through the netns
/// holder, then wrapped in the resource-limit scope — the three steps every launch path takes
/// between a `SandboxSpec` and a process, in the one order that is correct.
///
/// The first is [`crate::sandbox::argv::compose`]'s own, which is where it belongs: a cage with no
/// filter is not something a caller can produce, whether or not it came through here. What is left
/// for this function is the pair of steps that need what a spec alone does not carry — the host's
/// netns holder and the launch's resource limits.
///
/// The middle step is the one a new launch path would forget it needs: for an isolated cage that
/// renders a GUI or is wired for capture it routes the launch through the netns holder, which
/// configures the namespace bwrap creates — a `dummy0` interface, the capture tap (see
/// [`crate::sandbox::netns`]) — and for every other spec
/// [`crate::sandbox::netns::behind_holder`] leaves the command unchanged.
///
/// The memfds behind the seccomp filters and the cage's environment travel inside the returned
/// command, through both wrappers, so whatever starts it hands them to bwrap
/// ([`crate::sandbox::argv::CageCommand`]). So does the one the holder is handed the report
/// socket's token on, which the holder closes before it becomes bwrap
/// ([`crate::sandbox::netns::behind_holder`]).
pub(in crate::sandbox) fn cage_command(
    bwrap: &Path,
    spec: &SandboxSpec,
    limits: &crate::sandbox::cgroup::Limits,
) -> io::Result<crate::sandbox::argv::CageCommand> {
    cage_command_with(bwrap, spec, limits, None)
}

/// [`cage_command`], with bubblewrap reporting on `status` whether it set the cage up
/// ([`crate::sandbox::argv::compose_with`]). The flag is bubblewrap's own, so it is written before
/// either wrapper, and its descriptor crosses both like the others.
fn cage_command_with(
    bwrap: &Path,
    spec: &SandboxSpec,
    limits: &crate::sandbox::cgroup::Limits,
    status: Option<&std::fs::File>,
) -> io::Result<crate::sandbox::argv::CageCommand> {
    let cage = crate::sandbox::netns::behind_holder(
        crate::sandbox::argv::compose_with(bwrap, spec, status)?,
        spec.netns_dummy.as_ref(),
    )?;
    // The launch's own decision when it took one, so the cage carries the limits its contract
    // names; otherwise the one `wrap` takes here.
    Ok(match &spec.limit_scope {
        Some(scope) => cage.wrapped(|program, args| scope.wrap(program, args, &spec.cage_slug)),
        None => cage.wrapped(|program, args| {
            crate::sandbox::cgroup::wrap(program, args, limits, &spec.cage_slug)
        }),
    })
}

/// Whether `bwrap` mounts a bind from a descriptor (`--bind-fd`, `--ro-bind-fd`), probed once per
/// process.
///
/// Asked of the binary rather than read off a version: the options arrived upstream in 0.10.0, and
/// Ubuntu 24.04 carries them in its 0.9.0 as a backport, so a version number would refuse the host
/// sbx most often runs on. The capability is all this answers. That backport looks up the path of
/// the open source and mounts it without the check bubblewrap makes from 0.10.0, that what it
/// mounted is that object, so on it a swap during bubblewrap's own setup is caught by the cage's
/// own check of its binds instead ([`crate::sandbox::binds::held_source_check`]).
pub(in crate::sandbox) fn bwrap_binds_descriptors(bwrap: &Path) -> bool {
    static PROBED: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *PROBED.get_or_init(|| {
        std::process::Command::new(bwrap)
            .arg("--help")
            .output()
            .is_ok_and(|o| {
                String::from_utf8_lossy(&o.stdout).contains("--ro-bind-fd")
                    || String::from_utf8_lossy(&o.stderr).contains("--ro-bind-fd")
            })
    })
}

/// What the pty child exits with when the cage could not be entered at all — the descriptors could
/// not be made inheritable, the terminal could not be taken, or the `execv` failed.
///
/// Deliberately **not** `126` or `127`. Those two are the shell convention for answers the cage
/// itself gives about the program it was asked to run ("found but not executable", "not found"),
/// and the in-cage shim already uses them that way; a launcher that never reached the cage has to
/// say something the cage cannot. `125` is the spelling the surrounding tooling uses for "the
/// wrapper failed before the command ran", and it leaves both of the cage's own answers intact.
const CAGE_NEVER_STARTED: i32 = 125;

/// A process's exit code in the shell convention: its own code, or 128 + the signal that
/// killed it (matching the pty supervisor's `pump`).
pub(in crate::sandbox) fn status_code(status: std::process::ExitStatus) -> i32 {
    use std::os::unix::process::ExitStatusExt;
    status
        .code()
        .unwrap_or_else(|| status.signal().map(|s| 128 + s).unwrap_or(1))
}

/// Replace the current process with bubblewrap running `spec`. A successful
/// `exec` never returns, so this returns *only* on failure.
pub(super) fn exec(
    bwrap: &Path,
    spec: &SandboxSpec,
    limits: &crate::sandbox::cgroup::Limits,
) -> io::Error {
    // Defense in depth: a private-tty spec relies on a controlling terminal that
    // only the pty supervisor provides. Exec-replace would leave it inheriting
    // the launching terminal, so refuse it here rather than weaken isolation.
    if spec.terminal == TerminalPolicy::PrivateTty {
        return io::Error::other(
            "internal error: a private-tty sandbox must be launched through the pty supervisor",
        );
    }
    // The command owns the descriptors, so they stay open until the exec replaces this process,
    // or on failure until this returns. `exec` runs the registered `pre_exec` closures too, since
    // it reaches the same `do_exec` a spawn does, so they are cleared here exactly as they are on
    // the forking paths.
    let mut command = match cage_command(bwrap, spec, limits) {
        Ok(cage) => cage.into_command(),
        Err(e) => return e,
    };
    command.exec()
}

/// Run `spec` under a pty supervisor and return its exit status code. sbx opens
/// a pty, launches bwrap with the *slave* as its controlling terminal (via
/// `login_tty`), keeps the *master* itself, puts the real terminal in raw mode,
/// and relays bytes both ways until the session ends.
pub(super) fn supervise(
    bwrap: &Path,
    spec: &SandboxSpec,
    limits: &crate::sandbox::cgroup::Limits,
    gui: bool,
    status: Option<&std::fs::File>,
) -> Result<i32, PtyFailure> {
    // The command is built *before* the fork — nothing between fork and exec may allocate, and the
    // anonymous files behind it (the seccomp filters and the cage's environment) must be created
    // here so the child inherits their descriptors. `cage` holds them through `pump`, so bwrap can
    // still read them after the exec.
    let cage = cage_command_with(bwrap, spec, limits, status).map_err(PtyFailure::BeforeFork)?;
    // `inherit` is recorded before the fork, for the child to clear between `fork` and `execv`. The
    // parent keeps its copies close-on-exec, so nothing else this process launches inherits them —
    // see [`crate::sandbox::memfd::write`] for what that window cost.
    let (program, full_argv, inherit) = cage.fork_parts();
    let program_c = cstring(program.as_os_str().as_bytes()).map_err(PtyFailure::BeforeFork)?;
    let mut argv_owned = vec![program_c.clone()];
    for arg in full_argv {
        argv_owned.push(cstring(arg.as_bytes()).map_err(PtyFailure::BeforeFork)?);
    }
    let mut argv: Vec<*const libc::c_char> = argv_owned.iter().map(|c| c.as_ptr()).collect();
    argv.push(std::ptr::null());

    // The child of the fork below: it calls only async-signal-safe functions (`login_tty`, `execv`,
    // `_exit`) on the prebuilt argv, and never returns.
    //
    // What it exits with when it cannot get there is [`CAGE_NEVER_STARTED`] rather than the `127`
    // this used: `supervise` carries the child's status out as the launch's own, so `127` reached
    // the caller indistinguishable from the cage's own "command not found" — the same number for
    // "the cage said your program does not exist" and "the cage was never entered". The two call
    // for opposite next steps, and the second is the one nothing else reports.
    let in_child = move |slave: libc::c_int| -> std::convert::Infallible {
        // First, and through the same helper the `Command` paths use: bwrap reads these descriptors
        // by number off its own argument list, so an exec that dropped them would have it open
        // nothing. `clear_cloexec` calls only `fcntl`, which this child may.
        if !crate::sandbox::memfd::clear_cloexec(&inherit) {
            // SAFETY: `_exit` in a fork child, the only safe way out of here.
            unsafe { libc::_exit(CAGE_NEVER_STARTED) };
        }
        // SAFETY: this runs between `fork` and `exec` in `fork_with_pty`'s child, so it may call
        // only async-signal-safe code: `login_tty`, `execv` and `_exit` are raw syscalls, and
        // `program_c` and `argv` were built before the fork and moved into the closure, so nothing
        // here allocates.
        unsafe {
            // login_tty: setsid + make the slave our controlling terminal + dup it onto
            // stdin/out/err. This is what gives the sandbox a controlling terminal (and thus job
            // control).
            if libc::login_tty(slave) == 0 {
                crate::sandbox::memfd::default_signals_across_exec();
                libc::execv(program_c.as_ptr(), argv.as_ptr());
            }
            // only reached if login_tty or execv failed
            libc::_exit(CAGE_NEVER_STARTED)
        }
    };
    // SAFETY: the closure honours the async-signal-safe contract above, and `cage` holds the
    // filter/environment descriptors open for the whole relay.
    unsafe { fork_with_pty(gui, in_child) }
}

/// `CString` from raw bytes, mapping an interior NUL to an I/O error.
pub(super) fn cstring(bytes: &[u8]) -> io::Result<CString> {
    CString::new(bytes).map_err(|_| io::Error::other("argument contains an interior NUL byte"))
}

#[cfg(test)]
mod tests;
