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
//! The memfds backing the seccomp filters are handed back rather than dropped: they are not
//! close-on-exec, and closing one early would close the descriptor bubblewrap was told to read.
//!
//! This is the part of a launch that the rest of the sandbox reaches into — the task engine, the
//! task pool and the resolver each build a spec of their own and run it through the same argv.

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
pub(super) fn register(
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
    crate::session::Registry::at(data_dir)
        .register(&session)
        .ok()
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
/// core of [`run_supervised`], shared with the multi-cage upgrade roll: both run a series of
/// cages and need the code of each rather than exec-replacing the launcher. A failure to
/// prepare or spawn surfaces a pointed error and yields `1`, matching the supervised path.
pub(super) fn run_status(
    bwrap: &Path,
    spec: &SandboxSpec,
    limits: &crate::sandbox::cgroup::Limits,
) -> i32 {
    let (prog, args, keep_open) = match cage_command(bwrap, spec, limits) {
        Ok(cmd) => cmd,
        Err(e) => {
            // Not only the filter: this step also builds the descriptor carrying the cage's
            // environment, and naming the wrong one would send a reader looking at `[seccomp]`.
            crate::diag::error(&format!("sbx: cannot prepare the sandbox: {e}"));
            return 1;
        }
    };
    let mut command = Command::new(prog);
    command.args(args);
    crate::sandbox::memfd::inherit_across_exec(&mut command, &keep_open);
    match command.status() {
        Ok(status) => status_code(status),
        Err(e) => {
            crate::diag::error(&format!("sbx: failed to launch the sandbox: {e}"));
            1
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
    let (prog, args, keep_open) = match cage_command(bwrap, spec, limits) {
        Ok(cmd) => cmd,
        Err(e) => return (1, format!("cannot prepare the sandbox: {e}")),
    };
    let mut command = Command::new(prog);
    command
        .args(args)
        // No stdin, as `output()` gave it: this path is non-interactive, and the terminal it
        // reports to is the operator's.
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    crate::sandbox::memfd::inherit_across_exec(&mut command, &keep_open);
    let mut child = match command.spawn() {
        Ok(child) => child,
        Err(e) => return (1, format!("failed to launch the sandbox: {e}")),
    };
    let mut out_pipe = child.stdout.take().expect("stdout piped");
    let mut err_pipe = child.stderr.take().expect("stderr piped");
    let out_reader = std::thread::spawn(move || drain_capped(&mut out_pipe, CAPTURED_CAP));
    let err_reader = std::thread::spawn(move || drain_capped(&mut err_pipe, CAPTURED_CAP));

    let deadline = std::time::Instant::now() + CAPTURED_TIMEOUT;
    let mut timed_out = false;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if std::time::Instant::now() >= deadline => {
                // Killing bwrap tears the whole cage down with it: it is the pid-namespace init
                // for everything inside, so nothing outlives the ceiling.
                timed_out = true;
                let _ = child.kill();
                match child.wait() {
                    Ok(status) => break status,
                    Err(e) => return (1, format!("cannot reap the sandbox: {e}")),
                }
            }
            Ok(None) => std::thread::sleep(CAPTURED_POLL),
            Err(e) => return (1, format!("cannot wait for the sandbox: {e}")),
        }
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
        eprintln!("{line}");
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
/// The middle step is the one a new launch path would forget it needs: for a graphical isolated cage
/// it routes the launch through the netns holder so the namespace carries a `dummy0` interface (see
/// [`crate::sandbox::netns`]), and for every other spec `holder_wrap` is a byte-for-byte passthrough.
///
/// The returned files are the memfds behind the seccomp filters and the cage's environment. They are
/// not close-on-exec and bwrap reads them at the exec, so the caller must keep them alive until the
/// process it starts has been replaced — dropping them early closes the descriptors bwrap is told to
/// read.
pub(in crate::sandbox) fn cage_command(
    bwrap: &Path,
    spec: &SandboxSpec,
    limits: &crate::sandbox::cgroup::Limits,
) -> io::Result<(PathBuf, Vec<OsString>, Vec<File>)> {
    let (argv, keep_open) = crate::sandbox::argv::compose(spec)?;
    let (holder_prog, holder_argv) =
        crate::sandbox::netns::holder_wrap(bwrap, argv, spec.netns_dummy.as_ref());
    let (prog, args) =
        crate::sandbox::cgroup::wrap(&holder_prog, holder_argv, limits, &spec.cage_slug);
    Ok((prog, args, keep_open))
}

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
    // `keep_open` stays alive until the exec replaces this process (or, on failure, until this
    // returns), so bwrap can read the inherited filter descriptors.
    let (prog, args, keep_open) = match cage_command(bwrap, spec, limits) {
        Ok(cmd) => cmd,
        Err(e) => return e,
    };
    let mut command = Command::new(prog);
    command.args(args);
    // `exec` runs the registered `pre_exec` closures too — it reaches the same `do_exec` a spawn
    // does — so the descriptors are cleared here exactly as they are on the forking paths.
    crate::sandbox::memfd::inherit_across_exec(&mut command, &keep_open);
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
) -> io::Result<i32> {
    // The command is built *before* the fork — nothing between fork and exec may allocate, and the
    // anonymous files behind it (the seccomp filters and the cage's environment) must be created
    // here so the child inherits their descriptors. `_keep_open` holds them through `pump`, so bwrap
    // can still read them after the exec.
    let (program, full_argv, _keep_open) = cage_command(bwrap, spec, limits)?;
    // Recorded before the fork, for the child to clear between `fork` and `execv`. The parent keeps
    // its copies close-on-exec, so nothing else this process launches inherits them — see
    // [`crate::sandbox::memfd::write`] for what that window cost.
    let inherit: Vec<libc::c_int> = {
        use std::os::unix::io::AsRawFd;
        _keep_open.iter().map(|f| f.as_raw_fd()).collect()
    };
    let program_c = cstring(program.as_os_str().as_bytes())?;
    let mut argv_owned = vec![program_c.clone()];
    for arg in &full_argv {
        argv_owned.push(cstring(arg.as_bytes())?);
    }
    let mut argv: Vec<*const libc::c_char> = argv_owned.iter().map(|c| c.as_ptr()).collect();
    argv.push(std::ptr::null());

    // The child of the fork below: it calls only async-signal-safe functions (`login_tty`, `execv`,
    // `_exit`) on the prebuilt argv, and never returns.
    let in_child = move |slave: libc::c_int| -> std::convert::Infallible {
        // First, and through the same helper the `Command` paths use: bwrap reads these descriptors
        // by number off its own argument list, so an exec that dropped them would have it open
        // nothing. `clear_cloexec` calls only `fcntl`, which this child may.
        if !crate::sandbox::memfd::clear_cloexec(&inherit) {
            // SAFETY: `_exit` in a fork child, the only safe way out of here.
            unsafe { libc::_exit(127) };
        }
        unsafe {
            // login_tty: setsid + make the slave our controlling terminal + dup it onto
            // stdin/out/err. This is what gives the sandbox a controlling terminal (and thus job
            // control).
            if libc::login_tty(slave) == 0 {
                libc::execv(program_c.as_ptr(), argv.as_ptr());
            }
            // only reached if login_tty or execv failed
            libc::_exit(127)
        }
    };
    // SAFETY: the closure honours the async-signal-safe contract above, and `_keep_open` holds the
    // filter/environment descriptors open for the whole relay.
    unsafe { fork_with_pty(gui, in_child) }
}

/// `CString` from raw bytes, mapping an interior NUL to an I/O error.
pub(super) fn cstring(bytes: &[u8]) -> io::Result<CString> {
    CString::new(bytes).map_err(|_| io::Error::other("argument contains an interior NUL byte"))
}

#[cfg(test)]
mod tests;
