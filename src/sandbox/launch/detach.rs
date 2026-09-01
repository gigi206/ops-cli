//! The `--detach` daemon and the format of the log it leaves behind: the fork, the `setsid`, the
//! readiness pipe, the session-log header, and the trust-drop notes.
//!
//! Self-contained process plumbing. The split across a fork is structural rather than stylistic —
//! the cage's host-side filtering proxy runs on a thread, and a thread does not survive a fork, so
//! the daemon has to build its own cage after forking — and the readiness pipe is what lets the
//! caller's shell return only once that cage is standing.
//!
//! The log's writer and its reader are deliberately side by side: they share one format, and the
//! way that format breaks is a `writeln!` on one side of the tree that quietly stops matching a
//! parser on the other.

use super::build::build;
use super::cage::{exec, register, run_status};
use super::*;

/// The byte the detached child writes to the readiness pipe once the cage is built, registered,
/// and its log is open — the parent treats any other outcome (a closed pipe, no byte) as failure.
const DETACH_READY: u8 = 1;

/// Launch the cage as a background daemon and return to the caller's shell once it is ready.
///
/// The work is split across a `fork` for one structural reason: under a network allowlist the
/// cage's host filtering proxy runs on a thread, and a thread does not survive `fork` — only the
/// forking thread does. So the daemon must call [`build()`] (which spawns that thread) *itself*,
/// after the fork. The process is single-threaded at this point (nothing before [`build()`] spawns
/// a thread), which is what makes it safe for the child to run arbitrary code before `exec`.
///
/// A readiness pipe makes the handoff honest rather than blind: the child reports success only
/// after the cage is built, registered, and its log opened, so the parent returns a real session
/// id — not "started" for a daemon that then failed to provision with no terminal to show it. Any
/// setup error is printed to the caller's terminal (the child keeps it until success) before the
/// daemon redirects its output to the log.
pub(super) fn launch_detached(
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
/// run a second time in the child. With observation on — the `--observe` flag *or* a
/// config-declared `[proc] mode = "observe"` — it also stands up the process observer, which, like
/// a guard, forces the supervised (fork+wait) path so a live parent outlives the cage.
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
        crate::sandbox::observe_feed::Observation::start(
            prep.layout.data_dir(),
            &spec.workdir,
            exec_poll,
            fs,
            false,
        )
    });

    match guard {
        None if may_exec_replace(&prep.cfg.proc, observe) => {
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
/// [`build()`] already put these warnings on the launching terminal, and that ordering is deliberate:
/// stdout/stderr stay there through build and register so provisioning progress and any startup
/// error are seen live, and [`redirect_to_log`] only runs afterwards. The cost is that a detached
/// launch states its dropped security fields to a terminal it is about to lose, and keeps no record
/// — which is the one warning whose symptom arrives much later and in disguise, as a cage that is
/// not shaped the way its config plainly reads. A foreground launch needs none of this: its
/// warnings go to a stderr its invoker owns.
///
/// The redaction is [`trust_drop_notes`]'; see there for what the needle set is for.
///
/// Best-effort, like the header above it: a note that cannot be written costs a reader context,
/// never a session that is otherwise ready to run.
fn note_trust_drops(
    log: &File,
    warnings: &[String],
    wiring: Option<&crate::sandbox::notify_sink::NotifyWiring>,
) {
    use std::io::Write as _;
    let mut sink = log;
    for note in trust_drop_notes(warnings, wiring.map(|w| &w.needles)) {
        // Filtered for the same reason the terminal sites are ([`crate::diag::warn_config`]): a
        // detached session's log is read back by `sbx logs`, which is a terminal too, and the note
        // carries a key an untrusted project spelled.
        let note = crate::sandbox::sanitize(&note);
        let _ = writeln!(
            sink,
            "{SESSION_LOG_TRUST_DROP_OPEN}{note}{SESSION_LOG_HEADER_CLOSE}"
        );
    }
}

/// The trust-drop warnings of a launch, redacted, in the order they were produced.
///
/// `needles` redacts each note the way [`crate::sandbox::notify_sink`] redacts the very same string on its
/// way to the desktop. No producer of a trust-drop warning interpolates agent-chosen text today —
/// they carry a layer label, a caller-spelled field phrase, a bind count, plugin table names and a
/// nix tool name — so this is a no-op on every string it currently sees. It is here for the producer
/// added later: [`crate::config::is_trust_drop`] matches on the remedy rather than on any one
/// reason's wording, so a new one flows into this writer without anyone revisiting it. A launch that
/// needs no guard carries no needle set, and then the note goes out as the terminal already had it.
///
/// The lock is taken through [`crate::sandbox::locks::read_locked`], not `read().ok()`. This is the second
/// reader of a set whose [`Needles`](crate::sandbox::notify_sink::Needles) doc calls the delivery thread its
/// only one, and a panic on that thread poisons the `RwLock` for this one. `read().ok()` turned that
/// into `None` — the branch that writes the warning **unredacted** — so the one event most likely to
/// leave a half-finished credential set behind would also have been the event that stopped redacting
/// against it. Recovering the set is what the rest of the crate does with a poisoned lock, and it is
/// the fail-closed reading here: a set filled by a thread that later panicked still names real
/// credentials.
fn trust_drop_notes(
    warnings: &[String],
    needles: Option<&crate::sandbox::notify_sink::Needles>,
) -> Vec<String> {
    let needles = needles.map(|n| crate::sandbox::locks::read_locked(n));
    warnings
        .iter()
        .filter(|w| crate::config::is_trust_drop(w))
        .map(|warning| match needles.as_deref() {
            Some(n) => {
                crate::sandbox::redact::redact_string(
                    warning,
                    n,
                    &crate::sandbox::redact::Placeholder::Plain,
                )
                .0
            }
            None => warning.clone(),
        })
        .collect()
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

#[cfg(test)]
mod tests;
