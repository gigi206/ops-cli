//! Interactive-terminal (pty) supervision primitives: the stdin/stdout pump loop,
//! double-Ctrl+C escalation, the SIGWINCH resize relay, the raw-mode guard, child teardown, and the
//! open-fork-relay sequence that assembles them. Pure file-descriptor and terminal machinery — no
//! launch or config state.

use std::io;
use std::sync::atomic::{AtomicI32, Ordering};
use std::time::{Duration, Instant};

/// A second Ctrl+C within this window force-quits a graphical session (see the stdin relay below).
pub(crate) const DOUBLE_CTRL_C_WINDOW: Duration = Duration::from_secs(2);

/// What a chunk of graphical-session stdin means for the double-Ctrl+C escape hatch.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum CtrlC {
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
pub(crate) fn classify_ctrl_c(chunk: &[u8], last: Option<Instant>, now: Instant) -> CtrlC {
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

/// Relay bytes between the real terminal and the pty master until the session
/// ends, then reap the child and return its exit status code. `winch_fd` is the read
/// end of the resize relay's self-pipe (or `-1` when it could not be installed — `poll`
/// ignores a negative fd), readable when a `SIGWINCH` has arrived.
pub(crate) fn pump(
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
        // SAFETY: `fds` is a live stack array of three `pollfd`s and the count passed is its own
        // length, so `poll` writes `revents` only within it. An entry set to `-1` (stdin after EOF,
        // or an absent resize relay) is skipped by the kernel rather than dereferenced.
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
            // SAFETY: `master` is the pty master this relay was handed, closed by the caller only
            // after `pump` returns; `buf` is a live stack array and the length passed is its own.
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
            // SAFETY: fd 0 is the process's own stdin, which the relay never closes — an EOF
            // neutralizes only the `pollfd` entry — and `buf` is a live stack array bounded by its
            // own length.
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
        // SAFETY: `child` is the pid the caller forked and this loop is its only reaper, so the
        // number cannot yet name a recycled process; `status` is a live local for the kernel to
        // fill.
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
pub(crate) fn exit_code(status: libc::c_int) -> i32 {
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
    // SAFETY: `child` has not been reaped — this function is what reaps it — so the pid still names
    // the forked cage; `kill` takes two integers and no pointer.
    unsafe { libc::kill(child, libc::SIGTERM) };
    // Poll for a graceful exit for up to ~2s before the hard kill.
    for _ in 0..40 {
        let mut status: libc::c_int = 0;
        // SAFETY: `child` stays unreaped until one of these polls returns it, so the pid is still
        // its own; `status` is a live local the kernel fills.
        let r = unsafe { libc::waitpid(child, &mut status, libc::WNOHANG) };
        if r == child {
            return Ok(exit_code(status));
        }
        if r < 0 && io::Error::last_os_error().kind() != io::ErrorKind::Interrupted {
            return Ok(1); // already reaped / gone
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    // SAFETY: the grace loop above left without reaping `child` (a reaped or vanished one returns
    // from inside it), so the pid still names the forked cage.
    unsafe { libc::kill(child, libc::SIGKILL) };
    let mut status: libc::c_int = 0;
    loop {
        // SAFETY: `child` was signalled but not reaped, so the pid still names it; `status` is a
        // live local for the kernel to fill.
        let r = unsafe { libc::waitpid(child, &mut status, 0) };
        if r < 0 && io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
            continue;
        }
        break;
    }
    Ok(exit_code(status))
}

/// Write the whole buffer, retrying short writes and interrupts.
pub(crate) fn write_all(fd: libc::c_int, mut buf: &[u8]) -> io::Result<()> {
    while !buf.is_empty() {
        // SAFETY: `fd` is a descriptor the caller keeps open across the call, and the
        // pointer/length pair is the remaining slice of the caller's live buffer, which `write`
        // only reads.
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
/// atomic (no allocation, no locks). The write's *return value* is ignored, because a full pipe
/// (`EAGAIN`) or an absent relay costs nothing: the supervisor coalesces, so a dropped nudge only
/// means an already-pending resize is still pending.
///
/// `errno` is saved and restored around it, which the return value being ignored does not cover. A
/// handler runs on whatever thread the signal interrupted, and the code it interrupts here reads
/// `errno` a line after its own failing syscall — [`write_all`] and the pump's `poll` loop both
/// call `io::Error::last_os_error()` on the step after a `-1`. A resize landing in that gap
/// overwrote the real error with the handler's `EAGAIN`, so a genuine `EIO` on the pty was reported
/// as a would-block, and an `EINTR` the loops retry on was lost.
extern "C" fn winch_handler(_sig: libc::c_int) {
    let fd = WINCH_WRITE_FD.load(Ordering::Relaxed);
    if fd >= 0 {
        let byte = [1u8];
        // SAFETY: `__errno_location` returns this thread's own `errno` slot, and the write is a
        // single constant byte to a non-blocking descriptor.
        unsafe {
            let saved = *libc::__errno_location();
            libc::write(fd, byte.as_ptr().cast(), 1);
            *libc::__errno_location() = saved;
        }
    }
}

/// Relays terminal resizes onto the pty master for the life of a supervised session. Installs a
/// `SIGWINCH` self-pipe handler on construction and restores the previous disposition (and closes
/// the pipe) on drop, so the handler is live only while the supervisor is pumping.
pub(crate) struct WinchRelay {
    read_fd: libc::c_int,
    write_fd: libc::c_int,
    previous: libc::sigaction,
}

impl WinchRelay {
    /// Create the self-pipe and install the `SIGWINCH` handler, saving the previous disposition to
    /// restore on drop. Both ends are `O_CLOEXEC` (never inherited by bwrap); the read end is
    /// `O_NONBLOCK` so draining it in the poll loop cannot block.
    pub(crate) fn install() -> io::Result<Self> {
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
        // SAFETY: `act` is a live local, so `sa_mask` is a valid signal set for `sigemptyset` to
        // clear in place.
        unsafe { libc::sigemptyset(&mut act.sa_mask) };
        // No `SA_RESTART`: a resize should interrupt the blocking `poll` (the self-pipe is the
        // primary wakeup; the `EINTR` is a harmless second one the loop already handles).
        act.sa_flags = 0;
        // SAFETY: `sigaction` is integers, a signal set and a handler pointer, for which all-zero
        // is a valid value; the call below overwrites it with the old disposition before anything
        // reads it.
        let mut previous: libc::sigaction = unsafe { std::mem::zeroed() };
        // SAFETY: `act` is fully initialized above — handler, cleared mask, zero flags — and
        // `previous` is a live local for the kernel to fill; neither is retained past the call.
        if unsafe { libc::sigaction(libc::SIGWINCH, &act, &mut previous) } != 0 {
            let e = io::Error::last_os_error();
            WINCH_WRITE_FD.store(-1, Ordering::Relaxed);
            // SAFETY: both ends are the ones `pipe2` returned above and nothing has closed them.
            // The handler was never installed (the `sigaction` failed) and the atomic was reset on
            // the line before, so no signal can reach these descriptors.
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

    pub(crate) fn read_fd(&self) -> libc::c_int {
        self.read_fd
    }
}

impl Drop for WinchRelay {
    fn drop(&mut self) {
        // Restore the previous handler *first*, so `winch_handler` can no longer run, before
        // clearing the fd it reads and closing the pipe — no signal can then touch a closed fd.
        // SAFETY: `self.previous` was filled by the checked `sigaction` in `install` — `Self`
        // exists only after that call returned 0 — and a null third argument asks the kernel to
        // discard the disposition being replaced.
        unsafe { libc::sigaction(libc::SIGWINCH, &self.previous, std::ptr::null_mut()) };
        WINCH_WRITE_FD.store(-1, Ordering::Relaxed);
        // SAFETY: both fds are the `pipe2` ends this relay owns and has not closed. The previous
        // handler was restored and the atomic cleared above, so `winch_handler` can no longer write
        // to them.
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
    // SAFETY: this is reached only after `poll` reported `pipe_fd` readable, which the `-1`
    // placeholder for an absent relay never is, so it is the live relay's read end; `sink` is a
    // stack array bounded by its own length.
    while unsafe { libc::read(pipe_fd, sink.as_mut_ptr().cast(), sink.len()) } > 0 {}
    copy_winsize(0, master);
}

/// Copy `src`'s window size onto `dst` (`TIOCGWINSZ` → `TIOCSWINSZ`). Best effort: if `src` has no
/// size (not a terminal), `dst` is left unchanged.
pub(crate) fn copy_winsize(src: libc::c_int, dst: libc::c_int) {
    // SAFETY: `winsize` is four `c_ushort`s, so all-zero is a valid value; it is passed on only
    // after the `ioctl` below has filled it.
    let mut ws: libc::winsize = unsafe { std::mem::zeroed() };
    // SAFETY: `TIOCGWINSZ` takes a `struct winsize *` out-param, which is what `ws` is; a `src`
    // that is not a terminal is refused with `ENOTTY` rather than written through.
    if unsafe { libc::ioctl(src, libc::TIOCGWINSZ, &mut ws) } == 0 {
        // SAFETY: `TIOCSWINSZ` only reads the `struct winsize *` it is given, and `ws` was filled
        // by the successful `TIOCGWINSZ` on the line above.
        unsafe { libc::ioctl(dst, libc::TIOCSWINSZ, &ws) };
    }
}

/// Put a terminal into raw mode, restoring the original settings on drop (covers
/// normal return, `?`, and panic — but not a `SIGKILL`/`SIGTERM`).
pub(crate) struct RawMode {
    fd: libc::c_int,
    original: libc::termios,
}

impl RawMode {
    pub(crate) fn enable(fd: libc::c_int) -> io::Result<Self> {
        // SAFETY: `termios` is flag words, speeds and a control-character array — all-zero is a
        // valid value — and `tcgetattr` fills it below before anything reads it.
        let mut original: libc::termios = unsafe { std::mem::zeroed() };
        // SAFETY: `original` is a live local `termios` for `tcgetattr` to fill; a descriptor that
        // is not a terminal is answered with `ENOTTY` instead of a write.
        if unsafe { libc::tcgetattr(fd, &mut original) } != 0 {
            return Err(io::Error::last_os_error());
        }
        let mut raw = original;
        // SAFETY: `raw` is a live local copy of the settings `tcgetattr` just returned, which is
        // what `cfmakeraw` rewrites in place.
        unsafe { libc::cfmakeraw(&mut raw) };
        // SAFETY: `raw` is a fully initialized `termios` — the settings just read, put into raw
        // mode by `cfmakeraw` — which `tcsetattr` reads without retaining.
        if unsafe { libc::tcsetattr(fd, libc::TCSAFLUSH, &raw) } != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(RawMode { fd, original })
    }
}

impl Drop for RawMode {
    fn drop(&mut self) {
        // SAFETY: `self.original` was filled by the checked `tcgetattr` in `enable` — `Self` exists
        // only after it returned 0 — and `self.fd` is the terminal that call succeeded on, which
        // this guard never closes.
        unsafe { libc::tcsetattr(self.fd, libc::TCSAFLUSH, &self.original) };
    }
}

/// Open a pty, fork, and relay the terminal until the child exits — the machinery `launch::supervise` and
/// `launch::supervise_attach` share, which is every line of the two but the child itself. Returns the
/// child's exit code in the shell convention.
///
/// The parent keeps the pty master and never execs, so the master is set close-on-exec: it must
/// never reach the payload, which could otherwise read or inject its own terminal stream. The child
/// branch closes it outright before handing `slave` to `child`.
///
/// Everything `child` captured is dropped in the parent as soon as the fork returns, so a handle the
/// parent must not hold for the whole session — the attach path's `CageHandle`, which owns a
/// pidfd — is released there. The forked child holds its own copies.
///
/// `gui` is passed on to [`pump`]: a graphical cage reads a doubled Ctrl+C as the way out.
///
/// # Safety
///
/// `child` runs between `fork` and `exec` and must therefore touch only async-signal-safe code — no
/// allocation, no locks — and must not return. Everything it uses has to be prepared before the
/// call.
pub(super) unsafe fn fork_with_pty(
    gui: bool,
    child: impl FnOnce(libc::c_int) -> std::convert::Infallible,
) -> io::Result<i32> {
    // Carry the real terminal's window size onto the pty so the inner shell wraps correctly from
    // the start.
    // SAFETY: all-zero is a valid `winsize` (four `c_ushort`s), and it is handed to `openpty` only
    // on the branch where the `ioctl` below filled it.
    let mut ws: libc::winsize = unsafe { std::mem::zeroed() };
    // SAFETY: fd 0 is the process's own stdin and `TIOCGWINSZ` takes the `struct winsize *` out-
    // param `ws` is; a stdin that is not a terminal fails with `ENOTTY` and writes nothing.
    let winp = if unsafe { libc::ioctl(0, libc::TIOCGWINSZ, &mut ws) } == 0 {
        &ws as *const libc::winsize
    } else {
        std::ptr::null()
    };

    let mut master: libc::c_int = -1;
    let mut slave: libc::c_int = -1;
    // SAFETY: out-params are valid; name/termios are null (defaults), winp is null or a valid
    // winsize.
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

    // The master must never reach the sandbox. The parent keeps it (and never execs), so
    // close-on-exec is exactly right; the slave's controlling-terminal setup is the child's.
    // SAFETY: `master` is the descriptor `openpty` just returned and nothing has closed it; both
    // `fcntl` commands take an integer argument rather than a pointer.
    unsafe {
        let flags = libc::fcntl(master, libc::F_GETFD);
        libc::fcntl(master, libc::F_SETFD, flags | libc::FD_CLOEXEC);
    }

    // SAFETY: the child branch below runs only `close` and the caller's closure, whose contract is
    // the async-signal-safety this function documents.
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        let e = io::Error::last_os_error();
        // SAFETY: `fork` failed, so no second process shares them: `master` and `slave` are the
        // pair `openpty` returned and this is their only close.
        unsafe {
            libc::close(master);
            libc::close(slave);
        }
        return Err(e);
    }
    if pid == 0 {
        // SAFETY: this is the child, between `fork` and `exec`, and `close` is a raw syscall.
        // `master` is the child's own copy of the descriptor, so closing it leaves the parent's
        // alone.
        unsafe { libc::close(master) };
        child(slave);
    } else {
        // Release what the child captured: it has its own copies across the fork, and a handle the
        // parent keeps for the session is a handle held open for no reason (the attach path's
        // pidfd).
        drop(child);
    }

    // Parent: drop the slave, go raw, relay.
    // SAFETY: only the parent reaches this line — the child branch above never returns — and its
    // `slave` is its own copy of the descriptor, still open and used nowhere else here.
    unsafe { libc::close(slave) };
    let _raw = RawMode::enable(0)?;
    // Install the resize relay *after* the fork so the child never inherits the handler. sbx keeps
    // the real controlling terminal (only the child `setsid`'d, via `login_tty` or the attach
    // entry), so it receives `SIGWINCH` from the launching terminal naturally; the handler wakes
    // `pump` to copy the new size onto the pty master. Best effort: if it cannot be installed the
    // session still runs, only without dynamic resize (the startup size is already set by
    // `openpty`).
    let winch = WinchRelay::install().ok();
    if winch.is_some() {
        // Close a resize that raced startup (between `openpty` and now).
        copy_winsize(0, master);
    }
    let winch_fd = winch.as_ref().map_or(-1, WinchRelay::read_fd);
    let status = pump(master, pid, winch_fd, gui);
    drop(winch);
    // SAFETY: the parent has held `master` since `openpty` and `pump` has returned, so nothing is
    // still reading it; this is its only close.
    unsafe { libc::close(master) };
    status
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn winch_handler_leaves_errno_to_the_interrupted_call() {
        // A relay pipe filled to capacity, so the handler's write really fails and really sets
        // `errno` — the case a resize arriving mid-`write_all` produces.
        let mut fds = [0 as libc::c_int; 2];
        assert_eq!(
            unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC | libc::O_NONBLOCK) },
            0
        );
        let (read_fd, write_fd) = (fds[0], fds[1]);
        let filler = [0u8; 4096];
        while unsafe { libc::write(write_fd, filler.as_ptr().cast(), filler.len()) } > 0 {}
        assert_eq!(
            io::Error::last_os_error().raw_os_error(),
            Some(libc::EAGAIN),
            "the pipe must be full, or the handler's write would not fail at all"
        );

        let previous = WINCH_WRITE_FD.swap(write_fd, Ordering::Relaxed);
        // What a failing pty syscall left behind for the line that is about to read it.
        unsafe { *libc::__errno_location() = libc::EIO };
        winch_handler(libc::SIGWINCH);
        let after_failed_write = unsafe { *libc::__errno_location() };

        // And the nudge itself still happens when the pipe has room: the guard must not have
        // become "do nothing".
        let mut sink = [0u8; 64];
        while unsafe { libc::read(read_fd, sink.as_mut_ptr().cast(), sink.len()) } > 0 {}
        winch_handler(libc::SIGWINCH);
        let mut one = [0u8; 8];
        let nudged = unsafe { libc::read(read_fd, one.as_mut_ptr().cast(), one.len()) };

        WINCH_WRITE_FD.store(previous, Ordering::Relaxed);
        unsafe {
            libc::close(read_fd);
            libc::close(write_fd);
        }
        assert_eq!(
            after_failed_write,
            libc::EIO,
            "the handler overwrote the interrupted call's errno with its own"
        );
        assert_eq!(nudged, 1, "the handler stopped writing its nudge byte");
    }

    #[test]
    fn exit_code_maps_clean_and_signalled_children() {
        // waitpid encodes a clean exit in the high byte; code 7 -> 7.
        assert_eq!(exit_code(7 << 8), 7);
        // A signalled child is 128 + signo — the SIGKILL the force-quit escalates to.
        assert_eq!(exit_code(libc::SIGKILL), 128 + libc::SIGKILL);
    }
}
