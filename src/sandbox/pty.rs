//! Interactive-terminal (pty) supervision primitives: the stdin/stdout pump loop,
//! double-Ctrl+C escalation, the signal relay (a resize, a stop), the raw-mode guard, child teardown, and the
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

/// How long the master must stay quiet, once the child has exited, before the relay stops.
const QUIET_AFTER_EXIT_MS: libc::c_int = 100;

/// The longest the relay goes on reading the master once the child has exited.
const DRAIN_AFTER_EXIT: Duration = Duration::from_secs(1);

/// How often the relay asks whether the child has exited when it has no pidfd to wait on.
const EXIT_POLL_MS: libc::c_int = 200;

/// The most input the relay holds for a child that has not taken it yet. Far above what anyone
/// types; a paste larger than this into a program that reads slowly waits on the terminal instead,
/// and a graphical cage, which never reads its input, has the rest dropped.
const PENDING_INPUT_MAX: usize = 64 * 1024;

/// Relay bytes between the real terminal and the pty master until the child exits, then reap it
/// and return its exit status code, or until this process is asked to stop. `signals_fd` is the
/// read end of the [`SignalRelay`]'s self-pipe (or `-1` when it could not be installed — `poll`
/// ignores a negative fd), readable when a `SIGWINCH` or a `SIGTERM` has arrived.
///
/// The child's exit ends the session, not the master's end. The master reads `EIO` only once every
/// copy of the slave is closed, and a process the child left behind can hold one for as long as it
/// runs: a job put in the background in an attached shell, which is not the pid namespace's init
/// and so outlives the shell. Waiting for it kept `sbx session attach` on a raw terminal after the
/// shell had exited, and sent what the operator typed next into the cage. So the child is watched
/// through a pidfd (or, where the kernel offers none, asked every [`EXIT_POLL_MS`]), and once it
/// has exited the relay passes on what it left in the pty and stops.
///
/// The relay never waits on the child. The master is non-blocking, and input the child has not
/// taken yet waits in a buffer of at most [`PENDING_INPUT_MAX`] bytes; while it is full the terminal
/// is not read, so nothing is lost, except in a graphical cage, whose input is still read so that a
/// double Ctrl+C is seen, and what does not fit is dropped, said once. A child that stopped reading
/// its input therefore stalls none of its output, its resizes or a stop. What the relay does wait
/// on is its own standard output, shared with whatever else writes the terminal: one that stops
/// taking output stalls it.
pub(crate) fn pump(
    master: libc::c_int,
    child: libc::pid_t,
    signals_fd: libc::c_int,
    gui: bool,
) -> io::Result<Ended> {
    // On the master alone: the slave was opened with the same flags, and it is the child's own
    // standard input, which must keep blocking.
    // SAFETY: `fcntl` reads the status flags of the master this relay was handed.
    let flags = unsafe { libc::fcntl(master, libc::F_GETFL) };
    // SAFETY: and sets them back on the same descriptor with `O_NONBLOCK` added.
    let set =
        flags >= 0 && unsafe { libc::fcntl(master, libc::F_SETFL, flags | libc::O_NONBLOCK) } >= 0;
    if !set {
        let e = io::Error::last_os_error();
        let _ = terminate_and_reap(child);
        return Err(e);
    }
    // SAFETY: `pidfd_open` takes a pid and flags and returns a fresh descriptor, or -1 where the
    // kernel or a filter refuses it. `child` is unreaped, so the pid still names it.
    let pidfd = unsafe { libc::syscall(libc::SYS_pidfd_open, child, 0) } as libc::c_int;
    let exited = pump_until_exit(master, child, pidfd, signals_fd, gui);
    if pidfd >= 0 {
        // SAFETY: the descriptor `pidfd_open` returned above, used nowhere else; this is its only
        // close.
        unsafe { libc::close(pidfd) };
    }
    match exited {
        Ok(Some(ended)) => Ok(ended),
        Ok(None) => Ok(Ended::Exited(reap(child))),
        // The relay failed under a child that still runs (its standard output gone, a poll the
        // kernel refused): nothing will relay its terminal any more, so it is stopped and reaped
        // as a force-quit is, rather than left to a hangup it may never act on and to a zombie.
        Err(e) => {
            let _ = terminate_and_reap(child);
            Err(e)
        }
    }
}

/// How [`pump`] ended.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Ended {
    /// The child exited with this code, and is reaped.
    Exited(i32),
    /// This process was asked to stop (`SIGTERM`) while the relay ran. The child is left as it is:
    /// the caller gives the terminal back and then ends as the signal asked, which takes the cage
    /// down the way that signal always has.
    Stopped,
}

/// The relay loop of [`pump`]: `Some` when it reaped the child itself or was asked to stop, `None`
/// when the master ended first and the child is still to be reaped.
fn pump_until_exit(
    master: libc::c_int,
    child: libc::pid_t,
    pidfd: libc::c_int,
    signals_fd: libc::c_int,
    gui: bool,
) -> io::Result<Option<Ended>> {
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
            fd: signals_fd,
            events: libc::POLLIN,
            revents: 0,
        },
        libc::pollfd {
            fd: pidfd,
            events: libc::POLLIN,
            revents: 0,
        },
    ];
    let timeout = if pidfd < 0 { EXIT_POLL_MS } else { -1 };
    let mut buf = [0u8; 8192];
    let mut stdin_open = true;
    // For a GUI cage: the instant of the last unescalated Ctrl+C, so a second within the window
    // force-quits (a graphical app ignores the forwarded SIGINT). `None` outside a GUI cage.
    let mut last_ctrl_c: Option<Instant> = None;
    // Input read from the terminal that the master has not taken yet, and whether dropping some of
    // it in a graphical cage has been said.
    let mut pending: Vec<u8> = Vec::new();
    let mut said_dropped = false;

    loop {
        // What this round waits for. The terminal is read while what it gives has room, and always
        // in a graphical cage; the master is asked for room only while input waits, since a writable
        // master is otherwise always ready and the poll would spin. A paused stdin is a negative
        // descriptor rather than no events, because a hangup is reported whatever is asked.
        fds[0].fd = if stdin_open && (gui || pending.len() < PENDING_INPUT_MAX) {
            0
        } else {
            -1
        };
        fds[1].events = match pending.is_empty() {
            true => libc::POLLIN,
            false => libc::POLLIN | libc::POLLOUT,
        };
        // SAFETY: `fds` is a live stack array of `pollfd`s and the count passed is its own length,
        // so `poll` writes `revents` only within it. An entry set to `-1` (stdin after EOF or while
        // its input waits, an absent signal relay or pidfd) is skipped by the kernel rather than
        // dereferenced.
        let r = unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, timeout) };
        if r < 0 {
            let e = io::Error::last_os_error();
            if e.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(e);
        }

        // A signal arrived. A resize copies the real terminal's window size onto the pty, handled
        // before stdin so a resize delivered alongside input takes effect before that input
        // reaches the inner program. A stop ends the relay at once. The handler has given the
        // terminal back already, and the line saying so carries its own carriage returns, which
        // read the same whether the terminal is raw or not.
        if fds[2].revents != 0 {
            let caught = drain_signals(signals_fd);
            if caught.resized {
                copy_winsize(0, master);
            }
            if caught.stop {
                let _ = write_all(2, b"\r\nsbx: this session was asked to stop.\r\n");
                return Ok(Some(Ended::Stopped));
            }
        }

        // master -> stdout. Quit when the master closes (the child exited), which on Linux
        // surfaces as EIO rather than a clean EOF. Read only on what says there is something to
        // read: a master that is merely writable has nothing, and its `EAGAIN` is not an end.
        if fds[1].revents & (libc::POLLIN | libc::POLLHUP | libc::POLLERR) != 0 {
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
                if e.kind() != io::ErrorKind::WouldBlock {
                    break; // EIO: end of session
                }
            }
        }

        // pending input -> master, as much as it takes now. A failed write is not an end: a child
        // that has gone ends the relay through the master's read or its pidfd.
        if fds[1].revents & libc::POLLOUT != 0 && !pending.is_empty() {
            // SAFETY: `master` is open as above, and the pointer and length are those of the live
            // `pending` buffer, which `write` only reads.
            let n = unsafe { libc::write(master, pending.as_ptr().cast(), pending.len()) };
            if n > 0 {
                pending.drain(..n as usize);
            }
        }

        // stdin -> pending input. When the user's stdin ends, stop reading it but keep passing on
        // what waits and relaying the master until the child exits.
        if fds[0].fd >= 0 && fds[0].revents != 0 {
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
                            return terminate_and_reap(child).map(|code| Some(Ended::Exited(code)));
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
                // Every byte above was looked at for the double Ctrl+C; what is kept is what fits.
                let room = PENDING_INPUT_MAX.saturating_sub(pending.len());
                pending.extend_from_slice(&chunk[..chunk.len().min(room)]);
                if chunk.len() > room && !said_dropped {
                    said_dropped = true;
                    let _ = write_all(
                        2,
                        b"\r\nsbx: this graphical session is not reading its input; what does not fit is dropped.\r\n",
                    );
                }
            } else if n == 0 || !retryable(&io::Error::last_os_error()) {
                stdin_open = false;
                fds[0].fd = -1; // poll ignores a negative fd
            }
        }

        // The child exited: its pidfd turned readable or, with none, a reap that finds it gone.
        // Handled last, so what the master held in this round has been passed on already.
        if (pidfd < 0 || fds[3].revents != 0)
            && let Some(code) = reap_if_exited(child)
        {
            // The child is reaped, so what follows answers with its code whatever the drain
            // meets: an error here must not reach the `Err` arm of `pump`, which would signal a
            // pid that no longer names it.
            let _ = drain_after_exit(master, &mut buf);
            return Ok(Some(Ended::Exited(code)));
        }
    }
    Ok(None)
}

/// Reap `child` if it has exited, without waiting: its exit code, or `None` while it runs. A child
/// already reaped elsewhere has exited too, and answers `1`, the code a status that cannot be read
/// gets.
fn reap_if_exited(child: libc::pid_t) -> Option<i32> {
    let mut status: libc::c_int = 0;
    // SAFETY: `child` is unreaped until this call returns it, so the pid still names it; `status`
    // is a live local for the kernel to fill.
    let r = unsafe { libc::waitpid(child, &mut status, libc::WNOHANG) };
    if r == child {
        Some(exit_code(status))
    } else if r < 0 && io::Error::last_os_error().kind() != io::ErrorKind::Interrupted {
        Some(1)
    } else {
        None
    }
}

/// Pass on what the child left in the pty before it exited, then stop: read the master until it
/// has been quiet for [`QUIET_AFTER_EXIT_MS`] or ends, and for no longer than [`DRAIN_AFTER_EXIT`]
/// in all, so a process the child left behind that keeps writing cannot hold the session open.
fn drain_after_exit(master: libc::c_int, buf: &mut [u8]) -> io::Result<()> {
    let deadline = Instant::now() + DRAIN_AFTER_EXIT;
    while Instant::now() < deadline {
        let mut fd = libc::pollfd {
            fd: master,
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: one live `pollfd` on the stack, and the count passed is one.
        let r = unsafe { libc::poll(&mut fd, 1, QUIET_AFTER_EXIT_MS) };
        if r < 0 && io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
            continue;
        }
        if r <= 0 {
            return Ok(());
        }
        // SAFETY: `master` stays open until the caller's `pump` returns, and `buf` is the caller's
        // live buffer, bounded by its own length.
        let n = unsafe { libc::read(master, buf.as_mut_ptr().cast(), buf.len()) };
        if n > 0 {
            write_all(1, &buf[..n as usize])?;
        } else if n == 0 || io::Error::last_os_error().kind() != io::ErrorKind::Interrupted {
            return Ok(());
        }
    }
    Ok(())
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
/// from the pty relay when a graphical session is force-quit with a double Ctrl+C, and by
/// [`fork_with_pty`] when the terminal cannot be put in raw mode once the child has started.
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
    Ok(reap(child))
}

/// Wait for `child` and return its exit code. A wait that fails outright leaves the child's fate
/// unknown, and answers `1`, as [`exit_code`] does for a status it cannot read: the status word was
/// still zero there, and read as a clean exit it reported a success no one had seen.
fn reap(child: libc::pid_t) -> i32 {
    let mut status: libc::c_int = 0;
    loop {
        // SAFETY: `child` is the pid the caller forked and this loop is its only reaper, so the
        // number cannot yet name a recycled process; `status` is a live local for the kernel to
        // fill.
        let r = unsafe { libc::waitpid(child, &mut status, 0) };
        if r >= 0 {
            return exit_code(status);
        }
        if io::Error::last_os_error().kind() != io::ErrorKind::Interrupted {
            return 1;
        }
    }
}

/// Whether a failed read or write is worth trying again: an interrupt, or a descriptor some other
/// program left non-blocking. A terminal's open file is shared with whatever else holds it, and a
/// program that set `O_NONBLOCK` on it makes this process's reads and writes answer `EAGAIN` when
/// they would only have waited.
fn retryable(e: &io::Error) -> bool {
    matches!(
        e.kind(),
        io::ErrorKind::Interrupted | io::ErrorKind::WouldBlock
    )
}

/// Write the whole buffer, retrying short writes and interrupts, and waiting out a descriptor
/// another program left non-blocking ([`retryable`]) until it takes more.
pub(crate) fn write_all(fd: libc::c_int, mut buf: &[u8]) -> io::Result<()> {
    while !buf.is_empty() {
        // SAFETY: `fd` is a descriptor the caller keeps open across the call, and the
        // pointer/length pair is the remaining slice of the caller's live buffer, which `write`
        // only reads.
        let n = unsafe { libc::write(fd, buf.as_ptr().cast(), buf.len()) };
        if n < 0 {
            let e = io::Error::last_os_error();
            if e.kind() == io::ErrorKind::WouldBlock {
                let mut ready = libc::pollfd {
                    fd,
                    events: libc::POLLOUT,
                    revents: 0,
                };
                // SAFETY: one live `pollfd` on the stack, and the count passed is one. Its result
                // is not read: the write is tried again either way and says what went wrong.
                unsafe { libc::poll(&mut ready, 1, -1) };
                continue;
            }
            if e.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(e);
        }
        buf = &buf[n as usize..];
    }
    Ok(())
}

/// The write end of the signal relay's self-pipe, read by [`relay_handler`]. A process-wide atomic
/// because a signal handler cannot capture state; `-1` when no relay is installed. Only one pty
/// supervisor runs per process, so there is a single writer.
static SIGNAL_WRITE_FD: AtomicI32 = AtomicI32::new(-1);

/// The settings [`RawMode`] replaced, and the terminal they belong to, for [`relay_handler`] to put
/// back the moment a stop arrives ([`GIVE_BACK`]).
///
/// The handler cannot wait for the pump to return. The pump may be parked in a write to a standard
/// output that stopped taking it, where a stop waits for that output to be read and the stop's
/// escalation to `SIGKILL` comes first, ending the process with the terminal still raw. Put back
/// from the handler, without waiting for the output (`TCSANOW`), the terminal is the user's again
/// whichever comes next.
///
/// `fd` publishes `settings`: written before `fd` is stored (`Release`), read only once `fd` is
/// loaded (`Acquire`). One terminal at a time, as one pty supervisor runs per process: a second
/// [`RawMode`] finds the slot taken and leaves it alone.
struct GiveBack {
    /// The terminal the settings belong to; `-1` when none is saved, [`GiveBack::ARMING`] while
    /// they are being written.
    fd: AtomicI32,
    settings: std::cell::UnsafeCell<std::mem::MaybeUninit<libc::termios>>,
}

// SAFETY: `settings` is written only by the owner that took the slot from `-1`, before it publishes
// `fd`, and read only once `fd` names a terminal; see the type's documentation.
unsafe impl Sync for GiveBack {}

/// The one [`GiveBack`] slot of this process.
static GIVE_BACK: GiveBack = GiveBack {
    fd: AtomicI32::new(-1),
    settings: std::cell::UnsafeCell::new(std::mem::MaybeUninit::uninit()),
};

impl GiveBack {
    /// What `fd` holds while the settings are being written.
    const ARMING: libc::c_int = -2;

    /// Save `settings` as what `fd` is to be given back to, when no terminal is saved already, and
    /// say whether they were.
    fn arm(&self, fd: libc::c_int, settings: &libc::termios) -> bool {
        if self
            .fd
            .compare_exchange(-1, Self::ARMING, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            return false;
        }
        // SAFETY: the exchange above made this call the slot's only writer, and no reader looks at
        // `settings` until `fd` names a terminal, which the store below does after the write.
        unsafe { (*self.settings.get()).write(*settings) };
        self.fd.store(fd, Ordering::Release);
        true
    }

    /// Forget what `fd` was to be given back to.
    fn disarm(&self, fd: libc::c_int) {
        let _ = self
            .fd
            .compare_exchange(fd, -1, Ordering::Release, Ordering::Relaxed);
    }

    /// Give the saved terminal its settings back, at once and without waiting for its output: what
    /// [`relay_handler`] does on a stop. Async-signal-safe: an atomic load and `tcsetattr`.
    fn give_back(&self) {
        let fd = self.fd.load(Ordering::Acquire);
        if fd >= 0 {
            // SAFETY: `fd` names a terminal only once `arm` has written `settings`, so they are
            // initialised; `tcsetattr` reads them without retaining.
            unsafe { libc::tcsetattr(fd, libc::TCSANOW, (*self.settings.get()).as_ptr()) };
        }
    }
}

/// Signal handler: nudge the supervisor by writing the signal's number, one byte, to the self-pipe,
/// and on a stop give the terminal back first ([`GiveBack`]). Async-signal-safe — it does nothing
/// but `tcsetattr` on a stop and a single `write` of that byte to a non-blocking fd read from an
/// atomic (no allocation, no locks). The write's *return value* is ignored, because a full
/// pipe (`EAGAIN`) or an absent relay costs nothing that matters: the supervisor coalesces, so a
/// dropped resize only means an already-pending one is still pending, and a pipe full enough to
/// drop a stop is one the relay has stopped reading, where a stop's escalation to `SIGKILL` is what
/// ends the process.
///
/// `errno` is saved and restored around it, which the return value being ignored does not cover. A
/// handler runs on whatever thread the signal interrupted, and the code it interrupts here reads
/// `errno` a line after its own failing syscall — [`write_all`] and the pump's `poll` loop both
/// call `io::Error::last_os_error()` on the step after a `-1`. A resize landing in that gap
/// overwrote the real error with the handler's `EAGAIN`, so a genuine `EIO` on the pty was reported
/// as a would-block, and an `EINTR` the loops retry on was lost.
extern "C" fn relay_handler(sig: libc::c_int) {
    // SAFETY: `__errno_location` returns this thread's own `errno` slot, read here and written back
    // below around every call this handler makes.
    let saved = unsafe { *libc::__errno_location() };
    // A resize leaves the terminal raw: the session goes on.
    if sig == libc::SIGTERM {
        GIVE_BACK.give_back();
    }
    let fd = SIGNAL_WRITE_FD.load(Ordering::Relaxed);
    if fd >= 0 {
        let byte = [u8::try_from(sig).unwrap_or(0)];
        // SAFETY: the write is a single byte from a local array to a non-blocking descriptor.
        unsafe { libc::write(fd, byte.as_ptr().cast(), 1) };
    }
    // SAFETY: as above, this thread's own `errno` slot.
    unsafe { *libc::__errno_location() = saved };
}

/// Carries two signals to the pump for the life of a supervised session: `SIGWINCH`, a resize of
/// the real terminal, and `SIGTERM`, a request to stop (`sbx session stop`). Installs
/// [`relay_handler`] for both on construction and restores the previous dispositions (and closes
/// the pipe) on drop, so the handler is live only while the supervisor is pumping.
///
/// A stop is relayed rather than left to its default action because that action ends the process
/// on the spot, with the real terminal still raw: [`RawMode`]'s restore runs on a return, never on
/// a signal. Relayed, the handler gives the terminal back at once ([`GiveBack`]), the pump returns
/// [`Ended::Stopped`], and the process then ends as the signal asked ([`end_as_asked`]). A pump
/// parked in a write to a standard output that stopped taking it returns only once that output is
/// read, and the stop's escalation to `SIGKILL` may come first: the terminal is the user's already.
/// Once given back it is in its own mode again for the rest of that wait, so a Ctrl+C typed there
/// reaches this process as a `SIGINT`, which nothing here handles: its default action ends the
/// process at once, as the escalation would have later. A `SIGTERM` this process was started
/// ignoring stays ignored.
pub(crate) struct SignalRelay {
    read_fd: libc::c_int,
    write_fd: libc::c_int,
    /// The dispositions the handler replaced, each with its signal; restored on drop.
    previous: Vec<(libc::c_int, libc::sigaction)>,
}

impl SignalRelay {
    /// Create the self-pipe and install the handler, saving each previous disposition to restore on
    /// drop. Both ends are `O_CLOEXEC` (never inherited by bwrap); the read end is `O_NONBLOCK` so
    /// draining it in the poll loop cannot block.
    pub(crate) fn install() -> io::Result<Self> {
        let mut fds = [0 as libc::c_int; 2];
        // SAFETY: `pipe2` fills the two-element array.
        if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC | libc::O_NONBLOCK) } != 0 {
            return Err(io::Error::last_os_error());
        }
        let (read_fd, write_fd) = (fds[0], fds[1]);
        SIGNAL_WRITE_FD.store(write_fd, Ordering::Relaxed);
        let mut relay = SignalRelay {
            read_fd,
            write_fd,
            previous: Vec::new(),
        };

        // SAFETY: `act` is zeroed then fully initialized before use. The handler is
        // async-signal-safe (see `relay_handler`).
        let mut act: libc::sigaction = unsafe { std::mem::zeroed() };
        act.sa_sigaction = relay_handler as *const () as libc::sighandler_t;
        // SAFETY: `act` is a live local, so `sa_mask` is a valid signal set for `sigemptyset` to
        // clear in place.
        unsafe { libc::sigemptyset(&mut act.sa_mask) };
        // No `SA_RESTART`: a signal should interrupt the blocking `poll` (the self-pipe is the
        // primary wakeup; the `EINTR` is a harmless second one the loop already handles).
        act.sa_flags = 0;
        for sig in [libc::SIGWINCH, libc::SIGTERM] {
            // SAFETY: `sigaction` is integers, a signal set and a handler pointer, for which
            // all-zero is a valid value; each call below fills it before anything reads it.
            let mut previous: libc::sigaction = unsafe { std::mem::zeroed() };
            if sig == libc::SIGTERM {
                // SAFETY: a null new disposition only reads the current one into `previous`.
                let read = unsafe { libc::sigaction(sig, std::ptr::null(), &mut previous) };
                if read != 0 || previous.sa_sigaction == libc::SIG_IGN {
                    continue;
                }
            }
            // SAFETY: `act` is fully initialized above — handler, cleared mask, zero flags — and
            // `previous` is a live local for the kernel to fill; neither is retained past the call.
            if unsafe { libc::sigaction(sig, &act, &mut previous) } != 0 {
                // Dropping `relay` restores what was installed so far and closes the pipe.
                return Err(io::Error::last_os_error());
            }
            relay.previous.push((sig, previous));
        }
        Ok(relay)
    }

    pub(crate) fn read_fd(&self) -> libc::c_int {
        self.read_fd
    }
}

impl Drop for SignalRelay {
    fn drop(&mut self) {
        // Restore the previous handlers *first*, so `relay_handler` can no longer run, before
        // clearing the fd it reads and closing the pipe — no signal can then touch a closed fd.
        for (sig, previous) in &self.previous {
            // SAFETY: `previous` was filled by the checked `sigaction` in `install` that replaced
            // it, and a null third argument asks the kernel to discard the disposition being
            // replaced.
            unsafe { libc::sigaction(*sig, previous, std::ptr::null_mut()) };
        }
        SIGNAL_WRITE_FD.store(-1, Ordering::Relaxed);
        // SAFETY: both fds are the `pipe2` ends this relay owns and has not closed. The previous
        // handlers were restored and the atomic cleared above, so `relay_handler` can no longer
        // write to them.
        unsafe {
            libc::close(self.read_fd);
            libc::close(self.write_fd);
        }
    }
}

/// What the relay's self-pipe held since the last drain: whether the real terminal was resized,
/// and whether this process was asked to stop. However many of each queued count once.
struct Caught {
    resized: bool,
    stop: bool,
}

/// Drain the relay's self-pipe and say what it held ([`Caught`]).
fn drain_signals(pipe_fd: libc::c_int) -> Caught {
    let mut caught = Caught {
        resized: false,
        stop: false,
    };
    let mut sink = [0u8; 64];
    loop {
        // The read end is non-blocking, so this stops at `EAGAIN`.
        // SAFETY: this is reached only after `poll` reported `pipe_fd` readable, which the `-1`
        // placeholder for an absent relay never is, so it is the live relay's read end; `sink` is a
        // stack array bounded by its own length.
        let n = unsafe { libc::read(pipe_fd, sink.as_mut_ptr().cast(), sink.len()) };
        if n <= 0 {
            return caught;
        }
        for byte in &sink[..n as usize] {
            match libc::c_int::from(*byte) {
                libc::SIGWINCH => caught.resized = true,
                libc::SIGTERM => caught.stop = true,
                _ => {}
            }
        }
    }
}

/// End this process as the `SIGTERM` the relay caught asked, once the terminal is given back: the
/// default action is put back and the signal sent to this process again. Should no thread take it,
/// the process exits with the status a shell gives a death by that signal.
fn end_as_asked() -> ! {
    // SAFETY: `signal`, `kill`, `getpid` and `_exit` take integers and a handler constant; nothing
    // here touches memory.
    unsafe {
        libc::signal(libc::SIGTERM, libc::SIG_DFL);
        libc::kill(libc::getpid(), libc::SIGTERM);
        libc::_exit(128 + libc::SIGTERM)
    }
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

/// Put a terminal into raw mode, restoring the original settings on drop (covers normal return,
/// `?`, and panic — but no signal). [`fork_with_pty`] relays a `SIGTERM`, whose handler gives the
/// original settings back at once ([`GiveBack`]) and whose return path runs the drop. A `SIGKILL`
/// that comes with no `SIGTERM` before it, or a `SIGHUP`, still leaves the terminal raw.
pub(crate) struct RawMode {
    fd: libc::c_int,
    original: libc::termios,
    /// Whether the original settings are the ones a stop gives back ([`GiveBack::arm`]).
    armed: bool,
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
        let armed = GIVE_BACK.arm(fd, &original);
        Ok(RawMode {
            fd,
            original,
            armed,
        })
    }
}

impl Drop for RawMode {
    fn drop(&mut self) {
        // Forgotten first, so a stop that comes after this restore does not undo whatever the
        // terminal is put in next.
        if self.armed {
            GIVE_BACK.disarm(self.fd);
        }
        // SAFETY: `self.original` was filled by the checked `tcgetattr` in `enable` — `Self` exists
        // only after it returned 0 — and `self.fd` is the terminal that call succeeded on, which
        // this guard never closes.
        unsafe { libc::tcsetattr(self.fd, libc::TCSAFLUSH, &self.original) };
    }
}

/// Open a pty pair whose two descriptors are close-on-exec from the moment they exist, sized to
/// `size` when the real terminal has one.
///
/// `openpty` opens both ends without the flag, and setting it afterwards leaves a window: the
/// supervisor runs other threads by then (the egress proxy's, the port forwarder's), and a
/// process one of them started in that window carried a copy of the slave through its `exec`,
/// holding the session's terminal for as long as it ran, or of the master, with the terminal's
/// whole stream. The master comes from `posix_openpt` with the flag, and the slave from the master
/// itself (`TIOCGPTPEER`, Linux 4.13) with the flag in the same call; a kernel without that
/// request opens it by name instead, flag included. The child's `login_tty` puts the slave on its
/// standard descriptors, which carry no flag, so the command keeps its terminal.
fn open_pty_pair(size: Option<&libc::winsize>) -> io::Result<(libc::c_int, libc::c_int)> {
    const FLAGS: libc::c_int = libc::O_RDWR | libc::O_NOCTTY | libc::O_CLOEXEC;
    // SAFETY: `posix_openpt` takes flags and returns a fresh descriptor or -1.
    let master = unsafe { libc::posix_openpt(FLAGS) };
    if master < 0 {
        return Err(io::Error::last_os_error());
    }
    let fail = |master: libc::c_int| {
        let e = io::Error::last_os_error();
        // SAFETY: the master opened above, used nowhere else; this is its only close.
        unsafe { libc::close(master) };
        Err(e)
    };
    // SAFETY: both take the master `posix_openpt` returned and nothing else.
    if unsafe { libc::grantpt(master) } != 0 || unsafe { libc::unlockpt(master) } != 0 {
        return fail(master);
    }
    // SAFETY: `TIOCGPTPEER` takes the open flags as its integer argument and returns a fresh
    // descriptor for the master's slave, or -1.
    let mut slave = unsafe { libc::ioctl(master, libc::TIOCGPTPEER, FLAGS) };
    if slave < 0 {
        let mut name = [0 as libc::c_char; 64];
        // SAFETY: `ptsname_r` writes a NUL-terminated name of at most the length passed into the
        // local buffer, and `open` reads that name.
        slave = unsafe {
            if libc::ptsname_r(master, name.as_mut_ptr(), name.len()) != 0 {
                return fail(master);
            }
            libc::open(name.as_ptr(), FLAGS)
        };
        if slave < 0 {
            return fail(master);
        }
    }
    if let Some(size) = size {
        // SAFETY: `TIOCSWINSZ` reads the `struct winsize` it is handed. A failure leaves the pty at
        // its default size, which the signal relay corrects at the first `SIGWINCH`.
        unsafe { libc::ioctl(master, libc::TIOCSWINSZ, size as *const libc::winsize) };
    }
    Ok((master, slave))
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
/// A failure says which side of the fork it came from ([`PtyFailure`]): before it no child exists,
/// after it the child was started.
///
/// # Safety
///
/// `child` runs between `fork` and `exec` and must therefore touch only async-signal-safe code — no
/// allocation, no locks — and must not return. Everything it uses has to be prepared before the
/// call.
pub(super) unsafe fn fork_with_pty(
    gui: bool,
    child: impl FnOnce(libc::c_int) -> std::convert::Infallible,
) -> Result<i32, PtyFailure> {
    // Carry the real terminal's window size onto the pty so the inner shell wraps correctly from
    // the start.
    // SAFETY: all-zero is a valid `winsize` (four `c_ushort`s), and it is handed to `open_pty_pair`
    // only on the branch where the `ioctl` below filled it.
    let mut ws: libc::winsize = unsafe { std::mem::zeroed() };
    // SAFETY: fd 0 is the process's own stdin and `TIOCGWINSZ` takes the `struct winsize *` out-
    // param `ws` is; a stdin that is not a terminal fails with `ENOTTY` and writes nothing.
    let size = (unsafe { libc::ioctl(0, libc::TIOCGWINSZ, &mut ws) } == 0).then_some(&ws);

    let (master, slave) = open_pty_pair(size).map_err(PtyFailure::BeforeFork)?;

    // SAFETY: the child branch below runs only `close` and the caller's closure, whose contract is
    // the async-signal-safety this function documents.
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        let e = io::Error::last_os_error();
        // SAFETY: `fork` failed, so no second process shares them: `master` and `slave` are the
        // pair `open_pty_pair` returned and this is their only close.
        unsafe {
            libc::close(master);
            libc::close(slave);
        }
        return Err(PtyFailure::BeforeFork(e));
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

    // Parent: drop the slave, catch the signals the relay carries, go raw, relay.
    // SAFETY: only the parent reaches this line — the child branch above never returns — and its
    // `slave` is its own copy of the descriptor, still open and used nowhere else here.
    unsafe { libc::close(slave) };
    // The relay goes in *after* the fork, so the child never runs with its handler, and *before*
    // raw mode, so no stop can find the terminal raw with its default action still standing. sbx
    // keeps the real controlling terminal (only the child `setsid`'d, via `login_tty` or the attach
    // entry), so it receives `SIGWINCH` from the launching terminal naturally; the handler wakes
    // `pump` to copy the new size onto the pty master. Best effort: if it cannot be installed the
    // session still runs, only without dynamic resize (the startup size is already set when the
    // pair was opened) and with a stop that leaves the terminal raw.
    let relay = SignalRelay::install().ok();
    let raw = match RawMode::enable(0) {
        Ok(raw) => raw,
        Err(e) => {
            // The child is running and nothing will relay its terminal: stop it as a force-quit
            // does, and reap it, rather than leave a cage on a pty no one reads. The relay goes
            // first, so a stop that arrives meanwhile takes effect as it always did.
            drop(relay);
            // SAFETY: the parent has held `master` since `open_pty_pair` and nothing reads it now;
            // this is its only close.
            unsafe { libc::close(master) };
            let _ = terminate_and_reap(pid);
            return Err(PtyFailure::AfterFork(e));
        }
    };
    if relay.is_some() {
        // Close a resize that raced startup (between opening the pair and now).
        copy_winsize(0, master);
    }
    let signals_fd = relay.as_ref().map_or(-1, SignalRelay::read_fd);
    let status = pump(master, pid, signals_fd, gui);
    drop(relay);
    // SAFETY: the parent has held `master` since `open_pty_pair` and `pump` has returned, so nothing is
    // still reading it; this is its only close.
    unsafe { libc::close(master) };
    match status {
        Ok(Ended::Exited(code)) => Ok(code),
        // The terminal is given back first: that is what the relay is for.
        Ok(Ended::Stopped) => {
            drop(raw);
            end_as_asked()
        }
        Err(e) => Err(PtyFailure::AfterFork(e)),
    }
}

/// Why [`fork_with_pty`] has no exit code to give, by the side of the fork the failure came from.
///
/// The fork is the line a caller that learns from the session needs drawn: before it nothing ran,
/// so there is nothing to learn from; after it the child was started, and what it did stands even
/// though the relay under it failed.
#[derive(Debug)]
pub(super) enum PtyFailure {
    /// The pty could not be opened, or the fork failed, or the caller could not prepare the child:
    /// no child exists.
    BeforeFork(io::Error),
    /// The child was started, and the terminal or the relay failed under it.
    AfterFork(io::Error),
}

impl PtyFailure {
    /// Whether a child was started before the failure.
    pub(super) fn started(&self) -> bool {
        matches!(self, PtyFailure::AfterFork(_))
    }

    /// The I/O error, for a caller that answers both sides the same way.
    pub(super) fn into_io(self) -> io::Error {
        match self {
            PtyFailure::BeforeFork(e) | PtyFailure::AfterFork(e) => e,
        }
    }
}

impl std::fmt::Display for PtyFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PtyFailure::BeforeFork(e) | PtyFailure::AfterFork(e) => e.fmt(f),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A child started under a pty whose terminal then cannot go raw is stopped and reaped, not
    /// left running on a pty no one reads. Run alone, in a process whose stdin is `/dev/null`, so
    /// `RawMode::enable(0)` fails once the fork has happened whatever terminal this run has.
    #[test]
    fn a_terminal_that_cannot_go_raw_stops_and_reaps_the_started_child() {
        let ran = crate::testutil::run_within(
            crate::testutil::alone(
                concat!(module_path!(), "::a_pty_whose_terminal_cannot_go_raw"),
                "",
            )
            .stdin(std::process::Stdio::null()),
            "the pty whose terminal cannot go raw",
        );
        assert!(
            ran.ended_well(),
            "the process ended with {}: {}{}",
            ran.status,
            ran.stdout,
            ran.stderr
        );
    }

    /// A process run alone with a terminal of this test's own for its standard input, so a relay in
    /// it has something to put in raw mode and to give back, and its standard output read on a
    /// thread: what the stop and flood tests share.
    struct OnTerminal {
        run: std::process::Child,
        master: libc::c_int,
        slave: libc::c_int,
        before: libc::termios,
        heard: std::sync::mpsc::Receiver<Vec<u8>>,
        seen: Vec<u8>,
    }

    /// How a process run [`OnTerminal`] ended.
    struct Ending {
        ended: bool,
        status: std::process::ExitStatus,
        after: libc::termios,
        errors: String,
    }

    impl OnTerminal {
        fn start(entry: &str) -> Self {
            Self::spawn(entry, false)
        }

        /// [`Self::start`] with the process's standard output on the terminal as well, as a launch
        /// from a terminal has it, and read by no thread: what the process writes waits on the
        /// master for [`Self::read_until`].
        fn start_writing_to_it(entry: &str) -> Self {
            Self::spawn(entry, true)
        }

        fn spawn(entry: &str, writing_to_it: bool) -> Self {
            use std::io::Read as _;
            use std::os::fd::FromRawFd as _;
            let (master, slave) = open_pty_pair(None).expect("a terminal for the process run");
            // SAFETY: all-zero is a valid `termios`, and `tcgetattr` fills it from the slave this
            // test opened before anything reads it.
            let mut before: libc::termios = unsafe { std::mem::zeroed() };
            assert_eq!(unsafe { libc::tcgetattr(slave, &mut before) }, 0);
            // SAFETY: `dup` hands back a fresh descriptor for the slave, owned from here on and
            // given to the process run alone as its standard input.
            let stdin = unsafe { std::os::fd::OwnedFd::from_raw_fd(libc::dup(slave)) };
            let stdout = match writing_to_it {
                // SAFETY: as for `stdin`, a fresh descriptor for the slave, owned from here on.
                true => std::process::Stdio::from(unsafe {
                    std::os::fd::OwnedFd::from_raw_fd(libc::dup(slave))
                }),
                false => std::process::Stdio::piped(),
            };
            let mut run = crate::testutil::alone(entry, "")
                .stdin(std::process::Stdio::from(stdin))
                .stdout(stdout)
                .stderr(std::process::Stdio::piped())
                .spawn()
                .expect("the process run alone starts");
            let (tell, heard) = std::sync::mpsc::channel();
            if let Some(mut out) = run.stdout.take() {
                std::thread::spawn(move || {
                    let mut chunk = [0u8; 4096];
                    while let Ok(n) = out.read(&mut chunk) {
                        if n == 0 || tell.send(chunk[..n].to_vec()).is_err() {
                            break;
                        }
                    }
                });
            }
            OnTerminal {
                run,
                master,
                slave,
                before,
                heard,
                seen: Vec::new(),
            }
        }

        /// How many times `word` is in what the process relayed so far.
        fn count(&mut self, word: &[u8]) -> usize {
            while let Ok(chunk) = self.heard.try_recv() {
                self.seen.extend(chunk);
            }
            self.seen.windows(word.len()).filter(|w| *w == word).count()
        }

        /// Whether `word` has been relayed `times` times in all within `within`.
        fn hear(&mut self, word: &[u8], times: usize, within: Duration) -> bool {
            let deadline = Instant::now() + within;
            while self.count(word) < times {
                let left = deadline.saturating_duration_since(Instant::now());
                match self.heard.recv_timeout(left) {
                    Ok(chunk) => self.seen.extend(chunk),
                    Err(_) => return false,
                }
            }
            true
        }

        /// Send `signal` if there is one, give the process `within` to end, killing it past that,
        /// and say how it ended.
        fn end(&mut self, signal: Option<libc::c_int>, within: Duration) -> Ending {
            // A process [`Self::running`] already reaped has ended, and its pid names nothing left
            // to signal or to open a pidfd on.
            let ended = matches!(self.run.try_wait(), Ok(Some(_))) || {
                if let Some(signal) = signal {
                    // SAFETY: the process this test started, not yet reaped; two integers.
                    unsafe { libc::kill(self.run.id() as libc::pid_t, signal) };
                }
                let pidfd =
                    crate::session::open_pidfd(self.run.id()).expect("a pidfd for the process");
                let ended = crate::session::wait_for_exit(pidfd, within);
                crate::session::close_fd(pidfd);
                ended
            };
            if !ended {
                let _ = self.run.kill();
            }
            let status = self.run.wait().expect("the process run alone is reaped");
            // SAFETY: as for `before`, on the same slave, which this test still holds.
            let mut after: libc::termios = unsafe { std::mem::zeroed() };
            assert_eq!(unsafe { libc::tcgetattr(self.slave, &mut after) }, 0);
            let errors = self
                .run
                .stderr
                .take()
                .map(crate::testutil::queued)
                .unwrap_or_default();
            Ending {
                ended,
                status,
                after,
                errors,
            }
        }

        /// Whether the terminal's settings after are the ones from before the process ran.
        fn given_back(&self, ending: &Ending) -> bool {
            self.as_before(&ending.after)
        }

        /// Whether `settings` are the terminal's from before the process ran.
        fn as_before(&self, settings: &libc::termios) -> bool {
            let (a, b) = (settings, &self.before);
            (a.c_iflag, a.c_oflag, a.c_cflag, a.c_lflag)
                == (b.c_iflag, b.c_oflag, b.c_cflag, b.c_lflag)
        }

        /// Whether the terminal has its settings from before the process ran, now, while the
        /// process may still run.
        fn given_back_now(&self) -> bool {
            // SAFETY: as for `before`, on the same slave, which this test still holds.
            let mut now: libc::termios = unsafe { std::mem::zeroed() };
            assert_eq!(unsafe { libc::tcgetattr(self.slave, &mut now) }, 0);
            self.as_before(&now)
        }

        /// Read what the process wrote to the terminal ([`Self::start_writing_to_it`]) until `word`
        /// is in it or `within` passes, and say whether it was.
        fn read_until(&mut self, word: &[u8], within: Duration) -> bool {
            let deadline = Instant::now() + within;
            let mut chunk = [0u8; 4096];
            while !self.seen.windows(word.len()).any(|w| w == word) {
                let left = deadline.saturating_duration_since(Instant::now());
                if left.is_zero() {
                    return false;
                }
                let mut ready = libc::pollfd {
                    fd: self.master,
                    events: libc::POLLIN,
                    revents: 0,
                };
                let millis = libc::c_int::try_from(left.as_millis()).unwrap_or(libc::c_int::MAX);
                // SAFETY: one live `pollfd` on the master this test holds, with its count.
                if unsafe { libc::poll(&mut ready, 1, millis) } <= 0 {
                    continue;
                }
                // SAFETY: the master this test holds, read into a live stack array bounded by its
                // own length.
                let n = unsafe { libc::read(self.master, chunk.as_mut_ptr().cast(), chunk.len()) };
                if n > 0 {
                    self.seen.extend_from_slice(&chunk[..n as usize]);
                }
            }
            true
        }

        /// How many bytes the process wrote to the terminal that wait on the master unread.
        fn unread(&self) -> libc::c_int {
            let mut queued: libc::c_int = 0;
            // SAFETY: `FIONREAD` writes one `c_int` into what is passed, on the master this test
            // holds.
            unsafe { libc::ioctl(self.master, libc::FIONREAD, &mut queued) };
            queued
        }

        /// Whether the process still runs.
        fn running(&mut self) -> bool {
            matches!(self.run.try_wait(), Ok(None))
        }

        /// Type `bytes` of `fill` on the terminal from a thread, without ever blocking, until all
        /// are written or `within` passes; the thread hands back how many went in.
        fn flood(
            &self,
            fill: u8,
            bytes: usize,
            within: Duration,
        ) -> std::thread::JoinHandle<usize> {
            // SAFETY: `dup` gives the thread a descriptor of its own for the master, closed there.
            let fd = unsafe { libc::dup(self.master) };
            // SAFETY: `fcntl` sets non-blocking on the open file both descriptors share, which only
            // this test writes.
            unsafe {
                libc::fcntl(
                    fd,
                    libc::F_SETFL,
                    libc::fcntl(fd, libc::F_GETFL) | libc::O_NONBLOCK,
                )
            };
            std::thread::spawn(move || {
                let deadline = Instant::now() + within;
                let chunk = vec![fill; 4096];
                let mut written = 0;
                while written < bytes && Instant::now() < deadline {
                    // SAFETY: `fd` is this thread's own descriptor, and the pointer and length are
                    // those of the live `chunk`, cut to what is left to type.
                    let left = chunk.len().min(bytes - written);
                    let n = unsafe { libc::write(fd, chunk.as_ptr().cast(), left) };
                    if n > 0 {
                        written += n as usize;
                    } else {
                        std::thread::sleep(Duration::from_millis(5));
                    }
                }
                // SAFETY: the descriptor `dup` gave this thread; its only close.
                unsafe { libc::close(fd) };
                written
            })
        }
    }

    impl Drop for OnTerminal {
        fn drop(&mut self) {
            let _ = self.run.kill();
            let _ = self.run.wait();
            // SAFETY: the pair this test opened, closed once and used nowhere else.
            unsafe {
                libc::close(self.slave);
                libc::close(self.master);
            }
        }
    }

    /// The child the flood tests relay: it takes the pty as its terminal, in raw mode so what is
    /// typed is not dropped at a line's end but waits, never reads it, and says `tick` every tenth
    /// of a second for at most twenty seconds.
    fn ticks_and_reads_nothing(slave: libc::c_int) -> std::convert::Infallible {
        // SAFETY: `login_tty`, `tcgetattr`, `cfmakeraw`, `tcsetattr`, `write`, `usleep` and `_exit`
        // are async-signal-safe or pure, on a local `termios` and constant bytes; nothing here
        // allocates.
        unsafe {
            if libc::login_tty(slave) == 0 {
                let mut raw: libc::termios = std::mem::zeroed();
                if libc::tcgetattr(0, &mut raw) == 0 {
                    libc::cfmakeraw(&mut raw);
                    libc::tcsetattr(0, libc::TCSANOW, &raw);
                }
                let tick = b"tick\n";
                for _ in 0..200 {
                    libc::write(1, tick.as_ptr().cast(), tick.len());
                    libc::usleep(100_000);
                }
            }
            libc::_exit(0)
        }
    }

    /// A stop that arrives while the relay runs gives the terminal back before the process ends,
    /// and the process still ends as the signal asked.
    #[test]
    fn a_stop_while_the_relay_runs_gives_the_terminal_back() {
        use std::os::unix::process::ExitStatusExt as _;
        let mut term = OnTerminal::start(concat!(module_path!(), "::a_relay_told_to_stop"));
        // The child behind the relay says it runs through the pty, so the relay is pumping, its
        // handler installed, by the time this hears the word.
        let ran = term.hear(b"ready", 1, Duration::from_secs(10));
        let ending = term.end(ran.then_some(libc::SIGTERM), Duration::from_secs(10));
        let errors = &ending.errors;
        assert!(ran, "the relay never ran: {errors}");
        assert!(
            ending.ended,
            "the process did not end on the stop: {errors}"
        );
        assert_eq!(
            ending.status.signal(),
            Some(libc::SIGTERM),
            "it ends as the signal asked, not by returning: {} {errors}",
            ending.status
        );
        assert!(
            term.given_back(&ending),
            "the terminal is given back as it was: {errors}"
        );
    }

    /// A stop gives the terminal back while the relay is parked writing to it, behind output nobody
    /// reads: the stop's escalation to `SIGKILL` then finds the terminal as it was. A resize in the
    /// same wait leaves it raw, since the session goes on.
    ///
    /// The relay writes to the terminal itself, as from a launch on one, and this test stops
    /// reading it once the child's output has started. The output waiting unread stops growing once
    /// the terminal's read buffer is full, and the relay's write then sleeps, but not always at the
    /// terminal's limit: room can open behind a sleeping write without waking it, and any change to
    /// the terminal's settings wakes it, which the stop's own give-back is. A write so woken
    /// finishes, and the relay then ends on the stop at its poll. So the test wakes the write once
    /// before the stop, with settings that change nothing, and lets it fill what room it slept
    /// beside. The relay is still parked when the process outlives the stop: a relay at its poll
    /// ends on a stop at once. The stop lands on whichever thread of that process takes it.
    #[test]
    fn a_stop_gives_the_terminal_back_while_the_relay_is_parked_writing_to_it() {
        let mut term = OnTerminal::start_writing_to_it(concat!(
            module_path!(),
            "::a_relay_under_a_child_that_floods"
        ));
        let pid = term.run.id() as libc::pid_t;
        let ran = term.read_until(b"tick", Duration::from_secs(10));
        let mut stalled = false;
        let deadline = Instant::now() + Duration::from_secs(10);
        while ran && !stalled && Instant::now() < deadline {
            let before = term.unread();
            std::thread::sleep(Duration::from_millis(300));
            stalled = before > 0 && term.unread() == before;
        }
        // SAFETY: all-zero is a valid `termios`, filled from the slave this test holds and set back
        // on it unchanged: a change of nothing, which still wakes a write asleep on it.
        let mut now: libc::termios = unsafe { std::mem::zeroed() };
        assert_eq!(unsafe { libc::tcgetattr(term.slave, &mut now) }, 0);
        assert_eq!(
            unsafe { libc::tcsetattr(term.slave, libc::TCSANOW, &now) },
            0
        );
        std::thread::sleep(Duration::from_millis(300));
        let raw = !term.given_back_now();
        // SAFETY: the process this test started, not yet reaped; two integers.
        unsafe { libc::kill(pid, libc::SIGWINCH) };
        std::thread::sleep(Duration::from_millis(300));
        let raw_after_resize = !term.given_back_now();
        // SAFETY: as above.
        unsafe { libc::kill(pid, libc::SIGTERM) };
        let deadline = Instant::now() + Duration::from_secs(5);
        while !term.given_back_now() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(20));
        }
        let given_back = term.given_back_now();
        std::thread::sleep(Duration::from_millis(500));
        let still_parked = term.running();
        let ending = term.end(Some(libc::SIGKILL), Duration::from_secs(5));
        let errors = &ending.errors;
        assert!(ran, "the relay never ran: {errors}");
        assert!(stalled, "the relay's output never stalled: {errors}");
        assert!(
            raw,
            "the relay never put the terminal in raw mode: {errors}"
        );
        assert!(
            raw_after_resize,
            "a resize gave the terminal back: {errors}"
        );
        assert!(
            given_back,
            "the stop left the terminal raw while the relay was parked: {errors}"
        );
        assert!(
            still_parked,
            "the process ended on the stop ({}), so the relay was not parked: {errors}",
            ending.status
        );
        assert!(
            term.given_back(&ending),
            "the terminal is not as it was once the escalation ended the process: {errors}"
        );
    }

    /// The relay run by [`a_stop_gives_the_terminal_back_while_the_relay_is_parked_writing_to_it`];
    /// anywhere else it does nothing. Only the escalation ends it.
    #[test]
    #[ignore = "run alone by the test that stops it, writing to a terminal of that test's own"]
    fn a_relay_under_a_child_that_floods() {
        crate::testutil::when_run_alone(|_| {
            // SAFETY: the child honours the async-signal-safe contract and never returns.
            let result = unsafe { fork_with_pty(false, floods_and_reads_nothing) };
            Err(io::Error::other(format!(
                "the relay returned instead of being ended: {result:?}"
            )))
        });
    }

    /// The child the parked-relay test relays: it takes the pty as its terminal, says `tick`, then
    /// writes without pause for at most thirty seconds, and never reads. A write that fails ends
    /// it.
    fn floods_and_reads_nothing(slave: libc::c_int) -> std::convert::Infallible {
        // SAFETY: `login_tty`, `write`, `time` and `_exit` are async-signal-safe, on constant bytes
        // and a stack array; nothing here allocates.
        unsafe {
            if libc::login_tty(slave) == 0 {
                let tick = b"tick\n";
                libc::write(1, tick.as_ptr().cast(), tick.len());
                let fill = [b'x'; 4096];
                let until = libc::time(std::ptr::null_mut()) + 30;
                while libc::time(std::ptr::null_mut()) < until {
                    if libc::write(1, fill.as_ptr().cast(), fill.len()) < 0 {
                        break;
                    }
                }
            }
            libc::_exit(0)
        }
    }

    /// A child that stopped reading its input stalls none of its output and no stop, however much
    /// is typed: the relay holds what the child has not taken, stops reading the terminal once that
    /// is full, and goes on relaying. The flood goes past what the relay holds, so a relay that
    /// wrote to the child until it took everything would stall here.
    #[test]
    fn a_child_that_reads_nothing_stalls_neither_its_output_nor_a_stop() {
        use std::os::unix::process::ExitStatusExt as _;
        let mut term = OnTerminal::start(concat!(
            module_path!(),
            "::a_relay_under_a_child_that_reads_nothing"
        ));
        let ran = term.hear(b"tick", 1, Duration::from_secs(10));
        let flood = term.flood(b'a', 1 << 20, Duration::from_secs(2));
        let typed = flood.join().expect("the flood");
        let ticks = term.count(b"tick");
        let relaying = term.hear(b"tick", ticks + 5, Duration::from_secs(3));
        let ending = term.end(Some(libc::SIGTERM), Duration::from_secs(10));
        let errors = &ending.errors;
        assert!(ran, "the relay never ran: {errors}");
        assert!(
            typed >= PENDING_INPUT_MAX,
            "the flood fills what the relay holds: {typed} bytes typed"
        );
        assert!(
            relaying,
            "the child's output stops once it is flooded: {errors}"
        );
        assert!(
            ending.ended,
            "a stop does not end a flooded relay: {errors}"
        );
        assert_eq!(ending.status.signal(), Some(libc::SIGTERM), "{errors}");
        assert!(
            term.given_back(&ending),
            "the terminal is given back: {errors}"
        );
    }

    /// In a graphical cage, which never reads its input, the terminal is read whatever the flood, so
    /// a double Ctrl+C typed after it still force-quits; what does not fit is dropped, and said.
    #[test]
    fn a_graphical_child_that_reads_nothing_can_still_be_force_quit() {
        let mut term = OnTerminal::start(concat!(
            module_path!(),
            "::a_graphical_relay_under_a_child_that_reads_nothing"
        ));
        let ran = term.hear(b"tick", 1, Duration::from_secs(10));
        let typed = term
            .flood(b'a', 4 * PENDING_INPUT_MAX, Duration::from_secs(4))
            .join()
            .expect("the flood");
        // The flood leaves the master non-blocking, and a relay still draining it leaves no room
        // for a moment: the two keys go in as the flood's did, well inside the force-quit window.
        let sent = term
            .flood(0x03, 2, Duration::from_secs(1))
            .join()
            .expect("the double Ctrl+C");
        let ending = term.end(None, Duration::from_secs(10));
        let errors = &ending.errors;
        assert!(ran, "the relay never ran: {errors}");
        assert!(
            typed >= 4 * PENDING_INPUT_MAX,
            "a graphical relay reads the whole flood: {typed} bytes typed"
        );
        assert_eq!(sent, 2, "the double Ctrl+C was not typed: {errors}");
        assert!(ending.ended, "the double Ctrl+C was not seen: {errors}");
        assert!(errors.contains("force-quitting"), "{errors}");
        assert!(errors.contains("what does not fit is dropped"), "{errors}");
    }

    /// The relay ends on the child's exit, not on the last copy of the slave closing, and passes on
    /// what the child wrote before it exited. Run alone, in a process whose stdin is `/dev/null`,
    /// so the relay reads no terminal and its standard output is this test's to read.
    #[test]
    fn the_relay_ends_when_the_child_exits_though_something_it_left_holds_the_terminal() {
        let started = Instant::now();
        let ran = crate::testutil::run_within(
            crate::testutil::alone(
                concat!(
                    module_path!(),
                    "::a_relay_whose_child_leaves_a_holder_behind"
                ),
                "",
            )
            .stdin(std::process::Stdio::null()),
            "the relay whose child leaves a holder behind",
        );
        assert!(
            ran.ended_well(),
            "the process ended with {}: {}{}",
            ran.status,
            ran.stdout,
            ran.stderr
        );
        assert!(
            ran.stdout.contains("written before the exit"),
            "what the child wrote before it exited must reach the terminal: {}",
            ran.stdout
        );
        assert!(
            started.elapsed() < Duration::from_secs(8),
            "the relay waited for the holder ({:?})",
            started.elapsed()
        );
    }

    /// The relay run by
    /// [`the_relay_ends_when_the_child_exits_though_something_it_left_holds_the_terminal`];
    /// anywhere else it does nothing. The child leaves a grandchild holding the slave for ten
    /// seconds, writes a line and exits with 3; the relay must answer 3 well before the grandchild
    /// lets the slave go.
    #[test]
    #[ignore = "run alone by the test that reads how it ended, with stdin off any terminal"]
    fn a_relay_whose_child_leaves_a_holder_behind() {
        crate::testutil::when_run_alone(|_| {
            let mut pair = [-1 as libc::c_int; 2];
            // SAFETY: `openpty` fills the two out-params; the name, termios and size are null.
            assert_eq!(
                unsafe {
                    libc::openpty(
                        &mut pair[0],
                        &mut pair[1],
                        std::ptr::null_mut(),
                        std::ptr::null(),
                        std::ptr::null(),
                    )
                },
                0
            );
            let (master, slave) = (pair[0], pair[1]);
            let mut ends = [0 as libc::c_int; 2];
            // SAFETY: `pipe2` fills the two-element array it is handed.
            assert_eq!(
                unsafe { libc::pipe2(ends.as_mut_ptr(), libc::O_CLOEXEC) },
                0
            );
            let (read_fd, write_fd) = (ends[0], ends[1]);
            // SAFETY: the child runs only `close`, `fork`, `getpid`, `write`, `sleep` and `_exit`,
            // all async-signal-safe, on descriptors and local arrays prepared before the fork.
            let child = unsafe { libc::fork() };
            assert!(child >= 0, "fork failed");
            if child == 0 {
                unsafe {
                    libc::close(master);
                    if libc::fork() == 0 {
                        let pid = libc::getpid().to_ne_bytes();
                        libc::write(write_fd, pid.as_ptr().cast(), pid.len());
                        libc::sleep(10);
                        libc::_exit(0);
                    }
                    let line = b"written before the exit\n";
                    libc::write(slave, line.as_ptr().cast(), line.len());
                    libc::_exit(3);
                }
            }
            // SAFETY: this side's copies of the slave and of the pipe's write end, used nowhere
            // else, so the holder's are the only ones left.
            unsafe {
                libc::close(slave);
                libc::close(write_fd);
            }
            let started = Instant::now();
            let code = pump(master, child, -1, false);
            let took = started.elapsed();
            let mut pid = [0u8; 4];
            // SAFETY: `read_fd` is this test's own pipe end and `pid` a local buffer of its length.
            let got = unsafe { libc::read(read_fd, pid.as_mut_ptr().cast(), pid.len()) };
            if got == 4 {
                // SAFETY: the holder this test's child forked; `kill` takes two integers. It is
                // not this process's child, so its reaping is left to whoever adopted it.
                unsafe { libc::kill(libc::pid_t::from_ne_bytes(pid), libc::SIGKILL) };
            }
            // SAFETY: closes this test's own pipe end and the master it opened.
            unsafe {
                libc::close(read_fd);
                libc::close(master);
            }
            assert_eq!(got, 4, "the holder was started");
            assert_eq!(
                code.ok(),
                Some(Ended::Exited(3)),
                "the child's own exit code"
            );
            assert!(
                took < Duration::from_secs(5),
                "the relay ended only after {took:?}, with the holder gone rather than the child"
            );
            Ok(())
        });
    }

    /// A relay that fails under a running child stops and reaps it rather than leave it behind.
    /// Run alone, so the standard output the relay loses is this test process's own.
    #[test]
    fn a_relay_that_loses_its_output_stops_and_reaps_the_child() {
        let ran = crate::testutil::run_within(
            crate::testutil::alone(
                concat!(module_path!(), "::a_relay_whose_output_is_gone"),
                "",
            )
            .stdin(std::process::Stdio::null()),
            "the relay whose output is gone",
        );
        assert!(
            ran.ended_well(),
            "the process ended with {}: {}{}",
            ran.status,
            ran.stdout,
            ran.stderr
        );
    }

    /// The relay run by [`a_relay_that_loses_its_output_stops_and_reaps_the_child`]; anywhere
    /// else it does nothing. Its standard output is a pipe nobody reads, so the first line the
    /// child writes fails to reach it, while the child waits on.
    #[test]
    #[ignore = "run alone by the test that reads how it ended, with stdin off any terminal"]
    fn a_relay_whose_output_is_gone() {
        crate::testutil::when_run_alone(|_| {
            let mut pair = [-1 as libc::c_int; 2];
            let mut ends = [0 as libc::c_int; 2];
            // SAFETY: `openpty` fills the two out-params, its name, termios and size null; `pipe2`
            // fills the array it is handed; `dup` takes and returns a descriptor.
            let saved = unsafe {
                assert_eq!(
                    libc::openpty(
                        &mut pair[0],
                        &mut pair[1],
                        std::ptr::null_mut(),
                        std::ptr::null(),
                        std::ptr::null(),
                    ),
                    0
                );
                assert_eq!(libc::pipe2(ends.as_mut_ptr(), libc::O_CLOEXEC), 0);
                libc::dup(1)
            };
            let (master, slave) = (pair[0], pair[1]);
            // SAFETY: the child runs only `close`, `write`, `sleep` and `_exit`, all
            // async-signal-safe, on descriptors and a local array prepared before the fork.
            let child = unsafe { libc::fork() };
            assert!(child >= 0, "fork failed");
            if child == 0 {
                unsafe {
                    // Both ends of the pipe go: a read end left open here would take every write
                    // the relay makes, and nothing would fail.
                    libc::close(ends[0]);
                    libc::close(ends[1]);
                    libc::close(master);
                    let line = b"a line nobody will read\n";
                    libc::write(slave, line.as_ptr().cast(), line.len());
                    // Bounded, and past the harness's own limit: when a relay never stops it, the
                    // harness ends this process and not its fork, which would otherwise wait on
                    // for good.
                    libc::sleep(60);
                    libc::_exit(0);
                }
            }
            // SAFETY: this side's copy of the slave, and the pipe: its read end closed so a write
            // to the other fails, and its write end put on the standard output for the relay.
            unsafe {
                libc::close(slave);
                libc::close(ends[0]);
                libc::dup2(ends[1], 1);
                libc::close(ends[1]);
            }
            let relayed = pump(master, child, -1, false);
            // SAFETY: puts the standard output back for the harness's own last line, and closes
            // the copy and the master this test opened.
            unsafe {
                libc::dup2(saved, 1);
                libc::close(saved);
                libc::close(master);
            }
            // SAFETY: `kill` with signal 0 only asks whether `child` names a process.
            let alive = unsafe { libc::kill(child, 0) } == 0;
            if alive {
                // SAFETY: the child this test forked, still there; stopped and reaped so the test
                // leaves nothing behind whatever it asserts.
                unsafe {
                    libc::kill(child, libc::SIGKILL);
                    libc::waitpid(child, std::ptr::null_mut(), 0);
                }
            }
            assert!(relayed.is_err(), "a relay that lost its output says so");
            assert!(
                !alive,
                "the child must be stopped and reaped, not left running or a zombie"
            );
            Ok(())
        });
    }

    /// The relay run by [`a_child_that_reads_nothing_stalls_neither_its_output_nor_a_stop`];
    /// anywhere else it does nothing. Only the stop ends it.
    #[test]
    #[ignore = "run alone by the test that floods it, on a terminal of that test's own"]
    fn a_relay_under_a_child_that_reads_nothing() {
        crate::testutil::when_run_alone(|_| {
            // SAFETY: the child honours the async-signal-safe contract and never returns.
            let result = unsafe { fork_with_pty(false, ticks_and_reads_nothing) };
            Err(io::Error::other(format!(
                "the relay returned instead of ending as the stop asked: {result:?}"
            )))
        });
    }

    /// The relay run by [`a_graphical_child_that_reads_nothing_can_still_be_force_quit`]; anywhere
    /// else it does nothing. The double Ctrl+C ends it with the child's code.
    #[test]
    #[ignore = "run alone by the test that floods it, on a terminal of that test's own"]
    fn a_graphical_relay_under_a_child_that_reads_nothing() {
        crate::testutil::when_run_alone(|_| {
            // SAFETY: the child honours the async-signal-safe contract and never returns.
            match unsafe { fork_with_pty(true, ticks_and_reads_nothing) } {
                Ok(_) => Ok(()),
                Err(e) => Err(io::Error::other(format!("the relay failed: {e:?}"))),
            }
        });
    }

    /// The relay run by [`a_stop_while_the_relay_runs_gives_the_terminal_back`]; anywhere else it
    /// does nothing. The child takes the pty as its terminal, says it runs, and waits; the stop
    /// arrives while the relay pumps, and a relay that returned instead of ending says so.
    #[test]
    #[ignore = "run alone by the test that stops it, on a terminal of that test's own"]
    fn a_relay_told_to_stop() {
        crate::testutil::when_run_alone(|_| {
            let child = move |slave: libc::c_int| -> std::convert::Infallible {
                // SAFETY: `login_tty`, `write`, `sleep` and `_exit` are async-signal-safe, and the
                // bytes are a constant; nothing here allocates.
                unsafe {
                    if libc::login_tty(slave) == 0 {
                        let ready = b"ready\n";
                        libc::write(1, ready.as_ptr().cast(), ready.len());
                        // Bounded: the hangup when the relay's master closes ends it first.
                        libc::sleep(20);
                    }
                    libc::_exit(0)
                }
            };
            // SAFETY: the child above honours the async-signal-safe contract and never returns.
            let result = unsafe { fork_with_pty(false, child) };
            Err(io::Error::other(format!(
                "the relay returned instead of ending as the stop asked: {result:?}"
            )))
        });
    }

    /// The pty run by [`a_terminal_that_cannot_go_raw_stops_and_reaps_the_started_child`];
    /// anywhere else it does nothing. The child writes its pid and waits; SIGTERM is blocked in it
    /// (inherited from this thread's mask), so the pid is always written before the escalation to
    /// SIGKILL ends it.
    #[test]
    #[ignore = "run alone by the test that reads how it ended, with stdin off any terminal"]
    fn a_pty_whose_terminal_cannot_go_raw() {
        crate::testutil::when_run_alone(|_| {
            let mut ends = [0 as libc::c_int; 2];
            // SAFETY: `pipe2` fills the two-element array it is handed.
            assert_eq!(
                unsafe { libc::pipe2(ends.as_mut_ptr(), libc::O_CLOEXEC) },
                0
            );
            let (read_fd, write_fd) = (ends[0], ends[1]);
            // SAFETY: both are plain `sigset_t` operations on a local set, and `pthread_sigmask`
            // changes this thread's mask only, restored below.
            let previous = unsafe {
                let mut set: libc::sigset_t = std::mem::zeroed();
                let mut previous: libc::sigset_t = std::mem::zeroed();
                libc::sigemptyset(&mut set);
                libc::sigaddset(&mut set, libc::SIGTERM);
                libc::pthread_sigmask(libc::SIG_BLOCK, &set, &mut previous);
                previous
            };
            let child = move |_slave: libc::c_int| -> std::convert::Infallible {
                // SAFETY: `getpid`, `write`, `sleep` and `_exit` are async-signal-safe, and the
                // bytes are a local array; nothing here allocates.
                unsafe {
                    let pid = libc::getpid().to_ne_bytes();
                    libc::write(write_fd, pid.as_ptr().cast(), pid.len());
                    // Bounded, and past the harness's own limit: when nothing stops it, the
                    // harness ends this process and not its fork, which would otherwise wait on
                    // for good.
                    libc::sleep(60);
                    libc::_exit(0)
                }
            };
            // SAFETY: the child above honours the async-signal-safe contract and never returns.
            let result = unsafe { fork_with_pty(false, child) };
            // SAFETY: restores the mask saved above, on this same thread; then closes this side's
            // write end, so the read below ends once the child's copy is gone.
            unsafe {
                libc::pthread_sigmask(libc::SIG_SETMASK, &previous, std::ptr::null_mut());
                libc::close(write_fd);
            }
            let mut pid = [0u8; 4];
            // SAFETY: `read_fd` is this test's own pipe end and `pid` a local buffer of its length.
            let got = unsafe { libc::read(read_fd, pid.as_mut_ptr().cast(), pid.len()) };
            let pid = libc::pid_t::from_ne_bytes(pid);
            assert_eq!(got, 4, "the child wrote its pid before it was stopped");
            // SAFETY: `kill` with signal 0 only asks whether `pid` names a process.
            let alive = unsafe { libc::kill(pid, 0) } == 0;
            if alive {
                // SAFETY: the child this test forked, still there; stopped and reaped so the test
                // leaves nothing behind whatever it asserts.
                unsafe {
                    libc::kill(pid, libc::SIGKILL);
                    libc::waitpid(pid, std::ptr::null_mut(), 0);
                }
            }
            // SAFETY: closes this test's own read end.
            unsafe { libc::close(read_fd) };
            assert!(
                matches!(result, Err(PtyFailure::AfterFork(_))),
                "a failure after the fork says so: {result:?}"
            );
            assert!(
                !alive,
                "the child must be stopped and reaped, not left running or a zombie"
            );
            Ok(())
        });
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
    fn relay_handler_leaves_errno_to_the_interrupted_call() {
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

        let previous = SIGNAL_WRITE_FD.swap(write_fd, Ordering::Relaxed);
        // What a failing pty syscall left behind for the line that is about to read it.
        unsafe { *libc::__errno_location() = libc::EIO };
        relay_handler(libc::SIGWINCH);
        let after_failed_write = unsafe { *libc::__errno_location() };

        // And the nudge itself still happens when the pipe has room: the guard must not have
        // become "do nothing".
        let mut sink = [0u8; 64];
        while unsafe { libc::read(read_fd, sink.as_mut_ptr().cast(), sink.len()) } > 0 {}
        relay_handler(libc::SIGWINCH);
        let mut one = [0u8; 8];
        let nudged = unsafe { libc::read(read_fd, one.as_mut_ptr().cast(), one.len()) };

        SIGNAL_WRITE_FD.store(previous, Ordering::Relaxed);
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

    /// A child reaped elsewhere has an exit no one can read, and it is not reported as a success.
    /// The relay's wait failed on it and left the status word at zero, which read as a clean exit.
    #[test]
    fn a_child_whose_status_cannot_be_read_is_not_reported_as_a_success() {
        let mut pair = [-1 as libc::c_int; 2];
        // SAFETY: `openpty` fills the two out-params; the name, termios and size are null.
        assert_eq!(
            unsafe {
                libc::openpty(
                    &mut pair[0],
                    &mut pair[1],
                    std::ptr::null_mut(),
                    std::ptr::null(),
                    std::ptr::null(),
                )
            },
            0
        );
        let (master, slave) = (pair[0], pair[1]);
        // SAFETY: the child calls `_exit` only.
        let child = unsafe { libc::fork() };
        assert!(child >= 0, "fork failed");
        if child == 0 {
            unsafe { libc::_exit(0) };
        }
        // SAFETY: this side's copy of the slave, and the child, reaped here so the relay's own
        // wait finds nothing; the master closed once the relay is done with it.
        let code = unsafe {
            libc::close(slave);
            libc::waitpid(child, std::ptr::null_mut(), 0);
            let code = pump(master, child, -1, false);
            libc::close(master);
            code
        };
        assert_eq!(code.ok(), Some(Ended::Exited(1)));
    }

    /// A descriptor another program left non-blocking is waited on, not given up on: a full pipe
    /// in non-blocking mode answers `EAGAIN`, and the write goes through once the reader drains it.
    #[test]
    fn a_write_to_a_non_blocking_descriptor_waits_until_it_takes_more() {
        let mut ends = [0 as libc::c_int; 2];
        // SAFETY: `pipe2` fills the two-element array it is handed.
        assert_eq!(
            unsafe { libc::pipe2(ends.as_mut_ptr(), libc::O_CLOEXEC | libc::O_NONBLOCK) },
            0
        );
        let (read_fd, write_fd) = (ends[0], ends[1]);
        let chunk = [b'x'; 4096];
        // SAFETY: `write_fd` is this test's own pipe end and `chunk` a local array.
        while unsafe { libc::write(write_fd, chunk.as_ptr().cast(), chunk.len()) } > 0 {}
        let reader = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(100));
            let mut sink = [0u8; 4096];
            let mut total = 0usize;
            loop {
                // SAFETY: `read_fd` is this test's own pipe end, closed only after this loop, and
                // `sink` a local array of the length passed.
                let n = unsafe { libc::read(read_fd, sink.as_mut_ptr().cast(), sink.len()) };
                if n > 0 {
                    total += n as usize;
                } else if n == 0 {
                    break;
                } else {
                    std::thread::sleep(Duration::from_millis(5));
                }
            }
            // SAFETY: this thread's pipe end, used nowhere else.
            unsafe { libc::close(read_fd) };
            total
        });
        let written = write_all(write_fd, &[b'y'; 65536]);
        // SAFETY: this side's pipe end; closing it ends the reader's loop.
        unsafe { libc::close(write_fd) };
        let total = reader.join().expect("the reader");
        assert!(written.is_ok(), "the write gave up: {written:?}");
        assert!(total >= 65536, "the reader got {total} bytes");
    }

    /// Both ends of the pty are close-on-exec as they are opened, and they are one terminal: what
    /// the slave writes, the master reads.
    #[test]
    fn the_pty_pair_is_close_on_exec_from_its_opening() {
        let (master, slave) = open_pty_pair(None).expect("a pty pair");
        // SAFETY: `F_GETFD` takes no argument and reads the descriptor's flags.
        let flags = |fd| unsafe { libc::fcntl(fd, libc::F_GETFD) };
        let line = b"ping\n";
        let mut read = [0u8; 16];
        // SAFETY: the pair just opened, and local buffers of the lengths passed.
        let got = unsafe {
            libc::write(slave, line.as_ptr().cast(), line.len());
            libc::read(master, read.as_mut_ptr().cast(), read.len())
        };
        let (master_flags, slave_flags) = (flags(master), flags(slave));
        // SAFETY: the pair this test opened, used nowhere else.
        unsafe {
            libc::close(slave);
            libc::close(master);
        }
        assert_ne!(
            master_flags & libc::FD_CLOEXEC,
            0,
            "the master is close-on-exec"
        );
        assert_ne!(
            slave_flags & libc::FD_CLOEXEC,
            0,
            "the slave is close-on-exec"
        );
        assert!(got > 0, "the master reads what the slave wrote");
        assert!(
            read.starts_with(b"ping"),
            "{:?}",
            &read[..got.max(0) as usize]
        );
    }

    #[test]
    fn exit_code_maps_clean_and_signalled_children() {
        // waitpid encodes a clean exit in the high byte; code 7 -> 7.
        assert_eq!(exit_code(7 << 8), 7);
        // A signalled child is 128 + signo — the SIGKILL the force-quit escalates to.
        assert_eq!(exit_code(libc::SIGKILL), 128 + libc::SIGKILL);
    }
}
