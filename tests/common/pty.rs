//! A pseudo-terminal for the suites that drive an interactive launch through its master end.
//!
//! Both ends are close-on-exec. `openpty` opens them without the flag, and the suites run their
//! tests side by side: a launch another test spawned while they were open would carry a copy of
//! the slave through its exec, and a master whose slave some other process still holds never
//! reports the session's end. A read that waits for that end then waits out its whole deadline.

use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::process::{Child, Stdio};
use std::time::Instant;

/// A pseudo-terminal: the master this process drives, and the slave a launch is handed until
/// [`Pty::release_slave`].
pub struct Pty {
    master: OwnedFd,
    slave: Option<OwnedFd>,
}

impl Pty {
    /// Open a terminal, sized `rows` by `cols` when a size is given.
    pub fn open(size: Option<(u16, u16)>) -> Self {
        let ws = size.map(|(rows, cols)| libc::winsize {
            ws_row: rows,
            ws_col: cols,
            ws_xpixel: 0,
            ws_ypixel: 0,
        });
        let mut master: libc::c_int = -1;
        let mut slave: libc::c_int = -1;
        // SAFETY: `openpty` fills the two descriptors it is handed, and reads no name, no settings,
        // and the size only where one is given.
        let rc = unsafe {
            libc::openpty(
                &mut master,
                &mut slave,
                std::ptr::null_mut(),
                std::ptr::null(),
                ws.as_ref().map_or(std::ptr::null(), |ws| ws),
            )
        };
        assert_eq!(rc, 0, "openpty: {}", std::io::Error::last_os_error());
        // SAFETY: both were just opened here, and each is owned once.
        let (master, slave) =
            unsafe { (OwnedFd::from_raw_fd(master), OwnedFd::from_raw_fd(slave)) };
        for fd in [&master, &slave] {
            // SAFETY: `fcntl` on a descriptor this process holds, with an integer argument.
            let set = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_SETFD, libc::FD_CLOEXEC) };
            assert_ne!(
                set,
                -1,
                "close-on-exec: {}",
                std::io::Error::last_os_error()
            );
        }
        Pty {
            master,
            slave: Some(slave),
        }
    }

    /// A close-on-exec copy of the slave, for one of a launch's standard streams. The spawn moves
    /// it onto 0, 1 or 2, which clears the flag for the child alone.
    pub fn stdio(&self) -> Stdio {
        let slave = self.slave.as_ref().expect("the slave is still held");
        Stdio::from(
            slave
                .try_clone()
                .unwrap_or_else(|e| panic!("copying the terminal: {e}")),
        )
    }

    /// Close this process's own copy of the slave, once the launch holds its copies: the session
    /// ends when the last copy closes, and this one would otherwise outlive it.
    pub fn release_slave(&mut self) {
        self.slave = None;
    }

    /// The master's descriptor, for a caller that polls it itself.
    pub fn master(&self) -> libc::c_int {
        self.master.as_raw_fd()
    }

    /// Write all of `bytes` to the master, as typed input.
    pub fn send(&self, bytes: &[u8]) {
        let mut rest = bytes;
        while !rest.is_empty() {
            // SAFETY: a write of the given length from a live buffer.
            let n = unsafe { libc::write(self.master(), rest.as_ptr().cast(), rest.len()) };
            if n < 0 {
                let e = std::io::Error::last_os_error();
                assert_eq!(
                    e.kind(),
                    std::io::ErrorKind::Interrupted,
                    "typing into the terminal: {e}"
                );
                continue;
            }
            rest = &rest[n as usize..];
        }
    }

    /// Wait up to `wait_ms` for output and append what arrives to `out`. `false` once the session
    /// is over: every copy of the slave closed, which Linux reports as an end of file or `EIO`.
    pub fn read_into(&self, out: &mut Vec<u8>, wait_ms: libc::c_int) -> bool {
        let mut pfd = libc::pollfd {
            fd: self.master(),
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: one `pollfd` this frame owns.
        let ready = unsafe { libc::poll(&mut pfd, 1, wait_ms) };
        if ready < 0 {
            let e = std::io::Error::last_os_error();
            assert_eq!(
                e.kind(),
                std::io::ErrorKind::Interrupted,
                "polling the terminal: {e}"
            );
            return true;
        }
        if ready == 0 {
            return true;
        }
        let mut buf = [0u8; 4096];
        // SAFETY: a read into a buffer of the length given.
        let n = unsafe { libc::read(self.master(), buf.as_mut_ptr().cast(), buf.len()) };
        if n > 0 {
            out.extend_from_slice(&buf[..n as usize]);
            return true;
        }
        if n == 0 {
            return false;
        }
        let e = std::io::Error::last_os_error();
        match e.raw_os_error() {
            Some(libc::EIO) => false,
            Some(libc::EINTR | libc::EAGAIN) => true,
            _ => panic!("reading the terminal: {e}"),
        }
    }

    /// Read into `out` until `done` holds of it — `true` — or the session ends or `deadline`
    /// passes — `false`.
    pub fn read_until(
        &self,
        out: &mut Vec<u8>,
        deadline: Instant,
        done: impl Fn(&[u8]) -> bool,
    ) -> bool {
        while Instant::now() < deadline {
            if done(out) {
                return true;
            }
            if !self.read_into(out, 300) {
                return done(out);
            }
        }
        done(out)
    }

    /// Set the terminal's window size, as resizing the terminal window does.
    pub fn resize(&self, rows: u16, cols: u16) {
        let ws = libc::winsize {
            ws_row: rows,
            ws_col: cols,
            ws_xpixel: 0,
            ws_ypixel: 0,
        };
        // SAFETY: `TIOCSWINSZ` reads one `winsize`, which lives across the call.
        let rc = unsafe { libc::ioctl(self.master(), libc::TIOCSWINSZ, &ws) };
        assert_eq!(
            rc,
            0,
            "resizing the terminal: {}",
            std::io::Error::last_os_error()
        );
    }
}

/// A launch driven through a terminal, killed and reaped however the test ends — an assertion
/// that fails first included — so neither it nor the shell it holds outlives the test.
pub struct Reaped(pub Child);

impl Drop for Reaped {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
