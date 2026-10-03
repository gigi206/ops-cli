//! One wall-clock budget for a message that arrives across several reads.
//!
//! A socket's receive timeout and a message deadline are not the same bound, and the gap between
//! them is reachable by whoever is sending. `SO_RCVTIMEO` bounds a single `read`; a message read in
//! pieces — a byte at a time, a line at a time, a length then a body — starts a fresh timeout on
//! every piece. A sender that produces one byte just inside the timeout therefore holds the reader
//! for as long as the message is allowed to be, which is a length *it* chooses.
//!
//! What that costs is not the wait. It is what the wait holds: a host thread, whatever the reader
//! set up before the first byte, and a slot in whichever connection cap governs it — and threads
//! parked host-side are outside the cage's cgroup, so the host pays for them where the sandbox's
//! own limits do not reach.
//!
//! [`Deadlined`] closes it by carrying one budget for the whole message. It is checked *before*
//! each read rather than after, so what it bounds is the budget plus at most one socket timeout,
//! and a reader holding enough buffered bytes never blocks on it at all. It does not replace the
//! socket timeout: with none set, the first `read` of a sender that says nothing at all blocks
//! before the budget is ever consulted again. The two go together.
//!
//! The same gap opens on the other side of a conversation. A message written to a peer that takes
//! it a few bytes at a time, each inside the socket's send timeout, holds the writer for as long as
//! the message is long, so the adapter carries the budget over `Write` too. There the gap is wider
//! than one call: a send timeout bounds each wait for room in the socket, not the `write` that
//! waits, so one `write` of a large buffer to a peer that drains it steadily runs for as long as the
//! draining takes. The adapter therefore hands the socket at most [`WRITE_CHUNK`] per call, and asks
//! the budget again between calls.

use std::io::{self, BufRead, Read, Write};
use std::time::Instant;

/// What a read that ran out of its wall-clock budget is reported as. One sentence for every plane
/// that reads a bounded message, so an operator reading a log line and a caller reading a refusal
/// body see the same words.
pub(crate) const READ_DEADLINE_PASSED: &str =
    "a message did not arrive in full before the read deadline";

/// What a write that ran out of its wall-clock budget is reported as: a peer that did not take what
/// it was sent in time.
pub(crate) const WRITE_DEADLINE_PASSED: &str =
    "a message was not taken in full before the write deadline";

/// A `Read`/`BufRead`/`Write` adapter that gives everything read or written through it **one**
/// wall-clock budget, where a socket timeout gives one budget per call. See the module
/// documentation for what that difference costs when it is missing.
pub(crate) struct Deadlined<'a, R> {
    inner: &'a mut R,
    deadline: Instant,
}

impl<'a, R> Deadlined<'a, R> {
    pub(crate) fn new(inner: &'a mut R, deadline: Instant) -> Self {
        Deadlined { inner, deadline }
    }

    /// The budget, asked before every read or write: past it nothing more is done, and `passed`
    /// says which of the two ran out.
    fn budget_left(&self, passed: &'static str) -> io::Result<()> {
        if Instant::now() >= self.deadline {
            return Err(io::Error::new(io::ErrorKind::InvalidData, passed));
        }
        Ok(())
    }
}

impl<R: Read> Read for Deadlined<'_, R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.budget_left(READ_DEADLINE_PASSED)?;
        self.inner.read(buf)
    }
}

impl<R: BufRead> BufRead for Deadlined<'_, R> {
    fn fill_buf(&mut self) -> io::Result<&[u8]> {
        self.budget_left(READ_DEADLINE_PASSED)?;
        self.inner.fill_buf()
    }

    fn consume(&mut self, n: usize) {
        self.inner.consume(n);
    }
}

/// The most one `write` through [`Deadlined`] hands the inner writer at once.
///
/// Measured on a Unix socket pair: one `send` of 4 MiB to a peer draining 64 KiB every 150 ms ran
/// for 9 seconds under a 200 ms send timeout, every wait inside it short. A piece this size needs
/// room once, so each call waits at most one send timeout before the budget is asked again.
const WRITE_CHUNK: usize = 16 * 1024;

impl<W: Write> Write for Deadlined<'_, W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.budget_left(WRITE_DEADLINE_PASSED)?;
        self.inner.write(&buf[..buf.len().min(WRITE_CHUNK)])
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    /// A peer that takes one byte per call, slowly, the shape a socket's per-call timeout never
    /// catches: each call returns well inside any timeout.
    struct Sipping;

    impl Write for Sipping {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            std::thread::sleep(Duration::from_millis(10));
            Ok(buf.len().min(1))
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    /// A large write to a socket whose peer drains it steadily, each wait for room well inside the
    /// send timeout, is cut off at the budget. Handed over in one call, the buffer was written for
    /// as long as the draining took, since the budget is asked only between calls.
    #[test]
    fn a_large_write_to_a_steadily_draining_socket_ends_at_the_budget() {
        let (mut ours, mut theirs) = std::os::unix::net::UnixStream::pair().expect("a pair");
        ours.set_write_timeout(Some(Duration::from_millis(200)))
            .expect("a send timeout");
        let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let draining = std::sync::Arc::clone(&stop);
        let drain = std::thread::spawn(move || {
            let mut buf = vec![0u8; 64 * 1024];
            while !draining.load(std::sync::atomic::Ordering::SeqCst) {
                if matches!(theirs.read(&mut buf), Ok(0) | Err(_)) {
                    break;
                }
                std::thread::sleep(Duration::from_millis(150));
            }
        });
        let started = Instant::now();
        let written = Deadlined::new(&mut ours, started + Duration::from_millis(600))
            .write_all(&vec![b'x'; 4 << 20]);
        let took = started.elapsed();
        stop.store(true, std::sync::atomic::Ordering::SeqCst);
        drop(ours);
        let _ = drain.join();
        let err = written.expect_err("the budget ends it");
        assert_eq!(err.to_string(), WRITE_DEADLINE_PASSED);
        assert!(
            took < Duration::from_secs(3),
            "ended near the budget, not when the peer had drained it all: {took:?}"
        );
    }

    /// A write to a peer that sips is cut off at the budget for the whole message, not carried on
    /// for as long as the message is long.
    #[test]
    fn a_write_to_a_peer_that_sips_ends_at_the_budget() {
        let mut peer = Sipping;
        let started = Instant::now();
        let err = Deadlined::new(&mut peer, started + Duration::from_millis(100))
            .write_all(&[b'x'; 1000])
            .expect_err("the budget ends it");
        assert_eq!(err.to_string(), WRITE_DEADLINE_PASSED);
        assert!(
            started.elapsed() < Duration::from_secs(1),
            "ended near the budget, not after a thousand sips: {:?}",
            started.elapsed()
        );
    }
}
