//! The socket the supervisor and the proxy it serves talk over: one message per datagram, with the
//! descriptors it hands over beside it.
//!
//! A `SOCK_SEQPACKET` pair: each send is one message, received whole or not at all, so nothing
//! frames what it writes, and a descriptor rides the message it belongs to (`SCM_RIGHTS`). The two
//! directions are not alike, because the two ends do not trust each other alike.
//!
//! **Down, from the supervisor**: a tag byte, then the document. A document past [`INLINE_MAX`], or
//! past what this socket's send buffer lets one message hold, crosses instead in an anonymous
//! in-memory file handed as the message's first descriptor: a message is bounded by that buffer, and
//! the bound must not become one on a policy or a credential set. The descriptors the message hands
//! over follow, and the proxy receives each close-on-exec. More than the kernel passes in one
//! message is refused whole, never cut.
//!
//! **Up, from the proxy**: the document alone, at most [`MAX_UP`] bytes, and never a descriptor.
//! Once the proxy runs apart it may be what an attacker controls, so the supervisor reads with no
//! room for a descriptor: one sent anyway is discarded by the kernel before it enters the
//! supervisor, and the message that carried it is refused, as is one longer than the supervisor
//! reads, even when what it did read would parse.

use std::io::{self, Read};
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd, RawFd};
use std::time::Duration;

/// The largest document the supervisor sends in the message itself. Far below the send buffer a
/// host gives a socket by default, so the file is the exception: a policy or a credential set larger
/// than one written by hand.
pub(super) const INLINE_MAX: usize = 64 * 1024;

/// The largest message the proxy sends. Its longest is a question about a connection, which carries
/// the request's method and path whole: on HTTP/1.1 they fit the request's head, at most 16 KiB; on
/// HTTP/2 they fit the header list the proxy accepts, at most 64 KiB, of printable ASCII the URI
/// parser admits. Written as JSON, a byte of it takes at most two (`\\` and `\"`), and the host
/// comes from a 16 KiB head as well; this leaves room above that, and stays under the largest
/// datagram a socket's default send buffer holds.
pub(super) const MAX_UP: usize = 192 * 1024;

/// The most descriptors the kernel passes in one message (`SCM_MAX_FD`), and so the room the proxy
/// keeps for them.
const MAX_FDS: usize = 253;

/// The tag of a message whose document follows it.
const INLINE: u8 = 0;

/// The tag of a message whose document is in the file handed as its first descriptor.
const IN_FILE: u8 = 1;

/// One end of the link's socket.
pub(super) struct Socket(OwnedFd);

impl AsFd for Socket {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.0.as_fd()
    }
}

impl Socket {
    /// A connected pair, both ends close-on-exec.
    pub(super) fn pair() -> io::Result<(Socket, Socket)> {
        let mut fds: [RawFd; 2] = [-1; 2];
        // SAFETY: `socketpair` writes two descriptors into the two-element array on success, and
        // touches nothing else.
        let made = unsafe {
            libc::socketpair(
                libc::AF_UNIX,
                libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC,
                0,
                fds.as_mut_ptr(),
            )
        };
        if made < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: both are descriptors `socketpair` just opened for this process, each wrapped once.
        let pair = unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) };
        Ok((Socket(pair.0), Socket(pair.1)))
    }

    /// Wait at most `wait` for room to send a message, then fail the send with
    /// [`io::ErrorKind::WouldBlock`] rather than keep waiting.
    pub(super) fn send_wait(&self, wait: Duration) -> io::Result<()> {
        // Converted by inference rather than through the `time_t` alias, which musl's bindings
        // deprecate while its width changes; held within what the narrower width holds, far above
        // any wait set here.
        let timeout = libc::timeval {
            tv_sec: wait.as_secs().min(i32::MAX as u64) as _,
            tv_usec: wait.subsec_micros() as _,
        };
        // SAFETY: `SO_SNDTIMEO` reads one `timeval`, which is what is passed, with its size.
        let set = unsafe {
            libc::setsockopt(
                self.0.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_SNDTIMEO,
                std::ptr::from_ref(&timeout).cast(),
                size_of_val(&timeout) as libc::socklen_t,
            )
        };
        if set < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    /// Send `doc` to the proxy, handing over `fds` with it: in the message itself when it fits, in a
    /// file otherwise.
    pub(super) fn send_down(&self, doc: &[u8], fds: &[OwnedFd]) -> io::Result<()> {
        let handed: Vec<RawFd> = fds.iter().map(AsRawFd::as_raw_fd).collect();
        if doc.len() <= INLINE_MAX {
            match self.send(&[&[INLINE], doc], &handed) {
                // This socket's buffer holds less than the bound assumes: the file carries it.
                Err(e) if e.raw_os_error() == Some(libc::EMSGSIZE) => {}
                sent => return sent,
            }
        }
        // Dropped once sent: the message holds its own reference, and a file holding a credential
        // set is kept by nobody longer than it takes to hand it over.
        let file = crate::sandbox::memfd::handed(c"sbx-link", doc)?;
        let mut all = Vec::with_capacity(handed.len() + 1);
        all.push(file.as_raw_fd());
        all.extend(handed);
        self.send(&[&[IN_FILE]], &all)
    }

    /// The next message from the supervisor and the descriptors it handed over, or `None` where the
    /// link ends.
    pub(super) fn recv_down(&self) -> io::Result<Option<(Vec<u8>, Vec<OwnedFd>)>> {
        let mut buf = vec![0u8; 1 + INLINE_MAX];
        let (mut control, space) = control_room(MAX_FDS);
        let mut iov = libc::iovec {
            iov_base: buf.as_mut_ptr().cast(),
            iov_len: buf.len(),
        };
        // SAFETY: `msghdr` is pointers and lengths, for which all zeroes (null, empty) is valid;
        // the iov and control fields are pointed at live buffers below before `recvmsg` reads them.
        let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = control.as_mut_ptr().cast();
        msg.msg_controllen = space as _;
        // Close-on-exec as they arrive: a descriptor that landed without the flag would be inherited
        // by every process this one starts until something set it.
        let received_len = receive(&self.0, &mut msg, libc::MSG_CMSG_CLOEXEC)?;
        // Owned before anything is checked, so a refusal below closes what it refuses.
        let mut fds = received(&msg);
        if msg.msg_flags & libc::MSG_CTRUNC != 0 {
            return Err(invalid(
                "a message handing over more descriptors than it carries",
            ));
        }
        if msg.msg_flags & libc::MSG_TRUNC != 0 {
            return Err(invalid("a message larger than the link carries"));
        }
        let Some(n) = received_len else {
            return Ok(None);
        };
        buf.truncate(n);
        match buf[0] {
            INLINE => {
                buf.remove(0);
                Ok(Some((buf, fds)))
            }
            IN_FILE if !fds.is_empty() => {
                let mut doc = Vec::new();
                std::fs::File::from(fds.remove(0)).read_to_end(&mut doc)?;
                Ok(Some((doc, fds)))
            }
            IN_FILE => Err(invalid("a document in a file that was not handed over")),
            _ => Err(invalid("a message of no known form")),
        }
    }

    /// Send `doc` to the supervisor. A document past [`MAX_UP`] is refused here rather than sent to a
    /// supervisor that would refuse it and end the link.
    pub(super) fn send_up(&self, doc: &[u8]) -> io::Result<()> {
        if doc.len() > MAX_UP {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "link: a message larger than the link carries",
            ));
        }
        self.send(&[doc], &[])
    }

    /// The next message from the proxy, or `None` where the link ends.
    #[cfg(test)]
    pub(super) fn recv_up(&self) -> io::Result<Option<Vec<u8>>> {
        let mut buf = vec![0u8; MAX_UP];
        Ok(self.recv_up_into(&mut buf)?.map(|n| {
            buf.truncate(n);
            buf
        }))
    }

    /// Read the next message from the proxy into `buf`, which holds [`MAX_UP`] bytes: its length,
    /// or `None` where the link ends.
    pub(super) fn recv_up_into(&self, buf: &mut [u8]) -> io::Result<Option<usize>> {
        let mut iov = libc::iovec {
            iov_base: buf.as_mut_ptr().cast(),
            iov_len: buf.len(),
        };
        // SAFETY: as in `recv_down`; the control field stays null and empty, which is the point:
        // with no room for one, a descriptor the proxy sends is discarded by the kernel instead of
        // being installed here.
        let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        let received_len = receive(&self.0, &mut msg, 0)?;
        if msg.msg_flags & libc::MSG_CTRUNC != 0 {
            return Err(invalid("a message handing over a descriptor"));
        }
        if msg.msg_flags & libc::MSG_TRUNC != 0 {
            return Err(invalid("a message larger than the link carries"));
        }
        Ok(received_len)
    }

    /// Stop sending: the other end reads the end of the link once it has read what came before.
    pub(super) fn shutdown_write(&self) {
        // SAFETY: `shutdown` on a socket this end owns; an error leaves nothing to undo.
        unsafe { libc::shutdown(self.0.as_raw_fd(), libc::SHUT_WR) };
    }

    /// End the link both ways: a read blocked on this end returns, and the other end reads the end
    /// of the link.
    pub(super) fn shutdown(&self) {
        // SAFETY: as in `shutdown_write`.
        unsafe { libc::shutdown(self.0.as_raw_fd(), libc::SHUT_RDWR) };
    }

    /// Send `bytes` as one message handing over `fds`, whatever this direction allows: how a test
    /// plays a peer that keeps to none of it.
    #[cfg(test)]
    pub(super) fn send_raw(&self, bytes: &[u8], fds: &[RawFd]) -> io::Result<()> {
        self.send(&[bytes], fds)
    }

    /// Send one message made of `parts`, handing over `fds` with it.
    fn send(&self, parts: &[&[u8]], fds: &[RawFd]) -> io::Result<()> {
        let mut iov: Vec<libc::iovec> = parts
            .iter()
            .map(|part| libc::iovec {
                iov_base: part.as_ptr().cast_mut().cast(),
                iov_len: part.len(),
            })
            .collect();
        let (mut control, space) = control_room(fds.len());
        // SAFETY: as in `recv_down`; every field is pointed at a live buffer before `sendmsg`.
        let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
        msg.msg_iov = iov.as_mut_ptr();
        msg.msg_iovlen = iov.len() as _;
        if !fds.is_empty() {
            msg.msg_control = control.as_mut_ptr().cast();
            msg.msg_controllen = space as _;
            // SAFETY: the control buffer is `space` bytes, aligned for a `cmsghdr`, and sized by
            // `CMSG_SPACE` for exactly `fds.len()` descriptors, so the first header and its data
            // lie within it.
            unsafe {
                let header = libc::CMSG_FIRSTHDR(&msg);
                (*header).cmsg_level = libc::SOL_SOCKET;
                (*header).cmsg_type = libc::SCM_RIGHTS;
                (*header).cmsg_len = libc::CMSG_LEN(fds_len(fds.len())) as _;
                std::ptr::copy_nonoverlapping(
                    fds.as_ptr().cast::<u8>(),
                    libc::CMSG_DATA(header),
                    size_of_val(fds),
                );
            }
        }
        loop {
            // SAFETY: `msg` points at the live iovecs and control buffer above. `MSG_NOSIGNAL`: an
            // end that has gone answers `EPIPE` rather than a signal.
            if unsafe { libc::sendmsg(self.0.as_raw_fd(), &msg, libc::MSG_NOSIGNAL) } >= 0 {
                return Ok(());
            }
            let e = io::Error::last_os_error();
            if e.kind() != io::ErrorKind::Interrupted {
                return Err(e);
            }
        }
    }
}

/// Receive one message into what `msg` points at, returning its length, or `None` where the link
/// has ended.
///
/// An end the other side closed while messages it never read were waiting for it is reported
/// once as `ECONNRESET`, before whatever it had sent: the other side has ended the link all the
/// same, and what it left behind is for nobody.
fn receive(
    socket: &OwnedFd,
    msg: &mut libc::msghdr,
    flags: libc::c_int,
) -> io::Result<Option<usize>> {
    loop {
        // SAFETY: the caller pointed `msg` at live buffers of the lengths it states.
        let n = unsafe { libc::recvmsg(socket.as_raw_fd(), msg, flags) };
        if let Ok(n) = usize::try_from(n) {
            return Ok(Some(n).filter(|&n| n > 0));
        }
        let e = io::Error::last_os_error();
        match e.raw_os_error() {
            Some(libc::EINTR) => {}
            Some(libc::ECONNRESET) => return Ok(None),
            _ => return Err(e),
        }
    }
}

/// Every descriptor a received message carried, owned.
fn received(msg: &libc::msghdr) -> Vec<OwnedFd> {
    let mut fds = Vec::new();
    // SAFETY: `msg` was filled by `recvmsg`, which set `msg_controllen` to the control data it
    // wrote; the walk stays within it, and each `SCM_RIGHTS` header's data holds the descriptors
    // the kernel installed in this process, each owned by nothing else yet.
    unsafe {
        let mut header = libc::CMSG_FIRSTHDR(msg);
        while !header.is_null() {
            if (*header).cmsg_level == libc::SOL_SOCKET && (*header).cmsg_type == libc::SCM_RIGHTS {
                let data = libc::CMSG_DATA(header);
                let len = ((*header).cmsg_len as usize).saturating_sub(libc::CMSG_LEN(0) as usize)
                    / size_of::<RawFd>();
                for i in 0..len {
                    let fd = data
                        .add(i * size_of::<RawFd>())
                        .cast::<RawFd>()
                        .read_unaligned();
                    fds.push(OwnedFd::from_raw_fd(fd));
                }
            }
            header = libc::CMSG_NXTHDR(msg, header);
        }
    }
    fds
}

/// A control buffer with room for `count` descriptors, aligned for the header it starts with, and
/// its length in bytes.
fn control_room(count: usize) -> (Vec<libc::cmsghdr>, usize) {
    // SAFETY: `CMSG_SPACE` computes a length and reads nothing.
    let space = unsafe { libc::CMSG_SPACE(fds_len(count)) } as usize;
    // SAFETY: a `cmsghdr` is plain integers, for which all zeroes is a valid value.
    let zero: libc::cmsghdr = unsafe { std::mem::zeroed() };
    (
        vec![zero; space.div_ceil(size_of::<libc::cmsghdr>())],
        space,
    )
}

/// The length of `count` descriptors as a control message states it.
fn fds_len(count: usize) -> libc::c_uint {
    libc::c_uint::try_from(count * size_of::<RawFd>()).unwrap_or(libc::c_uint::MAX)
}

/// A message this end refuses, saying `what` is wrong with it. A fixed text: a message may hold a
/// credential set, and a parser's own message can quote the value it stopped at.
pub(super) fn invalid(what: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, format!("link: {what}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::MetadataExt;

    /// Send `bytes` as one raw message, handing over `fds`, as a peer that ignores every rule here
    /// would.
    fn raw(socket: &Socket, bytes: &[u8], fds: &[RawFd]) {
        socket.send(&[bytes], fds).unwrap();
    }

    /// The raw message waiting on `socket`: its bytes and the descriptors it carried.
    fn raw_recv(socket: &Socket) -> (Vec<u8>, Vec<OwnedFd>) {
        let mut buf = vec![0u8; 1 + INLINE_MAX];
        let (mut control, space) = control_room(MAX_FDS);
        let mut iov = libc::iovec {
            iov_base: buf.as_mut_ptr().cast(),
            iov_len: buf.len(),
        };
        let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = control.as_mut_ptr().cast();
        msg.msg_controllen = space as _;
        let n = receive(&socket.0, &mut msg, libc::MSG_CMSG_CLOEXEC)
            .unwrap()
            .unwrap_or(0);
        let fds = received(&msg);
        buf.truncate(n);
        (buf, fds)
    }

    /// The identity of the file a descriptor refers to.
    fn inode(fd: impl AsFd) -> (u64, u64) {
        let meta = std::fs::File::from(fd.as_fd().try_clone_to_owned().unwrap())
            .metadata()
            .unwrap();
        (meta.dev(), meta.ino())
    }

    fn close_on_exec(fd: impl AsFd) -> bool {
        // SAFETY: reading the descriptor flags of a descriptor the caller holds.
        let flags = unsafe { libc::fcntl(fd.as_fd().as_raw_fd(), libc::F_GETFD) };
        flags >= 0 && flags & libc::FD_CLOEXEC != 0
    }

    /// Whether the read end of a pipe reads the end, within a second: no write end is left open
    /// anywhere in this process.
    fn reads_the_end(read: &OwnedFd) -> bool {
        let mut poll = libc::pollfd {
            fd: read.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: one live `pollfd`.
        let ready = unsafe { libc::poll(&mut poll, 1, 1000) };
        let mut byte = [0u8; 1];
        ready == 1
            && std::fs::File::from(read.try_clone().unwrap())
                .read(&mut byte)
                .unwrap()
                == 0
    }

    fn pipe() -> (OwnedFd, OwnedFd) {
        let mut fds: [RawFd; 2] = [-1; 2];
        // SAFETY: `pipe2` writes two descriptors into the array.
        assert_eq!(unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) }, 0);
        // SAFETY: fresh descriptors, each wrapped once.
        unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) }
    }

    /// A document within the bound crosses in the message itself, and the descriptors handed with it
    /// arrive as the files they were, close-on-exec: this process starts other processes, and one
    /// that landed without the flag would be inherited by each of them.
    #[test]
    fn a_document_crosses_with_the_descriptors_handed_beside_it() {
        let (supervisor, proxy) = Socket::pair().unwrap();
        let (_read, write) = pipe();
        supervisor
            .send_down(b"{\"small\":1}", &[write.try_clone().unwrap()])
            .unwrap();
        let (doc, fds) = proxy.recv_down().unwrap().unwrap();
        assert_eq!(doc, b"{\"small\":1}");
        assert_eq!(fds.len(), 1);
        assert_eq!(inode(&fds[0]), inode(&write));
        assert!(close_on_exec(&fds[0]), "a descriptor arrived inheritable");
    }

    /// A document past the bound crosses in a file handed as the message's first descriptor, and
    /// arrives whole, the descriptors handed with it after the file and nothing else.
    #[test]
    fn a_document_past_the_bound_crosses_in_a_file_beside_the_message() {
        let (supervisor, proxy) = Socket::pair().unwrap();
        let doc: Vec<u8> = (0..INLINE_MAX + 1).map(|i| b'a' + (i % 26) as u8).collect();
        let (_read, write) = pipe();
        supervisor
            .send_down(&doc, &[write.try_clone().unwrap()])
            .unwrap();
        let (bytes, fds) = raw_recv(&proxy);
        assert_eq!(bytes, [IN_FILE], "the message holds the tag alone");
        assert_eq!(fds.len(), 2, "the file, then the descriptor handed with it");
        assert_eq!(inode(&fds[1]), inode(&write));

        supervisor
            .send_down(&doc, &[write.try_clone().unwrap()])
            .unwrap();
        let (received, fds) = proxy.recv_down().unwrap().unwrap();
        assert!(received == doc, "the document arrived altered");
        assert_eq!(fds.len(), 1);
        assert_eq!(inode(&fds[0]), inode(&write));
        assert!(close_on_exec(&fds[0]));
    }

    /// A document within the bound that this socket's send buffer cannot hold in one message still
    /// crosses, in a file: the bound assumes a buffer a host may have set smaller.
    #[test]
    fn a_document_the_send_buffer_cannot_hold_crosses_in_a_file() {
        let (supervisor, proxy) = Socket::pair().unwrap();
        let small: libc::c_int = 4096;
        // SAFETY: `SO_SNDBUF` reads one `c_int`.
        let set = unsafe {
            libc::setsockopt(
                supervisor.0.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_SNDBUF,
                std::ptr::from_ref(&small).cast(),
                size_of_val(&small) as libc::socklen_t,
            )
        };
        assert_eq!(set, 0);
        let doc = vec![b'x'; 20_000];
        assert!(doc.len() <= INLINE_MAX);
        supervisor.send_down(&doc, &[]).unwrap();
        let (received, fds) = proxy.recv_down().unwrap().unwrap();
        assert!(received == doc, "the document arrived altered");
        assert!(fds.is_empty());
    }

    /// A descriptor the proxy hands over never enters the supervisor, and the message that carried it
    /// is refused: the write end of a pipe sent up reads as closed once the sender's copy is, so no
    /// copy of it was installed on this side.
    #[test]
    fn a_descriptor_sent_up_is_refused_and_never_installed() {
        let (supervisor, proxy) = Socket::pair().unwrap();
        let (read, write) = pipe();
        raw(
            &proxy,
            b"{\"Installed\":{\"version\":1}}",
            &[write.as_raw_fd()],
        );
        drop(write);
        assert_eq!(
            supervisor.recv_up().unwrap_err().to_string(),
            "link: a message handing over a descriptor"
        );
        assert!(
            reads_the_end(&read),
            "a copy of the descriptor sent up is open on the supervisor's side"
        );
    }

    /// A message up longer than the supervisor reads is refused, even when what it did read parses:
    /// trailing spaces after a whole document are still a document.
    #[test]
    fn a_message_up_longer_than_the_bound_is_refused_even_when_its_start_reads() {
        let (supervisor, proxy) = Socket::pair().unwrap();
        let mut long = b"{\"Installed\":{\"version\":1}}".to_vec();
        long.resize(MAX_UP + 100, b' ');
        raw(&proxy, &long, &[]);
        assert_eq!(
            supervisor.recv_up().unwrap_err().to_string(),
            "link: a message larger than the link carries"
        );
    }

    /// The proxy refuses to send what the supervisor would refuse to read, and nothing is sent.
    #[test]
    fn a_message_up_past_the_bound_is_not_sent() {
        let (supervisor, proxy) = Socket::pair().unwrap();
        let e = proxy.send_up(&vec![b' '; MAX_UP + 1]).unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::InvalidInput);
        proxy.send_up(b"{}").unwrap();
        assert_eq!(supervisor.recv_up().unwrap().unwrap(), b"{}");
    }

    /// More descriptors than one message carries are refused whole, and nothing crosses: a set is
    /// never handed over with part of its plugins.
    #[test]
    fn more_descriptors_than_a_message_carries_are_refused_whole() {
        let (supervisor, proxy) = Socket::pair().unwrap();
        let (_read, write) = pipe();
        let many: Vec<OwnedFd> = (0..=MAX_FDS).map(|_| write.try_clone().unwrap()).collect();
        let e = supervisor.send_down(b"{}", &many).unwrap_err();
        assert_eq!(e.raw_os_error(), Some(libc::EINVAL));
        supervisor.send_down(b"{\"next\":1}", &many[..1]).unwrap();
        let (doc, fds) = proxy.recv_down().unwrap().unwrap();
        assert_eq!((doc.as_slice(), fds.len()), (&b"{\"next\":1}"[..], 1));
    }

    /// A send that finds no room within its wait fails rather than blocks: the supervisor is not held
    /// by a proxy that has stopped reading.
    #[test]
    fn a_send_that_finds_no_room_within_its_wait_fails() {
        let (supervisor, _proxy) = Socket::pair().unwrap();
        supervisor.send_wait(Duration::from_millis(100)).unwrap();
        let (done, failed) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let e = loop {
                if let Err(e) = supervisor.send_down(b"{\"Answer\":{}}", &[]) {
                    break e;
                }
            };
            let _ = done.send(e.kind());
        });
        assert_eq!(
            failed.recv_timeout(Duration::from_secs(10)),
            Ok(io::ErrorKind::WouldBlock)
        );
    }

    /// The other side's shutdown reads as the end of the link, and so does this side's own, even to
    /// a read already blocked on this side: that is how a side that gives up on the link wakes its
    /// own reader.
    #[test]
    fn a_shutdown_on_either_side_reads_as_the_end() {
        let (supervisor, proxy) = Socket::pair().unwrap();
        proxy.shutdown_write();
        assert!(supervisor.recv_up().unwrap().is_none());

        let (supervisor, proxy) = Socket::pair().unwrap();
        let supervisor = std::sync::Arc::new(supervisor);
        let own = {
            let supervisor = std::sync::Arc::clone(&supervisor);
            std::thread::spawn(move || supervisor.recv_up().map(|m| m.is_none()))
        };
        let other = std::thread::spawn(move || proxy.recv_down().map(|m| m.is_none()));
        std::thread::sleep(Duration::from_millis(50));
        supervisor.shutdown();
        assert!(own.join().unwrap().unwrap(), "this side's reader woke");
        assert!(
            other.join().unwrap().unwrap(),
            "the other side read the end"
        );
    }

    /// A side that closes while messages it never read wait for it has ended the link too: the
    /// other side reads the end, not an error, although the kernel reports the close as a reset.
    #[test]
    fn a_side_that_closes_with_messages_unread_ends_the_link() {
        let (supervisor, proxy) = Socket::pair().unwrap();
        supervisor.send_down(b"{\"never\":\"read\"}", &[]).unwrap();
        proxy.send_up(b"{\"read\":1}").unwrap();
        drop(proxy);
        assert!(supervisor.recv_up().unwrap().is_none());
    }
}
