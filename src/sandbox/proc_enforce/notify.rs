//! The kernel interface, and nothing else: the ioctl request codes derived from the struct
//! sizes, the four ways to answer a notification, the id-validity probe, and the `SCM_RIGHTS`
//! handoff that receives the listener fd.
//!
//! No policy is expressed here and no path is resolved: every item answers a question about the
//! notification descriptor itself, which is what lets the two lenses above it share one mechanism
//! without sharing a decision.

use std::io;
use std::os::unix::net::UnixStream;

// ── seccomp notification ioctl request codes (absent from the libc crate) ─────────────────────────
//
// `_IOC(dir, type, nr, size) = (dir << 30) | (size << 16) | (type << 8) | nr`, with the seccomp ioctl
// magic byte `'!'` (0x21). Sizes come from the structs so the codes cannot drift from the ABI. The
// layout is identical on x86_64 and aarch64.

const IOC_WRITE: libc::c_ulong = 1;
const IOC_READ: libc::c_ulong = 2;
const SECCOMP_IOC_MAGIC: libc::c_ulong = 0x21; // '!'

const fn seccomp_ioc(dir: libc::c_ulong, nr: libc::c_ulong, size: usize) -> libc::c_ulong {
    (dir << 30) | ((size as libc::c_ulong) << 16) | (SECCOMP_IOC_MAGIC << 8) | nr
}

pub(super) fn notif_recv_code() -> libc::c_ulong {
    seccomp_ioc(
        IOC_READ | IOC_WRITE,
        0,
        std::mem::size_of::<libc::seccomp_notif>(),
    )
}

pub(super) fn notif_send_code() -> libc::c_ulong {
    seccomp_ioc(
        IOC_READ | IOC_WRITE,
        1,
        std::mem::size_of::<libc::seccomp_notif_resp>(),
    )
}

pub(super) fn notif_id_valid_code() -> libc::c_ulong {
    seccomp_ioc(IOC_WRITE, 2, std::mem::size_of::<u64>())
}

/// Whether `fd` is a seccomp notification listener at all — asked of the kernel, not assumed.
///
/// The handoff socket is bound read-write into the cage, so whatever connects to it first is who
/// the supervisor hears from, and that need not be the shim. A descriptor that is not a listener
/// makes the first `NOTIF_RECV` fail and takes the whole launch with it, which is a refusal the
/// cage can trigger against itself; refused here instead, while the answer is still "that handoff
/// was not the shim's".
///
/// `ID_VALID` is the question that can be asked without consequence. `NOTIF_RECV` — the obvious
/// probe, and the one this reading of the code first reached for — **blocks** on a listener with
/// nothing pending, so probing with it would hang the supervisor on the ordinary path. Ids are
/// drawn from a counter that starts at one, so zero is never pending: a listener answers `ENOENT`
/// and anything else answers `ENOTTY`. A `0` return is accepted too rather than treated as
/// impossible — it would still mean the fd answered the seccomp ioctl.
pub(super) fn is_notif_listener(fd: libc::c_int) -> bool {
    let id: u64 = 0;
    // SAFETY: passes the address of a live local to the ID_VALID ioctl, which only reads it.
    let rc = unsafe { libc::ioctl(fd, notif_id_valid_code() as libc::Ioctl, &id as *const u64) };
    rc == 0 || io::Error::last_os_error().raw_os_error() == Some(libc::ENOENT)
}

/// Whether a seccomp notification id is still valid (the target has not been reaped).
pub(super) fn notif_id_valid(notif_fd: libc::c_int, id: u64) -> bool {
    // SAFETY: passes the address of a local u64 to the ID_VALID ioctl, which only reads it.
    unsafe {
        libc::ioctl(
            notif_fd,
            notif_id_valid_code() as libc::Ioctl,
            &id as *const u64,
        ) == 0
    }
}

/// Answer a notification with `CONTINUE` (let the real syscall run).
pub(super) fn respond_continue(notif_fd: libc::c_int, id: u64) {
    let mut resp: libc::seccomp_notif_resp = unsafe { std::mem::zeroed() };
    resp.id = id;
    resp.flags = libc::SECCOMP_USER_NOTIF_FLAG_CONTINUE as u32;
    send_resp(notif_fd, &resp);
}

/// Answer a notification with an errno (the syscall never runs).
pub(super) fn respond_errno(notif_fd: libc::c_int, id: u64, errno: libc::c_int) {
    let mut resp: libc::seccomp_notif_resp = unsafe { std::mem::zeroed() };
    resp.id = id;
    resp.error = -errno;
    send_resp(notif_fd, &resp);
}

/// Set once the kernel has refused an `ADDFD` answer, so a host without it pays one failed ioctl
/// for the whole session rather than one per open.
static ADDFD_UNAVAILABLE: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Answer a notification by handing the target a descriptor, rather than letting the real syscall
/// run a second time.
///
/// This is what makes an *allow* sound. `SECCOMP_ADDFD_FLAG_SEND` completes the notification in the
/// same operation that installs the descriptor, and the number it lands on becomes the syscall's
/// return value — so nothing re-resolves the path the cage wrote, and a sibling thread that rewrites
/// that buffer changes nothing. A `CONTINUE` answer cannot offer this: it re-runs the syscall from
/// its arguments, which is why the window exists at all.
///
/// `srcfd` is the supervisor's own descriptor for the inode it examined; the kernel duplicates it
/// into the target and leaves ours alone. Returns `false` when the kernel does not offer the
/// operation (`SECCOMP_ADDFD_FLAG_SEND` landed in 5.9), leaving the caller to fall back on the
/// answer every kernel before it had.
pub(super) fn respond_with_fd(
    notif_fd: libc::c_int,
    id: u64,
    srcfd: libc::c_int,
    cloexec: bool,
) -> bool {
    use std::sync::atomic::Ordering;
    if ADDFD_UNAVAILABLE.load(Ordering::Relaxed) {
        return false;
    }
    let mut addfd: libc::seccomp_notif_addfd = unsafe { std::mem::zeroed() };
    addfd.id = id;
    addfd.flags = libc::SECCOMP_ADDFD_FLAG_SEND as u32;
    addfd.srcfd = srcfd as u32;
    // `newfd` is ignored without `SECCOMP_ADDFD_FLAG_SETFD`: the kernel picks the lowest free
    // number in the target, which is what an ordinary `open` would have returned.
    addfd.newfd = 0;
    addfd.newfd_flags = if cloexec { libc::O_CLOEXEC as u32 } else { 0 };
    // SAFETY: addfd is a live, correctly-sized request for the ADDFD ioctl to read.
    let rc = unsafe {
        libc::ioctl(
            notif_fd,
            libc::SECCOMP_IOCTL_NOTIF_ADDFD as libc::Ioctl,
            &addfd as *const libc::seccomp_notif_addfd,
        )
    };
    if rc >= 0 {
        return true;
    }
    // Told apart on the errno: an old kernel does not know the operation at all, and remembering
    // that is worth a flag. Anything else is about *this* notification — the target was reaped, or
    // it ran out of descriptors — and must not condemn the mechanism for the rest of the session.
    let e = io::Error::last_os_error().raw_os_error().unwrap_or(0);
    if e == libc::EINVAL || e == libc::ENOTTY {
        // `swap` rather than `store`: a parked open answers from its own thread, so two can learn
        // this at once, and the session is meant to say it exactly once.
        //
        // Said at all, because the fallback is the whole difference between an allow that hands
        // over the inode that was examined and one that lets the path resolve a second time. A
        // person reading `[fs] scan` in their config has no other way to learn that the guard they
        // configured is running in its weaker form: nothing else in a launch mentions it, and the
        // kernel version alone does not answer it (a distribution may backport the operation).
        // This is not covered by a test: reproducing it needs a kernel that lacks the operation.
        if !ADDFD_UNAVAILABLE.swap(true, Ordering::Relaxed) {
            crate::diag::warn(
                "this kernel does not offer the seccomp operation that hands the cage the very \
                 descriptor `[fs] scan` examined (it landed in 5.9), so an allowed open is re-run \
                 from its arguments and what the cage receives may not be what was scanned",
            );
        }
    }
    false
}

/// The notification a memory read is guarded by, or `None` when the caller holds none.
///
/// A negative descriptor is how a caller says "no notification in hand" — the unit tests that drive
/// one arm of a decision directly, without a listener. Passing it through as a real pair would make
/// [`super::target::open_target_mem`]'s check fail on `EBADF` and read as "the target is gone",
/// turning the guard into a refusal of every such call.
pub(super) fn notif_of(notif_fd: libc::c_int, id: u64) -> Option<(libc::c_int, u64)> {
    (notif_fd >= 0).then_some((notif_fd, id))
}

/// Send a notification response, ignoring `ENOENT` (the target was reaped while we decided).
fn send_resp(notif_fd: libc::c_int, resp: &libc::seccomp_notif_resp) {
    // SAFETY: resp is a live, correctly-sized response for the SEND ioctl to read.
    unsafe {
        libc::ioctl(
            notif_fd,
            notif_send_code() as libc::Ioctl,
            resp as *const libc::seccomp_notif_resp,
        );
    }
}

/// Poll a descriptor for input with a millisecond timeout and return what the kernel reported.
///
/// The events themselves and not a verdict on them, because the receive loop has to tell two of them
/// apart: `POLLIN` is a notification to decide, while `POLLHUP` on a seccomp listener is the kernel
/// saying no task behind that filter is left — the one sound signal that supervision is over. A
/// caller that only asks "is there something to read" cannot distinguish them and has to infer the
/// hang-up from an errno instead, which is how a single vanished notification once ended a run's
/// supervision.
///
/// `0` for a timeout, and for a poll error too, so a caller re-checks its stop flag rather than
/// spinning.
pub(super) fn poll_events(fd: libc::c_int, timeout_ms: libc::c_int) -> libc::c_short {
    let mut pfd = libc::pollfd {
        fd,
        events: libc::POLLIN,
        revents: 0,
    };
    // SAFETY: pfd is a single live pollfd.
    let rc = unsafe { libc::poll(&mut pfd, 1, timeout_ms) };
    if rc > 0 { pfd.revents } else { 0 }
}

/// Poll a descriptor for readability with a millisecond timeout. `true` = readable (or hung up, so a
/// following read observes the end), `false` = timed out.
pub(super) fn poll_readable(fd: libc::c_int, timeout_ms: libc::c_int) -> bool {
    poll_events(fd, timeout_ms) != 0
}

/// A control buffer for exactly one `SCM_RIGHTS` cmsg, **aligned for a `cmsghdr`**.
///
/// A `[u8; N]` is byte-aligned and `cmsghdr` is not: `CMSG_FIRSTHDR` hands the buffer back as a
/// `*mut cmsghdr`, so every field access through it is only defined if the storage is aligned for
/// one. A bare local array is aligned in practice on the targets sbx builds for, and "in practice"
/// is not what the rule says — the union ties the alignment to the type itself rather than to a
/// number that would have to be kept right.
#[repr(C)]
pub(super) union CmsgBuf {
    bytes: [u8; 32], // >= CMSG_SPACE(size_of::<c_int>())
    _align: libc::cmsghdr,
}

impl CmsgBuf {
    pub(super) fn zeroed() -> Self {
        Self { bytes: [0u8; 32] }
    }

    /// The buffer as bytes, for `msg_control`. Reading the `bytes` arm is sound whatever was last
    /// written: every arm is plain data with no padding to leave uninitialised.
    pub(super) fn as_mut_ptr(&mut self) -> *mut libc::c_void {
        // SAFETY: `bytes` covers the whole union and every byte of it is initialised.
        unsafe { self.bytes.as_mut_ptr() as *mut libc::c_void }
    }

    fn len(&self) -> usize {
        std::mem::size_of::<Self>()
    }
}

/// Receive one file descriptor sent over a Unix stream as an `SCM_RIGHTS` ancillary message, and
/// confirm it is a seccomp notification listener before handing it back.
pub(super) fn recv_fd(stream: &UnixStream) -> io::Result<libc::c_int> {
    let fd = recv_fd_raw(stream)?;
    if !is_notif_listener(fd) {
        // SAFETY: `fd` is ours from `recv_fd_raw` and is closed exactly once here.
        unsafe { libc::close(fd) };
        return Err(io::Error::other(
            "the handoff carried a descriptor that is not a seccomp notification listener",
        ));
    }
    Ok(fd)
}

/// The receive itself, with no opinion about what the descriptor is.
///
/// Split out from [`recv_fd`] so the close-on-exec property below can be asserted against any
/// descriptor — the listener check needs a live seccomp filter, which means a cage, which means a
/// test that skips on the hosted runner. A guard whose test does not run where it ships is the
/// shape of guard this tree already had to go looking for once.
///
/// **`MSG_CMSG_CLOEXEC`**, and it is the whole point of the flag argument. A descriptor arriving
/// through `SCM_RIGHTS` is an ordinary one: without this it lands with `FD_CLOEXEC` clear and is
/// then inherited by every process the supervisor goes on to `fork`+`exec` — nix, bwrap, and the
/// third-party programs a broker or a signer plugin runs. What leaks is the seccomp **notification
/// listener**, so a process holding it can answer the cage's `execve` notifications itself, which is
/// the whole of exec enforcement. Setting it after the fact would leave a window; the flag makes it
/// atomic with the receive.
pub(super) fn recv_fd_raw(stream: &UnixStream) -> io::Result<libc::c_int> {
    use std::os::unix::io::AsRawFd;
    let mut dummy = [0u8; 1];
    let mut iov = libc::iovec {
        iov_base: dummy.as_mut_ptr() as *mut libc::c_void,
        iov_len: 1,
    };
    let mut cbuf = CmsgBuf::zeroed();
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = cbuf.as_mut_ptr();
    msg.msg_controllen = cbuf.len() as _;
    // SAFETY: msg's buffers are live and the control one is aligned for a `cmsghdr` ([`CmsgBuf`]);
    // we read every descriptor the cmsg carries, and close all of them on any refusal.
    unsafe {
        let n = libc::recvmsg(stream.as_raw_fd(), &mut msg, libc::MSG_CMSG_CLOEXEC);
        if n < 0 {
            return Err(io::Error::last_os_error());
        }
        let cmsg = libc::CMSG_FIRSTHDR(&msg);
        if cmsg.is_null()
            || (*cmsg).cmsg_type != libc::SCM_RIGHTS
            || (*cmsg).cmsg_level != libc::SOL_SOCKET
        {
            return Err(io::Error::other("no fd in the handoff message"));
        }
        // Every descriptor the message carried, not the first one. `SCM_RIGHTS` installs them all
        // into this process before a single line here runs, so reading one and walking away leaks
        // the rest for the life of the session — repeat it and the supervisor runs out of
        // descriptors. `cmsg_len` is the only thing that says how many arrived, and it was not
        // read at all.
        let header = libc::CMSG_LEN(0) as usize;
        let width = std::mem::size_of::<libc::c_int>();
        let count = ((*cmsg).cmsg_len as usize).saturating_sub(header) / width;
        let mut fds = vec![-1 as libc::c_int; count];
        std::ptr::copy_nonoverlapping(
            libc::CMSG_DATA(cmsg),
            fds.as_mut_ptr().cast::<u8>(),
            count * width,
        );
        // Closed before the refusal is returned, or the refusal leaks exactly what it refuses.
        let refuse = |why: &'static str| {
            for fd in &fds {
                if *fd >= 0 {
                    libc::close(*fd);
                }
            }
            Err(io::Error::other(why))
        };
        // `MSG_CTRUNC` is refused rather than trimmed, and the cleanup above is honest about its
        // limit: the kernel dropped control data that did not fit, so descriptors may have been
        // closed by it or may not exist at all, and none of them is named by a cmsg this code can
        // walk. What cannot be seen cannot be closed — but a handoff of this shape is not one this
        // protocol sends, so the connection has already failed its contract.
        if msg.msg_flags & libc::MSG_CTRUNC != 0 {
            return refuse("the handoff message was truncated by the kernel");
        }
        if count != 1 || !libc::CMSG_NXTHDR(&msg, cmsg).is_null() {
            return refuse("the handoff message carried more than one descriptor");
        }
        if fds[0] < 0 {
            return refuse("invalid fd in the handoff message");
        }
        Ok(fds[0])
    }
}
