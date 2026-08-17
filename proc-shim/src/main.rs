//! The in-cage half of exec enforcement: install a seccomp user-notification filter on
//! `execve`/`execveat`, hand the listener descriptor out to the host supervisor, then become the
//! payload.
//!
//! ## Why this is a binary of its own
//!
//! Deciding an `execve` by path needs a listener descriptor, and only the process itself can install
//! the filter that produces one — bubblewrap can load a *plain* cBPF filter (`--add-seccomp-fd`) but
//! not one returning a listener. So something has to run inside the sandbox to install it.
//!
//! That something is bound into a sandbox an untrusted agent controls, which decides what it may be:
//! a program that can express these three steps and nothing else. A general-purpose binary would be
//! safe only for as long as none of the state it can act on happened to be reachable from inside —
//! a property no one can check, and one that quietly stops holding the first time a new bind is
//! added. This binary links `libc` and nothing else, so the bound artifact's capabilities are a
//! property you can read rather than a claim you have to keep re-verifying.
//!
//! ## Fail-closed
//!
//! Every step before the `execvp` reports and exits **without** running the payload. An unenforced
//! command must never run in place of an enforced one: a filter that could not be installed, or a
//! supervisor that could not be reached, means the guarantee is absent, and running anyway would
//! turn a hard boundary into a silent maybe.
//!
//! ## Usage
//!
//! `sbx-proc-shim <notif-socket> [open-lens] -- <command…>`
//!
//! `open-lens` additionally notifies on the open family, which is what lets the host supervisor read
//! a file's content and refuse the open before any byte reaches the cage. It is opt-in: the traffic
//! is orders of magnitude heavier than `execve`'s.

use std::ffi::{CString, OsStr, OsString};
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::Duration;

/// Exit codes for the failure paths, distinct from any the payload itself can return so a failed
/// launch stays distinguishable from a command that ran and exited.
mod exit {
    /// The argument vector was not `<socket> -- <command…>`.
    pub const USAGE: i32 = 2;
    /// An argument contained a NUL byte, so it cannot cross `execvp`.
    pub const BAD_ARG: i32 = 94;
    /// The listener descriptor never reached the supervisor.
    pub const NO_SUPERVISOR: i32 = 96;
    /// The notification filter could not be installed.
    pub const NO_FILTER: i32 = 97;
    /// The payload was refused — the supervisor answered `EPERM`.
    pub const REFUSED: i32 = 126;
    /// The payload could not be executed for any other reason.
    pub const NOT_EXECUTABLE: i32 = 127;
}

fn fail(message: &str, code: i32) -> ! {
    eprintln!("sbx-proc-shim: {message}");
    std::process::exit(code)
}

fn main() {
    let args: Vec<OsString> = std::env::args_os().skip(1).collect();
    // args = [<notif-socket>, <flag…>, "--", payload0, payload1, …]
    let sep = args.iter().position(|a| a == "--");
    let (sock, flags, payload) = match sep {
        Some(i) if i >= 1 && i + 1 < args.len() => (&args[0], &args[1..i], &args[i + 1..]),
        _ => fail(
            "usage: sbx-proc-shim <notif-socket> [open-lens] -- <command…>",
            exit::USAGE,
        ),
    };
    // An unknown flag is refused rather than ignored: a lens the launcher asked for and the shim
    // silently dropped would leave the cage running unenforced under a name that says otherwise.
    let mut open_lens = false;
    for flag in flags {
        match flag.as_os_str().to_str() {
            Some(OPEN_LENS_FLAG) => open_lens = true,
            _ => fail(
                &format!("unknown flag {flag:?} — refusing to run"),
                exit::USAGE,
            ),
        }
    }

    let notif_fd = match install_notif_filter(open_lens) {
        Ok(fd) => fd,
        Err(e) => fail(
            &format!("cannot install the exec filter ({e}) — refusing to run"),
            exit::NO_FILTER,
        ),
    };
    if let Err(e) = hand_off(sock, notif_fd) {
        // SAFETY: notif_fd is our owned descriptor from install_notif_filter.
        unsafe { libc::close(notif_fd) };
        fail(
            &format!("cannot reach the exec supervisor ({e}) — refusing to run"),
            exit::NO_SUPERVISOR,
        );
    }
    // The supervisor holds the only reference now; drop ours so a supervisor exit tears the filter
    // down (matched execve then fail closed with ENOSYS) rather than lingering.
    // SAFETY: notif_fd is our owned descriptor; closed exactly once.
    unsafe { libc::close(notif_fd) };

    exec_payload(payload)
}

/// The flag asking for the open lens, spelled the same in the launcher and here.
const OPEN_LENS_FLAG: &str = "open-lens";

/// The open-family syscalls the content lens notifies on.
///
/// `open` is listed beside `openat`/`openat2` because x86-64 still carries it: glibc routes through
/// `openat`, but a static binary or a direct `syscall(2)` can issue the older number, and a lens
/// that watched only `openat` would be a one-line walk around.
///
/// A syscall absent from the target's ABI is simply not in this list — `open` does not exist on
/// aarch64, where `openat` is the only form.
fn open_lens_syscalls() -> Vec<libc::c_long> {
    let mut out = Vec::with_capacity(3);
    #[cfg(target_arch = "x86_64")]
    out.push(libc::SYS_open);
    out.push(libc::SYS_openat);
    out.push(libc::SYS_openat2);
    out
}

/// Install a `NEW_LISTENER` seccomp filter that notifies on `execve`/`execveat` — and, when
/// `open_lens` is set, on the open family too — and allows everything else, returning the listener
/// fd. Requires `no_new_privs` (bubblewrap already sets it; set again to be self-contained).
///
/// The open family is opt-in because it is not the same kind of traffic: `execve` fires rarely,
/// while a build issues thousands of opens, each of which would park a cage thread on the
/// supervisor. A launch that does not scan content must not pay a notification per open.
fn install_notif_filter(open_lens: bool) -> io::Result<libc::c_int> {
    // SAFETY: prctl with scalar args; no memory is shared.
    if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0 {
        return Err(io::Error::last_os_error());
    }
    // Opcodes (asm-generic/bpf_common.h): LD|W|ABS = 0x20, JMP|JEQ|K = 0x15, RET|K = 0x06. `nr` is
    // the first field of `seccomp_data`, at offset 0.
    const LD_ABS_W: u16 = 0x20;
    const JEQ_K: u16 = 0x15;
    const RET_K: u16 = 0x06;

    let mut notified: Vec<libc::c_long> = vec![libc::SYS_execve, libc::SYS_execveat];
    if open_lens {
        notified.extend(open_lens_syscalls());
    }

    // `n` comparisons then two returns: every match jumps to the last instruction (`USER_NOTIF`),
    // and falling off the end of the comparisons reaches the `ALLOW` just before it. Comparison `i`
    // (1-based) therefore jumps `n + 1 - i` forward, which is the arithmetic the two-syscall filter
    // this generalises was written out by hand.
    let n = notified.len();
    let mut filter = Vec::with_capacity(n + 3);
    filter.push(libc::sock_filter {
        code: LD_ABS_W,
        jt: 0,
        jf: 0,
        k: 0,
    });
    for (idx, nr) in notified.iter().enumerate() {
        filter.push(libc::sock_filter {
            code: JEQ_K,
            jt: (n - idx) as u8,
            jf: 0,
            k: *nr as u32,
        });
    }
    filter.push(libc::sock_filter {
        code: RET_K,
        jt: 0,
        jf: 0,
        k: libc::SECCOMP_RET_ALLOW,
    });
    filter.push(libc::sock_filter {
        code: RET_K,
        jt: 0,
        jf: 0,
        k: libc::SECCOMP_RET_USER_NOTIF,
    });
    let prog = libc::sock_fprog {
        len: filter.len() as u16,
        filter: filter.as_ptr() as *mut libc::sock_filter,
    };
    // SAFETY: prog points at the live `filter` array for the duration of the call.
    let fd = unsafe {
        libc::syscall(
            libc::SYS_seccomp,
            libc::SECCOMP_SET_MODE_FILTER,
            libc::SECCOMP_FILTER_FLAG_NEW_LISTENER,
            &prog as *const libc::sock_fprog,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(fd as libc::c_int)
}

/// Connect to the host supervisor's socket and send it the listener fd via `SCM_RIGHTS`. Retries the
/// connect briefly (the supervisor binds before the cage launches, so this normally succeeds at once).
fn hand_off(sock: &OsStr, notif_fd: libc::c_int) -> io::Result<()> {
    let mut stream = None;
    for _ in 0..200 {
        match UnixStream::connect(Path::new(sock)) {
            Ok(s) => {
                stream = Some(s);
                break;
            }
            Err(_) => std::thread::sleep(Duration::from_millis(5)),
        }
    }
    let stream = stream.ok_or_else(|| io::Error::other("supervisor socket never accepted"))?;
    send_fd(&stream, notif_fd)
}

/// Send one file descriptor over a connected Unix stream as an `SCM_RIGHTS` ancillary message.
fn send_fd(stream: &UnixStream, fd: libc::c_int) -> io::Result<()> {
    use std::os::unix::io::AsRawFd;
    let mut dummy: u8 = b'x';
    let mut iov = libc::iovec {
        iov_base: &mut dummy as *mut u8 as *mut libc::c_void,
        iov_len: 1,
    };
    // Control buffer sized for exactly one fd.
    let mut cbuf = [0u8; 32]; // >= CMSG_SPACE(size_of::<c_int>())
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = cbuf.as_mut_ptr() as *mut libc::c_void;
    msg.msg_controllen =
        unsafe { libc::CMSG_SPACE(std::mem::size_of::<libc::c_int>() as u32) } as _;
    // SAFETY: msg's control buffer is live and sized; we write exactly one aligned cmsg header + fd.
    unsafe {
        let cmsg = libc::CMSG_FIRSTHDR(&msg);
        (*cmsg).cmsg_level = libc::SOL_SOCKET;
        (*cmsg).cmsg_type = libc::SCM_RIGHTS;
        (*cmsg).cmsg_len = libc::CMSG_LEN(std::mem::size_of::<libc::c_int>() as u32) as _;
        std::ptr::copy_nonoverlapping(
            &fd as *const libc::c_int as *const u8,
            libc::CMSG_DATA(cmsg),
            std::mem::size_of::<libc::c_int>(),
        );
        let n = libc::sendmsg(stream.as_raw_fd(), &msg, 0);
        if n < 0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

/// `execvp` the payload, replacing the shim. Returns only on failure (a denied or missing command).
fn exec_payload(payload: &[OsString]) -> ! {
    let prog = match CString::new(payload[0].as_bytes()) {
        Ok(c) => c,
        Err(_) => fail("command contains a NUL byte", exit::BAD_ARG),
    };
    let args: Vec<CString> = payload
        .iter()
        .filter_map(|a| CString::new(a.as_bytes()).ok())
        .collect();
    if args.len() != payload.len() {
        fail("an argument contains a NUL byte", exit::BAD_ARG);
    }
    let mut ptrs: Vec<*const libc::c_char> = args.iter().map(|c| c.as_ptr()).collect();
    ptrs.push(std::ptr::null());
    // SAFETY: prog and ptrs live until execvp returns (which only happens on failure).
    unsafe { libc::execvp(prog.as_ptr(), ptrs.as_ptr()) };
    let err = io::Error::last_os_error();
    // A supervisor `EPERM` (a denied command) lands here; report as a blocked run.
    let code = if err.raw_os_error() == Some(libc::EPERM) {
        exit::REFUSED
    } else {
        exit::NOT_EXECUTABLE
    };
    fail(
        &format!(
            "cannot execute {}: {err}",
            payload[0].to_string_lossy()
        ),
        code,
    )
}
