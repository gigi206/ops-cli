//! The egress proxy's own seccomp filter: a list of what it may call, where every cage gets a list
//! of what it may not.
//!
//! The proxy ([`crate::sandbox::proxy::child`]) holds the credentials it injects and the key of the
//! authority it mints leaves with, and it reads what the cage sends. What it asks of the kernel is
//! narrow and known in advance: it serves the sockets it was handed, asks the supervisor for every
//! connection, allocates, and starts threads. So this filter names those calls and answers every
//! other one with `EPERM`: no file opened, no socket created or connected, no program run, no
//! process started. The cage the proxy runs in already holds no network and no host file but the
//! read-only userland; the filter takes away the calls that would reach past it, should a flaw in
//! the proxy hand someone its execution.
//!
//! The proxy installs it itself ([`confine`]), on the thread that runs it and before it starts any
//! other ([`allowlist`] says why that order, and what every such list starts from).
//!
//! ## What is on the list
//!
//! Two halves. The calls the proxy's own work makes ([`work`]), read from a trace of the proxy
//! serving every plane (cleartext, tunnelled, spliced, HTTP/2, refusals, parked requests, signers,
//! refreshes) under both C libraries sbx is built with, and from its code where no trace reaches.
//! And the floor every helper's list shares ([`allowlist::starting_from`]): memory grown in place,
//! a wait that sleeps or yields, a signal delivered, an abort that should still read as one;
//! `clone` for threads alone, and memory never mapped executable.
//!
//! A few calls are allowed only with some arguments: `ioctl` only to set a socket blocking or not,
//! `prctl` only to name a thread, `fcntl` only to duplicate a descriptor, mark it close-on-exec or
//! read its flags, `setsockopt` only the options the proxy sets.
//!
//! On aarch64 the list names the same calls, less the two that architecture has only under another
//! name (`poll` and `epoll_wait`, which its C libraries make as `ppoll` and `epoll_pwait`).

use super::{Rules, allowlist, arg1_is};
use std::io;

/// The calls the proxy's own work makes, allowed with any argument.
fn work() -> Vec<i64> {
    let calls = vec![
        // The sockets it was handed: the cage's, the link, the reports, the signers', and every
        // upstream connection the supervisor hands over.
        libc::SYS_accept4,
        libc::SYS_getpeername,
        libc::SYS_recvfrom,
        libc::SYS_recvmsg,
        libc::SYS_sendmsg,
        libc::SYS_sendto,
        libc::SYS_write,
        libc::SYS_writev,
        libc::SYS_shutdown,
        libc::SYS_close,
        // A document the supervisor hands over in a file when it outgrows one message
        // (`recv_down`), and an event counter drained.
        libc::SYS_read,
        // Waiting on them: the event loops of the HTTP/2 plane, and the WebSocket relay's `poll`.
        libc::SYS_epoll_create1,
        libc::SYS_epoll_ctl,
        libc::SYS_epoll_pwait,
        libc::SYS_eventfd2,
        libc::SYS_ppoll,
        // Memory.
        libc::SYS_brk,
        libc::SYS_munmap,
        libc::SYS_madvise,
        // Threads: starting, parking, sleeping, ending.
        libc::SYS_futex,
        libc::SYS_gettid,
        libc::SYS_rseq,
        libc::SYS_set_robust_list,
        libc::SYS_sigaltstack,
        libc::SYS_rt_sigaction,
        libc::SYS_rt_sigprocmask,
        libc::SYS_sched_getaffinity,
        libc::SYS_clock_nanosleep,
        libc::SYS_exit,
        libc::SYS_exit_group,
        // Keys, and the seeds of its hash tables.
        libc::SYS_getrandom,
    ];
    // The older spellings of two waits, which x86_64 still has and its C libraries still make. The
    // rebinding carries the same `cfg` as the extension it serves.
    #[cfg(target_arch = "x86_64")]
    let calls = {
        let mut calls = calls;
        calls.extend_from_slice(&[libc::SYS_poll, libc::SYS_epoll_wait]);
        calls
    };
    calls
}

/// What the proxy may call: every call named here, under its conditions when it has some.
fn allowed() -> Rules {
    let mut m = allowlist::starting_from(work());
    // Spelled through `c_ulong`, which is `u64` on every target sbx builds for: the constant is a
    // `c_ulong` under glibc and a `c_int` under musl.
    m.insert(
        libc::SYS_ioctl,
        vec![arg1_is(libc::FIONBIO as libc::c_ulong)],
    );
    m.insert(
        libc::SYS_prctl,
        vec![allowlist::arg_is(0, libc::PR_SET_NAME as u64)],
    );
    m.insert(
        libc::SYS_fcntl,
        [
            libc::F_DUPFD_CLOEXEC,
            libc::F_SETFD,
            libc::F_GETFD,
            libc::F_GETFL,
        ]
        .into_iter()
        .map(|cmd| allowlist::arg_is(1, cmd as u64))
        .collect(),
    );
    m.insert(
        libc::SYS_setsockopt,
        vec![
            allowlist::sockopt(libc::SOL_SOCKET, libc::SO_RCVTIMEO),
            allowlist::sockopt(libc::SOL_SOCKET, libc::SO_SNDTIMEO),
            allowlist::sockopt(libc::IPPROTO_TCP, libc::TCP_NODELAY),
        ],
    );
    m
}

/// Put the calling thread, and every thread it starts from now on, under the proxy's filters. Called
/// by the proxy first thing, before it starts any thread: one started earlier would run without
/// them.
pub(crate) fn confine() -> io::Result<()> {
    allowlist::confine(allowed())
}

#[cfg(test)]
mod tests {
    use super::super::allowlist::probe::{
        Probes, as_the_probes_process, call, done, in_a_process, opening, outcome,
    };
    use super::*;
    use std::io::Read;
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

    /// The probes' process ([`in_a_process`]), run by
    /// [`the_proxys_filters_refuse_what_its_work_does_not_make`]; anywhere else it does nothing.
    #[test]
    #[ignore = "run alone by the test that reads its report"]
    fn the_probes_process() {
        as_the_probes_process(|_| probes());
    }

    /// Confine the process under the proxy's filters, and make every probe, the calls that need a
    /// descriptor making them on ones opened before.
    fn probes() -> Probes {
        let mut pipe = [-1; 2];
        // SAFETY: `pipe2` writes two descriptors into the two-element array.
        assert_eq!(
            unsafe { libc::pipe2(pipe.as_mut_ptr(), libc::O_CLOEXEC) },
            0
        );
        // SAFETY: both were just opened and are owned by nothing else.
        let (pipe_r, pipe_w) =
            unsafe { (OwnedFd::from_raw_fd(pipe[0]), OwnedFd::from_raw_fd(pipe[1])) };
        let (socket, _peer) = std::os::unix::net::UnixStream::pair().unwrap();
        let mut file = crate::sandbox::memfd::write(c"sbx-probe", b"handed over").unwrap();
        // The size `read_to_end` asks for first is refused under the filters, which it survives.
        // Asked once out here, before them, so a choice the standard library makes once per
        // process, whether `statx` works, is settled outside the filters on every run.
        let _ = file.metadata();

        let mut out = Vec::new();
        out.push(("confine", done(confine())));
        let (r, w, s) = (
            pipe_r.as_raw_fd() as libc::c_long,
            pipe_w.as_raw_fd() as libc::c_long,
            socket.as_raw_fd() as libc::c_long,
        );
        let path = c"/dev/null".as_ptr() as libc::c_long;

        // Refused.
        out.push((
            "openat",
            opening(
                libc::SYS_openat,
                &[libc::AT_FDCWD as _, path, libc::O_RDONLY as _],
            ),
        ));
        #[cfg(target_arch = "x86_64")]
        out.push((
            "open",
            opening(libc::SYS_open, &[path, libc::O_RDONLY as _]),
        ));
        out.push((
            "socket inet",
            opening(
                libc::SYS_socket,
                &[libc::AF_INET as _, libc::SOCK_STREAM as _],
            ),
        ));
        out.push((
            "socket unix",
            opening(
                libc::SYS_socket,
                &[libc::AF_UNIX as _, libc::SOCK_STREAM as _],
            ),
        ));
        out.push(("connect", call(libc::SYS_connect, &[-1, 0, 0])));
        let nowhere = c"/nonexistent/sbx-probe".as_ptr() as libc::c_long;
        let empty: [*const libc::c_char; 1] = [std::ptr::null()];
        let empty = empty.as_ptr() as libc::c_long;
        out.push(("execve", call(libc::SYS_execve, &[nowhere, empty, empty])));
        // A process `clone` let through runs on here as a copy of this thread, and leaves at
        // once.
        let process = call(libc::SYS_clone, &[libc::SIGCHLD as _, 0, 0, 0, 0]);
        if process == Ok(0) {
            // SAFETY: `_exit` ends the copy without running anything of the process it copied.
            unsafe { libc::_exit(0) };
        }
        out.push(("clone process", process));
        out.push((
            "ioctl TCGETS",
            call(libc::SYS_ioctl, &[w, libc::TCGETS as _, 0]),
        ));
        out.push((
            "prctl PR_GET_DUMPABLE",
            call(libc::SYS_prctl, &[libc::PR_GET_DUMPABLE as _]),
        ));
        let (prot_rx, anon) = (
            (libc::PROT_READ | libc::PROT_EXEC) as libc::c_long,
            (libc::MAP_PRIVATE | libc::MAP_ANONYMOUS) as libc::c_long,
        );
        let page = 4096;
        out.push((
            "mmap PROT_EXEC",
            call(libc::SYS_mmap, &[0, page, prot_rx, anon, -1, 0]),
        ));
        let flags = call(libc::SYS_fcntl, &[w, libc::F_GETFL as _]);
        out.push(("fcntl F_GETFL", flags));
        out.push((
            "fcntl F_SETFL",
            call(
                libc::SYS_fcntl,
                &[w, libc::F_SETFL as _, flags.unwrap_or(0)],
            ),
        ));
        let one: libc::c_int = 1;
        let one_at = (&raw const one) as libc::c_long;
        let int = size_of::<libc::c_int>() as libc::c_long;
        out.push((
            "setsockopt SO_KEEPALIVE",
            call(
                libc::SYS_setsockopt,
                &[
                    s,
                    libc::SOL_SOCKET as _,
                    libc::SO_KEEPALIVE as _,
                    one_at,
                    int,
                ],
            ),
        ));
        // SAFETY: `getpid` reads nothing and cannot fail.
        let me = unsafe { libc::getpid() } as libc::c_long;
        out.push(("kill", call(libc::SYS_kill, &[me, 0])));

        // Answered `ENOSYS`.
        out.push(("clone3", call(libc::SYS_clone3, &[0, 0])));
        #[cfg(target_arch = "x86_64")]
        out.push((
            "x32",
            call(
                libc::SYS_getpid | super::super::X32_SYSCALL_BIT as libc::c_long,
                &[],
            ),
        ));

        // Allowed.
        let mut random = [0u8; 16];
        out.push((
            "getrandom",
            call(
                libc::SYS_getrandom,
                &[random.as_mut_ptr() as _, random.len() as _, 0],
            ),
        ));
        out.push(("write", call(libc::SYS_write, &[w, c"x".as_ptr() as _, 1])));
        out.push((
            "ioctl FIONBIO",
            call(libc::SYS_ioctl, &[w, libc::FIONBIO as _, one_at]),
        ));
        let name = c"sbx-probe".as_ptr() as libc::c_long;
        out.push((
            "prctl PR_SET_NAME",
            call(libc::SYS_prctl, &[libc::PR_SET_NAME as _, name]),
        ));
        let (prot_rw, prot_r) = (
            (libc::PROT_READ | libc::PROT_WRITE) as libc::c_long,
            libc::PROT_READ as libc::c_long,
        );
        let mapped = call(libc::SYS_mmap, &[0, page, prot_rw, anon, -1, 0]);
        out.push(("mmap", mapped.map(|_| 0)));
        if let Ok(at) = mapped {
            out.push((
                "mprotect PROT_EXEC",
                call(libc::SYS_mprotect, &[at, page, prot_rx]),
            ));
            out.push(("mprotect", call(libc::SYS_mprotect, &[at, page, prot_r])));
            out.push(("munmap", call(libc::SYS_munmap, &[at, page])));
        }
        // SAFETY: an empty set of descriptors, with its count, and no wait.
        out.push((
            "poll",
            outcome(unsafe { libc::poll(std::ptr::null_mut(), 0, 0) } as _),
        ));
        out.push((
            "fcntl F_DUPFD_CLOEXEC",
            opening(libc::SYS_fcntl, &[r, libc::F_DUPFD_CLOEXEC as _, 0]),
        ));
        let timeout = libc::timeval {
            tv_sec: 1,
            tv_usec: 0,
        };
        out.push((
            "setsockopt SO_SNDTIMEO",
            call(
                libc::SYS_setsockopt,
                &[
                    s,
                    libc::SOL_SOCKET as _,
                    libc::SO_SNDTIMEO as _,
                    (&raw const timeout) as _,
                    size_of::<libc::timeval>() as _,
                ],
            ),
        ));
        out.push(("thread", std::thread::spawn(|| 7_i64).join().map_err(|_| 0)));
        let mut read = Vec::new();
        out.push((
            "read_to_end",
            file.read_to_end(&mut read)
                .map(|n| n as i64)
                .map_err(|e| e.raw_os_error().unwrap_or(0)),
        ));
        out
    }

    /// The proxy's filters, in a process of their own: the calls that would reach past its cage
    /// are refused, `clone3` and the x32 ABI are answered `ENOSYS` so a fallback is taken, and the
    /// calls the proxy makes still work, starting a thread and reading a document handed over in a
    /// file among them.
    #[test]
    fn the_proxys_filters_refuse_what_its_work_does_not_make() {
        let outcomes = in_a_process(concat!(module_path!(), "::the_probes_process"));
        let got = |name: &str| {
            *outcomes
                .get(name)
                .unwrap_or_else(|| panic!("no probe {name}: {outcomes:?}"))
        };
        assert_eq!(got("confine"), Ok(0), "the filters install");

        let mut refused = vec![
            "openat",
            "socket inet",
            "socket unix",
            "connect",
            "execve",
            "clone process",
            "ioctl TCGETS",
            "prctl PR_GET_DUMPABLE",
            "mmap PROT_EXEC",
            "mprotect PROT_EXEC",
            "fcntl F_SETFL",
            "setsockopt SO_KEEPALIVE",
            "kill",
        ];
        if cfg!(target_arch = "x86_64") {
            refused.push("open");
        }
        for name in refused {
            assert_eq!(got(name), Err(libc::EPERM), "{name} is refused");
        }

        let mut fallback = vec!["clone3"];
        if cfg!(target_arch = "x86_64") {
            fallback.push("x32");
        }
        for name in fallback {
            assert_eq!(got(name), Err(libc::ENOSYS), "{name} is answered ENOSYS");
        }

        for name in [
            "getrandom",
            "write",
            "ioctl FIONBIO",
            "prctl PR_SET_NAME",
            "mmap",
            "mprotect",
            "munmap",
            "poll",
            "fcntl F_GETFL",
            "fcntl F_DUPFD_CLOEXEC",
            "setsockopt SO_SNDTIMEO",
        ] {
            assert!(got(name).is_ok(), "{name} is allowed: {:?}", got(name));
        }
        assert_eq!(got("getrandom"), Ok(16));
        assert_eq!(got("write"), Ok(1));
        assert_eq!(
            got("thread"),
            Ok(7),
            "a thread starts, through the fallback to `clone`"
        );
        assert_eq!(got("read_to_end"), Ok(b"handed over".len() as i64));
    }
}
