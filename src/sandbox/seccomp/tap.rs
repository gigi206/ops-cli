//! The transparent-capture tap's own seccomp filter: a list of what it may call, where every cage
//! gets a list of what it may not.
//!
//! The tap ([`crate::sandbox::nettap`]) parses the DNS the cage writes and reads the connections the
//! cage makes, so it is a process an attacker in the cage talks to. What it asks of the kernel once
//! its listeners are bound is narrow: it accepts on them, reads the address a redirected connection
//! was meant for, dials the two Unix sockets it was handed (the egress socket for each captured
//! connection, the report socket for each report), pumps bytes, and starts threads. So this filter
//! names those calls and answers every other one with `EPERM`: no file opened, no socket but a Unix
//! one, no listener bound, no program run, no process started. The cage the tap runs in holds no
//! host file but the read-only userland and those two sockets; the filter takes away the calls that
//! would reach past it, should a flaw in the tap hand someone its execution.
//!
//! The tap installs it itself ([`confine`]) once its listeners are bound and before it answers
//! anything or starts a thread ([`allowlist`] says why that order, and what every such list starts
//! from). The list was read from a trace of the tap serving every plane (DNS over UDP and over a
//! TCP connection carrying several queries, a capture the proxy accepts and one it refuses, and a
//! connection to an address no name was handed out for) under both C libraries sbx is built with.
//!
//! A few calls are allowed only with some arguments: `socket` only for a Unix socket, `getsockopt`
//! only to read the original destination of a redirected connection, `setsockopt` only the two
//! timeouts the tap sets, `fcntl` only to duplicate a descriptor or read and mark its close-on-exec
//! flag.

use super::{Rules, allowlist};
use std::io;

/// The calls the tap's own work makes, allowed with any argument.
fn work() -> Vec<i64> {
    vec![
        // Its listeners and the connections they accept; the two sockets it dials.
        libc::SYS_accept4,
        libc::SYS_connect,
        libc::SYS_recvfrom,
        libc::SYS_sendto,
        libc::SYS_shutdown,
        libc::SYS_close,
        // Its diagnostics, and the line that says it serves.
        libc::SYS_write,
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
        // The seeds of a hash table a thread makes.
        libc::SYS_getrandom,
    ]
}

/// What the tap may call: every call named here, under its conditions when it has some.
fn allowed() -> Rules {
    let mut m = allowlist::starting_from(work());
    m.insert(
        libc::SYS_socket,
        vec![allowlist::arg_is(0, libc::AF_UNIX as u64)],
    );
    m.insert(
        libc::SYS_getsockopt,
        vec![allowlist::sockopt(
            libc::SOL_IP,
            crate::sandbox::nettap::SO_ORIGINAL_DST,
        )],
    );
    m.insert(
        libc::SYS_setsockopt,
        vec![
            allowlist::sockopt(libc::SOL_SOCKET, libc::SO_RCVTIMEO),
            allowlist::sockopt(libc::SOL_SOCKET, libc::SO_SNDTIMEO),
        ],
    );
    m.insert(
        libc::SYS_fcntl,
        [libc::F_DUPFD_CLOEXEC, libc::F_SETFD, libc::F_GETFD]
            .into_iter()
            .map(|cmd| allowlist::arg_is(1, cmd as u64))
            .collect(),
    );
    m
}

/// Put the calling thread, and every thread it starts from now on, under the tap's filters. Called
/// by the tap once its listeners are bound, before it starts any thread: one started earlier would
/// run without them.
pub(crate) fn confine() -> io::Result<()> {
    allowlist::confine(allowed())
}

#[cfg(test)]
mod tests {
    use super::super::allowlist::probe::{
        Probes, as_the_probes_process, call, done, in_a_process, opening,
    };
    use super::*;
    use std::os::fd::AsRawFd;

    /// The probes' process ([`in_a_process`]), run by
    /// [`the_taps_filters_refuse_what_its_work_does_not_make`]; anywhere else it does nothing.
    #[test]
    #[ignore = "run alone by the test that reads its report"]
    fn the_probes_process() {
        as_the_probes_process(|_| probes());
    }

    /// Confine the process under the tap's filters, and make every probe, the calls that need a
    /// descriptor making them on one opened before.
    fn probes() -> Probes {
        let (socket, _peer) = std::os::unix::net::UnixStream::pair().unwrap();
        let mut out = Vec::new();
        out.push(("confine", done(confine())));
        let s = socket.as_raw_fd() as libc::c_long;
        let path = c"/dev/null".as_ptr() as libc::c_long;
        let int = size_of::<libc::c_int>() as libc::c_long;
        let mut value: libc::c_int = 1;
        let at = (&raw mut value) as libc::c_long;
        let mut len = int as libc::socklen_t;
        let len_at = (&raw mut len) as libc::c_long;

        // Refused.
        out.push((
            "openat",
            opening(
                libc::SYS_openat,
                &[libc::AT_FDCWD as _, path, libc::O_RDONLY as _],
            ),
        ));
        out.push((
            "socket inet",
            opening(
                libc::SYS_socket,
                &[libc::AF_INET as _, libc::SOCK_STREAM as _],
            ),
        ));
        out.push(("bind", call(libc::SYS_bind, &[s, 0, 0])));
        out.push(("listen", call(libc::SYS_listen, &[s, 1])));
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
            "getsockopt SO_TYPE",
            call(
                libc::SYS_getsockopt,
                &[s, libc::SOL_SOCKET as _, libc::SO_TYPE as _, at, len_at],
            ),
        ));
        out.push((
            "setsockopt SO_KEEPALIVE",
            call(
                libc::SYS_setsockopt,
                &[s, libc::SOL_SOCKET as _, libc::SO_KEEPALIVE as _, at, int],
            ),
        ));
        out.push((
            "ioctl TCGETS",
            call(libc::SYS_ioctl, &[s, libc::TCGETS as _, 0]),
        ));
        let page = 4096;
        let (prot_rx, anon) = (
            (libc::PROT_READ | libc::PROT_EXEC) as libc::c_long,
            (libc::MAP_PRIVATE | libc::MAP_ANONYMOUS) as libc::c_long,
        );
        out.push((
            "mmap PROT_EXEC",
            call(libc::SYS_mmap, &[0, page, prot_rx, anon, -1, 0]),
        ));
        // SAFETY: `getpid` reads nothing and cannot fail.
        let me = unsafe { libc::getpid() } as libc::c_long;
        out.push(("kill", call(libc::SYS_kill, &[me, 0])));

        // Answered `ENOSYS`.
        out.push(("clone3", call(libc::SYS_clone3, &[0, 0])));

        // Allowed.
        out.push((
            "socket unix",
            opening(
                libc::SYS_socket,
                &[libc::AF_UNIX as _, libc::SOCK_STREAM as _],
            ),
        ));
        out.push((
            "fcntl F_DUPFD_CLOEXEC",
            opening(libc::SYS_fcntl, &[s, libc::F_DUPFD_CLOEXEC as _, 0]),
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
        out
    }

    /// The tap's filters, in a process of their own: the calls that would reach past its cage are
    /// refused, `clone3` is answered `ENOSYS` so the fallback is taken, and the calls the tap makes
    /// still work, a thread started among them.
    #[test]
    fn the_taps_filters_refuse_what_its_work_does_not_make() {
        let outcomes = in_a_process(concat!(module_path!(), "::the_probes_process"));
        let got = |name: &str| {
            *outcomes
                .get(name)
                .unwrap_or_else(|| panic!("no probe {name}: {outcomes:?}"))
        };
        assert_eq!(got("confine"), Ok(0), "the filters install");
        for name in [
            "openat",
            "socket inet",
            "bind",
            "listen",
            "execve",
            "clone process",
            "getsockopt SO_TYPE",
            "setsockopt SO_KEEPALIVE",
            "ioctl TCGETS",
            "mmap PROT_EXEC",
            "kill",
        ] {
            assert_eq!(got(name), Err(libc::EPERM), "{name} is refused");
        }
        assert_eq!(
            got("clone3"),
            Err(libc::ENOSYS),
            "clone3 is answered ENOSYS"
        );
        for name in [
            "socket unix",
            "fcntl F_DUPFD_CLOEXEC",
            "setsockopt SO_SNDTIMEO",
        ] {
            assert!(got(name).is_ok(), "{name} is allowed: {:?}", got(name));
        }
        assert_eq!(
            got("thread"),
            Ok(7),
            "a thread starts, through the fallback to `clone`"
        );
    }
}
