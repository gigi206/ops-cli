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
//! other: a filter holds for the thread that installs it and every thread that thread starts, and
//! for no other. That is also what lets a test run the proxy's body on a thread of the test process
//! with the filter on, and the rest of the process without it.
//!
//! ## What is on the list
//!
//! Two halves, kept apart below. The calls the proxy's own work makes ([`work`]), read from a trace
//! of the proxy serving every plane (cleartext, tunnelled, spliced, HTTP/2, refusals, parked
//! requests, signers, refreshes) under both C libraries sbx is built with, and from its code where
//! no trace reaches. And a floor the runtime needs under a load no trace is sure to reach
//! ([`floor`]): memory grown in place, a wait that sleeps or yields, a signal delivered, an abort
//! that should still read as one.
//!
//! A few calls are allowed only with some arguments:
//!
//! - `clone` only with `CLONE_THREAD`: threads, not processes. `clone3` hides its flags in a
//!   structure a filter cannot read, so a program of its own answers it `ENOSYS`, and the C library
//!   falls back to `clone`, where they are visible.
//! - `mmap` and `mprotect` never with `PROT_EXEC`: nothing the proxy does maps new code.
//! - `ioctl` only to set a socket blocking or not, `prctl` only to name a thread, `fcntl` only to
//!   duplicate a descriptor, mark it close-on-exec or read its flags, `setsockopt` only the options
//!   the proxy sets.
//!
//! On aarch64 the list names the same calls, less the two that architecture has only under another
//! name (`poll` and `epoll_wait`, which its C libraries make as `ppoll` and `epoll_pwait`).

use super::{Rules, arg0_has_flag, arg1_is, compile, compile_with};
use seccompiler::{SeccompAction, SeccompCmpArgLen, SeccompCmpOp, SeccompCondition, SeccompRule};
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

/// What the runtime may call under a load the proxy's work does not always reach, allowed with any
/// argument.
fn floor() -> Vec<i64> {
    vec![
        // A large buffer grown in place.
        libc::SYS_mremap,
        // A lock that spins before it parks, and a sleep the C library makes the older way.
        libc::SYS_sched_yield,
        libc::SYS_nanosleep,
        // The clock, where the kernel's shared page does not answer it.
        libc::SYS_clock_gettime,
        // Returning from a signal handler, and resuming a wait a signal interrupted.
        libc::SYS_rt_sigreturn,
        libc::SYS_restart_syscall,
        // An abort, which signals its own process: refused, it would end in some other fault and
        // no longer read as one.
        libc::SYS_getpid,
        libc::SYS_tgkill,
        libc::SYS_tkill,
    ]
}

/// Match a call whose argument `index`, read as the kernel reads an `int`, equals `value`.
fn arg_is(index: u8, value: u64) -> SeccompRule {
    SeccompRule::new(vec![
        SeccompCondition::new(index, SeccompCmpArgLen::Dword, SeccompCmpOp::Eq, value)
            .expect("a constant condition is valid"),
    ])
    .expect("a single-condition rule is valid")
}

/// Match a call whose argument `index` carries none of the bits in `mask`.
fn arg_lacks(index: u8, mask: u64) -> SeccompRule {
    SeccompRule::new(vec![
        SeccompCondition::new(
            index,
            SeccompCmpArgLen::Dword,
            SeccompCmpOp::MaskedEq(mask),
            0,
        )
        .expect("a constant condition is valid"),
    ])
    .expect("a single-condition rule is valid")
}

/// Match a `setsockopt` of option `name` at `level`.
fn sets(level: libc::c_int, name: libc::c_int) -> SeccompRule {
    let is = |index, value: libc::c_int| {
        SeccompCondition::new(
            index,
            SeccompCmpArgLen::Dword,
            SeccompCmpOp::Eq,
            value as u64,
        )
        .expect("a constant condition is valid")
    };
    SeccompRule::new(vec![is(1, level), is(2, name)]).expect("a two-condition rule is valid")
}

/// What the proxy may call: every call named here, under its conditions when it has some.
fn allowed() -> Rules {
    let mut m = Rules::new();
    for nr in work().into_iter().chain(floor()) {
        m.insert(nr, vec![]);
    }
    // Answered `ENOSYS` by the program installed before this one ([`programs`]), and allowed here
    // so that answer stands: of two refusals, the kernel keeps the later filter's, and `EPERM`
    // would stop the C library from falling back to `clone`.
    m.insert(libc::SYS_clone3, vec![]);
    m.insert(
        libc::SYS_clone,
        vec![arg0_has_flag(libc::CLONE_THREAD as u64)],
    );
    let no_exec = || vec![arg_lacks(2, libc::PROT_EXEC as u64)];
    m.insert(libc::SYS_mmap, no_exec());
    m.insert(libc::SYS_mprotect, no_exec());
    // Spelled through `c_ulong`, which is `u64` on every target sbx builds for: the constant is a
    // `c_ulong` under glibc and a `c_int` under musl.
    m.insert(
        libc::SYS_ioctl,
        vec![arg1_is(libc::FIONBIO as libc::c_ulong)],
    );
    m.insert(libc::SYS_prctl, vec![arg_is(0, libc::PR_SET_NAME as u64)]);
    m.insert(
        libc::SYS_fcntl,
        [
            libc::F_DUPFD_CLOEXEC,
            libc::F_SETFD,
            libc::F_GETFD,
            libc::F_GETFL,
        ]
        .into_iter()
        .map(|cmd| arg_is(1, cmd as u64))
        .collect(),
    );
    m.insert(
        libc::SYS_setsockopt,
        vec![
            sets(libc::SOL_SOCKET, libc::SO_RCVTIMEO),
            sets(libc::SOL_SOCKET, libc::SO_SNDTIMEO),
            sets(libc::IPPROTO_TCP, libc::TCP_NODELAY),
        ],
    );
    m
}

/// The proxy's filters, in load order: `clone3` answered with `ENOSYS`, then the list, refusing
/// everything it does not name with `EPERM`. The list comes last because it is the end of
/// installing any: `prctl` is on it only to name a thread.
fn programs() -> Vec<Vec<u8>> {
    let mut clone3 = Rules::new();
    clone3.insert(libc::SYS_clone3, vec![]);
    vec![
        compile(clone3, SeccompAction::Errno(libc::ENOSYS as u32)),
        compile_with(
            allowed(),
            SeccompAction::Errno(libc::EPERM as u32),
            SeccompAction::Allow,
        ),
    ]
}

/// Put the calling thread, and every thread it starts from now on, under the proxy's filters. Called
/// by the proxy first thing, before it starts any thread: one started earlier would run without
/// them.
pub(crate) fn confine() -> io::Result<()> {
    let refused =
        |e: io::Error| io::Error::new(e.kind(), format!("its seccomp filter did not install: {e}"));
    // SAFETY: `PR_SET_NO_NEW_PRIVS` takes plain integers and sets a flag of the calling thread.
    if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0 {
        return Err(refused(io::Error::last_os_error()));
    }
    if !super::install_filters(&programs()) {
        return Err(refused(io::Error::last_os_error()));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::io::Read;
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

    /// What a call answered: its return, or the errno it failed with.
    type Outcome = Result<i64, i32>;

    /// The outcome of a raw call's return value, read before anything else can change `errno`.
    fn outcome(rc: libc::c_long) -> Outcome {
        if rc == -1 {
            Err(io::Error::last_os_error().raw_os_error().unwrap_or(0))
        } else {
            Ok(rc)
        }
    }

    /// The raw call `nr` with `args`, its unused trailing arguments zero.
    fn call(nr: libc::c_long, args: &[libc::c_long]) -> Outcome {
        let mut a = [0; 6];
        a[..args.len()].copy_from_slice(args);
        // SAFETY: every call made through this is given integers, null pointers or pointers to live
        // buffers of the lengths it states, and none of them writes past what it is handed.
        outcome(unsafe { libc::syscall(nr, a[0], a[1], a[2], a[3], a[4], a[5]) })
    }

    /// A call that opens a descriptor, which is closed again when the filter let it through.
    fn opening(nr: libc::c_long, args: &[libc::c_long]) -> Outcome {
        let got = call(nr, args);
        if let Ok(fd) = got {
            // SAFETY: the descriptor was just opened by this call and is owned by nothing else.
            drop(unsafe { OwnedFd::from_raw_fd(fd as i32) });
        }
        got
    }

    /// What the probes found: each call's outcome under the proxy's filters, by name, and the
    /// process a `clone` let through, if one did, for the caller to reap.
    struct Probed {
        outcomes: BTreeMap<&'static str, Outcome>,
        started: Option<libc::pid_t>,
    }

    /// Every probe, made on a thread of this process under the proxy's filters, the calls that need
    /// a descriptor making them on ones opened before it. Only that thread is confined, and the
    /// outcomes are judged by the caller, outside it.
    fn under_the_filters() -> Probed {
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
        // Asked once out here, so a choice the standard library makes once per process, whether
        // `statx` works, is made where it does: made first under the filters, it would be the wrong
        // one for every other test in the process.
        let _ = file.metadata();

        let probing = std::thread::spawn(move || {
            let mut out = BTreeMap::new();
            out.insert(
                "confine",
                confine()
                    .map(|()| 0)
                    .map_err(|e| e.raw_os_error().unwrap_or(0)),
            );
            let (r, w, s) = (
                pipe_r.as_raw_fd() as libc::c_long,
                pipe_w.as_raw_fd() as libc::c_long,
                socket.as_raw_fd() as libc::c_long,
            );
            let path = c"/dev/null".as_ptr() as libc::c_long;

            // Refused.
            out.insert(
                "openat",
                opening(
                    libc::SYS_openat,
                    &[libc::AT_FDCWD as _, path, libc::O_RDONLY as _],
                ),
            );
            #[cfg(target_arch = "x86_64")]
            out.insert(
                "open",
                opening(libc::SYS_open, &[path, libc::O_RDONLY as _]),
            );
            out.insert(
                "socket inet",
                opening(
                    libc::SYS_socket,
                    &[libc::AF_INET as _, libc::SOCK_STREAM as _],
                ),
            );
            out.insert(
                "socket unix",
                opening(
                    libc::SYS_socket,
                    &[libc::AF_UNIX as _, libc::SOCK_STREAM as _],
                ),
            );
            out.insert("connect", call(libc::SYS_connect, &[-1, 0, 0]));
            let nowhere = c"/nonexistent/sbx-probe".as_ptr() as libc::c_long;
            let empty: [*const libc::c_char; 1] = [std::ptr::null()];
            let empty = empty.as_ptr() as libc::c_long;
            out.insert("execve", call(libc::SYS_execve, &[nowhere, empty, empty]));
            // A process `clone` let through runs on here as a copy of this thread, and leaves at
            // once.
            let process = call(libc::SYS_clone, &[libc::SIGCHLD as _, 0, 0, 0, 0]);
            if process == Ok(0) {
                // SAFETY: `_exit` ends the copy without running anything of the process it copied.
                unsafe { libc::_exit(0) };
            }
            out.insert("clone process", process);
            out.insert(
                "ioctl TCGETS",
                call(libc::SYS_ioctl, &[w, libc::TCGETS as _, 0]),
            );
            out.insert(
                "prctl PR_GET_DUMPABLE",
                call(libc::SYS_prctl, &[libc::PR_GET_DUMPABLE as _]),
            );
            let (prot_rx, anon) = (
                (libc::PROT_READ | libc::PROT_EXEC) as libc::c_long,
                (libc::MAP_PRIVATE | libc::MAP_ANONYMOUS) as libc::c_long,
            );
            let page = 4096;
            out.insert(
                "mmap PROT_EXEC",
                call(libc::SYS_mmap, &[0, page, prot_rx, anon, -1, 0]),
            );
            let flags = call(libc::SYS_fcntl, &[w, libc::F_GETFL as _]);
            out.insert("fcntl F_GETFL", flags);
            out.insert(
                "fcntl F_SETFL",
                call(
                    libc::SYS_fcntl,
                    &[w, libc::F_SETFL as _, flags.unwrap_or(0)],
                ),
            );
            let one: libc::c_int = 1;
            let one_at = (&raw const one) as libc::c_long;
            let int = size_of::<libc::c_int>() as libc::c_long;
            out.insert(
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
            );
            // SAFETY: `getpid` reads nothing and cannot fail.
            let me = unsafe { libc::getpid() } as libc::c_long;
            out.insert("kill", call(libc::SYS_kill, &[me, 0]));

            // Answered `ENOSYS`.
            out.insert("clone3", call(libc::SYS_clone3, &[0, 0]));
            #[cfg(target_arch = "x86_64")]
            out.insert(
                "x32",
                call(
                    libc::SYS_getpid | super::super::X32_SYSCALL_BIT as libc::c_long,
                    &[],
                ),
            );

            // Allowed.
            let mut random = [0u8; 16];
            out.insert(
                "getrandom",
                call(
                    libc::SYS_getrandom,
                    &[random.as_mut_ptr() as _, random.len() as _, 0],
                ),
            );
            out.insert("write", call(libc::SYS_write, &[w, c"x".as_ptr() as _, 1]));
            out.insert(
                "ioctl FIONBIO",
                call(libc::SYS_ioctl, &[w, libc::FIONBIO as _, one_at]),
            );
            let name = c"sbx-probe".as_ptr() as libc::c_long;
            out.insert(
                "prctl PR_SET_NAME",
                call(libc::SYS_prctl, &[libc::PR_SET_NAME as _, name]),
            );
            let (prot_rw, prot_r) = (
                (libc::PROT_READ | libc::PROT_WRITE) as libc::c_long,
                libc::PROT_READ as libc::c_long,
            );
            let mapped = call(libc::SYS_mmap, &[0, page, prot_rw, anon, -1, 0]);
            out.insert("mmap", mapped.map(|_| 0));
            if let Ok(at) = mapped {
                out.insert(
                    "mprotect PROT_EXEC",
                    call(libc::SYS_mprotect, &[at, page, prot_rx]),
                );
                out.insert("mprotect", call(libc::SYS_mprotect, &[at, page, prot_r]));
                out.insert("munmap", call(libc::SYS_munmap, &[at, page]));
            }
            // SAFETY: an empty set of descriptors, with its count, and no wait.
            out.insert(
                "poll",
                outcome(unsafe { libc::poll(std::ptr::null_mut(), 0, 0) } as _),
            );
            out.insert(
                "fcntl F_DUPFD_CLOEXEC",
                opening(libc::SYS_fcntl, &[r, libc::F_DUPFD_CLOEXEC as _, 0]),
            );
            let timeout = libc::timeval {
                tv_sec: 1,
                tv_usec: 0,
            };
            out.insert(
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
            );
            out.insert("thread", std::thread::spawn(|| 7_i64).join().map_err(|_| 0));
            let mut read = Vec::new();
            out.insert(
                "read_to_end",
                file.read_to_end(&mut read)
                    .map(|n| n as i64)
                    .map_err(|e| e.raw_os_error().unwrap_or(0)),
            );
            drop((pipe_r, pipe_w, socket));
            Probed {
                started: process
                    .ok()
                    .filter(|&pid| pid > 0)
                    .map(|pid| pid as libc::pid_t),
                outcomes: out,
            }
        });
        probing.join().unwrap()
    }

    /// The proxy's filters, on a thread of the test process: the calls that would reach past its
    /// cage are refused, `clone3` and the x32 ABI are answered `ENOSYS` so a fallback is taken, and
    /// the calls the proxy makes still work, starting a thread and reading a document handed over
    /// in a file among them. Only the probing thread is confined.
    #[test]
    fn the_proxys_filters_refuse_what_its_work_does_not_make() {
        let probed = under_the_filters();
        if let Some(pid) = probed.started {
            let mut status = 0;
            // SAFETY: `pid` is a child of this process that has exited or is about to.
            unsafe { libc::waitpid(pid, &mut status, 0) };
        }
        let got = |name: &str| {
            *probed
                .outcomes
                .get(name)
                .unwrap_or_else(|| panic!("no probe {name}"))
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
