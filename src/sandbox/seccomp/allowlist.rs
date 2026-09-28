//! What the lists of sbx's own helpers share: the egress proxy's ([`super::proxy`]) and the capture
//! tap's ([`super::tap`]). Each names the calls its own work makes and answers every other one with
//! `EPERM`; what follows is where every such list starts, and how one is installed.
//!
//! Every list starts from its work and a floor the runtime needs under a load no trace is sure to
//! reach ([`floor`]), and allows two calls only with some arguments:
//!
//! - `clone` only with `CLONE_THREAD`: threads, not processes. `clone3` hides its flags in a
//!   structure a filter cannot read, so a program of its own answers it `ENOSYS`, and the C library
//!   falls back to `clone`, where they are visible.
//! - `mmap` and `mprotect` never with `PROT_EXEC`: nothing a helper does maps new code.
//!
//! A helper installs its list itself ([`confine`]), on the thread that runs it and before it starts
//! any other: a filter holds for the thread that installs it and every thread that thread starts,
//! and for no other. That is also what lets a test run a helper's body on a thread of the test
//! process with the filter on, and the rest of the process without it.

use super::{Rules, arg0_has_flag, compile, compile_with};
use seccompiler::{SeccompAction, SeccompCmpArgLen, SeccompCmpOp, SeccompCondition, SeccompRule};
use std::io;

/// What the runtime may call under a load a helper's work does not always reach, allowed with any
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
        // no longer read as one. glibc asks the kernel which thread it is on before signalling it,
        // where musl reads it from its own record.
        libc::SYS_getpid,
        libc::SYS_gettid,
        libc::SYS_tgkill,
        libc::SYS_tkill,
    ]
}

/// Match a call whose argument `index`, read as the kernel reads an `int`, equals `value`.
pub(super) fn arg_is(index: u8, value: u64) -> SeccompRule {
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

/// Match a `setsockopt` or a `getsockopt` of option `name` at `level`: the two calls take them at
/// the same places.
pub(super) fn sockopt(level: libc::c_int, name: libc::c_int) -> SeccompRule {
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

/// The list a helper whose own work makes the calls `work` starts from: those and the [`floor`]
/// with any argument, `clone` for threads alone, and memory never mapped or protected executable.
pub(super) fn starting_from(work: Vec<i64>) -> Rules {
    let mut m = Rules::new();
    for nr in work.into_iter().chain(floor()) {
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
    m
}

/// A helper's filters, in load order: `clone3` answered with `ENOSYS`, then its list `allowed`,
/// refusing everything it does not name with `EPERM`. The list comes last because it is the end of
/// installing any.
fn programs(allowed: Rules) -> Vec<Vec<u8>> {
    let mut clone3 = Rules::new();
    clone3.insert(libc::SYS_clone3, vec![]);
    vec![
        compile(clone3, SeccompAction::Errno(libc::ENOSYS as u32)),
        compile_with(
            allowed,
            SeccompAction::Errno(libc::EPERM as u32),
            SeccompAction::Allow,
        ),
    ]
}

/// Put the calling thread, and every thread it starts from now on, under `allowed` and the program
/// that answers `clone3`, with no new privileges. Called first thing by the helper, before it
/// starts any thread: one started earlier would run without them.
pub(super) fn confine(allowed: Rules) -> io::Result<()> {
    let refused =
        |e: io::Error| io::Error::new(e.kind(), format!("its seccomp filter did not install: {e}"));
    // SAFETY: `PR_SET_NO_NEW_PRIVS` takes plain integers and sets a flag of the calling thread.
    if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0 {
        return Err(refused(io::Error::last_os_error()));
    }
    if !super::install_filters(&programs(allowed)) {
        return Err(refused(io::Error::last_os_error()));
    }
    Ok(())
}

/// The raw calls a test of a helper's list probes it with.
#[cfg(test)]
pub(super) mod probe {
    use std::io;
    use std::os::fd::{FromRawFd, OwnedFd};

    /// What a call answered: its return, or the errno it failed with.
    pub(in crate::sandbox::seccomp) type Outcome = Result<i64, i32>;

    /// The outcome of a raw call's return value, read before anything else can change `errno`.
    pub(in crate::sandbox::seccomp) fn outcome(rc: libc::c_long) -> Outcome {
        if rc == -1 {
            Err(io::Error::last_os_error().raw_os_error().unwrap_or(0))
        } else {
            Ok(rc)
        }
    }

    /// The raw call `nr` with `args`, its unused trailing arguments zero.
    pub(in crate::sandbox::seccomp) fn call(nr: libc::c_long, args: &[libc::c_long]) -> Outcome {
        let mut a = [0; 6];
        a[..args.len()].copy_from_slice(args);
        // SAFETY: every call made through this is given integers, null pointers or pointers to live
        // buffers of the lengths it states, and none of them writes past what it is handed.
        outcome(unsafe { libc::syscall(nr, a[0], a[1], a[2], a[3], a[4], a[5]) })
    }

    /// A call that opens a descriptor, which is closed again when the filter let it through.
    pub(in crate::sandbox::seccomp) fn opening(nr: libc::c_long, args: &[libc::c_long]) -> Outcome {
        let got = call(nr, args);
        if let Ok(fd) = got {
            // SAFETY: the descriptor was just opened by this call and is owned by nothing else.
            drop(unsafe { OwnedFd::from_raw_fd(fd as i32) });
        }
        got
    }
}
