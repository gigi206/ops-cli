//! What the lists of sbx's own helpers share: the egress proxy's ([`super::proxy`]), the capture
//! tap's ([`super::tap`]) and a layer's unpack's ([`super::unpack`]). Each names the calls its own
//! work makes and answers every other one with `EPERM`; what follows is where every such list
//! starts, and how one is installed.
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
//! and for no other.

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

/// The raw calls a test of a helper's list probes it with, and the process it probes it in.
#[cfg(test)]
pub(super) mod probe {
    use crate::testutil::TmpDir;
    use std::collections::BTreeMap;
    use std::fs::File;
    use std::io::{self, Read, Write};
    use std::mem::ManuallyDrop;
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    use std::panic::AssertUnwindSafe;
    use std::path::{Path, PathBuf};
    use std::process::{Command, ExitStatus, Stdio};
    use std::time::Duration;

    /// What a call answered: its return, or the errno it failed with.
    pub(in crate::sandbox::seccomp) type Outcome = Result<i64, i32>;

    /// What the probes found, in the order they were made: each call's outcome, by name.
    pub(in crate::sandbox::seccomp) type Probes = Vec<(&'static str, Outcome)>;

    /// How long a test run alone has to end before it is killed and the test that ran it fails.
    const END_WITHIN: Duration = Duration::from_secs(30);

    /// The variable that tells a test it is run alone ([`run_alone`]), and names the directory it
    /// was handed.
    const RUN_ALONE_IN: &str = "SBX_SECCOMP_RUN_ALONE_IN";

    /// What starts a line of a probes' report, which libtest's own lines around it do not carry.
    const REPORTED: &str = "sbx-probe: ";

    /// How a test run alone ended, and what it wrote.
    pub(in crate::sandbox::seccomp) struct Ran {
        pub(in crate::sandbox::seccomp) status: ExitStatus,
        pub(in crate::sandbox::seccomp) stdout: String,
        pub(in crate::sandbox::seccomp) stderr: String,
    }

    /// Run the test `entry` alone, in a process of its own, and say how it ended. `entry` is the
    /// test's path, its module as `module_path!` spells it; the test is an ignored one that does
    /// nothing unless run this way ([`as_run_alone`]).
    ///
    /// A process, as each helper is, rather than a thread of the test process. A filter that
    /// refuses a call the rest of the process needs stops more than the thread it is on: without
    /// `futex`, a lock that thread releases while another waits on it is never handed over, and a
    /// wait of the C library's own that is refused ends the whole process, every other test with it
    /// and none of them named. A filter also holds for as long as its thread does, and a choice the
    /// standard library makes once per process, made first under it, would be the wrong one for
    /// every test after.
    ///
    /// And a process started afresh, the test binary run again for that one test, rather than a
    /// copy of this one by `fork`: a copy of a threaded process holds every lock another thread
    /// held at the fork. The C library resets its allocator's there, but the standard library does
    /// not reset the one it takes to record a thread it starts, and a thread started in the copy
    /// waits on it for good whenever another test was starting a thread at that instant.
    ///
    /// The test is handed a directory of its own, removed once it has ended. A test that has not
    /// ended within [`END_WITHIN`] is killed, and the test that ran it fails rather than waits: a
    /// fault the process has a handler for, and cannot take the handler off under the filters, is
    /// raised again forever. What it wrote is read once it has ended, and not to the end of the
    /// stream: a process another test forks meanwhile holds a copy of every descriptor this one has
    /// open, the pipes' among them, and a stream some other process holds does not end with the
    /// test. What it writes is far smaller than a pipe's buffer, so it is all there.
    pub(in crate::sandbox::seccomp) fn run_alone(entry: &str) -> Ran {
        // libtest names a test by its path in the crate, without the crate's own name.
        let (_, name) = entry.split_once("::").expect("a path in the crate");
        let dir = TmpDir::new();
        let mut child = Command::new(std::env::current_exe().expect("the test binary"))
            .args([
                name,
                "--exact",
                "--ignored",
                "--nocapture",
                "--test-threads=1",
            ])
            .env(RUN_ALONE_IN, dir.path())
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("the test binary runs again");
        let pidfd = crate::session::open_pidfd(child.id()).expect("a pidfd for the test run alone");
        let ended = crate::session::wait_for_exit(pidfd, END_WITHIN);
        crate::session::close_fd(pidfd);
        if !ended {
            let _ = child.kill();
        }
        let status = child.wait().expect("the test run alone is reaped");
        let stdout = queued(child.stdout.take().expect("its output"));
        let stderr = queued(child.stderr.take().expect("its errors"));
        assert!(
            ended,
            "{name} did not end within {END_WITHIN:?}: {stdout}{stderr}"
        );
        Ran {
            status,
            stdout,
            stderr,
        }
    }

    /// What is already queued on `pipe`, read without waiting for more.
    fn queued(mut pipe: impl Read + AsRawFd) -> String {
        let fd = pipe.as_raw_fd();
        // SAFETY: plain integer arguments on a descriptor this process holds.
        unsafe {
            libc::fcntl(
                fd,
                libc::F_SETFL,
                libc::fcntl(fd, libc::F_GETFL) | libc::O_NONBLOCK,
            )
        };
        let mut bytes = Vec::new();
        match pipe.read_to_end(&mut bytes) {
            Err(e) if e.kind() != io::ErrorKind::WouldBlock => panic!("a pipe that fails: {e}"),
            _ => String::from_utf8_lossy(&bytes).into_owned(),
        }
    }

    /// When this process is a test run alone ([`run_alone`]): mark it as one that leaves no core
    /// behind, should it end by a signal, and hand back the directory it was given. `None`
    /// anywhere else, where that test does nothing.
    pub(in crate::sandbox::seccomp) fn as_run_alone() -> Option<PathBuf> {
        let dir = std::env::var_os(RUN_ALONE_IN)?;
        // SAFETY: plain integer arguments, a flag of the calling process.
        unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) };
        Some(PathBuf::from(dir))
    }

    /// The outcome of an operation that answers no value, as a probe reports it.
    pub(in crate::sandbox::seccomp) fn done(r: io::Result<impl Sized>) -> Outcome {
        r.map(|_| 0).map_err(|e| e.raw_os_error().unwrap_or(-1))
    }

    /// What the probes the test `entry` makes found, in a process of its own ([`run_alone`] says
    /// why): each call's outcome, by name.
    pub(in crate::sandbox::seccomp) fn in_a_process(entry: &str) -> BTreeMap<String, Outcome> {
        let ran = run_alone(entry);
        // Exit 2: the report could not be written; 3: the probes panicked.
        assert!(
            ran.status.success(),
            "the probes' process ended with {}: {}{}",
            ran.status,
            ran.stdout,
            ran.stderr
        );
        let outcomes: BTreeMap<_, _> = ran
            .stdout
            .lines()
            .filter_map(|line| line.split_once(REPORTED))
            .map(|(_, line)| heard(line))
            .collect();
        assert!(
            !outcomes.is_empty(),
            "the probes' process reported nothing: {}{}",
            ran.stdout,
            ran.stderr
        );
        outcomes
    }

    /// The body of a helper's probes' test: run alone ([`in_a_process`]), make the probes
    /// `probes` makes in the directory it was handed, report what each answered, and end the
    /// process, never handing back to the harness, whose thread waiting for the test's end the
    /// filters may leave unwoken. Anywhere else, nothing.
    pub(in crate::sandbox::seccomp) fn as_the_probes_process(probes: impl FnOnce(&Path) -> Probes) {
        let Some(dir) = as_run_alone() else {
            return;
        };
        // Written by `write` on the descriptor itself, which every helper's list names, with no
        // lock or buffer of the standard library's in between.
        // SAFETY: the standard output is open for the whole process, and is left open.
        let mut out = ManuallyDrop::new(unsafe { File::from_raw_fd(libc::STDOUT_FILENO) });
        let found = std::panic::catch_unwind(AssertUnwindSafe(|| probes(&dir)));
        let code = match found.map(|found| out.write_all(said(&found).as_bytes())) {
            Ok(Ok(())) => 0,
            Ok(Err(_)) => 2,
            Err(_) => 3,
        };
        // SAFETY: `_exit` ends the process without running anything more of it.
        unsafe { libc::_exit(code) };
    }

    /// The report of what the probes found, one line a probe: `<name>=ok <value>` or
    /// `<name>=errno <errno>`, after [`REPORTED`] and on a line of its own.
    fn said(found: &Probes) -> String {
        let lines: String = found
            .iter()
            .map(|(name, outcome)| match outcome {
                Ok(value) => format!("{REPORTED}{name}=ok {value}\n"),
                Err(errno) => format!("{REPORTED}{name}=errno {errno}\n"),
            })
            .collect();
        format!("\n{lines}")
    }

    /// A line of the report [`said`] wrote, read back.
    fn heard(line: &str) -> (String, Outcome) {
        let (name, outcome) = line
            .split_once('=')
            .unwrap_or_else(|| panic!("not a probe's line: {line}"));
        let outcome = match outcome.split_once(' ') {
            Some(("ok", value)) => Ok(value.parse().expect("a call's return")),
            Some(("errno", errno)) => Err(errno.parse().expect("an errno")),
            _ => panic!("not a probe's outcome: {line}"),
        };
        (name.to_string(), outcome)
    }

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
