//! The network-namespace holder: gives an isolated cage a black-hole `dummy0` interface so an
//! in-cage graphical app reports itself *online*.
//!
//! ## Why
//!
//! Under a filtering network posture the cage runs in an empty network namespace (loopback only) —
//! its sole egress is the forwarder-to-proxy path on `127.0.0.1`. But Chromium/Electron decide
//! `navigator.onLine` from the *presence of a non-loopback interface*, not from actual reachability:
//! a loopback-only namespace reads as "no network", so a graphical agent panel freezes on
//! "No internet — wait for reconnection" even though egress works perfectly through the proxy.
//! Adding one dummy interface (a kernel black hole: no peer, no route, drops everything) flips
//! `navigator.onLine` to true without opening any egress — a direct connect still has no route and
//! fails closed, and all real traffic still goes through the proxy on loopback.
//!
//! ## How
//!
//! bwrap creates the cage's network namespace itself (`--unshare-net`) and cannot be told to
//! configure it, and the cage is cap-dropped so it could never add an interface either. So a tiny
//! holder runs first, as its own `__netns-holder` subcommand (host-side, never in the cage), and
//! configures the namespace from outside while bwrap waits for it:
//!
//! 1. fork a *configurer*, then `execve` the real command (`bwrap --info-fd … --block-fd … …`).
//!    bwrap creates its user and network namespaces, reports its child's pid on the info pipe, and
//!    holds the cage before its command until the block pipe is written to or closed.
//! 2. the configurer finds the user namespace that owns that network namespace
//!    (`NS_GET_USERNS`) and joins both. bwrap's outer user namespace is owned by the invoking uid
//!    and is a child of the host's, so the kernel grants a same-uid host process every capability
//!    in it — `CAP_NET_ADMIN` included — without creating a namespace of its own.
//! 3. bring up `lo` and add `dummy0` (best-effort — any failure degrades to a loopback-only
//!    namespace, i.e. exactly what `--unshare-net` produces), stand the capture tap up, then
//!    release the cage.
//!
//! Joining leaves the creation of every namespace to bwrap, which is what keeps this working on a
//! host that confines who may create one: Ubuntu's AppArmor restriction lets a path-profiled
//! `bwrap` create user namespaces with capabilities and refuses sbx the same, while the join is not
//! a creation. And because the namespace is bwrap's own, a configurer that fails leaves the cage in
//! an empty network namespace — never on the host's network.

use super::spec::{NetnsDummy, TapWiring};
use std::ffi::{CString, OsString};
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

/// The dummy interface's address (octets + prefix length). A private, non-routable /24: assigning it
/// installs only a connected route for its own subnet (no default route), so it can never become an
/// egress path — a cage connect to any real host still finds no route and fails closed, exactly as in
/// a loopback-only namespace.
const DUMMY_OCTETS: [u8; 4] = [10, 11, 12, 13];
const DUMMY_PREFIX: u8 = 24;

/// `cage` behind the netns holder `dummy` describes ([`holder_wrap`]), and unchanged without one.
///
/// The tap's end of the report channel rides along as a descriptor the command carries, which the
/// holder's argument list names by number ([`super::nettap::ReportChannel`]).
pub(crate) fn behind_holder(
    mut cage: super::argv::CageCommand,
    dummy: Option<&NetnsDummy>,
) -> io::Result<super::argv::CageCommand> {
    let report = dummy
        .and_then(|nd| nd.tap.as_ref())
        .and_then(|tap| tap.report.as_ref());
    let report_fd = match report {
        Some(report) => {
            let end = std::fs::File::from(report.dup()?);
            let fd = std::os::fd::AsRawFd::as_raw_fd(&end);
            cage.hand(end);
            Some(fd)
        }
        None => None,
    };
    Ok(cage.wrapped(|bwrap, argv| holder_wrap(bwrap, argv, dummy, report_fd)))
}

/// Wrap a bwrap invocation so it runs behind the netns holder, when `dummy` is set. Returns the
/// program to spawn and its argument list; with `None` it is the unchanged `(bwrap, argv)`, so the
/// ordinary launch path is byte-for-byte identical. The result is what the cgroup scope wrapper
/// then splices, giving `systemd-run --scope -- <sbx> __netns-holder <bwrap> <argv…>`.
///
/// `report_fd` is the number of the descriptor the tap's end of the report channel was handed on
/// ([`behind_holder`]), named only when the tap is wired.
pub(crate) fn holder_wrap(
    bwrap: &Path,
    bwrap_argv: Vec<OsString>,
    dummy: Option<&NetnsDummy>,
    report_fd: Option<RawFd>,
) -> (PathBuf, Vec<OsString>) {
    match dummy {
        None => (bwrap.to_path_buf(), bwrap_argv),
        Some(nd) => {
            let mut argv = Vec::with_capacity(bwrap_argv.len() + 10);
            argv.push(OsString::from("__netns-holder"));
            if let Some(tap) = &nd.tap {
                argv.push(OsString::from("--tap"));
                argv.push(tap.uds.as_os_str().to_owned());
                argv.push(OsString::from("--bwrap"));
                argv.push(tap.bwrap.as_os_str().to_owned());
                argv.push(OsString::from("--nft"));
                argv.push(tap.nft.as_os_str().to_owned());
                if let Some(fd) = report_fd {
                    argv.push(OsString::from("--report-fd"));
                    argv.push(OsString::from(fd.to_string()));
                }
            }
            // Always emitted, tap or no tap: it is what makes the command unambiguous to parse, so
            // a bwrap argument that happens to spell `--tap` can never be read as the holder's own.
            argv.push(OsString::from("--"));
            argv.push(bwrap.as_os_str().to_owned());
            argv.extend(bwrap_argv);
            (nd.holder_exe.clone(), argv)
        }
    }
}

/// The holder's own options, split from the command it will exec.
///
/// Returns `None` when the argument list has no `--`, which is a caller that did not come through
/// [`holder_wrap`]; the holder refuses rather than guessing where its options end.
///
/// A `--report-fd` descriptor is adopted as soon as its option is parsed
/// ([`super::nettap::adopt_report_end`]), which marks it close-on-exec, and that is why it is done
/// here: this process cleared the flag for its own exec, and what it becomes is the cage's bwrap,
/// which hands the cage every descriptor left without it. Adopted before the redirect starts its
/// `nft`, a plain spawn, it reaches none, and only the tap is handed a copy ([`start_tap`]). One
/// that is not the end of a report channel, or one of the standard three, refuses the whole list:
/// the launcher hands over nothing else, and a descriptor the holder cannot account for is one it
/// must not leave open for the cage. A refusal ends the holder, which closes the rest.
fn split_holder_args(argv: &[OsString]) -> Option<(Option<TapWiring>, &[OsString])> {
    let sep = argv.iter().position(|a| a == "--")?;
    let (opts, rest) = argv.split_at(sep);
    let rest = &rest[1..];
    let mut uds = None;
    let mut bwrap = None;
    let mut nft = None;
    let mut report = None;
    let mut i = 0;
    while i < opts.len() {
        match opts[i].to_str() {
            Some("--tap") => uds = opts.get(i + 1).map(PathBuf::from),
            Some("--bwrap") => bwrap = opts.get(i + 1).map(PathBuf::from),
            Some("--nft") => nft = opts.get(i + 1).map(PathBuf::from),
            Some("--report-fd") => {
                let fd = opts.get(i + 1)?.to_str()?.parse::<RawFd>().ok()?;
                if fd <= 2 {
                    return None;
                }
                let end = super::nettap::adopt_report_end(fd).ok()?;
                report = Some(super::nettap::ReportChannel::new(end));
            }
            _ => return None,
        }
        i += 2;
    }
    let tap = match (uds, bwrap, nft) {
        (Some(uds), Some(bwrap), Some(nft)) => Some(TapWiring {
            uds,
            bwrap,
            nft,
            report,
        }),
        // Part of a wiring is not one: the launcher emits all three or none. The report channel is
        // not one of them: without it the tap still captures, it just reports no resolutions. A
        // channel without a tap is closed here, with nothing to report down it.
        _ => None,
    };
    Some((tap, rest))
}

/// The `__netns-holder` subcommand body. `argv` is `[bwrap, bwrap-args…]`. Forks the configurer
/// ([`configure`]), then `execve`s bwrap with the two pipes that let the configurer find the cage's
/// network namespace and hold the cage until it is configured. Never returns: it either becomes
/// bwrap or exits non-zero with a diagnostic.
///
/// This process becomes bwrap rather than starting it, so the cage keeps the pid, the parent and
/// the exit status the launch path gave it; the configurer is the one that forks off.
pub(crate) fn run_holder(argv: &[OsString]) -> ! {
    let Some((tap, argv)) = split_holder_args(argv) else {
        die(
            NEVER_STARTED,
            "__netns-holder: malformed arguments (no `--` before the command)",
        );
    };
    if argv.is_empty() {
        die(NEVER_STARTED, "__netns-holder: no command to exec");
    }
    if let Err(e) = single_threaded() {
        die(NEVER_STARTED, &format!("__netns-holder: {e}"));
    }
    // A refusal is not fatal: bwrap then runs privileged, and the configurer's join is refused and
    // says so.
    let _ = unprivileged_for(Path::new(&argv[0]));
    let (info_r, info_w, block_r, block_w) = match sync_pipes() {
        Ok(fds) => fds,
        Err(e) => die(NEVER_STARTED, &format!("__netns-holder: {e}")),
    };
    let argv = with_sync_fds(argv, info_w.as_raw_fd(), block_r.as_raw_fd());

    // SAFETY: `getpid` takes no argument and cannot fail.
    let holder = unsafe { libc::getpid() };
    // SAFETY: this process is single-threaded (checked above), so the child is a complete copy of
    // it and may run ordinary code — allocate, open files, start the tap — before it exits.
    match unsafe { libc::fork() } {
        -1 => die(
            NEVER_STARTED,
            &format!("__netns-holder: fork: {}", io::Error::last_os_error()),
        ),
        0 => {
            // bwrap's two ends are bwrap's alone: a configurer holding the block pipe's read end
            // would be harmless, but one holding the info pipe's write end would never see the EOF
            // that says bwrap ended before reporting.
            drop(info_w);
            drop(block_r);
            configure(holder, info_r, block_w, tap.as_ref())
        }
        _ => {
            // The configurer's two ends are closed here, before the exec, and close-on-exec besides:
            // a bwrap that held the block pipe's write end would wait forever on a configurer that
            // died without writing to it, rather than reading the EOF that releases it.
            drop(info_r);
            drop(block_w);
            exec_bwrap(&argv)
        }
    }
}

/// Become `argv[0]`, run with the rest of `argv`. Never returns.
fn exec_bwrap(argv: &[OsString]) -> ! {
    let prog = to_cstring(&argv[0]);
    let cargs: Vec<CString> = argv.iter().map(to_cstring).collect();
    let mut ptrs: Vec<*const libc::c_char> = cargs.iter().map(|c| c.as_ptr()).collect();
    ptrs.push(std::ptr::null());
    // This process is sbx, whose runtime ignores `SIGPIPE`; bubblewrap would hand that on to the
    // cage.
    super::memfd::default_signals_across_exec();
    // SAFETY: `prog` and every `CString` in `cargs` are alive for the duration of the call, and
    // `ptrs` holds their pointers terminated by the null `execv` reads as the end of the vector.
    unsafe {
        libc::execv(prog.as_ptr(), ptrs.as_ptr());
    }
    die(
        EXEC_FAILED,
        &format!(
            "__netns-holder: execv {:?}: {}",
            argv[0],
            std::io::Error::last_os_error()
        ),
    );
}

/// `argv` with bwrap's two pipe options spliced in after the program: `--info-fd`, on which bwrap
/// reports the pid of its child, and `--block-fd`, on which that child waits before running the
/// cage's command. Right after the program because bwrap reads every option before the command, so
/// the place is free and the rest of the argv is left byte for byte as the launch built it.
fn with_sync_fds(argv: &[OsString], info: RawFd, block: RawFd) -> Vec<OsString> {
    let mut out = Vec::with_capacity(argv.len() + 4);
    out.push(argv[0].clone());
    out.push(OsString::from("--info-fd"));
    out.push(OsString::from(info.to_string()));
    out.push(OsString::from("--block-fd"));
    out.push(OsString::from(block.to_string()));
    out.extend_from_slice(&argv[1..]);
    out
}

/// The two pipes between bwrap and whoever configures its network namespace, as `(info read, info
/// write, block read, block write)`. Every end is close-on-exec but bwrap's two — the info pipe's
/// write end and the block pipe's read end — which have to cross its `execve`.
fn sync_pipes() -> io::Result<(OwnedFd, OwnedFd, OwnedFd, OwnedFd)> {
    let (info_r, info_w) = pipe()?;
    let (block_r, block_w) = pipe()?;
    inheritable(&info_w)?;
    inheritable(&block_r)?;
    Ok((info_r, info_w, block_r, block_w))
}

/// A close-on-exec pipe, as `(read end, write end)`.
fn pipe() -> io::Result<(OwnedFd, OwnedFd)> {
    let mut fds = [0 as libc::c_int; 2];
    // SAFETY: `fds` is a live two-element array the call writes the descriptors into.
    if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: both descriptors were just created by `pipe2` and are owned by nothing else.
    Ok(unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) })
}

/// Clear `FD_CLOEXEC` on `fd`, so it crosses the next `execve`.
fn inheritable(fd: &OwnedFd) -> io::Result<()> {
    // SAFETY: `fd` is a live descriptor this process owns; `F_SETFD` with `0` only clears its
    // close-on-exec flag.
    if unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_SETFD, 0) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Have a setuid `bwrap` run unprivileged when this process starts it, by first entering a user
/// namespace of its own that maps the invoking uid and gid to themselves and nothing else. A
/// `bwrap` that is not setuid is left alone, and this is a no-op.
///
/// A setuid `bwrap` creates the cage's namespaces with real privilege, so they belong to the host's
/// user namespace, where the configurer holds no capability and cannot join them. The kernel
/// ignores the setuid bit of a file whose owner the executing namespace does not map, and root is
/// not mapped here, so the `bwrap` this process runs is an unprivileged one, whose namespaces are
/// children of this one and owned by the invoking uid — the namespaces the configurer joins on any
/// other host. The cage's identity is unchanged: the invoking uid maps to itself.
///
/// Creating that namespace is what a host restricting unprivileged user namespaces refuses sbx;
/// `Err` then leaves this process as it was, and `bwrap` runs setuid.
fn unprivileged_for(bwrap: &Path) -> io::Result<()> {
    use std::os::unix::fs::MetadataExt;
    if std::fs::metadata(bwrap)?.mode() & libc::S_ISUID == 0 {
        return Ok(());
    }
    // Asked of a throwaway child first, because the step cannot be undone: a process never leaves
    // a user namespace it entered, and one that carries no capability would leave `bwrap` unable
    // to create its own, where running setuid it still could.
    if !identity_userns_bears_capabilities() {
        return Err(io::Error::other(
            "this host gives sbx no user namespace that bears capabilities",
        ));
    }
    enter_identity_userns()
}

/// Enter a new user namespace that maps the invoking uid and gid to themselves and nothing else.
fn enter_identity_userns() -> io::Result<()> {
    // SAFETY: `getuid`/`getgid` read this process's own real ids; they take no pointer and cannot
    // fail. Read before the namespace exists, after which they read as the overflow ids until the
    // maps are written.
    let (uid, gid) = unsafe { (libc::getuid(), libc::getgid()) };
    // SAFETY: `unshare` takes only a flag word, and its effect is confined to this process's own
    // namespace set; a refusal is reported through the return value.
    if unsafe { libc::unshare(libc::CLONE_NEWUSER) } != 0 {
        return Err(io::Error::last_os_error());
    }
    // `setgroups` must be denied before `gid_map` is written, a kernel requirement for a namespace
    // an unprivileged process maps.
    std::fs::write("/proc/self/setgroups", "deny")?;
    std::fs::write("/proc/self/uid_map", format!("{uid} {uid} 1"))?;
    std::fs::write("/proc/self/gid_map", format!("{gid} {gid} 1"))?;
    Ok(())
}

/// Whether [`enter_identity_userns`] gives a namespace whose capabilities can be used, asked of a
/// child that enters one and creates a UTS namespace inside it — a step that needs
/// `CAP_SYS_ADMIN` there, as `bwrap`'s own namespaces do — then ends with the answer.
///
/// Creating the user namespace alone proves nothing: a host that restricts unprivileged user
/// namespaces (Ubuntu's AppArmor restriction) lets it succeed and confines the process to a
/// profile that denies every capability in it.
fn identity_userns_bears_capabilities() -> bool {
    // SAFETY: both callers are single-threaded (checked before), so the child is a complete copy
    // and may run ordinary code before it exits; it touches nothing the parent shares.
    match unsafe { libc::fork() } {
        -1 => false,
        0 => {
            let usable = enter_identity_userns().is_ok()
                // SAFETY: a flag word is the whole argument list; the new UTS namespace is this
                // child's alone, and it ends right after.
                && unsafe { libc::unshare(libc::CLONE_NEWUTS) } == 0;
            // SAFETY: `_exit` ends the child at once, running none of the parent's exit handlers.
            unsafe { libc::_exit(if usable { 0 } else { 1 }) }
        }
        child => {
            let mut status = 0;
            // SAFETY: `child` is this process's own child and `status` a live integer the call
            // writes.
            let waited = unsafe { libc::waitpid(child, &mut status, 0) };
            waited == child && libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0
        }
    }
}

/// Refuse to go on in a process that runs more than one thread.
///
/// Two things here need it. `setns` into a user namespace fails with `EINVAL` in a multithreaded
/// process, and the holder forks a configurer that runs ordinary code — allocation included — which
/// is sound only when no other thread could have held a lock at the fork.
fn single_threaded() -> io::Result<()> {
    let threads = std::fs::read_dir("/proc/self/task")?.count();
    if threads != 1 {
        return Err(io::Error::other(format!(
            "this process runs {threads} threads; it must run one"
        )));
    }
    Ok(())
}

/// The configurer's body: wait for bwrap to report its child, join that child's network namespace,
/// configure it, then release the cage. Never returns.
///
/// Every failure is best-effort by design and ends the same way: the cage is released into the
/// namespace it has, which bwrap created empty, so what is lost is the online signal and the
/// capture — never the isolation. Releasing is writing to the block pipe or, should this process
/// die first, the EOF its death leaves there.
///
/// With a tap, this process stays: it is the tap's parent, the tap dies with it
/// (`PR_SET_PDEATHSIG`), and it dies with the holder, which by then is the cage's bwrap.
fn configure(holder: libc::pid_t, info: OwnedFd, block: OwnedFd, tap: Option<&TapWiring>) -> ! {
    let mut keep = vec![info.as_raw_fd(), block.as_raw_fd()];
    // The tap's end of the report channel, which the configurer hands the tap it starts.
    keep.extend(
        tap.and_then(|tap| tap.report.as_ref())
            .map(super::nettap::ReportChannel::as_raw_fd),
    );
    keep_only(&keep);
    die_with(holder);
    let child = match read_child_pid(&info, CHILD_PID_TIMEOUT) {
        Ok(pid) => pid,
        // bwrap ended before it reported a child: it said why on its own, and there is no cage to
        // configure.
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => std::process::exit(0),
        Err(e) => {
            unconfigured(
                tap.is_some(),
                &format!("bwrap did not report its sandbox ({e})"),
            );
            release(block);
        }
    };
    finish_report(info);
    if let Err(e) = join_netns(child) {
        unconfigured(
            tap.is_some(),
            &format!("the cage's network namespace could not be joined ({e})"),
        );
        release(block);
    }
    // Joining a user namespace changed this process's credentials, which clears the parent-death
    // signal armed above; it is armed again for the credentials it now runs with.
    die_with(holder);

    // Best-effort: loopback up + the black-hole dummy. A failure here (e.g. the `dummy` kernel
    // module is unavailable) leaves a loopback-only namespace — the cage still launches, just
    // without the online signal — so it is never fatal.
    configure_dummy();

    // Stand the transparent-capture tap up, if the launcher wired one. Best-effort by design: the
    // tap is not a containment layer, so every failure here degrades to the environment-variable
    // egress path — which is what the cage had before this existed — rather than failing the
    // launch. The empty namespace and the host proxy are untouched either way.
    let tap = tap.and_then(wire_tap);
    let _ = write_byte(&block);
    drop(block);
    if let Some(mut tap) = tap {
        let _ = tap.wait();
    }
    std::process::exit(0);
}

/// Release the cage unconfigured and end the configurer. Closing the block pipe is enough to
/// release it; the byte is written first so bwrap reads a release rather than an end.
fn release(block: OwnedFd) -> ! {
    let _ = write_byte(&block);
    drop(block);
    std::process::exit(0);
}

/// Write one byte to `fd`, retrying an interrupted write.
fn write_byte(fd: &OwnedFd) -> io::Result<()> {
    loop {
        // SAFETY: `fd` is a live descriptor and the one-byte buffer outlives the call.
        let n = unsafe { libc::write(fd.as_raw_fd(), b"x".as_ptr().cast(), 1) };
        if n == 1 {
            return Ok(());
        }
        let e = io::Error::last_os_error();
        if e.kind() != io::ErrorKind::Interrupted {
            return Err(e);
        }
    }
}

/// Say the cage starts with its network namespace unconfigured, naming what that costs it.
fn unconfigured(tap: bool, why: &str) {
    if tap {
        degraded(why);
    } else {
        crate::diag::warn(&format!(
            "{why}; the cage runs without the `dummy0` interface, so a graphical app may report \
             itself offline"
        ));
    }
}

/// Close every descriptor of the configurer but its standard error and `keep`, and point its
/// standard input and output at `/dev/null`.
///
/// It is a fork of the holder, which holds the cage's own descriptors for bwrap — the memfds behind
/// its filters and its environment, its terminal, a launcher's output pipe. The configurer needs
/// none, and outlives bwrap's reading of them by the whole session when it serves the tap: a pipe
/// it kept would keep a reader of the cage's output waiting on an end that never came. Standard
/// error stays, so a warning reaches the launch's terminal as the holder's did.
fn keep_only(keep: &[RawFd]) {
    if let Ok(null) = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/null")
    {
        // SAFETY: `null` is a live descriptor; `dup2` replaces the standard input and output with
        // copies of it, closing what they named.
        unsafe {
            libc::dup2(null.as_raw_fd(), libc::STDIN_FILENO);
            libc::dup2(null.as_raw_fd(), libc::STDOUT_FILENO);
        }
    }
    let open: Vec<RawFd> = match std::fs::read_dir("/proc/self/fd") {
        Ok(dir) => dir
            .filter_map(|e| e.ok()?.file_name().to_str()?.parse().ok())
            .collect(),
        Err(_) => return,
    };
    for fd in open {
        if fd > libc::STDERR_FILENO && !keep.contains(&fd) {
            // SAFETY: `fd` was listed open in this process a moment ago and nothing in it is
            // owned by a value that would close it again — the listing's own descriptor is closed
            // already and fails harmlessly.
            unsafe { libc::close(fd) };
        }
    }
}

/// Arm `SIGKILL` for when the holder — by now the cage's bwrap — exits, then end at once if it
/// already has: the signal is armed against the parent at the time of the call, so a holder that
/// ended before it is caught by the check that follows.
fn die_with(holder: libc::pid_t) {
    // SAFETY: `prctl` with `PR_SET_PDEATHSIG` takes a signal number and touches no memory.
    unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) };
    // SAFETY: `getppid` takes no argument and cannot fail.
    if unsafe { libc::getppid() } != holder {
        std::process::exit(0);
    }
}

/// How long the configurer waits for bwrap to report its child. Far above what that costs (bwrap
/// reports it as soon as the child exists); it bounds a bwrap that hangs before, so the configurer
/// releases the cage rather than holding it.
const CHILD_PID_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// Read bwrap's `--info-fd` report until it names the child's pid, within `timeout`. An EOF before
/// that is `UnexpectedEof`: bwrap ended without starting a child.
fn read_child_pid(info: &OwnedFd, timeout: std::time::Duration) -> io::Result<libc::pid_t> {
    let deadline = std::time::Instant::now() + timeout;
    let mut seen = Vec::new();
    loop {
        if let Some(pid) = child_pid(&seen) {
            return Ok(pid);
        }
        let left = deadline.saturating_duration_since(std::time::Instant::now());
        if left.is_zero() {
            return Err(io::Error::from(io::ErrorKind::TimedOut));
        }
        let mut pfd = libc::pollfd {
            fd: info.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        let ms = libc::c_int::try_from(left.as_millis()).unwrap_or(libc::c_int::MAX);
        // SAFETY: `pfd` is one live `pollfd` the call reads and writes.
        let ready = unsafe { libc::poll(&mut pfd, 1, ms) };
        if ready < 0 {
            let e = io::Error::last_os_error();
            if e.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(e);
        }
        if ready == 0 {
            continue;
        }
        let mut buf = [0u8; 512];
        // SAFETY: `buf` is a live buffer of the length passed.
        let n = unsafe { libc::read(info.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len()) };
        match n {
            0 => return Err(io::Error::from(io::ErrorKind::UnexpectedEof)),
            n if n < 0 => {
                let e = io::Error::last_os_error();
                if e.kind() != io::ErrorKind::Interrupted {
                    return Err(e);
                }
            }
            n => seen.extend_from_slice(&buf[..n.unsigned_abs()]),
        }
    }
}

/// Read the rest of bwrap's `--info-fd` report, to its end, before the reading end is closed.
///
/// bwrap writes the report in several writes — the child's pid, then the ids of its namespaces,
/// then the closing brace — and the pid is all [`read_child_pid`] waits for. A reading end closed
/// after the first would have bwrap's next write meet a pipe with no reader, and the holder hands
/// bwrap `SIGPIPE` at its default ([`super::memfd::default_signals_across_exec`]): bwrap, and the
/// cage with it, would die of the signal before running anything, whenever the configurer won the
/// race. bwrap closes its end once the report is written, so the end is near; a report that does
/// not end within [`CHILD_PID_TIMEOUT`] leaves the reading end open for the rest of this process
/// rather than closed under a bwrap still writing.
fn finish_report(info: OwnedFd) {
    let deadline = std::time::Instant::now() + CHILD_PID_TIMEOUT;
    let mut buf = [0u8; 512];
    loop {
        let left = deadline.saturating_duration_since(std::time::Instant::now());
        let mut pfd = libc::pollfd {
            fd: info.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        let ms = libc::c_int::try_from(left.as_millis()).unwrap_or(libc::c_int::MAX);
        // SAFETY: `pfd` is one live `pollfd` the call reads and writes.
        let ready = unsafe { libc::poll(&mut pfd, 1, ms) };
        if ready == 0 || left.is_zero() {
            std::mem::forget(info);
            return;
        }
        if ready < 0 {
            if io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
                continue;
            }
            std::mem::forget(info);
            return;
        }
        // SAFETY: `buf` is a live buffer of the length passed.
        let n = unsafe { libc::read(info.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len()) };
        if n == 0 {
            return;
        }
        if n < 0 && io::Error::last_os_error().kind() != io::ErrorKind::Interrupted {
            std::mem::forget(info);
            return;
        }
    }
}

/// The `child-pid` member of a bwrap info report read so far, once its value is complete — that
/// is, once a character that is not a digit follows it, so a pid split across two reads is never
/// taken for its first digits.
fn child_pid(report: &[u8]) -> Option<libc::pid_t> {
    const KEY: &[u8] = b"\"child-pid\"";
    let at = report.windows(KEY.len()).position(|w| w == KEY)? + KEY.len();
    let rest = &report[at..];
    let colon = rest.iter().position(|&b| b == b':')?;
    if !rest[..colon].iter().all(u8::is_ascii_whitespace) {
        return None;
    }
    let value = &rest[colon + 1..];
    let start = value.iter().position(|b| !b.is_ascii_whitespace())?;
    let digits = value[start..]
        .iter()
        .take_while(|b| b.is_ascii_digit())
        .count();
    if digits == 0 || start + digits == value.len() {
        return None;
    }
    std::str::from_utf8(&value[start..start + digits])
        .ok()?
        .parse()
        .ok()
}

/// `NS_GET_USERNS` from `<linux/nsfs.h>`: `_IO(0xb7, 0x1)`, a descriptor for the user namespace
/// that owns the namespace the descriptor it is asked of refers to. Spelled out for the reason the
/// netlink constants below are: a frozen kernel ABI that `libc` does not expose on every target.
const NS_GET_USERNS: u64 = 0xb701;

/// Join the network namespace of `pid`, through the user namespace that owns it, and become root
/// there — which is what lets this process configure the namespace and hand a program it starts
/// (`nft`) the capabilities to do the same.
///
/// That user namespace is bwrap's outer one: created by bwrap, owned by the invoking uid, mapping
/// its root to that uid when the cage mounts a `/dev`. A process of the same uid in the parent namespace holds every capability
/// in it, which is what makes the join legal without creating anything. It is found by asking the
/// network namespace (`NS_GET_USERNS`), not assumed from the child's own user namespace: bwrap
/// nests a second one for the cage on most argument lists, and that one owns nothing.
///
/// A network namespace owned by the host's user namespace — a setuid bwrap creates it with real
/// privilege — is refused before any join: this process holds no capability there.
fn join_netns(pid: libc::pid_t) -> io::Result<()> {
    use std::os::unix::fs::MetadataExt;
    let net = std::fs::File::open(format!("/proc/{pid}/ns/net")).map_err(|e| {
        if e.kind() == io::ErrorKind::PermissionDenied {
            // A privileged bwrap's sandbox is not this user's to inspect: the kernel hides its
            // namespaces from a process without capabilities over it.
            io::Error::other(
                "bwrap runs privileged (setuid), so its sandbox is not this user's to join",
            )
        } else {
            e
        }
    })?;
    // SAFETY: `net` is a live namespace descriptor; `NS_GET_USERNS` takes no argument and returns a
    // new descriptor or `-1`.
    let owner = unsafe { libc::ioctl(net.as_raw_fd(), NS_GET_USERNS as _) };
    if owner < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `owner` was just returned by the kernel and is owned by nothing else.
    let owner = unsafe { OwnedFd::from_raw_fd(owner) };
    let owner = std::fs::File::from(owner);
    let ours = std::fs::metadata("/proc/self/ns/user")?;
    let theirs = owner.metadata()?;
    if (ours.dev(), ours.ino()) == (theirs.dev(), theirs.ino()) {
        return Err(io::Error::other(
            "it belongs to the host's user namespace, where sbx holds no capability (a setuid \
             bwrap creates it so)",
        ));
    }
    for (fd, kind) in [
        (owner.as_raw_fd(), libc::CLONE_NEWUSER),
        (net.as_raw_fd(), libc::CLONE_NEWNET),
    ] {
        // SAFETY: `fd` is a live namespace descriptor of the kind named; the call changes only this
        // process's own namespace and reports a refusal through its return value.
        if unsafe { libc::setns(fd, kind) } != 0 {
            return Err(io::Error::last_os_error());
        }
    }
    mapped(pid, ID_MAP_TIMEOUT)?;
    // SAFETY: `setresgid`/`setresuid` take three ids and touch no memory. Becoming root is what
    // keeps the capabilities across the `execve` of `nft`.
    if unsafe { libc::setresgid(0, 0, 0) } != 0 || unsafe { libc::setresuid(0, 0, 0) } != 0 {
        let e = io::Error::last_os_error();
        // bwrap maps root in its outer namespace when it has to mount a `/dev` there, which every
        // launch's cage does; a namespace it created for no such mount maps the invoking uid alone.
        if e.raw_os_error() == Some(libc::EINVAL) {
            return Err(io::Error::other(
                "its user namespace maps no root to configure it as (a bwrap given no `--dev`)",
            ));
        }
        return Err(e);
    }
    Ok(())
}

/// How long [`mapped`] waits for bwrap to write the identity maps of the namespace just joined.
/// bwrap writes them right after reporting its child; this bounds a bwrap that never does.
const ID_MAP_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// Wait until the user namespace this process is in has both its uid and its gid map written.
///
/// bwrap reports its child on the info pipe *before* it writes the maps of the user namespace that
/// child was cloned into, so a configurer that joins on the report can arrive while they are still
/// empty — and an id that no map names cannot be taken: `setresgid(0, …)` fails with `EINVAL`.
///
/// A bwrap child that is gone before they are written will never write them — the bwrap that
/// failed to map them has ended — so its end is the answer, not the timeout.
fn mapped(pid: libc::pid_t, timeout: std::time::Duration) -> io::Result<()> {
    let deadline = std::time::Instant::now() + timeout;
    let written =
        |map: &str| std::fs::read_to_string(map).is_ok_and(|text| !text.trim().is_empty());
    while !(written("/proc/self/uid_map") && written("/proc/self/gid_map")) {
        if !alive(pid) {
            return Err(io::Error::other(
                "bwrap ended before it mapped the namespace's identities",
            ));
        }
        if std::time::Instant::now() >= deadline {
            return Err(io::Error::other(
                "bwrap did not map the namespace's identities in time",
            ));
        }
        std::thread::sleep(std::time::Duration::from_millis(1));
    }
    Ok(())
}

/// Whether `pid` still runs: listed, and neither a zombie nor dead. The state is the field after
/// the command name's closing parenthesis, which is found from the end because the name itself may
/// hold one.
fn alive(pid: libc::pid_t) -> bool {
    std::fs::read_to_string(format!("/proc/{pid}/stat")).is_ok_and(|stat| {
        stat.rsplit_once(')')
            .and_then(|(_, rest)| rest.trim_start().chars().next())
            .is_some_and(|state| !matches!(state, 'Z' | 'X'))
    })
}

/// What `__net-probe` exits with when the namespace itself was refused. Distinct from the status of
/// refused redirect rules, so a caller tells the two apart by the status and never by the wording.
const PROBE_NAMESPACE_REFUSED: i32 = 3;

/// The `__net-probe` subcommand body: answer whether sbx can configure the network namespace a
/// bwrap creates and, given an `nft`, whether that namespace takes the redirect rules — by starting
/// a throwaway bwrap, joining its namespace the way the configurer does ([`join_netns`]) and
/// installing them there. The bwrap is killed before it ever runs its command, so nothing is left
/// behind and the host's own networking is never touched.
///
/// It exists as a subcommand because the question cannot be answered in-process: `setns` is not
/// something `doctor` or a launch may do to itself. `argv` is `[<bwrap>]` for the namespace alone,
/// or `[<bwrap>, <nft>]` for the namespace and the rules. A refused namespace exits
/// [`PROBE_NAMESPACE_REFUSED`], refused rules exit 1.
pub(crate) fn run_probe(argv: &[OsString]) -> ! {
    let refused = |why: &str| -> ! {
        errln!("{why}");
        std::process::exit(PROBE_NAMESPACE_REFUSED);
    };
    let Some(bwrap) = argv.first() else {
        refused("__net-probe: no bubblewrap to probe with");
    };
    if let Err(e) = single_threaded() {
        refused(&format!("__net-probe: {e}"));
    }
    let _ = unprivileged_for(Path::new(bwrap));
    let (mut cage, pid, block, info) = match throwaway_cage(Path::new(bwrap)) {
        Ok(started) => started,
        Err(e) => refused(&format!(
            "bubblewrap did not start a sandbox to probe ({e})"
        )),
    };
    let verdict = match join_netns(pid) {
        Err(e) => Err((
            PROBE_NAMESPACE_REFUSED,
            format!("the cage's network namespace could not be joined ({e})"),
        )),
        Ok(()) => match argv.get(1) {
            None => Ok(()),
            Some(nft) => {
                super::nettap::install_redirect(Path::new(nft)).map_err(|e| (1, e.to_string()))
            }
        },
    };
    // Killed while it still waits on the block pipe, which is closed only after: the command it was
    // given never runs. The info pipe is held as long, so bwrap never writes its report to a pipe
    // with no reader ([`finish_report`]).
    let _ = cage.kill();
    let _ = cage.wait();
    drop(block);
    drop(info);
    match verdict {
        Ok(()) => std::process::exit(0),
        Err((code, why)) => {
            errln!("{why}");
            std::process::exit(code);
        }
    }
}

/// Start `bwrap` with the namespaces a cage gets and hold it before its command, returning
/// it, its child's pid, the block pipe's write end that holds it, and the info pipe's reading end.
fn throwaway_cage(
    bwrap: &Path,
) -> io::Result<(std::process::Child, libc::pid_t, OwnedFd, OwnedFd)> {
    let (info_r, info_w, block_r, block_w) = sync_pipes()?;
    let argv = with_sync_fds(
        &[
            bwrap.as_os_str().to_owned(),
            OsString::from("--unshare-user"),
            OsString::from("--unshare-net"),
            OsString::from("--die-with-parent"),
            // Every launch's cage mounts a fresh `/dev`, which is what has bwrap map root in the
            // namespace the configurer joins; without it the probe would answer for another one.
            OsString::from("--dev"),
            OsString::from("/dev"),
            OsString::from("--"),
            OsString::from("/nonexistent"),
        ],
        info_w.as_raw_fd(),
        block_r.as_raw_fd(),
    );
    let mut cage = std::process::Command::new(&argv[0])
        .args(&argv[1..])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        // Piped for the one case it is read: a bwrap that ends before it reports a child says why
        // on its standard error, and that is the answer the probe gives.
        .stderr(std::process::Stdio::piped())
        .spawn()?;
    drop(info_w);
    drop(block_r);
    match read_child_pid(&info_r, CHILD_PID_TIMEOUT) {
        Ok(pid) => Ok((cage, pid, block_w, info_r)),
        Err(e) => {
            let _ = cage.kill();
            let said = cage
                .wait_with_output()
                .map(|out| String::from_utf8_lossy(&out.stderr).trim().to_string())
                .unwrap_or_default();
            if said.is_empty() {
                Err(e)
            } else {
                Err(io::Error::other(said))
            }
        }
    }
}

/// What a throwaway `__net-probe` found.
pub(super) enum Probe {
    /// The namespace was joined and, when an `nft` was given, took the redirect rules.
    Passed,
    /// sbx could not configure the namespace, with the probe's words. A launch then runs without
    /// the holder: see [`probe_namespace`].
    NamespaceRefused(String),
    /// The namespace was joined and `nft` refused the rules in it, with its words.
    RulesRefused(String),
}

/// Run `<exe> __net-probe <bwrap> [<nft>]` and classify what it found, by its exit status.
///
/// A probe that cannot be started at all reads as a refused namespace: nothing proved the
/// namespace can be configured, and the launch reads the same answer, so the two stay in step.
pub(super) fn probe(exe: &Path, bwrap: &Path, nft: Option<&Path>) -> Probe {
    let mut cmd = std::process::Command::new(exe);
    cmd.arg("__net-probe").arg(bwrap);
    if let Some(nft) = nft {
        cmd.arg(nft);
    }
    let out = match cmd
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .output()
    {
        Ok(out) => out,
        Err(e) => return Probe::NamespaceRefused(format!("the probe could not run ({e})")),
    };
    if out.status.success() {
        return Probe::Passed;
    }
    let why = String::from_utf8_lossy(&out.stderr).trim().to_string();
    let why = if why.is_empty() {
        "the probe failed without saying why".to_string()
    } else {
        why
    };
    if out.status.code() == Some(PROBE_NAMESPACE_REFUSED) {
        Probe::NamespaceRefused(why)
    } else {
        Probe::RulesRefused(why)
    }
}

/// Whether sbx can configure the network namespace the launch's `bwrap` creates, asked of a
/// throwaway [`probe`] so the answer is the kernel's, reached through the steps the configurer
/// takes.
///
/// Asked before a launch chooses the holder, never by the holder itself. A configurer that fails
/// would leave the cage in bwrap's empty namespace anyway, but the cage's `/etc/resolv.conf` names
/// the tap's resolver only when the holder is chosen, and a cage whose tap could never stand up
/// would be left with no DNS at all. `Err` carries the probe's words.
pub(super) fn probe_namespace(exe: &Path, bwrap: &Path) -> Result<(), String> {
    match probe(exe, bwrap, None) {
        Probe::Passed => Ok(()),
        Probe::NamespaceRefused(why) | Probe::RulesRefused(why) => Err(why),
    }
}

/// Start the tap and point the namespace's traffic at it.
///
/// Order matters and is the reason the tap announces itself: the rules are installed **after** it
/// reports every listener bound, so no connection is ever bent toward a port with nothing behind it.
/// A tap that never reports leaves the rules uninstalled, which is exactly the degraded mode.
///
/// The tap runs in a cage of its own ([`tap_cage`]), started by the configurer once it has joined
/// the cage's network namespace, so it shares that namespace and nothing else of the configurer:
/// not the host's mount or pid namespaces, not the capabilities the configurer holds over the
/// namespace, and under a filter of its own ([`crate::sandbox::seccomp::tap`]). `PR_SET_PDEATHSIG`
/// ties it to the configurer, which is tied to the cage's `bwrap` the same way: when the cage ends,
/// so does the tap. Returned so the configurer can wait on it; `None` is the degraded mode, already
/// announced.
fn wire_tap(tap: &TapWiring) -> Option<std::process::Child> {
    let mut child = match start_tap(tap) {
        Ok(child) => child,
        Err(e) => {
            degraded(&format!("cannot start the capture tap ({e})"));
            return None;
        }
    };
    if let Err(e) = tap_is_ready(&mut child) {
        let _ = child.kill();
        let _ = child.wait();
        let said = match tap_said(&mut child) {
            said if said.is_empty() => said,
            said => format!("; it said: {said}"),
        };
        degraded(&format!("the capture tap did not come up ({e}{said})"));
        return None;
    }
    // The tap's words matter only while it comes up. The configurer waits on the tap for the whole
    // session, so a pipe it kept reading nothing from would fill and block a tap that wrote to it;
    // with the reading end gone, a later write fails and is dropped.
    drop(child.stderr.take());
    if let Err(e) = super::nettap::install_redirect(&tap.nft) {
        let _ = child.kill();
        let _ = child.wait();
        degraded(&format!("{e}"));
        return None;
    }
    // Last, and only now: the route that gives a connect somewhere to go. The redirect is already
    // in place, so the first packet that could use this route is bent to the tap before it is sent.
    //
    // A failure here is the one branch where tearing down is the wrong instinct. Without the route,
    // the kernel's route lookup — which precedes the `nat` `OUTPUT` hook for locally generated
    // traffic — refuses every connect with `ENETUNREACH` before netfilter is consulted at all. The
    // rules and the tap are therefore unreachable rather than harmful, and the cage behaves exactly
    // as it did before capture existed. Killing the tap would change nothing for the cage and would
    // open a window where a connect could arrive at a port that had just stopped listening.
    if let Err(e) = with_netlink(add_default_route) {
        degraded(&format!("the capture route could not be installed ({e})"));
    }
    Some(child)
}

/// Start the tap in its cage, with the standard streams [`tap_stdio`] gives it.
fn start_tap(tap: &TapWiring) -> io::Result<std::process::Child> {
    let (binary, copy) = super::selfcage::running()?;
    // A copy of the report channel's end of the tap's own, which its command carries to its exec
    // and to no other; the configurer's copy stays close-on-exec, and the holder's was closed on its
    // exec, so the cage holds none.
    let report = tap
        .report
        .as_ref()
        .map(super::nettap::ReportChannel::dup)
        .transpose()?
        .map(std::fs::File::from);
    let spec = tap_cage(
        binary.as_raw_fd(),
        copy,
        &tap.uds,
        report.as_ref().map(AsRawFd::as_raw_fd),
    )?;
    let mut cage = super::selfcage::command(&tap.bwrap, &spec, binary)?;
    if let Some(report) = report {
        cage.hand(report);
    }
    // The configurer has closed every descriptor of the holder's but the two pipes and the report
    // end, which are close-on-exec: the tap is handed its own files and nothing else.
    let mut cmd = cage.into_command_alone();
    let child = tap_stdio(&mut cmd).pre_exec_pdeathsig().spawn();
    // Read by bwrap by now, or never; closed here, so the configurer holds none for the session.
    drop(cmd);
    child
}

/// The tap's standard streams, none of them the configurer's: in a launch on a terminal, its
/// standard error is the cage's terminal, which the tap has no business reading or writing. Its
/// standard input is empty, standard output is the pipe it says it serves on, and standard error is
/// a pipe whose words reach the person only when the tap does not come up, inside the warning that
/// says so ([`tap_said`]). Once the tap is up the configurer drops the pipe's reading end, and
/// anything the tap writes there later is dropped.
fn tap_stdio(cmd: &mut std::process::Command) -> &mut std::process::Command {
    cmd.stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
}

/// Where the tap's cage binds the egress socket.
const TAP_EGRESS: &str = "/egress.sock";

/// The cage the tap runs in ([`super::selfcage::spec`]): nothing of the host but the read-only
/// userland, the binary, and the egress socket the tap dials, read-only at a fixed path, which the
/// cage already reaches. `report_fd` is the number of the report channel's end its command carries
/// (bubblewrap hands the command a descriptor it was not told about at the number it had), named
/// in the tap's arguments.
///
/// Its network is shared, and shared with the process that starts its `bwrap`: that is what puts
/// the tap in the cage's namespace, where the redirect sends it the cage's traffic. It is sound here
/// and nowhere else, because only the configurer starts it, and only once it has joined the cage's
/// namespace. The same spec started from any other process would share the host's network, which
/// is why this is private to the holder.
fn tap_cage(
    binary: std::os::fd::RawFd,
    copy: bool,
    uds: &Path,
    report_fd: Option<RawFd>,
) -> io::Result<super::spec::SandboxSpec> {
    let mounts = vec![super::spec::Mount::RoBind {
        src: uds.to_path_buf(),
        dest: TAP_EGRESS.into(),
    }];
    let mut args = vec![OsString::from("__net-tap"), OsString::from(TAP_EGRESS)];
    if let Some(fd) = report_fd {
        args.extend([
            OsString::from("--report-fd"),
            OsString::from(fd.to_string()),
        ]);
    }
    super::selfcage::spec(
        "the capture tap",
        binary,
        copy,
        mounts,
        super::spec::NetPolicy::Shared,
        args,
    )
}

/// Run one netlink operation against `dummy0`, opening and closing the socket around it.
fn with_netlink(op: impl Fn(libc::c_int, u32) -> io::Result<()>) -> io::Result<()> {
    let fd = nl_open()?;
    let index =
        if_index("dummy0").ok_or_else(|| io::Error::other("the cage has no `dummy0` interface"))?;
    let out = op(fd, index);
    // SAFETY: `fd` is this function's own netlink socket, opened above and used nowhere else.
    unsafe { libc::close(fd) };
    out
}

/// Wait for the tap's readiness line, bounded so a tap that hangs cannot hold the launch.
fn tap_is_ready(child: &mut std::process::Child) -> std::io::Result<()> {
    use std::io::{BufRead, BufReader};
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| std::io::Error::other("no pipe to the tap"))?;
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let mut line = String::new();
        let read = BufReader::new(stdout).read_line(&mut line);
        let _ = tx.send(read.map(|_| line));
    });
    match rx.recv_timeout(TAP_READY_TIMEOUT) {
        Ok(Ok(line)) if line.trim() == super::nettap::READY => Ok(()),
        Ok(Ok(line)) => Err(std::io::Error::other(format!(
            "unexpected greeting {:?}",
            line.trim()
        ))),
        Ok(Err(e)) => Err(e),
        Err(_) => Err(std::io::Error::other("timed out")),
    }
}

/// What the tap wrote to its standard error, for the warning that says it did not come up: its own
/// reason, such as a port already taken or a filter that did not install, or its cage's. Read once
/// the tap has been stopped, and for [`TAP_SAID_WAIT`] at most, since a process of its cage that
/// outlived it would hold the pipe open; whatever arrived by then is what is said, one line after
/// another with the characters that could rewrite the warning taken out.
fn tap_said(child: &mut std::process::Child) -> String {
    use std::io::Read;
    use std::sync::{Arc, Mutex};
    let Some(mut stderr) = child.stderr.take() else {
        return String::new();
    };
    let heard = Arc::new(Mutex::new(Vec::new()));
    let (done, finished) = std::sync::mpsc::channel::<()>();
    {
        let heard = Arc::clone(&heard);
        std::thread::spawn(move || {
            let mut chunk = [0u8; 512];
            loop {
                let n = match stderr.read(&mut chunk) {
                    Ok(0) => break,
                    Ok(n) => n,
                    Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                    Err(_) => break,
                };
                let mut heard = match heard.lock() {
                    Ok(heard) => heard,
                    Err(poisoned) => poisoned.into_inner(),
                };
                let room = TAP_SAID_MAX.saturating_sub(heard.len());
                heard.extend_from_slice(&chunk[..n.min(room)]);
                if n >= room {
                    break;
                }
            }
            drop(done);
        });
    }
    let _ = finished.recv_timeout(TAP_SAID_WAIT);
    let heard = match heard.lock() {
        Ok(heard) => heard.clone(),
        Err(poisoned) => poisoned.into_inner().clone(),
    };
    String::from_utf8_lossy(&heard)
        .lines()
        .map(super::observe_feed::sanitize)
        .filter(|line| !line.trim().is_empty())
        .collect::<Vec<_>>()
        .join("; ")
}

/// How much of the tap's standard error [`tap_said`] keeps: a reason, not a transcript.
const TAP_SAID_MAX: usize = 4096;

/// How long [`tap_said`] waits for the tap's standard error to close.
const TAP_SAID_WAIT: std::time::Duration = std::time::Duration::from_millis(500);

/// How long the configurer waits for the tap to report it serves: its cage started, its three loopback
/// sockets bound and its filter installed. Far above what that costs; it bounds a tap that hangs on
/// the way, so the launch degrades in a moment rather than stalling. One that fails outright (a
/// port already taken, a filter that does not install) exits at once and is not waited for.
const TAP_READY_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// Say why the cage is launching without transparent capture, then carry on. Never fatal: the
/// difference is that a proxy-blind client fails at `connect(2)` instead of being named, which is
/// the behaviour every cage had before the tap existed.
fn degraded(why: &str) {
    // A warning, never an error: the launch succeeds and filters exactly as before, so this belongs
    // to the same channel as any other piece of hardening that could not be applied. `sbx doctor`
    // classes capture the same way, and the guide says launches are unaffected — three statements
    // that have to agree.
    crate::diag::warn(&format!(
        "transparent capture unavailable ({why}); a client that ignores the proxy variables will \
         fail to connect rather than be routed"
    ));
}

/// `Command::pre_exec` with the one call the tap needs between fork and exec.
trait PreExecPdeathsig {
    fn pre_exec_pdeathsig(&mut self) -> &mut Self;
}

impl PreExecPdeathsig for std::process::Command {
    fn pre_exec_pdeathsig(&mut self) -> &mut Self {
        use std::os::unix::process::CommandExt;
        // SAFETY: the closure runs in the forked child before `execve`, where only
        // async-signal-safe calls are allowed. `prctl` is one: it takes no allocation, no lock and
        // no pointer into this process's heap, and its failure is ignored (the tap would then
        // outlive the cage only until its own reads fail).
        unsafe {
            self.pre_exec(|| {
                libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGTERM);
                Ok(())
            })
        }
    }
}

// Netlink protocol constants (stable Linux UAPI from <linux/netlink.h>, <linux/rtnetlink.h>,
// <linux/if_link.h>, <linux/if_addr.h>). Defined here rather than pulled from `libc`: the wire
// numbers are a frozen kernel ABI, and the attribute-type constants in particular are not uniformly
// exposed across `libc` versions, so a local, self-documenting block is the more auditable choice.
const NLM_F_REQUEST: u16 = 0x001;
const NLM_F_ACK: u16 = 0x004;
const NLM_F_EXCL: u16 = 0x200;
const NLM_F_CREATE: u16 = 0x400;
const NLMSG_ERROR: u16 = 0x2;
const RTM_NEWLINK: u16 = 16;
const RTM_NEWADDR: u16 = 20;
const RTM_NEWROUTE: u16 = 24;
const IFLA_IFNAME: u16 = 3;
const IFLA_LINKINFO: u16 = 18;
const IFLA_INFO_KIND: u16 = 1; // nested inside IFLA_LINKINFO
const IFA_ADDRESS: u16 = 1;
const RTA_OIF: u16 = 4;
const RTA_GATEWAY: u16 = 5;
/// `RT_SCOPE_UNIVERSE`, `RTPROT_STATIC`, `RTN_UNICAST` and the main table id: the ordinary shape of
/// a default route, spelled out for the same reason the constants above are.
const RT_TABLE_MAIN: u8 = 254;
const RTPROT_STATIC: u8 = 4;
const RT_SCOPE_UNIVERSE: u8 = 0;
const RTN_UNICAST: u8 = 1;
const IFA_LOCAL: u16 = 2;

/// The fixed byte length of a `nlmsghdr` (u32 len, u16 type, u16 flags, u32 seq, u32 pid).
const NLMSG_HDR_LEN: usize = 16;
/// The fixed byte length of an `rtattr` header (u16 len, u16 type).
const RTA_HDR_LEN: usize = 4;

/// Bring up loopback and add the black-hole `dummy0` interface, speaking `NETLINK_ROUTE` directly so
/// the holder depends on no host `ip` binary (sbx is otherwise self-contained). Best-effort
/// throughout: the configurer runs in the cage's network namespace, through the user namespace
/// that owns it, where it holds `CAP_NET_ADMIN`, and
/// any single failure (no netlink socket, the `dummy` kernel module absent) simply leaves a
/// loopback-only namespace — exactly what `--unshare-net` alone would have produced.
fn configure_dummy() {
    let fd = match nl_open() {
        Ok(fd) => fd,
        Err(_) => return,
    };
    // Four independent operations, each ignored on failure (mirrors the degrade-per-step behaviour of
    // the equivalent `ip` commands: lo up, create dummy0, give it the address, dummy0 up).
    if let Some(lo) = if_index("lo") {
        let _ = set_link_up(fd, lo);
    }
    let _ = create_dummy(fd);
    if let Some(idx) = if_index("dummy0") {
        let _ = add_dummy_addr(fd, idx);
        let _ = set_link_up(fd, idx);
    }
    // SAFETY: `fd` is the netlink socket `nl_open` handed this function, which is its only owner
    // and has not closed it — every use above is done.
    unsafe { libc::close(fd) };
}

/// Open a `NETLINK_ROUTE` socket. `SOCK_CLOEXEC` so it can never leak into the tap the configurer
/// starts (it is also closed explicitly once configuration is done).
fn nl_open() -> io::Result<libc::c_int> {
    // SAFETY: `socket` takes three integer arguments and returns a descriptor or `-1`; no pointer
    // is involved.
    let fd = unsafe {
        libc::socket(
            libc::AF_NETLINK,
            libc::SOCK_RAW | libc::SOCK_CLOEXEC,
            libc::NETLINK_ROUTE,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(fd)
}

/// The kernel index of an interface by name, or `None` if it does not exist in this namespace.
fn if_index(name: &str) -> Option<u32> {
    let c = CString::new(name).ok()?;
    // SAFETY: `c` is a live NUL-terminated interface name the call only reads; a name that does not
    // exist in this namespace is answered with `0`.
    let idx = unsafe { libc::if_nametoindex(c.as_ptr()) };
    (idx != 0).then_some(idx)
}

/// Set an interface's `IFF_UP` flag (an `RTM_NEWLINK` that modifies, not creates — no `NLM_F_CREATE`).
fn set_link_up(fd: libc::c_int, index: u32) -> io::Result<()> {
    let up = libc::IFF_UP as u32;
    nl_request(fd, RTM_NEWLINK, 0, &ifinfomsg(index, up, up))
}

/// Create the `dummy0` interface (`RTM_NEWLINK` with the `dummy` link kind).
fn create_dummy(fd: libc::c_int) -> io::Result<()> {
    nl_request(
        fd,
        RTM_NEWLINK,
        NLM_F_CREATE | NLM_F_EXCL,
        &create_dummy_body(),
    )
}

/// Assign the black-hole address to `dummy0` (`RTM_NEWADDR`). The prefix installs only the connected
/// /24 route; no default route is added, so this never becomes an egress path.
fn add_dummy_addr(fd: libc::c_int, index: u32) -> io::Result<()> {
    nl_request(
        fd,
        RTM_NEWADDR,
        NLM_F_CREATE | NLM_F_EXCL,
        &addr_body(index),
    )
}

// ---- pure wire-format builders (unit-tested) -------------------------------------------------

/// A 16-byte `ifinfomsg` body: family `AF_UNSPEC`, the given interface index, and a flags/change pair
/// (`change` is the mask of which flag bits `flags` applies).
fn ifinfomsg(index: u32, flags: u32, change: u32) -> Vec<u8> {
    let mut b = Vec::with_capacity(NLMSG_HDR_LEN);
    b.push(libc::AF_UNSPEC as u8); // ifi_family
    b.push(0); // padding
    b.extend_from_slice(&0u16.to_ne_bytes()); // ifi_type
    b.extend_from_slice(&(index as i32).to_ne_bytes()); // ifi_index
    b.extend_from_slice(&flags.to_ne_bytes()); // ifi_flags
    b.extend_from_slice(&change.to_ne_bytes()); // ifi_change
    b
}

/// Install a default route through the black-hole `dummy0`, so a connect to any address has
/// somewhere to go.
///
/// Only ever called when the capture tap is standing, and that gate is the whole point. For a
/// locally generated packet the kernel looks the route up **before** the `nat` `OUTPUT` hook runs,
/// so without a route a connect fails `ENETUNREACH` and the redirect rule is never consulted: the
/// tap would listen to silence. With the tap, a TCP connect and a DNS query are bent to loopback
/// before a packet reaches `dummy0` at all.
///
/// Everything else — UDP to any port but 53, and every other L4 protocol — is refused by the
/// `filter` chain of [`super::nettap::redirect_ruleset`], which is installed with the redirect and
/// is what keeps this route from becoming an egress path. Without that refusal the packets would
/// reach the dummy, which drops them, turning a fast, legible `ENETUNREACH` into a silent timeout;
/// adding the route without the whole ruleset would therefore be a regression rather than a gift.
fn add_default_route(fd: libc::c_int, index: u32) -> io::Result<()> {
    nl_request(
        fd,
        RTM_NEWROUTE,
        NLM_F_CREATE | NLM_F_EXCL,
        &default_route_body(index),
    )
}

/// The `RTM_NEWROUTE` body: an `rtmsg` with a zero destination prefix (that is what makes it the
/// default route), then the gateway and the output interface.
fn default_route_body(index: u32) -> Vec<u8> {
    let mut body = Vec::with_capacity(12);
    body.push(libc::AF_INET as u8); // rtm_family
    body.push(0); // rtm_dst_len: 0 = the default route
    body.push(0); // rtm_src_len
    body.push(0); // rtm_tos
    body.push(RT_TABLE_MAIN); // rtm_table
    body.push(RTPROT_STATIC); // rtm_protocol
    body.push(RT_SCOPE_UNIVERSE); // rtm_scope
    body.push(RTN_UNICAST); // rtm_type
    body.extend_from_slice(&0u32.to_ne_bytes()); // rtm_flags
    push_attr(&mut body, RTA_GATEWAY, &GATEWAY_OCTETS);
    push_attr(&mut body, RTA_OIF, &index.to_ne_bytes());
    body
}

/// The gateway the default route names: another address inside the dummy's own `/24`, so it is
/// reachable through the connected route the address installs and needs no interface of its own.
/// Nothing answers at it, and nothing has to: every packet is redirected before it is sent.
const GATEWAY_OCTETS: [u8; 4] = [DUMMY_OCTETS[0], DUMMY_OCTETS[1], DUMMY_OCTETS[2], 1];

/// The `RTM_NEWLINK` body that creates `dummy0`: an `ifinfomsg` (index 0 = kernel-assigned, no flags)
/// followed by `IFLA_IFNAME` and an `IFLA_LINKINFO` nesting `IFLA_INFO_KIND = "dummy"`.
fn create_dummy_body() -> Vec<u8> {
    let mut body = ifinfomsg(0, 0, 0);
    push_attr(&mut body, IFLA_IFNAME, b"dummy0\0");
    let mut linkinfo = Vec::new();
    push_attr(&mut linkinfo, IFLA_INFO_KIND, b"dummy\0");
    push_attr(&mut body, IFLA_LINKINFO, &linkinfo);
    body
}

/// The `RTM_NEWADDR` body: an 8-byte `ifaddrmsg` (AF_INET, the /24 prefix, the interface index)
/// followed by `IFA_LOCAL` and `IFA_ADDRESS`, both the dummy octets.
fn addr_body(index: u32) -> Vec<u8> {
    let mut body = Vec::with_capacity(8);
    body.push(libc::AF_INET as u8); // ifa_family
    body.push(DUMMY_PREFIX); // ifa_prefixlen
    body.push(0); // ifa_flags
    body.push(0); // ifa_scope (RT_SCOPE_UNIVERSE)
    body.extend_from_slice(&index.to_ne_bytes()); // ifa_index
    push_attr(&mut body, IFA_LOCAL, &DUMMY_OCTETS);
    push_attr(&mut body, IFA_ADDRESS, &DUMMY_OCTETS);
    body
}

/// Append one `rtattr` TLV — a 4-byte header (`rta_len`, `rta_type`) then the payload — padded to the
/// 4-byte netlink alignment. `rta_len` records the unpadded length, per the ABI.
fn push_attr(buf: &mut Vec<u8>, ty: u16, payload: &[u8]) {
    let len = RTA_HDR_LEN + payload.len();
    buf.extend_from_slice(&(len as u16).to_ne_bytes()); // rta_len
    buf.extend_from_slice(&ty.to_ne_bytes()); // rta_type
    buf.extend_from_slice(payload);
    buf.resize(buf.len() + (align4(len) - len), 0); // pad to 4-byte alignment
}

/// Round a length up to the 4-byte netlink alignment.
fn align4(n: usize) -> usize {
    (n + 3) & !3
}

// ---- socket exchange -------------------------------------------------------------------------

/// Send one request (a `nlmsghdr` framing `body`) with `NLM_F_ACK` and read the kernel's ACK. The
/// exchange is strictly serialized (send then recv before the next send), so a fixed sequence number
/// is unambiguous. A negative error in the `NLMSG_ERROR` reply becomes an `Err`.
fn nl_request(fd: libc::c_int, msg_type: u16, extra_flags: u16, body: &[u8]) -> io::Result<()> {
    let len = NLMSG_HDR_LEN + body.len();
    let mut buf = Vec::with_capacity(len);
    buf.extend_from_slice(&(len as u32).to_ne_bytes()); // nlmsg_len
    buf.extend_from_slice(&msg_type.to_ne_bytes()); // nlmsg_type
    buf.extend_from_slice(&(NLM_F_REQUEST | NLM_F_ACK | extra_flags).to_ne_bytes()); // nlmsg_flags
    buf.extend_from_slice(&1u32.to_ne_bytes()); // nlmsg_seq
    buf.extend_from_slice(&0u32.to_ne_bytes()); // nlmsg_pid (kernel fills its own)
    buf.extend_from_slice(body);

    // SAFETY: `fd` is the caller's live netlink socket, and the pointer/length pair is `buf`'s own
    // — a `Vec` alive across the call, from which `send` only reads.
    let sent = unsafe { libc::send(fd, buf.as_ptr().cast(), buf.len(), 0) };
    if sent < 0 {
        return Err(io::Error::last_os_error());
    }
    read_ack(fd)
}

/// Read a kernel reply and interpret an `NLMSG_ERROR` payload: `error == 0` is the success ACK, a
/// negative value is `-errno`.
fn read_ack(fd: libc::c_int) -> io::Result<()> {
    let mut rbuf = [0u8; 1024];
    // SAFETY: `fd` is the caller's live netlink socket, and `rbuf` is a live stack array whose own
    // length bounds what the kernel may write into it.
    let n = unsafe { libc::recv(fd, rbuf.as_mut_ptr().cast(), rbuf.len(), 0) };
    if n < 0 {
        return Err(io::Error::last_os_error());
    }
    let n = n as usize;
    // An NLMSG_ERROR payload is the 16-byte header, then an i32 error, then the offending header.
    if n < NLMSG_HDR_LEN + 4 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "short netlink reply",
        ));
    }
    let msg_type = u16::from_ne_bytes([rbuf[4], rbuf[5]]);
    if msg_type == NLMSG_ERROR {
        let err = i32::from_ne_bytes([rbuf[16], rbuf[17], rbuf[18], rbuf[19]]);
        if err != 0 {
            return Err(io::Error::from_raw_os_error(-err));
        }
    }
    Ok(())
}

fn to_cstring(s: &OsString) -> CString {
    CString::new(s.as_bytes()).unwrap_or_else(|_| {
        die(
            NEVER_STARTED,
            &format!("__netns-holder: argument contains a NUL byte: {s:?}"),
        )
    })
}

/// What the holder exits with when it never reached the command it was asked to become.
///
/// This process *becomes* the cage — it execs bwrap — so whatever it exits with is read as the
/// cage's own answer about that command. `125` is the number the launch path spells
/// `CAGE_NEVER_STARTED` and `sbx task run` documents for a refusal that ran nothing, and it leaves
/// the shell's own two answers to the cage.
const NEVER_STARTED: i32 = 125;

/// What the holder exits with when the `execv` itself failed: the shell convention for a program
/// that could not be found, which is what has actually happened at that one site.
const EXEC_FAILED: i32 = 127;

/// End the holder with `msg` on stderr and `code` as its status.
///
/// The code is a parameter because this function serves both of the above, and spelling them all
/// `127` had a namespace setup that failed report itself as bwrap being missing — the one reading
/// that sends a caller after the wrong thing.
fn die(code: i32, msg: &str) -> ! {
    errln!("{msg}");
    std::process::exit(code);
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The tap holds none of this process's standard streams, which in a launch on a terminal are
    /// the cage's terminal: its standard error is a pipe of its own. What it wrote there, its reason
    /// for not coming up, is quoted in the warning one line after another, with the characters that
    /// could rewrite that warning taken out.
    #[test]
    fn the_tap_writes_to_a_pipe_of_its_own_and_its_reason_is_quoted() {
        let mut cmd = std::process::Command::new("sh");
        cmd.args([
            "-c",
            "printf 'bwrap: \\033[2Jcleared\\n__net-tap: Address already in use\\n' >&2; exit 1",
        ]);
        let mut child = tap_stdio(&mut cmd).spawn().expect("spawn a stand-in tap");
        assert!(
            child.stdin.is_none(),
            "standard input is empty, not this process's"
        );
        assert!(
            child.stdout.is_some(),
            "standard output is the readiness pipe"
        );
        assert!(
            child.stderr.is_some(),
            "standard error is a pipe, not this process's"
        );
        let _ = child.wait();
        assert_eq!(
            tap_said(&mut child),
            "bwrap:  [2Jcleared; __net-tap: Address already in use"
        );
    }

    /// A process of the tap's cage that outlives it holds the pipe open, and the launch does not wait
    /// on it: what arrived before the wait ran out is what is quoted.
    #[test]
    fn a_pipe_held_open_by_a_survivor_is_read_for_a_moment_only() {
        let mut cmd = std::process::Command::new("sh");
        cmd.args(["-c", "echo 'said before it went' >&2; sleep 3 & exit 1"]);
        let mut child = tap_stdio(&mut cmd).spawn().expect("spawn a stand-in tap");
        let _ = child.wait();
        let started = std::time::Instant::now();
        assert_eq!(tap_said(&mut child), "said before it went");
        assert!(
            started.elapsed() < std::time::Duration::from_secs(2),
            "bounded by TAP_SAID_WAIT, not by the survivor: {:?}",
            started.elapsed()
        );
    }

    /// Whether `needle` appears as a contiguous run in `haystack`.
    fn contains(haystack: &[u8], needle: &[u8]) -> bool {
        haystack.windows(needle.len()).any(|w| w == needle)
    }

    #[test]
    fn align4_rounds_up_to_four() {
        assert_eq!(align4(0), 0);
        assert_eq!(align4(1), 4);
        assert_eq!(align4(4), 4);
        assert_eq!(align4(5), 8);
        assert_eq!(align4(6), 8);
    }

    #[test]
    fn push_attr_frames_a_tlv_padded_to_four() {
        let mut buf = Vec::new();
        push_attr(&mut buf, IFLA_INFO_KIND, b"dummy\0"); // 6-byte payload
        // rta_len = 4 + 6 = 10, padded to 12 bytes on the wire.
        assert_eq!(buf.len(), 12);
        assert_eq!(u16::from_ne_bytes([buf[0], buf[1]]), 10); // rta_len excludes padding
        assert_eq!(u16::from_ne_bytes([buf[2], buf[3]]), IFLA_INFO_KIND);
        assert_eq!(&buf[4..10], b"dummy\0");
        assert_eq!(&buf[10..12], &[0, 0]); // padding
    }

    #[test]
    fn ifinfomsg_is_sixteen_bytes_with_the_index_and_flags() {
        let up = libc::IFF_UP as u32;
        let b = ifinfomsg(7, up, up);
        assert_eq!(b.len(), NLMSG_HDR_LEN);
        assert_eq!(b[0], libc::AF_UNSPEC as u8); // ifi_family
        assert_eq!(i32::from_ne_bytes([b[4], b[5], b[6], b[7]]), 7); // ifi_index
        assert_eq!(u32::from_ne_bytes([b[8], b[9], b[10], b[11]]), up); // ifi_flags
        assert_eq!(u32::from_ne_bytes([b[12], b[13], b[14], b[15]]), up); // ifi_change
    }

    #[test]
    fn create_dummy_body_names_the_interface_and_the_dummy_kind() {
        let body = create_dummy_body();
        // Starts with a 16-byte ifinfomsg whose index is 0 (kernel-assigned).
        assert_eq!(i32::from_ne_bytes([body[4], body[5], body[6], body[7]]), 0);
        // 4-byte aligned overall, and carries both the requested name and link kind.
        assert_eq!(align4(body.len()), body.len());
        assert!(contains(&body, b"dummy0\0"));
        assert!(contains(&body, b"dummy\0"));
    }

    #[test]
    fn addr_body_carries_af_inet_the_prefix_and_the_octets() {
        let body = addr_body(9);
        assert_eq!(body[0], libc::AF_INET as u8); // ifa_family
        assert_eq!(body[1], DUMMY_PREFIX); // ifa_prefixlen
        assert_eq!(u32::from_ne_bytes([body[4], body[5], body[6], body[7]]), 9); // ifa_index
        assert!(contains(&body, &DUMMY_OCTETS));
    }

    #[test]
    fn holder_wrap_is_a_byte_for_byte_passthrough_without_a_dummy() {
        let argv = vec![OsString::from("--unshare-net"), OsString::from("--")];
        let (prog, out) = holder_wrap(Path::new("/usr/bin/bwrap"), argv.clone(), None, None);
        assert_eq!(prog, PathBuf::from("/usr/bin/bwrap"));
        assert_eq!(out, argv);
    }

    #[test]
    fn holder_wrap_prepends_the_subcommand_and_the_bwrap_path() {
        let nd = NetnsDummy {
            holder_exe: PathBuf::from("/opt/sbx"),
            tap: None,
        };
        let (prog, out) = holder_wrap(
            Path::new("/usr/bin/bwrap"),
            vec![OsString::from("--cap-drop"), OsString::from("ALL")],
            Some(&nd),
            None,
        );
        // The program becomes sbx itself, invoked as `__netns-holder -- <bwrap> <args…>`.
        assert_eq!(prog, PathBuf::from("/opt/sbx"));
        assert_eq!(
            out,
            vec![
                OsString::from("__netns-holder"),
                OsString::from("--"),
                OsString::from("/usr/bin/bwrap"),
                OsString::from("--cap-drop"),
                OsString::from("ALL"),
            ]
        );
    }

    /// The default route is what makes the redirect reachable at all: for a locally generated
    /// packet the kernel looks the route up **before** the `nat` `OUTPUT` hook, so without one a
    /// connect fails `ENETUNREACH` and the tap listens to silence. Measured that way on a real
    /// launch, which is why the body is pinned here.
    #[test]
    fn the_default_route_body_is_a_zero_prefix_through_the_dummys_own_subnet() {
        let body = default_route_body(7);
        assert_eq!(body[0], libc::AF_INET as u8); // rtm_family
        assert_eq!(
            body[1], 0,
            "a zero destination prefix is what makes it the default route"
        );
        assert_eq!(body[4], RT_TABLE_MAIN);
        assert_eq!(body[7], RTN_UNICAST);
        assert!(
            contains(&body, &GATEWAY_OCTETS),
            "the gateway rides as an attribute"
        );
        assert!(
            contains(&body, &7u32.to_ne_bytes()),
            "so does the output interface"
        );
        assert_eq!(align4(body.len()), body.len());
        // The gateway must sit inside the dummy's own /24, or it is unreachable and the route is
        // refused: the connected route the address installs is the only one that can carry it.
        assert_eq!(GATEWAY_OCTETS[..3], DUMMY_OCTETS[..3]);
        assert_ne!(
            GATEWAY_OCTETS, DUMMY_OCTETS,
            "never the dummy's own address"
        );
    }

    /// A holder wiring whose tap reports down `report`.
    fn holder_with_tap(report: Option<crate::sandbox::nettap::ReportChannel>) -> NetnsDummy {
        NetnsDummy {
            holder_exe: PathBuf::from("/opt/sbx"),
            tap: Some(TapWiring {
                uds: PathBuf::from("/run/sbx/proxy.sock"),
                bwrap: PathBuf::from("/usr/bin/bwrap"),
                nft: PathBuf::from("/usr/sbin/nft"),
                report,
            }),
        }
    }

    /// A report channel: the tap's end, held as a launch holds it, and the far end.
    fn channel() -> (
        crate::sandbox::nettap::ReportChannel,
        std::os::unix::net::UnixDatagram,
    ) {
        let (far, tap) = std::os::unix::net::UnixDatagram::pair().expect("a pair");
        (crate::sandbox::nettap::ReportChannel::new(tap.into()), far)
    }

    fn inode(fd: RawFd) -> Option<u64> {
        // SAFETY: `fstat` fills the zeroed `stat` on the stack, or fails on a closed number.
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        (unsafe { libc::fstat(fd, &mut st) } == 0).then_some(st.st_ino)
    }

    /// A copy of `fd` without the close-on-exec flag, as a process is started holding what it was
    /// handed.
    fn handed(fd: RawFd) -> RawFd {
        // SAFETY: `F_DUPFD` on an open descriptor returns a new number at or above 3, or fails.
        let copy = unsafe { libc::fcntl(fd, libc::F_DUPFD, 3) };
        assert!(copy > 2, "a copy above the standard three");
        copy
    }

    fn close_on_exec(fd: RawFd) -> bool {
        // SAFETY: `F_GETFD` reads a descriptor's flags and touches no memory.
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
        flags >= 0 && flags & libc::FD_CLOEXEC != 0
    }

    #[test]
    fn a_wired_tap_rides_the_holder_argv_and_comes_back_out_of_it() {
        let (report, _far) = channel();
        let fd = handed(report.as_raw_fd());
        let (_, argv) = holder_wrap(
            Path::new("/usr/bin/bwrap"),
            vec![OsString::from("--cap-drop"), OsString::from("ALL")],
            Some(&holder_with_tap(Some(report.clone()))),
            Some(fd),
        );
        assert_eq!(
            argv,
            vec![
                OsString::from("__netns-holder"),
                OsString::from("--tap"),
                OsString::from("/run/sbx/proxy.sock"),
                OsString::from("--bwrap"),
                OsString::from("/usr/bin/bwrap"),
                OsString::from("--nft"),
                OsString::from("/usr/sbin/nft"),
                OsString::from("--report-fd"),
                OsString::from(fd.to_string()),
                OsString::from("--"),
                OsString::from("/usr/bin/bwrap"),
                OsString::from("--cap-drop"),
                OsString::from("ALL"),
            ]
        );
        // What `holder_wrap` writes, `split_holder_args` must read back — the two are one contract,
        // and the holder is a separate process, so nothing else can catch them drifting apart.
        let (tap, rest) = split_holder_args(&argv[1..]).expect("parsed");
        let tap = tap.expect("a tap");
        let wired = holder_with_tap(None).tap.expect("a tap");
        assert_eq!(
            (&tap.uds, &tap.bwrap, &tap.nft),
            (&wired.uds, &wired.bwrap, &wired.nft)
        );
        let adopted = tap.report.as_ref().expect("the channel is wired");
        assert_eq!(
            adopted.as_raw_fd(),
            fd,
            "the descriptor named is the one held"
        );
        assert_eq!(
            inode(fd),
            inode(report.as_raw_fd()),
            "and it is the tap's end"
        );
        assert!(
            close_on_exec(fd),
            "the holder becomes bwrap, which hands the cage every descriptor left without the flag"
        );
        assert_eq!(rest[0], OsString::from("/usr/bin/bwrap"));
        assert_eq!(rest.len(), 3);
    }

    /// The channel reaches the holder on a descriptor the command carries, named by number.
    #[test]
    fn the_report_channel_rides_a_descriptor_the_holders_command_carries() {
        let spec = crate::sandbox::spec::SandboxSpec::new(
            PathBuf::from("/work"),
            vec![],
            vec![],
            crate::sandbox::spec::NetPolicy::Isolated,
            vec![OsString::from("true")],
        )
        .expect("a valid spec");
        let cage =
            crate::sandbox::argv::compose(Path::new("/usr/bin/bwrap"), &spec).expect("compose");
        let (report, _far) = channel();
        let cage = behind_holder(cage, Some(&holder_with_tap(Some(report.clone()))))
            .expect("behind the holder");
        let args = cage.args();
        let at = args
            .iter()
            .position(|a| a == "--report-fd")
            .expect("the holder is told where the channel is");
        let fd: RawFd = args[at + 1]
            .to_str()
            .and_then(|n| n.parse().ok())
            .expect("a number");
        assert!(
            cage.files()
                .iter()
                .any(|f| std::os::fd::AsRawFd::as_raw_fd(f) == fd),
            "the command carries the descriptor it names"
        );
        assert_eq!(inode(fd), inode(report.as_raw_fd()), "the tap's end");
    }

    /// A descriptor the holder cannot account for refuses the whole list rather than being left
    /// open for the cage: one that is no socket, a socket of another kind, one not open, and one of
    /// the standard three. Without the option the tap is wired to report nothing.
    #[test]
    fn a_report_descriptor_the_holder_cannot_account_for_refuses_the_list() {
        let tail = [OsString::from("--"), OsString::from("/usr/bin/bwrap")];
        let wiring = |extra: &[OsString]| {
            let mut argv = vec![
                OsString::from("--tap"),
                OsString::from("/run/s.sock"),
                OsString::from("--bwrap"),
                OsString::from("/usr/bin/bwrap"),
                OsString::from("--nft"),
                OsString::from("/usr/sbin/nft"),
            ];
            argv.extend_from_slice(extra);
            argv.extend_from_slice(&tail);
            argv
        };
        let (tap, _) = split_holder_args(&wiring(&[])).expect("parsed");
        assert_eq!(tap.expect("still a tap").report, None, "no channel at all");

        let file = std::fs::File::open("/dev/null").expect("a file");
        let (stream, _peer) = std::os::unix::net::UnixStream::pair().expect("a stream pair");
        let unaccounted = [
            std::os::fd::AsRawFd::as_raw_fd(&file).to_string(),
            std::os::fd::AsRawFd::as_raw_fd(&stream).to_string(),
            i32::MAX.to_string(),
            "0".to_string(),
            "1".to_string(),
            "2".to_string(),
        ];
        for fd in unaccounted {
            assert!(
                split_holder_args(&wiring(&[
                    OsString::from("--report-fd"),
                    OsString::from(&fd),
                ]))
                .is_none(),
                "descriptor {fd} is refused"
            );
        }
    }

    /// The tap's own cage names its end of the channel by number and binds no report socket: the
    /// egress socket is its one bind, and nothing travels in its environment.
    #[test]
    fn the_taps_cage_names_its_report_end_by_number_and_binds_no_report_socket() {
        let uds = Path::new("/run/sbx/proxy.sock");
        let spec = tap_cage(3, false, uds, Some(7)).expect("the tap's cage");
        assert!(spec.secret_env.is_empty(), "{:?}", spec.secret_env);
        let argv = crate::sandbox::argv::to_argv(&spec);
        let at = argv
            .iter()
            .position(|a| a == "__net-tap")
            .expect("the tap's command");
        assert_eq!(
            argv[at..],
            [
                OsString::from("__net-tap"),
                OsString::from(TAP_EGRESS),
                OsString::from("--report-fd"),
                OsString::from("7"),
            ]
        );
        let binds: Vec<&OsString> = argv
            .windows(2)
            .filter(|w| w[0] == "--ro-bind" || w[0] == "--bind")
            .map(|w| &w[1])
            .filter(|src| {
                src.as_os_str() == uds.as_os_str() || src.to_string_lossy().ends_with(".sock")
            })
            .collect();
        assert_eq!(binds, [uds.as_os_str()], "the egress socket alone");

        let spec = tap_cage(3, false, uds, None).expect("the tap's cage");
        let argv = crate::sandbox::argv::to_argv(&spec);
        assert!(
            !argv.iter().any(|a| a == "--report-fd"),
            "no channel, no option: {argv:?}"
        );
    }

    #[test]
    fn the_separator_is_what_keeps_a_bwrap_argument_from_being_read_as_the_holders() {
        // `--tap` here belongs to bwrap's side of the separator and must stay there.
        let argv = vec![
            OsString::from("--"),
            OsString::from("/usr/bin/bwrap"),
            OsString::from("--tap"),
            OsString::from("/not/ours"),
        ];
        let (tap, rest) = split_holder_args(&argv).expect("parsed");
        assert_eq!(tap, None, "nothing before the separator, so no wiring");
        assert_eq!(rest.len(), 3);
    }

    #[test]
    fn a_malformed_holder_argv_is_refused_rather_than_guessed() {
        // No separator at all: a caller that did not come through `holder_wrap`.
        assert!(split_holder_args(&[OsString::from("/usr/bin/bwrap")]).is_none());
        // An option the holder does not know.
        assert!(
            split_holder_args(&[
                OsString::from("--wat"),
                OsString::from("x"),
                OsString::from("--"),
                OsString::from("/usr/bin/bwrap"),
            ])
            .is_none()
        );
    }

    /// bwrap's two pipe options go right after the program, and the argv the launch built follows
    /// byte for byte — options and command alike.
    #[test]
    fn the_sync_fds_follow_the_program_and_leave_the_rest_untouched() {
        let argv: Vec<OsString> = ["/usr/bin/bwrap", "--unshare-net", "--", "/bin/sh"]
            .map(OsString::from)
            .to_vec();
        assert_eq!(
            with_sync_fds(&argv, 7, 9),
            [
                "/usr/bin/bwrap",
                "--info-fd",
                "7",
                "--block-fd",
                "9",
                "--unshare-net",
                "--",
                "/bin/sh",
            ]
            .map(OsString::from)
            .to_vec()
        );
    }

    /// The pid is read from bwrap's report as it arrives, and only once it is whole: a read that
    /// stops inside the number must not hand out its first digits.
    #[test]
    fn the_child_pid_is_read_once_its_value_is_complete() {
        let report = b"{\n    \"child-pid\": 12345,\n    \"net-namespace\": 4026533291\n}\n";
        assert_eq!(child_pid(report), Some(12345));
        assert_eq!(child_pid(b"{\"child-pid\":12345}"), Some(12345));
        for partial in [
            &b"{\n    \"child-pid\": 123"[..],
            b"{\n    \"child-pid\": ",
            b"{\n    \"child-pid\"",
            b"{\n    \"child-",
            b"",
        ] {
            assert_eq!(child_pid(partial), None, "{partial:?}");
        }
        // Only the `child-pid` member: another number in the report is not it.
        assert_eq!(child_pid(b"{\"net-namespace\": 42,"), None);
        assert_eq!(child_pid(b"{\"child-pid\": x1,"), None);
    }

    /// Half a wiring is not one: without the socket there is nothing to hand a captured connection
    /// to, and without `nft` no rule can be installed. Either alone must degrade, never half-wire.
    #[test]
    fn half_a_tap_wiring_is_no_wiring() {
        for opts in [
            vec![OsString::from("--tap"), OsString::from("/run/s.sock")],
            vec![OsString::from("--nft"), OsString::from("/usr/sbin/nft")],
        ] {
            let mut argv = opts;
            argv.push(OsString::from("--"));
            argv.push(OsString::from("/usr/bin/bwrap"));
            let (tap, _) = split_holder_args(&argv).expect("parsed");
            assert_eq!(tap, None);
        }
    }
}
