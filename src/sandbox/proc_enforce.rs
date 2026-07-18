//! Exec enforcement via seccomp user-notification — the host-side supervisor and the in-cage shim.
//!
//! This is the enforcement half of the process/exec lens (the observe half is
//! [`super::observe_feed`]/[`super::proc_control`]). Under `[proc] mode = enforce|ask` a launch stands
//! up a **park-and-decide** gate on `execve`/`execveat`: the syscall traps to a host-side supervisor
//! that decides — `deny` returns `EPERM` (the syscall never runs — TOCTOU-safe), `allow` continues, an
//! unmatched target under `ask` is parked for a live `sbx proc allow`/`deny`.
//!
//! ## Why an in-cage shim
//!
//! bubblewrap can only load a *plain* cBPF filter (`--add-seccomp-fd`); it cannot install a
//! `SECCOMP_FILTER_FLAG_NEW_LISTENER` filter (which returns a listener fd). So a tiny **in-cage shim**
//! ([`run_shim`], reached as `sbx __proc-shim`) installs the notification filter on itself, hands the
//! listener fd **out** to the host supervisor over a bind-mounted `AF_UNIX` socket (via `SCM_RIGHTS`,
//! the same socket shape as the egress UDS), then `execvp`s the real command. The filter is inherited
//! across `fork`+`exec`, so the whole cage process tree is covered — the agent cannot spawn an
//! unsurveilled child. The shim is sbx itself, bound read-only into the cage; a fully-static release
//! binary runs there by construction, and a dynamic dev binary runs under the base nix-ld loader
//! (verified). **Fail-closed:** if the shim cannot install the filter or hand off the fd, it exits
//! non-zero *without* executing the payload — the command never runs unobserved.
//!
//! ## The supervisor must be an ancestor
//!
//! Deciding a notified `execve` needs the target path, read from `/proc/<pid>/mem` at the notified
//! argument pointer while the target is parked in the syscall. Under YAMA `ptrace_scope = 1` that read
//! is permitted only to an ancestor of the target — which the supervisor (a thread in the launching
//! sbx process) is: the cage is its descendant in host pid-space for the whole live run (the
//! `systemd-run --scope` wrapper exec-chains, so bwrap stays a child of sbx; reparenting onto the
//! systemd manager only happens at teardown, after the run). [`SECCOMP_IOCTL_NOTIF_ID_VALID`] guards
//! the read against a reaped-and-reused pid.
//!
//! ## The single-listener discipline (no serialization deadlock)
//!
//! There is one notification fd. The receive loop must render a verdict on *every* notified `execve`,
//! but it must **never block** waiting for a human — that would stall every other `execve` in the cage
//! behind one parked decision. So an instant verdict (`deny`/`allow`) is answered inline, while an
//! `ask` park is *registered* (keyed by the kernel notification id) and left for the control plane to
//! answer out-of-band; the loop moves straight on to the next notification.
//!
//! ## Bypass resistance (a `deny` is hard against the in-cage adversary)
//!
//! Two ways a hostile agent might try to run a denied binary around this gate are both closed by the
//! kernel, verified empirically:
//!
//! - **A compat-ABI `execve`** (a 64-bit process issuing the i386 `int 0x80` `execve`, whose number is
//!   not the native one this filter matches) does not slip through: the mandatory M4.1 seccomp denylist
//!   is compiled by `seccompiler`, which prepends an architecture check that **kills the process**
//!   (`SECCOMP_RET_KILL_PROCESS`, the highest-precedence action) for any `seccomp_data.arch` that is
//!   not the native one. So a foreign-ABI `execve` traps that guard and dies rather than running
//!   untrapped. (The narrow exception is the x32 ABI, which shares x86-64's `arch` value with distinct
//!   syscall numbers — a blind spot shared with the M4.1 denylist itself, and the base toolset is
//!   x86-64.)
//! - **Installing its own notification filter** to capture and auto-`CONTINUE` its own `execve`s does
//!   not work: the kernel permits only one seccomp notification listener per process, so a second
//!   `SECCOMP_FILTER_FLAG_NEW_LISTENER` fails with `EBUSY`. The shim installs the sole listener before
//!   the agent runs, and it is held by the launcher's supervisor. A *plain* filter the agent adds can
//!   only make `execve` **more** restrictive (this filter's `USER_NOTIF` outranks a later `ALLOW`), so
//!   it can deny its own `execve` but never run a denied binary without the supervisor's `CONTINUE`.
//!
//! So a `deny` is a hard stop on `execve`. What exec enforcement is *not* is a full containment
//! boundary: an agent can do harm **in-process** (in its own interpreter) without `execve`ing at all,
//! and an `allow`/`CONTINUE` re-runs the real syscall so *approving a specific path* is TOCTOU-racy
//! (refusing is not — the syscall never runs). It is a guardrail with real teeth on the exec channel,
//! layered on the cage's actual boundaries (confinement by absence, the read-only store, the netns).

use std::collections::BTreeMap;
use std::ffi::{CString, OsStr, OsString};
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use super::binds::ExtraBind;
use super::proc_control::ExecRing;
use crate::proc_policy::{ProcPolicy, Verdict};

/// The most `ask`-parked `execve`s a session holds at once. Beyond this, a further undecided `execve`
/// is denied outright (fail-closed) rather than growing the registry without bound — mirroring the
/// egress ask flood cap.
const ASK_PENDING_CAP: usize = 256;

/// How long an `ask`-parked `execve` waits for a human decision before it is auto-denied. A finite
/// bound is load-bearing: a parked `execve` blocks its process, and a parent `wait`ing on it would
/// otherwise hang the whole tree — the timeout releases it (with `EPERM`, fail-closed) so the tree
/// makes progress. A live `sbx proc allow`/`deny` decides it well within this window.
const ASK_TIMEOUT: Duration = Duration::from_secs(120);

/// The hidden subcommand the wrapped command runs as, inside the cage.
pub(crate) const SHIM_VERB: &str = "__proc-shim";

/// Where sbx binds itself (the shim) read-only inside the cage, and where the notification handoff
/// socket appears. Both under `/opt/sbx`, beside the egress CA — a path the cage cannot reach outside
/// of these binds.
const SHIM_CAGE_PATH: &str = "/opt/sbx/proc-shim";
const NOTIF_SOCK_CAGE_PATH: &str = "/opt/sbx/proc-notif.sock";

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

fn notif_recv_code() -> libc::c_ulong {
    seccomp_ioc(
        IOC_READ | IOC_WRITE,
        0,
        std::mem::size_of::<libc::seccomp_notif>(),
    )
}

fn notif_send_code() -> libc::c_ulong {
    seccomp_ioc(
        IOC_READ | IOC_WRITE,
        1,
        std::mem::size_of::<libc::seccomp_notif_resp>(),
    )
}

fn notif_id_valid_code() -> libc::c_ulong {
    seccomp_ioc(IOC_WRITE, 2, std::mem::size_of::<u64>())
}

// ── the in-cage shim ──────────────────────────────────────────────────────────────────────────────

/// Run the in-cage shim: install the user-notification filter on `execve`/`execveat`, hand the
/// listener fd to the host supervisor over the bound socket, then `execvp` the payload. Reached as
/// `sbx __proc-shim <notif-socket> -- <payload…>`.
///
/// **Fail-closed:** every step before the `execvp` that errors returns a non-zero [`ExitCode`] *without*
/// running the payload — an un-enforced command must never run in a Mode-B cage. A denied first
/// `execve` (the supervisor answered `EPERM`) surfaces as a failed `execvp`, reported the same way.
pub(crate) fn run_shim(args: &[OsString]) -> ExitCode {
    // args = [<notif-socket>, "--", payload0, payload1, …]
    let sep = args.iter().position(|a| a == "--");
    let (sock, payload) = match sep {
        Some(i) if i >= 1 && i + 1 < args.len() => (&args[0], &args[i + 1..]),
        _ => {
            eprintln!("sbx {SHIM_VERB}: usage: {SHIM_VERB} <notif-socket> -- <command…>");
            return ExitCode::from(2);
        }
    };

    let notif_fd = match install_notif_filter() {
        Ok(fd) => fd,
        Err(e) => {
            eprintln!("sbx {SHIM_VERB}: cannot install the exec filter ({e}) — refusing to run");
            return ExitCode::from(97);
        }
    };
    if let Err(e) = hand_off(sock, notif_fd) {
        // SAFETY: notif_fd is our owned descriptor from install_notif_filter.
        unsafe { libc::close(notif_fd) };
        eprintln!("sbx {SHIM_VERB}: cannot reach the exec supervisor ({e}) — refusing to run");
        return ExitCode::from(96);
    }
    // The supervisor holds the only reference now; drop ours so a supervisor exit tears the filter
    // down (matched execve then fail closed with ENOSYS) rather than lingering.
    // SAFETY: notif_fd is our owned descriptor; closed exactly once.
    unsafe { libc::close(notif_fd) };

    exec_payload(payload)
}

/// Install a `NEW_LISTENER` seccomp filter that notifies on `execve`/`execveat` and allows everything
/// else, returning the listener fd. Requires `no_new_privs` (bwrap already sets it; set again to be
/// self-contained).
fn install_notif_filter() -> io::Result<libc::c_int> {
    // SAFETY: prctl with scalar args; no memory is shared.
    if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0 {
        return Err(io::Error::last_os_error());
    }
    // A 5-instruction cBPF program. Opcodes (asm-generic/bpf_common.h): LD|W|ABS = 0x20, JMP|JEQ|K =
    // 0x15, RET|K = 0x06. `nr` is the first field of `seccomp_data`, at offset 0.
    const LD_ABS_W: u16 = 0x20;
    const JEQ_K: u16 = 0x15;
    const RET_K: u16 = 0x06;
    let filter = [
        libc::sock_filter {
            code: LD_ABS_W,
            jt: 0,
            jf: 0,
            k: 0,
        },
        // if nr == execve   -> +2 (to the USER_NOTIF return)
        libc::sock_filter {
            code: JEQ_K,
            jt: 2,
            jf: 0,
            k: libc::SYS_execve as u32,
        },
        // if nr == execveat -> +1
        libc::sock_filter {
            code: JEQ_K,
            jt: 1,
            jf: 0,
            k: libc::SYS_execveat as u32,
        },
        // else allow
        libc::sock_filter {
            code: RET_K,
            jt: 0,
            jf: 0,
            k: libc::SECCOMP_RET_ALLOW,
        },
        // execve/execveat -> notify the supervisor
        libc::sock_filter {
            code: RET_K,
            jt: 0,
            jf: 0,
            k: libc::SECCOMP_RET_USER_NOTIF,
        },
    ];
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
fn exec_payload(payload: &[OsString]) -> ExitCode {
    let prog = match CString::new(payload[0].as_bytes()) {
        Ok(c) => c,
        Err(_) => {
            eprintln!("sbx {SHIM_VERB}: command contains a NUL byte");
            return ExitCode::from(94);
        }
    };
    let args: Vec<CString> = payload
        .iter()
        .filter_map(|a| CString::new(a.as_bytes()).ok())
        .collect();
    if args.len() != payload.len() {
        eprintln!("sbx {SHIM_VERB}: an argument contains a NUL byte");
        return ExitCode::from(94);
    }
    let mut ptrs: Vec<*const libc::c_char> = args.iter().map(|c| c.as_ptr()).collect();
    ptrs.push(std::ptr::null());
    // SAFETY: prog and ptrs live until execvp returns (which only happens on failure).
    unsafe { libc::execvp(prog.as_ptr(), ptrs.as_ptr()) };
    let err = io::Error::last_os_error();
    eprintln!(
        "sbx {SHIM_VERB}: cannot execute {}: {err}",
        payload[0].to_string_lossy()
    );
    // A supervisor `EPERM` (a denied command) lands here; report as a blocked run.
    ExitCode::from(if err.raw_os_error() == Some(libc::EPERM) {
        126
    } else {
        127
    })
}

// ── the host supervisor ───────────────────────────────────────────────────────────────────────────

/// The cage binds a launch injects for exec enforcement: the shim binary (read-only) and the
/// notification handoff socket (writable — the shim `connect`s to it).
pub(crate) struct Wiring {
    pub(crate) binds: Vec<ExtraBind>,
}

/// The host-side enforcement resource: the bound handoff socket, the supervisor thread, and the proc
/// control socket the notified events are served on (so `sbx proc logs` reads them). Held by the
/// supervised launch paths for the cage's lifetime; dropping it stops the supervisor and unlinks both
/// sockets. The [`PendingExec`] is shared with the control serve thread so `sbx proc allow`/`deny` can
/// answer a parked `execve`.
pub(crate) struct ProcEnforce {
    stop: Arc<AtomicBool>,
    handle: Option<JoinHandle<()>>,
    notif_socket: PathBuf,
    control_socket: Option<PathBuf>,
}

impl Drop for ProcEnforce {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
        let _ = std::fs::remove_file(&self.notif_socket);
        if let Some(s) = &self.control_socket {
            let _ = std::fs::remove_file(s);
        }
    }
}

/// Stand up exec enforcement for a launch: create the exec ring + the `ask` pending registry, bind and
/// serve the proc control socket (so `sbx proc logs`/`allow`/`deny` reach this session), bind the
/// notification handoff socket, and spawn the supervisor thread — which accepts the shim's one
/// connection, receives the listener fd, then decides every notified `execve` against `policy`. Returns
/// the cage binds (the shim binary + the handoff socket) to merge into the spec.
///
/// The shim binary is `sbx_exe` (this binary), bound read-only. The handoff socket appears in the cage
/// at [`NOTIF_SOCK_CAGE_PATH`]; wrap the command with [`wrap_command`] so it runs under the shim.
pub(crate) fn start(
    data_dir: &Path,
    sbx_exe: &Path,
    policy: ProcPolicy,
) -> io::Result<(ProcEnforce, Wiring)> {
    use std::os::unix::fs::DirBuilderExt;
    let dir = super::proc_control::proc_control_dir(data_dir);
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(&dir)?;

    let ring = Arc::new(ExecRing::new(super::proc_control::EXEC_RING_CAP));
    let pending = Arc::new(PendingExec::new());

    // The proc control socket: `sbx proc logs` reads the ring, and (under ask) `sbx proc allow`/`deny`
    // answer a parked `execve`. Best-effort — a failure here still leaves enforcement running, only the
    // out-of-band viewer/decider is unavailable.
    let control_socket = super::proc_control::proc_control_socket(data_dir, std::process::id());
    let _ = std::fs::remove_file(&control_socket);
    let control_socket = match UnixListener::bind(&control_socket) {
        Ok(l) => {
            let ring = ring.clone();
            let pending = pending.clone();
            std::thread::spawn(move || {
                let _ = super::proc_control::serve_enforced(l, ring, pending);
            });
            Some(control_socket)
        }
        Err(e) => {
            crate::diag::warn(&format!(
                "could not bind the process-observation socket ({e}) — `sbx proc logs`/`allow`/`deny` \
                 will not see this session; under `ask` an unmatched exec then has no way to be \
                 decided and is auto-denied when its timeout lapses"
            ));
            None
        }
    };

    let notif_socket = dir.join(format!("notif-{}.sock", std::process::id()));
    let _ = std::fs::remove_file(&notif_socket);
    let listener = UnixListener::bind(&notif_socket)?;
    listener.set_nonblocking(true)?;

    let stop = Arc::new(AtomicBool::new(false));
    let flag = stop.clone();
    let handle = std::thread::spawn(move || {
        supervise(listener, &flag, &policy, &ring, &pending);
    });

    let binds = vec![
        ExtraBind {
            src: sbx_exe.to_path_buf(),
            dest: PathBuf::from(SHIM_CAGE_PATH),
            writable: false,
        },
        ExtraBind {
            src: notif_socket.clone(),
            dest: PathBuf::from(NOTIF_SOCK_CAGE_PATH),
            writable: true,
        },
    ];
    Ok((
        ProcEnforce {
            stop,
            handle: Some(handle),
            notif_socket,
            control_socket,
        },
        Wiring { binds },
    ))
}

/// Prepend the shim invocation to a command, so it runs under the exec filter. This is applied
/// **innermost** (before the provisioning/egress wraps), so only the real command and its children are
/// filtered, not the launch's own plumbing. All values are positional — no shell, no injection.
pub(crate) fn wrap_command(cmd: Vec<OsString>) -> Vec<OsString> {
    let mut out = Vec::with_capacity(cmd.len() + 4);
    out.push(OsString::from(SHIM_CAGE_PATH));
    out.push(OsString::from(SHIM_VERB));
    out.push(OsString::from(NOTIF_SOCK_CAGE_PATH));
    out.push(OsString::from("--"));
    out.extend(cmd);
    out
}

/// The supervisor thread: wait (with a stop-checking poll) for the shim's one connection, receive the
/// listener fd, close the listening socket (no second connection is accepted), then run the receive
/// loop until the cage's filter is gone.
fn supervise(
    listener: UnixListener,
    stop: &AtomicBool,
    policy: &ProcPolicy,
    ring: &ExecRing,
    pending: &PendingExec,
) {
    let notif_fd = match accept_handoff(&listener, stop) {
        Some(fd) => fd,
        None => return, // stopped before the shim connected, or the handoff failed
    };
    drop(listener); // one handoff only; the agent cannot connect a second fd
    recv_loop(notif_fd, stop, policy, ring, pending);
    // SAFETY: notif_fd is our owned descriptor from recv_fd; closed exactly once here.
    unsafe { libc::close(notif_fd) };
}

/// Poll the listening socket in short slices (honouring `stop`), accept the shim's connection, and
/// receive the listener fd it sends. Returns `None` if stopped first or the handoff fails.
fn accept_handoff(listener: &UnixListener, stop: &AtomicBool) -> Option<libc::c_int> {
    use std::os::unix::io::AsRawFd;
    while !stop.load(Ordering::Relaxed) {
        if !poll_readable(listener.as_raw_fd(), 250) {
            continue;
        }
        match listener.accept() {
            Ok((stream, _)) => return recv_fd(&stream).ok(),
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => continue,
            Err(_) => return None,
        }
    }
    None
}

/// The receive loop: for each notified `execve`, read the target path, decide, and respond — a `deny`
/// with `EPERM`, an `allow`/continue, an `ask`-undecided by parking it in `pending` for the control
/// plane (never blocking here — the single notification fd must keep draining). Ends when the cage's
/// filter is gone (the fd hangs up) or on stop.
fn recv_loop(
    notif_fd: libc::c_int,
    stop: &AtomicBool,
    policy: &ProcPolicy,
    ring: &ExecRing,
    pending: &PendingExec,
) {
    while !stop.load(Ordering::Relaxed) {
        if !poll_readable(notif_fd, 250) {
            // Idle tick: release any parked `execve` that has waited past the decision timeout, so a
            // stalled decision never hangs a process tree.
            pending.sweep();
            continue;
        }
        let mut req: libc::seccomp_notif = unsafe { std::mem::zeroed() };
        // SAFETY: req is a live, correctly-sized seccomp_notif for the RECV ioctl to fill.
        let rc = unsafe { libc::ioctl(notif_fd, notif_recv_code(), &mut req) };
        if rc < 0 {
            let err = io::Error::last_os_error();
            if err.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return; // ENOENT / hang-up: the cage's filter is gone
        }
        handle_notif(notif_fd, &req, policy, ring, pending);
    }
}

/// Decide one notified `execve` and answer it. The path is read from the parked target's memory; an
/// unreadable path (an anomaly under the ancestor invariant) is treated as unmatched — never a
/// silent deny that could brick the whole cage, and never a silent allow of a named `deny`.
fn handle_notif(
    notif_fd: libc::c_int,
    req: &libc::seccomp_notif,
    policy: &ProcPolicy,
    ring: &ExecRing,
    pending: &PendingExec,
) {
    // Confirm the notification is still live before reading the target's memory (a reaped-and-reused
    // pid would otherwise be read/acted on as the wrong process).
    if !notif_id_valid(notif_fd, req.id) {
        return;
    }
    let path = read_exec_path(req.pid, req.data.args[0]).unwrap_or_default();
    let verdict = if path.is_empty() {
        // Could not read the path: fall back to the mode's unmatched default (allow under a denylist,
        // park under ask) rather than guessing a name match.
        match policy.mode {
            crate::proc_policy::ProcMode::Ask => Verdict::Ask,
            _ => Verdict::Allow,
        }
    } else {
        policy.decide(&path)
    };
    let shown = if path.is_empty() {
        "<unreadable>"
    } else {
        &path
    };
    match verdict {
        Verdict::Allow => {
            ring.push_verdict(req.pid, shown, "allow");
            respond_continue(notif_fd, req.id);
        }
        Verdict::Deny => {
            ring.push_verdict(req.pid, shown, "deny");
            respond_errno(notif_fd, req.id, libc::EPERM);
        }
        Verdict::Ask => {
            // Park it: register the kernel notification id so the control plane can answer it later.
            // The receive loop does not block — it returns to draining the next notification.
            ring.push_verdict(req.pid, shown, "ask");
            pending.park(notif_fd, req.id, req.pid, shown);
        }
    }
}

/// Whether a seccomp notification id is still valid (the target has not been reaped).
fn notif_id_valid(notif_fd: libc::c_int, id: u64) -> bool {
    // SAFETY: passes the address of a local u64 to the ID_VALID ioctl, which only reads it.
    unsafe { libc::ioctl(notif_fd, notif_id_valid_code(), &id as *const u64) == 0 }
}

/// Answer a notification with `CONTINUE` (let the real syscall run).
fn respond_continue(notif_fd: libc::c_int, id: u64) {
    let mut resp: libc::seccomp_notif_resp = unsafe { std::mem::zeroed() };
    resp.id = id;
    resp.flags = libc::SECCOMP_USER_NOTIF_FLAG_CONTINUE as u32;
    send_resp(notif_fd, &resp);
}

/// Answer a notification with an errno (the syscall never runs).
fn respond_errno(notif_fd: libc::c_int, id: u64, errno: libc::c_int) {
    let mut resp: libc::seccomp_notif_resp = unsafe { std::mem::zeroed() };
    resp.id = id;
    resp.error = -errno;
    send_resp(notif_fd, &resp);
}

/// Send a notification response, ignoring `ENOENT` (the target was reaped while we decided).
pub(crate) fn send_resp(notif_fd: libc::c_int, resp: &libc::seccomp_notif_resp) {
    // SAFETY: resp is a live, correctly-sized response for the SEND ioctl to read.
    unsafe {
        libc::ioctl(
            notif_fd,
            notif_send_code(),
            resp as *const libc::seccomp_notif_resp,
        );
    }
}

// ── ask-mode parking ──────────────────────────────────────────────────────────────────────────────

/// The registry of `ask`-parked `execve`s awaiting a decision. Each entry carries the kernel
/// notification id and the fd needed to answer it, so the control plane (`sbx proc allow`/`deny`) and
/// the idle-tick timeout sweeper can respond out-of-band while the receive loop keeps draining the next
/// notification. Shared (via `Arc`) between the supervisor thread and the control serve thread.
pub(crate) struct PendingExec {
    inner: Mutex<BTreeMap<u64, Parked>>,
}

struct Parked {
    id: u64,
    notif_fd: libc::c_int,
    pid: u32,
    path: String,
    since: Instant,
}

impl PendingExec {
    pub(crate) fn new() -> PendingExec {
        PendingExec {
            inner: Mutex::new(BTreeMap::new()),
        }
    }

    /// Register a parked `execve` (non-blocking). Over the flood cap, deny it outright (fail-closed)
    /// rather than growing the registry without bound.
    fn park(&self, notif_fd: libc::c_int, id: u64, pid: u32, path: &str) {
        {
            let mut g = self.inner.lock().unwrap();
            if g.len() < ASK_PENDING_CAP {
                g.insert(
                    id,
                    Parked {
                        id,
                        notif_fd,
                        pid,
                        path: path.to_string(),
                        since: Instant::now(),
                    },
                );
                return;
            }
        }
        respond_errno(notif_fd, id, libc::EPERM);
    }

    /// Answer one parked `execve` by its notification id: allow (`CONTINUE`) or deny (`EPERM`). Returns
    /// the `(pid, path)` decided, or `None` if the id is unknown (already answered / timed out).
    pub(crate) fn answer(&self, id: u64, allow: bool) -> Option<(u32, String)> {
        let parked = self.inner.lock().unwrap().remove(&id)?;
        answer_parked(&parked, allow);
        Some((parked.pid, parked.path))
    }

    /// Answer every parked `execve` at once (the `*` bulk form). Returns each decided `(id, pid, path)`.
    pub(crate) fn answer_all(&self, allow: bool) -> Vec<(u64, u32, String)> {
        let taken = std::mem::take(&mut *self.inner.lock().unwrap());
        taken
            .into_values()
            .map(|p| {
                answer_parked(&p, allow);
                (p.id, p.pid, p.path)
            })
            .collect()
    }

    /// The currently-parked `execve`s: `(id, pid, path, time parked)`, oldest id first.
    pub(crate) fn list(&self) -> Vec<(u64, u32, String, Duration)> {
        self.inner
            .lock()
            .unwrap()
            .values()
            .map(|p| (p.id, p.pid, p.path.clone(), p.since.elapsed()))
            .collect()
    }

    /// Auto-deny (with `EPERM`) any parked `execve` older than [`ASK_TIMEOUT`], so a stalled decision
    /// never hangs a process tree. Called on the receive loop's idle ticks.
    fn sweep(&self) {
        let mut g = self.inner.lock().unwrap();
        let expired: Vec<u64> = g
            .values()
            .filter(|p| p.since.elapsed() >= ASK_TIMEOUT)
            .map(|p| p.id)
            .collect();
        for id in expired {
            if let Some(p) = g.remove(&id) {
                answer_parked(&p, false);
            }
        }
    }
}

/// Answer a single parked entry, guarded by the notification id still being valid (the target may have
/// been reaped while parked, in which case there is nothing to answer).
fn answer_parked(p: &Parked, allow: bool) {
    if !notif_id_valid(p.notif_fd, p.id) {
        return;
    }
    if allow {
        respond_continue(p.notif_fd, p.id);
    } else {
        respond_errno(p.notif_fd, p.id, libc::EPERM);
    }
}

/// Read a NUL-terminated path from a parked target's memory at `addr`. The target is blocked in the
/// `execve` notification, so the pointer is valid and its memory is stable. Returns `None` on any read
/// failure.
fn read_exec_path(pid: u32, addr: u64) -> Option<String> {
    use std::io::Read;
    let mut file = std::fs::File::open(format!("/proc/{pid}/mem")).ok()?;
    // Seek and read a bounded window; a path is at most PATH_MAX.
    use std::io::{Seek, SeekFrom};
    file.seek(SeekFrom::Start(addr)).ok()?;
    let mut buf = [0u8; 4096];
    let n = file.read(&mut buf).ok()?;
    if n == 0 {
        return None;
    }
    let end = buf[..n].iter().position(|&b| b == 0).unwrap_or(n);
    Some(String::from_utf8_lossy(&buf[..end]).into_owned())
}

/// Poll a descriptor for readability with a millisecond timeout. `true` = readable (or hung up, so a
/// following read observes the end), `false` = timed out. A poll error is treated as "not readable"
/// so the caller re-checks its stop flag rather than spinning.
fn poll_readable(fd: libc::c_int, timeout_ms: libc::c_int) -> bool {
    let mut pfd = libc::pollfd {
        fd,
        events: libc::POLLIN,
        revents: 0,
    };
    // SAFETY: pfd is a single live pollfd.
    let rc = unsafe { libc::poll(&mut pfd, 1, timeout_ms) };
    rc > 0
}

/// Receive one file descriptor sent over a Unix stream as an `SCM_RIGHTS` ancillary message.
fn recv_fd(stream: &UnixStream) -> io::Result<libc::c_int> {
    use std::os::unix::io::AsRawFd;
    let mut dummy = [0u8; 1];
    let mut iov = libc::iovec {
        iov_base: dummy.as_mut_ptr() as *mut libc::c_void,
        iov_len: 1,
    };
    let mut cbuf = [0u8; 32];
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = cbuf.as_mut_ptr() as *mut libc::c_void;
    msg.msg_controllen = cbuf.len() as _;
    // SAFETY: msg's buffers are live; we read exactly one cmsg carrying one fd.
    unsafe {
        let n = libc::recvmsg(stream.as_raw_fd(), &mut msg, 0);
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
        let mut fd: libc::c_int = -1;
        std::ptr::copy_nonoverlapping(
            libc::CMSG_DATA(cmsg),
            &mut fd as *mut libc::c_int as *mut u8,
            std::mem::size_of::<libc::c_int>(),
        );
        if fd < 0 {
            return Err(io::Error::other("invalid fd in the handoff message"));
        }
        Ok(fd)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proc_policy::ProcMode;

    #[test]
    fn ioctl_codes_match_the_kernel_abi() {
        // Computed once against the struct sizes; pin the well-known x86_64/aarch64 values so a wrong
        // direction/size bit is caught here, not at runtime.
        // seccomp_notif = 80 bytes, seccomp_notif_resp = 24 bytes.
        assert_eq!(std::mem::size_of::<libc::seccomp_notif>(), 80);
        assert_eq!(std::mem::size_of::<libc::seccomp_notif_resp>(), 24);
        // _IOWR('!', 0, seccomp_notif) = 0xC0502100; _IOWR('!', 1, resp) = 0xC0182101;
        // _IOW('!', 2, u64) = 0x40082102.
        assert_eq!(notif_recv_code(), 0xC050_2100);
        assert_eq!(notif_send_code(), 0xC018_2101);
        assert_eq!(notif_id_valid_code(), 0x4008_2102);
    }

    #[test]
    fn wrap_command_prepends_the_shim_positionally() {
        let cmd = vec![OsString::from("node"), OsString::from("agent.js")];
        let out = wrap_command(cmd);
        assert_eq!(
            out,
            vec![
                OsString::from(SHIM_CAGE_PATH),
                OsString::from(SHIM_VERB),
                OsString::from(NOTIF_SOCK_CAGE_PATH),
                OsString::from("--"),
                OsString::from("node"),
                OsString::from("agent.js"),
            ]
        );
    }

    /// The load-bearing enforcement proof, host-side (no cage): a child installs the real
    /// user-notification filter and hands the listener fd back over a socketpair, then attempts two
    /// `execve`s; the parent runs the real RECV → decide → SEND path against a policy that denies one
    /// binary. It asserts the denied `execve` returns `EPERM` (the file is never executed) and the
    /// allowed one runs — the same path the cage uses, with the supervisor as the child's direct parent
    /// (a YAMA ancestor, so the `/proc/<pid>/mem` read is permitted).
    ///
    /// The child runs between `fork` and `exec` in a multi-threaded test harness, so it does only
    /// async-signal-safe work: raw syscalls, stack-only `send_fd`, byte-literal C strings, and a
    /// single-byte report per step — no heap allocation (a `format!`/`CString::new` could deadlock on
    /// the inherited malloc lock).
    #[test]
    fn a_denied_execve_returns_eperm_and_an_allowed_one_runs() {
        use std::os::unix::io::FromRawFd;

        let mut sv = [0 as libc::c_int; 2];
        assert_eq!(
            unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, sv.as_mut_ptr()) },
            0
        );
        let mut pv = [0 as libc::c_int; 2];
        assert_eq!(unsafe { libc::pipe(pv.as_mut_ptr()) }, 0);

        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "fork failed");
        if pid == 0 {
            // ── child (async-signal-safe only) ──
            unsafe {
                libc::close(sv[0]);
                libc::close(pv[0]);
                let notif = match install_notif_filter() {
                    Ok(fd) => fd,
                    Err(_) => libc::_exit(90),
                };
                let sock = UnixStream::from_raw_fd(sv[1]);
                if send_fd(&sock, notif).is_err() {
                    libc::_exit(91);
                }
                libc::close(notif);
                // Probe /bin/true (denied): one execve, traps to the parent, returns EPERM.
                let targv = [c"/bin/true".as_ptr(), std::ptr::null()];
                libc::execv(c"/bin/true".as_ptr(), targv.as_ptr());
                let err = *libc::__errno_location();
                let byte = [if err == libc::EPERM { b'D' } else { b'X' }];
                libc::write(pv[1], byte.as_ptr() as *const libc::c_void, 1);
                // Report "reached the allowed exec" BEFORE it replaces us.
                libc::write(pv[1], c"R".as_ptr() as *const libc::c_void, 1);
                // /bin/echo (allowed): CONTINUE runs it, replacing the child.
                let eargv = [c"echo".as_ptr(), std::ptr::null()];
                libc::execv(c"/bin/echo".as_ptr(), eargv.as_ptr());
                libc::_exit(3); // only if /bin/echo was denied/missing
            }
        }

        // ── parent (the supervisor) ──
        unsafe {
            libc::close(sv[1]);
            libc::close(pv[1]);
        }
        let sock = unsafe { UnixStream::from_raw_fd(sv[0]) };
        let notif = recv_fd(&sock).expect("parent: recv notif fd");

        // Deny /bin/true, allow everything else (denylist default-allow).
        let policy = ProcPolicy::new(ProcMode::Enforce, &[], &["/bin/true".to_string()]);
        let ring = Arc::new(ExecRing::new(16));
        let pending = Arc::new(PendingExec::new());
        for _ in 0..2 {
            assert!(poll_readable(notif, 3000), "no notification arrived");
            let mut req: libc::seccomp_notif = unsafe { std::mem::zeroed() };
            let rc = unsafe { libc::ioctl(notif, notif_recv_code(), &mut req) };
            if rc < 0 {
                break;
            }
            handle_notif(notif, &req, &policy, &ring, &pending);
        }

        // Read the child's two report bytes.
        let mut buf = [0u8; 8];
        let n = unsafe { libc::read(pv[0], buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
        unsafe {
            libc::close(pv[0]);
            let mut status = 0;
            libc::waitpid(pid, &mut status, 0);
            libc::close(notif);
        }
        drop(sock);
        let report = &buf[..n.max(0) as usize];
        assert_eq!(
            report.first().copied(),
            Some(b'D'),
            "the denied execve must return EPERM (child report byte); got {report:?}"
        );
        assert!(
            report.contains(&b'R'),
            "child reached the allowed exec; got {report:?}"
        );
        // The ring recorded a denied /bin/true and an allowed /bin/echo.
        let snap = ring.snapshot(None);
        assert!(
            snap.events
                .iter()
                .any(|e| e.command.contains("/bin/true") && e.verdict == "deny"),
            "ring must show the denied exec: {:?}",
            snap.events
        );
        assert!(
            snap.events
                .iter()
                .any(|e| e.command.contains("/bin/echo") && e.verdict == "allow"),
            "ring must show the allowed exec: {:?}",
            snap.events
        );
    }
}
