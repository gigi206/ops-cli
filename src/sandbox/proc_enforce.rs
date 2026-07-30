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
//! installs the notification filter on itself, hands the listener fd **out** to the host supervisor
//! over a bind-mounted `AF_UNIX` socket (via `SCM_RIGHTS`, the same socket shape as the egress UDS),
//! then `execvp`s the real command. The filter is inherited across `fork`+`exec`, so the whole cage
//! process tree is covered — the agent cannot spawn an unsurveilled child. **Fail-closed:** if the
//! shim cannot install the filter or hand off the fd, it exits non-zero *without* executing the
//! payload — the command never runs unobserved.
//!
//! The shim is a **separate binary** (`proc-shim/`), carried inside sbx and materialized under the
//! data directory by [`crate::store::ensure_proc_shim`]. It has to be separate. What is bound into a
//! cage is reachable by whatever runs there, so binding a general-purpose binary would make the
//! sandbox's safety depend on none of that binary's state happening to be mounted — a property
//! nothing checks, and one that stops holding the first time a bind is added. The shim links `libc`
//! and nothing else, so what the cage holds is a program that can install a filter, pass a
//! descriptor and exec, and cannot express anything further.
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
use std::ffi::OsString;
use std::io;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use super::binds::ExtraBind;
use super::proc_control::ExecRing;
use crate::proc_policy::{ProcMode, ProcPolicy, ProcRule, Verdict};

/// The most `ask`-parked `execve`s a session holds at once. Beyond this, a further undecided `execve`
/// is denied outright (fail-closed) rather than growing the registry without bound — mirroring the
/// egress ask flood cap.
const ASK_PENDING_CAP: usize = 256;

/// How long an `ask`-parked `execve` waits for a human decision before it is auto-denied. A finite
/// bound is load-bearing: a parked `execve` blocks its process, and a parent `wait`ing on it would
/// otherwise hang the whole tree — the timeout releases it (with `EPERM`, fail-closed) so the tree
/// makes progress. A live `sbx proc allow`/`deny` decides it well within this window.
const ASK_TIMEOUT: Duration = Duration::from_secs(120);

/// Where the exec shim is bound read-only inside the cage, and where the notification handoff
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

// ── the live `--session` rule overlay ────────────────────────────────────────────────────────────

/// Extra allow/deny rules loaded into a **running** enforcing session by `sbx proc allow|deny
/// --session`, folded onto the resolved config policy at every decision (deny wins across both). It
/// is shared (`Arc`) between the supervisor's decide path and the control server that writes it,
/// starts empty, is never persisted, and dies with the session — the proc analogue of the egress
/// `ManualRules` overlay.
pub(crate) struct ProcOverlay {
    inner: RwLock<OverlayInner>,
}

#[derive(Default)]
struct OverlayInner {
    allow: Vec<ProcRule>,
    deny: Vec<ProcRule>,
}

impl ProcOverlay {
    pub(crate) fn new() -> ProcOverlay {
        ProcOverlay {
            inner: RwLock::new(OverlayInner::default()),
        }
    }

    /// Add a rule to the overlay (a `Deny` verdict to the deny list, else the allow list), deduped on
    /// the exact raw string. Returns whether it was newly added.
    pub(crate) fn remember(&self, verdict: Verdict, rule: &str) -> bool {
        let mut g = self.inner.write().expect("overlay lock");
        let list = if verdict == Verdict::Deny {
            &mut g.deny
        } else {
            &mut g.allow
        };
        if list.iter().any(|r| r.as_str() == rule) {
            return false;
        }
        list.push(ProcRule::new(rule));
        true
    }

    /// Decide an exec target with the current overlay folded onto `base` (a short read-lock held for
    /// the decision). Fast-pathed when the overlay is empty — the common case — to `base.decide`,
    /// mirroring the egress proxy's borrow-when-empty effective policy.
    pub(crate) fn decide(&self, base: &ProcPolicy, exec_path: &str) -> Verdict {
        let g = self.inner.read().expect("overlay lock");
        if g.allow.is_empty() && g.deny.is_empty() {
            base.decide(exec_path)
        } else {
            base.decide_with(exec_path, &g.allow, &g.deny)
        }
    }

    /// Snapshot the overlay as `(verdict-label, raw rule)` pairs (allow first, then deny), for
    /// `sbx proc rules`.
    pub(crate) fn snapshot(&self) -> Vec<(&'static str, String)> {
        let g = self.inner.read().expect("overlay lock");
        let mut out = Vec::with_capacity(g.allow.len() + g.deny.len());
        out.extend(g.allow.iter().map(|r| ("allow", r.as_str().to_string())));
        out.extend(g.deny.iter().map(|r| ("deny", r.as_str().to_string())));
        out
    }
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
/// `shim_bin` is the materialized exec shim (see [`crate::store::ensure_proc_shim`]), bound read-only.
/// The handoff socket appears in the cage at [`NOTIF_SOCK_CAGE_PATH`]; wrap the command with
/// [`wrap_command`] so it runs under the shim.
pub(crate) fn start(
    data_dir: &Path,
    shim_bin: &Path,
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
    // The live `--session` rule overlay, shared between the control server (which writes it) and the
    // supervisor (which folds it into every decision). The mode is captured here (Copy) because the
    // policy itself moves into the supervisor thread below.
    let overlay = Arc::new(ProcOverlay::new());
    let mode = policy.mode;

    // The proc control socket: `sbx proc logs` reads the ring, `sbx proc allow`/`deny` (under ask)
    // answer a parked `execve` or (with `--session`) load a live rule into the overlay. Best-effort — a
    // failure here still leaves enforcement running, only the out-of-band viewer/decider is unavailable.
    let control_socket = super::proc_control::proc_control_socket(data_dir, std::process::id());
    let _ = std::fs::remove_file(&control_socket);
    let control_socket = match UnixListener::bind(&control_socket) {
        Ok(l) => {
            let ring = ring.clone();
            let pending = pending.clone();
            let overlay = overlay.clone();
            std::thread::spawn(move || {
                let _ = super::proc_control::serve_enforced(l, ring, pending, overlay, mode);
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
        supervise(listener, &flag, &policy, &overlay, &ring, &pending);
    });

    let binds = vec![
        ExtraBind {
            src: shim_bin.to_path_buf(),
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
    overlay: &ProcOverlay,
    ring: &ExecRing,
    pending: &PendingExec,
) {
    let notif_fd = match accept_handoff(&listener, stop) {
        Some(fd) => fd,
        None => return, // stopped before the shim connected, or the handoff failed
    };
    drop(listener); // one handoff only; the agent cannot connect a second fd
    recv_loop(notif_fd, stop, policy, overlay, ring, pending);
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
    overlay: &ProcOverlay,
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
        // `ioctl`'s request argument is `c_ulong` on glibc but `c_int` on musl, so cast the
        // 32-bit request code to whichever the target libc expects (the shipping binary is musl).
        let rc = unsafe { libc::ioctl(notif_fd, notif_recv_code() as libc::Ioctl, &mut req) };
        if rc < 0 {
            let err = io::Error::last_os_error();
            if err.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return; // ENOENT / hang-up: the cage's filter is gone
        }
        handle_notif(notif_fd, &req, policy, overlay, ring, pending);
    }
}

/// Decide one notified `execve` and answer it. The path is read from the parked target's memory; an
/// unreadable path (an anomaly under the ancestor invariant) is treated as unmatched — never a
/// silent deny that could brick the whole cage, and never a silent allow of a named `deny`.
fn handle_notif(
    notif_fd: libc::c_int,
    req: &libc::seccomp_notif,
    policy: &ProcPolicy,
    overlay: &ProcOverlay,
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
            ProcMode::Ask => Verdict::Ask,
            _ => Verdict::Allow,
        }
    } else {
        // Decide against the config policy folded with the live `--session` overlay (deny wins across
        // both). The overlay read-lock is held only for this decision.
        overlay.decide(policy, &path)
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
    unsafe {
        libc::ioctl(
            notif_fd,
            notif_id_valid_code() as libc::Ioctl,
            &id as *const u64,
        ) == 0
    }
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
            notif_send_code() as libc::Ioctl,
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
    use crate::testutil::TmpDir;

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
                OsString::from(NOTIF_SOCK_CAGE_PATH),
                OsString::from("--"),
                OsString::from("node"),
                OsString::from("agent.js"),
            ]
        );
    }

    /// Lay the embedded shim down as an executable file and return its path. The tests below run
    /// **this** binary — the one a launch binds into a cage — so a change to the shim's protocol or
    /// its exit codes fails here rather than in a sandbox.
    fn materialized_shim(dir: &TmpDir) -> PathBuf {
        use std::os::unix::fs::PermissionsExt;
        let path = dir.join("proc-shim");
        std::fs::write(&path, crate::store::embedded_proc_shim()).expect("write the shim");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755))
            .expect("make the shim executable");
        path
    }

    /// Start a freshly written executable, waiting out `ETXTBSY`.
    ///
    /// Writing a file and then executing it is racy in a multi-threaded process: while the write is
    /// in flight its descriptor is inherited by whatever any *other* thread forks in that instant,
    /// and the kernel refuses to exec a file some process holds open for writing. The descriptor is
    /// close-on-exec, so the window shuts on its own the moment that other child execs — waiting is
    /// the whole fix. A test binary runs many threads spawning many processes, which is what makes
    /// this worth handling here.
    fn spawn_shim(cmd: &mut std::process::Command) -> std::process::Child {
        for _ in 0..100 {
            match cmd.spawn() {
                Err(e) if e.raw_os_error() == Some(libc::ETXTBSY) => {
                    std::thread::sleep(std::time::Duration::from_millis(20))
                }
                other => return other.expect("spawn the shim"),
            }
        }
        panic!("the shim stayed held open for writing");
    }

    /// The wait above is what keeps the tests below deterministic, so it is proved rather than
    /// assumed: a descriptor held open for writing does refuse the exec, and releasing it lets the
    /// very same spawn through.
    #[test]
    fn a_shim_held_open_for_writing_is_waited_out_rather_than_failed() {
        let dir = TmpDir::new();
        let shim = materialized_shim(&dir);
        let writer = std::fs::OpenOptions::new()
            .write(true)
            .open(&shim)
            .expect("hold the shim open for writing");

        assert_eq!(
            std::process::Command::new(&shim)
                .stderr(std::process::Stdio::null())
                .spawn()
                .err()
                .and_then(|e| e.raw_os_error()),
            Some(libc::ETXTBSY),
            "a held-open executable must be refused, or this proves nothing"
        );

        std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_millis(100));
            drop(writer);
        });
        let status =
            spawn_shim(std::process::Command::new(&shim).stderr(std::process::Stdio::null()))
                .wait()
                .expect("wait for the shim");
        assert_eq!(
            status.code(),
            Some(2),
            "the shim ran (and reported its usage) once the writer let go"
        );
    }

    /// Run the real shim against a real supervisor and return `(shim exit code, the ring)`.
    ///
    /// The harness is the production shape: a listening socket the shim connects back to, the shim
    /// `execvp`ing `payload`, and the parent running the real RECV → decide → SEND path. The
    /// supervisor is the child's direct parent, which is what makes the `/proc/<pid>/mem` read
    /// permitted under YAMA `ptrace_scope = 1` — the same relationship a launch has to its cage.
    fn run_under_supervisor(
        payload: &str,
        policy: &ProcPolicy,
        overlay: &ProcOverlay,
    ) -> (Option<i32>, Arc<ExecRing>) {
        let dir = TmpDir::new();
        let shim = materialized_shim(&dir);
        let sock_path = dir.join("notif.sock");
        let listener = UnixListener::bind(&sock_path).expect("bind the handoff socket");

        let mut child = spawn_shim(
            std::process::Command::new(&shim)
                .arg(&sock_path)
                .arg("--")
                .arg(payload),
        );

        let (sock, _) = listener.accept().expect("the shim never connected");
        let notif = recv_fd(&sock).expect("receive the listener fd");

        let ring = Arc::new(ExecRing::new(16));
        let pending = Arc::new(PendingExec::new());
        // Exactly one `execve` is notified: the shim's own exec of the payload. The shim's own
        // launch happened before the filter existed, so it never traps.
        if poll_readable(notif, 5000) {
            let mut req: libc::seccomp_notif = unsafe { std::mem::zeroed() };
            let rc = unsafe { libc::ioctl(notif, notif_recv_code() as libc::Ioctl, &mut req) };
            if rc >= 0 {
                handle_notif(notif, &req, policy, overlay, &ring, &pending);
            }
        }
        let status = child.wait().expect("wait for the shim");
        // SAFETY: notif is our owned descriptor from recv_fd; closed exactly once.
        unsafe { libc::close(notif) };
        (status.code(), ring)
    }

    /// The load-bearing enforcement proof, host-side (no cage): a `deny` verdict reaches the syscall
    /// as `EPERM`, so the payload is **never executed** — there is no time-of-check/time-of-use
    /// window on a refusal. The shim reports that refusal as its own exit 126.
    #[test]
    fn a_denied_execve_returns_eperm_and_the_payload_never_runs() {
        let policy = ProcPolicy::new(ProcMode::Enforce, &[], &["/bin/true".to_string()]);
        let (code, ring) = run_under_supervisor("/bin/true", &policy, &ProcOverlay::new());

        assert_eq!(
            code,
            Some(126),
            "a denied payload must surface as the shim's refusal code, not as the payload's own exit"
        );
        assert!(
            ring.snapshot(None)
                .events
                .iter()
                .any(|e| e.command.contains("/bin/true") && e.verdict == "deny"),
            "the ring must record the denied exec"
        );
    }

    /// The other half: an allowed target is `CONTINUE`d and really runs, so the shim is replaced by
    /// the payload and the payload's own exit code is what comes back.
    #[test]
    fn an_allowed_execve_runs_the_payload() {
        // A denylist that denies something else entirely: `/bin/true` is unmatched, which under
        // `enforce` means allowed.
        let policy = ProcPolicy::new(ProcMode::Enforce, &[], &["/bin/nonexistent".to_string()]);
        let (code, ring) = run_under_supervisor("/bin/true", &policy, &ProcOverlay::new());

        assert_eq!(code, Some(0), "the allowed payload must have run");
        assert!(
            ring.snapshot(None)
                .events
                .iter()
                .any(|e| e.command.contains("/bin/true") && e.verdict == "allow"),
            "the ring must record the allowed exec"
        );
    }

    /// A live `--session` overlay deny reaches the real syscall handler: the config policy denies
    /// **nothing** and the deny for `/bin/true` lives only in the [`ProcOverlay`]. The deterministic
    /// proof of the link that the cage `--session` e2e (skipped where the host cannot sandbox) would
    /// otherwise be the only cover for.
    #[test]
    fn a_session_overlay_deny_returns_eperm_at_the_syscall() {
        let policy = ProcPolicy::new(ProcMode::Enforce, &[], &[]);
        let overlay = ProcOverlay::new();
        assert!(overlay.remember(Verdict::Deny, "/bin/true"));

        let (code, ring) = run_under_supervisor("/bin/true", &policy, &overlay);

        assert_eq!(
            code,
            Some(126),
            "an overlay-sourced deny must refuse the payload at the syscall"
        );
        assert!(
            ring.snapshot(None)
                .events
                .iter()
                .any(|e| e.command.contains("/bin/true") && e.verdict == "deny"),
            "the ring must show the overlay-denied exec"
        );
    }

    /// The shim refuses to run its payload when it cannot reach a supervisor. This is the property
    /// that makes enforcement a boundary rather than a preference: a launch whose supervisor is gone
    /// must run nothing, not run everything.
    #[test]
    fn the_shim_refuses_to_run_a_payload_with_no_supervisor() {
        let dir = TmpDir::new();
        let shim = materialized_shim(&dir);
        let marker = dir.join("the-payload-ran");

        let status = spawn_shim(
            std::process::Command::new(&shim)
                .arg(dir.join("nothing-is-listening.sock"))
                .arg("--")
                .arg("/bin/touch")
                .arg(&marker),
        )
        .wait()
        .expect("wait for the shim");

        assert_eq!(
            status.code(),
            Some(96),
            "an unreachable supervisor must be reported, not worked around"
        );
        assert!(
            !marker.exists(),
            "the payload ran unenforced — the shim must never fall back to executing it"
        );
    }
}
