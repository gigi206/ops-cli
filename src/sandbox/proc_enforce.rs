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
//! systemd manager only happens at teardown, after the run). [`notif_id_valid`] guards
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
//!   not the native one this filter matches) does not slip through: the mandatory seccomp denylist
//!   is compiled by `seccompiler`, which prepends an architecture check that **kills the process**
//!   (`SECCOMP_RET_KILL_PROCESS`, the highest-precedence action) for any `seccomp_data.arch` that is
//!   not the native one. So a foreign-ABI `execve` traps that guard and dies rather than running
//!   untrapped. (The narrow exception is the x32 ABI, which shares x86-64's `arch` value with distinct
//!   syscall numbers — a blind spot shared with the denylist itself, and the base toolset is
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
use crate::proc_policy::{ProcPolicy, ProcRule, Verdict};

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
pub(super) const SHIM_CAGE_PATH: &str = "/opt/sbx/proc-shim";
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
    pub(crate) fn decide(&self, base: &ProcPolicy, caller: &[String], exec_path: &str) -> Verdict {
        let g = self.inner.read().expect("overlay lock");
        if g.allow.is_empty() && g.deny.is_empty() {
            base.decide(caller, exec_path)
        } else {
            base.decide_chain(caller, exec_path, &g.allow, &g.deny)
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
    /// Whether the shim must additionally notify on the open family.
    ///
    /// Carried here rather than re-derived at the call site so that the filter the cage installs and
    /// the lens the supervisor runs can never disagree: one launch, one answer.
    pub(crate) open_lens: bool,
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
    ring: Arc<ExecRing>,
}

impl ProcEnforce {
    /// The exec targets this supervisor refused, in order, deduplicated.
    ///
    /// A refusal is invisible from the outside: the `execve` returns an error to a process that
    /// decides for itself whether to mention it, and several do not — a caller then sees an empty
    /// result and a success code with nothing to explain them. Where a launch has no interactive
    /// control plane to consult (a task's), this is how the refusals get said out loud.
    ///
    /// Only a target that was **there** counts. A `PATH` walk refuses one candidate per directory it
    /// passes through, and reporting those would announce a handful of refusals every time a program
    /// is found somewhere other than the first entry — while the run succeeded and nothing was kept
    /// from it.
    pub(crate) fn refusals(&self) -> Vec<Refusal> {
        let mut seen: Vec<Refusal> = Vec::new();
        for event in self.ring.snapshot(None).events {
            if event.verdict != "deny" {
                continue;
            }
            let refusal = Refusal {
                caller: event.caller,
                target: event.command,
            };
            if !seen.contains(&refusal) {
                seen.push(refusal);
            }
        }
        seen
    }
}

/// One `execve` a policy stopped: who reached, and for what.
///
/// Both halves, because under a per-caller policy the target alone misleads. A program can be
/// declared and still refused — to whoever reached for it — and a report naming only the target
/// sends its reader to add an entry that is already there.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Refusal {
    /// The caller's own executable, or empty where the policy decided by target alone.
    pub(crate) caller: String,
    pub(crate) target: String,
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
    open: Option<(crate::open_policy::OpenPolicy, PathBuf)>,
    notifier: Arc<crate::sandbox::notify_sink::Notifier>,
) -> io::Result<(ProcEnforce, Wiring)> {
    start_inner(data_dir, shim_bin, policy, open, "", true, notifier)
}

/// The same supervisor for **one task invocation**, which differs from a session's in two ways.
///
/// Its socket carries the invocation number, because a session serving two invocations at once would
/// otherwise have them race for one path — the loser either fails to bind or has its live socket
/// unlinked from under it. The separator is a `.` so the runtime sweep can still read the pid out of
/// the name.
///
/// And it opens **no control socket**: `sbx proc allow`/`deny` decide a parked `execve`, and nothing
/// parks here — a task is confined by an allowlist, which refuses rather than asks. A socket nobody
/// can answer would be one more per-invocation file for no reach.
pub(crate) fn start_for_task(
    data_dir: &Path,
    shim_bin: &Path,
    policy: ProcPolicy,
    open: Option<(crate::open_policy::OpenPolicy, PathBuf)>,
    invocation: u64,
    notifier: Arc<crate::sandbox::notify_sink::Notifier>,
) -> io::Result<(ProcEnforce, Wiring)> {
    start_inner(
        data_dir,
        shim_bin,
        policy,
        open,
        &format!(".t{invocation}"),
        false,
        notifier,
    )
}

fn start_inner(
    data_dir: &Path,
    shim_bin: &Path,
    policy: ProcPolicy,
    open: Option<(crate::open_policy::OpenPolicy, PathBuf)>,
    instance: &str,
    control: bool,
    notifier: Arc<crate::sandbox::notify_sink::Notifier>,
) -> io::Result<(ProcEnforce, Wiring)> {
    let dir = super::proc_control::proc_control_dir(data_dir);
    // Unlike the observing path, this directory holds the notification socket enforcement itself
    // runs on, not only the reader's — so a failure here is the launch's, not a lens going quiet.
    super::lens::ensure_control_dir(&dir)?;

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
    let control_socket = if !control {
        None
    } else {
        let control_socket = super::proc_control::proc_control_socket(data_dir, std::process::id());
        let (ring, pending, overlay) = (ring.clone(), pending.clone(), overlay.clone());
        let served = super::lens::bind_and_serve(&control_socket, move |l| {
            super::proc_control::serve_enforced(l, ring, pending, overlay, mode)
        });
        match served {
            Ok(()) => Some(control_socket),
            Err(e) => {
                crate::diag::warn(&format!(
                    "could not bind the process-observation socket ({e}) — `sbx proc \
                     logs`/`allow`/`deny` will not see this session; under `ask` an unmatched exec \
                     then has no way to be decided and is auto-denied when its timeout lapses"
                ));
                None
            }
        }
    };

    let notif_socket = dir.join(format!("notif-{}{instance}.sock", std::process::id()));
    let _ = std::fs::remove_file(&notif_socket);
    let listener = UnixListener::bind(&notif_socket)?;
    listener.set_nonblocking(true)?;

    let stop = Arc::new(AtomicBool::new(false));
    let flag = stop.clone();
    let kept = ring.clone();
    let lens = open.map(|(policy, root)| OpenLens::new(policy, root));
    let lens_armed = lens.is_some();
    let handle = std::thread::spawn(move || {
        supervise(
            listener,
            &flag,
            &Deciding {
                policy: &policy,
                overlay: &overlay,
                ring: &ring,
                pending: &pending,
                notifier: &notifier,
                open: lens.as_ref(),
            },
        );
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
            ring: kept,
        },
        Wiring {
            binds,
            open_lens: lens_armed,
        },
    ))
}

/// Prepend the shim invocation to a command, so it runs under the exec filter. This is applied
/// **innermost** (before the provisioning/egress wraps), so only the real command and its children are
/// filtered, not the launch's own plumbing. All values are positional — no shell, no injection.
/// The flag that asks the shim for the open lens. Spelled once here and matched literally by
/// `proc-shim`, which refuses an unknown flag rather than running unenforced under one.
const OPEN_LENS_FLAG: &str = "open-lens";

pub(crate) fn wrap_command(cmd: Vec<OsString>, open_lens: bool) -> Vec<OsString> {
    let mut out = Vec::with_capacity(cmd.len() + 5);
    out.push(OsString::from(SHIM_CAGE_PATH));
    out.push(OsString::from(NOTIF_SOCK_CAGE_PATH));
    if open_lens {
        out.push(OsString::from(OPEN_LENS_FLAG));
    }
    out.push(OsString::from("--"));
    out.extend(cmd);
    out
}

/// The supervisor thread: wait (with a stop-checking poll) for the shim's one connection, receive the
/// listener fd, close the listening socket (no second connection is accepted), then run the receive
/// loop until the cage's filter is gone.
/// What one supervisor needs to decide a notification, carried together because every step of the
/// receive path needs the same set.
struct Deciding<'a> {
    policy: &'a ProcPolicy,
    overlay: &'a ProcOverlay,
    ring: &'a ExecRing,
    pending: &'a PendingExec,
    notifier: &'a crate::sandbox::notify_sink::Notifier,
    /// The content lens, when this launch asked for one.
    open: Option<&'a OpenLens>,
}

fn supervise(listener: UnixListener, stop: &AtomicBool, cx: &Deciding<'_>) {
    let notif_fd = match accept_handoff(&listener, stop) {
        Some(fd) => fd,
        None => return, // stopped before the shim connected, or the handoff failed
    };
    drop(listener); // one handoff only; the agent cannot connect a second fd
    recv_loop(notif_fd, stop, cx);
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
fn recv_loop(notif_fd: libc::c_int, stop: &AtomicBool, cx: &Deciding<'_>) {
    while !stop.load(Ordering::Relaxed) {
        if !poll_readable(notif_fd, 250) {
            // Idle tick: release any parked `execve` that has waited past the decision timeout, so a
            // stalled decision never hangs a process tree.
            cx.pending.sweep();
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
        handle_notif(notif_fd, &req, cx);
    }
}

/// Decide one notified `execve` and answer it. The path is read from the parked target's memory; an
/// unreadable path (an anomaly under the ancestor invariant) is treated as unmatched — never a
/// silent deny that could brick the whole cage, and never a silent allow of a named `deny`.
fn handle_notif(notif_fd: libc::c_int, req: &libc::seccomp_notif, cx: &Deciding<'_>) {
    // Confirm the notification is still live before reading the target's memory (a reaped-and-reused
    // pid would otherwise be read/acted on as the wrong process).
    if !notif_id_valid(notif_fd, req.id) {
        return;
    }
    // The open family is decided by *content* and answered here, never falling through to the exec
    // policy below — which reads a different argument and would judge an open against exec rules.
    // Checked on the syscall number rather than on the lens being present, so a notification the
    // filter should not have produced is still answered as an open.
    if let Some((dirfd, path_addr)) = open_args(req.data.nr, &req.data.args) {
        let outcome = match cx.open {
            Some(lens) => match read_exec_path(req.pid, path_addr) {
                // An unreadable path is allowed, like an unreadable exec target: the lens takes away
                // what it can prove, and a cage whose undecidable opens all failed would not run.
                Some(path) if !path.is_empty() => open_is_refused(lens, req.pid, dirfd, &path),
                _ => OpenOutcome::ALLOWED,
            },
            None => OpenOutcome::ALLOWED,
        };
        if let Some(report) = &outcome.report {
            if report.partial {
                crate::diag::warn(&format!(
                    "`{}` is longer than the {} bytes the content scan reads, so it is open to the \
                     cage on the strength of its start alone — anything past that was not examined",
                    report.path,
                    policy_scan_ceiling(cx.open)
                ));
            } else {
                // Named rather than merely counted: a refusal a person cannot attribute to a pattern
                // is one they will turn the lens off to escape.
                let shapes = report.shapes.join("`, `");
                crate::diag::warn(&format!(
                    "closed `{}` to the cage: its content matches `{shapes}`",
                    report.path
                ));
            }
        }
        if outcome.refused {
            respond_errno(notif_fd, req.id, libc::EACCES);
        } else {
            respond_continue(notif_fd, req.id);
        }
        return;
    }
    let path = read_exec_path(req.pid, req.data.args[0]).unwrap_or_default();
    let caller = caller_chain(cx.policy, req.pid);
    let verdict = if path.is_empty() {
        // Could not read the path: fall back to the mode's unmatched default rather than guessing a
        // name match — allow under a denylist, park under ask, refuse under an allowlist (where an
        // undecidable target is exactly the one that must not run).
        cx.policy.unmatched()
    } else {
        // Decide against the config policy folded with the live `--session` overlay (deny wins across
        // both). The overlay read-lock is held only for this decision.
        cx.overlay.decide(cx.policy, &caller, &path)
    };
    let shown = if path.is_empty() {
        "<unreadable>"
    } else {
        &path
    };
    let by = caller.last().map(String::as_str).unwrap_or_default();
    match verdict {
        Verdict::Allow => {
            cx.ring.push_verdict(req.pid, by, shown, "allow");
            respond_continue(notif_fd, req.id);
        }
        Verdict::Deny => {
            let errno = refusal_errno(req.pid, shown);
            // A name lookup is one `execve` per `PATH` entry, so a program found in the fourth
            // directory leaves three refusals behind it — of files that were never there. Recorded
            // apart from a refusal of something real, because they are the same event a cage with
            // no policy at all would produce, and a warning that fires when nothing was denied
            // teaches a reader to stop reading it.
            let recorded = if errno == libc::ENOENT {
                "absent"
            } else {
                "deny"
            };
            cx.ring.push_verdict(req.pid, by, shown, recorded);
            // Announce only a refusal of something that was **there**. A `PATH` walk refuses one
            // candidate per directory it passes through, and announcing those would raise a handful
            // of notifications every time a program is simply found somewhere other than the first
            // entry — while the run succeeded and nothing was kept from it. Same rule the refusal
            // report applies, for the same reason.
            if recorded == "deny" {
                cx.notifier.block(crate::notify::Block {
                    event: crate::notify::NotifyEvent::Proc,
                    subject: shown.to_string(),
                    reason: "denied-by-policy".to_string(),
                    detail: if by.is_empty() {
                        "the exec policy does not allow this program to run".to_string()
                    } else {
                        format!("`{by}` is not allowed to run it by the exec policy")
                    },
                    // No `sbx proc allow` suggestion: under `enforce` the rule that refused is a
                    // deliberate `deny` entry, and a one-line "allow it" would invite undoing the
                    // very thing that was asked for. `sbx proc logs` is where the decision is read.
                    fix: String::new(),
                });
            }
            respond_errno(notif_fd, req.id, errno);
        }
        Verdict::Ask => {
            // Park it: register the kernel notification id so the control plane can answer it later.
            // The receive loop does not block — it returns to draining the next notification.
            cx.ring.push_verdict(req.pid, by, shown, "ask");
            cx.pending.park(notif_fd, req.id, req.pid, shown);
        }
    }
}

/// How the caller of a notified `execve` is addressed, when the policy decides by caller at all.
///
/// One element today: the program the calling process **is** at the moment of the syscall, read from
/// `/proc/<pid>/exe`. A chain rather than a bare program because the address is what a deeper form
/// would lengthen, and because `decide_chain` reading only the last element is a fact stated in one
/// place instead of a signature everything would have to change.
///
/// `/proc/<pid>/exe` and not the argv the process was started with: a process writes its own
/// `cmdline`, so that is the caller's own account of itself. `exe` is the kernel's, it survives
/// `fork` (a child that has not exec'd is still its parent's program), and it survives reparenting —
/// so a double-fork does not turn a program into an unknown. It resolves symlinks, which is why the
/// keys a policy is built from are resolved the same way and never guessed.
///
/// Skipped entirely under a flat policy, where the caller decides nothing. Measured on a workload
/// that does nothing but `execve`, the `readlink` costs ~3 µs: about a sixth of the ~17 µs the
/// supervisor spends per notification, and a tenth of the ~31 µs enforcement adds to an `execve`.
/// Small in absolute terms — but there is one receive loop for the whole cage, so per-notification
/// work is a throughput ceiling and not merely a latency; and a syscall issued for an answer nobody
/// reads is not a small cost, it is a wrong one.
fn caller_chain(policy: &ProcPolicy, pid: u32) -> Vec<String> {
    if policy.graph.is_none() {
        return Vec::new();
    }
    std::fs::read_link(format!("/proc/{pid}/exe"))
        .ok()
        .map(|p| vec![p.to_string_lossy().into_owned()])
        .unwrap_or_default()
}

/// Which errno a refusal answers with: `ENOENT` when the target does not exist, `EPERM` otherwise.
///
/// This is not a security choice — the syscall never runs either way, and a file's absence is not a
/// secret the caller could not learn with `stat`. It is what keeps a **name lookup behaving like a
/// name lookup**. `execvp("git")` is not one syscall: it issues an `execve` per `PATH` entry until
/// one succeeds, and glibc only keeps walking on `ENOENT`/`EACCES`. Answering `EPERM` for a
/// candidate that was never there aborts the walk before it reaches the directory that has the
/// program — so under an allowlist keyed to absolute paths, every allowed program not sitting in the
/// first `PATH` entry would become unlaunchable. Measured, not assumed.
///
/// The target's path is read in **its** mount namespace, so existence is tested through
/// `/proc/<pid>/root`. Anything that cannot be resolved that way (a relative path, a dead target)
/// keeps `EPERM`, the stricter answer.
fn refusal_errno(pid: u32, path: &str) -> libc::c_int {
    if !path.starts_with('/') {
        return libc::EPERM;
    }
    if Path::new(&format!("/proc/{pid}/root{path}")).exists() {
        libc::EPERM
    } else {
        libc::ENOENT
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

/// Read a NUL-terminated path from a parked target's memory at `addr`. The notified *thread* is
/// blocked in the `execve`, so the pointer is valid to read — but only that thread is stopped: a
/// sibling in the cage can rewrite the buffer between this read and the `CONTINUE`, which is why
/// allowing a named path is TOCTOU-racy while refusing one is not (module header). Nothing here
/// closes that window. Returns `None` on any read failure.
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

/// Where a notified open keeps its directory descriptor and its path pointer, by syscall number.
///
/// The three forms do not agree on argument order: `open(path, …)` has no descriptor at all and is
/// implicitly relative to the working directory, while `openat(dirfd, path, …)` and
/// `openat2(dirfd, path, …)` lead with one. Reading the path from the wrong register would scan an
/// unrelated address, so the mapping is explicit and unit-tested rather than inferred at the call
/// site.
///
/// `None` for any other syscall: the same receive loop also carries `execve`, which is decided
/// elsewhere.
fn open_args(nr: libc::c_int, args: &[u64; 6]) -> Option<(libc::c_int, u64)> {
    #[cfg(target_arch = "x86_64")]
    if nr as libc::c_long == libc::SYS_open {
        return Some((libc::AT_FDCWD, args[0]));
    }
    if nr as libc::c_long == libc::SYS_openat || nr as libc::c_long == libc::SYS_openat2 {
        return Some((args[0] as libc::c_int, args[1]));
    }
    None
}

/// One file's identity for the scan cache: the same bytes under a different name are the same
/// answer, and a rewrite changes at least one of these fields.
///
/// `mtime` alone would miss a write that lands inside the same timestamp granularity, so size and
/// inode ride along. This is a cache key, not a boundary: a rewrite that preserved all four would
/// serve a stale verdict, which is the same window a scan-at-open filesystem has and is why the lens
/// is a backstop rather than a proof.
#[derive(PartialEq, Eq, PartialOrd, Ord, Clone, Copy, Debug)]
struct FileId {
    dev: u64,
    ino: u64,
    size: u64,
    mtime: i64,
    mtime_nsec: i64,
}

impl FileId {
    fn of(meta: &std::fs::Metadata) -> FileId {
        use std::os::unix::fs::MetadataExt;
        FileId {
            dev: meta.dev(),
            ino: meta.ino(),
            size: meta.size(),
            mtime: meta.mtime(),
            mtime_nsec: meta.mtime_nsec(),
        }
    }
}

/// How many distinct files the scan cache remembers within one launch.
///
/// A build reopens the same headers and sources over and over, which is what the cache exists for.
/// The ceiling bounds the supervisor's own memory; past it the map is cleared rather than evicted
/// one by one, because the cost of a miss is one bounded scan and the cost of tracking recency on
/// every open is paid whether or not it ever helps.
const SCAN_CACHE_MAX: usize = 8192;

/// The per-launch memory of what the content scan already decided.
#[derive(Default)]
struct ScanCache {
    seen: Mutex<BTreeMap<FileId, bool>>,
}

impl ScanCache {
    /// The remembered verdict for `id`, if this launch already scanned that exact content.
    fn get(&self, id: &FileId) -> Option<bool> {
        self.seen.lock().ok()?.get(id).copied()
    }

    /// Remember `refused` for `id`.
    fn put(&self, id: FileId, refused: bool) {
        let Ok(mut seen) = self.seen.lock() else {
            return;
        };
        if seen.len() >= SCAN_CACHE_MAX {
            seen.clear();
        }
        seen.insert(id, refused);
    }
}

/// The scan ceiling of the lens in force, for a message that has to say how far it looked.
fn policy_scan_ceiling(open: Option<&OpenLens>) -> usize {
    open.map(|l| l.policy.max_scan()).unwrap_or(0)
}

/// The content lens a launch runs with: the compiled patterns, and what this launch already decided.
///
/// Held together because neither is useful alone — and because the cache is per launch, so two
/// sessions never share a verdict formed against another's patterns.
pub(crate) struct OpenLens {
    policy: crate::open_policy::OpenPolicy,
    cache: ScanCache,
    /// The project root, on the host, outside which nothing is scanned.
    ///
    /// The lens exists for the credentials that sit in the tree an agent works in. Everything else a
    /// cage opens — the read-only store, `/usr/lib`, `/proc` — is content the user did not write and
    /// cannot leave a secret in, and it is also where the volume is: a build's opens are mostly
    /// there. Bounding the scan by the project is what keeps the cost proportional to the risk.
    ///
    /// The bound is applied to the path the **kernel resolved**, never to the one the cage wrote, so
    /// a symlink pointing out of the tree cannot smuggle a scan-worthy file past it — nor one
    /// pointing in be scanned twice under two names.
    root: PathBuf,
}

impl OpenLens {
    pub(crate) fn new(policy: crate::open_policy::OpenPolicy, root: PathBuf) -> OpenLens {
        OpenLens {
            policy,
            cache: ScanCache::default(),
            root,
        }
    }
}

/// Decide one notified open: does the file it names carry a configured shape?
///
/// Returns `true` when the open must be refused. The supervisor reads the bytes **outside** the
/// cage, so the answer is formed before the cage holds a descriptor — and because the refusal is an
/// errno rather than an approval, it is not exposed to the re-pointing race that makes an *allow*
/// racy (module header).
///
/// Anything the supervisor cannot read — a path it cannot resolve, a directory, a device, a file it
/// has no permission on — is **allowed**. The lens closes what it can prove carries a secret; it is
/// not an allowlist, and a launch whose every unreadable open failed would not survive its first
/// `/proc` read.
fn open_is_refused(lens: &OpenLens, pid: u32, dirfd: libc::c_int, path: &str) -> OpenOutcome {
    let (policy, cache) = (&lens.policy, &lens.cache);
    use std::io::Read;
    use std::os::unix::io::FromRawFd;
    let target = open_target_path(pid, dirfd, path);
    let Ok(cpath) = std::ffi::CString::new(target.as_os_str().as_encoded_bytes()) else {
        return OpenOutcome::ALLOWED;
    };
    // Opened `O_PATH` first, which never blocks whatever sits at the path. Opening for reading
    // straight away would hang on a FIFO with no writer — and this is the one thread every other
    // open in the cage is queued behind, so that hang would be the whole cage's.
    //
    // Deliberately **without** `O_NOFOLLOW`: the kernel is about to follow the cage's symlinks, and
    // a scan that stopped at the link would be walked around with one `ln -s`.
    // SAFETY: cpath is a live NUL-terminated path for the duration of the call.
    let probe = unsafe { libc::open(cpath.as_ptr(), libc::O_PATH | libc::O_CLOEXEC) };
    if probe < 0 {
        return OpenOutcome::ALLOWED;
    }
    // SAFETY: probe is a fresh owned descriptor; the File takes sole ownership and closes it.
    let probe = unsafe { std::fs::File::from_raw_fd(probe) };
    use std::os::unix::io::AsRawFd;
    // What the kernel actually resolved, which is what the project bound is applied to.
    let Ok(resolved) = std::fs::read_link(format!("/proc/self/fd/{}", probe.as_raw_fd())) else {
        return OpenOutcome::ALLOWED;
    };
    if !resolved.starts_with(&lens.root) {
        return OpenOutcome::ALLOWED;
    }
    let Ok(meta) = probe.metadata() else {
        return OpenOutcome::ALLOWED;
    };
    if !meta.is_file() {
        // A directory, a FIFO, a socket or a device carries no content this policy is written
        // about, and reading one could block indefinitely.
        return OpenOutcome::ALLOWED;
    }
    let id = FileId::of(&meta);
    if let Some(remembered) = cache.get(&id) {
        // Already decided this launch: the same answer without reopening, reading or naming — which
        // is the whole point of the cache, and why it is consulted before the read is set up. A
        // repeat refusal is silent on purpose: a build reopening one denied file would otherwise
        // fill the diagnostics with the same line.
        return OpenOutcome {
            refused: remembered,
            report: None,
        };
    }
    // Re-opened for reading through the descriptor already resolved, so the bytes scanned belong to
    // the file just inspected rather than to whatever the path names a moment later.
    let Ok(mut file) = std::fs::File::open(format!("/proc/self/fd/{}", probe.as_raw_fd())) else {
        return OpenOutcome::ALLOWED;
    };
    // Bounded in *size*, not in time. `S_ISREG` is true of a file on a FUSE mount, an NFS path or
    // any other backing store that can stall, and this read is on the one thread every other open in
    // the cage is queued behind — the same failure shape the `O_PATH` probe closes for a FIFO, left
    // open here because bounding it needs a reader that can be abandoned rather than a ceiling.
    let mut buf = Vec::with_capacity(policy.max_scan().min(meta.len() as usize + 1));
    if file
        .by_ref()
        .take(policy.max_scan() as u64)
        .read_to_end(&mut buf)
        .is_err()
    {
        return OpenOutcome::ALLOWED;
    }
    let verdict = policy.verdict(&buf);
    cache.put(id, verdict.matched);
    if !verdict.matched {
        // The dangerous truncation is *this* one. A file that matched is refused whatever was left
        // unread, but a file that came back clean only because the scan stopped is a false negative,
        // and staying silent about it would present a prefix as a whole-file result.
        return OpenOutcome {
            refused: false,
            report: verdict.scanned.is_partial().then(|| OpenReport {
                path: path.to_string(),
                shapes: Vec::new(),
                partial: true,
            }),
        };
    }
    // Naming the shapes costs a second walk, paid only here — on content already refused, once per
    // file per launch.
    let shapes: Vec<String> = policy
        .matched_names(&buf)
        .into_iter()
        .map(str::to_string)
        .collect();
    OpenOutcome {
        refused: true,
        report: Some(OpenReport {
            path: path.to_string(),
            shapes,
            partial: false,
        }),
    }
}

/// What one notified open resolved to, and whether it is worth telling anyone.
struct OpenOutcome {
    refused: bool,
    /// Present only the first time this launch scanned the file, so one reopened in a loop is
    /// reported once.
    report: Option<OpenReport>,
}

impl OpenOutcome {
    const ALLOWED: OpenOutcome = OpenOutcome {
        refused: false,
        report: None,
    };
}

/// What one file's first scan is worth saying: either the shapes that closed it, or that the answer
/// covers only a prefix.
struct OpenReport {
    path: String,
    /// The patterns that matched. Empty when the report is about coverage rather than a refusal.
    shapes: Vec<String>,
    /// Whether the scan stopped before the end of the file, leaving the rest unexamined.
    partial: bool,
}

/// The host-side path naming what a cage's `openat(dirfd, path, …)` is about to open.
///
/// The supervisor runs outside the cage's mount namespace, so a path the cage wrote means something
/// else — or nothing — applied to the host root. Every form is therefore resolved through the
/// target's own `/proc` links, which the kernel resolves in *the target's* namespace:
///
/// - an absolute path, through `/proc/<pid>/root`;
/// - a relative path against `AT_FDCWD`, through `/proc/<pid>/cwd`;
/// - a relative path against a directory descriptor, through `/proc/<pid>/fd/<dirfd>`.
///
/// Concatenated rather than [`PathBuf::push`]ed, because pushing an absolute path *replaces* the
/// prefix — which would silently turn a cage path into the supervisor's own view of it.
///
/// Pure construction: whether the result resolves, and to what, is what the caller's `open` finds
/// out. Like [`read_exec_path`], nothing here closes the TOCTOU window on an *allow* — the path can
/// be re-pointed after it is read, which is why only a refusal is sound (module header).
fn open_target_path(pid: u32, dirfd: libc::c_int, path: &str) -> PathBuf {
    if path.starts_with('/') {
        return PathBuf::from(format!("/proc/{pid}/root{path}"));
    }
    let base = if dirfd == libc::AT_FDCWD {
        format!("/proc/{pid}/cwd")
    } else {
        format!("/proc/{pid}/fd/{dirfd}")
    };
    // A relative path is joined normally: it cannot take over the prefix.
    PathBuf::from(base).join(path)
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
mod open_path_tests {
    use super::*;

    #[test]
    fn each_open_form_is_read_from_its_own_registers() {
        // Distinctive values so a wrong register is visible rather than plausible.
        let args: [u64; 6] = [11, 22, 33, 44, 55, 66];

        #[cfg(target_arch = "x86_64")]
        assert_eq!(
            open_args(libc::SYS_open as libc::c_int, &args),
            Some((libc::AT_FDCWD, 11)),
            "`open(path, …)` carries no descriptor: the path is the first argument, and the form is              implicitly relative to the working directory"
        );
        assert_eq!(
            open_args(libc::SYS_openat as libc::c_int, &args),
            Some((11, 22)),
            "`openat(dirfd, path, …)` leads with the descriptor, so the path is the second argument"
        );
        assert_eq!(
            open_args(libc::SYS_openat2 as libc::c_int, &args),
            Some((11, 22)),
            "`openat2` agrees with `openat` on the first two arguments"
        );
    }

    #[test]
    fn a_syscall_that_is_not_an_open_is_left_to_the_exec_path() {
        let args: [u64; 6] = [11, 22, 33, 44, 55, 66];
        assert_eq!(
            open_args(libc::SYS_execve as libc::c_int, &args),
            None,
            "the same receive loop carries `execve`, which must fall through to the exec policy              rather than be read as a path to scan"
        );
        assert_eq!(open_args(libc::SYS_read as libc::c_int, &args), None);
    }

    #[test]
    fn an_absolute_path_is_read_through_the_targets_own_root() {
        assert_eq!(
            open_target_path(42, libc::AT_FDCWD, "/etc/passwd"),
            PathBuf::from("/proc/42/root/etc/passwd"),
            "an absolute cage path must be resolved in the cage's mount namespace, never against \
             the supervisor's own root"
        );
    }

    #[test]
    fn a_relative_path_follows_the_descriptor_it_was_opened_against() {
        assert_eq!(
            open_target_path(42, libc::AT_FDCWD, "secrets/prod.key"),
            PathBuf::from("/proc/42/cwd/secrets/prod.key")
        );
        assert_eq!(
            open_target_path(42, 7, "prod.key"),
            PathBuf::from("/proc/42/fd/7/prod.key"),
            "a path opened against a directory fd is resolved through that fd, not the cwd"
        );
    }

    // The lint fires on the very call this test exists to pin: the point is to demonstrate that
    // `join` discards the prefix, which is why `open_target_path` concatenates instead.
    #[allow(clippy::join_absolute_paths)]
    #[test]
    fn an_absolute_path_never_takes_over_the_prefix() {
        // The trap this guards: `PathBuf::join` with an absolute argument discards everything to its
        // left, which would hand the supervisor its *own* /etc/shadow instead of the cage's.
        let joined = PathBuf::from("/proc/42/root").join("/etc/shadow");
        assert_eq!(
            joined,
            PathBuf::from("/etc/shadow"),
            "join really does drop the prefix — which is why the absolute arm concatenates"
        );
        assert_eq!(
            open_target_path(42, libc::AT_FDCWD, "/etc/shadow"),
            PathBuf::from("/proc/42/root/etc/shadow")
        );
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

    /// Run `payload` under a supervisor whose content lens carries `patterns`, draining every
    /// notification until the payload exits.
    ///
    /// Unlike the exec harness, the notification count cannot be fixed in advance: the open lens
    /// also traps the loader's own opens, whose number belongs to the host's libc rather than to
    /// this test. So the loop drains until the child is gone.
    fn run_with_open_lens(
        payload: &[&str],
        patterns: &[&str],
        root: &std::path::Path,
    ) -> (Option<i32>, String) {
        let dir = TmpDir::new();
        let shim = materialized_shim(&dir);
        let sock_path = dir.join("notif.sock");
        let listener = UnixListener::bind(&sock_path).expect("bind the handoff socket");

        let mut cmd = std::process::Command::new(&shim);
        cmd.arg(&sock_path)
            .arg(OPEN_LENS_FLAG)
            .arg("--")
            .args(payload)
            .stderr(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped());
        let mut child = spawn_shim(&mut cmd);

        let (sock, _) = listener.accept().expect("the shim never connected");
        let notif = recv_fd(&sock).expect("receive the listener fd");

        let owned: Vec<String> = patterns.iter().map(|p| (*p).to_string()).collect();
        let lens = OpenLens::new(
            crate::open_policy::OpenPolicy::compile(&owned, crate::open_policy::MAX_SCAN_DEFAULT)
                .expect("the test patterns compile")
                .expect("a non-empty list yields a policy"),
            // The caller's fixture directory is the "project" here: everything else the payload
            // opens — its loader, its libc — is out of scope exactly as the store is in a real
            // launch. Canonicalised because the bound is applied to a resolved path.
            std::fs::canonicalize(root).expect("canonical fixture root"),
        );
        // Nothing is denied by exec policy here: the lens is what the test is about.
        let policy = ProcPolicy::new(ProcMode::Enforce, &[], &[]);
        let overlay = ProcOverlay::new();
        let ring = Arc::new(ExecRing::new(64));
        let pending = Arc::new(PendingExec::new());

        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
        let status = loop {
            if let Some(st) = child.try_wait().expect("poll the payload") {
                break Some(st);
            }
            if std::time::Instant::now() > deadline {
                let _ = child.kill();
                break None;
            }
            if !poll_readable(notif, 50) {
                continue;
            }
            let mut req: libc::seccomp_notif = unsafe { std::mem::zeroed() };
            let rc = unsafe { libc::ioctl(notif, notif_recv_code() as libc::Ioctl, &mut req) };
            if rc >= 0 {
                handle_notif(
                    notif,
                    &req,
                    &Deciding {
                        policy: &policy,
                        overlay: &overlay,
                        ring: &ring,
                        pending: &pending,
                        notifier: &crate::sandbox::notify_sink::Notifier::disabled(),
                        open: Some(&lens),
                    },
                );
            }
        };
        // SAFETY: notif is this test's owned descriptor, closed exactly once.
        unsafe { libc::close(notif) };
        let out = child
            .wait_with_output()
            .expect("collect the payload output");
        let code = status.and_then(|s| s.code());
        let mut text = String::from_utf8_lossy(&out.stdout).into_owned();
        text.push_str(&String::from_utf8_lossy(&out.stderr));
        (code, text)
    }

    #[test]
    fn a_file_whose_content_matches_is_refused_at_the_open() {
        let dir = TmpDir::new();
        let secret = dir.join("carries.txt");
        std::fs::write(&secret, b"API key: sk-ABC123DEF456GHI789\n").expect("write the fixture");

        let (code, out) = run_with_open_lens(
            &["/bin/cat", secret.to_str().expect("utf-8 fixture path")],
            &[r"sk-[A-Za-z0-9]{12,}"],
            &dir.join("."),
        );

        assert_ne!(
            code,
            Some(0),
            "reading a file whose content matches must fail, not succeed quietly: {out}"
        );
        assert!(
            !out.contains("sk-ABC123DEF456GHI789"),
            "not one byte of the matched content may reach the cage: {out}"
        );
        assert!(
            out.contains("Permission denied") || out.contains("denied"),
            "the refusal must surface as the open's own errno: {out}"
        );
    }

    #[test]
    #[ignore = "measurement, not an assertion"]
    fn measure_lens_end_to_end() {
        let dir = TmpDir::new();
        let tree = dir.join("tree");
        std::fs::create_dir_all(&tree).expect("make the tree");
        let body =
            "fn resolve(path: &Path) -> Option<PathBuf> { path.canonicalize().ok() }\n".repeat(430); // ~30 KiB per file
        for i in 0..200 {
            std::fs::write(tree.join(format!("f{i}.rs")), &body).expect("write a file");
        }
        let target = tree.to_str().expect("utf-8 path").to_string();

        let t0 = std::time::Instant::now();
        let bare = std::process::Command::new("/bin/grep")
            .args(["-rl", "nothing-matches-this", &target])
            .output()
            .expect("run grep");
        let bare_ms = t0.elapsed();
        assert!(!bare.status.success() || bare.stdout.is_empty());

        let t1 = std::time::Instant::now();
        let (code, _) = run_with_open_lens(
            &["/bin/grep", "-rl", "nothing-matches-this", &target],
            &[r"sk-[A-Za-z0-9]{12,}", r"AKIA[0-9A-Z]{16}"],
            &tree,
        );
        let lens_ms = t1.elapsed();

        println!(
            "200 files x 30 KiB — bare={bare_ms:>8.2?}  lens={lens_ms:>8.2?}  ratio={:.1}x  code={code:?}",
            lens_ms.as_secs_f64() / bare_ms.as_secs_f64()
        );
    }

    #[test]
    fn a_symlink_to_matching_content_is_refused_like_its_target() {
        let dir = TmpDir::new();
        let secret = dir.join("carries.txt");
        std::fs::write(&secret, b"API key: sk-ABC123DEF456GHI789\n").expect("write the fixture");
        let link = dir.join("innocent.txt");
        std::os::unix::fs::symlink(&secret, &link).expect("link the fixture");

        let (code, out) = run_with_open_lens(
            &["/bin/cat", link.to_str().expect("utf-8 fixture path")],
            &[r"sk-[A-Za-z0-9]{12,}"],
            &dir.join("."),
        );

        assert_ne!(
            code,
            Some(0),
            "the kernel is about to follow this link, so the scan must follow it too — otherwise \
             one `ln -s` walks around the lens: {out}"
        );
        assert!(
            !out.contains("sk-ABC123DEF456GHI789"),
            "no byte of the linked-to content may reach the cage: {out}"
        );
    }

    #[test]
    fn a_fifo_does_not_wedge_the_supervisor() {
        let dir = TmpDir::new();
        let fifo = dir.join("pipe");
        let cfifo = std::ffi::CString::new(fifo.as_os_str().as_encoded_bytes()).expect("fifo path");
        // SAFETY: cfifo is a live NUL-terminated path for the duration of the call.
        assert_eq!(unsafe { libc::mkfifo(cfifo.as_ptr(), 0o600) }, 0, "mkfifo");
        let clean = dir.join("ordinary.txt");
        std::fs::write(&clean, b"read after the fifo\n").expect("write the fixture");

        // A *reader* on a FIFO with no writer is what blocks — `<>` would block nobody and prove
        // nothing. The payload therefore issues a plain `O_RDONLY` open under `timeout`, so it parks
        // in that open and then gives up on its own rather than leaking a process that holds the
        // harness's pipe. The supervisor is notified of that same open: if it parked with it, the
        // read that follows would never be decided and this test would hit its deadline.
        let script = format!(
            "timeout 1 cat {} >/dev/null 2>&1; cat {}",
            fifo.to_str().expect("utf-8 fixture path"),
            clean.to_str().expect("utf-8 fixture path")
        );
        let (code, out) = run_with_open_lens(
            &["/bin/sh", "-c", &script],
            &[r"sk-[A-Za-z0-9]{12,}"],
            &dir.join("."),
        );

        assert_eq!(
            code,
            Some(0),
            "an open on a FIFO must not wedge the one thread every other open queues behind: {out}"
        );
        assert!(
            out.contains("read after the fifo"),
            "the open after the FIFO must still be decided: {out}"
        );
    }

    #[test]
    fn a_file_whose_content_does_not_match_is_read_normally() {
        let dir = TmpDir::new();
        let clean = dir.join("ordinary.txt");
        std::fs::write(&clean, b"just ordinary prose, no credential here\n")
            .expect("write the fixture");

        let (code, out) = run_with_open_lens(
            &["/bin/cat", clean.to_str().expect("utf-8 fixture path")],
            &[r"sk-[A-Za-z0-9]{12,}"],
            &dir.join("."),
        );

        assert_eq!(
            code,
            Some(0),
            "a file the patterns do not match must read as it always did: {out}"
        );
        assert!(
            out.contains("just ordinary prose"),
            "the content must arrive intact: {out}"
        );
    }

    #[test]
    fn wrap_command_prepends_the_shim_positionally() {
        let cmd = vec![OsString::from("node"), OsString::from("agent.js")];
        let out = wrap_command(cmd.clone(), false);
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

    #[test]
    fn the_open_lens_flag_rides_before_the_separator() {
        let cmd = vec![OsString::from("node"), OsString::from("agent.js")];
        let out = wrap_command(cmd, true);
        assert_eq!(
            out,
            vec![
                OsString::from(SHIM_CAGE_PATH),
                OsString::from(NOTIF_SOCK_CAGE_PATH),
                OsString::from(OPEN_LENS_FLAG),
                OsString::from("--"),
                OsString::from("node"),
                OsString::from("agent.js"),
            ],
            "the flag must sit between the socket and `--`, where the shim parses its flags: after              the separator it would be handed to the payload as an argument instead"
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
        payload: &[&str],
        policy: &ProcPolicy,
        overlay: &ProcOverlay,
    ) -> (Option<i32>, Arc<ExecRing>) {
        // One notification: the shim's own exec of the payload. The shim's own launch happened
        // before the filter existed, so it never traps.
        run_under_supervisor_n(payload, policy, overlay, 1)
    }

    /// The same harness, serving `notifs` notifications instead of one — what a payload that goes on
    /// to exec something itself needs.
    fn run_under_supervisor_n(
        payload: &[&str],
        policy: &ProcPolicy,
        overlay: &ProcOverlay,
        notifs: usize,
    ) -> (Option<i32>, Arc<ExecRing>) {
        run_under_supervisor_full(payload, policy, overlay, notifs, None)
    }

    /// The harness with the payload's `PATH` pinned, so a test about name lookup does not depend on
    /// what the developer's own `PATH` happens to hold.
    fn run_under_supervisor_full(
        payload: &[&str],
        policy: &ProcPolicy,
        overlay: &ProcOverlay,
        notifs: usize,
        path: Option<&str>,
    ) -> (Option<i32>, Arc<ExecRing>) {
        run_under_supervisor_notified(
            payload,
            policy,
            overlay,
            notifs,
            path,
            &crate::sandbox::notify_sink::Notifier::disabled(),
        )
    }

    fn run_under_supervisor_notified(
        payload: &[&str],
        policy: &ProcPolicy,
        overlay: &ProcOverlay,
        notifs: usize,
        path: Option<&str>,
        notifier: &crate::sandbox::notify_sink::Notifier,
    ) -> (Option<i32>, Arc<ExecRing>) {
        let dir = TmpDir::new();
        let shim = materialized_shim(&dir);
        let sock_path = dir.join("notif.sock");
        let listener = UnixListener::bind(&sock_path).expect("bind the handoff socket");

        let mut cmd = std::process::Command::new(&shim);
        cmd.arg(&sock_path).arg("--").args(payload);
        if let Some(p) = path {
            cmd.env("PATH", p);
        }
        let mut child = spawn_shim(&mut cmd);

        let (sock, _) = listener.accept().expect("the shim never connected");
        let notif = recv_fd(&sock).expect("receive the listener fd");

        let ring = Arc::new(ExecRing::new(16));
        let pending = Arc::new(PendingExec::new());
        for _ in 0..notifs {
            if !poll_readable(notif, 5000) {
                break;
            }
            let mut req: libc::seccomp_notif = unsafe { std::mem::zeroed() };
            let rc = unsafe { libc::ioctl(notif, notif_recv_code() as libc::Ioctl, &mut req) };
            if rc >= 0 {
                handle_notif(
                    notif,
                    &req,
                    &Deciding {
                        policy,
                        overlay,
                        ring: &ring,
                        pending: &pending,
                        notifier,
                        open: None,
                    },
                );
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
    fn a_denied_execve_announces_what_the_user_reads() {
        // The refusal's own words, which nothing else asserted: they are built here and rendered by
        // the notification path, so a wrong edit to either ships as user-visible text that every
        // other test still passes over.
        struct Recorder(Arc<Mutex<Vec<(String, String)>>>);
        impl crate::sandbox::notify_sink::Sink for Recorder {
            fn deliver(
                &mut self,
                summary: &str,
                body: &str,
                _replaces: Option<u32>,
            ) -> Result<Option<u32>, ()> {
                self.0
                    .lock()
                    .expect("recorder lock")
                    .push((summary.to_string(), body.to_string()));
                Ok(None)
            }
        }
        let seen = Arc::new(Mutex::new(Vec::new()));
        let notifier = crate::sandbox::notify_sink::Notifier::recording(
            crate::notify::NotifyPolicy::uniform(crate::notify::NotifyMode::Always),
            Box::new(Recorder(Arc::clone(&seen))),
        );

        let policy = ProcPolicy::new(ProcMode::Enforce, &[], &["/bin/true".to_string()]);
        let (code, _) = run_under_supervisor_notified(
            &["/bin/true"],
            &policy,
            &ProcOverlay::new(),
            1,
            None,
            &notifier,
        );
        assert_eq!(code, Some(126), "the payload must have been refused");

        let announced = seen.lock().expect("recorder lock").clone();
        let (summary, body) = announced
            .first()
            .unwrap_or_else(|| panic!("a denied exec announced nothing: {announced:?}"));
        assert!(
            summary.contains("/bin/true"),
            "the announcement must name the program that was refused: {summary:?}"
        );
        assert!(
            body.contains("exec policy"),
            "the announcement must say what refused it, in the words the user reads: {body:?}"
        );
    }

    #[test]
    fn a_denied_execve_returns_eperm_and_the_payload_never_runs() {
        let policy = ProcPolicy::new(ProcMode::Enforce, &[], &["/bin/true".to_string()]);
        let (code, ring) = run_under_supervisor(&["/bin/true"], &policy, &ProcOverlay::new());

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
        let (code, ring) = run_under_supervisor(&["/bin/true"], &policy, &ProcOverlay::new());

        assert_eq!(code, Some(0), "the allowed payload must have run");
        assert!(
            ring.snapshot(None)
                .events
                .iter()
                .any(|e| e.command.contains("/bin/true") && e.verdict == "allow"),
            "the ring must record the allowed exec"
        );
    }

    /// A strict allowlist must not break name lookup. `execvp("true")` is not one syscall: it issues
    /// an `execve` per `PATH` entry until one succeeds, and glibc only keeps walking on
    /// `ENOENT`/`EACCES`. Refusing a candidate that was never there with `EPERM` would abort the walk
    /// before it reached the directory that has the program — so the refusal answers `ENOENT` when
    /// the path does not exist, and the lookup completes. Without that, an allowlisted program not
    /// sitting in the first `PATH` entry is unlaunchable.
    #[test]
    fn a_confined_allowlist_still_lets_a_name_lookup_find_its_program() {
        let empty = TmpDir::new();
        std::fs::create_dir_all(empty.join("a")).expect("an empty PATH entry");
        std::fs::create_dir_all(empty.join("b")).expect("another empty PATH entry");
        let path = format!(
            "{}:{}:/usr/bin",
            empty.join("a").display(),
            empty.join("b").display()
        );

        let policy = ProcPolicy::new(
            ProcMode::Confine,
            &["/usr/bin/env".to_string(), "/usr/bin/true".to_string()],
            &[],
        );
        let (code, ring) = run_under_supervisor_full(
            &["/usr/bin/env", "true"],
            &policy,
            &ProcOverlay::new(),
            8,
            Some(&path),
        );

        let events = ring.snapshot(None).events;
        assert_eq!(
            code,
            Some(0),
            "the allowed program must still be found through PATH: {events:?}"
        );
        assert!(
            events
                .iter()
                .any(|e| e.command.ends_with("/a/true") && e.verdict == "absent"),
            "the walk's earlier candidates are refused, and recorded as the absences they are — that \
             is the situation under test: {events:?}"
        );
        assert!(
            events
                .iter()
                .any(|e| e.command == "/usr/bin/true" && e.verdict == "allow"),
            "and the walk reached the real one: {events:?}"
        );
    }

    /// The gate covers the process **tree**, not just the command it was handed. The filter the shim
    /// installs is inherited across `fork` *and* `exec`, so a program the payload runs — and one that
    /// program runs in turn — traps the same supervisor. That is what makes a rule mean "this may run
    /// in this cage" rather than "the first command may run this", and it is the property the whole
    /// enforcement posture rests on: without it, allowing one program would hand it an unwatched
    /// tree. Measured here rather than taken from the kernel's documentation.
    #[test]
    fn a_grandchild_execve_traps_the_same_supervisor() {
        // `timeout` forks and execs its argument, so the denied target is reached across both — a
        // chain the payload's own exec could not demonstrate on its own.
        let policy = ProcPolicy::new(ProcMode::Enforce, &[], &["/bin/true".to_string()]);
        let (_, ring) = run_under_supervisor_n(
            &["/usr/bin/timeout", "5", "/bin/true"],
            &policy,
            &ProcOverlay::new(),
            2,
        );

        let events = ring.snapshot(None).events;
        assert!(
            events
                .iter()
                .any(|e| e.command.contains("/usr/bin/timeout") && e.verdict == "allow"),
            "the payload's own exec must be allowed through: {events:?}"
        );
        assert!(
            events
                .iter()
                .any(|e| e.command.contains("/bin/true") && e.verdict == "deny"),
            "the exec a *forked descendant* attempts must reach the supervisor too — if this is \
             missing, the filter did not survive fork+exec: {events:?}"
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

        let (code, ring) = run_under_supervisor(&["/bin/true"], &policy, &overlay);

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
