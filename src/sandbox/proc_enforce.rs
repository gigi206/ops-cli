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

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::io;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use super::binds::ExtraBind;
use super::proc_control::ExecRing;
use crate::proc_policy::{ProcPolicy, ProcRule, Verdict};
use crate::sandbox::locks::{locked, read_locked, write_locked};

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
        let mut g = write_locked(&self.inner);
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
        let g = read_locked(&self.inner);
        if g.allow.is_empty() && g.deny.is_empty() {
            base.decide(caller, exec_path)
        } else {
            base.decide_chain(caller, exec_path, &g.allow, &g.deny)
        }
    }

    /// Snapshot the overlay as `(verdict-label, raw rule)` pairs (allow first, then deny), for
    /// `sbx proc rules`.
    pub(crate) fn snapshot(&self) -> Vec<(&'static str, String)> {
        let g = read_locked(&self.inner);
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
    /// Shared with the supervisor thread; read here once that thread has been joined.
    undecidable: Arc<Undecidable>,
    /// What this policy's mode does with a decision that had nothing to match, in the words the
    /// teardown report needs. Captured at start-up because the policy itself moves into the thread.
    unmatched: &'static str,
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
        // After the join: nothing counts any more, so these totals are the run's.
        for line in self.undecidable.report(self.unmatched) {
            crate::diag::warn(&line);
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
    // Captured before the policy moves into the thread below.
    let unmatched = unmatched_word(&policy);
    let undecidable = Arc::new(Undecidable::default());
    let counted = undecidable.clone();
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
                undecidable: &counted,
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
            undecidable,
            unmatched,
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

/// The decisions a supervisor could not base on what it was deciding about, counted by kind.
///
/// Each of those decisions reads the parked target through `/proc/<pid>/…`, and each has a fallback
/// that keeps the cage running rather than bricking it on a read that did not work. That fallback
/// is right for one failure and wrong for a thousand: one is a process reaped between the
/// notification and the read, a thousand is the ancestor invariant of the module header not holding
/// on this host — and then the policy decides nothing by name. Nothing already recorded tells those
/// two apart. The exec ring notes an undecidable target as `<unreadable>`, but it is bounded, so a
/// collapse evicts every real entry and leaves a tail that reads like ordinary traffic; the open
/// lens records refusals rather than decisions, so an open it could not name leaves no entry at
/// all; and an unreadable caller is recorded as no caller, which is also what a policy that does
/// not decide by caller records.
///
/// So the count is the finding, and it is said twice. The first of each kind warns while the run is
/// still going. A kind that happened more than once is totalled at teardown — more than once and
/// not once, because the first already warned, and a second line that only ever repeats it teaches
/// a reader to skip the place the number appears.
///
/// Counted at the read and not by its caller, deliberately: a call site can be dropped and nothing
/// downstream would notice, while a return value cannot. That shape is what a test can hold, because
/// the two call sites in [`handle_notif`] are out of reach — getting there needs a read that fails
/// while a real target is parked in its syscall, and a parked target's memory is precisely what is
/// readable. Making it fail means raising the host's `ptrace_scope`, which is machine-wide and not a
/// test's to change. Revisit if a way appears to close one process's memory to another without
/// touching that sysctl.
///
/// One step is held by nothing at all: that [`ProcEnforce`]'s own drop calls [`Undecidable::report`].
/// Driving it needs a supervisor `start_inner` built — sockets, a shim, a thread — and then a run in
/// which a read fails more than once, which is the unreachable state above; revisit the two
/// together. What that drop does *not* depend on is the launcher reaching it: every path that ends a
/// run drops the guard explicitly before leaving, because a bare `process::exit` runs no destructors
/// and the launcher says so where it exits. So the only teardown that reports nothing is one that
/// also unlinks no socket.
#[derive(Default)]
struct Undecidable {
    /// An `execve` whose target path could not be read.
    exec: AtomicU64,
    /// An open whose path could not be read, so the content lens examined nothing.
    open: AtomicU64,
    /// An `execve` whose calling program could not be read, or is not a name a policy can hold.
    caller: AtomicU64,
}

impl Undecidable {
    /// What a finished run owes its user about the decisions it could not base on a name, given the
    /// word for what its mode does with a decision that matched nothing.
    ///
    /// Read after the supervisor thread has been joined, so the counts are final. A kind that
    /// happened once is left out: it already warned when it happened, and a teardown line that only
    /// ever says `1` is one a reader learns to skip — including on the run where it says `8412`.
    /// Each line carries what the fallback did, because that is the part its reader acts on.
    fn report(&self, unmatched: &str) -> Vec<String> {
        let mut lines = Vec::new();
        let n = self.exec.load(Ordering::Relaxed);
        if n > 1 {
            lines.push(format!(
                "`[proc]`: {n} `execve`s were decided without reading what they would run — each \
                 was {unmatched} by the mode's default rather than by a rule. A supervisor that \
                 cannot read a parked target decides nothing by name"
            ));
        }
        let n = self.open.load(Ordering::Relaxed);
        if n > 1 {
            lines.push(format!(
                "`[proc]`: {n} opens were allowed without the content lens reading what they asked \
                 for. A supervisor that cannot read a parked caller examines nothing"
            ));
        }
        let n = self.caller.load(Ordering::Relaxed);
        if n > 1 {
            lines.push(format!(
                "`[proc]`: {n} `execve`s were decided without reading which program issued them — \
                 each was {unmatched} by the mode's default rather than by that caller's own rules"
            ));
        }
        lines
    }
}

/// What a mode's default does with a decision that had nothing to match, in the words a warning
/// needs: what a reader has to know is what happened to the syscall, not which arm answered.
fn unmatched_word(policy: &ProcPolicy) -> &'static str {
    match policy.unmatched() {
        Verdict::Allow => "allowed",
        Verdict::Deny => "refused",
        Verdict::Ask => "parked for a decision",
    }
}

/// Decide one notified `execve` by the name written at `addr` in the target's memory, and say what
/// to record for it.
///
/// The verdict and the record travel together because one read produces both: a target that could
/// not be read is decided by the mode's default and recorded as `<unreadable>`, and splitting them
/// across two reads would let a supervisor record a decision it did not take.
///
/// The fallback is deliberate and stays: one that refused every target it could not read would
/// brick a whole cage on a single process reaped mid-decision. What it must not be is unremarked,
/// so the read that did not work is counted here — at the read, where the failure is known — and
/// the first of them is said out loud.
fn exec_verdict(cx: &Deciding<'_>, caller: &[String], pid: u32, addr: u64) -> (Verdict, String) {
    if let Some(path) = read_exec_path(pid, addr).filter(|p| !p.is_empty()) {
        // Decide against the config policy folded with the live `--session` overlay (deny wins
        // across both). The overlay read-lock is held only for this decision.
        let verdict = cx.overlay.decide(cx.policy, caller, &path);
        return (verdict, path);
    }
    // Fall back to the mode's unmatched default rather than guess a name match — allow under a
    // denylist, park under ask, refuse under an allowlist, where an undecidable target is exactly
    // the one that must not run.
    if cx.undecidable.exec.fetch_add(1, Ordering::Relaxed) == 0 {
        crate::diag::warn(&format!(
            "could not read what an `execve` was about to run, so the `[proc]` policy had no name \
             to match and the mode's default decided it: {}. That read needs this supervisor to be \
             the target's ancestor; where that does not hold, nothing is decided by name",
            unmatched_word(cx.policy)
        ));
    }
    (cx.policy.unmatched(), "<unreadable>".to_string())
}

/// The path an open asked for, or the empty string when it could not be read.
///
/// The read is where an unnameable open is counted, because it is the only step that knows it
/// happened: the decision downstream allows it, and this lens records the refusals it decided rather
/// than the decisions it could not take, so nothing afterwards would remember. Counted only where a
/// lens is armed — with none there was nothing to decide and nothing was given up, and a number on
/// those cages would be a number on a lens they never asked for.
fn open_name(cx: &Deciding<'_>, pid: u32, path_addr: u64) -> String {
    if let Some(named) = read_exec_path(pid, path_addr).filter(|p| !p.is_empty()) {
        return named;
    }
    if cx.open.is_some() && cx.undecidable.open.fetch_add(1, Ordering::Relaxed) == 0 {
        crate::diag::warn(
            "could not read the path an open asked for, so the content lens examined nothing and \
             the open was allowed. That read needs this supervisor to be the caller's ancestor; \
             where that does not hold, the lens examines nothing at all",
        );
    }
    String::new()
}

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
    /// Shared with the [`ProcEnforce`] that owns this supervisor, which reports the totals once the
    /// thread has been joined.
    undecidable: &'a Undecidable,
}

/// The supervisor thread: wait (with a stop-checking poll) for the shim's one connection, receive the
/// listener fd, close the listening socket (no second connection is accepted), then run the receive
/// loop until the cage's filter is gone.
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
        let named = open_name(cx, req.pid, path_addr);
        // Twice at most, and the second pass only when the first found nothing there and the open
        // asked for the name to be created. Creating it is what makes the second pass meaningful:
        // the file exists by then, so the ordinary decision has something to examine.
        for pass in 0..2 {
            let outcome = match cx.open {
                // An unreadable path is allowed, like an unreadable exec target: the lens takes away
                // what it can prove, and a cage whose undecidable opens all failed would not run.
                Some(lens) if !named.is_empty() => open_is_refused(lens, req.pid, dirfd, &named),
                _ => OpenOutcome::ALLOWED,
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
            } else if let Some(errno) = outcome.errno {
                // A name that is not there is the answer to a plain open and not to a creating one, and
                // the probe that looked for it creates nothing. Rather than report the absence the
                // probe met, make what the open asked for.
                if pass == 0
                    && errno == libc::ENOENT
                    && let Some(lens) = cx.open
                {
                    match serve_creation(notif_fd, req, lens, dirfd, &named) {
                        Creation::Served => return,
                        // The name is there after all — it appeared while this was being decided, so it
                        // carries content nothing has examined and belongs to the ordinary decision.
                        Creation::Exists => continue,
                        Creation::Declined => {}
                    }
                }
                respond_errno(notif_fd, req.id, errno);
            } else if !serve_open(notif_fd, req, dirfd, &named, outcome.probe) {
                // Nothing sound to serve it from, so the open runs the way it always did — and with it
                // the re-resolution a sibling thread can redirect. The cases that land here are named
                // where each is decided: a target whose type would make a reopen block, flags that
                // cannot be carried onto a descriptor, and a kernel without `ADDFD`.
                respond_continue(notif_fd, req.id);
            }
            return;
        }
        return;
    }
    let caller = caller_chain(cx, req.pid);
    let (verdict, shown) = exec_verdict(cx, &caller, req.pid, req.data.args[0]);
    let shown = shown.as_str();
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
fn caller_chain(cx: &Deciding<'_>, pid: u32) -> Vec<String> {
    if cx.policy.graph.is_none() {
        return Vec::new();
    }
    // `into_string` and not `to_string_lossy`: this string is matched against the policy's caller
    // nodes and recorded as who reached, and a lossy one is neither. Every byte the encoding cannot
    // carry becomes the same replacement character, so two callers that are different programs
    // arrive here under one name — the same collapse a trust marker's key must not make. A name
    // that cannot be carried is not a name, and joins the reads that did not work.
    let named = std::fs::read_link(format!("/proc/{pid}/exe"))
        .ok()
        .and_then(|p| p.into_os_string().into_string().ok());
    let Some(program) = named else {
        // An empty chain matches no node, so the mode's default decides — and the ring records this
        // `execve` with no caller, exactly as it records one under a policy that does not decide by
        // caller at all. Nothing in the log separates those, so the count does.
        if cx.undecidable.caller.fetch_add(1, Ordering::Relaxed) == 0 {
            crate::diag::warn(&format!(
                "could not read the program that issued an `execve`, so the per-caller policy had \
                 no node to match and the mode's default decided it: {}",
                unmatched_word(cx.policy)
            ));
        }
        return Vec::new();
    };
    vec![program]
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

/// Set once the kernel has refused an `ADDFD` answer, so a host without it pays one failed ioctl
/// for the whole session rather than one per open.
static ADDFD_UNAVAILABLE: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Answer a notification by handing the target a descriptor, rather than letting the real syscall
/// run a second time.
///
/// This is what makes an *allow* sound. `SECCOMP_ADDFD_FLAG_SEND` completes the notification in the
/// same operation that installs the descriptor, and the number it lands on becomes the syscall's
/// return value — so nothing re-resolves the path the cage wrote, and a sibling thread that rewrites
/// that buffer changes nothing. A `CONTINUE` answer cannot offer this: it re-runs the syscall from
/// its arguments, which is why the window exists at all.
///
/// `srcfd` is the supervisor's own descriptor for the inode it examined; the kernel duplicates it
/// into the target and leaves ours alone. Returns `false` when the kernel does not offer the
/// operation (`SECCOMP_ADDFD_FLAG_SEND` landed in 5.9), leaving the caller to fall back on the
/// answer every kernel before it had.
fn respond_with_fd(notif_fd: libc::c_int, id: u64, srcfd: libc::c_int, cloexec: bool) -> bool {
    use std::sync::atomic::Ordering;
    if ADDFD_UNAVAILABLE.load(Ordering::Relaxed) {
        return false;
    }
    let mut addfd: libc::seccomp_notif_addfd = unsafe { std::mem::zeroed() };
    addfd.id = id;
    addfd.flags = libc::SECCOMP_ADDFD_FLAG_SEND as u32;
    addfd.srcfd = srcfd as u32;
    // `newfd` is ignored without `SECCOMP_ADDFD_FLAG_SETFD`: the kernel picks the lowest free
    // number in the target, which is what an ordinary `open` would have returned.
    addfd.newfd = 0;
    addfd.newfd_flags = if cloexec { libc::O_CLOEXEC as u32 } else { 0 };
    // SAFETY: addfd is a live, correctly-sized request for the ADDFD ioctl to read.
    let rc = unsafe {
        libc::ioctl(
            notif_fd,
            libc::SECCOMP_IOCTL_NOTIF_ADDFD as libc::Ioctl,
            &addfd as *const libc::seccomp_notif_addfd,
        )
    };
    if rc >= 0 {
        return true;
    }
    // Told apart on the errno: an old kernel does not know the operation at all, and remembering
    // that is worth a flag. Anything else is about *this* notification — the target was reaped, or
    // it ran out of descriptors — and must not condemn the mechanism for the rest of the session.
    let e = io::Error::last_os_error().raw_os_error().unwrap_or(0);
    if e == libc::EINVAL || e == libc::ENOTTY {
        // `swap` rather than `store`: a parked open answers from its own thread, so two can learn
        // this at once, and the session is meant to say it exactly once.
        //
        // Said at all, because the fallback is the whole difference between an allow that hands
        // over the inode that was examined and one that lets the path resolve a second time. A
        // person reading `[fs] scan` in their config has no other way to learn that the guard they
        // configured is running in its weaker form: nothing else in a launch mentions it, and the
        // kernel version alone does not answer it (a distribution may backport the operation).
        // This is not covered by a test: reproducing it needs a kernel that lacks the operation.
        if !ADDFD_UNAVAILABLE.swap(true, Ordering::Relaxed) {
            crate::diag::warn(
                "this kernel does not offer the seccomp operation that hands the cage the very \
                 descriptor `[fs] scan` examined (it landed in 5.9), so an allowed open is re-run \
                 from its arguments and what the cage receives may not be what was scanned",
            );
        }
    }
    false
}

/// Serve one allowed open from the descriptor the supervisor already holds, rather than letting the
/// syscall run again.
///
/// This is the whole point of the lens being sound on an *allow*. The verdict was formed against the
/// inode behind `probe`; reopening through `/proc/self/fd/<probe>` reaches that same inode without
/// walking a path, so the descriptor the cage receives is definitionally the one that was examined.
/// A `CONTINUE` answer would instead re-run the syscall from its arguments, and a sibling thread is
/// free to have rewritten them meanwhile.
///
/// Serving carries no authority the cage did not have: the probe was taken through
/// `/proc/<pid>/root` and then vouched for by [`vouched_probe`], so it sits on the cage's own
/// mounts, and a read-only bind refuses a write reopen with `EROFS` exactly as it would have refused
/// the cage. The prefix alone does not carry that far — a symlink target beginning with `/` restarts
/// the walk at this process's root — which is what the vouching is for.
///
/// Returns `false` when the call cannot be served this way, leaving the caller to answer `CONTINUE`
/// — which is the pre-existing behaviour, and with it the pre-existing race.
fn serve_open(
    notif_fd: libc::c_int,
    req: &libc::seccomp_notif,
    dirfd: libc::c_int,
    path: &str,
    probe: Option<std::fs::File>,
) -> bool {
    let Some(probe) = probe else { return false };
    let Some(flags) = open_flags(req.pid, req.data.nr, &req.data.args) else {
        return false;
    };
    let flags = flags as libc::c_int;
    // `O_TMPFILE` names a directory and asks for a new unnamed inode under it. There is no existing
    // file to serve, and the probe is not it.
    if flags & libc::O_TMPFILE == libc::O_TMPFILE {
        return false;
    }
    // The file exists — holding a descriptor on it is the proof — so `O_CREAT|O_EXCL` is precisely
    // the case the caller asked to be told about, and the errno it expects is the sound answer.
    if flags & libc::O_CREAT != 0 && flags & libc::O_EXCL != 0 {
        respond_errno(notif_fd, req.id, libc::EEXIST);
        return true;
    }
    // `O_NOFOLLOW` asks to fail when the final component is a symlink. The probe followed links on
    // purpose (a scan that stopped at the link would be walked around with one `ln -s`), and
    // `/proc/self/fd/<n>` is itself a link, so the flag cannot ride into the reopen. It is decided
    // here instead, against the same path, and answered the way the kernel would have.
    //
    // Re-walking the path is a second resolution, and the cage may have moved it since. The two
    // outcomes of losing that race are a spurious `ELOOP` and serving the inode that was scanned —
    // never an open the lens did not examine, which is the property being defended.
    if flags & libc::O_NOFOLLOW != 0 {
        let target = open_target_path(req.pid, dirfd, path);
        let Ok(c) = std::ffi::CString::new(target.as_os_str().as_encoded_bytes()) else {
            return false;
        };
        // SAFETY: c is a live NUL-terminated path for the duration of the call.
        let link_probe = unsafe {
            libc::open(
                c.as_ptr(),
                libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if link_probe < 0 {
            respond_errno(notif_fd, req.id, libc::ELOOP);
            return true;
        }
        // SAFETY: link_probe is a fresh owned descriptor this call is done with.
        unsafe { libc::close(link_probe) };
    }
    // `O_CREAT` on a file that exists is a no-op, and `O_NOFOLLOW` has just been answered. Our own
    // descriptor is always close-on-exec; what the *cage's* copy carries is set on the response.
    let reopen = (flags & !libc::O_CREAT & !libc::O_NOFOLLOW) | libc::O_CLOEXEC;
    let cloexec = flags & libc::O_CLOEXEC != 0;

    use std::os::unix::fs::FileTypeExt;
    let kind = probe.metadata().map(|m| m.file_type());
    let Ok(kind) = kind else { return false };

    // A socket inode cannot be opened at all: measured, `open` on one returns `ENXIO` whatever the
    // access mode. Answering it here is both the truthful reply and one less door, since no reopen
    // has to be attempted to know it.
    if kind.is_socket() {
        respond_errno(notif_fd, req.id, libc::ENXIO);
        return true;
    }

    // A FIFO is the one type whose open blocks by design, and the direction decides how. Measured
    // on a pipe with no peer at all, which is what the first reading of it got wrong: a probe left
    // waiting in one direction counts as a peer for the other, and made the write side look
    // instantaneous.
    //
    // - `O_RDWR` never blocks, so it is served here like any other.
    // - `O_WRONLY` blocks for a reader, and `O_NONBLOCK` reports `ENXIO` until one arrives — so a
    //   retry loop is *faithful* (the caller does wait for a reader) and bounded (it gives up when
    //   the notification stops being valid, which is when the target is gone).
    // - `O_RDONLY` blocks for a writer, and `O_NONBLOCK` succeeds immediately without one — so a
    //   retry loop would drift, letting the caller past and turning its first `read` into an EOF
    //   where the open should still have been waiting. Only a blocking open is faithful there.
    if kind.is_fifo() && flags & libc::O_ACCMODE != libc::O_RDWR {
        return park_open(notif_fd, req.id, probe, reopen, cloexec);
    }

    // A character or block device may wait on the hardware behind it (a serial line waiting for
    // carrier). `O_NONBLOCK` is the standard way to open one without hanging on that, and clearing
    // it afterwards restores what the caller asked for on the description it receives.
    let nonblock_dance =
        (kind.is_char_device() || kind.is_block_device()) && flags & libc::O_NONBLOCK == 0;
    let attempt = if nonblock_dance {
        reopen | libc::O_NONBLOCK
    } else {
        reopen
    };
    let served = reopen_probe(&probe, attempt);
    if served < 0 {
        // Whose failure is it? An errno about the *file* is one the cage would have met itself,
        // reopening the same inode on the same mounts under the same identity, so it is the answer
        // and the path is not walked again. An errno about the *opener* — this process out of
        // descriptors, the machine out of memory — says nothing about the cage, and inventing it
        // would fail an open that had every right to succeed. Only those fall back, and with them
        // the race, for a window the cage cannot arrange from inside.
        let e = io::Error::last_os_error().raw_os_error().unwrap_or(0);
        if errno_describes_the_file(e) {
            respond_errno(notif_fd, req.id, e);
            return true;
        }
        return false;
    }
    if nonblock_dance {
        // SAFETY: served is this call's live descriptor; F_SETFL only alters its status flags.
        unsafe {
            let cur = libc::fcntl(served, libc::F_GETFL);
            if cur >= 0 {
                libc::fcntl(served, libc::F_SETFL, cur & !libc::O_NONBLOCK);
            }
        }
    }
    let ok = respond_with_fd(notif_fd, req.id, served, cloexec);
    // SAFETY: served is a fresh owned descriptor; the kernel copied it into the target if it took
    // it at all, and either way this side is done with it.
    unsafe { libc::close(served) };
    ok
}

/// What came of trying to make the file an open named and the probe could not find.
enum Creation {
    /// The file was made and its descriptor handed over; the notification is answered.
    Served,
    /// The name is there after all, so the ordinary decision applies to it.
    Exists,
    /// Nothing was made, and nothing was answered.
    Declined,
}

/// Make, on the cage's behalf, the file its open named and the supervisor's probe could not find.
///
/// The probe that examines a path opens it `O_PATH`, which creates nothing — so a name that is not
/// there yet makes it fail, and the `ENOENT` it met is not the answer to an open carrying `O_CREAT`.
/// Measured against a control arm, that left a cage under `[fs] scan` unable to write a single new
/// file, which is most of what a build does.
///
/// Answering `CONTINUE` would be worse than the failure it fixes. Naming a file that is not there is
/// something a cage can do whenever it likes, so that answer would be a trigger in its hands — and
/// behind the answer sits the re-resolution a re-pointed path walks through.
///
/// So the file is made here, inside a directory this supervisor has vouched for by the same walk a
/// read goes through, and the descriptor is handed over. `O_EXCL` is added whether or not the cage
/// asked for it: it is what makes the served descriptor certainly empty, and an empty file certainly
/// carries no content a scan has not examined. Its `EEXIST` says the name appeared while this was
/// being decided, and such a file belongs to the ordinary decision rather than to this path.
///
/// A name that is a dangling symlink also answers `EEXIST`, so it takes the ordinary decision too
/// and is reported absent. The cage's own open would have created the link's target instead; making
/// it here would mean resolving that target on the cage's behalf, which is the walk this module
/// declines to make on anything it has not vouched for.
fn serve_creation(
    notif_fd: libc::c_int,
    req: &libc::seccomp_notif,
    lens: &OpenLens,
    dirfd: libc::c_int,
    path: &str,
) -> Creation {
    use std::os::unix::io::{AsRawFd, FromRawFd};
    let (Some(flags), Some(mode)) = (
        open_flags(req.pid, req.data.nr, &req.data.args),
        open_mode(req.pid, req.data.nr, &req.data.args),
    ) else {
        return Creation::Declined;
    };
    let flags = flags as libc::c_int;
    if flags & libc::O_CREAT == 0 {
        return Creation::Declined;
    }
    // The directory that will hold the name, and the name itself. The separator stays with the
    // directory so that `/x` asks for `/` rather than for the empty string.
    let (dir, base) = match path.rfind('/') {
        Some(cut) => (&path[..=cut], &path[cut + 1..]),
        None => (".", path),
    };
    if base.is_empty() || base == "." || base == ".." {
        return Creation::Declined;
    }
    let target = open_target_path(req.pid, dirfd, dir);
    let Ok(cdir) = std::ffi::CString::new(target.as_os_str().as_encoded_bytes()) else {
        return Creation::Declined;
    };
    // SAFETY: cdir is a live NUL-terminated path for the duration of the call.
    let parent = unsafe {
        libc::open(
            cdir.as_ptr(),
            libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC,
        )
    };
    if parent < 0 {
        return Creation::Declined;
    }
    // SAFETY: parent is a fresh owned descriptor; the File takes sole ownership and closes it.
    let parent = unsafe { std::fs::File::from_raw_fd(parent) };
    // The same vouching a read gets: a directory reached through a walk that left the cage's mounts
    // is not one to create in, whatever it holds.
    // Never `own`: a file is created in a directory a mount vouches for, and no anonymous inode is
    // a directory to create in.
    let Ok(parent) = vouched_probe(lens, req.pid, parent, false) else {
        return Creation::Declined;
    };
    let Ok(cbase) = std::ffi::CString::new(base) else {
        return Creation::Declined;
    };
    // The kernel subtracts the *creating* process's umask from the mode, and the creating process
    // here is the supervisor rather than the cage. The two part company the moment the cage sets its
    // own — which is what a script writing a key does — so the caller's is applied here instead.
    // Measured under `[fs] scan` before this: a cage asking for `0600` under `umask 077` received
    // `0664`, group-readable and group-writable.
    let Some(umask) = caller_umask(req.pid) else {
        return Creation::Declined;
    };
    let wanted = mode as libc::c_uint & !umask;
    // `O_PATH` is dropped because this descriptor is the one the cage receives and has to be usable;
    // ours is always close-on-exec, and what the cage's copy carries is set on the response.
    let asked = (flags & !libc::O_PATH) | libc::O_CREAT | libc::O_EXCL | libc::O_CLOEXEC;
    // SAFETY: parent is a live directory descriptor and cbase a live NUL-terminated name.
    let made = unsafe { libc::openat(parent.as_raw_fd(), cbase.as_ptr(), asked, wanted) };
    if made < 0 {
        let e = io::Error::last_os_error().raw_os_error().unwrap_or(0);
        return if e == libc::EEXIST {
            Creation::Exists
        } else {
            Creation::Declined
        };
    }
    // The supervisor's own umask was subtracted by the kernel a moment ago, so the file may have
    // landed narrower than the cage asked. `fchmod` is not umask-governed and settles it exactly.
    // Widening rather than narrowing, and only after `O_EXCL` proved the file is this call's, so the
    // window before it is the narrower mode and never a wider one.
    // SAFETY: made is this call's live descriptor, and fchmod only alters its mode bits.
    unsafe { libc::fchmod(made, wanted as libc::mode_t) };
    let ok = respond_with_fd(notif_fd, req.id, made, flags & libc::O_CLOEXEC != 0);
    // SAFETY: made is a fresh owned descriptor; the kernel copied it into the target if it took it
    // at all, and either way this side is done with it.
    unsafe { libc::close(made) };
    if ok {
        Creation::Served
    } else {
        // The file was made but could not be handed over. It is there now, and empty, so the
        // ordinary decision reaches the same place by the ordinary route.
        Creation::Exists
    }
}

/// Whether an `errno` from an open describes the **file** or this **process**.
///
/// The distinction decides what may be reported to the cage. An errno about the file is one the cage
/// would have met itself, reopening the same inode on the same mounts under the same identity, so it
/// is the answer. An errno about the opener — this process out of descriptors, the machine out of
/// memory — says nothing about the cage: reporting it fails an open that had every right to succeed,
/// and tells the caller its own descriptors ran out when they did not.
///
/// One definition, because the two places that ask are written apart and only one of them used to
/// ask. The reopen that *serves* an open carried this list; the `O_PATH` probe that *examines* the
/// path did not, and passed whatever it got straight back — so a supervisor under descriptor
/// pressure answered `EMFILE` to a cage that had every descriptor it needed. A rule stated in one
/// site's comment is a rule the other site misses.
fn errno_describes_the_file(e: libc::c_int) -> bool {
    matches!(
        e,
        libc::EROFS
            | libc::EACCES
            | libc::EPERM
            | libc::ENXIO
            | libc::ELOOP
            | libc::ENOTDIR
            | libc::EISDIR
            | libc::ENOENT
            | libc::ETXTBSY
    )
}

/// Reopen the inode behind `probe` with `flags`, without walking a path.
///
/// `/proc/self/fd/<n>` names the descriptor's inode, not the name it was reached by, so this reaches
/// exactly what was examined however the cage has since rearranged its tree. Returns a raw
/// descriptor, or a negative value with `errno` set.
fn reopen_probe(probe: &std::fs::File, flags: libc::c_int) -> libc::c_int {
    use std::os::unix::io::AsRawFd;
    let by_fd = format!("/proc/self/fd/{}", probe.as_raw_fd());
    let Ok(c) = std::ffi::CString::new(by_fd) else {
        return -1;
    };
    // SAFETY: c is a live NUL-terminated path for the duration of the call.
    unsafe { libc::open(c.as_ptr(), flags) }
}

/// How many notified opens may be waiting on a blocking reopen at once.
///
/// The same shape as the `ask` registry's cap and for the same reason: a cage that can create pipes
/// can create them faster than anyone drains them, and a registry that grows with what the cage asks
/// for is a registry the cage sizes.
const PARKED_OPEN_CAP: usize = 64;

/// Opens currently parked on a thread of their own.
static PARKED_OPENS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

/// How often a write-direction FIFO open asks again while it waits for a reader.
const FIFO_RETRY: Duration = Duration::from_millis(10);

/// Serve an open whose reopen may block, on a thread of its own.
///
/// The thread that decides is the one every other open in the cage is queued behind, so it must
/// never be the thread that waits. Answering from elsewhere is not new here: the `ask` registry
/// already has the control plane answer parked `execve`s while the receive loop keeps draining, and
/// the kernel serialises the ioctls that do it.
///
/// Over the cap the answer is `EACCES`, never `CONTINUE`. Falling back to `CONTINUE` under pressure
/// would hand the cage the door back by the simple act of asking for too much at once, which is a
/// door that opens *wider* the harder it is pushed.
///
/// The notification descriptor is duplicated for the thread rather than shared. A parked open can
/// outlive the supervisor's own descriptor, and answering through a number that has since been
/// closed and handed to something else would send an ioctl to whatever now holds it.
fn park_open(
    notif_fd: libc::c_int,
    id: u64,
    probe: std::fs::File,
    reopen: libc::c_int,
    cloexec: bool,
) -> bool {
    use std::sync::atomic::Ordering;
    if PARKED_OPENS.fetch_add(1, Ordering::SeqCst) >= PARKED_OPEN_CAP {
        PARKED_OPENS.fetch_sub(1, Ordering::SeqCst);
        respond_errno(notif_fd, id, libc::EACCES);
        return true;
    }
    // SAFETY: notif_fd is the supervisor's live notification descriptor; the copy is owned by the
    // thread below, which closes it.
    let own_fd = unsafe { libc::dup(notif_fd) };
    if own_fd < 0 {
        PARKED_OPENS.fetch_sub(1, Ordering::SeqCst);
        return false;
    }
    let write_side = reopen & libc::O_ACCMODE == libc::O_WRONLY;
    std::thread::spawn(move || {
        let served = if write_side {
            // Faithful *and* bounded: `ENXIO` means no reader yet, and the wait ends either when one
            // arrives or when the notification stops being valid, which is when the caller is gone.
            loop {
                let fd = reopen_probe(&probe, reopen | libc::O_NONBLOCK);
                if fd >= 0 {
                    // SAFETY: fd is this thread's live descriptor; F_SETFL only alters status flags.
                    unsafe {
                        let cur = libc::fcntl(fd, libc::F_GETFL);
                        if cur >= 0 {
                            libc::fcntl(fd, libc::F_SETFL, cur & !libc::O_NONBLOCK);
                        }
                    }
                    break fd;
                }
                if io::Error::last_os_error().raw_os_error() != Some(libc::ENXIO)
                    || !notif_id_valid(own_fd, id)
                {
                    break -1;
                }
                std::thread::sleep(FIFO_RETRY);
            }
        } else {
            // The read direction has no faithful poll, so this blocks exactly as the cage would
            // have. It ends when a writer arrives; a pipe no writer ever joins holds this thread for
            // as long as the supervisor lives, which is the price of not lying to the caller about
            // whether its open completed.
            reopen_probe(&probe, reopen)
        };
        if served >= 0 {
            respond_with_fd(own_fd, id, served, cloexec);
            // SAFETY: served is this thread's owned descriptor, closed exactly once.
            unsafe { libc::close(served) };
        } else {
            respond_errno(own_fd, id, libc::EACCES);
        }
        // SAFETY: own_fd is this thread's duplicate, closed exactly once.
        unsafe { libc::close(own_fd) };
        PARKED_OPENS.fetch_sub(1, Ordering::SeqCst);
    });
    true
}

/// Read one `u64` from a target's memory. `openat2` passes its flags behind a pointer rather than in
/// a register, and that word has to be read the same careful way the path is.
fn read_u64(pid: u32, addr: u64) -> Option<u64> {
    use std::io::{Read, Seek, SeekFrom};
    let mut file = std::fs::File::open(format!("/proc/{pid}/mem")).ok()?;
    file.seek(SeekFrom::Start(addr)).ok()?;
    let mut buf = [0u8; 8];
    file.read_exact(&mut buf).ok()?;
    Some(u64::from_ne_bytes(buf))
}

/// The flags a notified open was called with, by syscall number.
///
/// The three forms do not agree on where they keep them, exactly as they disagree on the path (see
/// [`open_args`]): `open(path, flags, …)` and `openat(dirfd, path, flags, …)` pass a register, while
/// `openat2(dirfd, path, how, size)` passes a pointer to a `struct open_how` whose first field is the
/// flag word. Reading the wrong register would serve a descriptor opened for something other than
/// what the cage asked for, so the mapping is explicit and unit-tested rather than inferred.
///
/// `None` means the flags could not be established, and a caller that cannot establish them must not
/// serve the open from a descriptor.
fn open_flags(pid: u32, nr: libc::c_int, args: &[u64; 6]) -> Option<u64> {
    if nr as libc::c_long == libc::SYS_open {
        return Some(args[1]);
    }
    if nr as libc::c_long == libc::SYS_openat {
        return Some(args[2]);
    }
    if nr as libc::c_long == libc::SYS_openat2 {
        // `struct open_how { __u64 flags; __u64 mode; __u64 resolve; }`. Only the first word is
        // wanted, and a `size` too small to hold it describes a call the kernel refuses anyway.
        if args[3] < 8 {
            return None;
        }
        return read_u64(pid, args[2]);
    }
    None
}

/// The mode a creating open asks its file to land with, read from wherever its own ABI puts it.
///
/// The mirror of [`open_flags`], and needed for the same reason: a file made on the cage's behalf
/// has to arrive with the permissions the cage asked for rather than with a guess.
fn open_mode(pid: u32, nr: libc::c_int, args: &[u64; 6]) -> Option<u64> {
    if nr as libc::c_long == libc::SYS_open {
        return Some(args[2]);
    }
    if nr as libc::c_long == libc::SYS_openat {
        return Some(args[3]);
    }
    if nr as libc::c_long == libc::SYS_openat2 {
        // `struct open_how { __u64 flags; __u64 mode; __u64 resolve; }`. The mode is the second
        // word, so the struct has to be long enough to carry one.
        if args[3] < 16 {
            return None;
        }
        return read_u64(pid, args[2].wrapping_add(8));
    }
    None
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
            let mut g = locked(&self.inner);
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
        let parked = locked(&self.inner).remove(&id)?;
        answer_parked(&parked, allow);
        Some((parked.pid, parked.path))
    }

    /// Answer every parked `execve` at once (the `*` bulk form). Returns each decided `(id, pid, path)`.
    pub(crate) fn answer_all(&self, allow: bool) -> Vec<(u64, u32, String)> {
        let taken = std::mem::take(&mut *locked(&self.inner));
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
        locked(&self.inner)
            .values()
            .map(|p| (p.id, p.pid, p.path.clone(), p.since.elapsed()))
            .collect()
    }

    /// Auto-deny (with `EPERM`) any parked `execve` older than [`ASK_TIMEOUT`], so a stalled decision
    /// never hangs a process tree. Called on the receive loop's idle ticks.
    fn sweep(&self) {
        let mut g = locked(&self.inner);
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

/// How many mount namespaces a launch remembers the mount set of.
///
/// One is the common case: the cage's own. A cage that puts a descendant in a mount namespace of its
/// own adds one per namespace, and the ceiling bounds the supervisor's memory rather than naming a
/// limit anyone should meet.
const CAGE_MOUNTS_MAX: usize = 64;

/// The mounts a cage can see, remembered per mount namespace.
///
/// The set answers one question: did the supervisor's own path walk stay on the mounts the *cage*
/// has? A walk that left them reached its object through this process's root rather than the cage's,
/// and what it found cannot be handed over on the cage's behalf.
///
/// Keyed by the namespace rather than by the pid, because a cage may put a descendant in a mount
/// namespace of its own and that descendant's opens have to be judged against the mounts *it* sees.
///
/// Never refreshed. A set older than a mount the cage made since only sends that open down the
/// slower path, which resolves inside the cage's root and reaches the same answer — so staleness
/// costs time, never correctness, and a refresh on every miss would let a cage spend the
/// supervisor's time by opening paths that miss on purpose.
#[derive(Default)]
struct CageMounts {
    seen: Mutex<BTreeMap<u64, BTreeSet<u64>>>,
}

impl CageMounts {
    /// The inode of `pid`'s mount namespace, which is what `/proc/<pid>/ns/mnt` names.
    fn namespace_of(pid: u32) -> Option<u64> {
        let link = std::fs::read_link(format!("/proc/{pid}/ns/mnt")).ok()?;
        link.to_str()?
            .strip_prefix("mnt:[")?
            .strip_suffix(']')?
            .parse()
            .ok()
    }

    /// The mount ids `pid` can see, as its own `mountinfo` numbers them.
    fn read(pid: u32) -> Option<BTreeSet<u64>> {
        let text = std::fs::read_to_string(format!("/proc/{pid}/mountinfo")).ok()?;
        let ids: BTreeSet<u64> = text
            .lines()
            .filter_map(|line| line.split_whitespace().next())
            .filter_map(|id| id.parse().ok())
            .collect();
        (!ids.is_empty()).then_some(ids)
    }

    /// Whether `id` names one of the mounts `pid` can see.
    ///
    /// `false` when the question cannot be answered at all — an unreadable `mountinfo`, a target
    /// already reaped — because an unknown mount must not be taken for a known one. The caller pays
    /// for that with a second resolution, which is the safe direction.
    fn holds(&self, pid: u32, id: u64) -> bool {
        let Some(ns) = Self::namespace_of(pid) else {
            return false;
        };
        if let Ok(seen) = self.seen.lock()
            && let Some(ids) = seen.get(&ns)
        {
            return ids.contains(&id);
        }
        let Some(fresh) = Self::read(pid) else {
            return false;
        };
        let holds = fresh.contains(&id);
        if let Ok(mut seen) = self.seen.lock() {
            if seen.len() >= CAGE_MOUNTS_MAX {
                seen.clear();
            }
            seen.insert(ns, fresh);
        }
        holds
    }
}

/// The bit that asks `statx` for the mount number, and the one it sets when it answered.
const STATX_MNT_ID: libc::c_uint = 0x1000;

/// The kernel's `struct statx`, of which this module reads two fields.
///
/// Declared here rather than taken from `libc`, which carries the type for some targets and not for
/// the static one this ships as. The layout is the kernel's ABI, fixed by it: a field read at the
/// wrong offset would come back as whatever sits there, plausibly and in silence, so the size and
/// the offsets of the two fields read here are asserted rather than assumed.
#[repr(C)]
struct Statx {
    mask: u32,
    blksize: u32,
    attributes: u64,
    nlink: u32,
    uid: u32,
    gid: u32,
    mode: u16,
    spare0: u16,
    ino: u64,
    size: u64,
    blocks: u64,
    attributes_mask: u64,
    /// Four `statx_timestamp`, sixteen bytes each, none of which this call asks for.
    times: [u64; 8],
    rdev_major: u32,
    rdev_minor: u32,
    dev_major: u32,
    dev_minor: u32,
    mnt_id: u64,
    /// The remainder of the 256 bytes the kernel is free to write into.
    tail: [u64; 13],
}

/// The mount the object behind `fd` sits on, numbered the way `mountinfo` numbers mounts.
///
/// `None` is a refusal to answer rather than an answer: a kernel that does not carry the field
/// leaves the caller to resolve inside the cage's root instead of taking an unknown mount for one
/// the cage has.
fn mount_id(fd: libc::c_int) -> Option<u64> {
    let mut buf: Statx = unsafe { std::mem::zeroed() };
    // SAFETY: buf is a live, correctly-sized statx buffer, and the empty path with `AT_EMPTY_PATH`
    // asks about the descriptor itself — the one question an `O_PATH` probe can answer.
    let rc = unsafe {
        libc::syscall(
            libc::SYS_statx,
            fd,
            c"".as_ptr(),
            libc::AT_EMPTY_PATH,
            STATX_MNT_ID,
            std::ptr::addr_of_mut!(buf),
        )
    };
    (rc == 0 && buf.mask & STATX_MNT_ID != 0).then_some(buf.mnt_id)
}

/// Set once the kernel has refused `openat2`, so a host without it pays one failed syscall for the
/// whole session rather than one per open that has to be resolved again.
static OPENAT2_UNAVAILABLE: AtomicBool = AtomicBool::new(false);

/// Reach `absolute` from **inside the cage's root**, the way the cage's own kernel would.
///
/// `RESOLVE_IN_ROOT` is what makes this faithful. A symlink whose target begins with `/` restarts
/// the resolution at the root of whoever is resolving, and a walk this process makes is resolved
/// against *its* root — so the target is taken relative to the cage's root instead. That is the
/// whole difference between reaching the cage's `/etc/hostname` and reaching ours, and it also means
/// the walk from here cannot leave the cage whatever it meets.
///
/// `absolute` is the path the supervisor's own walk ended on, which for the case that brings a
/// caller here — a symlink target beginning with `/` — is the path the cage's kernel resolves too.
/// The limit that leaves: an object the cage reaches under a *different* path than this process does
/// is not found, and the open is refused rather than served. That case needs both an absolute
/// symlink and a bind whose two sides sit at different paths; it fails closed, and the alternative
/// would be serving an object from a walk the cage did not make.
///
/// Returns the errno the cage's own open would have met, so the caller has an answer either way.
fn probe_in_cage_root(pid: u32, absolute: &Path) -> Result<libc::c_int, libc::c_int> {
    if OPENAT2_UNAVAILABLE.load(Ordering::Relaxed) {
        return Err(libc::ENOSYS);
    }
    // `/proc/<pid>/fd/<n>` is rendered by the kernel against *this* process's root, so a target it
    // cannot name from there comes back marked rather than absolute — and a path that is not
    // absolute is not one this walk can start from.
    let Some(rest) = absolute.to_str().and_then(|p| p.strip_prefix('/')) else {
        return Err(libc::ENOENT);
    };
    // An empty remainder names the root itself, which `openat2` spells `.`.
    let rest = if rest.is_empty() { "." } else { rest };
    let (Ok(cstart), Ok(crest)) = (
        std::ffi::CString::new(format!("/proc/{pid}/root")),
        std::ffi::CString::new(rest),
    ) else {
        return Err(libc::EINVAL);
    };
    // SAFETY: cstart is a live NUL-terminated path for the duration of the call.
    let start = unsafe { libc::open(cstart.as_ptr(), libc::O_PATH | libc::O_CLOEXEC) };
    if start < 0 {
        return Err(io::Error::last_os_error()
            .raw_os_error()
            .unwrap_or(libc::ENOENT));
    }
    // Zeroed and then filled: the struct is non-exhaustive, and a zero in a field this call does
    // not use is what the kernel reads as "unset" anyway.
    let mut how: libc::open_how = unsafe { std::mem::zeroed() };
    how.flags = (libc::O_PATH | libc::O_CLOEXEC) as u64;
    how.resolve = libc::RESOLVE_IN_ROOT;
    // SAFETY: start is this call's live descriptor, crest a live NUL-terminated path, and how a
    // live correctly-sized `open_how` for the kernel to read.
    let fd = unsafe {
        libc::syscall(
            libc::SYS_openat2,
            start,
            crest.as_ptr(),
            std::ptr::addr_of!(how),
            std::mem::size_of::<libc::open_how>(),
        )
    };
    let err = io::Error::last_os_error()
        .raw_os_error()
        .unwrap_or(libc::ENOENT);
    // SAFETY: start is this call's owned descriptor, closed exactly once.
    unsafe { libc::close(start) };
    if fd >= 0 {
        return Ok(fd as libc::c_int);
    }
    if err == libc::ENOSYS && !OPENAT2_UNAVAILABLE.swap(true, Ordering::Relaxed) {
        // Said at all, because it is the difference between a guard that holds and one that only
        // looks like it does, and nothing else in a launch mentions it. Said once, from whichever
        // thread learns it first: a parked open answers from its own.
        //
        // This is not covered by a test: reproducing it needs a kernel that lacks the operation.
        crate::diag::warn(
            "this kernel does not offer `openat2` (it landed in 5.6), which is what lets the \
             supervisor resolve a path the way the cage would; under `[fs] scan` an open whose walk \
             leaves the cage's own mounts is refused rather than answered from a resolution this \
             process's root steered",
        );
    }
    Err(err)
}

/// The probe, once it is known to describe what the **cage's** own walk would have reached.
///
/// The supervisor resolves through `/proc/<pid>/root`, which puts the walk on the cage's mounts —
/// but only until it meets a symlink whose target begins with `/`. Such a target restarts the
/// resolution at the resolving process's root, and that is this one's: `/dev/stdout` is a link to
/// `/proc/self/fd/1`, where `self` names the supervisor. Measured, a cage that opens it receives the
/// supervisor's own descriptor, and a link the cage plants itself reaches the host's copy of any
/// file it names.
///
/// So the walk is checked rather than trusted. Either the probe landed on a mount the cage can see,
/// and the walk stayed inside; or it did not, and the path it landed on is reached again from inside
/// the cage's root, which is the resolution the cage's own kernel performs for such a target. The
/// second form is exact for a bind of the same file — the cage reaches that inode under that name —
/// so a secret named through an absolute link is still scanned and still refused, and a store path
/// named through one is still served.
fn vouched_probe(
    lens: &OpenLens,
    pid: u32,
    probe: std::fs::File,
    own: bool,
) -> Result<std::fs::File, libc::c_int> {
    use std::os::unix::io::{AsRawFd, FromRawFd};
    if let Some(id) = mount_id(probe.as_raw_fd())
        && lens.mounts.holds(pid, id)
    {
        return Ok(probe);
    }
    let Ok(landed) = std::fs::read_link(format!("/proc/self/fd/{}", probe.as_raw_fd())) else {
        return Err(libc::ENOENT);
    };
    // A pipe, a socket or an anonymous inode sits on no mount any `mountinfo` lists, and the kernel
    // names it `pipe:[…]` rather than with a path — so no mount can ever vouch for one. Reached
    // through the caller's **own** `/proc` entry it needs none: what `/proc/self/fd` holds is what
    // the caller already holds, and handing a copy back grants nothing. Reached any other way it is
    // refused below, which is what keeps `/dev/stdout` from arriving as this process's descriptor.
    if own && landed.to_str().is_some_and(|named| !named.starts_with('/')) {
        return Ok(probe);
    }
    let fd = probe_in_cage_root(pid, &landed)?;
    // SAFETY: fd is a fresh owned descriptor; the File takes sole ownership and closes it.
    Ok(unsafe { std::fs::File::from_raw_fd(fd) })
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
    /// The mounts each cage namespace can see, which is what tells a walk that stayed inside from
    /// one that left through an absolute symlink.
    mounts: CageMounts,
}

impl OpenLens {
    pub(crate) fn new(policy: crate::open_policy::OpenPolicy, root: PathBuf) -> OpenLens {
        OpenLens {
            policy,
            cache: ScanCache::default(),
            root,
            mounts: CageMounts::default(),
        }
    }
}

/// Take the `O_PATH` probe for `target` and confirm it describes what the cage's own walk reaches.
///
/// Opened `O_PATH`, which never blocks whatever sits at the path. Opening for reading straight away
/// would hang on a FIFO with no writer — and this is the one thread every other open in the cage is
/// queued behind, so that hang would be the whole cage's.
///
/// Deliberately **without** `O_NOFOLLOW`: the kernel is about to follow the cage's symlinks, and a
/// scan that stopped at the link would be walked around with one `ln -s`.
///
/// The errno on failure is the one the cage's own open would have met. `O_PATH` is the most
/// permissive open there is, succeeding even without read permission, so a probe that fails
/// describes a path the cage was going to fail on too — which is what lets the answer be given
/// without a second walk, and closes the last way a `CONTINUE` could be reached by naming something
/// absent while the answer is formed and putting the secret behind it afterwards.
fn probe_and_vouch(
    lens: &OpenLens,
    pid: u32,
    target: &Path,
    own: bool,
) -> Result<std::fs::File, libc::c_int> {
    use std::os::unix::io::FromRawFd;
    let Ok(cpath) = std::ffi::CString::new(target.as_os_str().as_encoded_bytes()) else {
        return Err(libc::EINVAL);
    };
    // SAFETY: cpath is a live NUL-terminated path for the duration of the call.
    let probe = unsafe { libc::open(cpath.as_ptr(), libc::O_PATH | libc::O_CLOEXEC) };
    if probe < 0 {
        return Err(io::Error::last_os_error()
            .raw_os_error()
            .unwrap_or(libc::ENOENT));
    }
    // SAFETY: probe is a fresh owned descriptor; the File takes sole ownership and closes it.
    let probe = unsafe { std::fs::File::from_raw_fd(probe) };
    // Before a byte is read from it or it is handed over: is this what the *cage's* walk would have
    // reached? Asked before the type test below, because a device and a FIFO are served from the
    // probe without ever being scanned — and `/dev/stdout` is exactly such a device.
    vouched_probe(lens, pid, probe, own)
}

/// Replace the shortest prefix of `path` that is a symlink with what it points at.
///
/// Left to right rather than whole-path, because the link is not always the last component:
/// `/dev/fd/1` is not one, `/dev/fd` is. Reading the whole path would leave that intermediate link
/// to the kernel, which resolves what it points at against *this* process.
///
/// Only an absolute target ends the search with an answer. A relative one names something the
/// ordinary walk already reaches correctly, and stopping there keeps this from turning into a
/// resolution of its own.
fn splice_first_link(pid: u32, dirfd: libc::c_int, path: &str) -> Option<String> {
    let cuts = path
        .match_indices('/')
        .map(|(at, _)| at)
        .filter(|&at| at > 0)
        .chain(std::iter::once(path.len()));
    for cut in cuts {
        let Ok(target) = std::fs::read_link(open_target_path(pid, dirfd, &path[..cut])) else {
            continue;
        };
        let target = target.to_str()?;
        if !target.starts_with('/') {
            return None;
        }
        return Some(format!("{target}{}", &path[cut..]));
    }
    None
}

/// The caller's own `/proc` entry, when a path arrives there through a link rather than naming it.
///
/// `/dev/stdout`, `/dev/stderr`, `/dev/stdin` and `/dev/fd` are links into `/proc/self/fd`. Nothing
/// in the name the cage wrote says `self`, so the rewriting that handles the spelled-out form cannot
/// act on them, and a kernel asked to follow them resolves `self` against whoever is asking — this
/// process. The links are therefore read here rather than followed.
///
/// The hop count only has to outlast what a `/dev` entry uses; the kernel gives up at forty.
fn proc_self_behind_a_link(pid: u32, dirfd: libc::c_int, path: &str) -> Option<String> {
    let mut here = splice_first_link(pid, dirfd, path)?;
    for _ in 0..8 {
        if caller_proc_path(pid, &here).is_some() {
            return Some(here);
        }
        here = splice_first_link(pid, dirfd, &here)?;
    }
    None
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
    // A path that names the caller's own `/proc` entry is one whose object the caller already holds,
    // which is what lets an anonymous inode behind it be accepted where no mount could vouch for it.
    let own = caller_proc_path(pid, path).is_some();
    let probe = match probe_and_vouch(lens, pid, &open_target_path(pid, dirfd, path), own) {
        Ok(probe) => probe,
        // Nothing was reached, or what was reached is not what the cage's walk would have found.
        // Before answering with that, one more question: does the path arrive at the caller's own
        // `/proc` entry through a link? `/dev/stdout` is `/proc/self/fd/1`, and its neighbours are
        // the same shape — names that say nothing about `self`, so the rewriting that handles the
        // spelled-out form cannot see them, while the kernel following them resolves `self` against
        // this process. Asked only here, so an open that resolved normally pays nothing for it.
        Err(e) => {
            let Some(reached) = proc_self_behind_a_link(pid, dirfd, path) else {
                return OpenOutcome::failed(e);
            };
            match probe_and_vouch(lens, pid, &open_target_path(pid, dirfd, &reached), true) {
                Ok(probe) => probe,
                // The first answer, not the second: the link was a guess at what the path meant, and
                // a guess that led nowhere says nothing about the open.
                Err(_) => return OpenOutcome::failed(e),
            }
        }
    };
    use std::os::unix::io::AsRawFd;
    // What the kernel actually resolved, which is what the project bound is applied to.
    let Ok(resolved) = std::fs::read_link(format!("/proc/self/fd/{}", probe.as_raw_fd())) else {
        return OpenOutcome::ALLOWED;
    };
    let Ok(meta) = probe.metadata() else {
        return OpenOutcome::ALLOWED;
    };
    // A FIFO, a socket or a device carries no content this policy is written about, so none of them
    // is scanned. The descriptor still rides out: what serves such an open is decided in
    // `serve_open`, which knows the caller's flags and therefore knows whether reopening one could
    // block. Answering `CONTINUE` here instead would leave the widest door of all, since the cage
    // picks what it names first and a `mkfifo` in its own project costs it nothing.
    if !meta.is_file() && !meta.is_dir() {
        return OpenOutcome::allowed_from(probe);
    }
    // The type is settled before the project bound, because a file outside the tree is served from a
    // descriptor too. Nothing outside is *scanned* — that is what the bound is for — but a
    // `CONTINUE` there would re-resolve a path the cage can point back *into* the tree after the
    // fact, which would leave the whole lens walkable by naming `/etc/hostname` first.
    if !meta.is_file() || !resolved.starts_with(&lens.root) {
        return OpenOutcome::allowed_from(probe);
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
            probe: (!remembered).then_some(probe),
            errno: None,
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
            probe: Some(probe),
            errno: None,
        };
    }
    // Naming the shapes costs a second walk, paid only here — on content already refused, once per
    // file per launch.
    let shapes: Vec<String> = policy
        .matched_names(&buf)
        .into_iter()
        .map(str::to_string)
        .collect();
    // A refusal needs no descriptor: it is answered with an errno, and the syscall never runs.
    OpenOutcome {
        refused: true,
        report: Some(OpenReport {
            path: path.to_string(),
            shapes,
            partial: false,
        }),
        probe: None,
        errno: None,
    }
}

/// What one notified open resolved to, and whether it is worth telling anyone.
struct OpenOutcome {
    refused: bool,
    /// Present only the first time this launch scanned the file, so one reopened in a loop is
    /// reported once.
    report: Option<OpenReport>,
    /// The supervisor's own `O_PATH` descriptor for the inode it examined, when the open can be
    /// served from one.
    ///
    /// This is what closes the allow race. The verdict was formed against *this* inode; handing the
    /// cage a descriptor derived from it means the path it wrote is never resolved a second time,
    /// so there is no moment at which a sibling thread's rewrite could redirect the open. Absent
    /// when there is nothing to serve from: a refusal, which is answered with an errno of its own,
    /// or a probe that could not be taken at all.
    probe: Option<std::fs::File>,
    /// The errno the supervisor's own probe met, when it met one.
    ///
    /// Carried rather than discarded because it *is* the answer: a path the probe could not open is
    /// a path the cage could not have opened either, so replying with it settles the open without
    /// the kernel walking that path a second time.
    errno: Option<libc::c_int>,
}

impl OpenOutcome {
    const ALLOWED: OpenOutcome = OpenOutcome {
        refused: false,
        report: None,
        probe: None,
        errno: None,
    };

    /// The open the supervisor's probe could not make, answered with what it met.
    /// A refusal carrying the errno the cage is told.
    ///
    /// The rule is applied here rather than by the caller, because the caller is where it was
    /// missed: an errno that describes *this* process — out of descriptors, out of memory — is
    /// replaced by the supervisor's own `EACCES`. The refusal itself stands either way; a path that
    /// could not be examined is not one to serve, and answering `CONTINUE` instead would let a cage
    /// walk past the scan by putting the supervisor under descriptor pressure. What is corrected is
    /// only what the cage is told about *why*, which it would otherwise read as its own failure.
    fn failed(errno: libc::c_int) -> OpenOutcome {
        OpenOutcome {
            refused: false,
            report: None,
            probe: None,
            errno: Some(if errno_describes_the_file(errno) {
                errno
            } else {
                libc::EACCES
            }),
        }
    }

    /// Allowed, and servable from the descriptor the supervisor already holds.
    fn allowed_from(probe: std::fs::File) -> OpenOutcome {
        OpenOutcome {
            refused: false,
            report: None,
            probe: Some(probe),
            errno: None,
        }
    }
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

/// The caller's own numbers as its **cage** spells them.
///
/// `status` lists a task's id in each pid namespace it belongs to, outermost first, so the last
/// field is the one the cage's own `/proc` uses. Both are needed: `self` names the thread group and
/// `thread-self` names the thread inside it.
fn caller_ids_in_cage(pid: u32) -> Option<(u32, u32)> {
    innermost_ids(&std::fs::read_to_string(format!("/proc/{pid}/status")).ok()?)
}

/// The umask the caller creates files under, as its own `status` reports it.
fn caller_umask(pid: u32) -> Option<u32> {
    umask_of(&std::fs::read_to_string(format!("/proc/{pid}/status")).ok()?)
}

/// The `Umask` line of a `status` file, read as the octal it is written in.
///
/// Apart from the read so the parse can be pinned on a literal, like [`innermost_ids`] next door.
fn umask_of(status: &str) -> Option<u32> {
    u32::from_str_radix(
        status
            .lines()
            .find_map(|line| line.strip_prefix("Umask:"))?
            .trim(),
        8,
    )
    .ok()
}

/// The innermost `NStgid`/`NSpid` a `status` file carries.
///
/// Apart from the read so that the shape it parses can be pinned on a literal. The line a cage
/// produces carries two numbers and the file this process reads carries one, so the case that
/// matters here is the one a host cannot show by reading its own.
fn innermost_ids(status: &str) -> Option<(u32, u32)> {
    let innermost = |field: &str| -> Option<u32> {
        status
            .lines()
            .find_map(|line| line.strip_prefix(field))?
            .split_whitespace()
            .next_back()?
            .parse()
            .ok()
    };
    Some((innermost("NStgid:")?, innermost("NSpid:")?))
}

/// Rewrite a path that names `self` or `thread-self` into one that names the caller.
///
/// Those two are not ordinary entries: the kernel answers them with the number of whoever is
/// performing the lookup, in the pid namespace the `/proc` being walked belongs to. A supervisor
/// walking the cage's `/proc` is in neither, so it finds nothing — and the cage, whose open would
/// have succeeded, is told the file is not there.
///
/// The caller is who the path means, and it can be named outright. The result is spelled the way the
/// **cage** spells it, so the walk stays on the cage's own `/proc` mount and the descriptor handed
/// over is one the cage could have opened itself.
///
/// Only a path that names them outright is rewritten. A link the cage plants to one of them is
/// followed by the kernel against this process's root instead, and is refused rather than served —
/// the same answer, reached by [`vouched_probe`] rather than here.
fn caller_proc_path(pid: u32, path: &str) -> Option<String> {
    let (rest, thread) = match path.strip_prefix("/proc/self") {
        Some(rest) => (rest, false),
        None => (path.strip_prefix("/proc/thread-self")?, true),
    };
    // `/proc/selfish` is not `/proc/self`.
    if !rest.is_empty() && !rest.starts_with('/') {
        return None;
    }
    let (tgid, tid) = caller_ids_in_cage(pid)?;
    Some(if thread {
        format!("/proc/{tgid}/task/{tid}{rest}")
    } else {
        format!("/proc/{tgid}{rest}")
    })
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
        // `self` and `thread-self` mean the caller, and mean it only to whoever resolves them; a
        // walk from here would resolve them to this process, which is in neither of the cage's
        // namespaces. Named outright instead, so the walk reaches the caller's own entry.
        let named = caller_proc_path(pid, path);
        let path = named.as_deref().unwrap_or(path);
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
                        undecidable: &Undecidable::default(),
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
    fn an_allowed_open_hands_the_cage_the_inode_that_was_scanned() {
        // The property this defends is what makes an *allow* mean anything. The supervisor forms its
        // verdict against an inode, and the cage must receive a descriptor for that inode — not for
        // whatever the path it wrote names once the answer is given.
        //
        // The adversary here is a symlink flipped under the cage's feet, which races the same window
        // a sibling thread rewriting the path argument would: the supervisor scans what the link
        // pointed at, and the answer decides whether the kernel gets to walk the link a second time.
        // Answering `CONTINUE` lets it, and the secret crosses; serving the scanned descriptor does
        // not, and there is no second walk to redirect.
        use std::sync::atomic::{AtomicBool, Ordering};
        const SECRET: &str = "sk-ABC123DEF456GHI789";
        const ROUNDS: usize = 400;

        let dir = TmpDir::new();
        let secret = dir.join("secret.txt");
        std::fs::write(&secret, format!("API key: {SECRET}\n")).expect("write the secret fixture");
        let door = dir.join("door");
        std::os::unix::fs::symlink(&secret, &door).expect("plant the door");

        let stop = Arc::new(AtomicBool::new(false));
        let flipper = {
            let (stop, dir_path, door, secret) = (
                Arc::clone(&stop),
                dir.join(".").to_path_buf(),
                door.clone(),
                secret.clone(),
            );
            std::thread::spawn(move || {
                let mut n = 0usize;
                while !stop.load(Ordering::Relaxed) {
                    // A fresh inode for the clean side every flip, so its verdict is never answered
                    // from the cache: a cached answer skips the read, and the read is the widest
                    // part of the window this test has to be able to lose. Kept small, because the
                    // flip rate matters more here than the length of any one scan.
                    let clean = dir_path.join(format!("clean-{}.txt", n % 64));
                    n += 1;
                    if std::fs::write(&clean, vec![b'.'; 4096]).is_err() {
                        return;
                    }
                    for target in [clean.as_path(), secret.as_path()] {
                        let tmp = dir_path.join("door.tmp");
                        let _ = std::fs::remove_file(&tmp);
                        if std::os::unix::fs::symlink(target, &tmp).is_ok() {
                            let _ = std::fs::rename(&tmp, &door);
                        }
                    }
                }
            })
        };

        let script = format!(
            "i=0; while [ $i -lt {ROUNDS} ]; do /bin/cat {} 2>/dev/null; i=$((i+1)); done",
            door.to_str().expect("utf-8 fixture path")
        );
        let (_, out) = run_with_open_lens(
            &["/bin/sh", "-c", &script],
            &[r"sk-[A-Za-z0-9]{12,}"],
            &dir.join("."),
        );
        stop.store(true, Ordering::Relaxed);
        flipper.join().expect("the flipper thread");

        assert!(
            !out.contains(SECRET),
            "the cage received a descriptor for a file the supervisor never scanned: the verdict was \
             formed against one inode and the open landed on another"
        );
    }

    #[test]
    fn a_non_regular_first_target_no_longer_lets_the_swap_through() {
        // The door increment one left open, and the cheapest one to walk: the supervisor decides on
        // the path it read, so the cage picks what that path names *first*. Naming something the
        // supervisor could not serve from a descriptor sent the answer back to `CONTINUE`, and the
        // kernel then walked the path again onto whatever the cage had swapped in.
        //
        // A unix socket is the sharpest form of it. Its open fails whatever happens, so nothing here
        // depends on timing or on a peer: the only question is *which* file the failure is about.
        // Answered from the descriptor, it is the socket, every time. Answered with `CONTINUE`, it
        // is whatever the link points at by then, and that is a regular file holding a secret.
        use std::sync::atomic::{AtomicBool, Ordering};
        const SECRET: &str = "sk-ABC123DEF456GHI789";
        const ROUNDS: usize = 400;

        let dir = TmpDir::new();
        let secret = dir.join("secret.txt");
        std::fs::write(&secret, format!("API key: {SECRET}\n")).expect("write the secret fixture");
        let sock_path = dir.join("stand-in.sock");
        let _sock = UnixListener::bind(&sock_path).expect("bind the stand-in socket");
        let door = dir.join("door");
        std::os::unix::fs::symlink(&secret, &door).expect("plant the door");

        let stop = Arc::new(AtomicBool::new(false));
        let flipper = {
            let (stop, dir_path, door, secret, sock_path) = (
                Arc::clone(&stop),
                dir.join(".").to_path_buf(),
                door.clone(),
                secret.clone(),
                sock_path.clone(),
            );
            std::thread::spawn(move || {
                while !stop.load(Ordering::Relaxed) {
                    for target in [sock_path.as_path(), secret.as_path()] {
                        let tmp = dir_path.join("door.tmp");
                        let _ = std::fs::remove_file(&tmp);
                        if std::os::unix::fs::symlink(target, &tmp).is_ok() {
                            let _ = std::fs::rename(&tmp, &door);
                        }
                    }
                }
            })
        };

        let script = format!(
            "i=0; while [ $i -lt {ROUNDS} ]; do /bin/cat {} 2>/dev/null; i=$((i+1)); done",
            door.to_str().expect("utf-8 fixture path")
        );
        let (_, out) = run_with_open_lens(
            &["/bin/sh", "-c", &script],
            &[r"sk-[A-Za-z0-9]{12,}"],
            &dir.join("."),
        );
        stop.store(true, Ordering::Relaxed);
        flipper.join().expect("the flipper thread");

        assert!(
            !out.contains(SECRET),
            "naming a socket first sent the answer back to a path walk, and the walk landed on the \
             secret: a target the supervisor cannot read is still a target it must answer for"
        );
    }

    #[test]
    fn an_absent_first_target_is_answered_rather_than_walked_again() {
        // The cheapest door of the three, because it needs no special file at all: point the name at
        // nothing while the answer is being formed, and a `CONTINUE` would send the kernel back down
        // the path once the secret is behind it.
        //
        // Both halves matter. The secret must not cross, and a missing file must still read as
        // missing: answering with the probe's own errno is only sound if it is the errno the cage
        // would have met.
        use std::sync::atomic::{AtomicBool, Ordering};
        const SECRET: &str = "sk-ABC123DEF456GHI789";
        const ROUNDS: usize = 400;

        let dir = TmpDir::new();
        let secret = dir.join("secret.txt");
        std::fs::write(&secret, format!("API key: {SECRET}\n")).expect("write the secret fixture");
        let nowhere = dir.join("nowhere.txt");
        let door = dir.join("door");
        std::os::unix::fs::symlink(&secret, &door).expect("plant the door");

        let stop = Arc::new(AtomicBool::new(false));
        let flipper = {
            let (stop, dir_path, door, secret, nowhere) = (
                Arc::clone(&stop),
                dir.join(".").to_path_buf(),
                door.clone(),
                secret.clone(),
                nowhere.clone(),
            );
            std::thread::spawn(move || {
                while !stop.load(Ordering::Relaxed) {
                    for target in [nowhere.as_path(), secret.as_path()] {
                        let tmp = dir_path.join("door.tmp");
                        let _ = std::fs::remove_file(&tmp);
                        if std::os::unix::fs::symlink(target, &tmp).is_ok() {
                            let _ = std::fs::rename(&tmp, &door);
                        }
                    }
                }
            })
        };

        let script = format!(
            "i=0; while [ $i -lt {ROUNDS} ]; do /bin/cat {} 2>&1; i=$((i+1)); done",
            door.to_str().expect("utf-8 fixture path")
        );
        let (_, out) = run_with_open_lens(
            &["/bin/sh", "-c", &script],
            &[r"sk-[A-Za-z0-9]{12,}"],
            &dir.join("."),
        );
        stop.store(true, Ordering::Relaxed);
        flipper.join().expect("the flipper thread");

        assert!(
            !out.contains(SECRET),
            "naming something absent sent the answer back to a path walk, and the walk landed on \
             the secret once it was put there"
        );
        assert!(
            out.contains("No such file"),
            "a path that is not there must still read as not there, or the errno being replied with \
             is not the one the cage would have met: {out}"
        );
    }

    #[test]
    fn a_device_and_a_fifo_are_served_without_changing_what_the_cage_gets() {
        // The arms that carry the most machinery are also the ones that would break quietly: a cage
        // opens `/dev/null` constantly, and a FIFO read is served from a thread of its own. What is
        // asserted here is that neither behaves differently for being served.
        //
        // The `O_NONBLOCK` a character device is opened with is the supervisor's own doing, to avoid
        // hanging on hardware that waits; leaving it set on what the cage receives would turn a
        // blocking read into a spurious `EAGAIN` in the caller's hands.
        let dir = TmpDir::new();
        let pipe = dir.join("pipe");
        let c = std::ffi::CString::new(pipe.as_os_str().as_encoded_bytes()).expect("fixture path");
        // SAFETY: c is a live NUL-terminated path for the duration of the call.
        assert_eq!(
            unsafe { libc::mkfifo(c.as_ptr(), 0o600) },
            0,
            "make the fixture pipe"
        );

        // A writer for the whole run, so the read side completes rather than waiting for one, and a
        // bounded read so the payload ends rather than following the pipe forever.
        //
        // The wait for a reader is bounded the same way the supervisor bounds its own
        // write-direction open: `O_NONBLOCK` reports `ENXIO` until one arrives, so this asks again
        // rather than blocking in `open`. A blocking open here would be unbounded, and the `join`
        // below would then hold the whole test binary — not just this test — on any run where the
        // payload fails before it reaches the read side. That is a failure reported as a hang
        // rather than by name, and the deadline that would eventually catch it belongs to whatever
        // runs the suite.
        let writer = {
            let pipe = pipe.clone();
            std::thread::spawn(move || {
                use std::io::Write;
                use std::os::unix::fs::OpenOptionsExt;
                let deadline = std::time::Instant::now() + Duration::from_secs(20);
                let mut w = loop {
                    match std::fs::OpenOptions::new()
                        .write(true)
                        .custom_flags(libc::O_NONBLOCK)
                        .open(&pipe)
                    {
                        Ok(w) => break w,
                        Err(_) if std::time::Instant::now() < deadline => {
                            std::thread::sleep(Duration::from_millis(10));
                        }
                        Err(_) => return,
                    }
                };
                // The flag was for the open alone: the writes below are the ordinary blocking ones
                // the reader is meant to meet.
                use std::os::unix::io::AsRawFd;
                // SAFETY: w is this thread's live descriptor; F_SETFL only alters status flags.
                unsafe {
                    let cur = libc::fcntl(w.as_raw_fd(), libc::F_GETFL);
                    if cur >= 0 {
                        libc::fcntl(w.as_raw_fd(), libc::F_SETFL, cur & !libc::O_NONBLOCK);
                    }
                }
                for _ in 0..200 {
                    if w.write_all(b"pipebyte").is_err() {
                        return;
                    }
                }
            })
        };

        // The two output files exist before the payload runs. Creating one from inside would be a
        // different subject: the supervisor examines a path with a probe that does not create, so a
        // name that is not there yet is a question it cannot answer on the open's behalf.
        //
        // Each `dd` is given an `of=`, and what it wrote is read back from there. Without one, `dd`
        // examines its output by opening `/dev/stdout` — a link into `/proc/self/fd`, which names
        // whichever process resolves it. That would make the arm depend on what the suite's own
        // output happens to be rather than on the property asserted here; `/dev/stdout` across the
        // cage boundary is a subject of its own, and belongs to a test that has a boundary to cross.
        for name in ["device.bin", "fifo.bin"] {
            std::fs::write(dir.join(name), b"").expect("place the output fixture");
        }
        let script = format!(
            "/bin/cat /dev/null; \
             /bin/dd if=/dev/urandom bs=4 count=1 of={1} 2>/dev/null; /bin/wc -c < {1}; \
             /bin/dd if={0} bs=8 count=1 of={2} 2>/dev/null; /bin/cat {2}",
            pipe.to_str().expect("utf-8 fixture path"),
            dir.join("device.bin").to_str().expect("utf-8 fixture path"),
            dir.join("fifo.bin").to_str().expect("utf-8 fixture path"),
        );
        let (code, out) = run_with_open_lens(
            &["/bin/sh", "-c", &script],
            &[r"sk-[A-Za-z0-9]{12,}"],
            &dir.join("."),
        );
        let _ = writer.join();

        assert_eq!(code, Some(0), "the payload must run to the end: {out}");
        // The whole output, not a substring of it: a lone `4` is a digit half the diagnostics in
        // this file could produce, and an assertion a failure can still satisfy proves nothing.
        assert_eq!(
            out.trim_end(),
            "4\npipebyte",
            "a device must still deliver its four bytes and a pipe what its writer sent"
        );
    }

    #[test]
    fn self_and_thread_self_are_rewritten_to_the_caller_and_nothing_else_is() {
        // With this process as its own caller the two namespaces coincide, so what is pinned here is
        // the rewriting itself: which prefixes it claims, which it leaves alone, and that the two
        // forms differ — `self` names the group, `thread-self` the thread inside it.
        let me = std::process::id();
        let (tgid, tid) = caller_ids_in_cage(me).expect("this process has its own ids");
        assert_eq!(
            caller_proc_path(me, "/proc/self/maps").as_deref(),
            Some(format!("/proc/{tgid}/maps").as_str()),
            "`self` names the caller's thread group"
        );
        assert_eq!(
            caller_proc_path(me, "/proc/thread-self/status").as_deref(),
            Some(format!("/proc/{tgid}/task/{tid}/status").as_str()),
            "`thread-self` names the thread inside that group"
        );
        assert_eq!(
            caller_proc_path(me, "/proc/self").as_deref(),
            Some(format!("/proc/{tgid}").as_str()),
            "the directory itself is named too, not only what is under it"
        );
        // The prefix has to end where the component does, or a neighbouring name is captured with
        // it and the caller's own entry is served for a file that was never theirs.
        for untouched in [
            "/proc/selfish/maps",
            "/proc/thread-selfish",
            "/proc/1/maps",
            "/etc/passwd",
        ] {
            assert_eq!(
                caller_proc_path(me, untouched),
                None,
                "`{untouched}` does not name the caller"
            );
        }
        // A caller whose ids cannot be read leaves the path as it was, rather than being rewritten
        // against a number guessed for it.
        assert_eq!(caller_proc_path(u32::MAX, "/proc/self/maps"), None);
    }

    #[test]
    fn a_link_is_spliced_where_it_sits_and_not_only_at_the_end() {
        // `/dev/fd/1` is not a link; `/dev/fd` is. A chase that only read the last component would
        // leave that one to the kernel, which resolves what it points at against this process — the
        // very resolution being avoided.
        let me = std::process::id();
        let at = libc::AT_FDCWD;
        assert_eq!(
            splice_first_link(me, at, "/dev/fd/1").as_deref(),
            Some("/proc/self/fd/1"),
            "the link is the directory, and what follows it rides along"
        );
        assert_eq!(
            splice_first_link(me, at, "/dev/stdout").as_deref(),
            Some("/proc/self/fd/1"),
            "a link that is the whole path is spliced too"
        );

        let dir = TmpDir::new();
        std::fs::write(dir.join("plain.txt"), b"x").expect("write the fixture");
        assert_eq!(
            splice_first_link(me, at, dir.join("plain.txt").to_str().expect("utf-8")),
            None,
            "a path with no link on it has nothing to splice"
        );
        // A relative target names something the ordinary walk already reaches, and following it here
        // would make this a resolution of its own.
        std::os::unix::fs::symlink("plain.txt", dir.join("near")).expect("plant the near link");
        assert_eq!(
            splice_first_link(me, at, dir.join("near").to_str().expect("utf-8")),
            None,
            "a relative target is left to the ordinary walk"
        );
    }

    #[test]
    fn the_dev_links_arrive_at_the_callers_own_entry() {
        // What the chase exists for: none of these names says `self`, so the rewriting that handles
        // the spelled-out form cannot see them, and every one of them ends at `/proc/self/fd`.
        let me = std::process::id();
        let at = libc::AT_FDCWD;
        for (named, wanted) in [
            ("/dev/stdout", "/proc/self/fd/1"),
            ("/dev/stderr", "/proc/self/fd/2"),
            ("/dev/stdin", "/proc/self/fd/0"),
            ("/dev/fd/1", "/proc/self/fd/1"),
        ] {
            assert_eq!(
                proc_self_behind_a_link(me, at, named).as_deref(),
                Some(wanted),
                "`{named}` names the caller's own descriptor"
            );
        }
        assert_eq!(
            proc_self_behind_a_link(me, at, "/dev/null"),
            None,
            "a device that is not a link to `self` is left where it is"
        );
    }

    #[test]
    fn the_umask_line_is_read_as_the_octal_it_is_written_in() {
        // `status` writes the mask in octal without a prefix, so reading it as decimal turns `0022`
        // into eighteen — a mask that clears bits nobody asked to clear, silently.
        assert_eq!(umask_of("Name:\tsh\nUmask:\t0022\nTgid:\t1\n"), Some(0o022));
        assert_eq!(umask_of("Umask:\t0077\n"), Some(0o077));
        assert_eq!(umask_of("Umask:\t0000\n"), Some(0));
        assert_eq!(
            umask_of("Name:\tsh\nTgid:\t1\n"),
            None,
            "a file without the line answers nothing rather than a mask of zero, which would be the \
             most permissive answer there is"
        );
    }

    #[test]
    fn a_made_file_lands_with_the_masks_the_cage_asked_for() {
        // The file is made by the supervisor, so the kernel subtracts the *supervisor's* umask — and
        // the two part company the moment the cage sets its own, which is what a script writing a key
        // does. Both directions are pinned: a mask stricter than this process's has to be honoured,
        // and a mask looser than it must not be quietly narrowed by ours.
        use std::os::unix::fs::PermissionsExt;
        let dir = TmpDir::new();
        let (tight, wide) = (dir.join("tight.txt"), dir.join("wide.txt"));
        let script = format!(
            "umask 077; echo k > {}; umask 000; echo w > {}; echo done",
            tight.to_str().expect("utf-8 fixture path"),
            wide.to_str().expect("utf-8 fixture path"),
        );
        let (_, out) = run_with_open_lens(
            &["/bin/sh", "-c", &script],
            &[r"sk-[A-Za-z0-9]{12,}"],
            &dir.join("."),
        );
        assert!(
            out.contains("done"),
            "the payload must reach its last line: {out}"
        );
        let mode = |at: &std::path::Path| {
            std::fs::metadata(at)
                .unwrap_or_else(|e| panic!("the file must exist: {e}: {out}"))
                .permissions()
                .mode()
                & 0o777
        };
        assert_eq!(
            mode(&tight),
            0o600,
            "a mask the cage tightened has to reach the file, or a key it meant to keep to itself \
             arrives readable: {out}"
        );
        assert_eq!(
            mode(&wide),
            0o666,
            "and a mask the cage widened must not be narrowed by this process's own, which the \
             kernel would otherwise subtract on top: {out}"
        );
    }

    #[test]
    fn the_innermost_number_is_the_one_the_cage_uses() {
        // A cage's `status` names its tasks once per namespace it is in, outermost first. Reading
        // the first would name the task the way the *host* does, which is a number the cage's own
        // `/proc` has never heard of — so the last field is the one, and a file with a single field
        // has to keep working because that is what an uncaged process shows.
        assert_eq!(
            innermost_ids("Name:\tsh\nNStgid:\t2559290\t1\nNSpid:\t2559290\t1\n"),
            Some((1, 1)),
            "two namespaces: the cage's own numbers come last"
        );
        assert_eq!(
            innermost_ids("NStgid:\t4242\t17\t3\nNSpid:\t4242\t17\t5\n"),
            Some((3, 5)),
            "nested deeper, the innermost is still the last"
        );
        assert_eq!(
            innermost_ids("NStgid:\t4242\nNSpid:\t4242\n"),
            Some((4242, 4242)),
            "one namespace names the task once"
        );
        assert_eq!(
            innermost_ids("Name:\tsh\nNSpid:\t7\n"),
            None,
            "a file missing either line answers nothing rather than half"
        );
    }

    #[test]
    fn each_open_form_keeps_its_mode_where_its_own_abi_puts_it() {
        // The mirror of the flags test, for the argument a creating open carries. Reading the wrong
        // register would make a file land with permissions the cage never asked for.
        let mut args = [0u64; 6];
        args[2] = 0o600;
        args[3] = 0o640;
        assert_eq!(
            open_mode(std::process::id(), libc::SYS_open as libc::c_int, &args),
            Some(0o600),
            "`open` keeps its mode in the third argument"
        );
        assert_eq!(
            open_mode(std::process::id(), libc::SYS_openat as libc::c_int, &args),
            Some(0o640),
            "`openat` leads with the descriptor, so its mode sits one along"
        );
        assert_eq!(
            open_mode(std::process::id(), libc::SYS_read as libc::c_int, &args),
            None,
            "a syscall that is not an open has no mode to read"
        );
        // `openat2` carries the mode in the struct, and a `size` too small to reach it describes a
        // call the kernel refuses anyway.
        let how: [u64; 3] = [libc::O_CREAT as u64, 0o600, 0];
        let mut args2 = [0u64; 6];
        args2[2] = how.as_ptr() as u64;
        args2[3] = 8;
        assert_eq!(
            open_mode(std::process::id(), libc::SYS_openat2 as libc::c_int, &args2),
            None,
            "a struct too short to hold the mode word carries no mode"
        );
        args2[3] = std::mem::size_of_val(&how) as u64;
        assert_eq!(
            open_mode(std::process::id(), libc::SYS_openat2 as libc::c_int, &args2),
            Some(0o600),
            "the mode is the second field of `struct open_how`"
        );
    }

    #[test]
    fn a_name_that_is_not_there_yet_is_made_rather_than_reported_absent() {
        // The probe that examines a path creates nothing, so a creating open finds its name absent
        // and would be told so. Both halves are asserted: the file has to appear with the bytes the
        // cage wrote, and a file that already carries a secret must still be refused — a lens that
        // answered every creating open by making the file would satisfy the first alone.
        let dir = TmpDir::new();
        let secret = dir.join("carries.txt");
        std::fs::write(&secret, b"API key: sk-ABC123DEF456GHI789\n").expect("write the fixture");

        let made = dir.join("made.txt");
        let script = format!(
            // The refused read is not last: its own failure is the point, and the exit code
            // asserted below is about the payload reaching its end rather than about that read.
            "echo neuf > {0}; echo made=$?; cat {0}; cat {1} 2>&1; echo fin",
            made.to_str().expect("utf-8 fixture path"),
            secret.to_str().expect("utf-8 fixture path"),
        );
        let (code, out) = run_with_open_lens(
            &["/bin/sh", "-c", &script],
            &[r"sk-[A-Za-z0-9]{12,}"],
            &dir.join("."),
        );
        assert_eq!(code, Some(0), "the payload must run to the end: {out}");
        assert!(
            out.contains("fin"),
            "the payload must reach its last line: {out}"
        );
        assert!(
            out.contains("made=0") && out.contains("neuf"),
            "the file must be created and carry what was written to it: {out}"
        );
        assert_eq!(
            std::fs::read_to_string(&made).expect("the file exists on this side too"),
            "neuf\n",
            "the file the cage was served has to be the one that appeared on disk"
        );
        assert!(
            !out.contains("sk-ABC123DEF456GHI789"),
            "a file that already carries a secret is still refused: {out}"
        );
    }

    #[test]
    fn the_statx_layout_matches_the_kernels() {
        // The struct is filled by the kernel, so a field at the wrong offset would be read as
        // whatever sits there — silently, and with a plausible value. The two offsets that matter
        // are the mask the answer is confirmed with and the number it carries.
        assert_eq!(
            std::mem::size_of::<Statx>(),
            256,
            "`struct statx` is 256 bytes, and the kernel writes all of them"
        );
        assert_eq!(std::mem::offset_of!(Statx, mask), 0, "the mask leads");
        assert_eq!(
            std::mem::offset_of!(Statx, mnt_id),
            144,
            "the mount number sits after the device numbers"
        );
    }

    #[test]
    fn a_mount_this_process_cannot_see_is_never_taken_for_one_it_can() {
        // The gate that decides whether a walk stayed inside the cage. Both directions matter: a
        // mount the process has must be recognised, or every open pays a second resolution; and one
        // it does not have must not be, or the check passes what it exists to catch.
        let here = std::fs::File::open(".").expect("open the working directory");
        use std::os::unix::io::AsRawFd;
        let id = mount_id(here.as_raw_fd()).expect("this kernel carries the mount id");
        let mounts = CageMounts::default();
        let me = std::process::id();
        assert!(
            mounts.holds(me, id),
            "the mount this process's own directory sits on is one it can see"
        );
        // `u64::MAX` is not a mount number the kernel hands out, so nothing can make this one true.
        assert!(
            !mounts.holds(me, u64::MAX),
            "a mount number that names nothing must not be taken for one the process has"
        );
    }

    #[test]
    fn a_process_that_cannot_be_read_answers_no_rather_than_yes() {
        // The fail direction, which is the branch no host here exercises by accident. A target
        // already reaped, or a `/proc` entry that cannot be read, leaves the question unanswered —
        // and an unanswered question must send the open down the second resolution, never past it.
        let mounts = CageMounts::default();
        // A pid one past the maximum the kernel can allocate: `/proc/<it>` never exists.
        let absent = u32::MAX;
        assert!(
            CageMounts::namespace_of(absent).is_none(),
            "no namespace can be read for a process that is not there"
        );
        assert!(
            !mounts.holds(absent, 1),
            "a mount cannot be vouched for against a process that cannot be read"
        );
    }

    #[test]
    fn the_second_resolution_reaches_the_same_inode_and_refuses_a_marked_path() {
        // What the second resolution is for: reaching a path from inside a root rather than from
        // this process's own. With this process as its own target the two roots coincide, so what is
        // pinned here is that it reaches the file it names — and that a path the kernel *marked*
        // rather than named is refused, since such a string is not one a walk can start from.
        use std::os::unix::io::FromRawFd;
        let me = std::process::id();
        let dir = TmpDir::new();
        let file = dir.join("target.txt");
        std::fs::write(&file, b"contents\n").expect("write the fixture");

        let fd = probe_in_cage_root(me, &file).expect("the path resolves from inside the root");
        // SAFETY: fd is a fresh owned descriptor; the File takes sole ownership and closes it.
        let reached = unsafe { std::fs::File::from_raw_fd(fd) };
        let (want, got) = (
            FileId::of(&std::fs::metadata(&file).expect("stat the fixture")),
            FileId::of(&reached.metadata().expect("stat what was reached")),
        );
        assert_eq!(
            (want.dev, want.ino),
            (got.dev, got.ino),
            "the second resolution must reach the very file it names"
        );

        assert_eq!(
            probe_in_cage_root(me, Path::new("(unreachable)/etc/hostname")),
            Err(libc::ENOENT),
            "a path the kernel marked rather than named is not one a walk can start from"
        );
        assert_eq!(
            probe_in_cage_root(me, &dir.join("absent.txt")),
            Err(libc::ENOENT),
            "a name that is not there is answered with the errno the cage's own open would meet"
        );
    }

    #[test]
    fn a_secret_named_from_a_subdirectory_is_still_scanned() {
        // The fast path exists so that an ordinary relative open keeps resolving exactly as it did,
        // `..` included. Pinning it here because the alternative once considered — resolving every
        // open inside the cage's root — would rebase `..` onto the starting directory and let this
        // very open through unscanned.
        let dir = TmpDir::new();
        let secret = dir.join("carries.txt");
        std::fs::write(&secret, b"API key: sk-ABC123DEF456GHI789\n").expect("write the fixture");
        std::fs::create_dir(dir.join("sub")).expect("make the subdirectory");

        let script = format!(
            "cd {} && /bin/cat ../carries.txt 2>&1",
            dir.join("sub").to_str().expect("utf-8 fixture path")
        );
        let (_, out) = run_with_open_lens(
            &["/bin/sh", "-c", &script],
            &[r"sk-[A-Za-z0-9]{12,}"],
            &dir.join("."),
        );
        assert!(
            !out.contains("sk-ABC123DEF456GHI789"),
            "a secret named through `..` reached the cage, so the open was not scanned: {out}"
        );
        assert!(
            out.contains("Permission denied") || out.contains("Permission non accord"),
            "the open must be refused rather than fail for some other reason: {out}"
        );
    }

    #[test]
    fn each_open_form_keeps_its_flags_where_its_own_abi_puts_them() {
        // The mirror of `each_open_form_is_read_from_its_own_registers`, for the other argument the
        // decision now depends on. Reading the wrong register would serve a descriptor opened for
        // something other than what the cage asked for.
        let mut args = [0u64; 6];
        args[1] = 0x111;
        args[2] = 0x222;
        assert_eq!(
            open_flags(std::process::id(), libc::SYS_open as libc::c_int, &args),
            Some(0x111),
            "`open` keeps its flags in the second argument"
        );
        assert_eq!(
            open_flags(std::process::id(), libc::SYS_openat as libc::c_int, &args),
            Some(0x222),
            "`openat` leads with the descriptor, so its flags sit one along"
        );
        assert_eq!(
            open_flags(std::process::id(), libc::SYS_read as libc::c_int, &args),
            None,
            "a syscall that is not an open has no flags to read"
        );
    }

    #[test]
    fn openat2_reads_its_flags_from_the_struct_it_points_at() {
        // `openat2` is the one form that does not pass its flags in a register, and it is reachable
        // by an adversary calling the syscall directly whether or not a toolchain emits it.
        let how: [u64; 3] = [libc::O_RDONLY as u64 | libc::O_CLOEXEC as u64, 0, 0];
        let mut args = [0u64; 6];
        args[2] = how.as_ptr() as u64;
        args[3] = std::mem::size_of_val(&how) as u64;
        assert_eq!(
            open_flags(std::process::id(), libc::SYS_openat2 as libc::c_int, &args),
            Some(libc::O_RDONLY as u64 | libc::O_CLOEXEC as u64),
            "the flag word is the first field of `struct open_how`"
        );
        args[3] = 4;
        assert_eq!(
            open_flags(std::process::id(), libc::SYS_openat2 as libc::c_int, &args),
            None,
            "a `size` too small to hold the flag word describes a call the kernel refuses anyway"
        );
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

    /// The errno rule reports the file's failures and never this process's.
    ///
    /// Written against literals rather than against the function's own list: a test that asks the
    /// rule what the rule says would accept any list, including an empty one. The refused half is
    /// the half that matters — each of these three is a way *this* process can fail to open a path
    /// the cage had every right to open, and reporting one to the cage would deny that open and
    /// blame the caller's own descriptors for it.
    #[test]
    fn an_errno_about_this_process_is_never_reported_as_the_files() {
        for e in [
            libc::EROFS,
            libc::EACCES,
            libc::EPERM,
            libc::ENXIO,
            libc::ELOOP,
            libc::ENOTDIR,
            libc::EISDIR,
            libc::ENOENT,
            libc::ETXTBSY,
        ] {
            assert!(
                errno_describes_the_file(e),
                "errno {e} describes the file and is the cage's answer"
            );
        }
        for e in [libc::EMFILE, libc::ENFILE, libc::ENOMEM] {
            assert!(
                !errno_describes_the_file(e),
                "errno {e} describes the supervisor, and the cage must not be told it"
            );
        }
    }

    /// And the rule reaches the cage through the constructor, so a site that reports a refusal
    /// cannot skip it by being written later.
    #[test]
    fn a_refusal_never_carries_an_errno_about_the_supervisor() {
        assert_eq!(OpenOutcome::failed(libc::ENOENT).errno, Some(libc::ENOENT));
        assert_eq!(OpenOutcome::failed(libc::EMFILE).errno, Some(libc::EACCES));
        assert_eq!(OpenOutcome::failed(libc::ENOMEM).errno, Some(libc::EACCES));
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
                        undecidable: &Undecidable::default(),
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

        // The refusal and its announcement are not the same moment: what returns above is the
        // payload's exit status, while the notification is recorded on the supervisor's own
        // thread. Reading the recorder once therefore reads it before the writer reached it
        // whenever the machine is busy, so the read waits for the first announcement instead. The
        // deadline is what keeps a genuinely lost announcement a failure rather than a hang.
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        let announced = loop {
            let now = seen.lock().expect("recorder lock").clone();
            if !now.is_empty() || std::time::Instant::now() >= deadline {
                break now;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        };
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

    /// The pieces a [`Deciding`] borrows, owned by the caller so the context has something to point
    /// at. Only the policy is left out: it is what each test below varies.
    struct DecidingParts {
        overlay: ProcOverlay,
        ring: ExecRing,
        pending: PendingExec,
        notifier: crate::sandbox::notify_sink::Notifier,
        undecidable: Undecidable,
        lens: Option<OpenLens>,
    }

    impl DecidingParts {
        fn new() -> DecidingParts {
            DecidingParts {
                overlay: ProcOverlay::new(),
                ring: ExecRing::new(8),
                pending: PendingExec::new(),
                notifier: crate::sandbox::notify_sink::Notifier::disabled(),
                undecidable: Undecidable::default(),
                lens: None,
            }
        }

        /// The same pieces with a content lens armed. What it looks for does not matter to the tests
        /// below — they are about the opens it never gets to look at.
        fn with_lens() -> DecidingParts {
            let policy = crate::open_policy::OpenPolicy::compile(&["secret".to_string()], 4096)
                .expect("a valid pattern")
                .expect("a non-empty policy");
            DecidingParts {
                lens: Some(OpenLens::new(policy, PathBuf::from("/"))),
                ..DecidingParts::new()
            }
        }

        fn cx<'a>(&'a self, policy: &'a ProcPolicy) -> Deciding<'a> {
            Deciding {
                policy,
                overlay: &self.overlay,
                ring: &self.ring,
                pending: &self.pending,
                notifier: &self.notifier,
                open: self.lens.as_ref(),
                undecidable: &self.undecidable,
            }
        }
    }

    /// An address mapped in no process, in a process this one is not the ancestor of: between them
    /// they refuse both halves of the read, whichever the host's `ptrace_scope` allows. This is how
    /// the tests below reach the branch a hardened host would reach for every decision.
    const UNREADABLE: (u32, u64) = (1, 0);

    #[test]
    fn an_execve_whose_target_cannot_be_read_takes_the_modes_default_and_every_one_is_counted() {
        // The fallback itself is deliberate and stays: a supervisor that refused every read it could
        // not make would brick a cage on one process reaped mid-decision. What must not stay is that
        // it passes unremarked. The exec ring notes such a target as `<unreadable>`, but the ring is
        // bounded, so a run where every read fails evicts the real entries and leaves a tail that
        // reads like ordinary traffic. The count is what separates one race from a policy that is
        // deciding nothing by name, so every occurrence counts and not only the one that warned.
        for (mode, expected) in [
            (ProcMode::Enforce, Verdict::Allow),
            (ProcMode::Confine, Verdict::Deny),
            (ProcMode::Ask, Verdict::Ask),
        ] {
            let policy = ProcPolicy::new(mode, &[], &[]);
            let parts = DecidingParts::new();
            let cx = parts.cx(&policy);
            let (pid, addr) = UNREADABLE;
            for _ in 0..3 {
                assert_eq!(
                    exec_verdict(&cx, &[], pid, addr),
                    (expected, "<unreadable>".to_string()),
                    "under {mode:?}"
                );
            }
            assert_eq!(
                parts.undecidable.exec.load(Ordering::Relaxed),
                3,
                "under {mode:?}: every undecidable exec counts, not only the first"
            );
        }
    }

    #[test]
    fn an_open_the_lens_cannot_name_is_counted_because_it_leaves_nothing_else_behind() {
        // Unlike an exec, an open the lens could not name leaves no trace at all: this lens records
        // the refusals it decided, never the decisions it could not take. The counter is the only
        // thing that remembers it happened, which is the whole reason it exists.
        let policy = ProcPolicy::new(ProcMode::Enforce, &[], &[]);
        let (pid, addr) = UNREADABLE;

        let armed = DecidingParts::with_lens();
        for _ in 0..2 {
            assert!(
                open_name(&armed.cx(&policy), pid, addr).is_empty(),
                "an open whose path cannot be read has no name to decide against"
            );
        }
        assert_eq!(armed.undecidable.open.load(Ordering::Relaxed), 2);
        assert!(
            armed.ring.snapshot(None).events.is_empty(),
            "the open lens leaves no entry for a name it never read — hence the counter"
        );

        // And a cage that never asked for the lens is not told it lost something it never had.
        let bare = DecidingParts::new();
        assert!(open_name(&bare.cx(&policy), pid, addr).is_empty());
        assert_eq!(bare.undecidable.open.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn a_caller_whose_program_is_not_a_name_a_policy_can_hold_is_counted_rather_than_flattened() {
        // `/proc/<pid>/exe` is bytes and a policy's caller nodes are text. A lossy conversion bridges
        // the two by mapping every byte it cannot carry onto one replacement character, so callers
        // that are different programs would arrive under a single name and a rule written for one
        // would answer for the other. The fixture is a real process launched from a directory whose
        // name is not valid UTF-8: the read succeeds, and it is the conversion that cannot.
        use std::ffi::OsStr;
        use std::os::unix::ffi::OsStrExt;

        // Runs the payload and reports the caller chain the policy would decide against.
        fn chain_for(payload: &Path, parts: &DecidingParts, policy: &ProcPolicy) -> Vec<String> {
            let mut cmd = std::process::Command::new(payload);
            cmd.arg("30");
            // Freshly written, so it meets `ETXTBSY` the same way the shim does — see `spawn_shim`.
            let mut child = spawn_shim(&mut cmd);
            // Wait for the exec to land. Before it does, `/proc/<pid>/exe` still reports this test
            // binary — whose path is perfectly good UTF-8 — so the wait stops on the condition the
            // assertion rests on rather than on time having passed.
            let exe = format!("/proc/{}/exe", child.id());
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
            while std::fs::read_link(&exe).ok().as_deref() != Some(payload) {
                if std::time::Instant::now() > deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    panic!("the payload never became `{}`", payload.display());
                }
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
            let chain = caller_chain(&parts.cx(policy), child.id());
            let _ = child.kill();
            let _ = child.wait();
            chain
        }

        let dir = TmpDir::new();
        let policy = ProcPolicy::confined(crate::proc_policy::CallerGraph::default());
        let mut payloads = Vec::new();
        for name in [b"plain".as_slice(), b"p\xff".as_slice()] {
            let sub = dir.path().join(OsStr::from_bytes(name));
            std::fs::create_dir_all(&sub).expect("the fixture directory");
            let payload = sub.join("sleep");
            // A payload that stays alive long enough to be read, and that the kernel reports back at
            // this path. Canonicalised because `/proc/<pid>/exe` is, and the fixture root may not be.
            std::fs::copy("/bin/sleep", &payload).expect("copy the payload");
            payloads.push(std::fs::canonicalize(&payload).expect("canonical payload"));
        }

        // The control arm first: with a path that IS a name, the chain carries it and nothing counts.
        // Without this the empty chain below would equally be explained by a harness that never ran.
        let plain = DecidingParts::new();
        let chain = chain_for(&payloads[0], &plain, &policy);
        assert_eq!(
            chain,
            vec![
                payloads[0]
                    .to_str()
                    .expect("a UTF-8 control path")
                    .to_string()
            ],
            "the caller a policy can name is the one it decides against"
        );
        assert_eq!(plain.undecidable.caller.load(Ordering::Relaxed), 0);

        let odd = DecidingParts::new();
        let chain = chain_for(&payloads[1], &odd, &policy);
        assert!(
            chain.is_empty(),
            "a name that cannot be carried is not a name: {chain:?}"
        );
        assert_eq!(
            odd.undecidable.caller.load(Ordering::Relaxed),
            1,
            "and it joins the reads that did not work, rather than passing as a caller"
        );
    }

    #[test]
    fn the_teardown_report_names_a_kind_that_happened_more_than_once_and_not_one_that_happened_once()
     {
        let counts = Undecidable::default();
        counts.exec.store(1, Ordering::Relaxed);
        assert!(
            counts.report("allowed").is_empty(),
            "the single occurrence already warned when it happened; repeating it teaches a reader \
             to skip the line that one day says 8412"
        );

        counts.exec.store(8412, Ordering::Relaxed);
        counts.caller.store(2, Ordering::Relaxed);
        let lines = counts.report("allowed");
        assert_eq!(
            lines.len(),
            2,
            "one line per kind that happened more than once: {lines:?}"
        );
        assert!(
            lines[0].contains("8412") && lines[0].contains("allowed"),
            "the count and what the default did with each: {}",
            lines[0]
        );
        assert!(lines[1].contains(" 2 "), "{}", lines[1]);
        assert!(
            counts
                .report("refused")
                .iter()
                .all(|l| !l.contains("allowed")),
            "the report says what THIS mode's default did, which is what its reader acts on"
        );
    }

    #[test]
    fn a_parked_target_this_supervisor_cannot_read_reads_as_no_path_at_all() {
        // The branch guarded above is only worth guarding if production can reach it. It can: the
        // read is an ordinary open-and-read of another process's memory, and both halves refuse
        // here — the open because pid 1 is not this process's descendant, or, where it opens at all,
        // the read because address 0 is mapped in no process. Both `/proc/<pid>/mem` readers are
        // held, since the flag word is read the same careful way the path is.
        //
        // What this cannot show is how OFTEN production reaches it. That depends on the host's
        // `ptrace_scope`, a machine-wide setting no test may raise on its way past.
        let (pid, addr) = UNREADABLE;
        assert!(read_exec_path(pid, addr).is_none());
        assert!(read_u64(pid, addr).is_none());
    }
}
