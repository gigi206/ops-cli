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
//! systemd manager only happens at teardown, after the run).
//!
//! That read is guarded against a reaped-and-reused pid in the order `seccomp_unotify(2)`
//! prescribes: **open the handle, then validate, then read** ([`open_target_mem`]). Validating only
//! *before* the open proves nothing, because the two are separate steps — the target can be killed
//! and its number handed to a fresh process in between. Validating after does prove it: a pid is
//! free to be reused only once its process is gone, and a notification id stays valid only while
//! its target is parked, so an id still valid after the open says the target never left, which says
//! the number was never free, which says the descriptor is the target's.
//!
//! The check kept ahead of the read is an early-out, not the guard — it saves the work for a target
//! that is already gone. And even before the second check existed the window could not carry a
//! *verdict* anywhere: the kernel refuses every answer to a gone target's id (`NOTIF_SEND` and
//! `ADDFD` both return `ENOENT`), so what was at stake was a wrong line in the ring and a read of an
//! unrelated process's memory, rather than a decision landing on a stranger.
//!
//! The rest of the target's `/proc` — `root`, `cwd`, `fd/N`, `exe`, `status` — is still resolved by
//! path rather than through an `O_PATH` handle pinned at the same moment, so those reads keep the
//! narrower version of the same window. They inform the *name* a decision is recorded under, never
//! whether it reaches a process.
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
//! Three ways a hostile agent might try to run a denied binary around this gate are all closed by the
//! kernel, verified empirically:
//!
//! - **A compat-ABI `execve`** (a 64-bit process issuing the i386 `int 0x80` `execve`, whose number is
//!   not the native one this filter matches) does not slip through. Three filters would have to fail
//!   at once. The mandatory seccomp denylist is compiled by `seccompiler`, which prepends an
//!   architecture check that **kills the process** (`SECCOMP_RET_KILL_PROCESS`, the highest-precedence
//!   action) for any `seccomp_data.arch` that is not the native one; every compiled filter also opens
//!   by answering `ENOSYS` to any call number carrying the x32 bit, which is the one foreign ABI that
//!   passes the architecture check by sharing x86-64's `arch` value (see [`super::seccomp`]); and a
//!   policy that lifts *every* denied syscall still emits one filter carrying that pair, so the
//!   guard is not something a `[seccomp] allow` list can empty out. The shim's own notification
//!   filter opens with the same architecture check, for the same reason it sets `no_new_privs`
//!   again: what enforces exec supervision holds on its own terms.
//! - **The other exec form.** `execveat(dirfd, path, argv, envp, flags)` leads with a descriptor
//!   where `execve(path, …)` leads with the path, so a supervisor reading the first register for
//!   both reads an integer as an address, fails to name the target, and hands the decision to
//!   [`ProcPolicy::unmatched`] — `Allow` under the shipped denylist. The shim has always notified on
//!   both forms; it is the supervisor that read one of them wrong, which is why the target register
//!   is now chosen by syscall number ([`exec_args`], the exec twin of [`open_args`]) and a call that
//!   is neither exec nor open is refused rather than decided. `fexecve` is the same route wearing a
//!   library name: it issues `execveat` with an empty pathname and `AT_EMPTY_PATH`, so the target is
//!   named through the descriptor's own `/proc` link.
//! - **Installing its own notification filter** to capture and auto-`CONTINUE` its own `execve`s does
//!   not work: the kernel permits only one seccomp notification listener per process, so a second
//!   `SECCOMP_FILTER_FLAG_NEW_LISTENER` fails with `EBUSY`. The shim installs the sole listener before
//!   the agent runs, and it is held by the launcher's supervisor. A *plain* filter the agent adds can
//!   only make `execve` **more** restrictive (this filter's `USER_NOTIF` outranks a later `ALLOW`), so
//!   it can deny its own `execve` but never run a denied binary without the supervisor's `CONTINUE`.
//!
//! One route the kernel does **not** close, and this enumeration used to read as though there were
//! none: the interpreter a `#!` line names. `execve("./script")` on a file whose first two bytes are
//! `#!` is a single syscall — the kernel loads the named interpreter inside that same call, and no
//! second `execve` is ever issued — so the supervisor is notified of `./script` and never of
//! `/bin/sh`. A `deny` on `/bin/sh` therefore does not stop a script that runs under it, and the same
//! holds for every `binfmt_misc` handler (a registered interpreter for a `.jar`, a `.py`, a wine
//! binary): the enrolled interpreter runs without a notification of its own. The rule that leaves is
//! exact, and is the one to hold: **a rule decides what may be `execve`d, and an interpreter reached
//! through a `#!` line is decided by the script's own path, not by the interpreter's.** Under
//! `confine` that means a script is exactly as confined as the allowlist entry that let the *script*
//! run. Closing it needs the target's first two bytes read through a vouched probe (the shape the
//! open lens already walks) and the interpreter decided as well, on the stricter of the two verdicts;
//! that is not done today, and saying so is not the same as doing it.
//!
//! So a `deny` is a hard stop on the `execve` it names. What exec enforcement is *not* is a full
//! containment boundary: an agent can do harm **in-process** (in its own interpreter) without
//! `execve`ing at all, and an `allow`/`CONTINUE` re-runs the real syscall so *approving a specific
//! path* is TOCTOU-racy
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

/// How often the receive loop looks for a parked `execve` that has run out of time.
///
/// One tick of the loop's own poll slice. The sweep used to ride on the idle branch, which meant it
/// ran only when the cage had gone quiet — so the timeout was reliable exactly where nothing needed
/// releasing, and absent while a busy cage held the notification fd readable. Asking on a clock
/// instead of on idleness costs one registry lock per quarter-second at the very most, whatever the
/// cage does.
const SWEEP_EVERY: Duration = Duration::from_millis(250);

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
///
/// Its lock recovers from a poisoning panic (`sandbox::locks`), and it is the one site there whose
/// argument is not the module's: this is **live policy**, not a record kept for a reader, and a
/// verdict rendered against a rule list a panic left incomplete would be a `deny` the user believes
/// is in force and is not. Two things settle it. The list cannot be left incomplete: every mutation
/// is a `push` reached through operations that cannot unwind ([`ProcRule::new`] is total by its own
/// contract, and the read that precedes it only compares strings), so a poisoned overlay holds
/// exactly what a completed [`remember`](ProcOverlay::remember) put there. And the alternative is
/// worse in the direction that matters: [`decide`](ProcOverlay::decide) is taken on **every**
/// notified `execve`, so propagating the panic ends the supervisor thread, and a cage whose
/// supervisor has stopped deciding is one where no rule applies at all.
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
fn exec_verdict(
    cx: &Deciding<'_>,
    caller: &[String],
    pid: u32,
    dirfd: libc::c_int,
    addr: u64,
    notif: Option<(libc::c_int, u64)>,
) -> (Verdict, String) {
    let named = read_exec_path(pid, addr, notif)
        .filter(|p| !p.is_empty())
        // `execveat(fd, "", …, AT_EMPTY_PATH)` names its target by the descriptor and passes an
        // empty pathname — which is exactly what glibc's `fexecve` issues, so this is the ordinary
        // shape rather than an exotic one. The descriptor's own `/proc` link is the program, read in
        // the target's namespace like every other path here, so the policy gets a name to match
        // instead of the mode's unmatched default.
        .or_else(|| {
            (dirfd != libc::AT_FDCWD)
                .then(|| std::fs::read_link(format!("/proc/{pid}/fd/{dirfd}")).ok())
                .flatten()
                // `into_string` and not `to_string_lossy`, for the reason [`read_exec_path`] gives
                // about the path beside it: a link whose bytes no name can carry would arrive here
                // with each of them replaced, and the policy would decide — and the ring record —
                // a program that is not the one behind the descriptor.
                .and_then(|p| p.into_os_string().into_string().ok())
                .filter(|p| !p.is_empty())
        });
    if let Some(path) = named {
        // Folded to the spelling the kernel will resolve before either the decision or the record is
        // taken from it: the policy's own gate folds what it matches, and this is what keeps the
        // ring — the run's account of what was decided — showing the same path the rules were read
        // against, rather than the one a cage chose to write.
        let path = crate::proc_policy::lexical_path(&path).into_owned();
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

/// What the supervisor could make of the path a notified open named.
///
/// The two failures are answered differently, which is why they are told apart. See [`open_name`].
enum OpenName {
    /// A name this supervisor can carry, and so can resolve, scan and serve.
    Named(String),
    /// Nothing was read at all, so there is nothing to decide about. The lens allows these: it
    /// takes away what it can prove, and a cage whose undecidable opens all failed would not run.
    Unreadable,
    /// The path was read but is not a name this supervisor can carry (see [`read_exec_path`]), so it
    /// is refused rather than allowed — the one place the lens departs from "unreadable means
    /// allowed", because unlike a read that did not work this one is the cage's own choosing: a
    /// `rename` to a name with one non-UTF-8 byte costs it nothing and needs no read of the
    /// content, so allowing these would be a documented way around the scan rather than a hole in
    /// the supervisor's reach. Refusing is also what the cage already met — the substituted name
    /// resolved to nothing and the open was answered `ENOENT` — with the errno now saying which
    /// side refused it.
    Unusable,
}

/// The path an open asked for.
///
/// The read is where an unnameable open is counted, because it is the only step that knows it
/// happened: the decision downstream allows it, and this lens records the refusals it decided rather
/// than the decisions it could not take, so nothing afterwards would remember. Counted only where a
/// lens is armed — with none there was nothing to decide and nothing was given up, and a number on
/// those cages would be a number on a lens they never asked for.
fn open_name(
    cx: &Deciding<'_>,
    pid: u32,
    path_addr: u64,
    notif: Option<(libc::c_int, u64)>,
) -> OpenName {
    match read_path_bytes(pid, path_addr, notif) {
        Some(bytes) if !bytes.is_empty() => match String::from_utf8(bytes) {
            Ok(named) => return OpenName::Named(named),
            Err(_) => {
                // Once: a cage that keeps naming them would otherwise fill the session's output
                // with the same line, and it is the same line every time.
                if !UNNAMEABLE_OPEN_SAID.swap(true, Ordering::Relaxed) {
                    crate::diag::warn(
                        "an open named a path that is not valid UTF-8, and the content lens \
                         resolves, scans and serves by name — so it was refused rather than \
                         decided under a name with the bytes replaced, which would be a different \
                         file",
                    );
                }
                return OpenName::Unusable;
            }
        },
        // An empty pathname names no file; it is answered like a read that produced nothing.
        Some(_) | None => {}
    }
    if cx.open.is_some() && cx.undecidable.open.fetch_add(1, Ordering::Relaxed) == 0 {
        crate::diag::warn(
            "could not read the path an open asked for, so the content lens examined nothing and \
             the open was allowed. That read needs this supervisor to be the caller's ancestor; \
             where that does not hold, the lens examines nothing at all",
        );
    }
    OpenName::Unreadable
}

/// Set once an open has been refused for naming a path this supervisor cannot carry, so a cage that
/// keeps doing it pays one line for the session rather than one per open.
static UNNAMEABLE_OPEN_SAID: AtomicBool = AtomicBool::new(false);

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
    close_supervision(notif_fd, cx.pending);
}

/// End supervision: deny everything still parked, then close the notification descriptor.
///
/// Draining first is what gives a target parked at teardown a verdict from sbx rather than none:
/// `deny`, the same answer the sweep gives a decision that ran out of time, and the only
/// fail-closed one. The loop can return with entries still in the registry — on stop, or when the
/// cage's filter goes away with a decision outstanding — and each of them holds a process.
///
/// The order is *not* what keeps an entry from answering through a descriptor that no longer
/// exists, which is what this comment used to claim: [`PendingExec::answer`] takes an entry out of
/// the registry and answers it after releasing the lock, so a control thread already past the
/// `remove` finds nothing here to drain and is unaffected by any order this function could keep.
/// What settles it is that the entry answers through its own `dup` ([`Parked::notif_fd`]).
fn close_supervision(notif_fd: libc::c_int, pending: &PendingExec) {
    pending.answer_all(false);
    // SAFETY: notif_fd is our owned descriptor from recv_fd, closed exactly once here. Every parked
    // entry answers through a dup of its own, so this close cannot land under one mid-answer.
    unsafe { libc::close(notif_fd) };
}

/// Poll the listening socket in short slices (honouring `stop`), accept a connection, and receive
/// the listener fd it sends. Returns `None` if stopped first.
///
/// A connection that does not hand over a notification listener does **not** end the wait. The
/// socket is reachable from inside the cage, so the first connection is not necessarily the shim's,
/// and treating a bad handoff as the end of the story would let anything in the cage refuse its own
/// launch by connecting first. Refused and announced, the loop goes back to waiting, and the shim —
/// which retries its connect for a second — is still served. What this does not defend against is a
/// caller that floods the backlog for the whole of that second; that is a different bound, and not
/// one a check on the descriptor can supply.
fn accept_handoff(listener: &UnixListener, stop: &AtomicBool) -> Option<libc::c_int> {
    use std::os::unix::io::AsRawFd;
    let mut announced = false;
    while !stop.load(Ordering::Relaxed) {
        if !poll_readable(listener.as_raw_fd(), 250) {
            continue;
        }
        match listener.accept() {
            Ok((stream, _)) => match recv_fd(&stream) {
                Ok(fd) => return Some(fd),
                Err(why) => {
                    // Once: a caller that keeps trying would otherwise fill the session's output
                    // with the same line, and the first is the one that says something new.
                    if !announced {
                        announced = true;
                        crate::diag::warn(&format!(
                            "exec supervision: a connection to the handoff socket was refused \
                             ({why}); still waiting for the shim's"
                        ));
                    }
                    continue;
                }
            },
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
///
/// The expiry sweep runs on the loop itself, not on its idle branch. It sat on the idle branch,
/// which reads as "there is nothing else to do, so tidy up" and is wrong for the one thing the sweep
/// is for: a cage that keeps the notification fd busy never lets the poll time out, so
/// [`ASK_TIMEOUT`] never fires and the parked `execve` the timeout exists to release waits for a
/// human indefinitely. A process tree `execve`ing in a loop is enough to hold it there, and a cage
/// with a parked ancestor has every reason to. Paid once per [`SWEEP_EVERY`] rather than per
/// notification, so a hot loop still costs one registry lock per tick.
fn recv_loop(notif_fd: libc::c_int, stop: &AtomicBool, cx: &Deciding<'_>) {
    let mut last_sweep = Instant::now();
    while !stop.load(Ordering::Relaxed) {
        if last_sweep.elapsed() >= SWEEP_EVERY {
            cx.pending.sweep();
            last_sweep = Instant::now();
        }
        // The hang-up is asked of the poll rather than inferred from a failed receive. `POLLHUP` on
        // the listener is the kernel's own statement that no task behind the filter is left, which
        // is the condition that ends supervision; an errno is not, and reading one as a hang-up is
        // what used to end it early. Anything readable is taken first, so a notification pending
        // alongside the hang-up is still decided before the loop leaves.
        let events = poll_events(notif_fd, 250);
        if events & libc::POLLIN == 0 {
            // A descriptor that can no longer be polled ends the loop too: there is nothing left to
            // receive from, and re-polling it would spin. A kernel that reports no hang-up simply
            // keeps the loop polling until the teardown sets `stop`.
            if events & (libc::POLLHUP | libc::POLLERR | libc::POLLNVAL) != 0 {
                return;
            }
            continue;
        }
        let mut req: libc::seccomp_notif = unsafe { std::mem::zeroed() };
        // SAFETY: req is a live, correctly-sized seccomp_notif for the RECV ioctl to fill.
        // `ioctl`'s request argument is `c_ulong` on glibc but `c_int` on musl, so cast the
        // 32-bit request code to whichever the target libc expects (the shipping binary is musl).
        let rc = unsafe { libc::ioctl(notif_fd, notif_recv_code() as libc::Ioctl, &mut req) };
        if rc < 0 {
            let e = io::Error::last_os_error().raw_os_error().unwrap_or(0);
            if recv_ends_supervision(e) {
                return;
            }
            continue;
        }
        handle_notif(notif_fd, &req, cx);
    }
}

/// Whether a failed `SECCOMP_IOCTL_NOTIF_RECV` describes the end of supervision, or only the one
/// notification that was not there.
///
/// `ENOENT` is per-notification and not per-listener. `seccomp_unotify(2)` gives it when the kernel
/// woke this thread for a request that is no longer in `SECCOMP_NOTIFY_INIT` state — the target was
/// killed by a signal between the wake and the notification lock, so its request is gone while the
/// listener is untouched and the next receive serves the next `execve`. Read as a hang-up, it ended
/// the whole run's supervision on one process reaped at the wrong instant: everything parked is
/// denied, the descriptor is closed, and from then on the cage's filter answers every notified
/// `execve` — and, under `[fs] scan`, every notified open — with `ENOSYS`. Fail-closed, and fatal
/// to the session.
///
/// `EINTR` is the same story with a signal in place of the reap. What does end supervision is a
/// descriptor that cannot be received from at all (`EBADF`, `ENOTTY`); the cage's filter going away
/// is recognised in [`recv_loop`] by the hang-up the poll reports, which is the kernel's own
/// statement of it.
fn recv_ends_supervision(e: libc::c_int) -> bool {
    !matches!(e, libc::EINTR | libc::ENOENT)
}

/// Decide one notified `execve` and answer it. The path is read from the parked target's memory; an
/// unreadable path (an anomaly under the ancestor invariant) is treated as unmatched — never a
/// silent deny that could brick the whole cage, and never a silent allow of a named `deny`.
fn handle_notif(notif_fd: libc::c_int, req: &libc::seccomp_notif, cx: &Deciding<'_>) {
    // A live notification, asked before any of the target's `/proc` is read. This one is an
    // early-out — it saves the work when the target is already gone. The *guard* against reading a
    // stranger's memory is the second check, taken after `/proc/<pid>/mem` is opened: see
    // [`open_target_mem`], which is where the ordering that makes it a proof lives.
    if !notif_id_valid(notif_fd, req.id) {
        return;
    }
    // The open family is decided by *content* and answered here, never falling through to the exec
    // policy below — which reads a different argument and would judge an open against exec rules.
    // Checked on the syscall number rather than on the lens being present, so a notification the
    // filter should not have produced is still answered as an open.
    if let Some((dirfd, path_addr)) = open_args(req.data.nr, &req.data.args) {
        let named = match open_name(cx, req.pid, path_addr, notif_of(notif_fd, req.id)) {
            OpenName::Named(named) => named,
            // Nothing read: the empty name falls through to the allowing arm below, which is what
            // the lens does with an open it could not examine.
            OpenName::Unreadable => String::new(),
            // Read, and not a name this supervisor can act on. Answered here rather than allowed —
            // see [`OpenName::Unusable`].
            OpenName::Unusable => {
                respond_errno(notif_fd, req.id, libc::EACCES);
                return;
            }
        };
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
                        // Made and then unmade: nothing was handed over and the name is as the open
                        // found it, so the real syscall runs and creates it for itself. `CONTINUE`
                        // rather than the ordinary decision, which would answer `EEXIST` for the
                        // file this supervisor had just made and removed.
                        Creation::Unmade => {
                            respond_continue(notif_fd, req.id);
                            return;
                        }
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
    // The exec family, read from its own registers for the reason [`exec_args`] states. A
    // notification that is neither an open nor an exec is refused rather than judged: the shim's
    // filter produces only these five numbers, so a sixth means the filter and this supervisor
    // disagree about what is being supervised, and the module's fail-closed doctrine says an
    // unenforced call must not run in place of an enforced one.
    let Some((exec_dirfd, path_addr)) = exec_args(req.data.nr, &req.data.args) else {
        respond_errno(notif_fd, req.id, libc::EPERM);
        return;
    };
    let caller = caller_chain(cx, req.pid);
    let (verdict, shown) = exec_verdict(
        cx,
        &caller,
        req.pid,
        exec_dirfd,
        path_addr,
        notif_of(notif_fd, req.id),
    );
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

/// Whether `fd` is a seccomp notification listener at all — asked of the kernel, not assumed.
///
/// The handoff socket is bound read-write into the cage, so whatever connects to it first is who
/// the supervisor hears from, and that need not be the shim. A descriptor that is not a listener
/// makes the first `NOTIF_RECV` fail and takes the whole launch with it, which is a refusal the
/// cage can trigger against itself; refused here instead, while the answer is still "that handoff
/// was not the shim's".
///
/// `ID_VALID` is the question that can be asked without consequence. `NOTIF_RECV` — the obvious
/// probe, and the one this reading of the code first reached for — **blocks** on a listener with
/// nothing pending, so probing with it would hang the supervisor on the ordinary path. Ids are
/// drawn from a counter that starts at one, so zero is never pending: a listener answers `ENOENT`
/// and anything else answers `ENOTTY`. A `0` return is accepted too rather than treated as
/// impossible — it would still mean the fd answered the seccomp ioctl.
fn is_notif_listener(fd: libc::c_int) -> bool {
    let id: u64 = 0;
    // SAFETY: passes the address of a live local to the ID_VALID ioctl, which only reads it.
    let rc = unsafe { libc::ioctl(fd, notif_id_valid_code() as libc::Ioctl, &id as *const u64) };
    rc == 0 || io::Error::last_os_error().raw_os_error() == Some(libc::ENOENT)
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
    let Some(flags) = open_flags(
        req.pid,
        req.data.nr,
        &req.data.args,
        notif_of(notif_fd, req.id),
    ) else {
        return false;
    };
    let flags = flags as libc::c_int;
    // `O_TMPFILE` names a directory and asks for a new unnamed inode under it. There is no existing
    // file to serve, and the probe is not it.
    if flags & libc::O_TMPFILE == libc::O_TMPFILE {
        return false;
    }
    // An `openat2` may ask for a stricter walk than the one this supervisor performed: the probe
    // follows symlinks on purpose (a scan that stopped at a link would be walked around with one
    // `ln -s`), so serving from it would hand a caller that asked for `RESOLVE_NO_SYMLINKS` the
    // descriptor its own restriction was meant to refuse. The verdict is unaffected — the lens
    // judged the resolved target either way, and this is only reached for an open it permitted —
    // but a program inside the cage that hardened its own path walk must not have that hardening
    // quietly removed by being supervised. So the call is declined here and answered `CONTINUE`,
    // which runs the real `openat2` with the real `resolve` semantics; it joins the other flags
    // that cannot be carried onto a descriptor.
    match open_resolve(
        req.pid,
        req.data.nr,
        &req.data.args,
        notif_of(notif_fd, req.id),
    ) {
        Some(0) => {}
        _ => return false,
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
    // The final component's **type** is what settles it, asked with `lstat`. Asking instead whether
    // an `O_PATH | O_NOFOLLOW` open fails answers nothing: `open(2)` is explicit that the pair
    // *succeeds* on a symlink and hands back a descriptor referring to the link itself, so the one
    // case this guard exists to catch took the success path and the cage was served the probe —
    // which names the link's target. A program that opened its own log with `O_NOFOLLOW`, the
    // standard defence against having a file swapped for a link, had that defence removed by being
    // supervised. It is the same rule the `openat2` `resolve` check above states: a program that
    // hardened its own path walk must not have the hardening quietly dropped.
    //
    // Re-walking the path is a second resolution, and the cage may have moved it since. The two
    // outcomes of losing that race are a spurious `ELOOP` and serving the inode that was scanned —
    // never an open the lens did not examine, which is the property being defended.
    if flags & libc::O_NOFOLLOW != 0 {
        // Except with `O_PATH`, where the pair is not a refusal at all: the kernel answers it with a
        // descriptor for the link itself, which is neither `ELOOP` nor the inode the probe holds. It
        // joins the flags that cannot be carried onto a descriptor, and the real call runs.
        if flags & libc::O_PATH != 0 {
            return false;
        }
        let target = open_target_path(req.pid, dirfd, path);
        match std::fs::symlink_metadata(&target) {
            Ok(meta) if meta.file_type().is_symlink() => {
                respond_errno(notif_fd, req.id, libc::ELOOP);
                return true;
            }
            Ok(_) => {}
            // The path no longer resolves from here, which is the race above rather than a link.
            // Answered `ELOOP` all the same: the cage asked for the stricter walk, and the stricter
            // of the two answers is the one that cannot serve an inode this call did not establish.
            Err(_) => {
                respond_errno(notif_fd, req.id, libc::ELOOP);
                return true;
            }
        }
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
    /// The name is there after all — put there by someone else while this was being decided — so
    /// the ordinary decision applies to it.
    Exists,
    /// The file was made, could not be handed over, and has been taken away again, leaving the
    /// name as the open found it. Nothing was answered, and the real syscall has to run.
    Unmade,
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
        open_flags(
            req.pid,
            req.data.nr,
            &req.data.args,
            notif_of(notif_fd, req.id),
        ),
        open_mode(
            req.pid,
            req.data.nr,
            &req.data.args,
            notif_of(notif_fd, req.id),
        ),
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
        return Creation::Served;
    }
    // The file was made but could not be handed over — the kernel has no `ADDFD_SEND`, or this one
    // notification could not take it. Leaving it there and falling into the ordinary decision was
    // the shape this had, and it answered `EEXIST` to an `O_CREAT|O_EXCL` open: the second pass
    // finds a file that is there, and `serve_open` reports the exclusivity failure the caller asked
    // to be told about — for a file the supervisor itself had just created a line earlier. The cage
    // is then told a name it holds exclusively is taken, which is the one answer it acts on.
    //
    // So the creation is undone and the syscall left to run for real. `O_EXCL` proved the file was
    // this call's when it was made, and it has been open and empty ever since.
    // SAFETY: parent is a live directory descriptor and cbase a live NUL-terminated name.
    unsafe { libc::unlinkat(parent.as_raw_fd(), cbase.as_ptr(), 0) };
    Creation::Unmade
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

/// The notification a memory read is guarded by, or `None` when the caller holds none.
///
/// A negative descriptor is how a caller says "no notification in hand" — the unit tests that drive
/// one arm of a decision directly, without a listener. Passing it through as a real pair would make
/// [`open_target_mem`]'s check fail on `EBADF` and read as "the target is gone", turning the guard
/// into a refusal of every such call.
fn notif_of(notif_fd: libc::c_int, id: u64) -> Option<(libc::c_int, u64)> {
    (notif_fd >= 0).then_some((notif_fd, id))
}

/// Open a target's memory, and confirm afterwards that it is still the target's.
///
/// The order is the point, and it is what `seccomp_unotify(2)` prescribes: open first, then re-check
/// the notification id. A pid is only free to be reused once its process is gone, and a notification
/// id stays valid only while its target is parked in the syscall — so an id still valid *after* the
/// open proves the target never left, which proves the number was never free, which proves this
/// descriptor is the target's memory and not a stranger's.
///
/// Checking before the open cannot give that: the two are separate steps, and a target killed in
/// between can have its number reissued under the read. Nothing catastrophic followed (the kernel
/// refuses every answer to a gone target's id, so a verdict formed on a stranger's memory reaches no
/// process) — but a refusal line naming another process's path is still a wrong record, and reading
/// an unrelated process's memory at all is worth not doing.
///
/// `notif` is `None` for a caller with no notification in hand — the unit tests, which read this
/// process's own memory.
fn open_target_mem(pid: u32, notif: Option<(libc::c_int, u64)>) -> Option<std::fs::File> {
    let file = std::fs::File::open(format!("/proc/{pid}/mem")).ok()?;
    if let Some((notif_fd, id)) = notif
        && !notif_id_valid(notif_fd, id)
    {
        return None;
    }
    Some(file)
}

/// Read one `u64` from a target's memory. `openat2` passes its flags behind a pointer rather than in
/// a register, and that word has to be read the same careful way the path is.
fn read_u64(pid: u32, addr: u64, notif: Option<(libc::c_int, u64)>) -> Option<u64> {
    use std::io::{Read, Seek, SeekFrom};
    let mut file = open_target_mem(pid, notif)?;
    file.seek(SeekFrom::Start(addr)).ok()?;
    let mut buf = [0u8; 8];
    file.read_exact(&mut buf).ok()?;
    Some(u64::from_ne_bytes(buf))
}

/// The smallest `struct open_how` the kernel will accept from an `openat2` caller.
///
/// `openat2(dirfd, path, how, size)` refuses a `size` below this outright — `EINVAL`, before the
/// path is looked at — because the struct's first version is already three words long and there is
/// no shorter one to read. The three readers below therefore treat a short `size` as a call they
/// cannot establish anything about, rather than reading the words that *are* there: what they would
/// establish belongs to a syscall that never runs.
///
/// This is the ABI's own number and not a guess at it. `size_of::<libc::open_how>()` agrees today
/// and is asserted to, but the constant is the contract: a later kernel that grows the struct grows
/// the type with it, while the minimum the kernel accepts stays where it is.
const OPEN_HOW_VER0: u64 = 24;

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
fn open_flags(
    pid: u32,
    nr: libc::c_int,
    args: &[u64; 6],
    notif: Option<(libc::c_int, u64)>,
) -> Option<u64> {
    if nr as libc::c_long == libc::SYS_open {
        return Some(args[1]);
    }
    if nr as libc::c_long == libc::SYS_openat {
        return Some(args[2]);
    }
    if nr as libc::c_long == libc::SYS_openat2 {
        // `struct open_how { __u64 flags; __u64 mode; __u64 resolve; }`. Only the first word is
        // wanted, but a call whose `size` is short of the whole struct is one the kernel refuses
        // ([`OPEN_HOW_VER0`]) — so there are no flags to establish, whatever sits at that address.
        if args[3] < OPEN_HOW_VER0 {
            return None;
        }
        return read_u64(pid, args[2], notif);
    }
    None
}

/// The mode a creating open asks its file to land with, read from wherever its own ABI puts it.
///
/// The mirror of [`open_flags`], and needed for the same reason: a file made on the cage's behalf
/// has to arrive with the permissions the cage asked for rather than with a guess.
fn open_mode(
    pid: u32,
    nr: libc::c_int,
    args: &[u64; 6],
    notif: Option<(libc::c_int, u64)>,
) -> Option<u64> {
    if nr as libc::c_long == libc::SYS_open {
        return Some(args[2]);
    }
    if nr as libc::c_long == libc::SYS_openat {
        return Some(args[3]);
    }
    if nr as libc::c_long == libc::SYS_openat2 {
        // `struct open_how { __u64 flags; __u64 mode; __u64 resolve; }`. The mode is the second
        // word — and, as for the flags, a `size` short of the whole struct describes a call the
        // kernel refuses before it reads any of it ([`OPEN_HOW_VER0`]).
        if args[3] < OPEN_HOW_VER0 {
            return None;
        }
        return read_u64(pid, args[2].wrapping_add(8), notif);
    }
    None
}

/// The `resolve` word of an `openat2`, which names path-walk restrictions the caller wants the
/// kernel to enforce (`RESOLVE_NO_SYMLINKS`, `RESOLVE_BENEATH`, `RESOLVE_IN_ROOT`,
/// `RESOLVE_NO_MAGICLINKS`, `RESOLVE_NO_XDEV`). `Some(0)` for the two older forms, which have no
/// such word and therefore ask for no restriction.
///
/// The third word of `struct open_how`, and read for the same reason its siblings are: a caller
/// that asked for a stricter walk than the supervisor performed must not be handed the result of
/// the looser one.
///
/// `None` means it could not be established, which — like an unreadable flag word — is a call that
/// must not be served from a descriptor.
fn open_resolve(
    pid: u32,
    nr: libc::c_int,
    args: &[u64; 6],
    notif: Option<(libc::c_int, u64)>,
) -> Option<u64> {
    if nr as libc::c_long == libc::SYS_open || nr as libc::c_long == libc::SYS_openat {
        return Some(0);
    }
    if nr as libc::c_long == libc::SYS_openat2 {
        // `struct open_how { __u64 flags; __u64 mode; __u64 resolve; }`. A `size` short of the
        // third word was read here as a call asking for no restriction, on the reasoning that the
        // kernel reads a missing tail as zero. It does not: `copy_struct_from_user` zero-fills a
        // struct the *caller* is older than, but `openat2` refuses anything shorter than the first
        // version outright ([`OPEN_HOW_VER0`]). Answering `Some(0)` therefore served a descriptor
        // for a syscall that was never going to run, from a `resolve` word nobody had established.
        if args[3] < OPEN_HOW_VER0 {
            return None;
        }
        return read_u64(pid, args[2].wrapping_add(16), notif);
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
/// notification id and a descriptor of its own to answer it through, so the control plane
/// (`sbx proc allow`/`deny`) and the timeout sweeper can respond out-of-band while the receive loop
/// keeps draining the next notification. Shared (via `Arc`) between the supervisor thread and the
/// control serve thread.
pub(crate) struct PendingExec {
    inner: Mutex<BTreeMap<u64, Parked>>,
}

struct Parked {
    id: u64,
    /// This entry's **own** `dup` of the notification descriptor, closed when the entry is dropped.
    ///
    /// Not the supervisor's number, which is the shape this had and which the teardown order alone
    /// cannot save. `answer` takes an entry out of the registry and only then answers it, so a
    /// control thread can be between those two steps at the moment [`close_supervision`] drains the
    /// registry (finding it already empty) and closes the descriptor — after which the answer is an
    /// `ioctl` on a number this process may since have reissued to something else entirely. The
    /// `dup` is the same fix [`park_open`] makes for an open answered from its own thread, and it
    /// also keeps the kernel's listener alive for exactly as long as something can still answer
    /// through it.
    ///
    /// An [`OwnedFd`](std::os::fd::OwnedFd) and not a raw number, so the close rides on the entry
    /// leaving the registry however it leaves — answered, swept, or dropped with the map — and the
    /// rest of the entry stays movable out of it.
    notif_fd: std::os::fd::OwnedFd,
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
    ///
    /// The path is sanitised on the way in, for the reason
    /// [`super::proc_control::ExecRing::push_verdict`] states about the ring beside it: this registry
    /// is the **third** producer on that same line-based control wire, and it was the one written
    /// apart. `dispatch_enforced` renders these as `pending id=… pid=… path={path}` and
    /// `answered path={path}`, while the client reads the reply with `.lines()` and stops at the
    /// first bare `ok` — so a newline in a target the cage named (paths may carry one, and this one
    /// is read out of the cage's own memory) ends the row early and lets what follows read as
    /// another. A cage could hide a park behind a forged one, or paint rows the operator never had.
    /// Sanitising is idempotent, so the ring's copy of the same string is unaffected; the verdict
    /// itself was reached on the raw path, above.
    fn park(&self, notif_fd: libc::c_int, id: u64, pid: u32, path: &str) {
        use std::os::unix::io::FromRawFd;
        let path = super::sanitize(path);
        // SAFETY: notif_fd is the supervisor's live notification descriptor; the copy belongs to the
        // entry below, which closes it. See [`Parked::notif_fd`] for why the entry does not simply
        // keep the supervisor's number.
        let own_fd = unsafe { libc::dup(notif_fd) };
        if own_fd < 0 {
            // A park that cannot be answered later is not a park. Refused now, fail-closed, rather
            // than registered against a descriptor nobody can respond through.
            respond_errno(notif_fd, id, libc::EPERM);
            return;
        }
        // SAFETY: own_fd is a fresh owned descriptor; the OwnedFd takes sole ownership of it.
        let own_fd = unsafe { std::os::fd::OwnedFd::from_raw_fd(own_fd) };
        let entry = Parked {
            id,
            notif_fd: own_fd,
            pid,
            path,
            since: Instant::now(),
        };
        {
            let mut g = locked(&self.inner);
            if g.len() < ASK_PENDING_CAP {
                g.insert(id, entry);
                return;
            }
        }
        // Over the cap: `entry` was never inserted, so its `dup` is closed as it drops here.
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
    /// never hangs a process tree. Called once per [`SWEEP_EVERY`] by the receive loop — on the
    /// clock and not on the loop being idle, because a busy cage is exactly the case where a parked
    /// ancestor needs releasing and exactly the case an idle branch never reaches.
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
    use std::os::unix::io::AsRawFd;
    let fd = p.notif_fd.as_raw_fd();
    if !notif_id_valid(fd, p.id) {
        return;
    }
    if allow {
        respond_continue(fd, p.id);
    } else {
        respond_errno(fd, p.id, libc::EPERM);
    }
}

/// Read a NUL-terminated path from a parked target's memory at `addr`, as the bytes it is. The
/// notified *thread* is blocked in the `execve`, so the pointer is valid to read — but only that
/// thread is stopped: a sibling in the cage can rewrite the buffer between this read and the
/// `CONTINUE`, which is why allowing a named path is TOCTOU-racy while refusing one is not (module
/// header). Nothing here closes that window. Returns `None` on any read failure.
fn read_path_bytes(pid: u32, addr: u64, notif: Option<(libc::c_int, u64)>) -> Option<Vec<u8>> {
    use std::io::Read;
    let mut file = open_target_mem(pid, notif)?;
    // Seek and read a bounded window; a path is at most PATH_MAX.
    use std::io::{Seek, SeekFrom};
    file.seek(SeekFrom::Start(addr)).ok()?;
    let mut buf = [0u8; 4096];
    let n = file.read(&mut buf).ok()?;
    if n == 0 {
        return None;
    }
    let end = buf[..n].iter().position(|&b| b == 0).unwrap_or(n);
    Some(buf[..end].to_vec())
}

/// The same read, as a name this supervisor can carry — or `None` where it cannot.
///
/// `from_utf8` and not `from_utf8_lossy`, for the reason [`caller_chain`] gives about the program
/// that issued the call: a Linux path is bytes and every byte the encoding cannot carry becomes the
/// same replacement character, so what came back was a **different name** from the one the cage
/// wrote. That name was then matched against the policy, and — under the open lens — resolved,
/// scanned, served and created: measured, an `open` of a file whose name carries one non-UTF-8 byte
/// had the supervisor walk to a path that does not exist, and a *creating* one of the same shape
/// would have made a file under the substituted name and handed the cage its descriptor. A name
/// that cannot be carried is not a name, and joins the reads that did not work.
///
/// Carrying the bytes end to end would be better still — such a path would then be scanned like any
/// other rather than refused — but it is the whole resolution chain (`open_target_path`,
/// `caller_proc_path`, `splice_first_link`, `serve_creation`) plus the `String` keys
/// [`ProcPolicy`] matches on, and this is the half that stops a wrong file being acted on.
fn read_exec_path(pid: u32, addr: u64, notif: Option<(libc::c_int, u64)>) -> Option<String> {
    String::from_utf8(read_path_bytes(pid, addr, notif)?).ok()
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

/// Where a notified exec keeps its directory descriptor and its path pointer, by syscall number —
/// the exec half of the mapping [`open_args`] states for the open family, and for the same reason.
///
/// The shim notifies on **both** exec forms (`proc-shim`'s filter names `execve` and `execveat`),
/// and they do not agree on argument order: `execve(path, argv, envp)` leads with the path, while
/// `execveat(dirfd, path, argv, envp, flags)` leads with a descriptor. Reading the path from the
/// wrong register does not merely scan an unrelated address here — it makes the target unnameable,
/// and an unnameable target is decided by [`ProcPolicy::unmatched`], which under the shipped
/// `enforce` denylist is `Allow`. Every `execveat` therefore used to walk past a `deny` rule that
/// named it. The mapping is explicit and unit-tested rather than inferred at the call site.
///
/// `None` for any other syscall: the receive loop answers such a notification fail-closed rather
/// than judging it as an exec against a register that means something else.
fn exec_args(nr: libc::c_int, args: &[u64; 6]) -> Option<(libc::c_int, u64)> {
    if nr as libc::c_long == libc::SYS_execve {
        return Some((libc::AT_FDCWD, args[0]));
    }
    if nr as libc::c_long == libc::SYS_execveat {
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
                path: super::sanitize(path),
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
            path: super::sanitize(path),
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
    /// The name the cage asked for, **sanitised** on the way in — for the reason
    /// [`PendingExec::park`] states about the registry beside it, and it was this producer's turn to
    /// be written apart. This string is read out of the cage's own memory, a Linux path may carry a
    /// newline or an escape sequence, and both report sites put it on a `diag::warn` line that
    /// reaches the operator's terminal and the session log `sbx logs` reads. A cage could otherwise
    /// paint whole lines of its own there — a refusal that never happened, or an escape run that
    /// hides the one that did. Sanitising is idempotent and the verdict was reached on the raw path
    /// above, so nothing but the rendering changes.
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

/// Poll a descriptor for input with a millisecond timeout and return what the kernel reported.
///
/// The events themselves and not a verdict on them, because the receive loop has to tell two of them
/// apart: `POLLIN` is a notification to decide, while `POLLHUP` on a seccomp listener is the kernel
/// saying no task behind that filter is left — the one sound signal that supervision is over. A
/// caller that only asks "is there something to read" cannot distinguish them and has to infer the
/// hang-up from an errno instead, which is how a single vanished notification once ended a run's
/// supervision.
///
/// `0` for a timeout, and for a poll error too, so a caller re-checks its stop flag rather than
/// spinning.
fn poll_events(fd: libc::c_int, timeout_ms: libc::c_int) -> libc::c_short {
    let mut pfd = libc::pollfd {
        fd,
        events: libc::POLLIN,
        revents: 0,
    };
    // SAFETY: pfd is a single live pollfd.
    let rc = unsafe { libc::poll(&mut pfd, 1, timeout_ms) };
    if rc > 0 { pfd.revents } else { 0 }
}

/// Poll a descriptor for readability with a millisecond timeout. `true` = readable (or hung up, so a
/// following read observes the end), `false` = timed out.
fn poll_readable(fd: libc::c_int, timeout_ms: libc::c_int) -> bool {
    poll_events(fd, timeout_ms) != 0
}

/// A control buffer for exactly one `SCM_RIGHTS` cmsg, **aligned for a `cmsghdr`**.
///
/// A `[u8; N]` is byte-aligned and `cmsghdr` is not: `CMSG_FIRSTHDR` hands the buffer back as a
/// `*mut cmsghdr`, so every field access through it is only defined if the storage is aligned for
/// one. A bare local array is aligned in practice on the targets sbx builds for, and "in practice"
/// is not what the rule says — the union ties the alignment to the type itself rather than to a
/// number that would have to be kept right.
#[repr(C)]
union CmsgBuf {
    bytes: [u8; 32], // >= CMSG_SPACE(size_of::<c_int>())
    _align: libc::cmsghdr,
}

impl CmsgBuf {
    fn zeroed() -> Self {
        Self { bytes: [0u8; 32] }
    }

    /// The buffer as bytes, for `msg_control`. Reading the `bytes` arm is sound whatever was last
    /// written: every arm is plain data with no padding to leave uninitialised.
    fn as_mut_ptr(&mut self) -> *mut libc::c_void {
        // SAFETY: `bytes` covers the whole union and every byte of it is initialised.
        unsafe { self.bytes.as_mut_ptr() as *mut libc::c_void }
    }

    fn len(&self) -> usize {
        std::mem::size_of::<Self>()
    }
}

/// Receive one file descriptor sent over a Unix stream as an `SCM_RIGHTS` ancillary message, and
/// confirm it is a seccomp notification listener before handing it back.
fn recv_fd(stream: &UnixStream) -> io::Result<libc::c_int> {
    let fd = recv_fd_raw(stream)?;
    if !is_notif_listener(fd) {
        // SAFETY: `fd` is ours from `recv_fd_raw` and is closed exactly once here.
        unsafe { libc::close(fd) };
        return Err(io::Error::other(
            "the handoff carried a descriptor that is not a seccomp notification listener",
        ));
    }
    Ok(fd)
}

/// The receive itself, with no opinion about what the descriptor is.
///
/// Split out from [`recv_fd`] so the close-on-exec property below can be asserted against any
/// descriptor — the listener check needs a live seccomp filter, which means a cage, which means a
/// test that skips on the hosted runner. A guard whose test does not run where it ships is the
/// shape of guard this tree already had to go looking for once.
///
/// **`MSG_CMSG_CLOEXEC`**, and it is the whole point of the flag argument. A descriptor arriving
/// through `SCM_RIGHTS` is an ordinary one: without this it lands with `FD_CLOEXEC` clear and is
/// then inherited by every process the supervisor goes on to `fork`+`exec` — nix, bwrap, and the
/// third-party programs a broker or a signer plugin runs. What leaks is the seccomp **notification
/// listener**, so a process holding it can answer the cage's `execve` notifications itself, which is
/// the whole of exec enforcement. Setting it after the fact would leave a window; the flag makes it
/// atomic with the receive.
fn recv_fd_raw(stream: &UnixStream) -> io::Result<libc::c_int> {
    use std::os::unix::io::AsRawFd;
    let mut dummy = [0u8; 1];
    let mut iov = libc::iovec {
        iov_base: dummy.as_mut_ptr() as *mut libc::c_void,
        iov_len: 1,
    };
    let mut cbuf = CmsgBuf::zeroed();
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = cbuf.as_mut_ptr();
    msg.msg_controllen = cbuf.len() as _;
    // SAFETY: msg's buffers are live and the control one is aligned for a `cmsghdr` ([`CmsgBuf`]);
    // we read exactly one cmsg carrying one fd.
    unsafe {
        let n = libc::recvmsg(stream.as_raw_fd(), &mut msg, libc::MSG_CMSG_CLOEXEC);
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
mod open_path_tests;

#[cfg(test)]
mod tests;
