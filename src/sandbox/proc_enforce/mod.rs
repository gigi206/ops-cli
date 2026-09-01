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
//! prescribes: **open the handle, then validate, then read** ([`target::open_target_mem`]).
//! Validating only *before* the open proves nothing, because the two are separate steps — the
//! target can be killed and its number handed to a fresh process in between. Validating after does
//! prove it: a pid is free to be reused only once its process is gone, and a notification id stays
//! valid only while its target is parked, so an id still valid after the open says the target never
//! left, which says the number was never free, which says the descriptor is the target's.
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

use std::ffi::OsString;
use std::io;
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::JoinHandle;
use std::time::Instant;

use super::binds::ExtraBind;
use super::proc_control::ExecRing;
use crate::proc_policy::{ProcPolicy, Verdict};

mod cagepath;
mod notify;
mod open_lens;
mod open_serve;
mod overlay;
mod pending;
mod report;
mod target;

pub(crate) use overlay::ProcOverlay;
pub(crate) use pending::PendingExec;

use notify::{
    notif_id_valid, notif_of, notif_recv_code, poll_events, poll_readable, recv_fd,
    respond_continue, respond_errno,
};
use open_lens::{OpenLens, handle_open};
use pending::SWEEP_EVERY;
use report::{Undecidable, unmatched_word};
use target::{exec_args, open_args, read_exec_path};

/// Where the exec shim is bound read-only inside the cage, and where the notification handoff
/// socket appears. Both under `/opt/sbx`, beside the egress CA — a path the cage cannot reach outside
/// of these binds.
pub(super) const SHIM_CAGE_PATH: &str = "/opt/sbx/proc-shim";
const NOTIF_SOCK_CAGE_PATH: &str = "/opt/sbx/proc-notif.sock";

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
/// What settles it is that the entry answers through its own `dup` ([`pending::Parked::notif_fd`]).
fn close_supervision(notif_fd: libc::c_int, pending: &PendingExec) {
    pending.answer_all(false);
    // SAFETY: notif_fd is our owned descriptor from recv_fd, closed exactly once here. Every parked
    // entry answers through a dup of its own, so this close cannot land under one mid-answer.
    unsafe { libc::close(notif_fd) };
}

/// How long an accepted handoff may say nothing before it is treated as refused.
///
/// Chosen against the shim's own patience rather than against a clock: the shim retries its connect
/// for a second, so a bound comfortably under that leaves a real handoff room to be served on a
/// later pass, while a real one never approaches it — the descriptor is written immediately after
/// `connect` over a unix socket on the same host.
///
/// **The limit, stated because it is not the same bound as the one above.** This ends a *single*
/// silent connection; it does not stop a caller that opens one after another, each costing this
/// much. That is the backlog flood the paragraph above names, and it needs a concurrent accept
/// rather than a deadline. What is closed here is the permanent case, where one connection ended
/// supervision for the whole session.
const HANDOFF_SILENCE: std::time::Duration = std::time::Duration::from_millis(500);

/// Whether an accepted handoff has anything to read within [`HANDOFF_SILENCE`], polled in the same
/// slices the accept loop uses so `stop` keeps being read.
fn handoff_speaks(fd: libc::c_int, stop: &AtomicBool) -> bool {
    let deadline = Instant::now() + HANDOFF_SILENCE;
    while !stop.load(Ordering::Relaxed) {
        if poll_readable(fd, 100) {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
    }
    false
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
///
/// Nor does a connection that says **nothing** end it. `recv_fd` has no deadline of its own, and an
/// accepted socket does not inherit the listener's `O_NONBLOCK` on Linux, so a cage process that
/// connected and then held its peace parked this loop in `recvmsg` for the life of the session:
/// `stop` was never read again, and the shim's own handoff was never accepted, so exec supervision
/// ended and every launch failed closed. It is a denial of supervision rather than an escape, but
/// it costs one connection and no privilege. [`HANDOFF_SILENCE`] bounds it.
fn accept_handoff(listener: &UnixListener, stop: &AtomicBool) -> Option<libc::c_int> {
    use std::os::unix::io::AsRawFd;
    let mut announced = false;
    while !stop.load(Ordering::Relaxed) {
        if !poll_readable(listener.as_raw_fd(), 250) {
            continue;
        }
        match listener.accept() {
            Ok((stream, _)) if !handoff_speaks(stream.as_raw_fd(), stop) => {
                // Silent past the bound: treated exactly as a refused handoff, which is the answer
                // this loop already has for a connection that is not the shim's.
                if !announced {
                    announced = true;
                    crate::diag::warn(
                        "exec supervision: a connection to the handoff socket went silent; \
                         still waiting for the shim's",
                    );
                }
                continue;
            }
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
/// [`pending::ASK_TIMEOUT`] never fires and the parked `execve` the timeout exists to release waits
/// for a human indefinitely. A process tree `execve`ing in a loop is enough to hold it there, and a
/// cage with a parked ancestor has every reason to. Paid once per [`SWEEP_EVERY`] rather than per
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
        handle_open(notif_fd, req, dirfd, path_addr, cx.open, cx.undecidable);
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

#[cfg(test)]
mod open_path_tests;

#[cfg(test)]
mod tests;
