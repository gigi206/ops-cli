//! The `ask`-parked `execve` registry: shared mutable state reached from three threads — the
//! receive loop that parks and sweeps, the control server that answers, and the teardown that
//! drains — with its own flood cap, timeout and dup-per-entry discipline.

use std::collections::BTreeMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use super::notify::{notif_id_valid, respond_continue, respond_errno};
use crate::sandbox::locks::locked;

/// The most `ask`-parked `execve`s a session holds at once. Beyond this, a further undecided `execve`
/// is denied outright (fail-closed) rather than growing the registry without bound — mirroring the
/// egress ask flood cap.
const ASK_PENDING_CAP: usize = 256;

/// How long an `ask`-parked `execve` waits for a human decision before it is auto-denied. A finite
/// bound is load-bearing: a parked `execve` blocks its process, and a parent `wait`ing on it would
/// otherwise hang the whole tree — the timeout releases it (with `EPERM`, fail-closed) so the tree
/// makes progress. A live `sbx proc allow`/`deny` decides it well within this window.
pub(super) const ASK_TIMEOUT: Duration = Duration::from_secs(120);

/// How often the receive loop looks for a parked `execve` that has run out of time.
///
/// One tick of the loop's own poll slice. The sweep used to ride on the idle branch, which meant it
/// ran only when the cage had gone quiet — so the timeout was reliable exactly where nothing needed
/// releasing, and absent while a busy cage held the notification fd readable. Asking on a clock
/// instead of on idleness costs one registry lock per quarter-second at the very most, whatever the
/// cage does.
pub(super) const SWEEP_EVERY: Duration = Duration::from_millis(250);

/// The registry of `ask`-parked `execve`s awaiting a decision. Each entry carries the kernel
/// notification id and a descriptor of its own to answer it through, so the control plane
/// (`sbx proc allow`/`deny`) and the timeout sweeper can respond out-of-band while the receive loop
/// keeps draining the next notification. Shared (via `Arc`) between the supervisor thread and the
/// control serve thread.
pub(crate) struct PendingExec {
    pub(super) inner: Mutex<BTreeMap<u64, Parked>>,
}

pub(super) struct Parked {
    id: u64,
    /// This entry's **own** `dup` of the notification descriptor, closed when the entry is dropped.
    ///
    /// Not the supervisor's number, which is the shape this had and which the teardown order alone
    /// cannot save. `answer` takes an entry out of the registry and only then answers it, so a
    /// control thread can be between those two steps at the moment [`super::close_supervision`]
    /// drains the registry (finding it already empty) and closes the descriptor — after which the
    /// answer is an `ioctl` on a number this process may since have reissued to something else
    /// entirely. The `dup` is the same fix [`super::open_serve::park_open`] makes for an open
    /// answered from its own thread, and it also keeps the kernel's listener alive for exactly as
    /// long as something can still answer through it.
    ///
    /// An [`OwnedFd`](std::os::fd::OwnedFd) and not a raw number, so the close rides on the entry
    /// leaving the registry however it leaves — answered, swept, or dropped with the map — and the
    /// rest of the entry stays movable out of it.
    pub(super) notif_fd: std::os::fd::OwnedFd,
    pid: u32,
    path: String,
    pub(super) since: Instant,
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
    /// [`crate::sandbox::proc_control::ExecRing::push_verdict`] states about the ring beside it: this
    /// is the **third** producer on that same line-based control wire, and it was the one written
    /// apart. `dispatch_enforced` renders these as `pending id=… pid=… path={path}` and
    /// `answered path={path}`, while the client reads the reply with `.lines()` and stops at the
    /// first bare `ok` — so a newline in a target the cage named (paths may carry one, and this one
    /// is read out of the cage's own memory) ends the row early and lets what follows read as
    /// another. A cage could hide a park behind a forged one, or paint rows the operator never had.
    /// Sanitising is idempotent, so the ring's copy of the same string is unaffected; the verdict
    /// itself was reached on the raw path, above.
    pub(super) fn park(&self, notif_fd: libc::c_int, id: u64, pid: u32, path: &str) {
        use std::os::unix::io::FromRawFd;
        let path = crate::sandbox::sanitize(path);
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
    pub(super) fn sweep(&self) {
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
