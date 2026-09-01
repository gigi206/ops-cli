//! The rules every host-side accept loop follows: how many connections it serves at once, what it
//! does with a failed `accept(2)`, and what it does when the host will not give it a thread.
//!
//! Every socket sbx binds host-side is reachable from the cage, and a connection costs a thread for
//! as long as it lives. So each accept loop carries a ceiling, and beyond it a connection is
//! refused rather than allowed to pin another thread.
//!
//! The two failure rules live here for the same reason the ceiling does: each loop is the body of a
//! detached thread that owns its listener, so a loop that returns — or unwinds — closes its plane
//! for the rest of the launch with the session otherwise running fine. Neither rule is a judgement
//! a single plane gets to make differently.
//!
//! The ceiling exists as a type because the loops that need it wrote it four times and no copy had
//! both halves. Two took the slot atomically and released it by hand, so a serving thread that
//! panicked leaked the slot for the life of the session, and enough of those close the socket for
//! good. Two released it from a `Drop` guard and *checked* the ceiling before taking it, which lets
//! a burst of accepts all pass the check and land past the cap. [`ConnCap::take`] does both: the
//! slot is taken by the same operation that tests the ceiling, and it comes back when the guard
//! goes out of scope, panic or no panic.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

/// How long a loop pauses after a failure it means to survive. Far too short to matter to a real
/// connection, and long enough that a condition lasting seconds costs no core.
const BACKOFF: Duration = Duration::from_millis(20);

/// What an accept loop does with a failed `accept(2)`: say so, pause briefly, and carry on serving.
///
/// A per-connection error is that connection's problem, never the server's — and this tree has got
/// that wrong twice, in the two opposite ways, which is why the answer is written once here instead
/// of a fifth time at each loop.
///
/// `?` on the accept ends the `for`, and every one of these loops is the body of a detached thread,
/// so returning drops the `UnixListener` and closes the listening fd for the rest of the launch.
/// Nothing announces it: the socket file stays on disk (only the owner's `Drop` unlinks it) and the
/// pid keeps being reported, so the plane is simply gone and every verb that needs it fails for a
/// session that is otherwise running fine.
///
/// Swallowing it with a bare `continue` keeps the listener alive but spins the thread flat out for
/// as long as the condition lasts — and the usual cause is host fd exhaustion (`EMFILE`), which is
/// exactly when a machine can least afford a core. The pause is far too short to matter to a real
/// connection and long enough to make a persistent error cost nothing.
///
/// The egress proxy's loop and the egress control plane's carry this same defence inline, written
/// out with the history of how each came to need it; `who` names the plane so the line reads the
/// same as theirs.
pub(super) fn accept_backoff(who: &str, e: &std::io::Error) {
    crate::diag::error(&format!("sbx: {who}: accept error: {e}"));
    std::thread::sleep(BACKOFF);
}

/// Hand one accepted connection to its own thread, or say that the host would not give one.
///
/// The other half of [`accept_backoff`], and needed for the same reason: `std::thread::spawn`
/// *panics* when the kernel refuses a thread (`EAGAIN` under `RLIMIT_NPROC` or a slice's
/// `TasksMax`), and the spawn is the statement right after the accept in a loop that is itself the
/// body of a detached thread. The unwind drops the listener and closes the plane for the rest of
/// the launch — exactly the outcome [`accept_backoff`] exists to prevent, reached under the same
/// host condition, since fd exhaustion and thread exhaustion arrive together on a loaded machine.
/// `Builder::spawn` reports the refusal instead of panicking, so the connection is let go and the
/// loop keeps serving.
///
/// Whatever the connection holds — its [`ConnSlot`] above all — must travel *inside* `work`, which
/// is all a refused spawn gives back: a slot taken on the accept loop and released only by a thread
/// that never ran would leak one slot per refusal, until the count reached the ceiling and every
/// later connection was refused by a plane serving nothing at all.
///
/// Returns whether the thread was created. A refusal has already been reported and paused for, so a
/// loop with nothing further to say about the connection may ignore the answer and accept the next.
pub(super) fn spawn_conn<F>(who: &str, work: F) -> bool
where
    F: FnOnce() + Send + 'static,
{
    spawn_with(std::thread::Builder::new(), who, work)
}

/// [`spawn_conn`]'s body, with the builder passed in. The refusal path is otherwise reachable only
/// on a host already out of threads, and it is the path worth pinning, so the seam exists for a
/// test to ask for a thread the kernel is certain to refuse.
fn spawn_with<F>(builder: std::thread::Builder, who: &str, work: F) -> bool
where
    F: FnOnce() + Send + 'static,
{
    match builder.spawn(work) {
        Ok(_) => true,
        Err(e) => {
            crate::diag::error(&format!(
                "sbx: {who}: could not start a connection thread: {e}"
            ));
            std::thread::sleep(BACKOFF);
            false
        }
    }
}

/// A ceiling on live connections, shared by an accept loop and the threads it spawns.
#[derive(Clone)]
pub(super) struct ConnCap {
    live: Arc<AtomicUsize>,
    max: usize,
}

/// One taken slot. Holding it is what counts as a live connection; dropping it gives the slot back.
pub(super) struct ConnSlot(Arc<AtomicUsize>);

impl ConnCap {
    pub(super) fn new(max: usize) -> Self {
        Self {
            live: Arc::new(AtomicUsize::new(0)),
            max,
        }
    }

    /// Take a slot, or `None` when the ceiling is already reached.
    ///
    /// The take *is* the test: an accept loop that read the counter and then incremented it would
    /// let every thread of a burst read the same value below the ceiling and all take a slot. The
    /// counter may momentarily read above `max` here, and that is the point — the caller that made
    /// it do so is the one refused.
    pub(super) fn take(&self) -> Option<ConnSlot> {
        if self.live.fetch_add(1, Ordering::SeqCst) >= self.max {
            self.live.fetch_sub(1, Ordering::SeqCst);
            return None;
        }
        Some(ConnSlot(Arc::clone(&self.live)))
    }

    /// How many slots are held. For tests and diagnostics; a decision must go through
    /// [`Self::take`], which is the only reading that cannot be stale by the time it is acted on.
    #[cfg(test)]
    pub(super) fn live(&self) -> usize {
        self.live.load(Ordering::SeqCst)
    }
}

impl Drop for ConnSlot {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The ceiling admits exactly `max`, and a slot given back is a slot another caller can take.
    #[test]
    fn a_cap_admits_its_ceiling_and_refuses_past_it() {
        let cap = ConnCap::new(2);
        let first = cap.take().expect("the first is admitted");
        let second = cap.take().expect("the second is admitted");
        assert!(cap.take().is_none(), "the third is past the ceiling");
        assert_eq!(cap.live(), 2, "a refusal must not leave a slot taken");

        drop(second);
        assert_eq!(cap.live(), 1);
        let third = cap.take().expect("a returned slot is takeable again");
        drop((first, third));
        assert_eq!(cap.live(), 0);
    }

    /// A serving thread that panics gives its slot back, because the guard's `Drop` runs while the
    /// stack unwinds. The manual release this replaces did not: a panic leaked the slot for good,
    /// and enough of them closed the socket to every later caller.
    #[test]
    fn a_slot_held_by_a_thread_that_panics_comes_back() {
        let cap = ConnCap::new(1);
        let taken = cap.clone();
        let panicked = std::thread::spawn(move || {
            let _slot = taken.take().expect("admitted");
            panic!("the connection handler failed");
        })
        .join();
        assert!(
            panicked.is_err(),
            "the thread under test must have panicked"
        );
        assert_eq!(cap.live(), 0, "the slot was leaked by the panic");
        assert!(cap.take().is_some(), "and the socket is still serving");
    }

    /// The ordinary hand-over: the work runs on its own thread, and the slot it carried comes back
    /// when that work ends.
    #[test]
    fn a_connection_handed_over_runs_and_gives_its_slot_back() {
        let cap = ConnCap::new(1);
        let slot = cap.take().expect("admitted");
        let (done, ran) = std::sync::mpsc::channel();
        assert!(spawn_conn("test plane", move || {
            drop(slot);
            let _ = done.send(());
        }));
        ran.recv_timeout(Duration::from_secs(10))
            .expect("the connection's thread ran");
        assert_eq!(cap.live(), 0, "the slot came back with the work");
    }

    /// A connection whose thread the host refuses gives back everything that connection held, the
    /// loop is told, and nothing unwinds.
    ///
    /// The bare `std::thread::spawn` this replaces panicked instead, and the panic unwound the
    /// detached accept loop that owns the listener — closing the plane for the rest of the launch
    /// under precisely the host pressure the accept-error arm above it already anticipates.
    #[test]
    fn a_refused_thread_gives_the_connection_back_and_leaves_the_loop_standing() {
        let cap = ConnCap::new(1);
        let slot = cap.take().expect("admitted");
        // A stack larger than any Linux address space, so the thread is refused the way one is
        // refused under `RLIMIT_NPROC` — a condition a test cannot otherwise reach. Large, but
        // still small enough that the C library accepts it as a stack size (both glibc and musl
        // reject an outright absurd one on the attribute, which is a different failure): the
        // mapping is what has to fail here, not the request to make it.
        let spawned = spawn_with(
            std::thread::Builder::new().stack_size(usize::MAX / 8),
            "test plane",
            move || drop(slot),
        );
        assert!(!spawned, "the host cannot have created this thread");
        assert_eq!(cap.live(), 0, "the slot travelled inside the refused work");
        assert!(cap.take().is_some(), "and the plane is still serving");
    }

    /// Every host-side accept loop hands its connection over through [`spawn_conn`].
    ///
    /// The panic it prevents needs a host already out of threads, so nothing else in the suite
    /// notices a loop that goes back to the bare `std::thread::spawn` — which is the form a hand
    /// reaches for. Each loop is therefore read from its own file, anchored on the accept-error arm
    /// above it, and the first spawn after that anchor must be this one.
    #[test]
    fn every_accept_loop_hands_its_connection_over_through_the_helper() {
        for (plane, source, anchor) in [
            (
                "broker",
                include_str!("broker.rs"),
                r#"accept_backoff("broker""#,
            ),
            (
                "ssh-agent broker",
                include_str!("sshagent.rs"),
                r#"accept_backoff("ssh-agent broker""#,
            ),
            (
                "lens control",
                include_str!("lens.rs"),
                r#"accept_backoff("lens control""#,
            ),
            (
                "forward",
                include_str!("forward.rs"),
                r#"accept_backoff("forward""#,
            ),
            (
                "task control (cage)",
                include_str!("task_control.rs"),
                r#"accept_backoff("task control (cage)""#,
            ),
            (
                "task control (logs)",
                include_str!("task_control.rs"),
                r#"accept_backoff("task control (logs)""#,
            ),
            (
                "egress control",
                include_str!("control/mod.rs"),
                "sbx: egress control: accept error",
            ),
            (
                "egress proxy",
                include_str!("proxy/mod.rs"),
                "fn spawn_connection(",
            ),
        ] {
            let at = source
                .find(anchor)
                .unwrap_or_else(|| panic!("`{plane}`'s accept loop no longer reads as `{anchor}`"));
            let rest = &source[at..];
            let helper = rest.find("spawn_conn(").unwrap_or(usize::MAX);
            let bare = rest.find("thread::spawn(").unwrap_or(usize::MAX);
            assert!(
                helper < bare,
                "`{plane}` hands its connection to a bare `std::thread::spawn`, which panics when \
                 the host refuses the thread and unwinds the detached loop that owns the listener"
            );
        }
    }

    /// Contending takers never hold more slots at once than the ceiling allows.
    ///
    /// This is the property the check-then-take shape does not have, and testing it by *counting*
    /// what a burst admitted does not catch that: measured, a barrier of sixty-four threads against
    /// a ceiling of eight admitted exactly eight with the racy shape in place. What catches it is
    /// watching the peak — a ceiling of one, taken and released in a tight loop by every thread, so
    /// two takers reading the same value below the ceiling show up as two holders at once.
    #[test]
    fn contending_takers_never_hold_more_than_the_ceiling_at_once() {
        let cap = ConnCap::new(1);
        let held = Arc::new(AtomicUsize::new(0));
        let peak = Arc::new(AtomicUsize::new(0));
        let start = Arc::new(std::sync::Barrier::new(16));
        let mut takers = Vec::new();
        for _ in 0..16 {
            let (cap, held, peak, start) = (
                cap.clone(),
                Arc::clone(&held),
                Arc::clone(&peak),
                Arc::clone(&start),
            );
            takers.push(std::thread::spawn(move || {
                start.wait();
                for _ in 0..5_000 {
                    if let Some(slot) = cap.take() {
                        let now = held.fetch_add(1, Ordering::SeqCst) + 1;
                        peak.fetch_max(now, Ordering::SeqCst);
                        held.fetch_sub(1, Ordering::SeqCst);
                        drop(slot);
                    }
                }
            }));
        }
        for taker in takers {
            taker.join().expect("a taker panicked");
        }
        assert_eq!(
            peak.load(Ordering::SeqCst),
            1,
            "two takers held the one slot"
        );
        assert_eq!(cap.live(), 0, "every slot came back");
    }
}
