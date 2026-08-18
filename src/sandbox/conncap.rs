//! One definition of how many connections a host-side accept loop will serve at once.
//!
//! Every socket sbx binds host-side is reachable from the cage, and a connection costs a thread for
//! as long as it lives. So each accept loop carries a ceiling, and beyond it a connection is
//! refused rather than allowed to pin another thread.
//!
//! It exists as a type because the loops that need it wrote it four times and no copy had both
//! halves. Two took the slot atomically and released it by hand, so a serving thread that panicked
//! leaked the slot for the life of the session, and enough of those close the socket for good. Two
//! released it from a `Drop` guard and *checked* the ceiling before taking it, which lets a burst
//! of accepts all pass the check and land past the cap. [`ConnCap::take`] does both: the slot is
//! taken by the same operation that tests the ceiling, and it comes back when the guard goes out of
//! scope, panic or no panic.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

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
