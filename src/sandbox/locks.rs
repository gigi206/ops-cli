//! Taking a lock whose contents are worth more than the panic that touched them.
//!
//! A `Mutex` or `RwLock` is *poisoned* once a thread panics while holding it, and every later take
//! answers `Err` from then on. That default is the right one for data carrying an invariant a panic
//! could have left half-established: refusing to hand it out beats handing out something nobody
//! checked.
//!
//! It is the wrong default for the other half of what this program locks. Which half a lock belongs
//! to is decided once, here, rather than re-decided at each site that takes one.
//!
//! **A lock recovers when what it guards is kept for a reader** — a lens ring, a tally, an
//! invocation log, a registry the run consults. What such a record is worth is precisely that it
//! survived whatever went wrong, so propagating the panic destroys the one thing there was to have.
//! `sbx proc logs`, `sbx task status`, `sbx net stats` and the answer to a parked `execve` all read
//! through one of these, and one panic in an unrelated handler would turn every one of them into a
//! second panic. Taking the data is sound: these guards hold a queue, a map or a byte buffer whose
//! mutations are single calls, so a panic leaves them valid, at worst without the entry that was
//! being added.
//!
//! **A lock degrades when what it guards is handed back out for reuse** — a pooled upstream
//! connection, a cached resolution. There, redoing the work beats reusing something a panic touched
//! mid-flight, and the caller already has a path for "not available". Those sites take `.ok()`
//! rather than these helpers, and keep it: `proxy/pool.rs` and `proxy/dns.rs`. Named rather than
//! linked because both are private to the proxy, so a doc link from here would resolve to nothing.
//!
//! Two sites recover on neither argument, and each says so where it lives, because a lock that
//! guards a decision rather than data owes that argument in full at its own definition and does not
//! inherit one from here. `ProcOverlay` in `sandbox/proc_enforce.rs` and `ManualRules` in
//! `sandbox/control` are the live `--session` exec and egress rule overlays: **live policy**, which
//! is neither a record nor a resource. Both recover because their lists cannot be left incomplete by
//! an unwind, and because the panic's alternative — ending the thread that decides every `execve`,
//! or the thread that decides a request — removes the policy entirely rather than weakening it.
//!
//! The line between the two cases above is what the data is *for*, not what type it has. A record whose reader
//! would act on it as if nothing had happened is the case to look at twice: recovery must not turn
//! an absent record into a confident wrong one. Where a mutation writes a value and its own
//! qualifier as two steps, the qualifier is what a recovered guard has to settle — see
//! `proxy/capture.rs`, which states why its own two steps cannot be interrupted.

use std::sync::{Mutex, MutexGuard, RwLock, RwLockReadGuard, RwLockWriteGuard};

/// Take a mutex, recovering the data when a previous holder panicked. See the module header for
/// which locks may do this and which must not.
pub(crate) fn locked<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

/// [`locked`] for a read-lock.
pub(crate) fn read_locked<T>(l: &RwLock<T>) -> RwLockReadGuard<'_, T> {
    l.read().unwrap_or_else(|e| e.into_inner())
}

/// [`locked`] for a write-lock.
pub(crate) fn write_locked<T>(l: &RwLock<T>) -> RwLockWriteGuard<'_, T> {
    l.write().unwrap_or_else(|e| e.into_inner())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The rule itself, held apart from any of its users: a lock a panic has poisoned still yields
    /// what it was guarding, and yields it changed by whatever the panicking holder had already
    /// done. Both halves matter — recovering an empty value would be indistinguishable from having
    /// no record at all, which is the outcome this exists to avoid.
    #[test]
    fn a_poisoned_lock_still_yields_what_it_was_guarding() {
        let m = std::sync::Arc::new(Mutex::new(vec![1u8]));
        let poisoner = std::sync::Arc::clone(&m);
        let panicked = std::thread::spawn(move || {
            let mut g = locked(&poisoner);
            g.push(2);
            panic!("the holder gives up mid-flight");
        })
        .join();
        assert!(
            panicked.is_err(),
            "the fixture must actually poison the lock"
        );
        assert!(
            m.lock().is_err(),
            "…and the standard take must see it poisoned"
        );
        assert_eq!(
            *locked(&m),
            vec![1, 2],
            "including what the holder had already written"
        );
    }

    #[test]
    fn a_poisoned_rwlock_yields_to_both_kinds_of_take() {
        let l = std::sync::Arc::new(RwLock::new(7u32));
        let poisoner = std::sync::Arc::clone(&l);
        let _ = std::thread::spawn(move || {
            let _g = write_locked(&poisoner);
            panic!("the holder gives up mid-flight");
        })
        .join();
        assert!(
            l.read().is_err(),
            "the fixture must actually poison the lock"
        );
        assert_eq!(*read_locked(&l), 7);
        *write_locked(&l) = 8;
        assert_eq!(
            *read_locked(&l),
            8,
            "a poisoned lock stays usable, not merely readable"
        );
    }
}
