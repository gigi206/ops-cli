//! What a finished run owes its user about the decisions it could not base on a name: the three
//! counters, the word a mode's unmatched default deserves, and the teardown report that says a
//! kind twice only when it happened more than once.
//!
//! The `diag::warn` calls that say the *first* of each kind stay at the read that knows, which is
//! the discipline [`Undecidable`] argues for; only the totals are assembled here.

use std::sync::atomic::{AtomicU64, Ordering};

use crate::proc_policy::{ProcPolicy, Verdict};

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
/// the two call sites in [`super::handle_notif`] are out of reach — getting there needs a read that
/// fails while a real target is parked in its syscall, and a parked target's memory is precisely
/// what is readable. Making it fail means raising the host's `ptrace_scope`, which is machine-wide
/// and not a test's to change. Revisit if a way appears to close one process's memory to another
/// without touching that sysctl.
///
/// One step is held by nothing at all: that [`super::ProcEnforce`]'s own drop calls
/// [`Undecidable::report`]. Driving it needs a supervisor `start_inner` built — sockets, a shim, a
/// thread — and then a run in which a read fails more than once, which is the unreachable state
/// above; revisit the two together. What that drop does *not* depend on is the launcher reaching
/// it: every path that ends a run drops the guard explicitly before leaving, because a bare
/// `process::exit` runs no destructors and the launcher says so where it exits. So the only
/// teardown that reports nothing is one that also unlinks no socket.
#[derive(Default)]
pub(super) struct Undecidable {
    /// An `execve` whose target path could not be read.
    pub(super) exec: AtomicU64,
    /// An open whose path could not be read, so the content lens examined nothing.
    pub(super) open: AtomicU64,
    /// An `execve` whose calling program could not be read, or is not a name a policy can hold.
    pub(super) caller: AtomicU64,
}

impl Undecidable {
    /// What a finished run owes its user about the decisions it could not base on a name, given the
    /// word for what its mode does with a decision that matched nothing.
    ///
    /// Read after the supervisor thread has been joined, so the counts are final. A kind that
    /// happened once is left out: it already warned when it happened, and a teardown line that only
    /// ever says `1` is one a reader learns to skip — including on the run where it says `8412`.
    /// Each line carries what the fallback did, because that is the part its reader acts on.
    pub(super) fn report(&self, unmatched: &str) -> Vec<String> {
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
pub(super) fn unmatched_word(policy: &ProcPolicy) -> &'static str {
    match policy.unmatched() {
        Verdict::Allow => "allowed",
        Verdict::Deny => "refused",
        Verdict::Ask => "parked for a decision",
    }
}
