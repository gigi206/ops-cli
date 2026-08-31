//! The live `--session` rule overlay, folded onto the resolved config policy at every decision.
//!
//! Shared between the supervisor's decide path and the control server that writes it, and the one
//! lock in the tree that recovers from poisoning on an argument [`crate::sandbox::locks`]
//! explicitly declines to supply.

use std::sync::RwLock;

use crate::proc_policy::{ProcPolicy, ProcRule, Verdict};
use crate::sandbox::locks::{read_locked, write_locked};

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
    pub(super) inner: RwLock<OverlayInner>,
}

#[derive(Default)]
pub(super) struct OverlayInner {
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
