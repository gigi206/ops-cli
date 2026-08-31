//! The trust gate: whether a configuration layer may set a security-relevant field at all, and the
//! vocabulary of a field dropped for want of trust.
//!
//! Apart from the resolution engine next door because the two answer different questions. The
//! engine decides which layer a field comes from and folds it into the resolved set; the gate
//! decides whether that layer is trusted enough to have a say. Every gated field asks the gate the
//! same question, which is why the answer is spelled once here rather than once per field — a field
//! added without its gate then has nowhere to hide.
//!
//! The refusal wording lives here for the same reason. A dropped field is visible to a user only as
//! the sentence that says so, and there is more than one producer of that sentence — the gate's own
//! refusal, the bind count, and the launcher's withheld package — so the remedy they must all point
//! at ([`TRUST_DROP_MARKER`]) sits beside them instead of hundreds of lines away.

use super::*;

/// The trust verdict one configuration layer is subject to, and what names that layer when it has
/// to refuse a field.
///
/// A security field is honoured only from a trusted layer; an untrusted or changed one gets a
/// warning and the value accumulated so far stands. Every gated field asks that same question, so
/// the layer carries one of these and the decision is made in a single place rather than spelled
/// out once per field — and a field added without its gate has nowhere to hide.
pub(super) struct Gate<'a> {
    pub(super) trusted: bool,
    pub(super) state: TrustState,
    /// What names this layer in a warning: the project file, or an app's own source.
    pub(super) source: &'a str,
}

impl Gate<'_> {
    /// Refuse a field, naming it and the remedy — [`refuse_untrusted`] for a layer that has a gate.
    pub(super) fn refuse(&self, what: &str, warnings: &mut Vec<String>) {
        refuse_untrusted(warnings, self.source, what, self.state);
    }

    /// Take `value` outright when the layer is trusted, and record the layer as where it came from.
    ///
    /// For a posture that needs no validation past parsing.
    pub(super) fn take<T>(
        &self,
        slot: &mut T,
        origin: &mut Provenance,
        what: &str,
        value: T,
        warnings: &mut Vec<String>,
    ) {
        if !self.trusted {
            self.refuse(what, warnings);
            return;
        }
        *slot = value;
        *origin = Provenance::Project;
    }

    /// Take a validated replacement when the layer is trusted and validation produced one.
    ///
    /// `validate` sees the value accumulated so far, because a layer's table without a `mode`
    /// inherits it from the layer below. One that returns `None` has already said why in
    /// `warnings`, and the accumulated value stands — so provenance moves only when a value
    /// actually arrives.
    pub(super) fn take_validated<T>(
        &self,
        slot: &mut T,
        origin: &mut Provenance,
        what: &str,
        warnings: &mut Vec<String>,
        validate: impl FnOnce(&mut Vec<String>, &T) -> Option<T>,
    ) {
        if !self.trusted {
            self.refuse(what, warnings);
            return;
        }
        if let Some(value) = validate(warnings, slot) {
            *slot = value;
            *origin = Provenance::Project;
        }
    }

    /// Fold a trusted layer's contribution into an accumulating set.
    ///
    /// Provenance moves only when the layer actually contributed something: an empty contribution
    /// claiming it would make `config show` point at a layer that added nothing.
    ///
    /// `union` is named at the call site rather than assumed, because each set has its own idea of
    /// merging — and because these unions sort the accumulated value as a side effect, so a refused
    /// layer must not reach one at all.
    pub(super) fn union<T>(
        &self,
        acc: &mut Vec<T>,
        origin: &mut Provenance,
        what: &str,
        warnings: &mut Vec<String>,
        contribute: impl FnOnce(&mut Vec<String>) -> Vec<T>,
        union: fn(&mut Vec<T>, Vec<T>),
    ) {
        if !self.trusted {
            self.refuse(what, warnings);
            return;
        }
        let contributed = contribute(warnings);
        if !contributed.is_empty() {
            *origin = Provenance::Project;
        }
        union(acc, contributed);
    }
}

/// Refuse something for want of trust: name the layer, what was dropped, and the remedy.
///
/// The one place a resolution writes `<layer>: ignoring <what> (<reason>)` — the only thing that
/// tells anyone a declared field is not in effect. [`Gate::refuse`] is the method form, for the
/// fields a layer's gate decides. The tool-level guards in the `apply_*` helpers call this directly
/// instead, because they answer a different question — not whether the layer may set a field, but
/// whether it may override one a trusted layer already set — and they answer it where the
/// accumulated set is in hand rather than at the gate.
///
/// `what` is the whole phrase, passed verbatim by the caller — "`gpu` posture", "`forward` ports",
/// "`[devices]`". The nouns differ per field and that is deliberate: this sentence is what a user
/// reads, so it is the caller's to spell, never something derived from a field name here.
///
/// This is not the only producer of a dropped-for-want-of-trust warning — `binds` has a sentence of
/// its own, and the launcher withholds a package in words of its own again ([`TRUST_DROP_MARKER`]
/// is what spans them). What is centralized is one sentence, so that changing it is one edit.
pub(super) fn refuse_untrusted(
    warnings: &mut Vec<String>,
    source: &str,
    what: &str,
    state: TrustState,
) {
    warnings.push(format!(
        "{source}: ignoring {what} ({})",
        untrusted_reason(state)
    ));
}

/// The actionable reason a project's security-relevant value is held back, phrased
/// for the action it implies: a since-*changed* project points at re-approval, a
/// never-trusted one at first approval. Shared by the package launcher and
/// `sbx config` so the two never phrase the same verdict differently.
pub(crate) fn untrusted_reason(state: TrustState) -> &'static str {
    match state {
        TrustState::Changed => "changed since it was trusted — re-run `sbx trust`",
        _ => "untrusted — run `sbx trust`",
    }
}

/// What every dropped-for-want-of-trust warning points its reader at, and nothing else in a
/// resolution does.
///
/// The marker is the *remedy*, not the wording of any one reason, because there is more than one
/// producer: [`untrusted_reason`] phrases it one way and [`dropped_binds_warning`] another, and a
/// third added later will phrase it a third. Matching on a single reason's exact text would silently
/// stop covering the others — which is a failure of **silence**, the one thing nothing else catches.
/// A test pins every producer against this.
const TRUST_DROP_MARKER: &str = "`sbx trust`";

/// Whether a resolution warning is a security field dropped for want of trust.
pub(crate) fn is_trust_drop(warning: &str) -> bool {
    warning.contains(TRUST_DROP_MARKER)
}

/// The warning for security binds dropped from an untrusted project, made
/// actionable: a *changed* file points at re-approval, a never-trusted one at the
/// first approval.
pub(super) fn dropped_binds_warning(state: TrustState, count: usize) -> String {
    match state {
        TrustState::Changed => format!(
            "{PROJECT_CONFIG} changed since it was trusted: dropping {count} bind(s) — \
             re-run `sbx trust` to re-approve"
        ),
        _ => format!(
            "{PROJECT_CONFIG} is untrusted: dropping {count} bind(s) — \
             run `sbx trust` to apply them"
        ),
    }
}
