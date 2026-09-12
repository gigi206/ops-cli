//! The trust gate: whether a configuration layer may set a security-relevant field at all, and the
//! vocabulary of a field dropped for want of trust.
//!
//! Apart from the resolution engine next door because the two answer different questions. The
//! engine decides which layer a field comes from and folds it into the resolved set; the gate
//! decides whether that layer is trusted enough to have a say. Every gated field asks the gate the
//! same question, which is why the answer is spelled once here rather than once per field.
//!
//! That is a statement about the **vocabulary**, not about the coverage, and the difference is worth
//! writing down. A field added to `RawConfig` breaks the compilation of three exhaustive
//! destructurings, all of them in the override plane: `apply_override`, `overlay_into` and
//! `push_env_source_notices`. Each forces an author to say what a one-shot override does with the
//! new field. Nothing makes the same demand of the layering engine: the fields `resolve` and
//! `resolve_app` gate are reached by hand-written lines, so a field nobody wrote a line for is
//! simply not read there, and `RawApp` has no exhaustive destructuring in the engine at all. Every
//! field shipped today is reached by such a line; what says so is a reading, not a compiler.
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
/// out once per field. What decides *which* fields ask it is the resolution engine's own list of
/// lines, not this type: see the module header.
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

/// Tests that the layering engine still reaches every field a configuration layer can carry.
#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::path::{Path, PathBuf};

    /// A source file of the config plane, read the way a reader would open it.
    fn config_source(name: &str) -> String {
        let path: PathBuf = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("src/config")
            .join(name);
        std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("{} is readable: {e}", path.display()))
    }

    /// Every field of `RawConfig`, taken from the one list the **compiler** keeps current.
    ///
    /// Not parsed out of the struct: `overlay_into`'s destructuring is exhaustive, so a field added
    /// to `RawConfig` and not added here fails the build. Reading the population from a
    /// compiler-checked site is what keeps this test from going stale in the same way the thing it
    /// guards would. A field is written either bare (`env,`) or dropped on purpose (`distro: _,`),
    /// and both spellings count: what is asked below is whether the engine *reaches* the field, not
    /// what the override plane decides to do with it.
    fn raw_config_fields() -> Vec<String> {
        let src = config_source("overrides.rs");
        let from = src
            .find("fn overlay_into")
            .expect("`overlay_into` is the exhaustive destructuring this test reads");
        let open = src[from..]
            .find("let RawConfig {")
            .map(|i| from + i)
            .expect("`overlay_into` destructures `RawConfig`");
        let close = src[open..]
            .find("} = higher;")
            .map(|i| open + i)
            .expect("the destructuring closes on `higher`");

        let mut out = Vec::new();
        for line in src[open..close].lines().skip(1) {
            let line = line.trim();
            if line.is_empty() || line.starts_with("//") {
                continue;
            }
            let name = line
                .strip_suffix(',')
                .map(|n| n.split(':').next().unwrap_or(n).trim())
                .unwrap_or_default();
            if !name.is_empty() && name.chars().all(|c| c.is_ascii_lowercase() || c == '_') {
                out.push(name.to_string());
            }
        }
        assert!(
            out.len() > 30,
            "the destructuring parse found only {} field(s), so it has stopped matching the \
             source's shape and would pass vacuously",
            out.len()
        );
        out
    }

    /// The body of one function, by brace matching from its signature.
    ///
    /// The *function*, not the file: `apply_override` — one of the exhaustive destructurings that
    /// already name every field — lives in `config/mod.rs` beside the engine, so a whole-file
    /// search is satisfied by the very list this test must not read, and would pass over any
    /// omission. Measured: with a probe field added to `RawConfig`, the file-wide form stayed
    /// green.
    ///
    /// The counter is sound only while no literal carries an unbalanced brace inside either body.
    /// Checked when this was written: the two `{{`/`}}` sequences in these files
    /// (`apps.rs:194`'s `{{GET,HEAD}}` and `mod.rs:4602`'s `{{500}}`) are balanced *and* sit
    /// outside both bodies, and neither file holds a `'{'` or `'}'` char literal. An unbalanced one
    /// added later would truncate a body early rather than fail, which is what the size floor at
    /// the call site is for.
    fn body_of(source: &str, signature: &str) -> String {
        let at = source
            .find(signature)
            .unwrap_or_else(|| panic!("`{signature}` is in this source"));
        let open = at + source[at..].find('{').expect("the signature opens a body");
        let mut depth = 0usize;
        for (i, c) in source[open..].char_indices() {
            match c {
                '{' => depth += 1,
                '}' => {
                    depth -= 1;
                    if depth == 0 {
                        return source[open..open + i].to_string();
                    }
                }
                _ => {}
            }
        }
        panic!("`{signature}` never closes its body");
    }

    /// The layering engine names every field a layer can carry.
    ///
    /// This is the guard this module's header says does not exist. `apply_override`, `overlay_into`
    /// and `push_env_source_notices` are exhaustive, so the **override** plane cannot forget a
    /// field: the compiler refuses. The engine next door has no such destructuring — `resolve` and
    /// `resolve_app` reach their fields by hand-written lines, and `RawApp` is not destructured at
    /// all — so a field nobody writes a line for is simply never read from a layer, silently, and
    /// a security field that is never read is one an untrusted layer was never asked about.
    ///
    /// What it checks is **presence**, not correctness: that each engine function names the field
    /// somewhere in its body, not that it gates it rightly. A field can only be gated where it is
    /// named, so a name absent from both bodies is a field the engine cannot be reading — which is
    /// the failure this exists to make loud. Judging *how* it is read stays a reading.
    #[test]
    fn the_layering_engine_names_every_field_a_layer_can_carry() {
        // Floors per body, not on the pair: a truncation in one would otherwise hide behind the
        // other's size. Measured 2026-09-11 at 52,020 and 31,633 bytes; the floors sit near half,
        // low enough that an honest shrink of either function passes and high enough that a brace
        // counter that stopped early does not.
        let resolve = body_of(&config_source("mod.rs"), "fn resolve(");
        let resolve_app = body_of(&config_source("apps.rs"), "fn resolve_app(");
        for (what, body, floor) in [
            ("resolve", &resolve, 25_000),
            ("resolve_app", &resolve_app, 15_000),
        ] {
            assert!(
                body.len() > floor,
                "`{what}`'s body read as {} bytes, under the {floor} floor, so the extraction has \
                 stopped matching the source's shape and this test would pass vacuously",
                body.len()
            );
        }
        let engine = resolve + &resolve_app;
        let named: BTreeSet<&str> = engine
            .split(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
            .filter(|w| !w.is_empty())
            .collect();

        let unreached: Vec<String> = raw_config_fields()
            .into_iter()
            .filter(|f| !named.contains(f.as_str()))
            .collect();
        assert!(
            unreached.is_empty(),
            "these `RawConfig` fields are named nowhere in the layering engine's own bodies \
             (`resolve` in src/config/mod.rs, `resolve_app` in src/config/apps.rs), so no layer \
             can be setting them and no gate can be refusing them: {unreached:?}"
        );
    }
}
