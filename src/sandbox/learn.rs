//! What a learning run hands back, shared by the two lenses that have one.
//!
//! `--net-learn` reads an egress log and `--proc-learn` an exec record, but both answer the same
//! question — *which rules would admit what this run was not declared for* — and both are applied by
//! the same write path: surface the notes, preview or persist the rules. Keeping the shape here is
//! what lets that write path be written once — `finish_learn`, in the `app` command — instead of
//! once per lens, and what keeps a third lens from inventing a third spelling of "rules plus notes".

/// The result of turning one run's record into rules: the rule strings to add (sorted, deduplicated,
/// each already valid for the write path that will persist it), and human notes about anything worth
/// the caller seeing — an observation that produced no rule, or a scope that was widened.
///
/// Notes are not diagnostics the synthesizer prints itself: they are returned so the caller decides
/// where they go, which is what keeps a `--dry-run` preview and a real write saying the same things
/// in the same order.
pub(crate) struct Synthesis {
    pub(crate) rules: Vec<String>,
    pub(crate) notes: Vec<String>,
}
