//! Turning one run's exec record into the `[proc] allow` rules that would admit it.
//!
//! The process/exec twin of [`super::netlearn`], and deliberately not its copy: the two lenses learn
//! from opposite halves of a run. Egress learning reads what was **refused** — a denied connection
//! leaves the program running, so a refusal-driven run reaches the next host and the next, and one
//! pass collects them all. An exec refusal is not survivable that way: the first denied program
//! usually ends the run, so a refusal-driven exec pass would learn exactly one rule.
//!
//! So this learns from what a run **ran**. The record it reads comes from the seccomp
//! user-notification supervisor under a denylist with nothing on it — every `execve` notified, every
//! one allowed — which is the one posture that both leaves the workload untouched and sees every
//! exec. The cheap `/proc` poll ([`super::observe_feed`]) cannot serve here: it samples, so it misses
//! anything shorter than a tick, and an allowlist learned from a sample is an allowlist that parks
//! the agent on the first thing the sample missed.
//!
//! What is learned is an `allow` list, which is live only under `ask`. That is the posture the
//! feature exists to bootstrap: run once, learn what the agent reaches for, then let `ask` park
//! anything new for a person.

use std::collections::BTreeSet;

use crate::proc_policy::{self, ProcMode, ProcPolicy, Verdict};

use super::learn::Synthesis;

/// How wide a rule `--proc-learn` synthesizes for each observed target.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) enum Granularity {
    /// The target's basename: `git`. The default, because an in-cage program lives at a path the
    /// project does not own — a nix closure spells it `/nix/store/<hash>-git-2.51.0/bin/git`, and
    /// that hash changes on the next `sbx upgrade`. A rule written against the path would stop
    /// matching the same program the day its channel rolls; a rule written against the name keeps
    /// naming it. The price is stated where a person reads it: a name rule admits that basename
    /// wherever it is found, so `git` admits any program called `git`.
    #[default]
    Name,
    /// The whole in-cage path: `/nix/store/<hash>-git-2.51.0/bin/git`. The strict reading, for a
    /// cage whose programs sit at paths that do not move — a distro userland, or a project that
    /// pins and does not roll. It goes stale on a roll, which is a visible failure (the agent parks
    /// under `ask`) rather than a silent widening.
    Path,
}

impl Granularity {
    /// The values `--proc-learn=<v>` accepts, in the order a listing shows them. The single source
    /// for the parser, the usage message and the completion drive, so a value cannot be offered and
    /// then refused (or accepted and never offered).
    pub(crate) const VALUES: [&'static str; 2] = ["name", "path"];

    /// Parse the `--proc-learn=<granularity>` suffix. The error names what is accepted rather than
    /// only what was rejected, because the flag's whole vocabulary is two words.
    pub(crate) fn parse(s: &str) -> Result<Self, String> {
        match s {
            "name" => Ok(Granularity::Name),
            "path" => Ok(Granularity::Path),
            other => Err(format!(
                "unknown --proc-learn granularity {other:?} (expected {})",
                Self::VALUES.join(" or ")
            )),
        }
    }

    /// The canonical spelling, for the messages that report which granularity a run learned at.
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Granularity::Name => "name",
            Granularity::Path => "path",
        }
    }
}

/// Turn the exec `targets` one run decided against into the `allow` rules that would admit them
/// under `ask`, at the requested `gran`ularity.
///
/// `policy` is the configuration's own `[proc]` policy, whatever posture it is in — it is read as
/// the **rules**, not as the mode. The question a candidate has to answer is "would `ask` still stop
/// on this?", so the subsumption oracle is that policy's rule sets under [`ProcMode::Ask`]:
///
/// - [`Verdict::Allow`] — an existing `allow` rule already names it. Not proposed again; a learning
///   pass that re-proposed what is written would grow the list on every run.
/// - [`Verdict::Deny`] — an existing `deny` rule names it. **Never** turned into an allow: deny wins
///   in [`ProcPolicy::decide_chain`], so the rule would be inert, and a learning run must not look
///   like it undid a refusal the operator wrote on purpose. Surfaced as a note instead.
/// - [`Verdict::Ask`] — nothing speaks about it. This is what a rule is synthesized for.
///
/// Never emits a rule the write path would reject ([`proc_policy::validate_rule`] is the same gate
/// `sbx proc allow` passes through), never one that would admit more than the target it was learned
/// from ([`literal_rule`]), and never drops a target without a note.
pub(crate) fn synthesize(record: &Record, policy: &ProcPolicy, gran: Granularity) -> Synthesis {
    // The rules as they are, asked under `ask`. Cloned rather than rebuilt from strings: the
    // compiled rules are what the supervisor decides with, so the oracle answers with the same
    // matcher the run itself used.
    let oracle = ProcPolicy {
        mode: ProcMode::Ask,
        ..policy.clone()
    };
    let mut rules: BTreeSet<String> = BTreeSet::new();
    let mut notes: Vec<String> = Vec::new();
    // First, because it qualifies everything below it: a rule list synthesized from a cut record is
    // not the run's whole account, and acting on it would park the agent on whatever came after.
    if record.truncated {
        notes.push(format!(
            "proc-learn: the exec record stopped at {} distinct targets — these rules cover what \
             was recorded up to there, not the whole run",
            Learned::CAP
        ));
    }
    // Refused during the run by a live `sbx proc deny --session` rule: the config's own rules did
    // not refuse it, so the oracle below would propose it, and turning a refusal a person just made
    // into a persistent allow is the opposite of what they asked for.
    for target in &record.session_denied {
        notes.push(format!(
            "proc-learn: `{target}` was refused by a `--session` deny rule during the run — left \
             alone, an allow would undo that refusal"
        ));
    }
    for target in record.targets.difference(&record.session_denied) {
        match oracle.decide(&[], target) {
            Verdict::Allow => continue,
            Verdict::Deny => {
                notes.push(format!(
                    "proc-learn: `{target}` ran but a `[proc] deny` rule names it — left alone, an \
                     allow would be inert beside it"
                ));
                continue;
            }
            Verdict::Ask => {}
        }
        let rule = match gran {
            Granularity::Name => proc_policy::basename(target),
            Granularity::Path => target.as_str(),
        };
        // A target with no usable basename (a path ending in `/`, which the fold does not produce
        // but the record does not promise either) has nothing to write a rule about. Said out loud,
        // because dropping the one program a run cared about in silence is how an allowlist ends up
        // one rule short.
        if let Err(why) = proc_policy::validate_rule(rule).and_then(|()| literal_rule(rule, gran)) {
            notes.push(format!(
                "proc-learn: `{target}` produced no rule at `{}` granularity ({why})",
                gran.as_str()
            ));
            continue;
        }
        rules.insert(rule.to_string());
    }
    Synthesis {
        rules: rules.into_iter().collect(),
        notes,
    }
}

/// Refuse a candidate rule that, written to a config file, would not name exactly the target it
/// was learned from.
///
/// The rule grammar has no escape: `*` and `?` in a rule are always wildcards, so a program whose
/// name carries one (a legal file name) would be learned as a pattern — a binary called `*` would
/// become the rule `*`, which admits every program. Surrounding whitespace is trimmed when a config
/// rule is compiled ([`ProcPolicy::new`]), so ` git` would be read back as `git` and admit another
/// program than the one that ran. `..`, which only a relative target can leave as its basename,
/// names a directory rather than a program. And a `path` rule is a path rule only while it holds a
/// `/` ([`ProcRule::new`](proc_policy::ProcRule::new)): a relative target spelled without one
/// (`execve("build.sh")`) would be written as a name rule admitting that basename anywhere, wider
/// than the granularity that was asked for.
fn literal_rule(rule: &str, gran: Granularity) -> Result<(), String> {
    if rule.contains(['*', '?']) {
        return Err("the name carries `*` or `?`, which a rule reads as a wildcard".to_string());
    }
    if rule.trim() != rule {
        return Err("the name has surrounding whitespace, which a rule does not keep".to_string());
    }
    if rule == ".." {
        return Err("`..` names a directory, not a program".to_string());
    }
    if gran == Granularity::Path && !rule.contains('/') {
        return Err("a relative name with no `/` would be read as a name rule".to_string());
    }
    Ok(())
}

/// The distinct exec targets one run decided against — the record `--proc-learn` synthesizes from.
///
/// Deliberately **not** the exec ring. That ring is a live feed with a fixed capacity
/// ([`super::proc_control::EXEC_RING_CAP`]): an agent that execs more times than it holds evicts the
/// beginning of its own run, and an allowlist learned from what survived would be short by exactly
/// the programs the run started with — silently. What learning needs is not the sequence of events
/// but the *set* of targets, which is bounded by how many distinct programs a cage runs rather than
/// by how often it runs them.
///
/// It still has to be bounded, because the cage chooses the targets: a program that execs a fresh
/// path in a loop would otherwise grow this without limit. Past [`CAP`](Learned::CAP) the set stops
/// taking new entries and says so, so a truncated record is reported as truncated instead of being
/// handed over as if it were the whole run.
#[derive(Debug, Default)]
pub(crate) struct Learned {
    targets: std::sync::Mutex<BTreeSet<String>>,
    /// The targets a live `--session` deny rule refused and the config's own rules did not, kept
    /// apart because a learned allow must not undo that refusal.
    session_denied: std::sync::Mutex<BTreeSet<String>>,
    /// Set when a target was dropped for want of room. Read with the set, so the synthesis can say
    /// that its input was cut rather than let a short allowlist look complete.
    truncated: std::sync::atomic::AtomicBool,
}

impl Learned {
    /// How many distinct exec targets one run records. Far above what any real cage reaches (a
    /// toolchain plus an agent is tens of programs, not thousands) and low enough that a cage
    /// spinning fresh paths cannot spend the supervisor's memory on them.
    pub(crate) const CAP: usize = 4096;

    /// Record one target a decision was taken against. Called at the decision point, so what is
    /// learned is what the policy was actually asked about — including the interpreter of a script
    /// and the program a dynamic loader names, neither of which the `execve` itself carried.
    ///
    /// An absolute target is stored folded ([`proc_policy::lexical_path`]), the spelling the policy
    /// decides against, so `/usr//bin/git` and `/usr/bin/git` are one program and a rule
    /// synthesized from either is written in the form it matches. A relative target is kept as the
    /// cage spelled it: folding `./build.sh` to `build.sh` would drop the `/` that makes a `path`
    /// rule a path rule.
    pub(crate) fn record(&self, target: &str) {
        self.insert(&self.targets, target);
    }

    /// Record a target a live `--session` deny rule refused and the config's own rules did not.
    pub(crate) fn record_session_denied(&self, target: &str) {
        self.insert(&self.session_denied, target);
    }

    fn insert(&self, into: &std::sync::Mutex<BTreeSet<String>>, target: &str) {
        let target = if target.starts_with('/') {
            proc_policy::lexical_path(target)
        } else {
            std::borrow::Cow::Borrowed(target)
        };
        // A poisoned lock still holds a consistent set: nothing panics between the check and the
        // insert below, so the learning a run has done is kept rather than dropped.
        let mut set = into
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if set.contains(target.as_ref()) {
            return; // the hot path: the same program run again allocates nothing
        }
        if set.len() >= Self::CAP {
            self.truncated
                .store(true, std::sync::atomic::Ordering::Relaxed);
            return;
        }
        set.insert(target.into_owned());
    }

    /// The targets recorded so far. Read once the workload has exited: nothing execs after that, so
    /// the set is the run's.
    pub(crate) fn snapshot(&self) -> Record {
        let read = |set: &std::sync::Mutex<BTreeSet<String>>| {
            set.lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clone()
        };
        Record {
            targets: read(&self.targets),
            session_denied: read(&self.session_denied),
            truncated: self.truncated.load(std::sync::atomic::Ordering::Relaxed),
        }
    }
}

/// One run's exec record, as the synthesizer reads it.
#[derive(Debug, Default)]
pub(crate) struct Record {
    /// The distinct targets, absolute ones already folded to the spelling the policy matches
    /// against.
    pub(crate) targets: BTreeSet<String>,
    /// The targets a live `--session` deny rule refused during the run. Reported, never learned.
    pub(crate) session_denied: BTreeSet<String>,
    /// Whether [`Learned::CAP`] was reached, so the set is a prefix of what ran rather than all of
    /// it. Carried beside the targets because a short allowlist and a truncated record look the same
    /// from the outside, and only one of them is safe to act on.
    pub(crate) truncated: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(targets: &[&str]) -> Record {
        Record {
            targets: targets.iter().map(|t| (*t).to_string()).collect(),
            ..Record::default()
        }
    }

    fn policy(allow: &[&str], deny: &[&str]) -> ProcPolicy {
        let own = |v: &[&str]| v.iter().map(|s| (*s).to_string()).collect::<Vec<_>>();
        ProcPolicy::new(ProcMode::Enforce, &own(allow), &own(deny))
    }

    #[test]
    fn a_program_no_rule_names_becomes_a_rule_at_the_asked_width() {
        let rec = record(&["/nix/store/abc-git-2.51.0/bin/git", "/usr/bin/env"]);
        let by_name = synthesize(&rec, &policy(&[], &[]), Granularity::Name);
        assert_eq!(by_name.rules, vec!["env".to_string(), "git".to_string()]);
        let by_path = synthesize(&rec, &policy(&[], &[]), Granularity::Path);
        assert_eq!(
            by_path.rules,
            vec![
                "/nix/store/abc-git-2.51.0/bin/git".to_string(),
                "/usr/bin/env".to_string()
            ]
        );
    }

    #[test]
    fn a_program_an_existing_allow_already_names_is_not_proposed_again() {
        // Subsumption is asked of the compiled rules, not of the rule strings: `git` is a basename
        // rule, and the target is an absolute path. A string comparison would re-propose it on
        // every run and grow the list without bound.
        let synth = synthesize(
            &record(&["/nix/store/abc-git-2.51.0/bin/git"]),
            &policy(&["git"], &[]),
            Granularity::Name,
        );
        assert!(synth.rules.is_empty(), "{:?}", synth.rules);
        assert!(synth.notes.is_empty(), "{:?}", synth.notes);
    }

    #[test]
    fn a_program_a_deny_rule_names_is_never_turned_into_an_allow() {
        // It ran (the run was under `enforce`, where a deny that did not match lets it through, or
        // the rule was added between runs) — but deny wins in the matcher, so an allow beside it
        // would be inert, and writing one would read as undoing a refusal its author meant.
        let synth = synthesize(
            &record(&["/usr/bin/curl"]),
            &policy(&[], &["curl"]),
            Granularity::Name,
        );
        assert!(synth.rules.is_empty(), "{:?}", synth.rules);
        assert_eq!(synth.notes.len(), 1);
        assert!(
            synth.notes[0].contains("curl") && synth.notes[0].contains("deny"),
            "{}",
            synth.notes[0]
        );
    }

    #[test]
    fn a_cut_record_says_so_before_the_rules_it_produced() {
        let rec = Record {
            targets: ["/usr/bin/git"].iter().map(|t| t.to_string()).collect(),
            truncated: true,
            ..Record::default()
        };
        let synth = synthesize(&rec, &policy(&[], &[]), Granularity::Name);
        assert_eq!(synth.rules, vec!["git".to_string()]);
        assert!(
            synth
                .notes
                .first()
                .is_some_and(|n| n.contains("stopped at")),
            "a truncated record must be reported first: {:?}",
            synth.notes
        );
    }

    #[test]
    fn nothing_is_emitted_that_the_write_path_would_refuse() {
        // The synthesizer's output goes straight to a config file, so every rule must pass the same
        // gate `sbx proc allow` passes. A target that cannot make one is reported, never dropped.
        let rec = record(&["/usr/bin/git", "/tmp/dir/", "/usr/bin/a\u{7}b"]);
        for gran in [Granularity::Name, Granularity::Path] {
            let synth = synthesize(&rec, &policy(&[], &[]), gran);
            for rule in &synth.rules {
                assert!(
                    proc_policy::validate_rule(rule).is_ok(),
                    "{gran:?} emitted a rule the write path refuses: {rule:?}"
                );
            }
            assert_eq!(
                synth.rules.len() + synth.notes.len(),
                rec.targets.len(),
                "{gran:?} accounted for {} of {} targets: {:?} / {:?}",
                synth.rules.len() + synth.notes.len(),
                rec.targets.len(),
                synth.rules,
                synth.notes
            );
        }
    }

    #[test]
    fn a_name_the_grammar_would_read_as_more_than_itself_is_reported_not_learned() {
        // `*` and `?` are always wildcards and surrounding whitespace is trimmed when a rule is
        // compiled, so each of these would be written as a rule admitting other programs.
        let rec = record(&["/tmp/*", "/tmp/a?c", "/tmp/ git", "/tmp/git ", ".."]);
        for gran in [Granularity::Name, Granularity::Path] {
            let synth = synthesize(&rec, &policy(&[], &[]), gran);
            let widened: Vec<&String> = synth
                .rules
                .iter()
                .filter(|r| r.contains(['*', '?']) || r.trim() != r.as_str() || *r == "..")
                .collect();
            assert!(widened.is_empty(), "{gran:?} learned {widened:?}");
            assert_eq!(
                synth.rules.len() + synth.notes.len(),
                rec.targets.len(),
                "{gran:?} dropped a target in silence: {:?} / {:?}",
                synth.rules,
                synth.notes
            );
        }
        let by_name = synthesize(&rec, &policy(&[], &[]), Granularity::Name);
        assert!(by_name.rules.is_empty(), "{:?}", by_name.rules);
        assert_eq!(
            by_name.notes.len(),
            rec.targets.len(),
            "{:?}",
            by_name.notes
        );
    }

    #[test]
    fn a_target_is_recorded_in_the_spelling_the_policy_decides_against() {
        let learned = Learned::default();
        for spelling in [
            "/usr/bin/git",
            "/usr//bin/git",
            "/usr/./bin/git",
            "/usr/lib/../bin/git",
        ] {
            learned.record(spelling);
        }
        let snap = learned.snapshot();
        assert_eq!(
            snap.targets.iter().collect::<Vec<_>>(),
            vec!["/usr/bin/git"],
            "every spelling of one program is one target"
        );
        let synth = synthesize(&snap, &policy(&[], &[]), Granularity::Path);
        assert_eq!(synth.rules, vec!["/usr/bin/git".to_string()]);
    }

    #[test]
    fn a_path_rule_is_always_a_path_rule() {
        // `path` is the strict reading: every rule it writes must compile as a path rule, never as
        // a name rule admitting the basename anywhere. Relative targets are where that can slip.
        let learned = Learned::default();
        for target in [
            "./build.sh",
            "build.sh",
            "a/../x",
            "../tool",
            "/usr//bin/git",
        ] {
            learned.record(target);
        }
        let snap = learned.snapshot();
        let synth = synthesize(&snap, &policy(&[], &[]), Granularity::Path);
        for rule in &synth.rules {
            assert!(rule.contains('/'), "`path` wrote a name rule: {rule:?}");
        }
        assert!(
            synth.rules.contains(&"./build.sh".to_string()),
            "{:?}",
            synth.rules
        );
        assert!(
            synth.rules.contains(&"/usr/bin/git".to_string()),
            "{:?}",
            synth.rules
        );
        assert_eq!(
            synth.rules.len() + synth.notes.len(),
            snap.targets.len(),
            "{:?} / {:?}",
            synth.rules,
            synth.notes
        );
    }

    #[test]
    fn a_target_a_session_deny_refused_is_reported_never_learned() {
        let learned = Learned::default();
        learned.record("/usr/bin/git");
        learned.record("/usr/bin/curl");
        learned.record_session_denied("/usr/bin/curl");
        learned.record_session_denied("/usr/bin/wget");
        let snap = learned.snapshot();
        for gran in [Granularity::Name, Granularity::Path] {
            let synth = synthesize(&snap, &policy(&[], &[]), gran);
            assert!(
                synth
                    .rules
                    .iter()
                    .all(|r| !r.contains("curl") && !r.contains("wget")),
                "{gran:?} learned a refused target: {:?}",
                synth.rules
            );
            assert_eq!(synth.rules.len(), 1, "{:?}", synth.rules);
            for refused in ["curl", "wget"] {
                assert!(
                    synth
                        .notes
                        .iter()
                        .any(|n| n.contains(refused) && n.contains("--session")),
                    "{gran:?} did not report {refused}: {:?}",
                    synth.notes
                );
            }
        }
    }

    #[test]
    fn a_poisoned_record_keeps_what_it_learned_and_goes_on_learning() {
        let learned = std::sync::Arc::new(Learned::default());
        learned.record("/usr/bin/git");
        let held = learned.clone();
        let _ = std::thread::spawn(move || {
            let _guard = held.targets.lock().unwrap();
            panic!("poison the record");
        })
        .join();
        assert!(learned.targets.is_poisoned());
        learned.record("/usr/bin/env");
        let snap = learned.snapshot();
        assert_eq!(
            snap.targets.iter().collect::<Vec<_>>(),
            vec!["/usr/bin/env", "/usr/bin/git"]
        );
    }

    #[test]
    fn the_record_stops_growing_at_its_cap_and_says_that_it_did() {
        let learned = Learned::default();
        for i in 0..Learned::CAP + 10 {
            learned.record(&format!("/usr/bin/p{i}"));
        }
        let snap = learned.snapshot();
        assert_eq!(snap.targets.len(), Learned::CAP);
        assert!(snap.truncated);
        // A target already held is still accepted at the cap: the set is what bounds it, so a busy
        // cage re-running the same program must not be reported as truncated for doing so.
        let fresh = Learned::default();
        for _ in 0..Learned::CAP + 10 {
            fresh.record("/usr/bin/git");
        }
        let snap = fresh.snapshot();
        assert_eq!(snap.targets.len(), 1);
        assert!(!snap.truncated);
    }
}
