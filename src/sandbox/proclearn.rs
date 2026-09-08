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
/// `sbx proc allow` passes through), and never drops a target without a note.
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
    for target in &record.targets {
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
        if let Err(why) = proc_policy::validate_rule(rule) {
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
    pub(crate) fn record(&self, target: &str) {
        let Ok(mut set) = self.targets.lock() else {
            return; // a poisoned lock costs this run its learning, never the run itself
        };
        if set.len() >= Self::CAP && !set.contains(target) {
            self.truncated
                .store(true, std::sync::atomic::Ordering::Relaxed);
            return;
        }
        set.insert(target.to_string());
    }

    /// The targets recorded so far. Read once the workload has exited: nothing execs after that, so
    /// the set is the run's.
    pub(crate) fn snapshot(&self) -> Record {
        Record {
            targets: self.targets.lock().map(|s| s.clone()).unwrap_or_default(),
            truncated: self.truncated.load(std::sync::atomic::Ordering::Relaxed),
        }
    }
}

/// One run's exec record, as the synthesizer reads it.
#[derive(Debug, Default)]
pub(crate) struct Record {
    /// The distinct targets, already folded to the spelling the policy matches against.
    pub(crate) targets: BTreeSet<String>,
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
            truncated: false,
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
