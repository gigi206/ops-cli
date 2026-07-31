//! The process/exec policy: what an in-cage agent is allowed to `execve`, and the pure verdict a
//! parked syscall is decided against.
//!
//! This is the exec analogue of [`crate::allowlist`]'s `EgressPolicy`: a pure, I/O-free matcher that a
//! trusted config resolves into and that the host-side enforcement supervisor
//! ([`crate::sandbox::proc_enforce`]) consults for every notified `execve`. Keeping it pure means the
//! matching semantics — which are security-relevant — are unit-tested without a cage.
//!
//! ## Posture (denylist, deny-wins)
//!
//! The default posture is a **denylist**: everything is allowed except an explicit `deny` entry, so a
//! coding agent that spawns constantly is not bricked while specific dangerous binaries (`curl`,
//! `ssh`, …) are blocked *before the syscall runs*. `deny` always wins over `allow` (an entry in both
//! is denied), mirroring the egress rule. The two enforcing modes differ only in what an **unmatched**
//! target does: [`Enforce`](ProcMode::Enforce) allows it (static denylist), [`Ask`](ProcMode::Ask)
//! parks it for an interactive decision.
//!
//! ## Rule grammar
//!
//! A rule is a shell-style glob (`*` = any run, `?` = one character). A rule containing `/` matches
//! the **full exec path** (`/usr/bin/*`, `/nix/store/*/bin/git`); a rule without `/` matches the
//! target's **basename** (`curl` matches `/usr/bin/curl`), so a tool is named the way a user thinks of
//! it. Matching is exact otherwise — `curl` never matches `curlish`.

/// The process/exec lens mode, resolved from `[proc] mode`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) enum ProcMode {
    /// The lens is disabled — no capture, no enforcement.
    #[default]
    Off,
    /// Capture only (the cheap `/proc` poll), no enforcement. The exec feed may miss a command shorter
    /// than a poll tick; blocking is not in effect.
    Observe,
    /// Enforce a static denylist via the seccomp user-notification supervisor: `deny` targets return
    /// `EPERM` (the syscall never runs), everything else is allowed.
    Enforce,
    /// Enforce interactively: `deny` targets return `EPERM`, `allow` targets run, and an **unmatched**
    /// target is parked for a live `sbx proc allow`/`deny` decision.
    Ask,
    /// Enforce a strict **allowlist**: only an `allow` match runs; anything unmatched is refused. The
    /// inverse posture of [`Enforce`](ProcMode::Enforce), for a cage whose whole program set is known
    /// up front — a declared task's, where the command is fixed and what it may run is declared beside
    /// it. Not reachable from `[proc] mode`: a posture that refuses everything undeclared is only
    /// honest where the declaration enumerates the programs, which a general agent's does not.
    Confine,
}

impl ProcMode {
    /// Parse the `[proc] mode` string. An unknown value fails closed to [`Off`](ProcMode::Off) with
    /// `None`, so the caller can warn — an unrecognised posture must never silently enforce or
    /// silently disable in a surprising direction.
    pub(crate) fn parse(s: &str) -> Option<ProcMode> {
        match s {
            "off" => Some(ProcMode::Off),
            "observe" => Some(ProcMode::Observe),
            "enforce" => Some(ProcMode::Enforce),
            "ask" => Some(ProcMode::Ask),
            _ => None,
        }
    }

    /// The canonical string for this mode, used by `sbx config show` and the one-shot override
    /// display. Every mode a config can *write* round-trips [`parse`](ProcMode::parse);
    /// [`Confine`](ProcMode::Confine) deliberately does not, because it has no config spelling — it
    /// is reached only by a declaration that enumerates the programs it admits. Adding it to `parse`
    /// would offer a refuse-everything-undeclared posture to a config that cannot say what the
    /// exceptions are.
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            ProcMode::Off => "off",
            ProcMode::Observe => "observe",
            ProcMode::Enforce => "enforce",
            ProcMode::Ask => "ask",
            ProcMode::Confine => "confine",
        }
    }

    /// Whether this mode stands up the seccomp user-notification enforcement path (the in-cage shim +
    /// host supervisor). `enforce`, `ask` and `confine` do; `off`/`observe` do not.
    pub(crate) fn enforcing(self) -> bool {
        matches!(self, ProcMode::Enforce | ProcMode::Ask | ProcMode::Confine)
    }
}

/// One compiled exec rule: the raw text (kept for display) plus whether it matches the full path or a
/// basename.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ProcRule {
    raw: String,
    /// A rule with a `/` matches the whole exec path; without one, it matches the target's basename.
    on_path: bool,
}

impl ProcRule {
    /// Compile a rule string. Always succeeds (there is no invalid glob — an unbalanced `*` just
    /// matches literally); an empty string is a rule that never matches (the config layer drops empties
    /// before they get here, but the matcher stays total).
    pub(crate) fn new(raw: &str) -> ProcRule {
        ProcRule {
            raw: raw.to_string(),
            on_path: raw.contains('/'),
        }
    }

    /// The raw rule text, for `sbx config show` / the wire.
    pub(crate) fn as_str(&self) -> &str {
        &self.raw
    }

    /// Whether this rule matches an exec target. A path rule globs the whole `path`; a basename rule
    /// globs the final component.
    fn matches(&self, path: &str, basename: &str) -> bool {
        let subject = if self.on_path { path } else { basename };
        glob_match(&self.raw, subject)
    }
}

/// Validate a rule string before it is persisted to a config file or injected into a live session.
/// [`ProcRule::new`] is total (any string compiles), so this is the fail-closed gate the write and
/// `--session` paths share: a rule must be non-empty after trimming and carry no control character —
/// a newline would break the line-based control-socket framing, and a control byte has no place in an
/// exec path or basename — and stay within a sane length. Returns a human reason on refusal.
pub(crate) fn validate_rule(rule: &str) -> Result<(), String> {
    let trimmed = rule.trim();
    if trimmed.is_empty() {
        return Err("a rule must not be empty".to_string());
    }
    if trimmed.chars().any(char::is_control) {
        return Err("a rule must not contain control characters (including newlines)".to_string());
    }
    const MAX: usize = 256;
    if trimmed.chars().count() > MAX {
        return Err(format!("a rule must be at most {MAX} characters"));
    }
    Ok(())
}

/// The pure verdict for one exec target.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Verdict {
    /// Allow the `execve` (the supervisor answers `CONTINUE`).
    Allow,
    /// Deny the `execve` (the supervisor answers `EPERM`; the syscall never runs).
    Deny,
    /// Park the `execve` for an interactive decision (only reachable under [`ProcMode::Ask`]).
    Ask,
}

/// The resolved process/exec policy: the mode plus the classified allow/deny rules. Pure — the
/// enforcement supervisor calls [`decide`](ProcPolicy::decide) for every notified `execve`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub(crate) struct ProcPolicy {
    pub(crate) mode: ProcMode,
    pub(crate) allow: Vec<ProcRule>,
    pub(crate) deny: Vec<ProcRule>,
    /// Present when what may run depends on **who is running it**. Absent is the flat model, where
    /// one set governs the whole cage at any depth.
    pub(crate) graph: Option<CallerGraph>,
}

/// What each program may run, keyed by the program doing the running.
///
/// The key is the caller's executable as `/proc/<pid>/exe` reports it — an absolute in-cage path
/// with every symlink already followed, since that is what the kernel records. A program with no
/// entry may run **nothing**: there is no inheritance from whoever ran it, because inheritance would
/// hand back the very shortcut a graph exists to remove.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub(crate) struct CallerGraph {
    pub(crate) callers: std::collections::BTreeMap<String, Vec<ProcRule>>,
}

impl ProcPolicy {
    /// A disabled policy (the default when `[proc]` is absent).
    pub(crate) fn off() -> ProcPolicy {
        ProcPolicy {
            mode: ProcMode::Off,
            allow: Vec::new(),
            deny: Vec::new(),
            graph: None,
        }
    }

    /// A per-caller allowlist: an unmatched target is refused, and what is matched depends on which
    /// program is doing the running.
    pub(crate) fn confined(graph: CallerGraph) -> ProcPolicy {
        ProcPolicy {
            mode: ProcMode::Confine,
            allow: Vec::new(),
            deny: Vec::new(),
            graph: Some(graph),
        }
    }

    /// Build a policy from a mode and raw allow/deny rule strings, dropping empty entries.
    pub(crate) fn new(mode: ProcMode, allow: &[String], deny: &[String]) -> ProcPolicy {
        let compile = |rules: &[String]| {
            rules
                .iter()
                .filter(|r| !r.trim().is_empty())
                .map(|r| ProcRule::new(r.trim()))
                .collect()
        };
        ProcPolicy {
            mode,
            allow: compile(allow),
            deny: compile(deny),
            graph: None,
        }
    }

    /// Whether enforcement is in effect (`enforce`/`ask`).
    pub(crate) fn enforcing(&self) -> bool {
        self.mode.enforcing()
    }

    /// Decide one exec target. Deny-wins: a `deny` match is [`Deny`](Verdict::Deny) even if `allow`
    /// also matches. Otherwise an `allow` match is [`Allow`](Verdict::Allow). An **unmatched** target
    /// is [`Allow`](Verdict::Allow) under `enforce` (the denylist default), [`Ask`](Verdict::Ask)
    /// under `ask`, and [`Deny`](Verdict::Deny) under `confine` (the allowlist default); under a
    /// non-enforcing mode it is [`Allow`](Verdict::Allow) (decide is never called there, but the
    /// fallback is the safe, non-blocking one).
    pub(crate) fn decide(&self, caller: &[String], exec_path: &str) -> Verdict {
        self.decide_chain(caller, exec_path, &[], &[])
    }

    /// Decide one exec target for a caller addressed by its chain of programs, innermost **last**,
    /// folding in a live `--session` overlay's extra allow/deny rules on top of this config policy.
    /// **Deny wins across both sets**: an overlay `deny` cuts a config-allowed target, and a config
    /// `deny` cannot be overridden by an overlay `allow`.
    ///
    /// Under a [`CallerGraph`] only the last element is read — a node addresses a program, wherever
    /// that program was reached from. The whole chain is taken rather than the one program it uses,
    /// so that a chain-scoped address could be added without touching a single call site: an address
    /// that grows is a slice that grows.
    ///
    /// An **empty** chain against a graph matches nothing, which under `confine` is a refusal. That
    /// is the wanted answer for a caller whose program could not be read: the one execve that must
    /// not run is the one nothing can account for.
    pub(crate) fn decide_chain(
        &self,
        caller: &[String],
        exec_path: &str,
        overlay_allow: &[ProcRule],
        overlay_deny: &[ProcRule],
    ) -> Verdict {
        let basename = basename(exec_path);
        let any = |rules: &[ProcRule]| rules.iter().any(|r| r.matches(exec_path, basename));
        if any(&self.deny) || any(overlay_deny) {
            return Verdict::Deny;
        }
        if let Some(graph) = &self.graph {
            // Only the caller's own node answers. An overlay `allow` is deliberately not folded in
            // here: it arrives from a live control plane, and a per-caller policy is a task's, whose
            // plane has no such channel — while an overlay `deny`, decided above, still cuts.
            let allowed = caller.last().and_then(|c| graph.callers.get(c.as_str()));
            return match allowed {
                Some(rules) if any(rules) => Verdict::Allow,
                _ => self.unmatched(),
            };
        }
        if any(&self.allow) || any(overlay_allow) {
            return Verdict::Allow;
        }
        self.unmatched()
    }

    /// The verdict for a target no rule spoke about. Exhaustive on purpose: this default is the whole
    /// difference between a denylist and an allowlist, so a new posture must state its own rather
    /// than inherit a catch-all.
    pub(crate) fn unmatched(&self) -> Verdict {
        match self.mode {
            ProcMode::Ask => Verdict::Ask,
            ProcMode::Confine => Verdict::Deny,
            ProcMode::Off | ProcMode::Observe | ProcMode::Enforce => Verdict::Allow,
        }
    }
}

/// The final path component (the basename), or the whole string when there is no `/`. A trailing slash
/// yields an empty basename, which matches no non-empty rule — an exec target is never a directory.
fn basename(path: &str) -> &str {
    match path.rfind('/') {
        Some(i) => &path[i + 1..],
        None => path,
    }
}

/// A minimal shell-style glob match over bytes: `*` matches any run (including empty), `?` matches
/// exactly one character, everything else is literal. Iterative with backtracking (no recursion, so a
/// pathological pattern cannot blow the stack), O(pattern × text) worst case — the patterns here are
/// short, operator-authored config, so this is ample.
fn glob_match(pattern: &str, text: &str) -> bool {
    let p: Vec<char> = pattern.chars().collect();
    let t: Vec<char> = text.chars().collect();
    let (mut pi, mut ti) = (0usize, 0usize);
    // The last `*` seen and the text position to resume from if a later mismatch forces backtracking.
    let mut star: Option<usize> = None;
    let mut resume = 0usize;
    while ti < t.len() {
        if pi < p.len() && (p[pi] == '?' || p[pi] == t[ti]) {
            pi += 1;
            ti += 1;
        } else if pi < p.len() && p[pi] == '*' {
            star = Some(pi);
            resume = ti;
            pi += 1; // try matching `*` as empty first
        } else if let Some(s) = star {
            // Mismatch under an open `*`: let it swallow one more text char and retry.
            pi = s + 1;
            resume += 1;
            ti = resume;
        } else {
            return false;
        }
    }
    // Trailing `*`s in the pattern match the empty remainder.
    while pi < p.len() && p[pi] == '*' {
        pi += 1;
    }
    pi == p.len()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy(mode: ProcMode, allow: &[&str], deny: &[&str]) -> ProcPolicy {
        ProcPolicy::new(
            mode,
            &allow.iter().map(|s| s.to_string()).collect::<Vec<_>>(),
            &deny.iter().map(|s| s.to_string()).collect::<Vec<_>>(),
        )
    }

    #[test]
    fn glob_matches_star_and_question_and_literals() {
        assert!(glob_match("curl", "curl"));
        assert!(!glob_match("curl", "curlish"));
        assert!(!glob_match("curl", "url"));
        assert!(glob_match("py*", "python3"));
        assert!(glob_match("*", "anything"));
        assert!(glob_match("/usr/bin/*", "/usr/bin/git"));
        assert!(!glob_match("/usr/bin/*", "/usr/local/bin/git"));
        assert!(glob_match(
            "/nix/store/*/bin/git",
            "/nix/store/abc-git/bin/git"
        ));
        assert!(glob_match("c?rl", "curl"));
        assert!(!glob_match("c?rl", "crl"));
        // A trailing star swallows the rest, including empty.
        assert!(glob_match("git*", "git"));
    }

    #[test]
    fn basename_rule_matches_the_final_component_only() {
        let deny = policy(ProcMode::Enforce, &[], &["curl"]);
        assert_eq!(deny.decide(&[], "/usr/bin/curl"), Verdict::Deny);
        assert_eq!(deny.decide(&[], "curl"), Verdict::Deny);
        // A basename rule does not match a same-named directory prefix.
        assert_eq!(deny.decide(&[], "/opt/curl/bin/wget"), Verdict::Allow);
    }

    #[test]
    fn path_rule_matches_the_whole_path() {
        let deny = policy(ProcMode::Enforce, &[], &["/usr/bin/*"]);
        assert_eq!(deny.decide(&[], "/usr/bin/ssh"), Verdict::Deny);
        assert_eq!(deny.decide(&[], "/usr/local/bin/ssh"), Verdict::Allow);
    }

    #[test]
    fn deny_wins_over_allow() {
        let p = policy(ProcMode::Ask, &["curl"], &["curl"]);
        assert_eq!(p.decide(&[], "/usr/bin/curl"), Verdict::Deny);
    }

    #[test]
    fn enforce_allows_an_unmatched_target_but_ask_parks_it() {
        let enforce = policy(ProcMode::Enforce, &["git"], &["curl"]);
        assert_eq!(
            enforce.decide(&[], "/bin/rg"),
            Verdict::Allow,
            "denylist default-allow"
        );
        assert_eq!(enforce.decide(&[], "/usr/bin/curl"), Verdict::Deny);

        let ask = policy(ProcMode::Ask, &["git"], &["curl"]);
        assert_eq!(ask.decide(&[], "/usr/bin/git"), Verdict::Allow);
        assert_eq!(ask.decide(&[], "/usr/bin/curl"), Verdict::Deny);
        assert_eq!(
            ask.decide(&[], "/bin/rg"),
            Verdict::Ask,
            "unmatched under ask parks"
        );
    }

    #[test]
    fn empty_rules_are_dropped_and_off_is_never_enforcing() {
        let p = policy(ProcMode::Enforce, &["", "  "], &["curl", ""]);
        assert_eq!(p.allow.len(), 0, "blank allow entries dropped");
        assert_eq!(p.deny.len(), 1);
        assert!(!ProcPolicy::off().enforcing());
        assert!(policy(ProcMode::Enforce, &[], &[]).enforcing());
        assert!(policy(ProcMode::Ask, &[], &[]).enforcing());
        assert!(!policy(ProcMode::Observe, &[], &[]).enforcing());
    }

    #[test]
    fn mode_round_trips() {
        for m in [
            ProcMode::Off,
            ProcMode::Observe,
            ProcMode::Enforce,
            ProcMode::Ask,
        ] {
            assert_eq!(ProcMode::parse(m.as_str()), Some(m));
        }
        assert_eq!(ProcMode::parse("bogus"), None);
    }

    #[test]
    fn decide_with_folds_the_overlay_and_deny_wins() {
        let base = policy(ProcMode::Enforce, &["git"], &["curl"]);
        let one = |r: &str| vec![ProcRule::new(r)];

        // An overlay deny cuts a target the base would allow (unmatched → allow under enforce)…
        assert_eq!(
            base.decide_chain(&[], "/bin/wget", &[], &one("wget")),
            Verdict::Deny
        );
        // …while with no overlay that same target runs (denylist default-allow).
        assert_eq!(base.decide(&[], "/bin/wget"), Verdict::Allow);
        // Deny wins across BOTH sets: a base deny is not overridden by an overlay allow.
        assert_eq!(
            base.decide_chain(&[], "/bin/curl", &one("curl"), &[]),
            Verdict::Deny
        );
        // Under ask, an overlay allow un-parks an otherwise-unmatched target.
        let ask = policy(ProcMode::Ask, &[], &[]);
        assert_eq!(ask.decide(&[], "/bin/node"), Verdict::Ask);
        assert_eq!(
            ask.decide_chain(&[], "/bin/node", &one("node"), &[]),
            Verdict::Allow
        );
    }
}
