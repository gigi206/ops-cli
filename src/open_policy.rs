//! The open/content policy: which file contents an in-cage agent may be handed, and the pure verdict
//! a parked `openat` is decided against.
//!
//! This is the content analogue of [`crate::proc_policy`]: a pure, I/O-free matcher that a config
//! resolves into and that the host-side enforcement supervisor
//! ([`crate::sandbox::proc_enforce`]) consults for every notified open. Keeping it pure means the
//! matching semantics — which are security-relevant — are unit-tested without a cage, and the
//! supervisor keeps the one thing it cannot delegate: reading the bytes.
//!
//! ## Why the whole set is one automaton
//!
//! A deployment names the credential shapes it cares about, and that list is long: dozens of vendor
//! token prefixes, key headers, and per-project shapes. Running one search per pattern would make
//! the scan cost grow with the list, so the policy compiles every pattern into a single
//! [`regex::bytes::RegexSet`] and walks the bytes **once**, whatever the list's length. The set is
//! built at launch, never per open.
//!
//! It matches over **bytes**, not `str`. A file an agent opens is arbitrary content, and a scanner
//! that first had to prove UTF-8 would refuse to look at exactly the archives and binaries a
//! credential can also sit in.
//!
//! ## Two questions, two costs
//!
//! Deciding an open asks only *is there a match* — [`OpenPolicy::verdict`] stops at the first one.
//! Naming the pattern for the refusal message is a second, more expensive question, so
//! [`OpenPolicy::matched_names`] is asked **only about content already refused**: the hot path pays
//! for the answer it needs, and the rare path pays for the answer a person reads.
//!
//! ## The scan is bounded, and says so
//!
//! Content past [`OpenPolicy::max_scan`] is not examined. A verdict therefore carries how much of
//! the content it covers ([`Scanned`]), so a caller can report a partial scan as partial rather than
//! present it as a clean bill of health — the rule the WebSocket capture already applies to a
//! message that inflates past its own ceiling.

use regex::bytes::{RegexSet, RegexSetBuilder};

/// The most content one open's scan examines, in bytes, when the policy does not name its own.
///
/// A credential is short and sits near the top of the files that carry one — an `.env`, a config, a
/// key file. The ceiling exists so that opening a large artefact costs a bounded read rather than
/// its whole length, and it is the number a deployment raises when its secrets live further in.
pub(crate) const MAX_SCAN_DEFAULT: usize = 1 << 20;

/// The compiled-program ceiling for the whole set, in bytes.
///
/// `regex`'s own default is per-pattern and sized for a handful of them; a set naming hundreds of
/// credential shapes exceeds it long before the memory matters. Raising it keeps a long list
/// compilable, and keeps the failure — when it comes — a named refusal at launch rather than a
/// pattern silently dropped.
const SET_SIZE_LIMIT: usize = 32 << 20;

/// How much of the content a verdict covers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Scanned {
    /// Every byte of the content was examined.
    Whole,
    /// Only the first `usize` bytes were examined; the rest was not looked at.
    Truncated(usize),
}

impl Scanned {
    /// Whether anything was left unexamined — what a caller reports rather than hides.
    pub(crate) fn is_partial(self) -> bool {
        matches!(self, Scanned::Truncated(_))
    }
}

/// What the policy says about one file's content.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Verdict {
    /// Whether any pattern matched the examined bytes.
    pub(crate) matched: bool,
    /// How much of the content the answer rests on.
    pub(crate) scanned: Scanned,
}

/// The resolved content policy: the patterns a launch scans opened files for.
#[derive(Debug, Clone)]
pub(crate) struct OpenPolicy {
    set: RegexSet,
    /// The pattern strings, in the set's own index order, so a match can be named.
    ///
    /// Kept beside the set rather than read back from it because a refusal names what the *config*
    /// said, which is what a person can go and edit.
    names: Vec<String>,
    max_scan: usize,
}

/// Whether one configured pattern is a regex this scanner can carry.
///
/// Exposed so the config layer can refuse an entry where the user can still see which line is
/// wrong, rather than failing the whole launch at scan-build time with the set's own error.
pub(crate) fn validate_pattern(pattern: &str) -> Result<(), String> {
    regex::bytes::RegexBuilder::new(pattern)
        .size_limit(SET_SIZE_LIMIT)
        .build()
        .map(|_| ())
        .map_err(|e| e.to_string())
}

impl OpenPolicy {
    /// Compile a policy from its configured patterns.
    ///
    /// An empty list yields `None`: a policy that can never match is not a policy, and the caller
    /// skips the lens entirely rather than paying a notification per open to always allow.
    ///
    /// A pattern that does not compile fails the whole build, naming the offender. A launch that
    /// dropped it would run believing it scans for a shape it never looks at.
    pub(crate) fn compile(patterns: &[String], max_scan: usize) -> Result<Option<Self>, String> {
        if patterns.is_empty() {
            return Ok(None);
        }
        // Validated one at a time first: `RegexSet`'s own error names the set, not the entry, and a
        // person editing a list of hundreds needs the one that is wrong.
        for pattern in patterns {
            regex::bytes::RegexBuilder::new(pattern)
                .size_limit(SET_SIZE_LIMIT)
                .build()
                .map_err(|e| format!("the pattern `{pattern}` is not a valid regex: {e}"))?;
        }
        let set = RegexSetBuilder::new(patterns)
            .size_limit(SET_SIZE_LIMIT)
            .build()
            .map_err(|e| {
                format!(
                    "the {} patterns do not compile into one scanner: {e}",
                    patterns.len()
                )
            })?;
        Ok(Some(OpenPolicy {
            set,
            names: patterns.to_vec(),
            max_scan: max_scan.max(1),
        }))
    }

    /// The most content one scan examines.
    pub(crate) fn max_scan(&self) -> usize {
        self.max_scan
    }

    /// Whether `content` carries any configured shape.
    ///
    /// One pass over the bytes whatever the pattern count, stopping at the first match: the answer
    /// an open needs is whether *some* pattern hit, never which.
    pub(crate) fn verdict(&self, content: &[u8]) -> Verdict {
        let (window, scanned) = self.window(content);
        Verdict {
            matched: self.set.is_match(window),
            scanned,
        }
    }

    /// The patterns that matched, for the message a refusal shows.
    ///
    /// Deliberately separate from [`OpenPolicy::verdict`]: this walks the set to completion, so it
    /// is asked once about content already refused and never on the deciding path.
    pub(crate) fn matched_names(&self, content: &[u8]) -> Vec<&str> {
        let (window, _) = self.window(content);
        self.set
            .matches(window)
            .into_iter()
            .filter_map(|i| self.names.get(i).map(String::as_str))
            .collect()
    }

    /// The prefix of `content` this policy examines, and what that leaves out.
    fn window<'a>(&self, content: &'a [u8]) -> (&'a [u8], Scanned) {
        if content.len() > self.max_scan {
            (&content[..self.max_scan], Scanned::Truncated(self.max_scan))
        } else {
            (content, Scanned::Whole)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy(patterns: &[&str]) -> OpenPolicy {
        let owned: Vec<String> = patterns.iter().map(|p| (*p).to_string()).collect();
        OpenPolicy::compile(&owned, MAX_SCAN_DEFAULT)
            .expect("the test patterns compile")
            .expect("a non-empty list yields a policy")
    }

    #[test]
    fn an_empty_pattern_list_is_no_policy_at_all() {
        let none =
            OpenPolicy::compile(&[], MAX_SCAN_DEFAULT).expect("an empty list is not an error");
        assert!(
            none.is_none(),
            "an empty list must not build a scanner the supervisor would consult per open"
        );
    }

    #[test]
    fn a_configured_shape_is_found_anywhere_in_the_content() {
        let p = policy(&[r"sk-[A-Za-z0-9]{12,}", r"AKIA[0-9A-Z]{16}"]);
        assert!(p.verdict(b"API key: sk-ABC123DEF456GHI789\n").matched);
        assert!(
            p.verdict(b"\n\n\n  aws = AKIA1234567890ABCDEF\n").matched,
            "a shape is not required to sit at the start of the content"
        );
        assert!(
            !p.verdict(b"just ordinary prose about sk- and AKIA\n")
                .matched,
            "a prefix alone is not the shape: the pattern's own length rule decides"
        );
    }

    #[test]
    fn content_that_is_not_utf8_is_still_scanned() {
        let p = policy(&[r"sk-[A-Za-z0-9]{12,}"]);
        let mut content = vec![0xff, 0xfe, 0x00, 0x80];
        content.extend_from_slice(b"sk-ABC123DEF456GHI789");
        content.push(0xff);
        assert!(
            p.verdict(&content).matched,
            "a credential inside a binary file must be found: refusing to look at non-UTF-8 would \
             leave the shapes an archive carries unscanned"
        );
    }

    #[test]
    fn the_scan_says_when_it_did_not_look_at_everything() {
        let owned = vec![r"sk-[A-Za-z0-9]{12,}".to_string()];
        let p = OpenPolicy::compile(&owned, 16)
            .expect("the pattern compiles")
            .expect("a non-empty list yields a policy");
        let mut content = vec![b'.'; 64];
        content.extend_from_slice(b"sk-ABC123DEF456GHI789");

        let v = p.verdict(&content);
        assert!(
            !v.matched,
            "the shape sits past the ceiling, so it is not seen"
        );
        assert_eq!(
            v.scanned,
            Scanned::Truncated(16),
            "a verdict that covers a prefix must carry how far it looked"
        );
        assert!(
            v.scanned.is_partial(),
            "a partial scan must be reportable as partial rather than read as a clean result"
        );

        // Content that fits under the same ceiling is covered whole, so the two answers are
        // distinguishable: one rests on everything, the other on a prefix.
        let whole = p.verdict(b"sk-ABCDEFGHIJKL");
        assert!(whole.matched);
        assert_eq!(whole.scanned, Scanned::Whole);
        assert!(!whole.scanned.is_partial());
    }

    #[test]
    fn a_refusal_can_name_every_shape_it_found() {
        let p = policy(&[
            r"sk-[A-Za-z0-9]{12,}",
            r"AKIA[0-9A-Z]{16}",
            r"ghp_[A-Za-z0-9]{36}",
        ]);
        let content = b"sk-ABC123DEF456GHI789 and AKIA1234567890ABCDEF";
        let named = p.matched_names(content);
        assert_eq!(
            named,
            vec![r"sk-[A-Za-z0-9]{12,}", r"AKIA[0-9A-Z]{16}"],
            "the message names the patterns as the config wrote them, so they can be edited"
        );
        assert!(
            p.matched_names(b"nothing here").is_empty(),
            "content that passes names nothing"
        );
    }

    #[test]
    fn a_pattern_that_does_not_compile_names_itself_and_fails_the_build() {
        let owned = vec![r"sk-[A-Za-z0-9]{12,}".to_string(), r"(unclosed".to_string()];
        let err = OpenPolicy::compile(&owned, MAX_SCAN_DEFAULT)
            .expect_err("a broken pattern must not build a policy");
        assert!(
            err.contains("(unclosed"),
            "the error names the offending entry, not the set: {err}"
        );
        assert!(
            !err.contains("sk-["),
            "the valid entry is not implicated in the other's failure: {err}"
        );
    }

    #[test]
    fn hundreds_of_patterns_compile_into_one_scanner() {
        let owned: Vec<String> = (0..500)
            .map(|i| format!(r"tok{i}-[A-Za-z0-9]{{10,}}"))
            .collect();
        let p = OpenPolicy::compile(&owned, MAX_SCAN_DEFAULT)
            .expect("a long list compiles")
            .expect("a non-empty list yields a policy");
        assert!(
            p.verdict(b"here is tok499-ABCDEFGHIJ in the text").matched,
            "the last entry of a long list is scanned for like the first"
        );
        assert!(!p.verdict(b"here is tok500-ABCDEFGHIJ in the text").matched);
    }
}
