//! Ordering two version strings, and naming the transitions a roll must not call a move forward.
//!
//! Both consumers face the same problem from opposite ends. `sbx plugins` compares an installed
//! build against the one a store lists; `sbx upgrade` compares the version a tool left against the
//! one it arrived at. Neither controls the string: a manifest's `version` is free-form, and an
//! upstream tag is whatever its publisher pushed. So the rule here is to rank only what is plainly
//! ranked and to say nothing otherwise — [`version_order`] answers `None` rather than guess.
//!
//! [`regression`] builds on that refusal instead of hiding it. A roll that cannot rank its two
//! versions has still learned something when their **shape** differs: `7.4.17` against
//! `jetbrains/v7.1.2` names a different release line, whereas `0.preview.70` against
//! `0.preview.91` is the same line with its digits advanced. The first is worth reporting, the
//! second is an ordinary roll, and [`version_form`] is what separates them.

use std::cmp::Ordering;

/// Order two version strings when — and only when — both are plainly ordered: dot-separated
/// numbers with an optional pre-release suffix after a `-`. A manifest's `version` is free-form,
/// and a store's is whatever it published, so anything else (a date, a git describe, a letter, an
/// overflowing component) yields `None` and the caller says "differs" instead of inventing a
/// direction. Guessing here would be the one failure mode that matters: telling a user they are
/// up to date when they are not.
pub(crate) fn version_order(a: &str, b: &str) -> Option<Ordering> {
    /// `(numeric components, pre-release)`, or `None` when the core is not plainly numeric.
    fn split(v: &str) -> Option<(Vec<u64>, Option<&str>)> {
        let v = v.trim().strip_prefix('v').unwrap_or(v.trim());
        let (core, pre) = match v.split_once('-') {
            Some((core, pre)) if !pre.is_empty() => (core, Some(pre)),
            Some(_) => return None,
            None => (v, None),
        };
        if core.is_empty() {
            return None;
        }
        let nums: Option<Vec<u64>> = core.split('.').map(|c| c.parse::<u64>().ok()).collect();
        nums.filter(|n| !n.is_empty()).map(|n| (n, pre))
    }
    let (a_nums, a_pre) = split(a)?;
    let (b_nums, b_pre) = split(b)?;
    // `1.8` against `1.8.2`: a missing component is zero, so the shorter one sorts first.
    for i in 0..a_nums.len().max(b_nums.len()) {
        let (x, y) = (
            a_nums.get(i).copied().unwrap_or(0),
            b_nums.get(i).copied().unwrap_or(0),
        );
        if x != y {
            return Some(x.cmp(&y));
        }
    }
    match (a_pre, b_pre) {
        // A release outranks a pre-release of the same core (`1.2.0` over `1.2.0-rc1`).
        (None, None) => Some(Ordering::Equal),
        (None, Some(_)) => Some(Ordering::Greater),
        (Some(_), None) => Some(Ordering::Less),
        // Two pre-releases: identical is equal, and anything else is not ours to rank
        // (`rc2` vs `beta` has no numeric answer).
        (Some(x), Some(y)) if x == y => Some(Ordering::Equal),
        (Some(_), Some(_)) => None,
    }
}

/// A version's shape, with every run of digits collapsed to `#`.
///
/// What survives is the punctuation and the words a publisher puts around its numbers, which is
/// the part that identifies a release *line*: `0.preview.70` and `0.preview.91` share `#.preview.#`
/// because only their digits moved, while `7.4.17` and `jetbrains/v7.1.2` do not, because the
/// second carries a namespace the first never had. Digit runs collapse rather than being dropped so
/// that a component appearing or vanishing still shows: `1.2` and `1.2.3` differ here.
fn version_form(v: &str) -> String {
    let mut form = String::with_capacity(v.len());
    let mut in_digits = false;
    for c in v.trim().chars() {
        if c.is_ascii_digit() {
            if !in_digits {
                form.push('#');
                in_digits = true;
            }
        } else {
            form.push(c);
            in_digits = false;
        }
    }
    form
}

/// Why a version transition cannot be called a move forward.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub(crate) enum Regression {
    /// The two versions settle it between them: the new one ranks below the old.
    Backward,
    /// They cannot be ranked and they do not share a shape, so the new version names a different
    /// release line rather than a later release of the same one.
    ChangedLine,
}

impl Regression {
    /// The past-tense word for what happened, for a report that names it on one line.
    pub(crate) fn describe(self) -> &'static str {
        match self {
            Regression::Backward => "downgraded",
            Regression::ChangedLine => "changed release line",
        }
    }
}

/// The part of a version that identifies its release line: everything before the first `-`.
///
/// The pre-release suffix is the free-form half [`version_order`] already declines to rank, and
/// `rc2` against `beta` is churn inside one line rather than a move to another one. Comparing
/// shapes past the dash would report that churn as a line change and bury the case worth seeing
/// under it.
fn release_line(v: &str) -> &str {
    let v = v.trim();
    v.split_once('-').map_or(v, |(core, _)| core)
}

/// Classify a `<old>` → `<new>` step, naming only the two shapes a roll must not present as a
/// move forward.
///
/// Everything else is `None`, and that includes a pair the versions cannot rank while the shape of
/// their release line holds. Reporting those would bury the two cases that matter under every tool
/// whose publisher spells a version in words, and a roll that advances `0.preview.70` to
/// `0.preview.91` has done exactly what it was asked to.
pub(crate) fn regression(old: &str, new: &str) -> Option<Regression> {
    match version_order(old, new) {
        Some(Ordering::Greater) => Some(Regression::Backward),
        Some(_) => None,
        None if version_form(release_line(old)) != version_form(release_line(new)) => {
            Some(Regression::ChangedLine)
        }
        None => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_order_refuses_to_guess_what_it_cannot_order() {
        assert_eq!(version_order("1.0.0", "1.1.0"), Some(Ordering::Less));
        assert_eq!(version_order("2", "1.9.9"), Some(Ordering::Greater));
        // A missing component is zero, so a shorter version sorts before a longer one.
        assert_eq!(version_order("1.8", "1.8.2"), Some(Ordering::Less));
        assert_eq!(version_order("1.8", "1.8.0"), Some(Ordering::Equal));
        assert_eq!(version_order("v1.2.3", "1.2.3"), Some(Ordering::Equal));
        // A release outranks its own pre-release; two different pre-releases have no numeric answer.
        assert_eq!(version_order("1.2.0", "1.2.0-rc1"), Some(Ordering::Greater));
        assert_eq!(
            version_order("1.2.0-rc1", "1.2.0-rc1"),
            Some(Ordering::Equal)
        );
        assert_eq!(version_order("1.2.0-rc2", "1.2.0-beta"), None);
        // Free-form strings: a manifest's `version` is not constrained, so these must not be
        // ranked. Claiming "up to date" from a bad guess is the failure that matters.
        assert_eq!(version_order("2026-08-01", "2026-08-02"), None);
        assert_eq!(version_order("1.0.0a", "1.0.1"), None);
        assert_eq!(version_order("latest", "1.0.0"), None);
        assert_eq!(version_order("", "1.0.0"), None);
    }

    #[test]
    fn version_form_keeps_everything_that_is_not_a_digit() {
        // Only the digits move within one release line, so its shape is what remains.
        assert_eq!(version_form("0.preview.70"), version_form("0.preview.91"));
        assert_eq!(version_form("7.4.17"), "#.#.#");
        assert_eq!(version_form("jetbrains/v7.1.2"), "jetbrains/v#.#.#");
        // A run collapses to one marker, so a longer number is not a different shape.
        assert_eq!(version_form("1.1.8"), version_form("1.1.22"));
        // A component appearing is a shape change: the separator has no digits to hide behind.
        assert_ne!(version_form("1.2"), version_form("1.2.3"));
    }

    #[test]
    fn regression_names_a_step_back_and_a_line_change_and_nothing_else() {
        assert_eq!(regression("7.4.17", "7.1.2"), Some(Regression::Backward));
        assert_eq!(
            regression("7.4.17", "jetbrains/v7.1.2"),
            Some(Regression::ChangedLine)
        );
        // Ordinary rolls, ranked or not, stay silent.
        assert_eq!(regression("1.1.8", "1.1.22"), None);
        assert_eq!(regression("0.preview.70", "0.preview.91"), None);
        assert_eq!(regression("0.146.0", "0.151.0"), None);
        // An unrankable pair whose release line keeps its shape is not a regression: two different
        // pre-releases of one core have no numeric answer, and the shape is compared before the
        // dash precisely so this churn does not read as a move to another line.
        assert_eq!(regression("1.2.0-rc2", "1.2.0-beta"), None);
        assert_eq!(regression("1.2.0-beta", "1.2.0-rc2"), None);
    }

    /// The transitions a real multi-app roll produced, held here so the classifier is measured
    /// against the shapes upstreams actually publish rather than against invented ones. Every pair
    /// but the last is an ordinary roll; the last is the one that changed release line.
    #[test]
    fn a_recorded_roll_flags_only_the_transition_that_changed_line() {
        let ordinary = [
            ("1.1.8", "1.1.22"),
            ("0.preview.70", "0.preview.91"),
            ("0.34.0", "0.36.0"),
            ("0.0.1785961745-gfab117", "0.0.1788206450-g69fb1a"),
            ("2.130.0", "2.143.0"),
            ("0.146.0", "0.151.0"),
            ("1.13.0", "1.39.2"),
            ("0.183.0", "0.208.2"),
            ("2651.6.0", "3013.3.0"),
            ("2026.7.1-2", "2026.8.1"),
            ("0.1.0-rc.6", "0.1.1-rc.2"),
            ("17.2.7", "18.0.11"),
            ("0.31.0", "0.39.1"),
            ("1.1.35", "1.1.37"),
            ("2.1.223", "2.1.251"),
        ];
        for (old, new) in ordinary {
            assert_eq!(regression(old, new), None, "{old} → {new}");
        }
        assert_eq!(
            regression("7.4.17", "jetbrains/v7.1.2"),
            Some(Regression::ChangedLine)
        );
    }
}
