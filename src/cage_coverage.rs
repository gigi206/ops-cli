//! Tests that the two runs claiming to exercise the cage name every suite that needs one.
//!
//! `cargo test` counts a test that returns early as **passed**, so a suite whose prerequisites are
//! absent reports green over work it never did. Two runs exist to answer that — `mise run test-cage`
//! locally and the `Cage` workflow on a runner given the prerequisites — and both name their suites
//! in a written-out list rather than globbing the directory. That choice is deliberate and stated in
//! both files: a new suite should be a deliberate addition, not a silent inclusion.
//!
//! What the choice does not do by itself is notice an **omission**. The lists were hand-kept in two
//! places with a comment asking they be held in step, which is the shape every drift in this
//! repository has taken. Measured on 2026-08-21: fifteen suites carry a host-capability skip and
//! both lists named fourteen, `projects` having been added after the lists were written.
//!
//! So the list stays written out, and this is what makes forgetting it impossible. The addition is
//! still deliberate; only the silence is gone.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

/// The repository root, so a test reads the same files a reader would open.
fn root() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
}

/// The suites that carry a host-capability skip: the population both runs mean to name.
///
/// `skip_incapable!` and not `skip_unreachable!`, and the distinction is the whole rule. The first
/// says *this host* lacks userns, bwrap, nix or systemd — exactly what these runs provide, so a
/// suite carrying one belongs in them. The second says something outside the host is unavailable (a
/// cache, a registry, the network), which no runner setting makes dependable and which therefore
/// says nothing about whether the cage was exercised.
///
/// **The distinction has no subject in today's tree, and that is written here rather than left to be
/// rediscovered.** Measured on 2026-08-21: only `run` carries a `skip_unreachable!` (62 of them),
/// and it carries 106 `skip_incapable!` besides, so relaxing this predicate to any `skip_` selects
/// the same fifteen suites and a mutation doing so survives. The rule is still the right one — it is
/// the one both runs state — and it starts to bite the day a suite carries only the unenforceable
/// kind. Until then this test cannot tell the two apart, and a reader should not assume it can.
fn suites_carrying_a_cage_skip() -> BTreeSet<String> {
    let dir = root().join("tests");
    let mut out = BTreeSet::new();
    for entry in std::fs::read_dir(&dir).expect("the integration test directory is readable") {
        let path: PathBuf = entry.expect("a readable directory entry").path();
        if path.extension().and_then(|e| e.to_str()) != Some("rs") {
            continue;
        }
        let text = std::fs::read_to_string(&path).expect("an integration suite is readable");
        if text.contains("skip_incapable!")
            && let Some(stem) = path.file_stem().and_then(|s| s.to_str())
        {
            out.insert(stem.to_string());
        }
    }
    assert!(
        out.len() > 5,
        "the scan found only {} suite(s) carrying a cage skip, so it has stopped matching the \
         source's shape and this test would pass vacuously",
        out.len()
    );
    out
}

/// The suites a run spells out, read from its single `for suite in … ; do` line.
///
/// Both files write that loop the same way, so one reader serves both. A file that stops carrying
/// the line fails here rather than returning an empty set that would agree with nothing.
fn named_suites(relative: &str) -> BTreeSet<String> {
    let path = root().join(relative);
    let text =
        std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{relative} is readable: {e}"));
    let mut found: Option<BTreeSet<String>> = None;
    for line in text.lines() {
        let Some(rest) = line.trim().strip_prefix("for suite in ") else {
            continue;
        };
        let Some(names) = rest.split(';').next() else {
            continue;
        };
        let set: BTreeSet<String> = names.split_whitespace().map(str::to_string).collect();
        assert!(
            found.is_none(),
            "{relative} carries more than one `for suite in` line, so this reader cannot tell \
             which one runs the suites"
        );
        found = Some(set);
    }
    found.unwrap_or_else(|| {
        panic!("{relative} carries no `for suite in … ; do` line — the reader has gone stale")
    })
}

#[test]
fn both_cage_runs_name_every_suite_that_carries_a_cage_skip() {
    // Both lists are pinned to the same set in both directions, which is also what makes them
    // equal to each other: a separate "the two runs agree" test was written here and removed, having
    // no state in which it could fail while this one passed. A test that cannot go red on its own is
    // not a second guarantee, it is a second thing to read.
    let expected = suites_carrying_a_cage_skip();
    for run in [".github/workflows/cage.yml", "mise.toml"] {
        let named = named_suites(run);
        let missing: Vec<_> = expected.difference(&named).cloned().collect();
        let extra: Vec<_> = named.difference(&expected).cloned().collect();
        assert!(
            missing.is_empty(),
            "{run} does not name {missing:?}, which carry a `skip_incapable!` and so are exactly \
             the suites a hosted runner passes without running. Add them to its list."
        );
        assert!(
            extra.is_empty(),
            "{run} names {extra:?}, which carry no `skip_incapable!`. Either the suite lost its \
             skip and the name should go, or the skip was spelled `skip_unreachable!`, which no \
             runner setting can satisfy."
        );
    }
}
