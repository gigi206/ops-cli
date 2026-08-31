//! Helpers shared by the integration tests that sweep the **whole** command tree.
//!
//! `tests/help.rs` and `tests/completion.rs` each assert a property over every command and
//! subcommand, so both need the same answer to "what is the command tree?". That answer lives here,
//! in one definition: two copies drift, and a sweep walking a stale tree reports a coverage it does
//! not have — which is exactly what a hand-written list did here before, missing a third of the
//! surface while its header claimed to enumerate all of it.
//!
//! A shared test module is compiled *into* each test binary rather than linked once, so an item
//! only one sweep needs is dead code in the other — hence the module-wide allow, which says nothing
//! about the crate itself.
#![allow(dead_code)]

// The skip macros, included rather than linked: an integration test is its own crate and cannot see
// into the binary's `testskip` module, so both halves of the suite compile the same text. One
// definition -- a second copy would drift, and a skip counted by one half and not the other is
// worse than no count at all. Reach them with `#[macro_use] mod common;`.
include!("../../src/testskip.rs");

/// The fixture directory every suite creates its trees under, in one definition.
pub mod fixture;

use std::process::{Command, Output};

/// Run the binary under test with `args`.
pub fn sbx(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_sbx"))
        .args(args)
        .output()
        .expect("spawn sbx")
}

pub fn stdout_of(out: &Output) -> String {
    String::from_utf8_lossy(&out.stdout).into_owned()
}

/// The candidate names the completion oracle offers after `path`, for the given cursor word.
pub fn oracle(path: &[String], cursor: &str) -> Vec<String> {
    let mut argv: Vec<String> = vec!["__complete".into(), "--".into()];
    argv.extend(path.iter().cloned());
    argv.push(cursor.to_string());
    let borrowed: Vec<&str> = argv.iter().map(String::as_str).collect();
    stdout_of(&sbx(&borrowed))
        .lines()
        .filter_map(|l| l.split('\t').next().map(str::to_string))
        .collect()
}

/// Every command path the binary's completion can reach, found by walking it from the root.
///
/// The sweeps run over this rather than over a list kept by hand, so they cover whatever the binary
/// actually offers: a subcommand added tomorrow is swept the day it lands. The `help` verb mirrors
/// the whole tree beneath itself, so the walk covers each path twice, once directly and once
/// through `sbx help ...`; a caller wanting only the pages filters the mirrored half out.
///
/// Only names that resolve to a page are descended into: the menus also hold value vocabulary —
/// live ids, literal targets — that is machine state, not command tree, and walking into it would
/// loop on a real registry the moment one exists.
///
/// What this is **not**: an independent enumeration. The oracle and the help table are both fed by
/// the same page table, so a walk cannot notice a verb the dispatcher accepts and the table never
/// heard of. It answers "what does the binary declare?", and the sweeps assert that everything
/// declared behaves; the other direction is a property of the dispatch, not of a list.
pub fn walk() -> Vec<Vec<String>> {
    /// Whether a path names a page, and so is command tree rather than a value.
    ///
    /// A leading `help` is stripped before asking, because it is exactly what the page tree does
    /// not contain: `sbx help` has no page of its own (`sbx help help` is refused), so probing the
    /// path verbatim would answer "not a page" for `help` and prune the mirrored half of the tree —
    /// the half this walk exists to cover.
    fn is_page(path: &[String]) -> bool {
        let under_help = path.first().is_some_and(|w| w == "help");
        let probed: Vec<&str> = path
            .iter()
            .skip(usize::from(under_help))
            .map(String::as_str)
            .collect();
        // `sbx help` itself: a real verb, and the root of the mirror.
        if probed.is_empty() {
            return under_help;
        }
        let mut argv = vec!["help"];
        argv.extend(probed.iter().copied());
        let out = sbx(&argv);
        out.status.success() && stdout_of(&out).contains(&format!("sbx {} —", probed.join(" ")))
    }
    let mut found: Vec<Vec<String>> = Vec::new();
    let mut queue: Vec<Vec<String>> = vec![Vec::new()];
    while let Some(path) = queue.pop() {
        // A tree this deep would mean the walk is looping, not that the CLI grew: stop loudly
        // rather than spin (an earlier `help` that offered itself did exactly that).
        assert!(path.len() < 6, "the completion tree loops at {path:?}");
        for child in oracle(&path, "") {
            let mut deeper = path.clone();
            deeper.push(child);
            if !is_page(&deeper) {
                continue;
            }
            queue.push(deeper.clone());
            found.push(deeper);
        }
    }
    found
}

/// Every page path the binary declares, the `help`-mirrored half dropped — the command tree as a
/// reader meets it. `sbx help` has no page of its own, so it is absent by the same filter.
pub fn page_paths() -> Vec<Vec<String>> {
    walk()
        .into_iter()
        .filter(|p| p.first().is_none_or(|w| w != "help"))
        .collect()
}
