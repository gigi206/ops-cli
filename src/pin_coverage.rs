//! Tests that every pinned nixpkgs revision in the repository is the same one.
//!
//! The revision that supplies the bundled engines and the in-cage `mise` is written out in seven
//! places: twice in `mise.toml`, which realises `pkgsStatic.nix` and `pkgsStatic.bubblewrap`, and
//! once in each of the five workflows that need it. The publishing three realise the engines, the
//! WSL run builds the artifact a user would install, and the catalogue run realises the `mise` a
//! cage equips — which its own comment ties to the same revision on purpose, so that what the
//! catalogue asks a vendor is what a cage will run.
//!
//! Seven copies held in step by a comment is the shape every drift in this repository has taken.
//! There is a second guard downstream, and it is a different question: `build.rs` pins the SHA-256
//! of each engine's bytes, so a revision that changed without its hash following is refused at the
//! build. That one proves the copies *produced* the same engine. This one proves they *say* the
//! same thing — which is what fails first, and fails in a file `build.rs` never reads.

use std::collections::BTreeMap;
use std::path::Path;

/// The repository root, so a test reads the same files a reader would open.
fn root() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
}

/// Every file that pins the revision, and the spelling each uses.
///
/// The two spellings are the two ways the value is consumed: a workflow exports it as an
/// environment variable, `mise.toml` writes it inside the flake reference it realises. A file that
/// carries neither has gone stale for this reader and says so rather than contributing nothing.
const PINNING_FILES: &[&str] = &[
    "mise.toml",
    ".github/workflows/release.yml",
    ".github/workflows/nightly.yml",
    ".github/workflows/latest.yml",
    ".github/workflows/wsl.yml",
    ".github/workflows/catalogue.yml",
];

/// The revisions `relative` pins, in the order they appear.
///
/// Both spellings are read: `NIXPKGS_REV: "<rev>"` as a workflow writes it, and
/// `github:NixOS/nixpkgs/<rev>` as a flake reference spells it. A file naming the revision twice
/// contributes both, so a half-done bump inside one file is caught as surely as one across two.
fn pinned_revisions(relative: &str) -> Vec<String> {
    let path = root().join(relative);
    let text =
        std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{relative} is readable: {e}"));
    let mut found = Vec::new();
    for line in text.lines() {
        if let Some(rest) = line.split("github:NixOS/nixpkgs/").nth(1) {
            let rev: String = rest.chars().take_while(char::is_ascii_hexdigit).collect();
            if !rev.is_empty() {
                found.push(rev);
                continue;
            }
        }
        if let Some(rest) = line.split("NIXPKGS_REV:").nth(1) {
            let rev: String = rest
                .trim()
                .trim_matches('"')
                .chars()
                .take_while(char::is_ascii_hexdigit)
                .collect();
            if !rev.is_empty() {
                found.push(rev);
            }
        }
    }
    assert!(
        !found.is_empty(),
        "{relative} pins no nixpkgs revision in either spelling — the reader has gone stale, or \
         the file stopped pinning one and belongs out of this list"
    );
    found
}

/// Every pinned revision in the repository is one value.
///
/// The failure names which file disagrees and with what, because the fix is to bump the one that
/// was forgotten, not to discover which of seven it was.
#[test]
fn every_pinned_nixpkgs_revision_is_the_same_one() {
    let mut by_revision: BTreeMap<String, Vec<&str>> = BTreeMap::new();
    for relative in PINNING_FILES {
        for rev in pinned_revisions(relative) {
            by_revision.entry(rev).or_default().push(relative);
        }
    }
    assert_eq!(
        by_revision.len(),
        1,
        "the repository pins more than one nixpkgs revision, so a bump was left half-done: \
         {by_revision:?}"
    );
}
