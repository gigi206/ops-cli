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

/// Every file that pins the revision, with how many times it does.
///
/// The two spellings are the two ways the value is consumed: a workflow exports it as an
/// environment variable, `mise.toml` writes it inside the flake reference it realises. The count
/// is the file's, because a pin that stops being one does not disagree with the others: it
/// leaves, and seven copies held in step become six without a word. A file that carries neither
/// spelling has gone stale for this reader and says so rather than contributing nothing.
const PINNING_FILES: &[(&str, usize)] = &[
    ("mise.toml", 2),
    (".github/workflows/release.yml", 1),
    (".github/workflows/nightly.yml", 1),
    (".github/workflows/latest.yml", 1),
    (".github/workflows/wsl.yml", 1),
    (".github/workflows/catalogue.yml", 1),
];

/// What each spelling is followed by in `text`, in the order they appear: the 40-hex revision a
/// pin writes, or, where something else follows, that something, so the guard names it.
///
/// Both spellings are read: `NIXPKGS_REV: "<rev>"` as a workflow writes it, quoted either way or
/// bare, and `github:NixOS/nixpkgs/<rev>` as a flake reference spells it, every occurrence of
/// either on a line. A reference to the exported variable, `github:NixOS/nixpkgs/${NIXPKGS_REV}`,
/// reads the pin rather than writing one, and is not counted. Anything else in a pin's place, a
/// channel name or a revision cut short, is a reference that floats or names nothing, and comes
/// back for the guard to refuse.
fn revisions_in(text: &str) -> Vec<String> {
    let mut found = Vec::new();
    for line in text.lines() {
        for spelling in ["github:NixOS/nixpkgs/", "NIXPKGS_REV:"] {
            for rest in line.split(spelling).skip(1) {
                let value = rest.trim_start().trim_start_matches(['"', '\'']);
                if value.starts_with("${NIXPKGS_REV}") {
                    continue;
                }
                let token: String = value
                    .chars()
                    .take_while(|c| !c.is_whitespace() && !matches!(c, '"' | '\'' | '#'))
                    .collect();
                found.push(token);
            }
        }
    }
    found
}

/// Whether `rev` is a revision as a pin writes it: forty lowercase hexadecimal digits.
fn is_revision(rev: &str) -> bool {
    rev.len() == 40
        && rev
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// The revisions `relative` pins, in the order they appear.
fn pinned_revisions(relative: &str) -> Vec<String> {
    let path = root().join(relative);
    let text =
        std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{relative} is readable: {e}"));
    revisions_in(&text)
}

/// Every pinned revision in the repository is one value, written as many times as each file is
/// known to write it.
///
/// The failure names which file disagrees and with what, because the fix is to bump the one that
/// was forgotten, not to discover which of seven it was.
#[test]
fn every_pinned_nixpkgs_revision_is_the_same_one() {
    let mut by_revision: BTreeMap<String, Vec<&str>> = BTreeMap::new();
    for (relative, expected) in PINNING_FILES {
        let found = pinned_revisions(relative);
        assert!(
            !found.is_empty(),
            "{relative} pins no nixpkgs revision in either spelling — the reader has gone stale, \
             or the file stopped pinning one and belongs out of this list"
        );
        for rev in &found {
            assert!(
                is_revision(rev),
                "{relative} writes `{rev}` where a pin's 40-hex revision goes: a reference there \
                 floats, or names a revision cut short"
            );
        }
        assert_eq!(
            found.len(),
            *expected,
            "{relative} pins the revision {} time(s), not the {expected} this list knows: a pin \
             left the file, or one was added and belongs in the count — {found:?}",
            found.len()
        );
        for rev in found {
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

/// Each way a pin is written is read, and each way a reference stops being one is caught: quoted
/// either way or bare, both spellings on one line, a reference to the exported variable passed
/// over, and a channel name or a cut revision handed back for the guard to refuse.
#[test]
fn every_spelling_of_a_pin_is_read_and_a_floating_one_is_named() {
    let rev = "89570f24e97e614aa34aa9ab1c927b6578a43775";
    for (text, read) in [
        (format!("  NIXPKGS_REV: \"{rev}\""), vec![rev.to_string()]),
        (format!("  NIXPKGS_REV: '{rev}'"), vec![rev.to_string()]),
        (format!("  NIXPKGS_REV: {rev}"), vec![rev.to_string()]),
        (
            format!("ref='github:NixOS/nixpkgs/{rev}#pkgsStatic.nix'"),
            vec![rev.to_string()],
        ),
        (
            format!("ref='github:NixOS/nixpkgs/{rev}#a' NIXPKGS_REV: \"{rev}\""),
            vec![rev.to_string(), rev.to_string()],
        ),
        (
            "nix build \"github:NixOS/nixpkgs/${NIXPKGS_REV}#mise\"".to_string(),
            vec![],
        ),
        (
            "ref='github:NixOS/nixpkgs/nixos-unstable#pkgsStatic.nix'".to_string(),
            vec!["nixos-unstable".to_string()],
        ),
        (
            "  NIXPKGS_REV: \"89570f2\"".to_string(),
            vec!["89570f2".to_string()],
        ),
    ] {
        assert_eq!(revisions_in(&text), read, "{text}");
    }
    assert!(is_revision(rev));
    for not in [
        "89570f2",
        "nixos-unstable",
        &rev.to_uppercase(),
        &format!("{rev}0"),
    ] {
        assert!(!is_revision(not), "{not}");
    }
}
