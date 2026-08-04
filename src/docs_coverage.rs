//! Tests that the user guide still describes the whole product.
//!
//! Three surfaces are meant to be documented exhaustively: every CLI verb has a reference page,
//! every config field a launch accepts is named somewhere in the guide, and every shipped app
//! profile appears in the catalogue. Each of those held when written, but only by hand: nothing
//! failed when a new verb, field or profile arrived without its prose, so the gap surfaced when a
//! reader looked for it rather than when it was introduced. These tests move that to build time.
//!
//! They check *presence*, never wording: a page that exists but says the wrong thing still passes,
//! and no test here can tell whether prose is accurate. What they buy is that nothing ships
//! silently undocumented.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

/// The guide's root, resolved from the crate rather than the working directory so the tests run
/// from anywhere.
fn guide() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("docs-site/docs/guide")
}

/// The whole guide as one string. Every check that asks "is this named anywhere" reads this, since
/// a field is legitimately documented on whichever page owns its subject.
fn whole_guide() -> String {
    fn walk(dir: &Path, out: &mut String) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                walk(&path, out);
            } else if path.extension().is_some_and(|e| e == "md") {
                out.push_str(&std::fs::read_to_string(&path).unwrap_or_default());
                out.push('\n');
            }
        }
    }
    let mut out = String::new();
    walk(&guide(), &mut out);
    out
}

/// The `.md` stems of one guide directory, without their extension.
fn page_stems(subdir: &str) -> BTreeSet<String> {
    let mut stems = BTreeSet::new();
    let Ok(entries) = std::fs::read_dir(guide().join(subdir)) else {
        panic!(
            "the guide has no `{subdir}/` directory: {}",
            guide().display()
        );
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().is_some_and(|e| e == "md") {
            if let Some(stem) = path.file_stem().and_then(|s| s.to_str()) {
                stems.insert(stem.to_string());
            }
        }
    }
    stems
}

/// Every top-level verb has a `cli/<verb>.md`, and every such page names a real verb.
///
/// Both directions matter: a verb with no page is undocumented, and a page whose verb is gone is
/// worse than missing, since it documents something a reader cannot run.
#[test]
fn every_cli_verb_has_a_reference_page() {
    let verbs: BTreeSet<String> = crate::help::subcommands_of(&[])
        .into_iter()
        .map(|(name, _)| name.to_string())
        .collect();
    let mut pages = page_stems("cli");
    // The section's own landing page belongs to no verb.
    pages.remove("index");

    let undocumented: Vec<&String> = verbs.difference(&pages).collect();
    assert!(
        undocumented.is_empty(),
        "these verbs have no docs-site/docs/guide/cli/<verb>.md page: {undocumented:?}"
    );

    let orphaned: Vec<&String> = pages.difference(&verbs).collect();
    assert!(
        orphaned.is_empty(),
        "these cli pages name no verb the binary offers: {orphaned:?}"
    );
}

/// Every config field the schema accepts is named somewhere in the guide.
///
/// The field names are read out of the schema source, because a Rust struct carries no runtime
/// list of its fields. Two serde attributes decide what a reader would actually write: `rename`
/// gives the TOML spelling (so `value_type` is written `type`), and `skip` marks a field that is
/// never read from a file at all, which there is nothing to document.
/// A struct field's name, given what follows its visibility: `foo: Bar` yields `foo`, while a
/// `struct`/`enum`/`fn` declaration yields nothing (only fields are documented surface).
fn field_name(rest: &str) -> Option<String> {
    let name = rest.split(':').next()?;
    let is_field = !name.is_empty()
        && name
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
        && rest.len() > name.len();
    is_field.then(|| name.to_string())
}

#[test]
fn every_config_field_is_named_in_the_guide() {
    let source =
        std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("src/config/schema.rs"))
            .expect("the config schema source is readable");

    let mut fields: BTreeSet<String> = BTreeSet::new();
    let mut renamed: Option<String> = None;
    let mut skipped = false;
    for line in source.lines() {
        let line = line.trim();
        if line.starts_with("#[serde(") || line.starts_with("#[cfg_attr(") {
            if let Some(rest) = line.split("rename = \"").nth(1) {
                if let Some(name) = rest.split('"').next() {
                    renamed = Some(name.to_string());
                }
            }
            // `skip` alone; `skip_serializing_if` still describes a field a file may set.
            if line.contains("skip)") || line.contains("skip,") {
                skipped = true;
            }
            continue;
        }
        if let Some(name) = line.strip_prefix("pub(crate) ").and_then(field_name) {
            if !skipped {
                fields.insert(renamed.clone().unwrap_or(name));
            }
            renamed = None;
            skipped = false;
        } else if !line.is_empty() && !line.starts_with("///") && !line.starts_with("//") {
            renamed = None;
            skipped = false;
        }
    }
    assert!(
        fields.len() > 50,
        "the schema parse found only {} field(s), so it has stopped matching the source's shape \
         and would pass vacuously",
        fields.len()
    );

    let guide = whole_guide();
    let missing: Vec<&String> = fields.iter().filter(|f| !guide.contains(*f)).collect();
    assert!(
        missing.is_empty(),
        "these config fields are named nowhere in the guide: {missing:?}"
    );
}

/// Every shipped app profile appears in the catalogue page.
///
/// The catalogue is the only place a reader can discover a profile by name, so one that is shipped
/// but unlisted is one nobody imports.
#[test]
fn every_shipped_app_profile_is_in_the_catalogue() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("examples/app");
    let catalogue = std::fs::read_to_string(guide().join("apps/catalog.md"))
        .expect("the catalogue page exists");

    let mut missing = Vec::new();
    let mut seen = 0usize;
    for entry in std::fs::read_dir(&dir)
        .expect("the shipped profiles are readable")
        .flatten()
    {
        let path = entry.path();
        if !path.extension().is_some_and(|e| e == "toml") {
            continue;
        }
        seen += 1;
        let name = path
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or_default()
            .to_string();
        if !catalogue.contains(&name) {
            missing.push(name);
        }
    }
    assert!(seen > 0, "no profiles found under {}", dir.display());
    missing.sort();
    assert!(
        missing.is_empty(),
        "these shipped profiles are absent from the catalogue page: {missing:?}"
    );
}
