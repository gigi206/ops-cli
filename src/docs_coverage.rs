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

/// Every guide page's contents, one string per file.
///
/// Kept per file rather than pre-joined because code-fence state must not cross a page boundary:
/// one page whose fences do not balance would otherwise invert every page after it in the walk,
/// and the resulting check would be wrong in a way that looks like a documentation gap.
fn guide_pages() -> Vec<String> {
    fn walk(dir: &Path, out: &mut Vec<String>) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                walk(&path, out);
            } else if path.extension().is_some_and(|e| e == "md") {
                out.push(std::fs::read_to_string(&path).unwrap_or_default());
            }
        }
    }
    let mut out = Vec::new();
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
        if path.extension().is_some_and(|e| e == "md")
            && let Some(stem) = path.file_stem().and_then(|s| s.to_str())
        {
            stems.insert(stem.to_string());
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

/// The part of the guide where a config field is *written* rather than merely mentioned: the
/// contents of every fenced code block, plus every markdown table row.
///
/// This is what stops the check below from passing vacuously. A field whose name is an ordinary
/// word (`env`, `name`, `network`, `plugin`, `type`) occurs constantly in prose, so asking whether
/// the guide contains that word answers nothing: the whole schema could go undocumented and the
/// test would still be green. Those two surfaces are where the guide actually shows a field, in
/// the form a reader would type it, and neither is reachable by writing an English sentence.
fn documented_surface(pages: &[String]) -> String {
    let mut out = String::new();
    for page in pages {
        // Fence state is per page, never carried into the next one.
        let mut in_fence = false;
        for line in page.lines() {
            let trimmed = line.trim_start();
            if trimmed.starts_with("```") {
                in_fence = !in_fence;
                continue;
            }
            if !in_fence && !trimmed.starts_with('|') {
                continue;
            }
            // Runs of spaces collapse to one, because the guide aligns its assignments
            // (`nonce      = false`) and a field would otherwise look undocumented for having
            // been laid out tidily.
            let mut last_space = false;
            for c in trimmed.chars() {
                if c == ' ' {
                    if !last_space {
                        out.push(' ');
                    }
                    last_space = true;
                } else {
                    out.push(c);
                    last_space = false;
                }
            }
            out.push('\n');
        }
    }
    out
}

/// A struct field's name and type, given what follows its visibility: `foo: Bar` yields
/// `("foo", "Bar")`, while a `struct`/`enum`/`fn` declaration yields nothing (only fields are
/// documented surface).
fn field_decl(rest: &str) -> Option<(String, String)> {
    let (name, ty) = rest.split_once(':')?;
    let is_field = !name.is_empty()
        && name
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_');
    is_field.then(|| {
        (
            name.to_string(),
            ty.trim().trim_end_matches(',').trim().to_string(),
        )
    })
}

/// Whether a field's type makes it a **family of sections** (`[name.<key>]`) rather than a value.
///
/// The discriminator is the map's value type, not the map itself: `BTreeMap<String, String>` is an
/// inline table of scalars a reader writes as `env = { A = "1" }`, whereas
/// `BTreeMap<String, RawPluginConfig>` is a family of sections written as `[plugin.vault]`.
///
/// "Starts with an uppercase letter" does not separate the two on its own, `String` and `Vec` being
/// uppercase as well, so the container types are named and excluded. Getting this backwards is not
/// a harmless miss: it demands a section header for a field that has none, and the resulting
/// failure reads as a documentation gap that no amount of documenting can close.
fn is_section_family(ty: &str) -> bool {
    if !ty.starts_with("BTreeMap") && !ty.starts_with("HashMap") {
        return false;
    }
    let Some(args) = ty.split_once('<').map(|(_, rest)| rest) else {
        return false;
    };
    let Some(value) = args.split(',').nth(1).map(str::trim) else {
        return false;
    };
    let container = ["String", "Vec<", "Option<", "BTreeMap<", "HashMap<", "Box<"]
        .iter()
        .any(|c| value.starts_with(c));
    !container && value.starts_with(|c: char| c.is_ascii_uppercase())
}

/// Every config field the schema accepts is *shown* in the guide, in the form a reader writes it.
///
/// The field names are read out of the schema source, because a Rust struct carries no runtime
/// list of its fields. Three serde attributes decide what a reader would actually write: `rename`
/// gives the TOML spelling (so `value_type` is written `type`), `skip` marks a field that is never
/// read from a file at all, and `flatten` marks one whose *name is never written* — the reader
/// types the inner keys directly (`[task.db-query]`, not `tasks`), so the Rust name is an
/// implementation detail with nothing to document.
///
/// What this does **not** check: a field name is not unique across the schema, so a field of one
/// table is satisfied by the same name documented under another (`env` appears both as the
/// top-level table and inside `[plugin.<name>]`). Closing that would need each field's full TOML
/// path, which the struct nesting alone does not give. The check is presence in the right *form*,
/// which is what makes the common-word hole harmless, not presence in the right *place*.
#[test]
fn every_config_field_is_shown_in_the_guide() {
    let source =
        std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("src/config/schema.rs"))
            .expect("the config schema source is readable");

    // `(toml name, type, is a top-level section)`. The last one is what decides how strictly the
    // field must be shown: a family of sections at the root of the file is the one shape a reader
    // cannot guess from a field table, so it alone must appear as a header.
    let mut fields: BTreeSet<(String, String, bool)> = BTreeSet::new();
    let mut renamed: Option<String> = None;
    let mut skipped = false;
    let mut at_root = false;
    for line in source.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("pub(crate) struct ") {
            at_root = rest.starts_with("RawConfig");
        }
        if line.starts_with("#[serde(") || line.starts_with("#[cfg_attr(") {
            if let Some(rest) = line.split("rename = \"").nth(1)
                && let Some(name) = rest.split('"').next()
            {
                renamed = Some(name.to_string());
            }
            // `skip` alone; `skip_serializing_if` still describes a field a file may set.
            // `flatten` hides the name from the file entirely: the reader writes the inner keys.
            if line.contains("skip)") || line.contains("skip,") || line.contains("flatten") {
                skipped = true;
            }
            continue;
        }
        if let Some((name, ty)) = line.strip_prefix("pub(crate) ").and_then(field_decl) {
            if !skipped {
                fields.insert((renamed.clone().unwrap_or(name), ty, at_root));
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

    let pages = guide_pages();
    let guide = pages.join("\n");
    let surface = documented_surface(&pages);
    assert!(
        surface.len() > guide.len() / 20,
        "the code-block and table extraction found almost nothing ({} of {} bytes), so it has \
         stopped matching the guide's shape and every field would look undocumented",
        surface.len(),
        guide.len()
    );

    let missing: Vec<String> = fields
        .iter()
        .filter(|(name, ty, at_root)| {
            if *at_root && is_section_family(ty) {
                // A top-level family of sections is only really documented once its header form is
                // shown: `[plugin.vault]` teaches the shape, a bare `plugin` teaches nothing. Held
                // to this only at the root, since the same type nested inside a table is often
                // written inline instead (`params = { sql = "..." }`).
                !guide.contains(&format!("[{name}."))
            } else {
                // The forms a reader types: an assignment, a section header (whether top-level or
                // qualified, since `[task.defaults]` documents `defaults` as surely as
                // `[defaults]` would), or the name set as code in a field table.
                ![
                    format!("{name} ="),
                    format!("{name}="),
                    format!("[{name}]"),
                    format!("[{name}."),
                    format!(".{name}]"),
                    format!(".{name}."),
                    format!("`{name}`"),
                ]
                .iter()
                .any(|form| surface.contains(form))
            }
        })
        .map(|(name, _, _)| name.clone())
        .collect();
    assert!(
        missing.is_empty(),
        "these config fields are never shown in a code block or a field table in the guide, so a \
         reader is never told how to write them: {missing:?}"
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

/// Every `sbx upgrade` target has a row in the reference page's table.
///
/// A channel the binary offers but the page never lists is invisible: the reader cannot ask for
/// what they do not know exists. This is asserted against `TARGETS` itself rather than a literal
/// kept by hand, so the two sources stay independent — the code declares the channels, the page
/// documents them, and neither is written from the other.
///
/// A table row is required rather than a bare mention, and the distinction is what makes the check
/// mean anything: every one of these words (`all`, `nix`, `mise`, `binary`) occurs in the page's
/// prose already, so `contains(target)` would pass on a page that lists nothing.
#[test]
fn every_upgrade_target_has_a_row_in_its_reference_page() {
    let page = std::fs::read_to_string(guide().join("cli/upgrade.md"))
        .expect("docs-site/docs/guide/cli/upgrade.md must exist");
    let missing: Vec<&str> = crate::cli::upgrade::TARGETS
        .iter()
        .copied()
        .filter(|target| !page.contains(&format!("| `{target}` |")))
        .collect();
    assert!(
        missing.is_empty(),
        "these `sbx upgrade` targets have no row in docs-site/docs/guide/cli/upgrade.md: {missing:?}"
    );

    // The synopsis names the same set a second time, and it drifted the same way. Comparing it to
    // the binary's own synopsis keeps the page's first line from becoming a stale copy.
    let synopsis = crate::help::synopsis_of(&["upgrade"]);
    assert!(
        page.contains(synopsis),
        "the page's synopsis is not the binary's; expected to find:\n{synopsis}"
    );
}

/// The `sbx app` subcommand family is enumerated in prose twice, and both enumerations are the real
/// set, in the real order.
///
/// This is the drift a new subcommand actually causes. The dispatcher and the help table are
/// already tied together (`tests/help.rs` resolves every accepted path to a page), but the two
/// *sentences* that name the family are hand-written and go stale in silence: a reader is told the
/// verb has seven subcommands while the binary offers eight, and nothing fails. Asserted against
/// [`crate::help::subcommands_of`] rather than a literal kept here, so the code declares the set and
/// the prose is checked against it — neither is written from the other.
///
/// **Narrow on purpose.** The same check over every verb with subcommands was measured and refused:
/// 13 verbs document a subcommand as a table row or a section heading instead of an enumeration
/// (`sbx config get`, `sbx plugins install`, `sbx net deny` and 18 more), which is legitimate prose,
/// not drift. `app` is the verb that carries an explicit ordered enumeration in both places, so it
/// is the one that can be checked exactly rather than approximately.
///
/// **"Both places" means the two enumerations, not the whole page.** The reference page also opens
/// with a synopsis block listing each subcommand's grammar, and this says nothing about it: deleting
/// that block leaves this test green (checked). Guarding it too would mean matching a synopsis whose
/// wording legitimately differs from `help.rs`'s — the drift 14.2 measured and left alone across 13
/// pages. What is asserted here is the one sentence that names the family, in both artifacts.
#[test]
fn the_app_subcommand_enumeration_is_the_real_set_in_both_places() {
    let subs: Vec<&str> = crate::help::subcommands_of(&["app"])
        .into_iter()
        .map(|(name, _)| name)
        .collect();
    let enumeration = format!("`{}`", subs.join("`/`"));

    let page = std::fs::read_to_string(guide().join("cli/app.md"))
        .expect("docs-site/docs/guide/cli/app.md must exist");
    assert!(
        page.contains(&enumeration),
        "docs-site/docs/guide/cli/app.md does not enumerate the real subcommand set; \
         expected to find:\n{enumeration}"
    );

    let help = crate::help::page_usage(&["app"]).expect("the `app` page must exist");
    assert!(
        help.contains(&enumeration),
        "`sbx app --help` does not enumerate its own subcommands; expected to find:\n{enumeration}"
    );
}

/// Every tree the file-write feed stops watching is named in the page's scope section.
///
/// This one guards a blind spot rather than a feature. `IGNORED_COMPONENTS` removes trees from
/// observation, so a name added there and nowhere else makes the feed quieter about something a
/// reader still believes it reports. That is the failure this catches: not an undocumented
/// capability, but an undocumented *absence*, which no reader can discover by using the tool.
///
/// The search is confined to the `### Scope` section, where the limits are stated, so a mention
/// elsewhere on the page cannot satisfy it. It checks presence, never wording, and it says nothing
/// about the consequence of the gap: that a hook written under `.git` is executed outside the cage
/// is prose in the security model, and no test can hold it there.
#[test]
fn every_unwatched_tree_is_named_in_the_file_feed_page() {
    let page = std::fs::read_to_string(guide().join("cli/fs.md"))
        .expect("docs-site/docs/guide/cli/fs.md must exist");
    let scope = page
        .split_once("\n### Scope\n")
        .expect("the page must keep a `### Scope` section stating what is not watched")
        .1;
    let missing: Vec<&str> = crate::sandbox::fs_watch::IGNORED_COMPONENTS
        .iter()
        .copied()
        .filter(|tree| !scope.contains(&format!("`{tree}`")))
        .collect();
    assert!(
        missing.is_empty(),
        "these trees are excluded from the file-write feed but unnamed in the scope section of \
         docs-site/docs/guide/cli/fs.md: {missing:?}"
    );
}
