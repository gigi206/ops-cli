//! Tests that the user guide still describes the whole product.
//!
//! Three surfaces are meant to be documented exhaustively: every CLI verb has a reference page,
//! every config field a launch accepts is named somewhere in the guide, and every shipped app
//! profile appears in the catalogue. Each of those held when written, but only by hand: nothing
//! failed when a new verb, field or profile arrived without its prose, so the gap surfaced when a
//! reader looked for it rather than when it was introduced. These tests move that to build time.
//!
//! They check *presence*, never accuracy: a page that exists but says the wrong thing still passes,
//! and no test here can tell whether prose is true. What they buy is that nothing ships silently
//! undocumented.
//!
//! One check is of a different kind and is kept here because it has the same failure mode. The guide
//! writes no em dash of its own, a rule applied across it once by hand and reintroduced afterwards
//! because nothing failed when a new one arrived. That is a claim about *how* a sentence is written
//! rather than whether it exists, so it is the one place in this module that reads wording. It still
//! answers presence in the end: what it refuses is a character, never an argument.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

/// The guide's root, resolved from the crate rather than the working directory so the tests run
/// from anywhere.
fn guide() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("docs-site/docs/guide")
}

/// Every guide page, as its path and its contents.
///
/// Kept per file rather than pre-joined because code-fence state must not cross a page boundary:
/// one page whose fences do not balance would otherwise invert every page after it in the walk,
/// and the resulting check would be wrong in a way that looks like a documentation gap. The path
/// rides along so a check that finds a bad line can name where it is.
fn guide_pages() -> Vec<(PathBuf, String)> {
    fn walk(dir: &Path, out: &mut Vec<(PathBuf, String)>) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                walk(&path, out);
            } else if path.extension().is_some_and(|e| e == "md") {
                let text = std::fs::read_to_string(&path).unwrap_or_default();
                out.push((path, text));
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
fn documented_surface(pages: &[(PathBuf, String)]) -> String {
    let mut out = String::new();
    for (_, page) in pages {
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

/// Every field the config schema accepts, as `(toml name, type, is declared at the root)`.
///
/// The names are read out of the schema source, because a Rust struct carries no runtime list of
/// its fields. Three serde attributes decide what a reader would actually write: `rename` gives the
/// TOML spelling (so `value_type` is written `type`), `skip` marks a field that is never read from
/// a file at all, and `flatten` marks one whose *name is never written* — the reader types the
/// inner keys directly (`[task.db-query]`, not `tasks`), so the Rust name is an implementation
/// detail with nothing to document.
///
/// The root flag is what lets a caller hold a top-level field to a stricter rule than a nested one:
/// the root of the file is the surface a reader scans, and the one they cannot reconstruct from a
/// worked example somewhere else.
fn schema_fields() -> BTreeSet<(String, String, bool)> {
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
    fields
}

/// Every config field the schema accepts is *shown* in the guide, in the form a reader writes it.
///
/// What this does **not** check: a field name is not unique across the schema, so a field of one
/// table is satisfied by the same name documented under another (`env` appears both as the
/// top-level table and inside `[plugin.<name>]`). Closing that would need each field's full TOML
/// path, which the struct nesting alone does not give. The check is presence in the right *form*,
/// which is what makes the common-word hole harmless, not presence in the right *place*.
#[test]
fn every_config_field_is_shown_in_the_guide() {
    let fields = schema_fields();
    let pages = guide_pages();
    let guide = pages
        .iter()
        .map(|(_, text)| text.as_str())
        .collect::<Vec<_>>()
        .join("\n");
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

/// Every root-level config field has a row in the configuration overview's field map.
///
/// A field documented only in the prose of the page that owns it is reachable by search and by
/// nothing else. The map in `configuration/index.md` is the one surface that answers "what can this
/// file contain", so a field missing from it is invisible to the reader who is scanning rather than
/// looking a name up: `allow_insecure_http` sat in a code block on the packages page for exactly
/// that reason, a security field nobody could find.
///
/// Held to the root only. A nested field belongs to the table above it and is documented on that
/// table's own page, which the map already points at.
#[test]
fn every_root_config_field_has_a_row_in_the_field_map() {
    let page = std::fs::read_to_string(guide().join("configuration/index.md"))
        .expect("docs-site/docs/guide/configuration/index.md must exist");
    let map = page
        .split_once("## The fields")
        .and_then(|(_, rest)| rest.split_once("\n## "))
        .map(|(map, _)| map.to_string())
        .expect("the configuration overview must carry a `## The fields` map");

    let missing: Vec<String> = schema_fields()
        .iter()
        .filter(|(_, _, at_root)| *at_root)
        .map(|(name, _, _)| name.clone())
        // The map names a family of sections by its header form, and a scalar by its bare name.
        .filter(|name| {
            ![
                format!("`{name}`"),
                format!("`[{name}]`"),
                format!("`[{name}."),
            ]
            .iter()
            .any(|form| map.contains(form))
        })
        .collect();
    assert!(
        missing.is_empty(),
        "these root-level fields have no row in the field map of \
         docs-site/docs/guide/configuration/index.md, so a reader scanning the schema never meets \
         them: {missing:?}"
    );
}

/// The counts the guide writes for the shipped profiles and bundles are the real ones.
///
/// Three pages state how many profiles and bundles the repository ships, and a reader takes those
/// numbers as the shape of the catalogue: "all 71 name a bundle" is an argument, not decoration.
/// Adding one profile makes every one of them wrong, silently, because prose does not fail to
/// compile. The catalogue guard below proves each profile is *listed*; this one proves the guide
/// still knows how many there are.
#[test]
fn the_shipped_counts_the_guide_states_are_the_real_ones() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let count = |dir: &str| {
        std::fs::read_dir(root.join(dir))
            .unwrap_or_else(|e| panic!("{dir} must be readable: {e}"))
            .filter_map(Result::ok)
            .filter(|e| e.path().extension().is_some_and(|x| x == "toml"))
            .count()
    };
    let (profiles, bundles) = (count("examples/app"), count("examples/bundle"));
    assert!(
        profiles > 20 && bundles > 20,
        "the example scan found {profiles} profile(s) and {bundles} bundle(s), so it has stopped \
         matching the tree's shape and would pass vacuously"
    );

    // A number reads as a count only next to `shipped` or `importable`, so `1-64 characters` and
    // `4 per host` are not mistaken for one. The phrasings in use are `71 shipped profiles`,
    // `71 importable starter profiles`, `64 shipped bundles` and, on the bundles page, `64 of the
    // 71` — the last one stated as a fraction of the profiles rather than of anything else.
    let mut wrong: Vec<String> = Vec::new();
    for (path, page) in guide_pages() {
        let flat = page.split_whitespace().collect::<Vec<_>>().join(" ");
        let at = path.display().to_string();
        for (noun, want) in [("profiles", profiles), ("bundles", bundles)] {
            for (i, _) in flat.match_indices(noun) {
                let head = &flat[i.saturating_sub(40)..i];
                if !head.contains("shipped") && !head.contains("importable") {
                    continue;
                }
                let Some(num) = head
                    .split(|c: char| !c.is_ascii_digit())
                    .rfind(|t| !t.is_empty())
                else {
                    continue;
                };
                if num.parse::<usize>() != Ok(want) {
                    wrong.push(format!("{at}: `{num} ... {noun}` (there are {want})"));
                }
            }
        }
        if at.ends_with("bundles.md")
            && let Some(rest) = flat.split("of the ").nth(1)
            && let Some(claimed) = rest
                .split_whitespace()
                .next()
                .and_then(|n| n.parse::<usize>().ok())
            && claimed != profiles
        {
            wrong.push(format!(
                "{at}: `of the {claimed}` (there are {profiles} profiles)"
            ));
        }
    }
    assert!(
        wrong.is_empty(),
        "the guide states counts the repository no longer has: {wrong:?}"
    );
}

/// Every named-table example in the guide uses keys the struct behind it actually has.
///
/// A worked example is the part of a page a reader copies, so an example that cannot work is worse
/// than no example: it fails in the reader's config, not in ours. The schema is additive by design,
/// unknown keys being ignored rather than refused, which is exactly why nothing else catches this:
/// `[secret.github] resolver = "env://TOKEN"` parses, loads, and silently declares a credential for
/// a host named `github` with no header. It sat in the flagship how-to until it was read.
///
/// Scoped to the families whose tables are keyed by a name the writer chooses (`[secret."host"]`,
/// `[task.<name>]`, `[app.<name>]`, `[bundle.<name>]`), because those are the ones a key-name check
/// cannot reach by looking at the top level alone.
#[test]
fn every_named_table_example_uses_real_keys() {
    let source =
        std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("src/config/schema.rs"))
            .expect("the config schema source is readable");

    // `struct Name { … }` → the TOML spellings of its fields.
    let struct_fields = |name: &str| -> BTreeSet<String> {
        let mut out = BTreeSet::new();
        let Some(rest) = source.split_once(&format!("struct {name} {{")) else {
            return out;
        };
        let body = rest.1.split("\n}").next().unwrap_or("");
        let mut renamed: Option<String> = None;
        for line in body.lines() {
            let line = line.trim();
            if line.starts_with("#[") {
                if let Some(rest) = line.split("rename = \"").nth(1)
                    && let Some(name) = rest.split('"').next()
                {
                    renamed = Some(name.to_string());
                }
                continue;
            }
            if let Some((name, _)) = line.strip_prefix("pub(crate) ").and_then(field_decl) {
                out.insert(renamed.take().unwrap_or(name));
            } else if !line.is_empty() && !line.starts_with("//") {
                renamed = None;
            }
        }
        out
    };

    // (the table family, the struct its named entries deserialize into, extra keys it reserves)
    let families: Vec<(&str, BTreeSet<String>)> = vec![
        (
            "secret",
            struct_fields("RawHostSecret")
                .into_iter()
                .chain(struct_fields("RawSecretDefaults"))
                .chain(["defaults".to_string()])
                .collect(),
        ),
        (
            "task",
            struct_fields("RawTask")
                .into_iter()
                .chain(struct_fields("RawTaskDefaults"))
                .chain(["defaults".to_string()])
                .collect(),
        ),
        ("app", struct_fields("RawApp")),
        ("bundle", struct_fields("RawBundle")),
    ];
    for (family, fields) in &families {
        assert!(
            fields.len() > 3,
            "the field scan for `{family}` found {} field(s), so it has stopped matching the \
             schema's shape and would pass vacuously",
            fields.len()
        );
    }

    let mut offenders = Vec::new();
    for (path, page) in guide_pages() {
        for block in toml_blocks(&page) {
            let Ok(doc) = block.parse::<toml::Table>() else {
                // A fragment that is not a whole document (two forms in one fence, an
                // elided body) is not this test's business; the site build reads them as prose.
                continue;
            };
            for (family, fields) in &families {
                let Some(toml::Value::Table(named)) = doc.get(*family) else {
                    continue;
                };
                for (entry_name, entry) in named {
                    // `[[secret."host"]]` is an array of the same shape.
                    let rows: Vec<&toml::Value> = match entry {
                        toml::Value::Array(rows) => rows.iter().collect(),
                        other => vec![other],
                    };
                    for row in rows {
                        let Some(row) = row.as_table() else { continue };
                        for key in row.keys() {
                            // A sub-table is a nested family of its own (`[task.x.secret]`,
                            // `[app.x.network]`), named by the parent struct's own field.
                            if !fields.contains(key) && !row[key].is_table() {
                                let at = path.display().to_string();
                                offenders.push(format!("{at}: [{family}.{entry_name}] `{key}`"));
                            }
                        }
                    }
                }
            }
        }
    }
    assert!(
        offenders.is_empty(),
        "these worked examples name keys the schema has no field for, so a reader who copies one \
         gets a declaration that parses and does nothing: {offenders:?}"
    );
}

/// Every fenced `toml` block of a page, as its own string.
fn toml_blocks(page: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut current: Option<String> = None;
    for line in page.lines() {
        match (&mut current, line.trim_start()) {
            (None, "```toml") => current = Some(String::new()),
            (Some(_), fence) if fence.starts_with("```") => {
                out.push(current.take().unwrap_or_default());
            }
            (Some(buf), _) => {
                buf.push_str(line);
                buf.push('\n');
            }
            _ => {}
        }
    }
    out
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

/// How wide a slice around an em dash must be found under `src/` for the dash to count as a
/// quotation rather than prose.
///
/// Twelve characters each side is enough to identify the message it belongs to, and short enough to
/// survive assembly: the guide shows a withheld-package warning as one line, while the binary builds
/// that line from a wrapper format and a separate trust-state clause, so no single literal in `src/`
/// holds all of it.
const QUOTED_WINDOW: usize = 12;

/// Every `.rs` file under `src/`, concatenated: the corpus a quoted guide line is checked against.
fn rust_sources() -> String {
    fn walk(dir: &Path, out: &mut String) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                walk(&path, out);
            } else if path.extension().is_some_and(|e| e == "rs") {
                out.push_str(&std::fs::read_to_string(&path).unwrap_or_default());
                out.push('\n');
            }
        }
    }
    let mut out = String::new();
    walk(&Path::new(env!("CARGO_MANIFEST_DIR")).join("src"), &mut out);
    out
}

/// The character ranges of a line covered by inline code spans, so a dash inside one can be told
/// from a dash in prose.
///
/// Indices are into `chars`, not bytes, because an em dash is three bytes and the windowing above
/// counts characters. A closing run of at least the opener's length closes the span: the guide uses
/// the doubled form when the quoted text itself contains a backtick (a warning that names a config
/// key), and the single backticks inside it must not be read as the close.
fn code_spans(chars: &[char]) -> Vec<(usize, usize)> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < chars.len() {
        if chars[i] != '`' {
            i += 1;
            continue;
        }
        let open = i;
        while i < chars.len() && chars[i] == '`' {
            i += 1;
        }
        let ticks = i - open;
        let body = i;
        let mut close = None;
        while i < chars.len() {
            if chars[i] != '`' {
                i += 1;
                continue;
            }
            let run = i;
            while i < chars.len() && chars[i] == '`' {
                i += 1;
            }
            if i - run >= ticks {
                close = Some(run);
                break;
            }
        }
        match close {
            Some(end) => out.push((body, end)),
            // An unbalanced span: nothing after it is a span, so stop rather than guess.
            None => break,
        }
    }
    out
}

/// The guide writes no em dash of its own, and this is what fails when one arrives.
///
/// The joints an em dash makes are written `:`, `,`, `;` or with parentheses. The rule was applied
/// across the whole guide once and came back anyway, eight prose occurrences at a time, because
/// nothing failed when one was introduced: it surfaced only when someone counted. That is the shape
/// this module exists to move to build time.
///
/// **The exception is real and cannot be dropped**: a line that quotes what the binary prints
/// carries whatever punctuation the binary uses, and rewriting it would make the page lie about the
/// screen. So a dash is accepted in exactly two positions, and both were measured before being
/// allowed.
///
/// Inside a fenced block, unconditionally. The fence's tag does not separate a transcript from an
/// authored snippet, so it cannot be the discriminator: the `sh` blocks of the `proc` and `fs` pages
/// paste a feed header sbx prints, and a tag-based rule would flag real output as prose. The
/// residual is named rather than closed: a hand-written comment inside a `toml` fence is authoring,
/// and this check does not see it.
///
/// Outside a fence, only inside an inline code span whose surroundings are found under `src/`. Both
/// halves are load bearing. The span alone would let any dash through on a backtick, and the source
/// match alone would accept a sentence that happens to share twelve characters with a message.
///
/// One place the rule covers is deliberately out of scope: the landing page's transcript
/// (`docs-site/src/pages/index.tsx`) is quoted output end to end, and its one dash sits beside a
/// colour escape in `src/cli/doctor.rs`, so no window taken from the page can match the source. It
/// is checked by reading, not here.
#[test]
fn the_guide_writes_no_em_dash_outside_the_output_it_quotes() {
    let sources = rust_sources();
    let root = format!("{}/", env!("CARGO_MANIFEST_DIR"));
    let mut offenders = Vec::new();
    for (path, page) in guide_pages() {
        // Fence state is per page, never carried into the next one.
        let mut in_fence = false;
        for (n, line) in page.lines().enumerate() {
            if line.trim_start().starts_with("```") {
                in_fence = !in_fence;
                continue;
            }
            if in_fence || !line.contains('—') {
                continue;
            }
            let chars: Vec<char> = line.chars().collect();
            let spans = code_spans(&chars);
            for (i, c) in chars.iter().enumerate() {
                if *c != '—' {
                    continue;
                }
                let window: String = chars
                    [i.saturating_sub(QUOTED_WINDOW)..(i + QUOTED_WINDOW + 1).min(chars.len())]
                    .iter()
                    .collect();
                if spans.iter().any(|(a, b)| (*a..*b).contains(&i)) && sources.contains(&window) {
                    continue;
                }
                let at = path.display().to_string().replace(&root, "");
                offenders.push(format!("{at}:{}  {}", n + 1, line.trim()));
            }
        }
    }
    assert!(
        offenders.is_empty(),
        "the guide does not write em dashes: use `:`, `,`, `;` or parentheses. If the line quotes \
         what the binary prints, put it in a fenced block or an inline code span whose text matches \
         the message in `src/`, and it is accepted.\n{}",
        offenders.join("\n")
    );
}

/// The module-level items in `src/` that carry no doc comment today.
///
/// A grandfather list, not a permission: every entry is a gap this guard was switched on around,
/// and the test fails just as loudly on an entry that no longer applies, so the list can only
/// shrink. Keyed by `(file under `src/`, item name)` rather than by line so it survives every edit
/// that does not change what is documented.
const UNDOCUMENTED_MODULE_ITEMS: &[(&str, &str)] = &[
    ("allowlist/mod.rs", "EgressPolicy"),
    ("cli/app.rs", "merged"),
    ("cli/app.rs", "nothing_written"),
    ("cli/app.rs", "parse_app_rm"),
    ("cli/completion.rs", "completion_cmd"),
    ("cli/gc.rs", "run"),
    ("cli/logs.rs", "read_broker_rows"),
    ("cli/logs.rs", "read_fs_rows"),
    ("cli/logs.rs", "read_net_rows"),
    ("cli/logs.rs", "read_proc_rows"),
    ("cli/logs.rs", "read_signer_rows"),
    ("cli/logs.rs", "read_ssh_rows"),
    ("cli/logs.rs", "read_task_rows"),
    ("cli/projects.rs", "projects_list_cmd"),
    ("cli/projects.rs", "projects_rm_cmd"),
    ("cli/search.rs", "run"),
    ("cli/storage.rs", "StatusView"),
    ("cli/storage.rs", "down"),
    ("cli/storage.rs", "fail"),
    ("cli/storage.rs", "init"),
    ("cli/storage.rs", "parse_opts"),
    ("cli/storage.rs", "render"),
    ("cli/storage.rs", "status"),
    ("cli/storage.rs", "status_next_step"),
    ("cli/storage.rs", "storage_cmd"),
    ("cli/storage.rs", "up"),
    ("cli/task.rs", "RunOutputView"),
    ("cli/task.rs", "layout_or_fail"),
    ("cli/task.rs", "listing_args"),
    ("cli/task.rs", "no_sessions"),
    ("cli/task.rs", "one_plane"),
    ("cli/task.rs", "resolve_named"),
    ("config/fspolicy.rs", "glob_walk"),
    ("config/schema.rs", "NetworkField"),
    ("config/view.rs", "NetworkView"),
    ("main.rs", "main"),
    ("main.rs", "read_sysctl"),
    ("observe.rs", "node"),
    ("pathfind.rs", "is_executable"),
    ("paths.rs", "BaseView"),
    ("paths.rs", "ChildView"),
    ("paths.rs", "EntryView"),
    ("plugins/catalogue.rs", "RawCatalogue"),
    ("plugins/catalogue.rs", "RawEntry"),
    ("plugins/catalogue.rs", "collect_files"),
    ("plugins/stores.rs", "RawStoreToml"),
    ("sandbox/argv.rs", "lit"),
    ("sandbox/argv.rs", "path"),
    ("sandbox/binds.rs", "build_spec"),
    ("sandbox/broker.rs", "hex_digit"),
    ("sandbox/control/capture.rs", "CaptureInner"),
    ("sandbox/control/mod.rs", "FlowEntry"),
    ("sandbox/control/mod.rs", "FlowInner"),
    ("sandbox/control/mod.rs", "Inner"),
    ("sandbox/control/mod.rs", "LogInner"),
    ("sandbox/control/mod.rs", "ManualInner"),
    ("sandbox/gc.rs", "accumulate_usage"),
    ("sandbox/launch.rs", "missing"),
    ("sandbox/launch.rs", "prepare_config"),
    ("sandbox/lens.rs", "Inner"),
    ("sandbox/netns.rs", "die"),
    ("sandbox/netns.rs", "to_cstring"),
    ("sandbox/notify_relay.rs", "HostNotifications"),
    ("sandbox/proc_enforce.rs", "OverlayInner"),
    ("sandbox/proc_enforce.rs", "Parked"),
    ("sandbox/proc_enforce.rs", "notif_id_valid_code"),
    ("sandbox/proc_enforce.rs", "notif_recv_code"),
    ("sandbox/proc_enforce.rs", "notif_send_code"),
    ("sandbox/proc_enforce.rs", "seccomp_ioc"),
    ("sandbox/proc_enforce.rs", "start_inner"),
    ("sandbox/proc_enforce.rs", "wrap_command"),
    ("sandbox/projectstore.rs", "acquire_shared_gc_lock"),
    ("sandbox/proxy/bench.rs", "signing_injection"),
    ("sandbox/proxy/dns.rs", "default_resolve"),
    ("sandbox/proxy/inject.rs", "RefreshState"),
    ("sandbox/proxy/ssrf.rs", "classify_ip"),
    ("sandbox/proxy/ssrf.rs", "classify_v4"),
    ("sandbox/proxy/ssrf.rs", "classify_v6"),
    ("sandbox/proxy/websocket.rs", "relay_websocket"),
    ("sandbox/seccomp.rs", "write_to_memfd"),
    ("sandbox/task_control.rs", "Inner"),
    ("sandbox/theme_relay.rs", "HostSettings"),
    ("session.rs", "close_fd"),
    ("storage.rs", "lock_image"),
];

/// One module-level item declaration: the file it is in, its name, and whether a doc comment sits
/// directly above it.
struct ItemDoc {
    file: String,
    name: String,
    documented: bool,
}

/// Every module-level `fn`/`struct`/`enum`/`trait`/`union` in `src/`, with whether it is documented.
///
/// Deliberately a line scanner and not a parse: the question is "does a `///` sit above this
/// declaration", which is exactly what a reader sees, and a real parser would answer a subtly
/// different question (a doc *attribute*, wherever it came from). Three regions are skipped because
/// nothing in them is expected to carry prose of its own — a `impl Trait for Type` body, whose
/// methods inherit the trait's documentation; anything under `mod tests`; and any item attributed
/// `#[test]` or `#[cfg(test)]`. Files named `tests.rs` / `*_tests.rs` are skipped whole, being
/// test-only modules.
fn module_level_items() -> Vec<ItemDoc> {
    let item = regex::Regex::new(
        r#"^(?:pub(?:\([a-z(): ]+\))?\s+)?(?:const\s+)?(?:async\s+)?(?:unsafe\s+)?(?:extern\s+"[^"]*"\s+)?(?:fn|struct|enum|trait|union)\s+([A-Za-z_][A-Za-z0-9_]*)"#,
    )
    .expect("the item pattern compiles");
    let trait_impl = regex::Regex::new(r"^\s*impl(?:<[^>]*>)?\s+.*\s+for\s+")
        .expect("the impl pattern compiles");
    let mod_tests = regex::Regex::new(r"^\s*(?:#\[cfg\(test\)\]\s*)?mod\s+tests\s*\{")
        .expect("the tests pattern compiles");

    fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                walk(&path, out);
            } else if path.extension().is_some_and(|e| e == "rs") {
                out.push(path);
            }
        }
    }
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut paths = Vec::new();
    walk(&root, &mut paths);
    paths.sort();

    let is_attr = |l: &str| l.trim_start().starts_with("#[") || l.trim_start().starts_with("#![");
    let is_doc = |l: &str| l.trim_start().starts_with("///");

    let mut out = Vec::new();
    for path in paths {
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or_default();
        if name == "tests.rs" || name.ends_with("_tests.rs") {
            continue;
        }
        let rel = path
            .strip_prefix(&root)
            .unwrap_or(&path)
            .display()
            .to_string();
        let text = std::fs::read_to_string(&path).unwrap_or_default();
        let lines: Vec<&str> = text.lines().collect();
        let mut depth: i32 = 0;
        let mut skip: Vec<i32> = Vec::new();
        for (i, line) in lines.iter().enumerate() {
            if (trait_impl.is_match(line) && line.trim_end().ends_with('{'))
                || mod_tests.is_match(line)
            {
                skip.push(depth);
            }
            if skip.is_empty()
                && !line.starts_with([' ', '\t'])
                && let Some(caps) = item.captures(line)
            {
                let mut j = i;
                let mut in_test = false;
                while j > 0 && is_attr(lines[j - 1]) {
                    if lines[j - 1].contains("#[test") || lines[j - 1].contains("#[cfg(test)") {
                        in_test = true;
                    }
                    j -= 1;
                }
                if !in_test {
                    out.push(ItemDoc {
                        file: rel.clone(),
                        name: caps[1].to_string(),
                        documented: j > 0 && is_doc(lines[j - 1]),
                    });
                }
            }
            depth += line.matches('{').count() as i32 - line.matches('}').count() as i32;
            while skip.last().is_some_and(|d| depth <= *d) {
                skip.pop();
            }
        }
    }
    out
}

/// Every module-level item carries a doc comment, or is a named pre-existing gap.
///
/// This closes a failure mode nothing else here catches. A doc comment belongs to whatever item
/// follows it, so when a refactor moves, renames or deletes an item and leaves its `///` block
/// behind, the block silently becomes the *next* item's documentation — and the compiler, clippy
/// and `mise run rustdoc` all stay green, because the block still parses and its intra-doc links
/// still resolve. Only a reader notices, and only if they happen to read that item's prose against
/// its code. Forty-seven such blocks had accumulated when this test was written.
///
/// What makes it catchable is the other half of the same event: the severed block leaves its
/// rightful owner with no documentation at all. So this checks presence, in the spirit of the rest
/// of the module — it cannot tell whether prose is true, only that an item which had prose still
/// has some.
#[test]
fn every_module_level_item_carries_a_doc_comment() {
    let allowed: BTreeSet<(&str, &str)> = UNDOCUMENTED_MODULE_ITEMS.iter().copied().collect();
    let items = module_level_items();

    let mut undocumented = Vec::new();
    let mut seen = BTreeSet::new();
    for it in &items {
        let key = (it.file.as_str(), it.name.as_str());
        if it.documented {
            continue;
        }
        seen.insert((it.file.clone(), it.name.clone()));
        if !allowed.contains(&key) {
            undocumented.push(format!("{}: {}", it.file, it.name));
        }
    }
    assert!(
        undocumented.is_empty(),
        "these module-level items carry no doc comment. If a refactor moved one, its `///` block \
         is most likely still sitting above whichever item now follows it — where it reads as that \
         item's documentation. Move the block back rather than writing a new one:\n{}",
        undocumented.join("\n")
    );

    let stale: Vec<String> = UNDOCUMENTED_MODULE_ITEMS
        .iter()
        .filter(|(f, n)| !seen.contains(&((*f).to_string(), (*n).to_string())))
        .map(|(f, n)| format!("{f}: {n}"))
        .collect();
    assert!(
        stale.is_empty(),
        "`UNDOCUMENTED_MODULE_ITEMS` names items that are now documented or gone. Drop these \
         entries so the list keeps shrinking:\n{}",
        stale.join("\n")
    );
}

/// The width doc comments in this crate wrap at, and the discriminator this check rests on.
///
/// A doc line that reaches the margin ended *because it wrapped*; a short one ended because its
/// author ended the paragraph. Both can close a sentence, and only the second is a paragraph break,
/// so the length is what tells one from the other. Measured rather than guessed: 283 adjacent pairs
/// in `src/` close a sentence on a full-width line and continue in the same paragraph, against 110
/// that closed it short. Without this bound the check would flag all 393 and be unusable.
const DOC_WRAP: usize = 96;

/// Sentence-ending abbreviations, which end in a period without ending a sentence.
const DOC_ABBREVIATIONS: &[&str] = &["e.g.", "i.e.", "etc.", "vs.", "cf."];

/// Every `.rs` file under `src/` and `tests/`, as its repo-relative path and its contents.
fn crate_and_test_sources() -> Vec<(String, String)> {
    fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                walk(&path, out);
            } else if path.extension().is_some_and(|e| e == "rs") {
                out.push(path);
            }
        }
    }
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut paths = Vec::new();
    walk(&root.join("src"), &mut paths);
    walk(&root.join("tests"), &mut paths);
    paths.sort();
    paths
        .into_iter()
        .map(|p| {
            let rel = p.strip_prefix(root).unwrap_or(&p).display().to_string();
            let text = std::fs::read_to_string(&p).unwrap_or_default();
            (rel, text)
        })
        .collect()
}

/// A doc comment's separator is not decoration: a block that lost its item merges into the next one
/// exactly here.
///
/// The first guard catches the *victim* — the item left with no prose. This one catches the
/// *merge*, and it reaches where the other cannot: a struct field, an enum variant, a second summary
/// line on the same function. Two of the forty-seven severed blocks lived below module level, and
/// nothing but this would see them come back.
///
/// What it asserts is that a paragraph break inside a doc block is written as one. A `///` line that
/// closes a sentence well short of the margin ([`DOC_WRAP`]) ended a paragraph, so a bare `///` has
/// to follow it before the next paragraph opens. That is already how the crate is written — 1751
/// separators against the 110 that were missing when this was added — so the rule records existing
/// practice rather than imposing a new one.
///
/// Markdown structure is exempt: list items and their indented continuations, and anything inside a
/// fenced block, where a blank line changes what renders rather than how it reads.
///
/// The bound leaves a gap it cannot close: a severed block whose last line happens to land within a
/// few characters of the margin reads as a wrapped line and passes. That is roughly one in
/// twenty-five, and the price of a check that is quiet on the other twenty-four.
#[test]
fn a_paragraph_break_inside_a_doc_comment_is_written_as_one() {
    let list_item = regex::Regex::new(r"^([*+-] |[0-9]+[.)] )").expect("the list pattern compiles");
    let mut offenders = Vec::new();

    for (path, text) in crate_and_test_sources() {
        let lines: Vec<&str> = text.lines().collect();
        let body = |l: &str| -> Option<String> {
            let t = l.trim_start();
            t.strip_prefix("/// ").map(|b| b.to_string())
        };
        let mut fenced = false;
        let mut in_fence = Vec::with_capacity(lines.len());
        for line in &lines {
            if body(line).is_some_and(|b| b.starts_with("```")) {
                fenced = !fenced;
            }
            in_fence.push(fenced);
        }

        for i in 0..lines.len().saturating_sub(1) {
            let (Some(cur), Some(next)) = (body(lines[i]), body(lines[i + 1])) else {
                continue;
            };
            if in_fence[i] || in_fence[i + 1] {
                continue;
            }
            if [&cur, &next]
                .iter()
                .any(|b| list_item.is_match(b) || b.starts_with(char::is_whitespace))
            {
                continue;
            }
            if !cur.ends_with(['.', '!', '?'])
                || DOC_ABBREVIATIONS.iter().any(|a| cur.ends_with(a))
                || lines[i].chars().count() >= DOC_WRAP
            {
                continue;
            }
            if next.starts_with(|c: char| c.is_uppercase() || "`[*".contains(c)) {
                offenders.push(format!("{path}:{}  {}", i + 1, cur));
            }
        }
    }

    assert!(
        offenders.is_empty(),
        "a paragraph ends on each of these lines and the next one opens another, with no `///` \
         between them. If that is a new paragraph, separate it with a bare `///`. If the block \
         below it belongs to an item that moved, it is documenting the wrong thing now — put it \
         back rather than separating it:\n{}",
        offenders.join("\n")
    );
}
