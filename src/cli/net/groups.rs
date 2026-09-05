//! `sbx net groups` — the reusable egress groups.
//!
//! Listing the groups in force and resolving what each expands to, exporting them as a portable
//! fragment, importing one back with the replaced copy kept beside it, entry validation, and the
//! group presenter.

use std::ffi::OsString;
use std::io::IsTerminal;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use crate::config_cwd;
use crate::{allowlist, config, diag, help, style};

/// `sbx net groups [<name>…] [--json]`: list the reusable egress groups declared in the global
/// config (`[network.groups]`), or resolve named ones to their entries. Groups are global-only (the
/// resolver honors them only from the global config), so there is no scope flag — this always reads
/// the global config. Read-only, network-free. With no name it lists each group and its entry count;
/// with names it prints each named group's authored entries, flagging a malformed or nested one.
pub(super) fn net_groups_list(args: &[OsString]) -> ExitCode {
    let mut json = false;
    let mut names: Vec<String> = Vec::new();
    for arg in args {
        match arg.to_str() {
            Some("--json") => json = true,
            Some(s) if s.starts_with('-') => {
                diag::error(&format!("sbx: net groups: unknown flag `{s}`"));
                diag::error(&format!(
                    "sbx: usage: {}",
                    help::synopsis_of(&["net", "groups"])
                ));
                return ExitCode::from(2);
            }
            Some(s) => names.push(s.to_string()),
            None => {
                diag::error("sbx: net groups: a group name must be valid UTF-8");
                return ExitCode::from(2);
            }
        }
    }
    let (groups, warnings) = config::net_groups();
    for w in &warnings {
        diag::warn_config(w);
    }

    // A named group that does not exist is an explicit error (never a blank success). Report every
    // missing name at once, and point at what *is* defined.
    if !names.is_empty() {
        let missing: Vec<&str> = names
            .iter()
            .filter(|n| !groups.contains_key(*n))
            .map(String::as_str)
            .collect();
        if !missing.is_empty() {
            diag::error(&format!(
                "sbx: net groups: no such group: {}",
                missing.join(", ")
            ));
            if groups.is_empty() {
                diag::error(
                    "sbx: no egress groups are defined — declare them under [network.groups] in the \
                     global config",
                );
            } else {
                let avail: Vec<&str> = groups.keys().map(String::as_str).collect();
                diag::error(&format!("sbx: defined groups: {}", avail.join(", ")));
            }
            return ExitCode::from(2);
        }
    }

    if json {
        // name → [ { entry, invalid } ], all groups (sorted) or the named subset (given order).
        let selected: Vec<(&String, &Vec<String>)> = if names.is_empty() {
            groups.iter().collect()
        } else {
            names
                .iter()
                .filter_map(|n| groups.get_key_value(n))
                .collect()
        };
        let obj: Vec<_> = selected
            .iter()
            .map(|(name, entries)| {
                let rows: Vec<_> = entries
                    .iter()
                    .map(|e| serde_json::json!({ "entry": e, "invalid": net_group_entry_issue(e) }))
                    .collect();
                serde_json::json!({ "name": name, "entries": rows })
            })
            .collect();
        println!("{}", serde_json::json!({ "groups": obj }));
        return ExitCode::SUCCESS;
    }

    let pal = style::Palette::for_stream(std::io::stdout().is_terminal());
    print!("{}", render_net_groups(&groups, &names, &pal));
    ExitCode::SUCCESS
}

/// `sbx net groups export [<name>…] [--out <file>]`: write the reusable egress groups as a portable
/// `[network.groups]` TOML fragment — every group, or the named subset — to stdout (the default,
/// composable and clobber-safe: `sbx net groups export > groups.toml`) or to `--out <file>`. The
/// inverse of `import`. Read-only on the config; no launch, no nix.
pub(super) fn net_groups_export(args: &[OsString]) -> ExitCode {
    let mut out: Option<PathBuf> = None;
    let mut names: Vec<String> = Vec::new();
    let mut it = args.iter();
    while let Some(arg) = it.next() {
        match arg.to_str() {
            Some("--out") | Some("-o") => {
                let Some(v) = it.next() else {
                    diag::error("sbx: net groups export: `--out` needs a file path");
                    return ExitCode::from(2);
                };
                out = Some(PathBuf::from(v));
            }
            Some(s) if s.starts_with('-') => {
                diag::error(&format!("sbx: net groups export: unknown flag `{s}`"));
                diag::error(&format!(
                    "sbx: usage: {}",
                    help::synopsis_of(&["net", "groups", "export"])
                ));
                return ExitCode::from(2);
            }
            Some(s) => names.push(s.to_string()),
            None => {
                diag::error("sbx: net groups export: a group name must be valid UTF-8");
                return ExitCode::from(2);
            }
        }
    }

    let (groups, warnings) = config::net_groups();
    for w in &warnings {
        diag::warn_config(w);
    }

    // Select all groups (sorted) or the named subset. An unknown name is an explicit error.
    let selected: std::collections::BTreeMap<String, Vec<String>> = if names.is_empty() {
        groups.clone()
    } else {
        let missing: Vec<&str> = names
            .iter()
            .filter(|n| !groups.contains_key(*n))
            .map(String::as_str)
            .collect();
        if !missing.is_empty() {
            diag::error(&format!(
                "sbx: net groups export: no such group: {}",
                missing.join(", ")
            ));
            return ExitCode::from(2);
        }
        names
            .iter()
            .filter_map(|n| groups.get_key_value(n).map(|(k, v)| (k.clone(), v.clone())))
            .collect()
    };
    if selected.is_empty() {
        diag::error(
            "sbx: net groups export: no egress groups to export (none are defined under \
             [network.groups] in the global config)",
        );
        return ExitCode::from(2);
    }

    let fragment = config::manage::export_net_groups(&selected);
    match &out {
        None => {
            print!("{fragment}");
            ExitCode::SUCCESS
        }
        Some(path) => write_groups_fragment(path, &fragment, selected.len()),
    }
}

/// Write an exported `[network.groups]` fragment to the `--out` destination, and report what
/// landed there. `count` is the number of groups the fragment carries, for the success line.
///
/// The write goes through [`config::manage::write_text`] — the writer `sbx bundle export --out`
/// already uses for the same job — rather than straight through. A fragment exists to be handed
/// back to `sbx net groups import`, so a write cut short (a full filesystem) would leave a
/// truncated group list at exactly the path someone later imports as though it were complete; the
/// shared writer renames a finished temp file into place, and creates the destination's parent
/// directory so a path into a not-yet-existing backup directory is written rather than refused.
fn write_groups_fragment(path: &Path, fragment: &str, count: usize) -> ExitCode {
    match config::manage::write_text(path, fragment, None) {
        Ok(()) => {
            let s = if count == 1 { "" } else { "s" };
            println!("exported {count} egress group{s} to {}", path.display());
            ExitCode::SUCCESS
        }
        Err(e) => {
            // The error already names the path it failed on, so the action alone is prefixed here.
            diag::error(&format!("sbx: net groups export: {e}"));
            ExitCode::FAILURE
        }
    }
}

/// Keep every egress group a forced import is about to replace, and say what the incoming fragment
/// no longer declares — [`crate::cli::keep_replaced_fragments`] with this family's nouns and its
/// exporter.
///
/// A group is a key inside the shared global config, not a file of its own, so what stands in for a
/// per-file copy is the fragment `sbx net groups export` already emits: the replaced group is
/// written back out in the same portable form, as `<name>.group.replaced` beside the config, so
/// re-declaring it is `sbx net groups import` on that file. The name is read as configuration by
/// nothing (the loader reads `sbx.toml` and `apps/*.toml`).
fn keep_replaced_groups(
    config_path: &std::path::Path,
    incoming: &std::collections::BTreeMap<String, Vec<String>>,
    force: bool,
) -> Result<Vec<String>, String> {
    crate::cli::keep_replaced_fragments(
        config_path,
        incoming,
        || config::net_groups().0,
        force,
        "egress group",
        "group",
        |name, entries| {
            Ok(config::manage::export_net_groups(
                &std::collections::BTreeMap::from([(name.to_string(), entries.clone())]),
            ))
        },
    )
}

/// `sbx net groups import <file> [--force]`: merge a portable `[network.groups]` fragment into the
/// global config, preserving every existing group and comment (`toml_edit`). Groups are global-only,
/// so the target is always the global config; the deliberate command is the consent (an agent in the
/// cage cannot run it), and the global config is trusted by location, so there is no prompt. A name
/// that already exists is refused unless `--force` overwrites it. The imported groups are inert until
/// referenced by a `[network]` `allow`/`deny` with `@<name>`.
pub(super) fn net_groups_import(args: &[OsString]) -> ExitCode {
    let (file, force) =
        match crate::cli::one_file(args, &["net", "groups", "import"], &["-f", "--force"]) {
            Ok(parsed) => parsed,
            Err(code) => return code,
        };

    let groups = match config::read_net_groups_fragment(&file) {
        Ok(g) => g,
        Err(e) => {
            diag::error(&format!("sbx: net groups import: {e}"));
            return ExitCode::from(2);
        }
    };
    // Validate every name before writing (a name keys a referenceable identifier and, if invalid,
    // would be dropped at load) — fail closed, naming the offender.
    if let Some(bad) = groups.keys().find(|n| !config::is_valid_group_name(n)) {
        diag::error(&format!(
            "sbx: net groups import: invalid group name `{bad}` (1–64 of [A-Za-z0-9._-]); nothing imported"
        ));
        return ExitCode::from(2);
    }

    let cwd = match config_cwd() {
        Ok(d) => d,
        Err(code) => return code,
    };
    let path = match config::manage::scope_path(&config::manage::Scope::Global, &cwd) {
        Ok(p) => p,
        Err(e) => {
            diag::error(&format!("sbx: net groups import: {e}"));
            return ExitCode::from(1);
        }
    };
    // `--force` replaces groups that are already declared, and one may carry an entry added by hand
    // on this machine — an egress group is policy, so a silent drop widens or narrows what an app
    // may reach. Keep each replaced group beside the config BEFORE the write, and report what the
    // incoming fragment no longer declares.
    let replaced = match keep_replaced_groups(&path, &groups, force) {
        Ok(kept) => kept,
        Err(e) => {
            diag::error(&format!(
                "sbx: net groups import: {e} — nothing was overwritten"
            ));
            return ExitCode::FAILURE;
        }
    };
    match config::manage::import_net_groups(&path, &groups, force) {
        Ok(outcome) => {
            for note in &replaced {
                diag::warn(note);
            }
            let mut parts = Vec::new();
            if !outcome.added.is_empty() {
                parts.push(format!("added {}", outcome.added.join(", ")));
            }
            if !outcome.overwritten.is_empty() {
                parts.push(format!("overwrote {}", outcome.overwritten.join(", ")));
            }
            let summary = if parts.is_empty() {
                "nothing to do".to_string()
            } else {
                parts.join("; ")
            };
            println!(
                "imported {} egress group(s) into {} — {summary}",
                groups.len(),
                path.display()
            );
            // Import is the one moment the user consciously brings in someone else's data, so flag any
            // entry that will not resolve (a malformed or nested one) right here — the same inspect-time
            // check `sbx net groups <name>` applies — rather than let it surface only at the next launch.
            let dead: Vec<String> = groups
                .iter()
                .filter(|(_, entries)| entries.iter().any(|e| net_group_entry_issue(e).is_some()))
                .map(|(name, _)| name.clone())
                .collect();
            if !dead.is_empty() {
                diag::warn(&format!(
                    "some entries will not resolve in: {} — inspect with `sbx net groups <name>`",
                    dead.join(", ")
                ));
            }
            ExitCode::SUCCESS
        }
        Err(config::manage::ManageError::GroupCollision(names)) => {
            diag::error(&format!(
                "sbx: net groups import: {} already defined: {} — re-run with --force to overwrite, \
                 or rename in the fragment (nothing was written)",
                if names.len() == 1 { "group" } else { "groups" },
                names.join(", ")
            ));
            ExitCode::from(2)
        }
        Err(e) => {
            diag::error(&format!("sbx: net groups import: {e}"));
            ExitCode::FAILURE
        }
    }
}

/// Why a group entry is not a usable rule, or `None` if it is fine. Mirrors what `build_net_groups`
/// does at resolve time: a leading `@` is a nested reference (a group is flat, so it is ignored);
/// anything else is classified, and a classification error is the reason. Used to flag an entry in
/// the `sbx net groups <name>` listing so a typo in a group is visible where the group is inspected.
fn net_group_entry_issue(entry: &str) -> Option<String> {
    if entry.trim().starts_with('@') {
        return Some("nested group reference — ignored (a group is a flat list of entries)".into());
    }
    allowlist::classify(entry).err()
}

/// Render `sbx net groups` — a pure presenter (its layout is asserted in a test). With no names it
/// lists each group and its entry count; with names it prints each named group's entries (as a
/// `@name` block), appending a note to any entry that would be ignored or is malformed.
fn render_net_groups(
    groups: &std::collections::BTreeMap<String, Vec<String>>,
    names: &[String],
    pal: &style::Palette,
) -> String {
    use std::fmt::Write as _;
    let (h, n, dim, r) = (pal.head, pal.name, pal.dim, pal.reset);
    let plural = |count: usize| if count == 1 { "entry" } else { "entries" };
    let mut o = String::new();

    if names.is_empty() {
        let _ = writeln!(o, "{h}egress groups{r} {dim}({}){r}", groups.len());
        if groups.is_empty() {
            let _ = writeln!(
                o,
                "  {dim}none defined — declare them under [network.groups] in the global config{r}"
            );
            return o;
        }
        let name_w = groups.keys().map(String::len).max().unwrap_or(0);
        for (name, entries) in groups {
            let _ = writeln!(
                o,
                "  {n}{name:<name_w$}{r}  {dim}({} {}){r}",
                entries.len(),
                plural(entries.len())
            );
        }
        let _ = writeln!(
            o,
            "  {}",
            style::dim_prose("resolve one with `sbx net groups <name>`", pal)
        );
        return o;
    }

    for name in names {
        let Some(entries) = groups.get(name) else {
            continue; // an unknown name was already reported by the caller
        };
        let _ = writeln!(
            o,
            "{h}@{name}{r} {dim}({} {}){r}",
            entries.len(),
            plural(entries.len())
        );
        if entries.is_empty() {
            let _ = writeln!(o, "  {dim}(empty){r}");
        }
        for e in entries {
            match net_group_entry_issue(e) {
                None => {
                    let _ = writeln!(o, "  {e}");
                }
                Some(issue) => {
                    let _ = writeln!(o, "  {e}  {dim}({issue}){r}");
                }
            }
        }
    }
    o
}
#[cfg(test)]
mod tests {
    use super::*;

    /// The overwrite warning: a few dropped entries named in full, the rest counted, and always
    /// the path the previous fragment went to — a group lives in a shared file, so that path is the
    /// only way back.
    #[test]
    fn the_group_overwrite_warning_names_a_few_losses_and_counts_the_rest() {
        let kept = std::path::Path::new("/config/sbx/ci.group.replaced");
        let one = crate::cli::render_replaced_fragment(
            "egress group",
            "ci",
            &["\"{GET} https://x\",".to_string()],
            &[],
            kept,
        );
        assert!(one.contains("`ci`") && one.contains("1 line"), "{one}");
        assert!(one.contains("ci.group.replaced"), "{one}");
        let many: Vec<String> = (0..5).map(|i| format!("\"e{i}\",")).collect();
        let lots = crate::cli::render_replaced_fragment("egress group", "ci", &many, &[], kept);
        assert!(
            lots.contains("5 lines") && lots.contains("(and 2 more)"),
            "{lots}"
        );
        // A group that differs only in layout still names where the previous fragment went.
        let none = crate::cli::render_replaced_fragment("egress group", "ci", &[], &[], kept);
        assert!(
            none.contains("only in layout") && none.contains(".replaced"),
            "{none}"
        );
        // Entries the incoming group adds are named too: a wider group is what an import of the
        // same name most often is.
        let gained = crate::cli::render_replaced_fragment(
            "egress group",
            "ci",
            &[],
            &["\"{GET} https://added.example\",".to_string()],
            kept,
        );
        assert!(
            !gained.contains("only in layout") && gained.contains("added.example"),
            "{gained}"
        );
    }

    #[test]
    fn net_group_entry_issue_flags_malformed_and_nested_entries() {
        // A well-formed entry of any kind is fine.
        assert!(net_group_entry_issue("github.com:443").is_none());
        assert!(net_group_entry_issue("{*} api.example.com:443").is_none());
        assert!(net_group_entry_issue("re:^https://x/").is_none());
        // A nested reference is ignored (a group is flat) — reported so a typo is visible.
        let nested = net_group_entry_issue("@other").expect("a nested ref is flagged");
        assert!(nested.contains("nested group reference"), "{nested}");
        // A malformed entry carries the classifier's reason.
        assert!(net_group_entry_issue("https://*").is_some());
    }

    #[test]
    fn render_net_groups_lists_and_resolves() {
        use std::collections::BTreeMap;
        let p = style::Palette::plain();
        let groups: BTreeMap<String, Vec<String>> = [
            ("mcp".to_string(), vec!["{*} a.example.com:443".to_string()]),
            (
                "telemetry".to_string(),
                vec!["*.datadoghq.com:*".to_string(), "*.sentry.io:*".to_string()],
            ),
        ]
        .into_iter()
        .collect();

        // List mode (no names): a count header and one line per group with its entry count.
        let list = render_net_groups(&groups, &[], &p);
        assert!(list.contains("egress groups (2)"), "{list}");
        assert!(list.contains("mcp") && list.contains("(1 entry)"), "{list}");
        assert!(
            list.contains("telemetry") && list.contains("(2 entries)"),
            "{list}"
        );

        // Resolve mode (a name): a `@name` block listing the authored entries verbatim.
        let resolved = render_net_groups(&groups, &["mcp".to_string()], &p);
        assert!(resolved.contains("@mcp (1 entry)"), "{resolved}");
        assert!(resolved.contains("{*} a.example.com:443"), "{resolved}");
        // Only the named group is shown, not the whole set.
        assert!(!resolved.contains("telemetry"), "{resolved}");

        // Empty set: an explicit "none defined" line, not a blank output.
        assert!(render_net_groups(&BTreeMap::new(), &[], &p).contains("none defined"));
    }

    /// An exported fragment is an artifact whose whole purpose is to be handed back to `sbx net
    /// groups import`, so it is written on the terms the config itself is written on: a complete
    /// temp file renamed into place, under a destination directory the writer creates. A
    /// straight-through write refuses a path whose parent does not exist yet, and a write cut short
    /// leaves a truncated group list at exactly the path someone later imports as though it were
    /// whole.
    #[test]
    fn an_exported_group_fragment_lands_whole_in_a_destination_directory_that_did_not_exist() {
        let name = format!("sbx-net-groups-export-{}", std::process::id());
        let base = std::env::temp_dir().join(name);
        let _ = std::fs::remove_dir_all(&base);
        let dir = base.join("2026-08");
        let path = dir.join("groups.toml");
        let fragment = "[network.groups]\nci = [\"api.test\"]\n";

        let _ = write_groups_fragment(&path, fragment, 1);

        let written = std::fs::read_to_string(&path);
        // What the destination directory holds afterwards: the export and nothing else — the
        // temp file the writer stages through is renamed onto the destination, not left beside it.
        let mut left: Vec<String> = match std::fs::read_dir(&dir) {
            Ok(entries) => entries
                .flatten()
                .map(|e| e.file_name().to_string_lossy().into_owned())
                .collect(),
            Err(_) => Vec::new(),
        };
        left.sort();
        let _ = std::fs::remove_dir_all(&base);

        assert_eq!(
            written.ok().as_deref(),
            Some(fragment),
            "the fragment must land under a parent directory that did not exist yet"
        );
        assert_eq!(left, ["groups.toml"], "no staging file may be left behind");
    }
}
