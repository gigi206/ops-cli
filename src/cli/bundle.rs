//! `sbx bundle` — the reusable tool-bundle surface.
//!
//! A bundle (`[bundle.<name>]` in the global config) is everything one tool needs to be *installed*
//! and to *reach its own services*: its packages, the environment it reads, its egress rules, and
//! the credential it authenticates with. An app names one in `use = ["<name>"]` and the fold
//! applies it before resolution, so an orchestrator that drives another agent's CLI states that
//! agent's requirements once instead of copying — and copies are what drift.
//!
//! This module is the read and move surface only: `list`/`show` read the global config,
//! `export`/`import` move bundles between configs. It never resolves or launches anything.

use std::ffi::OsString;
use std::io::IsTerminal;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use crate::cli::import_remedy;
use crate::{config, diag, help, style};

/// `sbx bundle` — dispatch. `export`/`import` are reserved subcommand verbs, so a bundle named
/// `export` is listable and usable in a `use` list but not resolvable by bare name here (use the
/// listing); anything else is the list/show reader.
pub(crate) fn bundle_cmd(args: &[OsString]) -> ExitCode {
    match args.first().and_then(|a| a.to_str()) {
        Some("export") => bundle_export(&args[1..]),
        Some("import") => bundle_import(&args[1..]),
        _ => bundle_list(args),
    }
}

/// `sbx bundle [<name>…] [--json]`: list the tool bundles declared in the global config, or show
/// named ones in full. Bundles are global-only (the fold honors them only from the global config),
/// so there is no scope flag. Read-only, network-free.
fn bundle_list(args: &[OsString]) -> ExitCode {
    let mut json = false;
    let mut names: Vec<String> = Vec::new();
    for arg in args {
        match arg.to_str() {
            Some("--json") => json = true,
            Some(s) if s.starts_with('-') => {
                diag::error(&format!("sbx: bundle: unknown flag `{s}`"));
                diag::error(&format!("sbx: usage: {}", help::synopsis_of(&["bundle"])));
                return ExitCode::from(2);
            }
            Some(s) => names.push(s.to_string()),
            None => {
                diag::error("sbx: bundle: a bundle name must be valid UTF-8");
                return ExitCode::from(2);
            }
        }
    }
    let (bundles, warnings) = config::bundles();
    for w in &warnings {
        diag::warn(w);
    }

    // A named bundle that does not exist is an explicit error, never a blank success — the same
    // shape `sbx net groups` uses, and the same reason: silence would read as "it is empty".
    if let Some(code) = report_missing(&names, &bundles) {
        return code;
    }

    let selected: Vec<(&String, &config::RawBundle)> = if names.is_empty() {
        bundles.iter().collect()
    } else {
        names
            .iter()
            .filter_map(|n| bundles.get_key_value(n))
            .collect()
    };

    if json {
        let obj: Vec<_> = selected
            .iter()
            .map(|(name, b)| {
                serde_json::json!({
                    "name": name,
                    "packages": b.packages,
                    "env": b.env.keys().collect::<Vec<_>>(),
                    "allow": b.allow,
                    "deny": b.deny,
                    "mute": b.mute,
                    "secrets": b.secret.as_ref().map(|s| s.hosts.len()).unwrap_or(0),
                })
            })
            .collect();
        println!("{}", serde_json::json!({ "bundles": obj }));
        return ExitCode::SUCCESS;
    }

    let pal = style::Palette::for_stream(std::io::stdout().is_terminal());
    print!("{}", render_bundles(&selected, names.is_empty(), &pal));
    ExitCode::SUCCESS
}

/// Report every unknown name at once, pointing at what *is* defined. `None` when all names resolve.
fn report_missing(
    names: &[String],
    bundles: &std::collections::BTreeMap<String, config::RawBundle>,
) -> Option<ExitCode> {
    if names.is_empty() {
        return None;
    }
    let missing: Vec<&str> = names
        .iter()
        .filter(|n| !bundles.contains_key(*n))
        .map(String::as_str)
        .collect();
    if missing.is_empty() {
        return None;
    }
    diag::error(&format!(
        "sbx: bundle: no such bundle: {}",
        missing.join(", ")
    ));
    if bundles.is_empty() {
        diag::error(
            "sbx: no bundles are declared — add one under [bundle.<name>] in the global config, \
             or bring one in with `sbx bundle import <file>`",
        );
    } else {
        let avail: Vec<&str> = bundles.keys().map(String::as_str).collect();
        diag::error(&format!("sbx: declared bundles: {}", avail.join(", ")));
    }
    Some(ExitCode::from(2))
}

/// Render the listing: one summary line per bundle when listing them all, the full contents when
/// named. Pure over its inputs so the shape is unit-testable without a config on disk.
fn render_bundles(
    selected: &[(&String, &config::RawBundle)],
    summary: bool,
    pal: &style::Palette,
) -> String {
    use std::fmt::Write as _;
    let (n, dim, r) = (pal.name, pal.dim, pal.reset);
    let mut out = String::new();
    if selected.is_empty() {
        let _ = writeln!(
            out,
            "  {dim}none declared — add one under [bundle.<name>] in the global config, or bring \
             one in with `sbx bundle import`{r}"
        );
        return out;
    }
    for (name, b) in selected {
        if summary {
            // Count what the bundle contributes, so the listing answers "how much does using this
            // pull in?" without printing the whole thing.
            let mut parts = Vec::new();
            if !b.packages.is_empty() {
                parts.push(format!("{} package(s)", b.packages.len()));
            }
            if !b.env.is_empty() {
                parts.push(format!("{} env", b.env.len()));
            }
            let rules = b.allow.len() + b.deny.len() + b.mute.len();
            if rules > 0 {
                parts.push(format!("{rules} egress rule(s)"));
            }
            if let Some(creds) = b.secret.as_ref().map(|s| s.hosts.len()).filter(|c| *c > 0) {
                parts.push(format!("{creds} credential(s)"));
            }
            if b.provision.is_some() {
                parts.push("an install step".to_string());
            }
            if parts.is_empty() {
                parts.push("empty".to_string());
            }
            let _ = writeln!(out, "{n}{name}{r}  {dim}{}{r}", parts.join(", "));
            continue;
        }
        let _ = writeln!(out, "{n}{name}{r}");
        for (k, v) in &b.packages {
            out.push_str(&format!("  package  {k} = {v}\n"));
        }
        // Values are not printed: an env entry may carry a token placeholder, and the listing is
        // about what using the bundle *brings in*, not about its contents.
        for k in b.env.keys() {
            out.push_str(&format!("  env      {k}\n"));
        }
        for e in &b.allow {
            out.push_str(&format!("  allow    {e}\n"));
        }
        for e in &b.deny {
            out.push_str(&format!("  deny     {e}\n"));
        }
        for e in &b.mute {
            out.push_str(&format!("  mute     {e}\n"));
        }
        if let Some(secret) = &b.secret {
            for host in secret.hosts.keys() {
                out.push_str(&format!("  secret   {host} (injected host-side)\n"));
            }
        }
        // Printed in full, unlike an env value: this one is a command that will run in the cage,
        // and a reader deciding whether to name this bundle is deciding about exactly these words.
        if let Some(provision) = &b.provision {
            out.push_str(&format!(
                "  install  {} (runs once, before the app's own command)\n",
                provision.clone().into_argv().join(" ")
            ));
        }
    }
    out
}

/// `sbx bundle export [<name>…] [--out <file>]`: write the bundles as a portable
/// `[bundle.<name>]` TOML fragment — every one, or the named subset — to stdout (the default:
/// composable and clobber-safe) or to `--out <file>`. The inverse of `import`.
fn bundle_export(args: &[OsString]) -> ExitCode {
    let mut out_file: Option<PathBuf> = None;
    let mut names: Vec<String> = Vec::new();
    let mut it = args.iter();
    while let Some(arg) = it.next() {
        match arg.to_str() {
            Some("--out") | Some("-o") => match it.next() {
                Some(p) => out_file = Some(PathBuf::from(p)),
                None => {
                    diag::error("sbx: bundle export: `--out` needs a file path");
                    return ExitCode::from(2);
                }
            },
            Some(s) if s.starts_with('-') => {
                diag::error(&format!("sbx: bundle export: unknown flag `{s}`"));
                diag::error(&format!(
                    "sbx: usage: {}",
                    help::synopsis_of(&["bundle", "export"])
                ));
                return ExitCode::from(2);
            }
            Some(s) => names.push(s.to_string()),
            None => {
                diag::error("sbx: bundle export: a bundle name must be valid UTF-8");
                return ExitCode::from(2);
            }
        }
    }

    let (bundles, warnings) = config::bundles();
    for w in &warnings {
        diag::warn(w);
    }
    if let Some(code) = report_missing(&names, &bundles) {
        return code;
    }
    let selected: std::collections::BTreeMap<String, config::RawBundle> = if names.is_empty() {
        bundles
    } else {
        names
            .iter()
            .filter_map(|n| bundles.get_key_value(n))
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect()
    };
    if selected.is_empty() {
        diag::error(
            "sbx: bundle export: no bundles to export (none are declared under [bundle.<name>] \
             in the global config)",
        );
        return ExitCode::from(1);
    }

    let fragment = match config::manage::export_bundles(&selected) {
        Ok(f) => f,
        Err(e) => {
            diag::error(&format!("sbx: bundle export: {e}"));
            return ExitCode::FAILURE;
        }
    };
    match out_file {
        Some(path) => {
            // No mode of sbx's own: `sbx bundle export > bundles.toml` and `--out <file>` are
            // the same command spelled two ways, and a fragment is an artifact to hand on.
            if let Err(e) = config::manage::write_text(&path, &fragment, None) {
                diag::error(&format!(
                    "sbx: bundle export: cannot write {}: {e}",
                    path.display()
                ));
                return ExitCode::FAILURE;
            }
            println!(
                "exported {} bundle(s) to {}",
                selected.len(),
                path.display()
            );
        }
        None => print!("{fragment}"),
    }
    ExitCode::SUCCESS
}

/// Keep every bundle a forced import is about to replace, and say what the incoming fragment no
/// longer declares. Returns one warning per replaced bundle, for the caller to surface once the
/// write succeeded.
///
/// A bundle is a table inside the shared global config, not a file of its own, so the copy an app
/// profile gets (`<name>.toml.replaced`, beside it) has no equivalent here. What stands in for it is
/// the fragment `sbx bundle export` already emits: the replaced bundle is written back out in the
/// same portable form, as `<name>.bundle.replaced` beside the config, so re-declaring it is
/// `sbx bundle import` on that file. The name ends in neither `.toml` nor a profile path, so
/// nothing reads it as configuration.
///
/// Only a bundle whose declaration actually CHANGES is kept: re-importing an identical fragment
/// leaves no copy and reports nothing. An error here fails the import closed, before the write, so
/// a bundle is never overwritten with no way back.
fn keep_replaced_bundles(
    config_path: &Path,
    incoming: &std::collections::BTreeMap<String, config::RawBundle>,
    force: bool,
) -> Result<Vec<String>, String> {
    if !force {
        return Ok(Vec::new());
    }
    let Some(dir) = config_path.parent() else {
        return Ok(Vec::new());
    };
    let (declared, _) = config::bundles();
    let mut notes = Vec::new();
    for (name, new) in incoming {
        let Some(old) = declared.get(name) else {
            continue; // added, not replaced
        };
        let one = |n: &String, b: &config::RawBundle| {
            config::manage::export_bundles(&std::collections::BTreeMap::from([(
                n.clone(),
                b.clone(),
            )]))
        };
        let (before, after) = (one(name, old)?, one(name, new)?);
        if before == after {
            continue;
        }
        let kept = dir.join(format!("{name}.bundle.replaced"));
        std::fs::write(&kept, &before).map_err(|e| {
            format!(
                "cannot keep the bundle being replaced at {}: {e}",
                kept.display()
            )
        })?;
        notes.push(render_replaced_bundle(
            name,
            &crate::cli::settings_dropped_by(&before, &after),
            &kept,
        ));
    }
    Ok(notes)
}

/// The overwrite warning for one bundle: what its replacement no longer declares, and where the
/// previous fragment is. A few dropped lines are named in full (the point is to recognize one's own
/// edit); beyond that the count stands in, because the kept fragment is the better place to read
/// the rest.
fn render_replaced_bundle(name: &str, dropped: &[String], kept: &Path) -> String {
    const NAMED: usize = 3;
    let kept = kept.display();
    if dropped.is_empty() {
        return format!(
            "replaced bundle `{name}`, which differed only in layout — the previous fragment is \
             kept at {kept}"
        );
    }
    let named = dropped
        .iter()
        .take(NAMED)
        .map(|l| format!("`{l}`"))
        .collect::<Vec<_>>()
        .join(", ");
    let rest = dropped.len().saturating_sub(NAMED);
    let more = if rest > 0 {
        format!(" (and {rest} more)")
    } else {
        String::new()
    };
    format!(
        "replaced bundle `{name}`, which declared {} the new one does not: {named}{more} — the \
         previous fragment is kept at {kept}, so a per-machine entry can be read back and \
         re-imported",
        if dropped.len() == 1 {
            "1 line".to_string()
        } else {
            format!("{} lines", dropped.len())
        },
    )
}

/// `sbx bundle import <file> [--force]`: merge a portable `[bundle.<name>]` fragment into the
/// global config, preserving every existing bundle and comment. Bundles are global-only, so the
/// target is always the global config; the deliberate command is the consent (an agent in the cage
/// cannot run it), and the global config is trusted by location, so there is no prompt. A name that
/// already exists is refused unless `--force` overwrites it. An imported bundle is **inert** until
/// an app names it in `use`.
fn bundle_import(args: &[OsString]) -> ExitCode {
    let (file, force) = match crate::cli::one_file(args, &["bundle", "import"], &["-f", "--force"])
    {
        Ok(parsed) => parsed,
        Err(code) => return code,
    };

    let bundles = match config::read_bundle_fragment(&file) {
        Ok(b) => b,
        Err(e) => {
            diag::error(&format!("sbx: bundle import: {e}"));
            return ExitCode::from(2);
        }
    };
    // Validate every name before writing — an invalid one would be dropped at load, leaving an app
    // that names it silently short of its tool. Fail closed, naming the offender.
    if let Some(bad) = bundles.keys().find(|n| !config::is_valid_bundle_name(n)) {
        diag::error(&format!(
            "sbx: bundle import: invalid bundle name `{bad}` (1–64 of [A-Za-z0-9._-]); nothing \
             imported"
        ));
        return ExitCode::from(2);
    }

    let cwd = match std::env::current_dir() {
        Ok(d) => d,
        Err(e) => {
            diag::error(&format!("sbx: cannot read the current directory: {e}"));
            return ExitCode::FAILURE;
        }
    };
    let path = match config::manage::scope_path(&config::manage::Scope::Global, &cwd) {
        Ok(p) => p,
        Err(e) => {
            diag::error(&format!("sbx: bundle import: {e}"));
            return ExitCode::from(1);
        }
    };
    // `--force` replaces bundles that are already declared, and one may carry a rule or a package
    // added by hand on this machine. Keep each replaced bundle beside the config BEFORE the write,
    // and report what the incoming fragment no longer declares.
    let replaced = match keep_replaced_bundles(&path, &bundles, force) {
        Ok(kept) => kept,
        Err(e) => {
            diag::error(&format!(
                "sbx: bundle import: {e} — nothing was overwritten"
            ));
            return ExitCode::FAILURE;
        }
    };
    match config::manage::import_bundles(&path, &bundles, force) {
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
                "imported {} bundle(s) into {} — {summary}",
                bundles.len(),
                path.display()
            );
            if let Some(note) = granting_note(&bundles) {
                diag::warn(&note);
            }
            // A bundle's egress list may reference a group, and a group is global-only: undefined,
            // its entries are dropped at the fold and the consuming app reaches LESS than the
            // bundle names. This is where the majority of them surface — an app profile resolves
            // nothing from disk, so `sbx app import` cannot see into the bundle its `use` names,
            // and without this the reference is silent until a launch that quietly falls short.
            if let Some(note) = undefined_groups_note(&bundles, &file) {
                diag::warn(&note);
            }
            ExitCode::SUCCESS
        }
        Err(e) => {
            diag::error(&format!("sbx: bundle import: {e}"));
            ExitCode::from(1)
        }
    }
}

/// What naming these bundles from an app would grant, or `None` when they carry nothing to warn
/// about. Import is the one moment someone consciously brings in another author's data, so the
/// grant is named here rather than surfacing as a credential or an egress rule at the next launch.
///
/// Shared with `sbx app import --with-deps`, which writes bundles the user never named on the
/// command line: the announcement has to follow the bytes, not the verb that happened to write
/// them, or the one import where the grant is least expected would be the one that stays silent.
pub(crate) fn granting_note(
    bundles: &std::collections::BTreeMap<String, config::RawBundle>,
) -> Option<String> {
    let granting: Vec<String> = bundles
        .iter()
        .filter_map(|(name, b)| {
            let rules = b.allow.len() + b.deny.len() + b.mute.len();
            let creds = b.secret.as_ref().map(|s| s.hosts.len()).unwrap_or(0);
            // An install step is named apart from the counts: it is a command that will run in the
            // consuming app's cage, which is a different kind of grant from a host or a key, and the
            // one a reader is least likely to expect.
            let step = b.provision.is_some().then_some(", an install step");
            (rules > 0 || creds > 0 || step.is_some()).then(|| {
                format!(
                    "{name} ({rules} egress rule(s), {creds} credential(s){})",
                    step.unwrap_or("")
                )
            })
        })
        .collect();
    (!granting.is_empty()).then(|| {
        format!(
            "an app that names these gains their egress, credentials and install steps: {} — \
             inspect with `sbx bundle <name>`",
            granting.join(", ")
        )
    })
}

/// The groups a set of bundles reference that `declared` does not define, each paired with the
/// sibling file that declares it. `src` is the file being imported, so a remedy built from this can
/// name where each group most likely came from.
///
/// Read from the *incoming* bundles rather than from the folded config: the fold drops an
/// unresolved reference and only records it against the consuming app, so a bundle imported before
/// any app names it would carry the gap with nothing to attribute it to. `declared` is passed in
/// rather than read here, so a caller that already holds the group table decides against one set of
/// bytes throughout instead of re-reading a file that may have changed under it.
pub(crate) fn undefined_groups(
    bundles: &std::collections::BTreeMap<String, config::RawBundle>,
    src: &Path,
    declared: &std::collections::BTreeMap<String, Vec<String>>,
) -> Vec<crate::cli::MissingRef> {
    let referenced = config::group_refs(
        bundles
            .values()
            .flat_map(|b| b.allow.iter().chain(b.deny.iter()).chain(b.mute.iter())),
    );
    if referenced.is_empty() {
        return Vec::new();
    }
    crate::cli::missing_refs(
        &referenced,
        declared,
        src,
        "net-groups",
        config::read_net_groups_fragment,
    )
}

/// The warning for [`undefined_groups`], or `None` when every reference resolves.
fn undefined_groups_note(
    bundles: &std::collections::BTreeMap<String, config::RawBundle>,
    src: &Path,
) -> Option<String> {
    let (declared, _) = config::net_groups();
    let missing = undefined_groups(bundles, src, &declared);
    if missing.is_empty() {
        return None;
    }
    let remedy = import_remedy("net groups import", &missing);
    Some(format!(
        "{} no `[network.groups]` here defines: {} — import {} too ({remedy}), or those entries \
         are ignored and an app using this bundle reaches less than it names",
        if missing.len() == 1 {
            "this bundle references an egress group"
        } else {
            "this bundle references egress groups"
        },
        missing
            .iter()
            .map(|m| format!("@{}", m.name))
            .collect::<Vec<_>>()
            .join(", "),
        if missing.len() == 1 { "it" } else { "them" },
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bundle_of(packages: &[(&str, &str)], allow: &[&str]) -> config::RawBundle {
        config::RawBundle {
            packages: packages
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
            allow: allow.iter().map(|s| s.to_string()).collect(),
            ..config::RawBundle::default()
        }
    }

    /// The overwrite warning: a few dropped lines named in full, the rest counted, and always the
    /// path the previous fragment went to — a bundle lives in a shared file, so that path is the
    /// only way back.
    #[test]
    fn the_bundle_overwrite_warning_names_a_few_losses_and_counts_the_rest() {
        let kept = Path::new("/config/sbx/demo.bundle.replaced");
        let one = render_replaced_bundle("demo", &["allow = [\"x\"]".to_string()], kept);
        assert!(one.contains("`demo`") && one.contains("1 line"), "{one}");
        assert!(one.contains("demo.bundle.replaced"), "{one}");
        let many: Vec<String> = (0..5).map(|i| format!("k{i} = {i}")).collect();
        let lots = render_replaced_bundle("demo", &many, kept);
        assert!(
            lots.contains("5 lines") && lots.contains("(and 2 more)"),
            "{lots}"
        );
        assert!(
            lots.contains("`k0 = 0`") && !lots.contains("`k4 = 4`"),
            "{lots}"
        );
        // A bundle that differs only in layout still names where the previous fragment went.
        let none = render_replaced_bundle("demo", &[], kept);
        assert!(
            none.contains("only in layout") && none.contains(".replaced"),
            "{none}"
        );
    }

    #[test]
    fn the_listing_summarizes_what_using_a_bundle_would_pull_in() {
        // The summary line has to answer "how much does this bring?" — a bundle that grants egress
        // must not read the same as one that only installs a tool.
        let pal = style::Palette::plain();
        let tool = bundle_of(&[("demo", "mise:demo")], &[]);
        let reaching = bundle_of(&[("demo", "mise:demo")], &["{*} https://api.example.com"]);
        let name_a = "tool-only".to_string();
        let name_b = "reaching".to_string();

        let out = render_bundles(&[(&name_a, &tool), (&name_b, &reaching)], true, &pal);
        assert!(out.contains("tool-only  1 package(s)"), "{out}");
        assert!(
            out.contains("reaching  1 package(s), 1 egress rule(s)"),
            "the egress a bundle grants is visible in the summary: {out}"
        );
        assert!(
            !out.contains("api.example.com"),
            "but the summary stays a summary: {out}"
        );

        // Named, the full contents print — including the rule the summary only counted.
        let shown = render_bundles(&[(&name_b, &reaching)], false, &pal);
        assert!(
            shown.contains("allow    {*} https://api.example.com"),
            "{shown}"
        );
        assert!(shown.contains("package  demo = mise:demo"), "{shown}");
    }

    #[test]
    fn an_install_step_is_named_in_the_summary_and_printed_in_full_when_shown() {
        // A `provision` runs a command inside the cage before the app's own, so a reader deciding
        // whether to name this bundle is deciding about exactly those words: the summary must say
        // one exists, and the full listing must print it rather than counting it.
        let pal = style::Palette::plain();
        let mut b = bundle_of(&[("demo", "mise:demo")], &[]);
        b.provision = Some(config::RawCmd::Argv(vec![
            "bash".to_string(),
            "-c".to_string(),
            "npm rebuild demo-addon".to_string(),
        ]));
        let name = "with-install".to_string();

        let summary = render_bundles(&[(&name, &b)], true, &pal);
        assert!(
            summary.contains("1 package(s), an install step"),
            "the summary says a step exists: {summary}"
        );
        assert!(
            !summary.contains("npm rebuild"),
            "but does not print it: {summary}"
        );

        let shown = render_bundles(&[(&name, &b)], false, &pal);
        assert!(
            shown.contains("install  bash -c npm rebuild demo-addon"),
            "the full listing prints the command verbatim: {shown}"
        );
        assert!(
            shown.contains("before the app's own command"),
            "and says when it runs, since that is what distinguishes it from a `cmd`: {shown}"
        );
    }

    #[test]
    fn an_export_round_trips_back_through_the_fragment_reader() {
        // `export` writes what `import` reads: the pair is the whole portability story, so a shape
        // either side cannot express would strand a bundle.
        let mut b = bundle_of(
            &[("demo", "mise:aqua:example/demo")],
            &["{*,WS} https://api.example.com"],
        );
        b.env = [("DEMO_HOME".to_string(), "/tmp/demo".to_string())]
            .into_iter()
            .collect();
        b.mute = vec!["*.telemetry.example.com".to_string()];
        let set: std::collections::BTreeMap<String, config::RawBundle> =
            [("demo".to_string(), b.clone())].into_iter().collect();

        let fragment = config::manage::export_bundles(&set).expect("export serializes");
        assert!(
            fragment.contains("[bundle.demo]"),
            "the fragment is keyed under `bundle`: {fragment}"
        );
        let tmp = crate::testutil::TmpDir::new();
        let path = tmp.path().join("bundles.toml");
        std::fs::write(&path, &fragment).unwrap();
        let parsed = config::read_bundle_fragment(&path).expect("the fragment re-parses");
        assert_eq!(parsed, set, "export → import is lossless");
    }
}
