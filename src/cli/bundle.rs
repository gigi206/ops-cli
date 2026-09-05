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

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::io::IsTerminal;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use crate::cli::import_remedy;
use crate::{config, config_cwd, diag, help, style};

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
        diag::warn_config(w);
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
                    // Everything below is what a consuming app also folds in. Left out, a `--json`
                    // audit of an imported fragment reported a bundle as harmless while it carried
                    // a declared operation, a service or a URI handler.
                    "provision": b.provision.is_some(),
                    "tasks": b.task.as_ref()
                        .map(|t| t.tasks.keys().collect::<Vec<_>>())
                        .unwrap_or_default(),
                    "services": b.service.keys().collect::<Vec<_>>(),
                    "open": b.open.keys().collect::<Vec<_>>(),
                    "flakes": b.flakes.keys().collect::<Vec<_>>(),
                    // Keyed on the `resolve` command rather than on the table holding it: the same
                    // table may carry `libs` alone, which rolls nothing, so listing every table
                    // here would report an upgrade path a `--json` audit cannot act on. The
                    // library attributes such a table does grant are reported beside it.
                    "resolvers": {
                        "tarball": resolver_names(&b.tarball),
                        "deb": resolver_names(&b.deb),
                        "appimage": resolver_names(&b.appimage),
                        "binary": resolver_names(&b.binary),
                    },
                    "libs": {
                        "tarball": lib_names(&b.tarball),
                        "deb": lib_names(&b.deb),
                        "appimage": lib_names(&b.appimage),
                        "binary": lib_names(&b.binary),
                    },
                    // Beside `libs` for the same reason: it is the other half of what such a table
                    // grants, and it decides which file in the artefact the launch actually runs.
                    "main": {
                        "tarball": main_names(&b.tarball),
                        "deb": main_names(&b.deb),
                        "appimage": main_names(&b.appimage),
                        "binary": main_names(&b.binary),
                    },
                    "accepts_fresh_releases": b.accepts_fresh_releases,
                    "undescribed": undescribed_sections(b),
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
            // pull in?" without printing the whole thing. The grant phrases come from the same
            // `grants_of` the import warning is built from, so a bundle cannot read as `empty`
            // here and grant something there.
            let mut parts = Vec::new();
            if !b.packages.is_empty() {
                parts.push(format!("{} package(s)", b.packages.len()));
            }
            if !b.env.is_empty() {
                parts.push(format!("{} env", b.env.len()));
            }
            parts.extend(grants_of(b));
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
        // The rest of what a consuming app folds in. It was absent here as well as from the
        // summary, so the remedy the import warning names — "inspect with `sbx bundle <name>`" —
        // could not show the largest grant a fragment can carry.
        for name in &b.accepts_fresh_releases {
            out.push_str(&format!(
                "  fresh    {name} (accepted with no cooling-off period)\n"
            ));
        }
        for name in b.flakes.keys() {
            out.push_str(&format!("  flake    {name} (inline flake source)\n"));
        }
        for (table, entries) in [
            ("tarball", &b.tarball),
            ("deb", &b.deb),
            ("appimage", &b.appimage),
            ("binary", &b.binary),
        ] {
            for (name, entry) in entries {
                // The two halves of such a table are reported separately, because only one of them
                // is an upgrade path: a table carrying `libs` alone rolls nothing, and calling it a
                // resolver would promise a release lookup that does not exist.
                if !entry.resolve.is_empty() {
                    out.push_str(&format!(
                        "  resolve  {name} ({table}: where an upgrade looks for a new release)\n"
                    ));
                }
                if !entry.libs.is_empty() {
                    out.push_str(&format!(
                        "  libs     {name} ({table}: {} extra nixpkgs attribute(s) the build \
                         patches against)\n",
                        entry.libs.len()
                    ));
                }
                // Named on its own line, because it decides which file in the artefact the launch
                // runs: a reader deciding whether to fold this bundle in is owed that, not just the
                // fact that a table exists.
                if !entry.main.is_empty() {
                    out.push_str(&format!(
                        "  main     {name} ({table}: `{}` is the program inside the artefact)\n",
                        entry.main
                    ));
                }
            }
        }
        for scheme in b.open.keys() {
            out.push_str(&format!(
                "  open     {scheme}: (URI handler, run in the cage)\n"
            ));
        }
        for name in b.service.keys() {
            out.push_str(&format!(
                "  service  {name} (started with the cage and kept running)\n"
            ));
        }
        if let Some(task) = &b.task {
            for name in task.tasks.keys() {
                out.push_str(&format!(
                    "  task     {name} (a declared operation the caged agent can invoke)\n"
                ));
            }
        }
        for key in undescribed_sections(b) {
            out.push_str(&format!(
                "  section  [{key}] — read it in the fragment before importing\n"
            ));
        }
    }
    out
}

/// The bundle sections the listing and the grant note account for by name, keyed as they are in the
/// TOML.
///
/// Compared against what a bundle actually serializes to, so the two readers below cannot fall
/// behind the schema: the way they fell behind was a field added to `RawBundle` and not added here,
/// after which the import announced less than it wrote and the listing showed less than it held.
/// This is the construction `describe_app_posture` already applies to an app profile, for the same
/// reason — consent is never given to something unstated.
const DESCRIBED_BUNDLE_SECTIONS: &[&str] = &[
    "packages",
    "accepts_fresh_releases",
    "env",
    "allow",
    "deny",
    "mute",
    "secret",
    "provision",
    "task",
    "flakes",
    "open",
    "service",
    "tarball",
    "deb",
    "appimage",
    "binary",
];

/// The packages in one `[<backend>.<name>]` map whose table carries a `resolve` command — the ones
/// `sbx upgrade` re-queries for a new release.
///
/// Split from [`lib_names`] because the two halves of such a table are independent: a table may
/// carry either, or both. Reporting the map's keys instead would name an upgrade path for a table
/// that declares only library attributes, and so has none.
fn resolver_names(tables: &BTreeMap<String, config::RawResolve>) -> Vec<&String> {
    tables
        .iter()
        .filter(|(_, table)| !table.resolve.is_empty())
        .map(|(name, _)| name)
        .collect()
}

/// The packages in one `[<backend>.<name>]` map whose table carries extra nixpkgs library
/// attributes — what widens the set the package's ELFs are autoPatchelf'd against.
fn lib_names(tables: &BTreeMap<String, config::RawResolve>) -> Vec<&String> {
    tables
        .iter()
        .filter(|(_, table)| !table.libs.is_empty())
        .map(|(name, _)| name)
        .collect()
}

/// The packages in one `[<backend>.<name>]` map whose table names the program inside the artefact —
/// the third independent half of such a table, beside its resolver and its library attributes.
fn main_names(tables: &BTreeMap<String, config::RawResolve>) -> Vec<&String> {
    tables
        .iter()
        .filter(|(_, table)| !table.main.is_empty())
        .map(|(name, _)| name)
        .collect()
}

/// Every top-level key a bundle declares that neither [`render_bundles`] nor [`grants_of`] renders
/// a line of its own for — including a key sbx does not know, which `RawBundle` keeps rather than
/// discards.
fn undescribed_sections(b: &config::RawBundle) -> Vec<String> {
    let Ok(toml::Value::Table(table)) = toml::Value::try_from(b) else {
        return Vec::new();
    };
    table
        .keys()
        .filter(|k| !DESCRIBED_BUNDLE_SECTIONS.contains(&k.as_str()))
        .cloned()
        .collect()
}

/// What naming this bundle from an app would grant, phrase by phrase — empty when it carries only
/// the tools it installs and the environment they read, which grant nothing beyond themselves.
///
/// Each kind is named apart from the counts it is not comparable with. An install step, a declared
/// operation and a service are commands that will run; a URI handler is a scheme the cage will act
/// on; a resolver is where an upgrade will look. None of those is a host or a key, and the
/// difference is the whole point of the announcement — a `[task]` in particular is a fixed
/// host-side command an app's caged agent may invoke over the task control socket, with a
/// credential the caller never holds.
///
/// A section with no phrase of its own is named by its key, so the disclosure cannot fall behind
/// the schema: while this counted egress, credentials and the install step alone, a bundle carrying
/// nothing but a `[task]` returned no warning at all and was imported in silence.
fn grants_of(b: &config::RawBundle) -> Vec<String> {
    let mut parts: Vec<String> = Vec::new();
    let rules = b.allow.len() + b.deny.len() + b.mute.len();
    if rules > 0 {
        parts.push(format!("{rules} egress rule(s)"));
    }
    if let Some(creds) = b.secret.as_ref().map(|s| s.hosts.len()).filter(|c| *c > 0) {
        parts.push(format!("{creds} credential(s)"));
    }
    // Named apart from the egress rules it is not: a group grants no reach, it widens where a
    // credential the cage obtained for itself may travel. The fallback below would have named the
    // section, which says a key was written rather than what naming this bundle would allow.
    if !b.shared_credential.is_empty() {
        parts.push(format!(
            "{} shared-credential group(s)",
            b.shared_credential.len()
        ));
    }
    if b.provision.is_some() {
        parts.push("an install step".to_string());
    }
    if let Some(tasks) = b.task.as_ref().map(|t| t.tasks.len()).filter(|n| *n > 0) {
        parts.push(format!("{tasks} declared operation(s)"));
    }
    if !b.service.is_empty() {
        parts.push(format!("{} service(s)", b.service.len()));
    }
    if !b.open.is_empty() {
        parts.push(format!("{} URI handler(s)", b.open.len()));
    }
    if !b.flakes.is_empty() {
        parts.push(format!("{} inline flake(s)", b.flakes.len()));
    }
    // A `[<backend>.<name>]` table declares two separable things, and only one of them is an
    // upgrade path: the `resolve` command is what `sbx upgrade` re-runs, while a `libs` list widens
    // the nixpkgs attributes the package's ELFs are patched against. A table carrying `libs` alone
    // rolls nothing, so counting the tables would name a resolver that does not exist — and would
    // leave unnamed the one thing such a table does grant, which is a wider build input set.
    let prebuilt = [&b.tarball, &b.deb, &b.appimage, &b.binary];
    let resolvers = prebuilt
        .iter()
        .flat_map(|tables| tables.values())
        .filter(|table| !table.resolve.is_empty())
        .count();
    if resolvers > 0 {
        parts.push(format!("{resolvers} upgrade resolver(s)"));
    }
    let libs: usize = prebuilt
        .iter()
        .flat_map(|tables| tables.values())
        .map(|table| table.libs.len())
        .sum();
    if libs > 0 {
        parts.push(format!("{libs} extra library attribute(s)"));
    }
    let mains = prebuilt
        .iter()
        .flat_map(|tables| tables.values())
        .filter(|table| !table.main.is_empty())
        .count();
    if mains > 0 {
        parts.push(format!("{mains} declared program name(s)"));
    }
    if !b.accepts_fresh_releases.is_empty() {
        parts.push(format!(
            "{} freshness exemption(s)",
            b.accepts_fresh_releases.len()
        ));
    }
    parts.extend(
        undescribed_sections(b)
            .into_iter()
            .map(|key| format!("a `{key}` section")),
    );
    parts
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
        diag::warn_config(w);
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
/// longer declares — [`super::keep_replaced_fragments`] with this family's nouns and exporter.
///
/// A bundle is a table inside the shared global config, not a file of its own, so the copy an app
/// profile gets (`<name>.toml.replaced`, beside it) has no equivalent here. What stands in for it is
/// the fragment `sbx bundle export` already emits: the replaced bundle is written back out in the
/// same portable form, as `<name>.bundle.replaced` beside the config, so re-declaring it is
/// `sbx bundle import` on that file.
fn keep_replaced_bundles(
    config_path: &Path,
    incoming: &std::collections::BTreeMap<String, config::RawBundle>,
    force: bool,
) -> Result<Vec<String>, String> {
    super::keep_replaced_fragments(
        config_path,
        incoming,
        || config::bundles().0,
        force,
        "bundle",
        "bundle",
        |name, bundle| {
            config::manage::export_bundles(&std::collections::BTreeMap::from([(
                name.to_string(),
                bundle.clone(),
            )]))
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

    let cwd = match config_cwd() {
        Ok(d) => d,
        Err(code) => return code,
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
            let grants = grants_of(b);
            (!grants.is_empty()).then(|| format!("{name} ({})", grants.join(", ")))
        })
        .collect();
    (!granting.is_empty()).then(|| {
        format!(
            "an app that names these gains everything they declare: {} — inspect with \
             `sbx bundle <name>`",
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
        let one = crate::cli::render_replaced_fragment(
            "bundle",
            "demo",
            &["allow = [\"x\"]".to_string()],
            kept,
        );
        assert!(one.contains("`demo`") && one.contains("1 line"), "{one}");
        assert!(one.contains("demo.bundle.replaced"), "{one}");
        let many: Vec<String> = (0..5).map(|i| format!("k{i} = {i}")).collect();
        let lots = crate::cli::render_replaced_fragment("bundle", "demo", &many, kept);
        assert!(
            lots.contains("5 lines") && lots.contains("(and 2 more)"),
            "{lots}"
        );
        assert!(
            lots.contains("`k0 = 0`") && !lots.contains("`k4 = 4`"),
            "{lots}"
        );
        // A bundle that differs only in layout still names where the previous fragment went.
        let none = crate::cli::render_replaced_fragment("bundle", "demo", &[], kept);
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

    /// A `[<backend>.<name>]` table is read for what it declares, not for existing: a `resolve`
    /// command is an upgrade path, a `libs` list is a wider build input set, and a table may carry
    /// either alone.
    ///
    /// Both halves are asserted in one test because the defect is the confusion between them: a
    /// reader told a libs-only table is "1 upgrade resolver" will look for a roll that never
    /// happens, and one told nothing about the attributes never learns the build reaches further
    /// than the shared set. The control is the resolver arm — it must keep reading exactly as it
    /// did, or this would be a rename rather than a distinction.
    #[test]
    fn a_prebuilt_table_is_reported_by_what_it_declares_not_by_existing() {
        let pal = style::Palette::plain();

        let mut libs_only = bundle_of(&[("demo", "deb:https://example.com/demo.deb")], &[]);
        libs_only.deb.insert(
            "demo".to_string(),
            config::RawResolve {
                resolve: Vec::new(),
                libs: vec!["libusb1".to_string(), "qt6.qtbase.out".to_string()],
                main: String::new(),
            },
        );
        let name = "libs-only".to_string();

        let summary = render_bundles(&[(&name, &libs_only)], true, &pal);
        assert!(
            summary.contains("1 package(s), 2 extra library attribute(s)"),
            "a libs-only table is counted as what it is: {summary}"
        );
        assert!(
            !summary.contains("resolver"),
            "and never as an upgrade path it does not carry: {summary}"
        );

        let shown = render_bundles(&[(&name, &libs_only)], false, &pal);
        assert!(
            shown.contains("libs     demo (deb: 2 extra nixpkgs attribute(s)"),
            "the full listing names the table and how many attributes it adds: {shown}"
        );
        assert!(!shown.contains("resolve  demo"), "{shown}");

        // The control: a table that does carry a command still reads as a resolver, and a table
        // carrying both is reported twice rather than one masking the other.
        let mut both = bundle_of(&[("demo", "deb:resolve")], &[]);
        both.deb.insert(
            "demo".to_string(),
            config::RawResolve {
                resolve: vec!["sh".to_string(), "-c".to_string(), "echo url".to_string()],
                libs: vec!["webkitgtk_4_1".to_string()],
                main: String::new(),
            },
        );
        let name = "both".to_string();
        let summary = render_bundles(&[(&name, &both)], true, &pal);
        assert!(
            summary.contains("1 upgrade resolver(s), 1 extra library attribute(s)"),
            "{summary}"
        );
        let shown = render_bundles(&[(&name, &both)], false, &pal);
        assert!(shown.contains("resolve  demo (deb:"), "{shown}");
        assert!(shown.contains("libs     demo (deb:"), "{shown}");
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

    /// A bundle carrying only a `[task]` used to import in complete silence and then show as
    /// `empty` in the very listing the warning tells the reader to consult. A `[task.<name>]` is a
    /// fixed host-side command run in an ephemeral sibling cage with a credential the caller never
    /// holds, folded into every app that names the bundle in `use` — the largest grant a fragment
    /// can carry, announced by nothing. The disclosure counted egress rules, credentials and the
    /// install step and stopped there.
    #[test]
    fn a_bundle_that_grants_only_a_task_is_announced_and_listed() {
        let b: config::RawBundle = toml::from_str(concat!(
            "packages = { helper = \"mise:helper\" }\n",
            "[task.sync]\n",
            "cmd = [\"/bin/true\"]\n",
        ))
        .expect("the fragment parses");
        let set: std::collections::BTreeMap<String, config::RawBundle> =
            [("helper".to_string(), b.clone())].into_iter().collect();

        let note = granting_note(&set).expect("a declared operation is a grant");
        assert!(
            note.contains("helper") && note.contains("declared operation"),
            "the import must name the operation it writes: {note}"
        );

        // The remedy the note names has to be able to show it, in both renderings.
        let name = "helper".to_string();
        let pal = style::Palette::plain();
        let shown = render_bundles(&[(&name, &b)], false, &pal);
        assert!(
            shown.contains("task     sync"),
            "the full listing names the operation: {shown}"
        );
        let summary = render_bundles(&[(&name, &b)], true, &pal);
        assert!(
            summary.contains("1 declared operation(s)") && !summary.contains("empty"),
            "the summary counts it rather than reading as harmless: {summary}"
        );
    }

    /// The disclosure is built from what the bundle serializes to, not from a list of sections
    /// somebody remembered to extend — so a section this code has never heard of still reaches the
    /// reader instead of arriving unannounced. That is the property the previous shape lacked: it
    /// fell behind `RawBundle` silently, each time a field was added.
    #[test]
    fn a_section_no_reader_here_knows_is_still_named_rather_than_passed_over() {
        // A key `RawBundle` has no field for: kept by its `rest` map, and named here by its key.
        let odd: config::RawBundle =
            toml::from_str("[not_a_known_section]\nk = 1\n").expect("the fragment parses");
        assert_eq!(undescribed_sections(&odd), vec!["not_a_known_section"]);
        let set: std::collections::BTreeMap<String, config::RawBundle> =
            [("odd".to_string(), odd.clone())].into_iter().collect();
        let note = granting_note(&set).expect("an unrecognised section is not nothing");
        assert!(note.contains("`not_a_known_section`"), "{note}");

        let name = "odd".to_string();
        let shown = render_bundles(&[(&name, &odd)], false, &style::Palette::plain());
        assert!(shown.contains("[not_a_known_section]"), "{shown}");

        // The sections that DO have a line of their own are not reported twice.
        let known: config::RawBundle = toml::from_str(concat!(
            "packages = { helper = \"mise:helper\" }\n",
            "allow = [\"{*} https://api.example.com\"]\n",
            "service = { db = [\"/bin/true\"] }\n",
            "open = { helper = [\"/bin/true\"] }\n",
        ))
        .expect("the fragment parses");
        assert!(undescribed_sections(&known).is_empty());
        let grants = grants_of(&known);
        assert!(
            grants.iter().any(|g| g.contains("1 service(s)"))
                && grants.iter().any(|g| g.contains("1 URI handler(s)"))
                && grants.iter().any(|g| g.contains("1 egress rule(s)")),
            "{grants:?}"
        );
        assert!(
            !grants.iter().any(|g| g.contains("section")),
            "a described section must not also be reported as undescribed: {grants:?}"
        );
    }
}
