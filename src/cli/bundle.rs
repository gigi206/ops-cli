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
use std::path::PathBuf;
use std::process::ExitCode;

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
            if let Err(e) = std::fs::write(&path, &fragment) {
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
    match config::manage::import_bundles(&path, &bundles, force) {
        Ok(outcome) => {
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
            // Import is the one moment someone consciously brings in another author's data, so name
            // what using it would grant, rather than letting a credential or an egress rule surface
            // only at the next launch.
            let granting: Vec<String> = bundles
                .iter()
                .filter_map(|(name, b)| {
                    let rules = b.allow.len() + b.deny.len() + b.mute.len();
                    let creds = b.secret.as_ref().map(|s| s.hosts.len()).unwrap_or(0);
                    // An install step is named apart from the counts: it is a command that will run
                    // in the consuming app's cage, which is a different kind of grant from a host
                    // or a key, and the one a reader is least likely to expect.
                    let step = b.provision.is_some().then_some(", an install step");
                    (rules > 0 || creds > 0 || step.is_some()).then(|| {
                        format!(
                            "{name} ({rules} egress rule(s), {creds} credential(s){})",
                            step.unwrap_or("")
                        )
                    })
                })
                .collect();
            if !granting.is_empty() {
                diag::warn(&format!(
                    "an app that names these gains their egress, credentials and install steps: \
                     {} — inspect with `sbx bundle <name>`",
                    granting.join(", ")
                ));
            }
            ExitCode::SUCCESS
        }
        Err(e) => {
            diag::error(&format!("sbx: bundle import: {e}"));
            ExitCode::from(1)
        }
    }
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
