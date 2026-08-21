//! Asks every shipped profile's vendor whether the package it names can still be resolved.
//!
//! **The problem this exists for, with its cost.** `aionui` named `deb:github:iOfficeAI/AionUi`,
//! which resolves through the latest release's linux-amd64 asset. Upstream stopped attaching assets
//! on 2026-08-05, and the app could be neither launched nor upgraded from that day. It was found on
//! 2026-08-21, by launching it. Nothing in this repository asks a vendor anything: the six
//! `every_shipped_*` guards read files, and a file cannot say that the thing it points at is gone.
//!
//! **Why it cannot live in the ordinary suite.** Every check here is a network call to a third
//! party. `cargo test` runs offline, on contributors' machines and in a hosted job that has no
//! business being red because a vendor is having an afternoon. So the module is inert unless
//! `SBX_CATALOGUE_CHECK=1` arms it, and a scheduled run is what arms it — the same shape
//! `test-cage` uses for capability skips, with `skip_unreachable!` because no runner setting makes
//! a vendor dependable.
//!
//! **What a failure means, and what it does not.** A vendor being briefly unreachable fails this
//! run. That is accepted rather than papered over: retrying until green would hide exactly the
//! outage that matters, and the finding here is durable by nature — a vendor that stopped
//! publishing stays stopped. Read a red as "go look", not as "the tree is broken".
//!
//! **What it checks.** The three resolutions that answer "can this package still be found":
//! `github:` prebuilt locators (an asset for this architecture in the latest release),
//! `<backend>:resolve` commands (they still print a URL, and it is served), and `mise:` specs (mise
//! still names a version). The last needs a mise, which the scheduled run provides through
//! `SBX_CATALOGUE_MISE`; without one those specs are reported **unchecked**, never as passing.
//!
//! **What calibrated it, and it was not a fabricated mutation.** The first armed run reported
//! exactly two packages broken — `amp` and `deepseek-harness` — and nothing else, out of the
//! catalogue's fifty-eight resolutions. Both were real, both had been found by hand hours earlier,
//! and the run reproduced them from the profiles alone. It also exposed a fault of its own: it asked
//! mise the bare question where the cage asks an exempted one, so it would have kept calling those
//! two broken after they were fixed. The `mise:` arm now sets the same
//! `accepts_fresh_releases` exemption the launch sets, and the run is green on all fifty-eight.
//!
//! **What it does not check, measured on the day it was written.** Three of the seven apps broken
//! that day would have survived this module. `deepseek-harness`, `sigit` and `reasonix` resolved
//! their version perfectly and failed at *install*; `junie` and `openfox` resolved and installed and
//! failed at *launch*. Only launching an app catches those, and launching 71 of them is a different
//! run with a different budget. This module answers one question, and the prose above is what keeps
//! its green from being read as a wider one.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::config::schema;

/// The repository root, so a run reads the same files a reader would open.
fn root() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
}

/// One thing to ask a vendor about: where it was declared, and what to ask.
#[derive(Debug)]
enum Check {
    /// A `deb:github:<owner>/<repo>` or `appimage:github:…` locator: the latest release must carry
    /// an asset for this architecture.
    GithubAsset { repo: String, ext: &'static str },
    /// A `<backend>:resolve` command: it must still print a URL, and that URL must be served.
    Resolver { argv: Vec<String> },
    /// A `mise:` token: mise must still name a version for it.
    ///
    /// `fresh` carries the layer's `accepts_fresh_releases` verdict for this package, because the
    /// question to ask is the **cage's**, not a bare one: a package the cage exempts from mise's
    /// freshness delay resolves under that exemption and nowhere else. Asking without it reports a
    /// working app as broken, which is how this arm was written the first time.
    MiseSpec { token: String, fresh: bool },
}

/// Every check the shipped catalogue implies, keyed by the profile that declares it.
fn shipped_checks() -> Vec<(String, Check)> {
    let mut out = Vec::new();
    for dir in ["examples/bundle", "examples/app"] {
        let mut files: Vec<PathBuf> = std::fs::read_dir(root().join(dir))
            .expect("the examples directory is readable")
            .flatten()
            .map(|e| e.path())
            .filter(|p| p.extension().and_then(|e| e.to_str()) == Some("toml"))
            .collect();
        files.sort();
        for path in files {
            let stem = path.file_stem().unwrap().to_str().unwrap().to_string();
            let raw = schema::parse(&std::fs::read(&path).expect("read the profile"))
                .unwrap_or_else(|e| panic!("{} does not parse: {e}", path.display()));
            // A bundle file carries its declarations under `[bundle.<name>]`; an app profile
            // carries them at the root. Both are read, because both ship packages.
            let (packages, resolvers, exempt) = match raw.bundle.get(&stem) {
                Some(b) => (
                    b.packages.clone(),
                    vec![&b.deb, &b.appimage, &b.tarball, &b.binary],
                    b.accepts_fresh_releases.clone(),
                ),
                None => (
                    raw.packages.clone(),
                    vec![&raw.deb, &raw.appimage, &raw.tarball, &raw.binary],
                    raw.accepts_fresh_releases.clone(),
                ),
            };
            for (name, locator) in &packages {
                if let Some(spec) = locator.strip_prefix("mise:") {
                    out.push((
                        stem.clone(),
                        Check::MiseSpec {
                            token: spec.into(),
                            fresh: exempt.contains(name),
                        },
                    ));
                } else if let Some(repo) = locator.strip_prefix("deb:github:") {
                    out.push((
                        stem.clone(),
                        Check::GithubAsset {
                            repo: repo.into(),
                            ext: ".deb",
                        },
                    ));
                } else if let Some(repo) = locator.strip_prefix("appimage:github:") {
                    out.push((
                        stem.clone(),
                        Check::GithubAsset {
                            repo: repo.into(),
                            ext: ".appimage",
                        },
                    ));
                }
            }
            for table in resolvers {
                for entry in table.values() {
                    if !entry.resolve.is_empty() {
                        out.push((
                            stem.clone(),
                            Check::Resolver {
                                argv: entry.resolve.clone(),
                            },
                        ));
                    }
                }
            }
        }
    }
    out
}

/// Run `argv`, capturing stdout, with a bound so a hung vendor does not hang the run.
fn run(argv: &[String]) -> Result<String, String> {
    run_with(argv, &[])
}

/// The same, with environment the cage would have set for this call.
fn run_with(argv: &[String], env: &[(&str, &str)]) -> Result<String, String> {
    let mut cmd = Command::new("timeout");
    cmd.arg("120").args(argv);
    for (k, v) in env {
        cmd.env(k, v);
    }
    let out = cmd.output().map_err(|e| format!("cannot spawn: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "exit {}: {}",
            out.status.code().unwrap_or(-1),
            String::from_utf8_lossy(&out.stderr)
                .trim()
                .chars()
                .take(160)
                .collect::<String>()
        ));
    }
    Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

/// The latest release of `repo`, as GitHub returns it.
///
/// Returned whole rather than reduced to asset names, because the launcher's selector reads the
/// release object itself — handing it a list this module had already filtered would put this
/// module's idea of the rule back in the middle of the check.
fn latest_release(repo: &str) -> Result<serde_json::Value, String> {
    let api = format!("https://api.github.com/repos/{repo}/releases/latest");
    // `-f` so an HTTP error is an error here rather than a body to misparse. The token, when the
    // scheduled run provides one, lifts the 60/hour anonymous cap that the shipped catalogue's
    // GitHub-backed entries and resolvers would otherwise share.
    let mut argv = vec![
        "curl".to_string(),
        "-fsS".to_string(),
        "--max-time".to_string(),
        "60".to_string(),
    ];
    if let Ok(token) = std::env::var("GITHUB_TOKEN") {
        argv.push("-H".into());
        argv.push(format!("Authorization: Bearer {token}"));
    }
    argv.push(api);
    let body = run(&argv)?;
    serde_json::from_str(&body).map_err(|e| format!("release JSON does not parse: {e}"))
}

/// Whether the launcher would select an asset from this release, asked of the launcher itself.
///
/// The selection is not re-implemented here, and the difference is not cosmetic: the real rule
/// prefers an architecture token that is **terminal** (`…_amd64.deb`, not `…_amd64-cuda.deb`) and
/// falls back to a mid-name one, so an approximation would pass a release whose only asset the
/// launch refuses — a green on an app that cannot start. This module exists to catch that class, so
/// it asks the function the launch asks.
fn launcher_selects(json: &serde_json::Value, ext: &str) -> bool {
    let system = super::current_system();
    match ext {
        ".deb" => super::deb::select_deb_asset(json, &system).is_some(),
        _ => super::appimage::select_appimage_asset(json, &system).is_some(),
    }
}

#[test]
fn every_shipped_package_still_resolves_at_its_vendor() {
    if std::env::var_os("SBX_CATALOGUE_CHECK").is_none() {
        skip_unreachable!(
            "skipping the catalogue freshness check: it calls third-party vendors, so it runs only \
             when SBX_CATALOGUE_CHECK=1 arms it (see this module's header)"
        );
        return;
    }
    let mise = std::env::var("SBX_CATALOGUE_MISE").ok();
    let checks = shipped_checks();
    assert!(
        checks.len() > 40,
        "the catalogue scan found only {} check(s), so it has stopped matching the profiles' shape \
         and this run would pass vacuously",
        checks.len()
    );

    let mut failed: Vec<String> = Vec::new();
    let mut unchecked: Vec<String> = Vec::new();
    let mut seen: BTreeMap<String, ()> = BTreeMap::new();
    for (profile, check) in &checks {
        match check {
            Check::GithubAsset { repo, ext } => {
                if seen.insert(format!("gh:{repo}{ext}"), ()).is_some() {
                    continue;
                }
                match latest_release(repo) {
                    Err(e) => failed.push(format!("{profile}: {repo} latest release: {e}")),
                    Ok(json) if !launcher_selects(&json, ext) => {
                        let n = json
                            .get("assets")
                            .and_then(|a| a.as_array())
                            .map_or(0, |a| a.len());
                        failed.push(format!(
                            "{profile}: the launcher selects no `{ext}` asset from the latest \
                             release of {repo} ({n} asset(s) in all) — the app cannot be provisioned"
                        ));
                    }
                    Ok(_) => {}
                }
            }
            Check::Resolver { argv } => {
                let key = format!("resolve:{}", argv.join(" "));
                if seen.insert(key, ()).is_some() {
                    continue;
                }
                match run(argv) {
                    Err(e) => failed.push(format!("{profile}: its resolver failed: {e}")),
                    Ok(url) if !url.starts_with("https://") => failed.push(format!(
                        "{profile}: its resolver printed something that is not an https URL: {}",
                        url.chars().take(120).collect::<String>()
                    )),
                    Ok(url) => {
                        // Printing a URL is half the contract; the other half is that a vendor still
                        // serves it. A resolver reading a stale manifest passes the first and fails
                        // the second, which is the shape a vendor migration takes.
                        let head = vec![
                            "curl".to_string(),
                            "-fsSIL".to_string(),
                            "--max-time".to_string(),
                            "60".to_string(),
                            "-o".to_string(),
                            "/dev/null".to_string(),
                            url.clone(),
                        ];
                        if let Err(e) = run(&head) {
                            failed
                                .push(format!("{profile}: its resolver's URL is not served: {e}"));
                        }
                    }
                }
            }
            Check::MiseSpec { token, fresh } => {
                if seen.insert(format!("mise:{token}:{fresh}"), ()).is_some() {
                    continue;
                }
                let Some(mise) = &mise else {
                    unchecked.push(format!("{profile}: mise:{token}"));
                    continue;
                };
                let argv = vec![mise.clone(), "latest".to_string(), token.clone()];
                // The exemption the cage sets for this package, set here too. Without it the two
                // packages that need one are reported broken while they launch perfectly.
                let env: Vec<(&str, &str)> = if *fresh {
                    vec![("MISE_MINIMUM_RELEASE_AGE_EXCLUDES", token.as_str())]
                } else {
                    vec![]
                };
                match run_with(&argv, &env) {
                    Err(e) => failed.push(format!("{profile}: mise:{token} did not resolve: {e}")),
                    // The empty answer is the whole reason this arm exists: mise reports success and
                    // prints nothing when no release clears its freshness delay, so a caller reading
                    // only the exit status sees a healthy package that cannot be equipped.
                    Ok(v) if v.is_empty() => failed.push(format!(
                        "{profile}: mise names NO version for mise:{token} (exit 0, empty output) — \
                         it can be neither equipped nor rolled"
                    )),
                    Ok(_) => {}
                }
            }
        }
    }

    if !unchecked.is_empty() {
        eprintln!(
            "catalogue: {} `mise:` spec(s) were NOT checked, because SBX_CATALOGUE_MISE named no \
             mise binary. They are not passing, they are unmeasured:\n  {}",
            unchecked.len(),
            unchecked.join("\n  ")
        );
    }
    assert!(
        failed.is_empty(),
        "{} shipped package(s) can no longer be resolved at their vendor:\n  {}",
        failed.len(),
        failed.join("\n  ")
    );
}
