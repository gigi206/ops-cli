//! `appimage:` packages — a prebuilt AppImage provisioned host-side.
//!
//! For a GUI/desktop app distributed only as an `.AppImage` (no `.deb`, no runnable release binary,
//! no nixpkgs attribute), sbx packages the prebuilt AppImage directly, exactly as it does a `.deb`:
//! resolve the URL to a content hash, then build a generated derivation that extracts the AppImage's
//! squashfs and `autoPatchelfHook`s the ELF binaries against the curated Electron/Chromium library
//! set ([`super::prebuilt::ELECTRON_LIBS`]). Extraction runs no build script (`dontBuild`), so —
//! unlike an arbitrary `flake:` — evaluating and building it host-side is safe; it is therefore
//! provisioned like `nix:`/`deb:` (into sbx's store, seeded, offline-reusable) rather than in-cage.
//!
//! **The AppImage is unpacked at BUILD time, never run as an AppImage.** `wrapType2`, `appimage-run`,
//! and the raw `.AppImage` all self-mount a squashfs via FUSE (a runtime namespace op) — which the
//! cage's seccomp denylist blocks. Build-time squashfs extraction (`appimageTools.extractType2`,
//! `unsquashfs` under the hood) plus a plain autoPatchelf'd ELF is the only mechanism that runs
//! inside the cage; see [`super::prebuilt`] for the full rationale shared with `deb:`.
//!
//! Two source forms (both trusted-only, like every `[packages]` backend), dispatched from the prefix:
//!   * `appimage:<https url>` — a fixed `.AppImage` URL. A GitHub
//!     `…/releases/latest/download/<stable>.AppImage` URL rolls forward via the redirect; a
//!     version-embedding URL does not.
//!   * `appimage:github:<owner>/<repo>` — query the repo's latest release and select its linux
//!     `.AppImage` asset, so even a project whose asset name embeds the version rolls forward.
//!
//! Update model: pin-on-first-use (see [`provision`]) — identical to `deb:`.

use super::prebuilt::{self, ELECTRON_LIBS};
use crate::store::{self, Layout};
use std::collections::BTreeMap;
use std::io;
use std::path::{Path, PathBuf};

const APPIMAGE_LOCK: &str = "appimage-packages.lock";

/// The AppImage's own bundled legacy tray/indicator/GConf shims (`usr/lib/libappindicator.so.1`,
/// `libindicator.so.7`, `libgconf-2.so.4`) reference these old GTK2-era libraries. The main Electron
/// binary does not need them and a hermetic cage has no system tray, so they are ignored rather than
/// dragging GTK2 + libdbusmenu + dbus-glib into the closure — the autoPatchelf equivalent of the
/// `.deb`'s musl-loader ignore.
const APPIMAGE_IGNORE_MISSING: &[&str] = &[
    "libc.musl-x86_64.so.1",
    "libdbusmenu-gtk.so.4",
    "libdbusmenu-glib.so.4",
    "libgtk-x11-2.0.so.0",
    "libdbus-glib-1.so.2",
];

/// A locked `appimage:` package, keyed in the lock by its declared *locator* (the `.AppImage` URL, or
/// a `github:<owner>/<repo>`). `url` is the concrete `.AppImage` the pin resolved to (== the locator
/// for a direct URL, the selected release asset for a `github:` locator), and `hash` its SRI content
/// hash — so a warm launch fetches and builds the pinned asset offline without re-querying GitHub.
#[derive(Clone)]
pub(crate) struct AppImagePin {
    pub(crate) hash: String,
    pub(crate) url: String,
}

/// The two shapes a declared `appimage:` locator can take, dispatched from its prefix.
enum AppImageSource {
    /// A direct `https://…/….AppImage` URL — resolved to itself.
    Url(String),
    /// `github:<owner>/<repo>` — resolved via the repo's latest release.
    Github { owner: String, repo: String },
}

/// Parse a declared locator (already validated by `config::parse_backend`) into its source shape.
fn parse_source(locator: &str) -> AppImageSource {
    if let Some(path) = locator.strip_prefix("github:") {
        if let Some((owner, repo)) = path.split_once('/') {
            return AppImageSource::Github {
                owner: owner.to_string(),
                repo: repo.to_string(),
            };
        }
    }
    AppImageSource::Url(locator.to_string())
}

/// The outcome of re-resolving one declared `appimage:` reference during `sbx upgrade`.
pub(crate) enum AppImageUpgrade {
    Pinned {
        url: String,
        hash: String,
    },
    Rolled {
        url: String,
        from: String,
        to: String,
    },
    Unchanged {
        url: String,
        hash: String,
    },
    Pruned {
        url: String,
    },
    Failed {
        url: String,
        error: String,
    },
}

fn lock_path(layout: &Layout, project_id: &str) -> PathBuf {
    layout
        .data_dir()
        .join("projects")
        .join(project_id)
        .join(APPIMAGE_LOCK)
}

/// Read the per-project appimage lock. Each line is `key\thash` or `key\thash\turl`: a two-column
/// line (a direct-URL pin) takes the key as its resolved URL; a three-column line (a `github:` pin)
/// carries the resolved asset URL separately. A corrupt line self-heals by being dropped; an absent
/// lock is an empty map (the unpinned state).
pub(crate) fn pins(layout: &Layout, project_id: &str) -> BTreeMap<String, AppImagePin> {
    let mut map = BTreeMap::new();
    let Ok(text) = std::fs::read_to_string(lock_path(layout, project_id)) else {
        return map;
    };
    for line in text.lines() {
        let mut it = line.splitn(3, '\t');
        if let (Some(key), Some(hash)) = (it.next(), it.next()) {
            if !key.is_empty() && prebuilt::is_sri(hash) {
                let url = it.next().filter(|u| !u.is_empty()).unwrap_or(key);
                map.insert(
                    key.to_string(),
                    AppImagePin {
                        hash: hash.to_string(),
                        url: url.to_string(),
                    },
                );
            }
        }
    }
    map
}

/// The pinned content hashes for a project's `appimage:` packages, keyed by the declared URL (a
/// package's locator, so `sbx config` can look each up directly), shortened for display. Reads only
/// the per-project lock — surfaces a pin without resolving or building — so the config view stays
/// side-effect-free, exactly like [`super::deb::pinned_hashes`].
pub(crate) fn pinned_hashes(cwd: &Path) -> BTreeMap<String, String> {
    let Some(layout) = Layout::from_env() else {
        return BTreeMap::new();
    };
    let Ok(id) = super::binds::project_runtime_id(cwd) else {
        return BTreeMap::new();
    };
    pins(&layout, &id)
        .into_iter()
        .map(|(url, pin)| {
            let short: String = pin
                .hash
                .strip_prefix("sha256-")
                .unwrap_or(&pin.hash)
                .chars()
                .take(8)
                .collect();
            (url, short)
        })
        .collect()
}

/// Write the per-project appimage lock atomically (temp + rename), so a concurrent same-project
/// launch never observes a half-written file.
fn write_pins(
    layout: &Layout,
    project_id: &str,
    lock: &BTreeMap<String, AppImagePin>,
) -> io::Result<()> {
    let path = lock_path(layout, project_id);
    if let Some(parent) = path.parent() {
        use std::fs::DirBuilder;
        use std::os::unix::fs::DirBuilderExt;
        DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(parent)?;
    }
    let mut body = String::new();
    for (key, pin) in lock {
        // A direct-URL pin keeps the compact two-column form (key == resolved url); a `github:` pin,
        // whose resolved asset url differs from its key, needs the third column.
        if pin.url == *key {
            body.push_str(&format!("{key}\t{}\n", pin.hash));
        } else {
            body.push_str(&format!("{key}\t{}\t{}\n", pin.hash, pin.url));
        }
    }
    let tmp = path.with_extension(format!("tmp-{}", std::process::id()));
    std::fs::write(&tmp, body)?;
    match std::fs::rename(&tmp, &path) {
        Ok(()) => Ok(()),
        Err(e) => {
            let _ = std::fs::remove_file(&tmp);
            Err(e)
        }
    }
}

/// Resolve a declared `appimage:` locator to `(concrete .AppImage url, SRI content hash)`. A direct
/// URL resolves to itself; a `github:<owner>/<repo>` locator queries the repo's latest release,
/// selects its linux `.AppImage` asset, and **re-validates that GitHub-supplied URL** through the
/// same injection-free barrier a hand-written `appimage:` URL passes before it is fetched or
/// interpolated into the generated derivation. `fresh` bypasses the fetch cache (set on `sbx upgrade`,
/// so it sees a new release). Fail-closed: an unvalidated or unselectable asset returns an error.
pub(crate) fn resolve_source(
    nix: &Path,
    layout: &Layout,
    locator: &str,
    system: &str,
    fresh: bool,
) -> io::Result<(String, String)> {
    let url = match parse_source(locator) {
        AppImageSource::Url(url) => url,
        AppImageSource::Github { owner, repo } => {
            let api = format!("https://api.github.com/repos/{owner}/{repo}/releases/latest");
            let json = super::nixhub::fetch_url_json(nix, layout, &api, fresh)?;
            let url = select_appimage_asset(&json, system).ok_or_else(|| {
                io::Error::other(format!(
                    "no linux {} `.AppImage` asset in the latest release of {owner}/{repo}",
                    prebuilt::arch_label(system)
                ))
            })?;
            if !crate::config::is_valid_appimage_url(&url) {
                return Err(io::Error::other(format!(
                    "the latest release of {owner}/{repo} selected an asset URL that is not a \
                     valid `.AppImage` URL: {url}"
                )));
            }
            url
        }
    };
    // A re-resolve (`fresh`) is an `sbx upgrade` step — capture nix's output and fold the cause
    // into the error; a first launch streams the download progress live.
    let hash = prebuilt::prefetch_hash(nix, layout, &url, fresh)?;
    Ok((url, hash))
}

/// Select the linux `.AppImage` asset URL matching `system` from a GitHub release's JSON. An
/// AppImage is a Linux bundle by definition, so the discriminant is CPU architecture, not the OS: an
/// asset whose name names a *foreign* arch is dropped, then one positively naming this arch is chosen
/// (deterministic by name); a single unambiguous `.AppImage` with no arch token is the fallback for a
/// single-arch repo. Pure, so selection is testable against captured release JSON.
fn select_appimage_asset(json: &serde_json::Value, system: &str) -> Option<String> {
    let (accept, reject) = prebuilt::arch_tokens(system);
    let mut native: Vec<(String, String)> = json
        .get("assets")?
        .as_array()?
        .iter()
        .filter_map(|a| {
            let name = a.get("name")?.as_str()?.to_ascii_lowercase();
            let url = a.get("browser_download_url")?.as_str()?;
            (name.ends_with(".appimage") && !reject.iter().any(|t| name.contains(t)))
                .then(|| (name, url.to_string()))
        })
        .collect();
    native.sort();
    native
        .iter()
        .find(|(name, _)| accept.iter().any(|t| name.contains(t)))
        .or_else(|| native.first().filter(|_| native.len() == 1))
        .map(|(_, url)| url.clone())
}

/// The generated nix expression building one `appimage:` package: fetch the pinned `.AppImage`,
/// extract its squashfs with `appimageTools.extractType2`, copy it into `$out`, and autoPatchelf it
/// against [`ELECTRON_LIBS`] from the pinned `nixpkgs`. The launcher-locating install phase is shared
/// with `deb:` ([`prebuilt::electron_wrap`], which excludes the AppImage `AppRun` script so the real
/// binary is wrapped). Every interpolated value is sbx-controlled and charset-validated (`name`,
/// `url`, `hash`, the pinned `nixpkgs`, `system`), so the expression carries nothing to escape;
/// placeholders keep nix's `${…}`/`{…}` out of Rust's formatter.
fn derivation_expr(nixpkgs: &str, system: &str, name: &str, url: &str, hash: &str) -> String {
    const TEMPLATE: &str = r#"let pkgs = (builtins.getFlake "@NIXPKGS@").legacyPackages.@SYSTEM@;
    extracted = pkgs.appimageTools.extractType2 {
      pname = "@NAME@";
      version = "0";
      src = pkgs.fetchurl { url = "@URL@"; hash = "@HASH@"; };
    };
in pkgs.stdenvNoCC.mkDerivation (finalAttrs: {
  name = "@NAME@";
  dontUnpack = true;
  nativeBuildInputs = with pkgs; [ makeWrapper autoPatchelfHook ];
  buildInputs = with pkgs; [ @LIBS@ ];
  autoPatchelfIgnoreMissingDeps = [ @IGNORE@ ];
  dontConfigure = true;
  dontBuild = true;
  installPhase = ''
    mkdir -p $out
    cp -r ${extracted}/. "$out"
    chmod -R u+w "$out"
@WRAP@
  '';
  meta.mainProgram = "@NAME@";
})
"#;
    // The AppImage's Chromium `.so`s (`libEGL.so`, `libffmpeg.so`, …) sit loose in the bundle root,
    // so the wrapper prepends `$out` to `LD_LIBRARY_PATH` (beside the buildInputs closure) — unlike a
    // `.deb`, whose binary finds its siblings via RUNPATH.
    let wrap = prebuilt::electron_wrap(
        name,
        "$out:${pkgs.lib.makeLibraryPath finalAttrs.buildInputs}",
    );
    let ignore = APPIMAGE_IGNORE_MISSING
        .iter()
        .map(|s| format!("\"{s}\""))
        .collect::<Vec<_>>()
        .join(" ");
    TEMPLATE
        .replace("@WRAP@", &wrap)
        .replace("@NIXPKGS@", nixpkgs)
        .replace("@SYSTEM@", system)
        .replace("@LIBS@", &ELECTRON_LIBS.join(" "))
        .replace("@IGNORE@", &ignore)
        .replace("@URL@", url)
        .replace("@HASH@", hash)
        .replace("@NAME@", name)
}

/// Provision one `appimage:` package host-side: resolve the URL to a hash (pinning it on first use),
/// build the generated derivation into sbx's store, and return `(bin directory, store root)` — the
/// bin dir to prepend to the sandbox `PATH`, the root whose closure the project store seeds. Mirrors
/// [`super::deb::provision`]'s per-package gcroot, name-keyed under the project.
pub(crate) fn provision(
    nix: &Path,
    layout: &Layout,
    project: &Path,
    nixpkgs: &str,
    name: &str,
    locator: &str,
) -> io::Result<(PathBuf, PathBuf)> {
    let project_id = super::binds::project_runtime_id(project)?;
    let system = super::current_system();
    let mut lock = pins(layout, project_id.as_str());
    let (url, hash) = match lock.get(locator) {
        Some(pin) => (pin.url.clone(), pin.hash.clone()),
        None => {
            let (u, h) = resolve_source(nix, layout, locator, &system, false)?;
            lock.insert(
                locator.to_string(),
                AppImagePin {
                    hash: h.clone(),
                    url: u.clone(),
                },
            );
            write_pins(layout, project_id.as_str(), &lock)?;
            (u, h)
        }
    };
    let expr = derivation_expr(nixpkgs, &system, name, &url, &hash);
    let gcroot = layout
        .data_dir()
        .join("gcroots")
        .join("projects")
        .join(project_id.as_str())
        .join(format!("appimage-{name}"));
    let logical = store::provision_expr(nix, layout, &gcroot, &expr, name, "bin")?;
    Ok((logical.join("bin"), logical))
}

/// Re-resolve a project's declared `appimage:` references and rewrite the per-project lock — pinning
/// new ones, rolling changed ones forward, and pruning entries whose URL is no longer declared.
/// Mirrors [`super::deb::upgrade`]: references collected generically across the baseline and each
/// app, resolution best-effort per reference, lock rewritten once at the end.
pub(crate) fn upgrade(
    nix: &Path,
    layout: &Layout,
    project: &Path,
    cfg: &crate::config::Resolved,
) -> io::Result<Vec<AppImageUpgrade>> {
    let project_id = super::binds::project_runtime_id(project)?;
    let Declared {
        trusted: declared,
        all: universe,
    } = declared(cfg);
    let system = super::current_system();
    let mut lock = pins(layout, project_id.as_str());
    let mut outcomes = Vec::new();

    // Prune entries whose locator is no longer declared (across ALL layers regardless of trust, so a
    // withheld project's still-declared package keeps its pin rather than being silently unpinned).
    let stale: Vec<String> = lock
        .keys()
        .filter(|k| !universe.contains(k.as_str()))
        .cloned()
        .collect();
    for url in stale {
        lock.remove(&url);
        outcomes.push(AppImageUpgrade::Pruned { url });
    }

    for locator in &declared {
        let previous = lock.get(locator).map(|p| p.hash.clone());
        match resolve_source(nix, layout, locator, &system, true) {
            Ok((url, hash)) => {
                let outcome = match &previous {
                    Some(old) if old == &hash => AppImageUpgrade::Unchanged {
                        url: locator.clone(),
                        hash: hash.clone(),
                    },
                    Some(old) => AppImageUpgrade::Rolled {
                        url: locator.clone(),
                        from: old.clone(),
                        to: hash.clone(),
                    },
                    None => AppImageUpgrade::Pinned {
                        url: locator.clone(),
                        hash: hash.clone(),
                    },
                };
                lock.insert(locator.clone(), AppImagePin { hash, url });
                outcomes.push(outcome);
            }
            Err(e) => outcomes.push(AppImageUpgrade::Failed {
                url: locator.clone(),
                error: e.to_string(),
            }),
        }
    }

    write_pins(layout, project_id.as_str(), &lock)?;
    Ok(outcomes)
}

/// The two views `sbx upgrade appimage` needs of a project's declared `appimage:` URLs, collected in
/// one pass over the baseline and each app overlay (see [`declared`]).
struct Declared {
    /// Deterministic, deduplicated, **trusted-only** — the set to roll forward.
    trusted: Vec<String>,
    /// Every declared URL **regardless of trust** — the universe the lock is pruned against, so an
    /// untrusted/Changed project's still-declared package keeps its pin instead of being unpinned.
    all: std::collections::BTreeSet<String>,
}

/// Collect both views in a single walk of the layers, each app overlay materialized once (a
/// `merge_app` clone) — so `sbx upgrade` walks the apps once, not twice.
fn declared(cfg: &crate::config::Resolved) -> Declared {
    let mut seen = std::collections::BTreeSet::new();
    let mut trusted = Vec::new();
    let mut all = std::collections::BTreeSet::new();
    let mut absorb = |pkgs: &[crate::config::Package]| {
        for (_, url) in super::packages::appimage_packages(pkgs) {
            if seen.insert(url.clone()) {
                trusted.push(url);
            }
        }
        for p in pkgs {
            if let crate::config::Backend::AppImage(url) = &p.backend {
                all.insert(url.clone());
            }
        }
    };
    absorb(&cfg.packages);
    for app in cfg.apps.values() {
        let mut merged = cfg.clone();
        merged.merge_app(app.clone());
        absorb(&merged.packages);
    }
    Declared { trusted, all }
}

/// How many declared `appimage:` packages are withheld for being untrusted — across the baseline and
/// each app. A count only (the per-package reason is warned on the launch path), so `sbx upgrade`
/// does not read as "none declared" when an untrusted project declares one.
pub(crate) fn withheld(cfg: &crate::config::Resolved) -> usize {
    let untrusted = |pkgs: &[crate::config::Package]| {
        pkgs.iter()
            .filter(|p| {
                matches!(p.backend, crate::config::Backend::AppImage(_))
                    && p.state != crate::trust::TrustState::Trusted
            })
            .count()
    };
    untrusted(&cfg.packages)
        + cfg
            .apps
            .values()
            .map(|app| untrusted(&app.packages))
            .sum::<usize>()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::TmpDir;

    const HASH: &str = "sha256-+mBp+wPrJRV/HpaimQHcqBuwqZcPWTbKJVNCVW7ELgo=";

    #[test]
    fn the_generated_derivation_extracts_the_squashfs_and_wraps_the_electron_launcher() {
        let expr = derivation_expr(
            "github:NixOS/nixpkgs/abc",
            "x86_64-linux",
            "demo-app",
            "https://example.com/x/demo-app-0.0.28-x86_64.AppImage",
            HASH,
        );
        // pinned source (url + resolved hash) against the pinned nixpkgs, extracted (not run) via
        // extractType2 — the build-time squashfs unpack the seccomp cage requires.
        assert!(expr.contains(
            "(builtins.getFlake \"github:NixOS/nixpkgs/abc\").legacyPackages.x86_64-linux"
        ));
        assert!(expr.contains("appimageTools.extractType2"));
        assert!(expr.contains("url = \"https://example.com/x/demo-app-0.0.28-x86_64.AppImage\";"));
        assert!(expr.contains(&format!("hash = \"{HASH}\";")));
        assert!(expr.contains("cp -r ${extracted}/. \"$out\""));
        assert!(expr.contains("dontBuild = true;"));
        // the shared Electron lib set + the AppImage-specific ignore of the bundled tray shims.
        assert!(expr.contains("nss") && expr.contains("gtk3") && expr.contains("libx11"));
        assert!(expr.contains("\"libdbusmenu-gtk.so.4\""));
        // shared launcher-locating install phase, wrapped as bin/<name>, prepending the bundle root.
        assert!(expr.contains("app.asar"));
        assert!(expr.contains("! -name 'AppRun'"));
        assert!(expr.contains("$out/bin/demo-app"));
        assert!(expr.contains("LD_LIBRARY_PATH : \"$out:"));
        assert!(expr.contains("meta.mainProgram = \"demo-app\";"));
        // no leftover placeholder
        assert!(!expr.contains('@'), "unreplaced placeholder in:\n{expr}");
    }

    #[test]
    fn parse_source_dispatches_github_from_url() {
        match parse_source("github:example/demo-app") {
            AppImageSource::Github { owner, repo } => {
                assert_eq!(owner, "example");
                assert_eq!(repo, "demo-app");
            }
            AppImageSource::Url(_) => panic!("github locator misparsed as a URL"),
        }
        assert!(matches!(
            parse_source("https://example.com/x.AppImage"),
            AppImageSource::Url(u) if u == "https://example.com/x.AppImage"
        ));
    }

    // A trimmed capture of a desktop app's `releases/latest` asset set (the same names + URL shape a
    // real release carries), the shape [`select_appimage_asset`] must pick from: one linux
    // `.AppImage` beside its update yml.
    const RELEASE_ASSETS: &str = r#"{
      "tag_name": "v0.0.28",
      "assets": [
        { "name": "latest-linux.yml",
          "browser_download_url": "https://github.com/example/demo-app/releases/download/v0.0.28/latest-linux.yml" },
        { "name": "demo-app-0.0.28-x86_64.AppImage",
          "browser_download_url": "https://github.com/example/demo-app/releases/download/v0.0.28/demo-app-0.0.28-x86_64.AppImage" }
      ]
    }"#;

    #[test]
    fn select_appimage_asset_picks_the_native_arch_appimage() {
        let json: serde_json::Value = serde_json::from_str(RELEASE_ASSETS).unwrap();
        // x86_64 selects the x86_64 AppImage, never the update yml.
        assert_eq!(
            select_appimage_asset(&json, "x86_64-linux").as_deref(),
            Some("https://github.com/example/demo-app/releases/download/v0.0.28/demo-app-0.0.28-x86_64.AppImage")
        );
        // aarch64 host: no arm64 AppImage in this release → None (fail-closed, no guess).
        assert_eq!(select_appimage_asset(&json, "aarch64-linux"), None);
    }

    #[test]
    fn select_appimage_asset_rejects_foreign_and_falls_back_to_a_single_untokened() {
        // a multi-arch release: x86_64 host takes the amd64 one, never the arm64.
        let multi = serde_json::json!({
            "assets": [
                { "name": "App-1.0-x86_64.AppImage", "browser_download_url": "https://e/x86_64.AppImage" },
                { "name": "App-1.0-arm64.AppImage", "browser_download_url": "https://e/arm64.AppImage" }
            ]
        });
        assert_eq!(
            select_appimage_asset(&multi, "x86_64-linux").as_deref(),
            Some("https://e/x86_64.AppImage")
        );
        // a single AppImage with no arch token is taken (x86_64 host).
        let single = serde_json::json!({
            "assets": [
                { "name": "App-1.0.AppImage", "browser_download_url": "https://e/App.AppImage" },
                { "name": "App-1.0.zsync", "browser_download_url": "https://e/App.zsync" }
            ]
        });
        assert_eq!(
            select_appimage_asset(&single, "x86_64-linux").as_deref(),
            Some("https://e/App.AppImage")
        );
        // no `.AppImage` at all → None (the caller turns this into a fail-closed error, no pin).
        let none = serde_json::json!({
            "assets": [ { "name": "app.deb", "browser_download_url": "https://e/app.deb" } ]
        });
        assert_eq!(select_appimage_asset(&none, "x86_64-linux"), None);
    }

    #[test]
    fn the_lock_round_trips_both_forms_and_a_corrupt_line_self_heals() {
        let data = TmpDir::new();
        let layout = Layout::under(data.path());
        let id = "proj1";
        let mut lock = BTreeMap::new();
        lock.insert(
            "https://example.com/a.AppImage".to_string(),
            AppImagePin {
                hash: HASH.to_string(),
                url: "https://example.com/a.AppImage".to_string(),
            },
        );
        lock.insert(
            "github:example/demo-app".to_string(),
            AppImagePin {
                hash: HASH.to_string(),
                url: "https://github.com/example/demo-app/releases/download/v0.0.28/demo-app-0.0.28-x86_64.AppImage".to_string(),
            },
        );
        write_pins(&layout, id, &lock).expect("write the lock");

        // the direct-URL pin stays a compact two-column line.
        let raw = std::fs::read_to_string(lock_path(&layout, id)).unwrap();
        assert!(
            raw.contains(&format!("https://example.com/a.AppImage\t{HASH}\n")),
            "a direct-URL pin keeps the two-column form:\n{raw}"
        );

        let read = pins(&layout, id);
        assert_eq!(read.len(), 2);
        assert_eq!(
            read["https://example.com/a.AppImage"].url,
            "https://example.com/a.AppImage"
        );
        assert_eq!(
            read["github:example/demo-app"].url,
            "https://github.com/example/demo-app/releases/download/v0.0.28/demo-app-0.0.28-x86_64.AppImage"
        );

        // a corrupt (non-SRI) line self-heals (drop).
        std::fs::write(
            lock_path(&layout, id),
            format!("https://example.com/a.AppImage\t{HASH}\nhttps://bad/b.AppImage\tnot-a-hash\n"),
        )
        .unwrap();
        let read = pins(&layout, id);
        assert_eq!(read.len(), 1, "the corrupt line must self-heal (drop)");
    }

    fn appimage_pkg(name: &str, url: &str, trusted: bool) -> crate::config::Package {
        crate::config::Package {
            name: name.into(),
            backend: crate::config::Backend::AppImage(url.into()),
            state: if trusted {
                crate::trust::TrustState::Trusted
            } else {
                crate::trust::TrustState::Untrusted
            },
        }
    }

    fn app_with(packages: Vec<crate::config::Package>) -> crate::config::ResolvedApp {
        crate::config::ResolvedApp {
            cmd: vec!["x".into()],
            home_scope: crate::config::AppHomeScope::Global,
            env: vec![],
            binds: vec![],
            packages,
            network: None,
            gui: None,
            gpu: None,
            audio: None,
            dbus: None,
            limits: Default::default(),
            forward: vec![],
            secrets: vec![],
            default_methods: crate::allowlist::Methods::Unspecified,
            cmd_origin: Default::default(),
            network_origin: Default::default(),
            gui_origin: Default::default(),
            gpu_origin: Default::default(),
            audio_origin: Default::default(),
            dbus_origin: Default::default(),
            forward_origin: Default::default(),
            limits_origin: Default::default(),
            seccomp: Default::default(),
            seccomp_origin: Default::default(),
            devices: Vec::new(),
            devices_origin: Default::default(),
            proc: None,
            proc_origin: Default::default(),
            home_scope_origin: None,
            warnings: vec![],
        }
    }

    fn resolved(
        packages: Vec<crate::config::Package>,
        apps: Vec<(&str, crate::config::ResolvedApp)>,
    ) -> crate::config::Resolved {
        crate::config::Resolved {
            env: vec![],
            env_layer: Default::default(),
            binds: vec![],
            bind_layer: Default::default(),
            packages,
            nixpkgs_global: None,
            nixpkgs_project: None,
            mise: None,
            network: crate::config::NetworkPolicy::default(),
            network_origin: Default::default(),
            egress_stats: true,
            gui: crate::config::GuiPolicy::default(),
            gui_origin: Default::default(),
            proc: Default::default(),
            proc_origin: Default::default(),
            gpu: false,
            audio: false,
            dbus: false,
            gpu_origin: Default::default(),
            audio_origin: Default::default(),
            dbus_origin: Default::default(),
            forward: vec![],
            forward_origin: Default::default(),
            limits: Default::default(),
            limits_origin: Default::default(),
            secrets: vec![],
            seccomp: Default::default(),
            seccomp_origin: Default::default(),
            devices: Vec::new(),
            devices_origin: Default::default(),
            declared_secrets: vec![],
            apps: apps.into_iter().map(|(n, a)| (n.to_string(), a)).collect(),
            warnings: vec![],
        }
    }

    #[test]
    fn declared_trusted_covers_baseline_and_apps_and_the_prune_universe_keeps_untrusted() {
        let cfg = resolved(
            vec![
                appimage_pkg("a", "https://e/a.AppImage", true),
                appimage_pkg("evil", "https://e/evil.AppImage", false),
            ],
            vec![(
                "alpha",
                app_with(vec![
                    appimage_pkg("b", "https://e/b.AppImage", true),
                    appimage_pkg("a2", "https://e/a.AppImage", true), // duplicate url: deduped
                ]),
            )],
        );
        // baseline first, then the app's new url; the duplicate and the untrusted one are gone.
        assert_eq!(
            declared(&cfg).trusted,
            vec!["https://e/a.AppImage", "https://e/b.AppImage"]
        );
        // the prune universe keeps the untrusted url (so `sbx upgrade` never unpins a withheld pin).
        let universe = declared(&cfg).all;
        assert!(universe.contains("https://e/evil.AppImage"));
        assert_eq!(withheld(&cfg), 1);
    }
}
