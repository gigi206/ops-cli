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
//! Update model: pin-on-first-use (see [`prebuilt::provision`]) — identical to `deb:`.

use super::prebuilt;
use crate::store::Layout;
use std::collections::BTreeMap;
use std::io;
use std::path::Path;

/// The AppImage's own bundled legacy tray/indicator/GConf shims reference these old libraries. The
/// main Electron binary does not need them and a hermetic cage has no system tray, so they are
/// ignored rather than dragging GTK2 + libdbusmenu + dbus-glib into the closure — the autoPatchelf
/// equivalent of the `.deb`'s musl-loader ignore.
///
/// Both shim generations must be covered, because which one an AppImage carries is decided by the
/// packager's AppImage toolset, not by the app: the GTK2 set (`usr/lib/libappindicator.so.1`,
/// `libindicator.so.7`) wants `libdbusmenu-gtk.so.4`, and the GTK3 set (`libappindicator3.so.1`,
/// `libindicator3.so.7`) wants `libdbusmenu-gtk3.so.4`. Listing one alone still fails the build:
/// autoPatchelf refuses on the unlisted name even though the shim beside it was ignored.
const APPIMAGE_IGNORE_MISSING: &[&str] = &[
    "libc.musl-x86_64.so.1",
    "libdbusmenu-gtk.so.4",
    "libdbusmenu-gtk3.so.4",
    "libdbusmenu-glib.so.4",
    "libgtk-x11-2.0.so.0",
    "libdbus-glib-1.so.2",
];

/// A locked `appimage:` package, keyed in the lock by its declared *locator* (the `.AppImage` URL,
/// or a `github:<owner>/<repo>`). Its `url` is the concrete `.AppImage` the pin resolved to — the
/// locator itself for a direct URL, the selected release asset for a `github:` locator — so a warm
/// launch builds it offline without re-querying GitHub. See [`prebuilt::Pin`].
#[cfg(test)]
type AppImagePin = prebuilt::Pin;

/// The two shapes a declared `appimage:` locator can take, dispatched from its prefix.
enum AppImageSource {
    /// A direct `https://…/….AppImage` URL — resolved to itself.
    Url(String),
    /// `github:<owner>/<repo>` — resolved via the repo's latest release.
    Github { owner: String, repo: String },
}

/// Parse a declared locator (already validated by `config::parse_backend`) into its source shape.
fn parse_source(locator: &str) -> AppImageSource {
    if let Some(path) = locator.strip_prefix("github:")
        && let Some((owner, repo)) = path.split_once('/')
    {
        return AppImageSource::Github {
            owner: owner.to_string(),
            repo: repo.to_string(),
        };
    }
    AppImageSource::Url(locator.to_string())
}

/// The outcome of re-resolving one declared `appimage:` reference during `sbx upgrade`.
/// See [`prebuilt::Upgrade`].
pub(crate) type AppImageUpgrade = prebuilt::Upgrade;

/// Where this backend's lock lives. Production reads and writes it through [`prebuilt`]; this names
/// the same path for the tests that assert the on-disk format.
#[cfg(test)]
fn lock_path(layout: &Layout, project_id: &str) -> std::path::PathBuf {
    prebuilt::lock_path(layout, project_id, &prebuilt::lock_file(&AppImage))
}

/// Read the per-project appimage lock. A three-column line is a `github:` pin, whose resolved asset
/// URL differs from its key; see [`prebuilt::pins`] for the format.
#[cfg(test)]
fn pins(layout: &Layout, project_id: &str) -> BTreeMap<String, AppImagePin> {
    prebuilt::pins(layout, project_id, &prebuilt::lock_file(&AppImage))
}

/// The pinned content hashes for a project's `appimage:` packages, keyed by the declared locator so
/// `sbx config` can look each up directly. See [`prebuilt::pinned_hashes`].
pub(crate) fn pinned_hashes(cwd: &Path) -> BTreeMap<String, String> {
    prebuilt::pinned_hashes(cwd, &prebuilt::lock_file(&AppImage))
}

/// Write the per-project appimage lock atomically, for the tests that assert the on-disk
/// format. Production writes it through [`prebuilt::upgrade`].
#[cfg(test)]
fn write_pins(
    layout: &Layout,
    project_id: &str,
    lock: &BTreeMap<String, AppImagePin>,
) -> io::Result<()> {
    prebuilt::write_pins(layout, project_id, &prebuilt::lock_file(&AppImage), lock)
}

/// Resolve a declared `appimage:` locator to `(concrete .AppImage url, SRI content hash)`. A direct
/// URL resolves to itself; a `github:<owner>/<repo>` locator queries the repo's latest release,
/// selects its linux `.AppImage` asset, and **re-validates that GitHub-supplied URL** through the
/// same injection-free barrier a hand-written `appimage:` URL passes before it is fetched or
/// interpolated into the generated derivation. `fresh` marks an `sbx upgrade` re-resolve: the release
/// query bypasses nix's metadata cache so it sees a new release, and the artefact fetch stays quiet
/// for the summary. Fail-closed: an unvalidated or unselectable asset returns an error.
pub(crate) fn resolve_source(
    nix: &Path,
    layout: &Layout,
    locator: &str,
    system: &str,
    fresh: bool,
    allow_insecure_http: bool,
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
            if !crate::config::is_valid_appimage_url(&url, allow_insecure_http) {
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
pub(super) fn select_appimage_asset(json: &serde_json::Value, system: &str) -> Option<String> {
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
/// against [`prebuilt::ELECTRON_LIBS`] from the pinned `nixpkgs`. The launcher-locating install
/// phase is shared with `deb:` ([`prebuilt::launcher_wrap`], which excludes the AppImage `AppRun`
/// script so the real binary is wrapped). Every interpolated value is sbx-controlled and
/// charset-validated (`name`, `url`, `hash`, the pinned `nixpkgs`, `system`), so the expression
/// carries nothing to escape; placeholders keep nix's `${…}`/`{…}` out of Rust's formatter.
fn derivation_expr(
    nixpkgs: &str,
    system: &str,
    name: &str,
    url: &str,
    hash: &str,
    libs: &[String],
) -> String {
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
    let wrap = prebuilt::launcher_wrap(
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
        .replace("@LIBS@", &prebuilt::lib_set(libs))
        .replace("@IGNORE@", &ignore)
        .replace("@URL@", url)
        .replace("@HASH@", hash)
        .replace("@NAME@", name)
}

/// The `appimage:` backend — the two decisions [`prebuilt::Kind`] leaves to it are its locator forms
/// (a direct URL, `github:`) and extracting the AppImage's squashfs at build time.
pub(crate) struct AppImage;

impl prebuilt::Kind for AppImage {
    fn name(&self) -> &'static str {
        "appimage"
    }

    fn artefact(&self) -> &'static str {
        "`.AppImage`"
    }

    fn url_validator(&self) -> fn(&str, bool) -> bool {
        crate::config::is_valid_appimage_url
    }

    fn resolve_source(
        &self,
        nix: &Path,
        layout: &Layout,
        locator: &str,
        system: &str,
        fresh: bool,
        allow_insecure_http: bool,
    ) -> io::Result<(String, String)> {
        resolve_source(nix, layout, locator, system, fresh, allow_insecure_http)
    }

    fn derivation_expr(
        &self,
        nixpkgs: &str,
        system: &str,
        name: &str,
        url: &str,
        hash: &str,
        libs: &[String],
    ) -> String {
        derivation_expr(nixpkgs, system, name, url, hash, libs)
    }

    fn form(&self, package: &crate::config::Package) -> Option<prebuilt::Form> {
        match &package.backend {
            crate::config::Backend::AppImage(locator) => {
                Some(prebuilt::Form::Direct(locator.clone()))
            }
            crate::config::Backend::AppImageResolve { command } => {
                Some(prebuilt::Form::Resolve(command.clone()))
            }
            // Spelled out rather than `_`: a new backend variant must fail to compile here. Falling
            // through to `None` would leave its packages out of the prune universe, and `upgrade`
            // would drop a still-declared pin without a word.
            crate::config::Backend::Nix(_)
            | crate::config::Backend::Mise(_)
            | crate::config::Backend::Flake(_)
            | crate::config::Backend::FlakeInline { .. }
            | crate::config::Backend::Deb(_)
            | crate::config::Backend::DebResolve { .. }
            | crate::config::Backend::Tarball(_)
            | crate::config::Backend::TarballResolve { .. }
            | crate::config::Backend::Binary(_)
            | crate::config::Backend::BinaryResolve { .. } => None,
        }
    }
}

/// `sbx upgrade appimage`: roll a project's declared `appimage:` packages forward. See
/// [`prebuilt::upgrade_project`].
pub(crate) fn upgrade_project(
    nix: &Path,
    layout: &Layout,
    project: &Path,
    cfg: &crate::config::Resolved,
) -> io::Result<Vec<AppImageUpgrade>> {
    prebuilt::upgrade_project(&AppImage, nix, layout, project, cfg)
}

/// How many declared `appimage:` packages are withheld for being untrusted. See
/// [`prebuilt::withheld`].
pub(crate) fn withheld(cfg: &crate::config::Resolved) -> usize {
    prebuilt::withheld(&AppImage, cfg)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::{TmpDir, app_with, resolved};

    const HASH: &str = "sha256-+mBp+wPrJRV/HpaimQHcqBuwqZcPWTbKJVNCVW7ELgo=";

    #[test]
    fn the_generated_derivation_extracts_the_squashfs_and_wraps_the_electron_launcher() {
        let expr = derivation_expr(
            "github:NixOS/nixpkgs/abc",
            "x86_64-linux",
            "demo-app",
            "https://example.com/x/demo-app-0.0.28-x86_64.AppImage",
            HASH,
            &[],
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
        // both shim generations: an AppImage carries the GTK2 set or the GTK3 one, and a build
        // fails on whichever name is missing from the ignore list.
        assert!(expr.contains("\"libdbusmenu-gtk.so.4\""));
        assert!(expr.contains("\"libdbusmenu-gtk3.so.4\""));
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
            Some(
                "https://github.com/example/demo-app/releases/download/v0.0.28/demo-app-0.0.28-x86_64.AppImage"
            )
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
            libs: Vec::new(),
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
        let keys: Vec<String> = prebuilt::declared(&AppImage, &cfg)
            .trusted
            .iter()
            .map(prebuilt::Ref::key)
            .collect();
        assert_eq!(keys, vec!["https://e/a.AppImage", "https://e/b.AppImage"]);
        // the prune universe keeps the untrusted url (so `sbx upgrade` never unpins a withheld pin).
        let universe = prebuilt::declared(&AppImage, &cfg).all;
        assert!(universe.contains("https://e/evil.AppImage"));
        assert_eq!(withheld(&cfg), 1);
    }
}
