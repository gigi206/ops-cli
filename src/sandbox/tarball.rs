//! `tarball:` packages — a prebuilt application `.tar.gz` provisioned host-side.
//!
//! For a GUI/desktop app distributed only as a plain compressed tarball (no `.deb`, no `.AppImage`,
//! no nixpkgs attribute, and no *official* flake — the vendor ships a `.tar.gz` you extract and run),
//! sbx packages the tarball directly: resolve the URL to a content
//! hash, then build a generated derivation that `tar -xz`-unpacks it and `autoPatchelfHook`s the ELF
//! binaries against the same curated Electron/Chromium library set the `deb:`/`appimage:` backends
//! use. **No build script runs** (`dontBuild`), so — unlike an arbitrary `flake:` — evaluating and
//! building it host-side is safe; it is therefore provisioned like `nix:` (into sbx's store, seeded,
//! offline-reusable) rather than in-cage. Extraction happens at BUILD time (a plain `tar`, no runtime
//! namespace op), which is the only mechanism that works in-cage — the cage's seccomp denylist blocks
//! the FUSE/namespace self-mount an AppImage-style runtime extraction would need.
//!
//! Source form (this increment): `tarball:<https url>` — a direct `.tar.gz`/`.tgz` URL. A
//! version-stamped vendor URL does not roll forward on its own; the auto-upgrade manifest form
//! (querying a vendor version API and constructing the newest URL) is a following increment.
//!
//! Update model: pin-on-first-use — identical to `deb:`. A launch resolves the source to a concrete
//! URL and its content hash, records both in a per-project lock (`tarball-packages.lock`), and later
//! launches reuse the pin offline; the launch hot path never touches the network. `sbx upgrade`
//! re-resolves each declared source and rewrites the lock.

use super::prebuilt::{self, ELECTRON_LIBS};
use crate::store::{self, Layout};
use std::collections::BTreeMap;
use std::io;
use std::path::{Path, PathBuf};

const TARBALL_LOCK: &str = "tarball-packages.lock";

/// A locked `tarball:` package, keyed in the lock by its declared *locator* (the `.tar.gz` URL).
/// `url` is the concrete tarball the pin resolved to (== the locator for a direct URL) and `hash`
/// its SRI content hash — so a warm launch fetches and builds the pinned asset offline.
#[derive(Clone)]
pub(crate) struct TarballPin {
    pub(crate) hash: String,
    pub(crate) url: String,
}

/// The outcome of re-resolving one declared `tarball:` reference during `sbx upgrade`.
pub(crate) enum TarballUpgrade {
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
        .join(TARBALL_LOCK)
}

/// Read the per-project tarball lock. Each line is `key\thash` (a direct-URL pin, whose key IS its
/// resolved URL). A corrupt line self-heals by being dropped; an absent lock is an empty map (the
/// unpinned state). The three-column form the `deb:` lock uses for a `github:` pin is unused here —
/// a direct-URL locator equals its resolved URL — but a third column is tolerated (its resolved URL
/// wins) so the format can grow to a manifest form without a lock migration.
pub(crate) fn pins(layout: &Layout, project_id: &str) -> BTreeMap<String, TarballPin> {
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
                    TarballPin {
                        hash: hash.to_string(),
                        url: url.to_string(),
                    },
                );
            }
        }
    }
    map
}

/// The pinned content hashes for a project's `tarball:` packages, keyed by the declared URL and
/// shortened for display. Reads only the per-project lock — surfaces a pin without resolving or
/// building — so the config view stays side-effect-free, exactly like [`super::deb::pinned_hashes`].
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

/// Write the per-project tarball lock atomically (temp + rename), so a concurrent same-project launch
/// never observes a half-written file.
fn write_pins(
    layout: &Layout,
    project_id: &str,
    lock: &BTreeMap<String, TarballPin>,
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
        // A direct-URL pin keeps the compact two-column form (key == resolved url); a form whose
        // resolved url differs from its key (a future manifest locator) uses the third column.
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

/// Resolve a declared `tarball:` locator to `(concrete .tar.gz url, SRI content hash)`. A direct URL
/// resolves to itself; the hash is fetched via `nix store prefetch-file`, which follows redirects and
/// adds the file to sbx's store. `fresh` bypasses the fetch cache (set on `sbx upgrade`). The locator
/// was already validated injection-free by `config::parse_backend`, so it is safe to fetch and later
/// interpolate into the generated derivation.
pub(crate) fn resolve_source(
    nix: &Path,
    layout: &Layout,
    locator: &str,
    _fresh: bool,
) -> io::Result<(String, String)> {
    let url = locator.to_string();
    let hash = prebuilt::prefetch_hash(nix, layout, &url)?;
    Ok((url, hash))
}

/// The generated nix expression building one `tarball:` package: fetch the pinned `.tar.gz`, extract
/// it, and autoPatchelf it against [`ELECTRON_LIBS`] from the pinned `nixpkgs`. The install phase is
/// generic for an Electron layout — [`prebuilt::electron_wrap`] locates the app directory by its
/// `resources/` signature (a packed `resources/app.asar` or, for an asar-less VS Code fork, the
/// `resources/app/` directory) and wraps the app's own launcher, so no
/// per-app path is hardcoded. Every interpolated value is sbx-controlled and charset-validated
/// (`name`, `url`, `hash`, the pinned `nixpkgs`, the `system`), so the expression carries nothing to
/// escape; placeholders keep nix's `${…}`/`{…}` out of Rust's formatter.
fn derivation_expr(nixpkgs: &str, system: &str, name: &str, url: &str, hash: &str) -> String {
    const TEMPLATE: &str = r#"let pkgs = (builtins.getFlake "@NIXPKGS@").legacyPackages.@SYSTEM@;
in pkgs.stdenvNoCC.mkDerivation (finalAttrs: {
  name = "@NAME@";
  src = pkgs.fetchurl { url = "@URL@"; hash = "@HASH@"; };
  nativeBuildInputs = with pkgs; [ gzip gnutar makeWrapper autoPatchelfHook ];
  buildInputs = with pkgs; [ @LIBS@ ];
  # Ignore ALL unresolved deps (not just the musl loader the `deb:` backend lists). A raw vendor
  # tarball is the least-curated prebuilt form: it commonly bundles OPTIONAL native modules — editor
  # extensions, alternate-auth helpers (e.g. a bundled auth `.so` wanting webkit2gtk/libsoup) — whose
  # libraries are irrelevant to a run that does not use that feature. Forcing every one to resolve would
  # brick the whole app over an optional extension. The CORE binaries are still fully patched (their
  # deps ARE in `@LIBS@`), reach their sibling `.so`s via RUNPATH, and get the wrapper's LD_LIBRARY_PATH;
  # a genuinely-missing core library would surface at first launch, which the profile's live validation
  # catches. This is the common posture for a prebuilt-Electron nix package.
  autoPatchelfIgnoreMissingDeps = true;
  # Extract with a plain, unprivileged `tar` that does NOT restore permissions or ownership. A
  # prebuilt Electron bundle ships Chromium's `chrome-sandbox` setuid (mode 04755); a non-root nix
  # builder cannot chmod setuid ("Operation not permitted"), so `--no-same-permissions` is what keeps
  # the unpack from aborting. This is safe and load-bearing: the launcher runs with `--no-sandbox`
  # (bubblewrap + seccomp + the empty netns is the boundary), so that helper is never used, and
  # setuid could not take effect in the cage anyway.
  unpackPhase = ''
    mkdir extracted
    tar -xz --no-same-permissions --no-same-owner -f $src -C extracted
  '';
  dontConfigure = true;
  dontBuild = true;
  installPhase = ''
    mkdir -p $out
    cp -r extracted/. "$out"
@WRAP@
  '';
  meta.mainProgram = "@NAME@";
})
"#;
    // The bundled binary lives under its own prefix and finds its sibling `.so`s via RUNPATH, so the
    // wrapper's `LD_LIBRARY_PATH` is just the buildInputs closure — no bundle-root prefix (unlike an
    // AppImage, whose Chromium `.so`s sit loose beside the launcher).
    let wrap = prebuilt::electron_wrap(name, "${pkgs.lib.makeLibraryPath finalAttrs.buildInputs}");
    TEMPLATE
        .replace("@WRAP@", &wrap)
        .replace("@NIXPKGS@", nixpkgs)
        .replace("@SYSTEM@", system)
        .replace("@LIBS@", &ELECTRON_LIBS.join(" "))
        .replace("@URL@", url)
        .replace("@HASH@", hash)
        .replace("@NAME@", name)
}

/// Provision one `tarball:` package host-side: resolve the URL to a hash (pinning it on first use),
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
            let (u, h) = resolve_source(nix, layout, locator, false)?;
            lock.insert(
                locator.to_string(),
                TarballPin {
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
        .join(format!("tarball-{name}"));
    let logical = store::provision_expr(nix, layout, &gcroot, &expr, name, "bin")?;
    Ok((logical.join("bin"), logical))
}

/// Re-resolve a project's declared `tarball:` references and rewrite the per-project lock — pinning
/// new ones, rolling changed ones forward, and pruning entries whose URL is no longer declared.
/// Mirrors [`super::deb::upgrade`]: references collected generically across the baseline and each
/// app, resolution best-effort per reference, lock rewritten once at the end.
pub(crate) fn upgrade(
    nix: &Path,
    layout: &Layout,
    project: &Path,
    cfg: &crate::config::Resolved,
) -> io::Result<Vec<TarballUpgrade>> {
    let project_id = super::binds::project_runtime_id(project)?;
    let Declared {
        trusted: declared,
        all: universe,
    } = declared(cfg);
    let mut lock = pins(layout, project_id.as_str());
    let mut outcomes = Vec::new();

    // Prune entries whose locator is no longer declared (across ALL layers regardless of trust, so
    // a withheld project's still-declared package keeps its pin rather than being silently unpinned).
    let stale: Vec<String> = lock
        .keys()
        .filter(|k| !universe.contains(k.as_str()))
        .cloned()
        .collect();
    for url in stale {
        lock.remove(&url);
        outcomes.push(TarballUpgrade::Pruned { url });
    }

    for locator in &declared {
        let previous = lock.get(locator).map(|p| p.hash.clone());
        match resolve_source(nix, layout, locator, true) {
            Ok((url, hash)) => {
                let outcome = match &previous {
                    Some(old) if old == &hash => TarballUpgrade::Unchanged {
                        url: locator.clone(),
                        hash: hash.clone(),
                    },
                    Some(old) => TarballUpgrade::Rolled {
                        url: locator.clone(),
                        from: old.clone(),
                        to: hash.clone(),
                    },
                    None => TarballUpgrade::Pinned {
                        url: locator.clone(),
                        hash: hash.clone(),
                    },
                };
                lock.insert(locator.clone(), TarballPin { hash, url });
                outcomes.push(outcome);
            }
            Err(e) => outcomes.push(TarballUpgrade::Failed {
                url: locator.clone(),
                error: e.to_string(),
            }),
        }
    }

    write_pins(layout, project_id.as_str(), &lock)?;
    Ok(outcomes)
}

/// The two views `sbx upgrade tarball` needs of a project's declared `tarball:` URLs, collected in
/// one pass over the baseline and each app overlay (see [`declared`]).
struct Declared {
    /// Deterministic, deduplicated, **trusted-only** — the set to roll forward (baseline first,
    /// then apps by name).
    trusted: Vec<String>,
    /// Every declared URL **regardless of trust** — the universe the lock is pruned against, so an
    /// untrusted/Changed project's still-declared package keeps its pin instead of being unpinned.
    all: std::collections::BTreeSet<String>,
}

/// Collect both views in a single walk of the layers. Each app overlay is materialized once (a
/// `merge_app` clone), then contributes to both the trusted roll set and the trust-agnostic prune
/// universe — so `sbx upgrade` walks the apps once, not twice.
fn declared(cfg: &crate::config::Resolved) -> Declared {
    let mut seen = std::collections::BTreeSet::new();
    let mut trusted = Vec::new();
    let mut all = std::collections::BTreeSet::new();
    let mut absorb = |pkgs: &[crate::config::Package]| {
        for (_, url) in super::packages::tarball_packages(pkgs) {
            if seen.insert(url.clone()) {
                trusted.push(url);
            }
        }
        for p in pkgs {
            if let crate::config::Backend::Tarball(url) = &p.backend {
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

/// How many declared `tarball:` packages are withheld for being untrusted — across the baseline and
/// each app. A count only (the per-package reason is warned on the launch path), so `sbx upgrade`
/// does not read as "none declared" when an untrusted project declares one.
pub(crate) fn withheld(cfg: &crate::config::Resolved) -> usize {
    let untrusted = |pkgs: &[crate::config::Package]| {
        pkgs.iter()
            .filter(|p| {
                matches!(p.backend, crate::config::Backend::Tarball(_))
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

    const HASH: &str = "sha256-jBGtMS5lpJWVXe+KzQgRSho8BcaEzGvONzIbAWled0w=";

    #[test]
    fn the_generated_derivation_pins_the_source_and_wraps_the_electron_launcher() {
        let expr = derivation_expr(
            "github:NixOS/nixpkgs/abc",
            "x86_64-linux",
            "demo-app",
            "https://example.com/x/1.0/linux-x64/Demo%20App.tar.gz",
            HASH,
        );
        // pinned source (url + resolved hash), against the pinned nixpkgs for this system
        assert!(expr.contains(
            "(builtins.getFlake \"github:NixOS/nixpkgs/abc\").legacyPackages.x86_64-linux"
        ));
        assert!(expr.contains("url = \"https://example.com/x/1.0/linux-x64/Demo%20App.tar.gz\";"));
        assert!(expr.contains(&format!("hash = \"{HASH}\";")));
        // gzip tarball extraction with a non-root `tar` so a setuid `chrome-sandbox` does not abort
        // the unpack; unpack-only, no build script (safe host-side); the Electron lib set is present.
        assert!(expr.contains("tar -xz --no-same-permissions --no-same-owner -f $src"));
        assert!(expr.contains("dontBuild = true;"));
        assert!(expr.contains("nss") && expr.contains("gtk3") && expr.contains("libx11"));
        // generic Electron install: find the app by its resources/app(.asar), wrap the launcher.
        assert!(expr.contains("$out/bin/demo-app"));
        assert!(expr.contains("meta.mainProgram = \"demo-app\";"));
        // no leftover placeholder
        assert!(!expr.contains('@'), "unreplaced placeholder in:\n{expr}");
    }

    #[test]
    fn the_lock_round_trips_and_a_corrupt_line_self_heals() {
        let data = TmpDir::new();
        let layout = Layout::under(data.path());
        let id = "proj1";
        let mut lock = BTreeMap::new();
        lock.insert(
            "https://e/app.tar.gz".to_string(),
            TarballPin {
                hash: HASH.to_string(),
                url: "https://e/app.tar.gz".to_string(),
            },
        );
        write_pins(&layout, id, &lock).expect("write the lock");

        // the direct-URL pin is a compact two-column line.
        let raw = std::fs::read_to_string(lock_path(&layout, id)).unwrap();
        assert!(
            raw.contains(&format!("https://e/app.tar.gz\t{HASH}\n")),
            "a direct-URL pin keeps the two-column form:\n{raw}"
        );

        let read = pins(&layout, id);
        assert_eq!(read.len(), 1);
        assert_eq!(read["https://e/app.tar.gz"].url, "https://e/app.tar.gz");
        assert_eq!(read["https://e/app.tar.gz"].hash, HASH);

        // a corrupt (non-SRI) line self-heals (drop).
        std::fs::write(
            lock_path(&layout, id),
            format!("https://e/app.tar.gz\t{HASH}\nhttps://bad/b.tar.gz\tnot-a-hash\n"),
        )
        .unwrap();
        let read = pins(&layout, id);
        assert_eq!(read.len(), 1, "the corrupt line must self-heal (drop)");
    }
}
