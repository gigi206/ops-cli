//! `deb:` packages — a prebuilt Debian package (`.deb`) provisioned host-side.
//!
//! For a GUI/desktop app distributed only as a `.deb` (no runnable release binary, no nixpkgs
//! attribute, and — for opencode-desktop — an official flake whose from-source build is broken by a
//! bun-version mismatch), sbx packages the prebuilt `.deb` directly: resolve the URL to a content
//! hash, then build a generated derivation that `dpkg-deb -x`-unpacks it and `autoPatchelfHook`s the
//! ELF binaries against a curated Electron/Chromium library set. **No build script runs**
//! (`dontBuild`), so — unlike an arbitrary `flake:` — evaluating and building it host-side is safe;
//! it is therefore provisioned like `nix:` (into sbx's store, seeded, offline-reusable) rather than
//! in-cage.
//!
//! Three source forms (all trusted-only, like every `[packages]` backend):
//!   * `deb:<https url>` — a fixed `.deb` URL. A GitHub `…/releases/latest/download/<stable>.deb`
//!     URL already rolls forward via the redirect; a version-embedding URL does not.
//!   * `deb:github:<owner>/<repo>` — query the repo's latest release and select its linux `.deb`
//!     asset, so even a project whose asset name embeds the version rolls forward.
//!   * `deb:apt:<https Packages-index url>` — track an apt repository's highest-version `.deb`, for a
//!     vendor pool that publishes versioned filenames with no `latest` alias (so a hand-pinned URL
//!     goes stale). sbx fetches the uncompressed `Packages` index, picks the newest version, and
//!     **re-validates the derived `.deb` URL** through the same charset check a hand-written `deb:`
//!     URL passes. Scope, not a gap: uncompressed index only, no `InRelease`/GPG check, a
//!     single-application repo — the same TLS-plus-unpack trust level as a direct `deb:` URL.
//!
//! Update model: pin-on-first-use. A launch resolves the source to a concrete `.deb` URL and its
//! content hash, records both in a per-project lock (`deb-packages.lock`), and later launches reuse
//! the pin offline — the launch hot path never touches the network. `sbx upgrade` re-resolves each
//! declared source forward (re-querying GitHub for the `github:` form, the apt index for the `apt:`
//! form) and rewrites the lock.

use super::prebuilt::{self, ELECTRON_LIBS};
use crate::store::{self, Layout};
use std::collections::BTreeMap;
use std::io;
use std::path::{Path, PathBuf};

const DEB_LOCK: &str = "deb-packages.lock";

/// A locked `deb:` package, keyed in the lock by its declared *locator* (the `.deb` URL, or a
/// `github:<owner>/<repo>`). `url` is the concrete `.deb` the pin resolved to (== the locator for a
/// direct URL, the selected release asset for a `github:` locator), and `hash` its SRI content hash
/// — so a warm launch fetches and builds the pinned asset offline without re-querying GitHub.
#[derive(Clone)]
pub(crate) struct DebPin {
    pub(crate) hash: String,
    pub(crate) url: String,
}

/// The shapes a declared `deb:` locator can take, dispatched from its prefix.
enum DebSource {
    /// A direct `https://…/….deb` URL — resolved to itself.
    Url(String),
    /// `github:<owner>/<repo>` — resolved via the repo's latest release.
    Github { owner: String, repo: String },
    /// `apt:<packages-index-url>` — resolved via an apt repository's uncompressed `Packages` index
    /// (its highest-version `.deb`), for a vendor pool with no `latest` alias.
    Apt { packages_url: String },
}

/// Parse a declared locator (already validated by `config::parse_backend`) into its [`DebSource`].
fn parse_source(locator: &str) -> DebSource {
    if let Some(url) = locator.strip_prefix("apt:") {
        return DebSource::Apt {
            packages_url: url.to_string(),
        };
    }
    if let Some(path) = locator.strip_prefix("github:") {
        if let Some((owner, repo)) = path.split_once('/') {
            return DebSource::Github {
                owner: owner.to_string(),
                repo: repo.to_string(),
            };
        }
    }
    DebSource::Url(locator.to_string())
}

/// The outcome of re-resolving one declared `deb:` reference during `sbx upgrade`.
pub(crate) enum DebUpgrade {
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
        .join(DEB_LOCK)
}

/// Read the per-project deb lock. Each line is `key\thash` or `key\thash\turl`: a two-column line
/// (a direct-URL pin, and the legacy format) takes the key as its resolved URL; a three-column line
/// (a `github:` pin) carries the resolved asset URL separately. A corrupt line self-heals by being
/// dropped; an absent lock is an empty map (the unpinned state).
pub(crate) fn pins(layout: &Layout, project_id: &str) -> BTreeMap<String, DebPin> {
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
                    DebPin {
                        hash: hash.to_string(),
                        url: url.to_string(),
                    },
                );
            }
        }
    }
    map
}

/// The pinned content hashes for a project's `deb:` packages, keyed by the declared URL (a
/// package's locator, so `sbx config` can look each up directly), shortened for display. Reads
/// only the per-project lock — surfaces a pin without resolving or building — so the config view
/// stays side-effect-free, exactly like [`super::flake::pinned_revs`].
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

/// Write the per-project deb lock atomically (temp + rename), so a concurrent same-project launch
/// never observes a half-written file.
fn write_pins(
    layout: &Layout,
    project_id: &str,
    lock: &BTreeMap<String, DebPin>,
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
        // A direct-URL pin keeps the compact two-column form (key == resolved url), byte-identical
        // to the legacy lock; a `github:` pin, whose resolved asset url differs from its key, needs
        // the third column.
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

/// Resolve a declared `deb:` locator to `(concrete .deb url, SRI content hash)`. A direct URL
/// resolves to itself; a `github:<owner>/<repo>` locator queries the repo's latest release, selects
/// its linux `.deb` asset, and **re-validates that GitHub-supplied URL** through the same
/// injection-free barrier a hand-written `deb:` URL passes before it is fetched or interpolated into
/// the generated derivation. `fresh` bypasses the fetch cache (set on `sbx upgrade`, so it sees a
/// new release). Fail-closed: an unvalidated or unselectable asset returns an error and no pin.
pub(crate) fn resolve_source(
    nix: &Path,
    layout: &Layout,
    locator: &str,
    system: &str,
    fresh: bool,
) -> io::Result<(String, String)> {
    let url = match parse_source(locator) {
        DebSource::Url(url) => url,
        DebSource::Github { owner, repo } => {
            let api = format!("https://api.github.com/repos/{owner}/{repo}/releases/latest");
            let json = super::nixhub::fetch_url_json(nix, layout, &api, fresh)?;
            let url = select_deb_asset(&json, system).ok_or_else(|| {
                io::Error::other(format!(
                    "no linux {} `.deb` asset in the latest release of {owner}/{repo}",
                    prebuilt::arch_label(system)
                ))
            })?;
            if !crate::config::is_valid_deb_url(&url) {
                return Err(io::Error::other(format!(
                    "the latest release of {owner}/{repo} selected an asset URL that is not a \
                     valid `.deb` URL: {url}"
                )));
            }
            url
        }
        DebSource::Apt { packages_url } => resolve_apt_deb_url(nix, layout, &packages_url, fresh)?,
    };
    let hash = prebuilt::prefetch_hash(nix, layout, &url)?;
    Ok((url, hash))
}

/// Resolve an `apt:` locator's Packages index to the concrete `.deb` URL of its highest-version
/// package — the one network+derivation step `deb:apt:` adds over a direct `deb:` URL, kept as a
/// seam so it is testable against a real index without the heavy `.deb` prefetch. Fetches the index
/// (fresh past the cache on `sbx upgrade`), selects the newest version, resolves its `Filename:`
/// against the repo root, and **re-validates that derived URL through [`is_valid_deb_url`]** — the
/// index is remote-controlled, so this is the injection boundary before the URL is fetched or
/// interpolated into the generated derivation. Fail-closed at every step.
fn resolve_apt_deb_url(
    nix: &Path,
    layout: &Layout,
    packages_url: &str,
    fresh: bool,
) -> io::Result<String> {
    let index = super::nixhub::fetch_url_text(nix, layout, packages_url, fresh)?;
    let (version, filename) = select_latest_apt_deb(&index).map_err(|e| {
        io::Error::other(format!(
            "the apt Packages index at {packages_url} could not be resolved: {e}"
        ))
    })?;
    let root = apt_repo_root(packages_url).ok_or_else(|| {
        io::Error::other(format!(
            "the apt Packages URL must contain a `/dists/` segment to locate the repo root: \
             {packages_url}"
        ))
    })?;
    let url = format!("{root}/{}", filename.trim_start_matches('/'));
    if !crate::config::is_valid_deb_url(&url) {
        return Err(io::Error::other(format!(
            "the apt index at {packages_url} selected a `.deb` URL (version {version}) that is not \
             a valid `.deb` URL: {url}"
        )));
    }
    Ok(url)
}

/// Select the newest package's `.deb` from an apt `Packages` index. The index is RFC822-style
/// stanzas separated by blank lines, each carrying `Package:`, `Version:`, and `Filename:` fields.
/// sbx targets a **single-application** apt repo (a vendor's own pool), so every stanza must name the
/// SAME `Package:` — a multi-package Debian mirror is refused (it is ambiguous which app to track).
/// The highest `Version:` wins, compared as dotted **decimal** components (`1.21459.0` > `1.18286.2`);
/// a version carrying a non-numeric component is **refused** rather than mis-ordered — this is
/// deliberately not full dpkg ordering (no epochs, no `~`). Returns `(version, filename)` of the
/// winner, `filename` being the path relative to the repo root. Pure, so it is unit-tested against a
/// captured index.
fn select_latest_apt_deb(index: &str) -> Result<(String, String), String> {
    let mut stanzas: Vec<(String, String, String)> = Vec::new();
    let (mut pkg, mut ver, mut file): (Option<String>, Option<String>, Option<String>) =
        (None, None, None);
    // Group RFC822 stanzas on blank lines by iterating `lines()` (which strips both `\n` and `\r\n`)
    // rather than splitting on `"\n\n"` — so an apt `Packages` served with CRLF still parses into
    // separate stanzas instead of collapsing into one. A trailing sentinel flushes the final stanza
    // when the file does not end in a blank line.
    for line in index.lines().chain(std::iter::once("")) {
        if line.trim().is_empty() {
            if let (Some(p), Some(v), Some(f)) = (pkg.take(), ver.take(), file.take()) {
                if !p.is_empty() && !v.is_empty() && !f.is_empty() {
                    stanzas.push((p, v, f));
                }
            }
        } else if let Some(v) = line.strip_prefix("Package:") {
            pkg = Some(v.trim().to_string());
        } else if let Some(v) = line.strip_prefix("Version:") {
            ver = Some(v.trim().to_string());
        } else if let Some(v) = line.strip_prefix("Filename:") {
            file = Some(v.trim().to_string());
        }
    }
    let first = stanzas
        .first()
        .ok_or("no package stanza (Package/Version/Filename) found")?;
    let name = first.0.clone();
    if stanzas.iter().any(|(p, _, _)| *p != name) {
        return Err(format!(
            "the index names more than one package (e.g. `{name}`); `deb:apt:` tracks a \
             single-application repo"
        ));
    }
    // Parse EVERY version (so a non-numeric one anywhere is refused, not just the winner) and keep
    // the index of the highest — dotted-decimal order, so `1.21459.0` > `1.18286.2`.
    let bad = |v: &str| {
        format!("version `{v}` is not a plain dotted-decimal version `deb:apt:` can order")
    };
    let mut best_idx = 0usize;
    let mut best_ver = parse_numeric_version(&stanzas[0].1).ok_or_else(|| bad(&stanzas[0].1))?;
    for (i, stanza) in stanzas.iter().enumerate().skip(1) {
        let ver = parse_numeric_version(&stanza.1).ok_or_else(|| bad(&stanza.1))?;
        if ver > best_ver {
            best_ver = ver;
            best_idx = i;
        }
    }
    let winner = &stanzas[best_idx];
    Ok((winner.1.clone(), winner.2.clone()))
}

/// Parse a dotted-decimal version (`1.21459.0`) into comparable numeric components. Returns `None` if
/// any component is not a plain non-negative integer, so [`select_latest_apt_deb`] refuses such a
/// version rather than mis-ordering it (it does not implement dpkg epoch/`~` semantics).
fn parse_numeric_version(v: &str) -> Option<Vec<u64>> {
    if v.is_empty() {
        return None;
    }
    v.split('.').map(|c| c.parse::<u64>().ok()).collect()
}

/// The repository root of an apt `Packages` URL — the base each stanza's `Filename:` (a repo-relative
/// `pool/…/*.deb` path) resolves against. In the standard layout the index lives at
/// `<root>/dists/<suite>/<component>/binary-<arch>/Packages`, so the root is the URL up to (not
/// including) the `/dists/` segment. Returns `None` if there is no `/dists/` segment.
fn apt_repo_root(packages_url: &str) -> Option<&str> {
    packages_url.split_once("/dists/").map(|(root, _)| root)
}

/// Select the linux `.deb` asset URL matching `system` from a GitHub release's JSON. A `.deb` is a
/// Linux package by definition, so the discriminant is CPU architecture, not the OS: an asset whose
/// name names a *foreign* arch is dropped, then one positively naming this arch is chosen
/// (deterministic by name); a single unambiguous `.deb` with no arch token is the fallback for a
/// single-arch repo. Pure, so selection is testable against captured release JSON.
fn select_deb_asset(json: &serde_json::Value, system: &str) -> Option<String> {
    let (accept, reject) = prebuilt::arch_tokens(system);
    let mut native: Vec<(String, String)> = json
        .get("assets")?
        .as_array()?
        .iter()
        .filter_map(|a| {
            let name = a.get("name")?.as_str()?.to_ascii_lowercase();
            let url = a.get("browser_download_url")?.as_str()?;
            (name.ends_with(".deb") && !reject.iter().any(|t| name.contains(t)))
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

/// The generated nix expression building one `deb:` package: fetch the pinned `.deb`, unpack it, and
/// autoPatchelf it against [`ELECTRON_LIBS`] from the pinned `nixpkgs`. The install phase is generic
/// for an Electron layout — it locates the app directory by its `resources/` signature (a packed
/// `resources/app.asar` or, for an asar-less VS Code fork, the `resources/app/` directory) and
/// wraps the app's own launcher (the executable beside it that is not a `.so` or a Chromium helper),
/// so no per-app path is hardcoded. Every interpolated value is sbx-controlled and charset-validated
/// (`name`, `url`, `hash`, the pinned `nixpkgs`, the `system`), so the expression carries nothing to
/// escape; placeholders keep nix's `${…}`/`{…}` out of Rust's formatter.
fn derivation_expr(nixpkgs: &str, system: &str, name: &str, url: &str, hash: &str) -> String {
    const TEMPLATE: &str = r#"let pkgs = (builtins.getFlake "@NIXPKGS@").legacyPackages.@SYSTEM@;
in pkgs.stdenvNoCC.mkDerivation (finalAttrs: {
  name = "@NAME@";
  src = pkgs.fetchurl { url = "@URL@"; hash = "@HASH@"; };
  nativeBuildInputs = with pkgs; [ dpkg makeWrapper autoPatchelfHook ];
  buildInputs = with pkgs; [ @LIBS@ ];
  autoPatchelfIgnoreMissingDeps = [ "libc.musl-x86_64.so.1" ];
  # Extract the data tarball with a plain, unprivileged `tar` instead of `dpkg-deb -x`. The latter
  # restores exact modes and aborts when a `.deb` ships a setuid file (Chromium's `chrome-sandbox`,
  # mode 04755): a non-root nix builder cannot chmod setuid ("Operation not permitted"), which fails
  # the whole unpack. `tar` without `--preserve-permissions` simply does not restore the setuid bit.
  # This is safe and load-bearing for Electron apps: the launcher runs with `--no-sandbox` (bubblewrap
  # + seccomp + the empty netns is the boundary), so that helper is never used, and setuid could not
  # take effect in the cage anyway.
  unpackPhase = ''
    mkdir extracted
    dpkg-deb --fsys-tarfile $src | tar -x --no-same-permissions --no-same-owner -C extracted
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
    // The `.deb` binary lives under its own prefix and finds its sibling `.so`s via RUNPATH, so the
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

/// Provision one `deb:` package host-side: resolve the URL to a hash (pinning it on first use),
/// build the generated derivation into sbx's store, and return `(bin directory, store root)` — the
/// bin dir to prepend to the sandbox `PATH`, the root whose closure the project store seeds. Mirrors
/// [`super::packages::provision`]'s per-package gcroot, name-keyed under the project.
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
                DebPin {
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
        .join(format!("deb-{name}"));
    let logical = store::provision_expr(nix, layout, &gcroot, &expr, name, "bin")?;
    Ok((logical.join("bin"), logical))
}

/// Re-resolve a project's declared `deb:` references and rewrite the per-project lock — pinning new
/// ones, rolling changed ones forward, and pruning entries whose URL is no longer declared. Mirrors
/// [`super::flake::upgrade`]: references collected generically across the baseline and each app,
/// resolution best-effort per reference, lock rewritten once at the end.
pub(crate) fn upgrade(
    nix: &Path,
    layout: &Layout,
    project: &Path,
    cfg: &crate::config::Resolved,
) -> io::Result<Vec<DebUpgrade>> {
    let project_id = super::binds::project_runtime_id(project)?;
    // One walk of the layers yields both the trusted roll set and the trust-agnostic prune universe.
    let Declared {
        trusted: declared,
        all: universe,
    } = declared(cfg);
    let system = super::current_system();
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
        outcomes.push(DebUpgrade::Pruned { url });
    }

    for locator in &declared {
        let previous = lock.get(locator).map(|p| p.hash.clone());
        // `fresh` re-queries GitHub (for a `github:` locator) past the fetch cache, so a new release
        // is seen; a direct URL ignores it. The lock records the resolved asset URL, not the locator.
        match resolve_source(nix, layout, locator, &system, true) {
            Ok((url, hash)) => {
                let outcome = match &previous {
                    Some(old) if old == &hash => DebUpgrade::Unchanged {
                        url: locator.clone(),
                        hash: hash.clone(),
                    },
                    Some(old) => DebUpgrade::Rolled {
                        url: locator.clone(),
                        from: old.clone(),
                        to: hash.clone(),
                    },
                    None => DebUpgrade::Pinned {
                        url: locator.clone(),
                        hash: hash.clone(),
                    },
                };
                lock.insert(locator.clone(), DebPin { hash, url });
                outcomes.push(outcome);
            }
            Err(e) => outcomes.push(DebUpgrade::Failed {
                url: locator.clone(),
                error: e.to_string(),
            }),
        }
    }

    write_pins(layout, project_id.as_str(), &lock)?;
    Ok(outcomes)
}

/// The two views `sbx upgrade deb` needs of a project's declared `deb:` URLs, collected in one pass
/// over the baseline and each app overlay (see [`declared`]).
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
        for (_, url) in super::packages::deb_packages(pkgs) {
            if seen.insert(url.clone()) {
                trusted.push(url);
            }
        }
        for p in pkgs {
            if let crate::config::Backend::Deb(url) = &p.backend {
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

/// How many declared `deb:` packages are withheld for being untrusted — across the baseline and
/// each app. A count only (the per-package reason is warned on the launch path), so `sbx upgrade`
/// does not read as "none declared" when an untrusted project declares one.
pub(crate) fn withheld(cfg: &crate::config::Resolved) -> usize {
    let untrusted = |pkgs: &[crate::config::Package]| {
        pkgs.iter()
            .filter(|p| {
                matches!(p.backend, crate::config::Backend::Deb(_))
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
            "opencode-desktop",
            "https://example.com/x/opencode-desktop-linux-amd64.deb",
            HASH,
        );
        // pinned source (url + resolved hash), against the pinned nixpkgs for this system
        assert!(expr.contains(
            "(builtins.getFlake \"github:NixOS/nixpkgs/abc\").legacyPackages.x86_64-linux"
        ));
        assert!(expr.contains("url = \"https://example.com/x/opencode-desktop-linux-amd64.deb\";"));
        assert!(expr.contains(&format!("hash = \"{HASH}\";")));
        // unpack-only, no build script (safe host-side); the Electron lib set is present. The
        // extraction pipes the data tarball through a non-root `tar` so a setuid file (Chromium's
        // `chrome-sandbox`) does not abort the unpack in the unprivileged nix builder.
        assert!(expr.contains("dpkg-deb --fsys-tarfile $src | tar -x --no-same-permissions"));
        assert!(expr.contains("dontBuild = true;"));
        assert!(expr.contains("nss") && expr.contains("gtk3") && expr.contains("libx11"));
        // generic Electron install: find the app by its app.asar, wrap the launcher as bin/<name>
        assert!(expr.contains("resources/"));
        assert!(expr.contains("app.asar"));
        assert!(expr.contains("$out/bin/opencode-desktop"));
        assert!(expr.contains("meta.mainProgram = \"opencode-desktop\";"));
        // no leftover placeholder
        assert!(!expr.contains('@'), "unreplaced placeholder in:\n{expr}");
    }

    #[test]
    fn the_lock_round_trips_both_forms_and_a_corrupt_line_self_heals() {
        let data = TmpDir::new();
        let layout = Layout::under(data.path());
        let id = "proj1";
        let mut lock = BTreeMap::new();
        // a direct-URL pin (url == key) and a `github:` pin (url != key, the resolved asset).
        lock.insert(
            "https://example.com/a.deb".to_string(),
            DebPin {
                hash: HASH.to_string(),
                url: "https://example.com/a.deb".to_string(),
            },
        );
        lock.insert(
            "github:iOfficeAI/AionUi".to_string(),
            DebPin {
                hash: HASH.to_string(),
                url: "https://github.com/iOfficeAI/AionUi/releases/download/v2.1.35/AionUi-2.1.35-linux-amd64.deb".to_string(),
            },
        );
        write_pins(&layout, id, &lock).expect("write the lock");

        // the direct-URL pin stays a compact two-column line (byte-compatible with the legacy lock).
        let raw = std::fs::read_to_string(lock_path(&layout, id)).unwrap();
        assert!(
            raw.contains(&format!("https://example.com/a.deb\t{HASH}\n")),
            "a direct-URL pin keeps the two-column form:\n{raw}"
        );

        let read = pins(&layout, id);
        assert_eq!(read.len(), 2);
        assert_eq!(
            read["https://example.com/a.deb"].url,
            "https://example.com/a.deb"
        );
        assert_eq!(
            read["github:iOfficeAI/AionUi"].url,
            "https://github.com/iOfficeAI/AionUi/releases/download/v2.1.35/AionUi-2.1.35-linux-amd64.deb"
        );
        assert_eq!(read["github:iOfficeAI/AionUi"].hash, HASH);

        // a legacy two-column line reads with url == key; a corrupt (non-SRI) line self-heals (drop).
        std::fs::write(
            lock_path(&layout, id),
            format!("https://example.com/a.deb\t{HASH}\nhttps://bad.example/b.deb\tnot-a-hash\n"),
        )
        .unwrap();
        let read = pins(&layout, id);
        assert_eq!(read.len(), 1, "the corrupt line must self-heal (drop)");
        assert_eq!(
            read["https://example.com/a.deb"].url, "https://example.com/a.deb",
            "a two-column (legacy) line takes its key as the resolved url"
        );
    }

    #[test]
    fn parse_source_dispatches_github_from_url() {
        match parse_source("github:iOfficeAI/AionUi") {
            DebSource::Github { owner, repo } => {
                assert_eq!(owner, "iOfficeAI");
                assert_eq!(repo, "AionUi");
            }
            DebSource::Url(_) | DebSource::Apt { .. } => panic!("github locator misparsed"),
        }
        assert!(matches!(
            parse_source("https://example.com/x.deb"),
            DebSource::Url(u) if u == "https://example.com/x.deb"
        ));
    }

    // A trimmed capture of iOfficeAI/AionUi's `releases/latest` asset set (real names + URLs), the
    // shape [`select_deb_asset`] must pick from: two linux `.deb`s (amd64 + arm64) beside mac/win.
    const AIONUI_ASSETS: &str = r#"{
      "tag_name": "v2.1.35",
      "assets": [
        { "name": "AionUi-2.1.35-linux-amd64.deb",
          "browser_download_url": "https://github.com/iOfficeAI/AionUi/releases/download/v2.1.35/AionUi-2.1.35-linux-amd64.deb" },
        { "name": "AionUi-2.1.35-linux-arm64.deb",
          "browser_download_url": "https://github.com/iOfficeAI/AionUi/releases/download/v2.1.35/AionUi-2.1.35-linux-arm64.deb" },
        { "name": "AionUi-2.1.35-mac-x64.dmg",
          "browser_download_url": "https://github.com/iOfficeAI/AionUi/releases/download/v2.1.35/AionUi-2.1.35-mac-x64.dmg" },
        { "name": "AionUi-2.1.35-win-x64.exe",
          "browser_download_url": "https://github.com/iOfficeAI/AionUi/releases/download/v2.1.35/AionUi-2.1.35-win-x64.exe" }
      ]
    }"#;

    #[test]
    fn select_deb_asset_picks_the_native_arch_and_rejects_the_foreign_one() {
        let json: serde_json::Value = serde_json::from_str(AIONUI_ASSETS).unwrap();
        // x86_64 selects the amd64 deb, never the arm64 deb or the mac/win assets.
        assert_eq!(
            select_deb_asset(&json, "x86_64-linux").as_deref(),
            Some("https://github.com/iOfficeAI/AionUi/releases/download/v2.1.35/AionUi-2.1.35-linux-amd64.deb")
        );
        // aarch64 selects the arm64 deb from the same release.
        assert_eq!(
            select_deb_asset(&json, "aarch64-linux").as_deref(),
            Some("https://github.com/iOfficeAI/AionUi/releases/download/v2.1.35/AionUi-2.1.35-linux-arm64.deb")
        );
    }

    #[test]
    fn select_deb_asset_falls_back_to_a_single_untokened_deb_and_none_when_absent() {
        // a single-arch repo whose one `.deb` carries no arch token is taken (x86_64 host).
        let single = serde_json::json!({
            "assets": [
                { "name": "myapp_1.2.3.deb", "browser_download_url": "https://e/myapp_1.2.3.deb" },
                { "name": "myapp_1.2.3.AppImage", "browser_download_url": "https://e/x.AppImage" }
            ]
        });
        assert_eq!(
            select_deb_asset(&single, "x86_64-linux").as_deref(),
            Some("https://e/myapp_1.2.3.deb")
        );
        // no `.deb` at all → None (the caller turns this into a fail-closed error, no pin).
        let none = serde_json::json!({
            "assets": [ { "name": "app.AppImage", "browser_download_url": "https://e/app.AppImage" } ]
        });
        assert_eq!(select_deb_asset(&none, "x86_64-linux"), None);
        // two arch-tokened debs but neither native, and >1 survivor → ambiguous → None (no guess).
        let foreign = serde_json::json!({
            "assets": [
                { "name": "app-arm64.deb", "browser_download_url": "https://e/arm64.deb" },
                { "name": "app-armhf.deb", "browser_download_url": "https://e/armhf.deb" }
            ]
        });
        assert_eq!(select_deb_asset(&foreign, "x86_64-linux"), None);
    }

    fn deb_pkg(name: &str, url: &str, trusted: bool) -> crate::config::Package {
        crate::config::Package {
            name: name.into(),
            backend: crate::config::Backend::Deb(url.into()),
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
    fn declared_trusted_covers_baseline_and_apps_dedups_and_drops_untrusted() {
        let cfg = resolved(
            vec![
                deb_pkg("a", "https://e/a.deb", true),
                deb_pkg("evil", "https://e/evil.deb", false), // untrusted: dropped
            ],
            vec![
                (
                    "alpha",
                    app_with(vec![
                        deb_pkg("b", "https://e/b.deb", true),
                        deb_pkg("a2", "https://e/a.deb", true), // duplicate url: deduped
                    ]),
                ),
                ("beta", app_with(vec![])), // no deb package: contributes nothing
            ],
        );
        // baseline first, then the app's new url; the duplicate and the untrusted one are gone.
        assert_eq!(
            declared(&cfg).trusted,
            vec!["https://e/a.deb", "https://e/b.deb"]
        );
    }

    #[test]
    fn the_prune_universe_keeps_untrusted_so_upgrade_never_prunes_a_withheld_pin() {
        // The prune universe must NOT drop a still-declared url just because the project is
        // untrusted — else `sbx upgrade deb` on a Changed project unpins it. Unlike the trusted roll
        // set, `declared().all` keeps the untrusted url; `withheld` counts it so the summary is honest.
        let cfg = resolved(
            vec![
                deb_pkg("a", "https://e/a.deb", true),
                deb_pkg("evil", "https://e/evil.deb", false),
            ],
            vec![(
                "app",
                app_with(vec![deb_pkg("c", "https://e/c.deb", false)]),
            )],
        );
        let universe = declared(&cfg).all;
        assert!(universe.contains("https://e/a.deb"));
        assert!(
            universe.contains("https://e/evil.deb"),
            "a withheld-but-declared url must survive pruning"
        );
        assert!(universe.contains("https://e/c.deb"));
        assert_eq!(
            withheld(&cfg),
            2,
            "the two untrusted deb packages are counted"
        );
    }

    #[test]
    fn parse_source_dispatches_apt_url_and_github_by_prefix() {
        assert!(matches!(parse_source("apt:https://h/x/dists/s/Packages"),
            DebSource::Apt { packages_url } if packages_url == "https://h/x/dists/s/Packages"));
        assert!(matches!(
            parse_source("github:o/r"),
            DebSource::Github { .. }
        ));
        assert!(matches!(parse_source("https://h/x.deb"), DebSource::Url(_)));
    }

    // A trimmed apt `Packages` index shaped like a vendor's single-application pool: several versions
    // of one package, newest NOT last, so the ordering (not the file order) is what's under test.
    const APT_INDEX: &str = "\
Package: claude-desktop
Version: 1.18286.2
Filename: pool/main/c/claude-desktop/claude-desktop_1.18286.2_amd64.deb

Package: claude-desktop
Version: 1.21459.0
Filename: pool/main/c/claude-desktop/claude-desktop_1.21459.0_amd64.deb

Package: claude-desktop
Version: 1.17377.0
Filename: pool/main/c/claude-desktop/claude-desktop_1.17377.0_amd64.deb
";

    #[test]
    fn select_latest_apt_deb_picks_the_highest_version_not_the_last_line() {
        let (version, filename) = select_latest_apt_deb(APT_INDEX).expect("resolves");
        // 1.21459.0 > 1.18286.2 numerically (a lexical/`sort`-style compare would pick 1.18286.2);
        // and it is not the last stanza, so file order is not what won.
        assert_eq!(version, "1.21459.0");
        assert_eq!(
            filename,
            "pool/main/c/claude-desktop/claude-desktop_1.21459.0_amd64.deb"
        );
    }

    #[test]
    fn select_latest_apt_deb_is_crlf_safe() {
        // The same index served with CRLF line endings must parse into the same stanzas and pick the
        // same newest version — grouping on `lines()` (not `split("\n\n")`) makes it CRLF-safe. A
        // `\n\n`-based parser would collapse this to one block and return the LAST stanza (1.17377.0).
        let crlf = APT_INDEX.replace('\n', "\r\n");
        let (version, _) = select_latest_apt_deb(&crlf).expect("resolves");
        assert_eq!(version, "1.21459.0");
    }

    #[test]
    fn select_latest_apt_deb_refuses_a_multi_package_index() {
        let multi =
            format!("{APT_INDEX}\nPackage: other-app\nVersion: 9.9.9\nFilename: pool/o.deb\n");
        let err = select_latest_apt_deb(&multi).unwrap_err();
        assert!(err.contains("more than one package"), "got: {err}");
    }

    #[test]
    fn select_latest_apt_deb_refuses_a_non_numeric_version_rather_than_misordering() {
        let idx = "Package: p\nVersion: 2.0.0~rc1\nFilename: pool/p.deb\n";
        let err = select_latest_apt_deb(idx).unwrap_err();
        assert!(err.contains("dotted-decimal"), "got: {err}");
        // an empty index is refused too
        assert!(select_latest_apt_deb("").is_err());
    }

    // Live check (skip-not-fail, like the nixhub resolution test): resolve a REAL vendor apt index
    // through the whole Rust chain — nix fetch of the uncompressed `Packages`, version selection,
    // repo-root join, and the `is_valid_deb_url` re-validation — WITHOUT the heavy `.deb` prefetch.
    // Anthropic's claude-desktop pool has no `latest` alias, which is exactly what `deb:apt:` is for.
    #[test]
    fn resolve_apt_deb_url_derives_a_current_deb_from_the_real_claude_index() {
        let Some(nix) = store::resolve_nix(None) else {
            eprintln!("skipping deb:apt live resolve: no nix on PATH");
            return;
        };
        let data = TmpDir::new();
        let layout = Layout::under(data.path());
        const INDEX: &str = "https://downloads.claude.ai/claude-desktop/apt/stable/dists/stable/main/binary-amd64/Packages";
        let url = match resolve_apt_deb_url(&nix, &layout, INDEX, true) {
            Ok(u) => u,
            Err(e) => {
                eprintln!("skipping deb:apt live resolve (network/nix): {e}");
                return;
            }
        };
        // The derived URL passed the same charset validation a hand-written `deb:` URL does, and
        // names the claude-desktop pool.
        assert!(
            crate::config::is_valid_deb_url(&url),
            "derived URL invalid: {url}"
        );
        assert!(
            url.starts_with("https://downloads.claude.ai/claude-desktop/apt/stable/pool/")
                && url.contains("/claude-desktop_")
                && url.ends_with("_amd64.deb"),
            "unexpected derived URL: {url}"
        );
        // It is a *current* pick: the version embedded in the resolved filename orders at or above
        // the version this profile used to hand-pin (1.18286.2), proving newest-wins on the live
        // index, not a stale or lexical choice.
        let ver = url
            .rsplit_once("claude-desktop_")
            .and_then(|(_, tail)| tail.strip_suffix("_amd64.deb"))
            .expect("version token in filename");
        let (parsed, floor) = (
            parse_numeric_version(ver).expect("numeric version"),
            parse_numeric_version("1.18286.2").unwrap(),
        );
        assert!(
            parsed >= floor,
            "resolved {ver} is older than the former pin 1.18286.2"
        );
    }

    #[test]
    fn numeric_version_parse_and_repo_root() {
        assert_eq!(parse_numeric_version("1.21459.0"), Some(vec![1, 21459, 0]));
        assert!(parse_numeric_version("1.2~rc").is_none());
        assert!(parse_numeric_version("").is_none());
        // repo root is the URL up to the `/dists/` segment; Filename resolves against it.
        assert_eq!(
            apt_repo_root("https://d.claude.ai/claude-desktop/apt/stable/dists/stable/main/binary-amd64/Packages"),
            Some("https://d.claude.ai/claude-desktop/apt/stable")
        );
        assert_eq!(apt_repo_root("https://h/no-dists/Packages"), None);
    }
}
