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
//! Two source forms:
//! * `tarball:<https url>` — a direct `.tar.gz`/`.tgz` URL. A version-stamped vendor URL does not
//!   roll forward on its own (only a stable "latest" alias would).
//! * `tarball:resolve` (paired with a `[tarball.<name>]` table carrying a `resolve` **command**) —
//!   the auto-upgrade form. sbx runs the command in a hermetic bubblewrap cage (sbx's own base tools
//!   plus the app's `nix:` bins on `PATH`, sbx's store + CA bundle bound, shared network so it can
//!   reach a vendor version API), captures the `.tar.gz` URL it prints, validates it, and pins it, so
//!   `sbx upgrade` rolls the app forward automatically. The command is arbitrary code — honored only
//!   from a trusted layer, never run for an untrusted one — and its printed URL is re-validated by
//!   [`is_valid_tarball_url`] before any fetch, so it cannot point sbx at an injecting source.
//!
//! Update model: pin-on-first-use — identical to `deb:`. A launch resolves the source to a concrete
//! URL and its content hash, records both in a per-project lock (`tarball-packages.lock`), and later
//! launches reuse the pin offline; the launch hot path never touches the network (and a warm launch
//! never re-runs a resolve command). `sbx upgrade` re-resolves each declared source and rewrites the
//! lock — for a resolver package it re-runs the command and skips the heavy tarball re-fetch when the
//! newest release URL is unchanged.

use super::prebuilt::{self, ELECTRON_LIBS};
use super::resolve::{resolve_url, ResolveCage};
use crate::config::is_valid_tarball_url;
use crate::store::{self, Layout};
use std::collections::BTreeMap;
use std::io;
use std::path::{Path, PathBuf};

const TARBALL_LOCK: &str = "tarball-packages.lock";

/// A locked `tarball:` package, keyed in the lock by its declared *locator* — the `.tar.gz` URL for
/// a direct package, or `resolve:<name>` for a `tarball:resolve` package. `url` is the concrete
/// tarball the pin resolved to (== the key for a direct URL, the command-resolved download URL for a
/// resolver) and `hash` its SRI content hash — so a warm launch fetches and builds the pinned asset
/// offline.
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
/// unpinned state). A direct-URL pin is two-column (its key equals its resolved URL); a
/// `tarball:resolve` pin is three-column (`resolve:<name>` key, hash, the command-resolved URL), and
/// the third column's resolved URL wins.
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
        // resolved url differs from its key (a `resolve:<name>` locator) uses the third column.
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
    fresh: bool,
) -> io::Result<(String, String)> {
    let url = locator.to_string();
    // A re-resolve (`fresh`) is an `sbx upgrade` step — capture nix's output and fold the cause
    // into the error; a first launch streams the download progress live.
    let hash = prebuilt::prefetch_hash(nix, layout, &url, fresh)?;
    Ok((url, hash))
}

/// The per-project lock key of a `tarball:resolve` package: prefixed by `resolve:` so its key space
/// is disjoint from a direct package's `.tar.gz` URL (which never contains a bare `resolve:` prefix),
/// and keyed by the package name (unique per resolved config) so a warm launch and `sbx gc` can find
/// the pin without re-running the resolver command.
fn resolve_key(name: &str) -> String {
    format!("resolve:{name}")
}

/// Build one already-resolved `tarball:` package (direct or resolver form) into sbx's store and
/// return `(bin dir, store root)`. Shared by [`provision`], [`provision_resolve`], and the gc keep
/// path, so the derivation + per-package gcroot are identical across forms.
fn build_pinned(
    nix: &Path,
    layout: &Layout,
    project_id: &str,
    nixpkgs: &str,
    name: &str,
    url: &str,
    hash: &str,
) -> io::Result<(PathBuf, PathBuf)> {
    let system = super::current_system();
    let expr = derivation_expr(nixpkgs, &system, name, url, hash);
    let gcroot = layout
        .data_dir()
        .join("gcroots")
        .join("projects")
        .join(project_id)
        .join(format!("tarball-{name}"));
    let logical = store::provision_expr(nix, layout, &gcroot, &expr, name, "bin")?;
    Ok((logical.join("bin"), logical))
}

/// Provision one `tarball:resolve` package host-side — the auto-upgrade twin of [`provision`]. The
/// per-project lock is keyed by `resolve:<name>`; on a **warm** launch the pinned `(url, hash)` is
/// reused offline and the resolve command is **not run** (the offline invariant), and only a first
/// launch or `sbx upgrade` runs it. Builds the same derivation and per-package gcroot as the direct
/// form, so the two forms provision identically once resolved.
pub(crate) fn provision_resolve(
    nix: &Path,
    layout: &Layout,
    project: &Path,
    nixpkgs: &str,
    name: &str,
    command: &[String],
    cage: &ResolveCage,
) -> io::Result<(PathBuf, PathBuf)> {
    let project_id = super::binds::project_runtime_id(project)?;
    let key = resolve_key(name);
    let mut lock = pins(layout, project_id.as_str());
    let (url, hash) = match lock.get(&key) {
        Some(pin) => (pin.url.clone(), pin.hash.clone()),
        None => {
            let u = resolve_url(cage, name, command, is_valid_tarball_url, "`.tar.gz`")?;
            let h = prebuilt::prefetch_hash(nix, layout, &u, false)?;
            lock.insert(
                key,
                TarballPin {
                    hash: h.clone(),
                    url: u.clone(),
                },
            );
            write_pins(layout, project_id.as_str(), &lock)?;
            (u, h)
        }
    };
    build_pinned(nix, layout, project_id.as_str(), nixpkgs, name, &url, &hash)
}

/// Build a `tarball:resolve` package from its EXISTING pin only — for the gc keep path, which must
/// never run the resolve command or touch the network. Returns `None` when the package is not yet
/// pinned (nothing has been built to keep), so gc skips it rather than resolving.
pub(crate) fn provision_resolve_pinned(
    nix: &Path,
    layout: &Layout,
    project: &Path,
    nixpkgs: &str,
    name: &str,
) -> io::Result<Option<(PathBuf, PathBuf)>> {
    let project_id = super::binds::project_runtime_id(project)?;
    let Some(pin) = pins(layout, project_id.as_str()).remove(&resolve_key(name)) else {
        return Ok(None);
    };
    build_pinned(
        nix,
        layout,
        project_id.as_str(),
        nixpkgs,
        name,
        &pin.url,
        &pin.hash,
    )
    .map(Some)
}

/// The generated nix expression building one `tarball:` package: fetch the pinned `.tar.gz`, extract
/// it, and autoPatchelf it against [`ELECTRON_LIBS`] from the pinned `nixpkgs`. The install phase is
/// generic for an Electron layout — [`prebuilt::launcher_wrap`] locates the app directory by its
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
    let wrap = prebuilt::launcher_wrap(name, "${pkgs.lib.makeLibraryPath finalAttrs.buildInputs}");
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

/// A declared `tarball:` reference to roll forward, in either form. The lock is keyed by [`Self::key`]
/// — the direct URL, or `resolve:<name>` for a resolver package.
enum TarballRef {
    /// A direct `tarball:<url>` — resolves to itself; its content hash is always re-fetched.
    Direct(String),
    /// A `tarball:resolve` — its concrete download URL is re-derived by re-running the resolve
    /// command, and the heavy tarball prefetch runs only when that URL differs from the stored pin.
    Resolve { name: String, command: Vec<String> },
}

impl TarballRef {
    /// The per-project lock key: the direct URL, or `resolve:<name>`.
    fn key(&self) -> String {
        match self {
            TarballRef::Direct(url) => url.clone(),
            TarballRef::Resolve { name, .. } => resolve_key(name),
        }
    }
}

/// Re-resolve a project's declared `tarball:` references and rewrite the per-project lock — pinning
/// new ones, rolling changed ones forward, and pruning entries no longer declared. Mirrors
/// [`super::deb::upgrade`]: references collected generically across the baseline and each app,
/// resolution best-effort per reference, lock rewritten once at the end. A direct URL always
/// re-prefetches (its content can move); a `tarball:resolve` first re-runs its command to re-derive
/// the download URL and **skips the heavy tarball prefetch when that URL is unchanged**, so a no-op
/// `sbx upgrade` does not re-download a large versioned asset. `cage` is the sandbox resolve commands
/// run in; when it is `None` (the host cannot sandbox), a resolver reference cannot be rolled and is
/// reported as failed rather than silently frozen.
pub(crate) fn upgrade(
    nix: &Path,
    layout: &Layout,
    project: &Path,
    cfg: &crate::config::Resolved,
    cage: Option<&ResolveCage>,
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

    for reference in &declared {
        let key = reference.key();
        let previous = lock.get(&key).cloned();
        let resolved = match reference {
            // A direct URL: always re-prefetch (a stable URL's content can change).
            TarballRef::Direct(url) => resolve_source(nix, layout, url, true),
            // A resolver: re-run its command for the concrete URL. If it equals the stored pin's URL,
            // reuse the pinned hash without prefetching the (large) tarball again.
            TarballRef::Resolve { name, command } => match cage {
                None => Err(io::Error::other(
                    "cannot run the resolve command (no usable sandbox on this host)",
                )),
                Some(cage) => {
                    match resolve_url(cage, name, command, is_valid_tarball_url, "`.tar.gz`") {
                        Ok(url) => match &previous {
                            Some(pin) if pin.url == url => Ok((url, pin.hash.clone())),
                            _ => prebuilt::prefetch_hash(nix, layout, &url, true).map(|h| (url, h)),
                        },
                        Err(e) => Err(e),
                    }
                }
            },
        };
        match resolved {
            Ok((url, hash)) => {
                let outcome = match &previous {
                    Some(pin) if pin.hash == hash => TarballUpgrade::Unchanged {
                        url: key.clone(),
                        hash: hash.clone(),
                    },
                    Some(pin) => TarballUpgrade::Rolled {
                        url: key.clone(),
                        from: pin.hash.clone(),
                        to: hash.clone(),
                    },
                    None => TarballUpgrade::Pinned {
                        url: key.clone(),
                        hash: hash.clone(),
                    },
                };
                lock.insert(key, TarballPin { hash, url });
                outcomes.push(outcome);
            }
            Err(e) => outcomes.push(TarballUpgrade::Failed {
                url: key,
                error: e.to_string(),
            }),
        }
    }

    write_pins(layout, project_id.as_str(), &lock)?;
    Ok(outcomes)
}

/// The owned pieces a `tarball:resolve` upgrade cage borrows from — held across the [`upgrade`] call
/// so the [`ResolveCage`]'s references stay valid.
struct ResolveCageParts {
    bwrap: PathBuf,
    store_src: PathBuf,
    shell_bin: PathBuf,
    ca_bundle: PathBuf,
    bins: Vec<PathBuf>,
}

/// Whether the project (baseline or any app) declares a trusted `tarball:resolve` package — so the
/// upgrade path builds the (heavy) resolver sandbox only when it is actually needed.
fn has_resolve_ref(cfg: &crate::config::Resolved) -> bool {
    let any = |pkgs: &[crate::config::Package]| {
        !super::packages::tarball_resolve_packages(pkgs).is_empty()
    };
    any(&cfg.packages)
        || cfg.apps.values().any(|app| {
            let mut merged = cfg.clone();
            merged.merge_app(app.clone());
            any(&merged.packages)
        })
}

/// Assemble the resolver sandbox for `sbx upgrade` — the same hermetic base userland + the project's
/// `nix:` package bins a launch gives a resolve command, so a command runs identically at first launch
/// and at upgrade. Best-effort: if the host cannot resolve an engine or sandbox, this returns `None`
/// and [`upgrade_project`] reports each resolver reference as un-rollable rather than silently frozen.
fn build_resolve_cage_parts(
    nix: &Path,
    layout: &Layout,
    project: &Path,
    cfg: &crate::config::Resolved,
) -> Option<ResolveCageParts> {
    let bwrap = crate::store::resolve_bwrap(Some(layout))?.path;
    let nixpkgs = super::launch::effective_lock_target(project, layout, cfg)
        .ok()?
        .resolve(nix, layout)
        .ok()?;
    let engine_ref =
        crate::store::resolve_engine_ref(nix, layout, cfg.nixpkgs_global.as_deref()).ok()?;
    let userland = super::fhs::resolve_userland(nix, layout, &nixpkgs, &engine_ref).ok()?;
    let mut bins = userland.bin_paths.clone();
    // The app's `nix:` bins, so a resolve command using e.g. `jq` resolves at upgrade time exactly as
    // it does at launch. Best-effort — the base tools are always present regardless.
    if let Ok(p) = super::packages::provision(nix, layout, project, &nixpkgs, &cfg.packages) {
        bins.extend(p.bins);
    }
    Some(ResolveCageParts {
        bwrap,
        store_src: crate::store::physical_path(layout, Path::new("/nix")),
        shell_bin: userland.shell_bin.clone(),
        ca_bundle: userland.ca_bundle_src.clone(),
        bins,
    })
}

/// `sbx upgrade tarball`: roll a project's declared `tarball:` packages forward. Builds the resolver
/// sandbox (only when a `tarball:resolve` package is declared) and delegates to [`upgrade`]. A
/// direct-only project keeps the cheap path (no base-userland build).
pub(crate) fn upgrade_project(
    nix: &Path,
    layout: &Layout,
    project: &Path,
    cfg: &crate::config::Resolved,
) -> io::Result<Vec<TarballUpgrade>> {
    let parts = if has_resolve_ref(cfg) {
        build_resolve_cage_parts(nix, layout, project, cfg)
    } else {
        None
    };
    let cage = parts.as_ref().map(|p| ResolveCage {
        bwrap: p.bwrap.as_path(),
        store_src: p.store_src.clone(),
        shell_bin: p.shell_bin.as_path(),
        ca_bundle: p.ca_bundle.as_path(),
        bins: p.bins.clone(),
    });
    upgrade(nix, layout, project, cfg, cage.as_ref())
}

/// The two views `sbx upgrade tarball` needs of a project's declared `tarball:` references, collected
/// in one pass over the baseline and each app overlay (see [`declared`]).
struct Declared {
    /// Deterministic, deduplicated, **trusted-only** — the set to roll forward (baseline first,
    /// then apps by name), each in its declared form.
    trusted: Vec<TarballRef>,
    /// Every declared lock key **regardless of trust** — the universe the lock is pruned against, so
    /// an untrusted/Changed project's still-declared package keeps its pin instead of being unpinned.
    all: std::collections::BTreeSet<String>,
}

/// Collect both views in a single walk of the layers. Each app overlay is materialized once (a
/// `merge_app` clone), then contributes to both the trusted roll set and the trust-agnostic prune
/// universe — so `sbx upgrade` walks the apps once, not twice. Both `tarball:` forms are collected:
/// a direct URL keyed by its URL, a resolver package keyed by `resolve:<name>`.
fn declared(cfg: &crate::config::Resolved) -> Declared {
    let mut seen = std::collections::BTreeSet::new();
    let mut trusted = Vec::new();
    let mut all = std::collections::BTreeSet::new();
    let mut absorb = |pkgs: &[crate::config::Package]| {
        for (_, url) in super::packages::tarball_packages(pkgs) {
            if seen.insert(url.clone()) {
                trusted.push(TarballRef::Direct(url));
            }
        }
        for (name, command) in super::packages::tarball_resolve_packages(pkgs) {
            if seen.insert(resolve_key(&name)) {
                trusted.push(TarballRef::Resolve { name, command });
            }
        }
        for p in pkgs {
            match &p.backend {
                crate::config::Backend::Tarball(url) => {
                    all.insert(url.clone());
                }
                crate::config::Backend::TarballResolve { .. } => {
                    all.insert(resolve_key(&p.name));
                }
                _ => {}
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
                matches!(
                    p.backend,
                    crate::config::Backend::Tarball(_)
                        | crate::config::Backend::TarballResolve { .. }
                ) && p.state != crate::trust::TrustState::Trusted
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

    #[test]
    fn a_resolve_pin_round_trips_as_a_three_column_line() {
        let data = TmpDir::new();
        let layout = Layout::under(data.path());
        let id = "projr";
        // the lock key is `resolve:<name>`; the resolved url is the concrete versioned tarball, so
        // key != url and the pin needs the third column.
        let key = resolve_key("demo-app");
        let concrete = "https://cdn.example.com/app/2.1.1-6123990880747520/linux-x64/App.tar.gz";
        let mut lock = BTreeMap::new();
        lock.insert(
            key.clone(),
            TarballPin {
                hash: HASH.to_string(),
                url: concrete.to_string(),
            },
        );
        write_pins(&layout, id, &lock).expect("write the lock");

        let raw = std::fs::read_to_string(lock_path(&layout, id)).unwrap();
        assert!(
            raw.contains(&format!("{key}\t{HASH}\t{concrete}\n")),
            "a resolver pin keeps the three-column form (resolve:<name>, hash, resolved url):\n{raw}"
        );

        let read = pins(&layout, id);
        assert_eq!(read[&key].url, concrete);
        assert_eq!(read[&key].hash, HASH);
    }

    fn tarball_pkg(name: &str, url: &str, trusted: bool) -> crate::config::Package {
        crate::config::Package {
            name: name.into(),
            backend: crate::config::Backend::Tarball(url.into()),
            state: if trusted {
                crate::trust::TrustState::Trusted
            } else {
                crate::trust::TrustState::Untrusted
            },
        }
    }

    fn tarball_resolve_pkg(name: &str, command: &[&str], trusted: bool) -> crate::config::Package {
        crate::config::Package {
            name: name.into(),
            backend: crate::config::Backend::TarballResolve {
                command: command.iter().map(|s| s.to_string()).collect(),
            },
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
            tasks: vec![],
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
            tasks: vec![],
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
    fn tarball_declared_trusted_covers_both_forms_dedups_and_drops_untrusted() {
        let cfg = resolved(
            vec![
                tarball_pkg("a", "https://e/a.tar.gz", true),
                tarball_pkg("evil", "https://e/evil.tar.gz", false), // untrusted: dropped
                tarball_resolve_pkg("res", &["print-url"], true), // resolver form, key `resolve:res`
            ],
            vec![
                (
                    "alpha",
                    app_with(vec![
                        tarball_pkg("b", "https://e/b.tar.gz", true),
                        tarball_pkg("a2", "https://e/a.tar.gz", true), // duplicate url: deduped
                    ]),
                ),
                ("beta", app_with(vec![])), // no tarball package: contributes nothing
            ],
        );
        // Both `tarball:` forms are collected, baseline first (direct, then resolver), then the app's
        // new url; the duplicate and the untrusted one are gone.
        let keys: Vec<String> = declared(&cfg).trusted.iter().map(TarballRef::key).collect();
        assert_eq!(
            keys,
            vec![
                "https://e/a.tar.gz".to_string(),
                resolve_key("res"),
                "https://e/b.tar.gz".to_string(),
            ]
        );
    }

    #[test]
    fn tarball_prune_universe_keeps_untrusted_and_withheld_counts_both_forms() {
        let cfg = resolved(
            vec![
                tarball_pkg("a", "https://e/a.tar.gz", true),
                tarball_pkg("evil", "https://e/evil.tar.gz", false),
                tarball_resolve_pkg("badres", &["x"], false), // untrusted resolver
            ],
            vec![(
                "app",
                app_with(vec![tarball_pkg("c", "https://e/c.tar.gz", false)]),
            )],
        );
        // The prune universe keeps every declared key regardless of trust, so `sbx upgrade` on a
        // Changed project never unpins a still-declared package.
        let universe = declared(&cfg).all;
        assert!(universe.contains("https://e/a.tar.gz"));
        assert!(
            universe.contains("https://e/evil.tar.gz"),
            "a withheld-but-declared url must survive pruning"
        );
        assert!(universe.contains(&resolve_key("badres")));
        assert!(universe.contains("https://e/c.tar.gz"));
        // `withheld` counts every untrusted tarball package (both forms), across baseline and apps.
        assert_eq!(
            withheld(&cfg),
            3,
            "two untrusted baseline packages + one untrusted app package"
        );
    }

    #[test]
    fn has_resolve_ref_detects_a_declared_resolver_in_the_baseline_or_an_app() {
        let baseline = resolved(vec![tarball_resolve_pkg("r", &["print"], true)], vec![]);
        assert!(has_resolve_ref(&baseline));

        let direct_only = resolved(vec![tarball_pkg("d", "https://e/d.tar.gz", true)], vec![]);
        assert!(!has_resolve_ref(&direct_only));

        let in_app = resolved(
            vec![],
            vec![("a", app_with(vec![tarball_resolve_pkg("ar", &["p"], true)]))],
        );
        assert!(
            has_resolve_ref(&in_app),
            "a resolver declared only inside an app overlay is still detected"
        );
    }
}
