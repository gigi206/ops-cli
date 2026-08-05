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
use super::resolve::ResolveCage;
use crate::config::is_valid_tarball_url;
use crate::store::Layout;
use std::collections::BTreeMap;
use std::io;
use std::path::{Path, PathBuf};

/// A locked `tarball:` package, keyed in the lock by its declared *locator* — the `.tar.gz` URL for
/// a direct package, or `resolve:<name>` for a `tarball:resolve` package, whose `url` is then the
/// command-resolved download URL. See [`prebuilt::Pin`].
#[cfg(test)]
type TarballPin = prebuilt::Pin;

/// The outcome of re-resolving one declared `tarball:` reference during `sbx upgrade`.
/// See [`prebuilt::Upgrade`].
pub(crate) type TarballUpgrade = prebuilt::Upgrade;

/// Where this backend's lock lives. Production reads and writes it through [`prebuilt`]; this names
/// the same path for the tests that assert the on-disk format.
#[cfg(test)]
fn lock_path(layout: &Layout, project_id: &str) -> PathBuf {
    prebuilt::lock_path(layout, project_id, &prebuilt::lock_file(&Tarball))
}

/// Read the per-project tarball lock. A three-column line is a `tarball:resolve` pin
/// (`resolve:<name>` key, hash, the command-resolved URL); see [`prebuilt::pins`] for the format.
#[cfg(test)]
fn pins(layout: &Layout, project_id: &str) -> BTreeMap<String, TarballPin> {
    prebuilt::pins(layout, project_id, &prebuilt::lock_file(&Tarball))
}

/// The pinned content hashes for a project's `tarball:` packages, keyed by the declared locator.
/// See [`prebuilt::pinned_hashes`].
pub(crate) fn pinned_hashes(cwd: &Path) -> BTreeMap<String, String> {
    prebuilt::pinned_hashes(cwd, &prebuilt::lock_file(&Tarball))
}

/// Write the per-project tarball lock atomically, for the tests that assert the on-disk
/// format. Production writes it through [`prebuilt::upgrade`].
#[cfg(test)]
fn write_pins(
    layout: &Layout,
    project_id: &str,
    lock: &BTreeMap<String, TarballPin>,
) -> io::Result<()> {
    prebuilt::write_pins(layout, project_id, &prebuilt::lock_file(&Tarball), lock)
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

/// The `tarball:` backend — the two decisions [`prebuilt::Kind`] leaves to it are its locator form (a
/// direct URL, always its own download URL) and a plain `tar -xz` unpack. It is the plainest of the
/// three, so it takes no `system`: a `.tar.gz` locator names one artefact, with no asset to select.
pub(crate) struct Tarball;

impl prebuilt::Kind for Tarball {
    fn name(&self) -> &'static str {
        "tarball"
    }

    fn artefact(&self) -> &'static str {
        "`.tar.gz`"
    }

    fn url_validator(&self) -> fn(&str) -> bool {
        is_valid_tarball_url
    }

    fn resolve_source(
        &self,
        nix: &Path,
        layout: &Layout,
        locator: &str,
        _system: &str,
        fresh: bool,
    ) -> io::Result<(String, String)> {
        resolve_source(nix, layout, locator, fresh)
    }

    fn derivation_expr(
        &self,
        nixpkgs: &str,
        system: &str,
        name: &str,
        url: &str,
        hash: &str,
    ) -> String {
        derivation_expr(nixpkgs, system, name, url, hash)
    }

    fn packages(&self, packages: &[crate::config::Package]) -> Vec<(String, String)> {
        super::packages::tarball_packages(packages)
    }

    fn resolve_packages(&self, packages: &[crate::config::Package]) -> Vec<(String, Vec<String>)> {
        super::packages::tarball_resolve_packages(packages)
    }

    fn lock_key(&self, package: &crate::config::Package) -> Option<String> {
        match &package.backend {
            crate::config::Backend::Tarball(url) => Some(url.clone()),
            crate::config::Backend::TarballResolve { .. } => {
                Some(prebuilt::resolve_key(&package.name))
            }
            _ => None,
        }
    }
}

/// The context a `tarball:` provisioning call runs in. See [`prebuilt::Ctx`].
fn ctx<'a>(
    nix: &'a Path,
    layout: &'a Layout,
    project: &'a Path,
    nixpkgs: &'a str,
) -> prebuilt::Ctx<'a> {
    prebuilt::Ctx {
        nix,
        layout,
        project,
        nixpkgs,
    }
}

/// Provision one `tarball:` package host-side. See [`prebuilt::provision`].
pub(crate) fn provision(
    nix: &Path,
    layout: &Layout,
    project: &Path,
    nixpkgs: &str,
    name: &str,
    locator: &str,
) -> io::Result<(PathBuf, PathBuf)> {
    prebuilt::provision(&Tarball, &ctx(nix, layout, project, nixpkgs), name, locator)
}

/// Provision one `tarball:resolve` package host-side. See [`prebuilt::provision_resolve`].
pub(crate) fn provision_resolve(
    nix: &Path,
    layout: &Layout,
    project: &Path,
    nixpkgs: &str,
    name: &str,
    command: &[String],
    cage: &ResolveCage,
) -> io::Result<(PathBuf, PathBuf)> {
    prebuilt::provision_resolve(
        &Tarball,
        &ctx(nix, layout, project, nixpkgs),
        name,
        command,
        cage,
    )
}

/// Build a `tarball:resolve` package from its existing pin only, for the gc keep path. See
/// [`prebuilt::provision_resolve_pinned`].
pub(crate) fn provision_resolve_pinned(
    nix: &Path,
    layout: &Layout,
    project: &Path,
    nixpkgs: &str,
    name: &str,
) -> io::Result<Option<(PathBuf, PathBuf)>> {
    prebuilt::provision_resolve_pinned(&Tarball, &ctx(nix, layout, project, nixpkgs), name)
}

/// `sbx upgrade tarball`: roll a project's declared `tarball:` packages forward. See
/// [`prebuilt::upgrade_project`].
pub(crate) fn upgrade_project(
    nix: &Path,
    layout: &Layout,
    project: &Path,
    cfg: &crate::config::Resolved,
) -> io::Result<Vec<TarballUpgrade>> {
    prebuilt::upgrade_project(&Tarball, nix, layout, project, cfg)
}

/// How many declared `tarball:` packages are withheld for being untrusted. See
/// [`prebuilt::withheld`].
pub(crate) fn withheld(cfg: &crate::config::Resolved) -> usize {
    prebuilt::withheld(&Tarball, cfg)
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
        let key = prebuilt::resolve_key("demo-app");
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
            fs: Default::default(),
            fs_origin: crate::config::Provenance::Default,
            notify: None,
            notify_origin: Default::default(),
            ssh_agent_confirm: false,
            ssh_agent_origin: Default::default(),
            ssh_agent: Vec::new(),
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
            fs: Default::default(),
            fs_origin: crate::config::Provenance::Default,
            notify: Default::default(),
            notify_origin: Default::default(),
            ssh_agent_confirm: false,
            env: vec![],
            env_layer: Default::default(),
            binds: vec![],
            bind_layer: Default::default(),
            packages,
            nixpkgs_global: None,
            nixpkgs_project: None,
            mise: None,
            network: crate::config::NetworkPolicy::Shared,
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
            ssh_agent: vec![],
            ssh_agent_origin: Default::default(),
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
        let keys: Vec<String> = prebuilt::declared(&Tarball, &cfg)
            .trusted
            .iter()
            .map(prebuilt::Ref::key)
            .collect();
        assert_eq!(
            keys,
            vec![
                "https://e/a.tar.gz".to_string(),
                prebuilt::resolve_key("res"),
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
        let universe = prebuilt::declared(&Tarball, &cfg).all;
        assert!(universe.contains("https://e/a.tar.gz"));
        assert!(
            universe.contains("https://e/evil.tar.gz"),
            "a withheld-but-declared url must survive pruning"
        );
        assert!(universe.contains(&prebuilt::resolve_key("badres")));
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
        assert!(prebuilt::has_resolve_ref(&Tarball, &baseline));

        let direct_only = resolved(vec![tarball_pkg("d", "https://e/d.tar.gz", true)], vec![]);
        assert!(!prebuilt::has_resolve_ref(&Tarball, &direct_only));

        let in_app = resolved(
            vec![],
            vec![("a", app_with(vec![tarball_resolve_pkg("ar", &["p"], true)]))],
        );
        assert!(
            prebuilt::has_resolve_ref(&Tarball, &in_app),
            "a resolver declared only inside an app overlay is still detected"
        );
    }
}
