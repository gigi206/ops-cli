//! `deb:` packages — a prebuilt Debian package (`.deb`) provisioned host-side.
//!
//! For a GUI/desktop app distributed only as a `.deb` (no runnable release binary, no nixpkgs
//! attribute, and — for opencode-desktop — an official flake whose from-source build is broken by a
//! bun-version mismatch), ops packages the prebuilt `.deb` directly: resolve the URL to a content
//! hash, then build a generated derivation that `dpkg-deb -x`-unpacks it and `autoPatchelfHook`s the
//! ELF binaries against a curated Electron/Chromium library set. **No build script runs**
//! (`dontBuild`), so — unlike an arbitrary `flake:` — evaluating and building it host-side is safe;
//! it is therefore provisioned like `nix:` (into ops's store, seeded, offline-reusable) rather than
//! in-cage.
//!
//! Update model: pin-on-first-use. A launch resolves the URL to a hash and records it in a
//! per-project lock (`deb-packages.lock`), so later launches reuse the pinned hash offline; a
//! GitHub `…/releases/latest/download/…` URL means the *first* resolve tracks upstream, and
//! `ops upgrade` re-resolves it forward. Trusted-only, like every `[packages]` backend.

use crate::store::{self, Layout};
use std::collections::BTreeMap;
use std::io;
use std::path::{Path, PathBuf};
use std::process::Stdio;

const DEB_LOCK: &str = "deb-packages.lock";

/// The Electron/Chromium runtime library set the generated derivation autoPatchelfs a desktop
/// `.deb` against — nixpkgs attribute paths, grounded on a working Electron app's dependency set.
/// `musl` satisfies the musl-variant native node addons that ship beside the glibc ones; the
/// derivation additionally ignores the musl *loader* reference (see [`derivation_expr`]).
const ELECTRON_LIBS: &[&str] = &[
    "alsa-lib",
    "at-spi2-atk",
    "at-spi2-core",
    "atk",
    "cairo",
    "cups",
    "dbus",
    "expat",
    "gdk-pixbuf",
    "glib",
    "gtk3",
    "libdrm",
    "libGL",
    "libnotify",
    "libsecret",
    "libxkbcommon",
    "mesa",
    "musl",
    "nspr",
    "nss",
    "pango",
    "xorg.libX11",
    "xorg.libxcb",
    "xorg.libXcomposite",
    "xorg.libXdamage",
    "xorg.libXext",
    "xorg.libXfixes",
    "xorg.libXrandr",
    "xorg.libxshmfence",
];

/// A locked `deb:` package: the SRI content hash the URL resolved to. Keyed by the declared URL.
#[derive(Clone)]
pub(crate) struct DebPin {
    pub(crate) hash: String,
}

/// The outcome of re-resolving one declared `deb:` reference during `ops upgrade`.
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

/// An SRI SHA-256 hash string as `nix store prefetch-file` emits (`sha256-<base64>`).
fn is_sri(s: &str) -> bool {
    s.strip_prefix("sha256-").is_some_and(|b| {
        !b.is_empty()
            && b.chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '/' | '='))
    })
}

fn lock_path(layout: &Layout, project_id: &str) -> PathBuf {
    layout
        .data_dir()
        .join("projects")
        .join(project_id)
        .join(DEB_LOCK)
}

/// Read the per-project deb lock (`url\thash` per line). A corrupt line self-heals by being dropped;
/// an absent lock is an empty map (the unpinned state).
pub(crate) fn pins(layout: &Layout, project_id: &str) -> BTreeMap<String, DebPin> {
    let mut map = BTreeMap::new();
    let Ok(text) = std::fs::read_to_string(lock_path(layout, project_id)) else {
        return map;
    };
    for line in text.lines() {
        let mut it = line.splitn(2, '\t');
        if let (Some(url), Some(hash)) = (it.next(), it.next()) {
            if !url.is_empty() && is_sri(hash) {
                map.insert(
                    url.to_string(),
                    DebPin {
                        hash: hash.to_string(),
                    },
                );
            }
        }
    }
    map
}

/// The pinned content hashes for a project's `deb:` packages, keyed by the declared URL (a
/// package's locator, so `ops config` can look each up directly), shortened for display. Reads
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
    for (url, pin) in lock {
        body.push_str(&format!("{url}\t{}\n", pin.hash));
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

/// Resolve a `.deb` URL to its SRI content hash via `nix store prefetch-file`, which follows
/// redirects (so a `…/releases/latest/download/…` URL resolves to the current asset) and adds the
/// file to ops's store. Pure fetch — no code runs.
pub(crate) fn resolve(nix: &Path, layout: &Layout, url: &str) -> io::Result<String> {
    let mut cmd = store::nix_command(nix, layout);
    cmd.args(["--extra-experimental-features", "nix-command flakes"])
        .args(["store", "prefetch-file", "--json"])
        .arg(url)
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit());
    let out = cmd.spawn()?.wait_with_output()?;
    if !out.status.success() {
        return Err(io::Error::other(format!(
            "nix store prefetch-file {url} failed"
        )));
    }
    let v: serde_json::Value = serde_json::from_slice(&out.stdout)
        .map_err(|e| io::Error::other(format!("prefetch-file returned invalid JSON: {e}")))?;
    let hash = v
        .get("hash")
        .and_then(|h| h.as_str())
        .ok_or_else(|| io::Error::other("prefetch-file JSON has no `hash`"))?;
    if !is_sri(hash) {
        return Err(io::Error::other(format!(
            "prefetch-file returned a non-SRI hash: {hash}"
        )));
    }
    Ok(hash.to_string())
}

/// The generated nix expression building one `deb:` package: fetch the pinned `.deb`, unpack it, and
/// autoPatchelf it against [`ELECTRON_LIBS`] from the pinned `nixpkgs`. The install phase is generic
/// for an Electron layout — it locates the app directory by its `resources/app.asar` signature and
/// wraps the app's own launcher (the executable beside it that is not a `.so` or a Chromium helper),
/// so no per-app path is hardcoded. Every interpolated value is ops-controlled and charset-validated
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
  unpackPhase = "dpkg-deb -x $src extracted";
  dontConfigure = true;
  dontBuild = true;
  installPhase = ''
    mkdir -p $out
    cp -r extracted/. "$out"
    asar=$(find $out -type f -name app.asar -path '*/resources/*' | sort | head -1)
    [ -n "$asar" ] || { echo "deb: no Electron resources/app.asar found in @NAME@" >&2; exit 1; }
    appdir=$(dirname "$(dirname "$asar")")
    main=$(find "$appdir" -maxdepth 1 -type f -executable \
      ! -name 'chrome-sandbox' ! -name 'chrome_crashpad_handler' \
      ! -name '*.so' ! -name '*.so.*' | sort | head -1)
    [ -n "$main" ] || { echo "deb: no launcher binary found in $appdir" >&2; exit 1; }
    mkdir -p $out/bin
    makeWrapper "$main" "$out/bin/@NAME@" \
      --prefix LD_LIBRARY_PATH : "${pkgs.lib.makeLibraryPath finalAttrs.buildInputs}"
  '';
  meta.mainProgram = "@NAME@";
})
"#;
    TEMPLATE
        .replace("@NIXPKGS@", nixpkgs)
        .replace("@SYSTEM@", system)
        .replace("@LIBS@", &ELECTRON_LIBS.join(" "))
        .replace("@URL@", url)
        .replace("@HASH@", hash)
        .replace("@NAME@", name)
}

/// Provision one `deb:` package host-side: resolve the URL to a hash (pinning it on first use),
/// build the generated derivation into ops's store, and return `(bin directory, store root)` — the
/// bin dir to prepend to the sandbox `PATH`, the root whose closure the project store seeds. Mirrors
/// [`super::packages::provision`]'s per-package gcroot, name-keyed under the project.
pub(crate) fn provision(
    nix: &Path,
    layout: &Layout,
    project: &Path,
    nixpkgs: &str,
    name: &str,
    url: &str,
) -> io::Result<(PathBuf, PathBuf)> {
    let project_id = super::binds::project_runtime_id(project)?;
    let mut lock = pins(layout, project_id.as_str());
    let hash = match lock.get(url) {
        Some(pin) => pin.hash.clone(),
        None => {
            let h = resolve(nix, layout, url)?;
            lock.insert(url.to_string(), DebPin { hash: h.clone() });
            write_pins(layout, project_id.as_str(), &lock)?;
            h
        }
    };
    let system = super::current_system();
    let expr = derivation_expr(nixpkgs, &system, name, url, &hash);
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
    let mut lock = pins(layout, project_id.as_str());
    let mut outcomes = Vec::new();

    // Prune entries whose URL is no longer declared (across ALL layers regardless of trust, so a
    // withheld project's still-declared package keeps its pin rather than being silently unpinned).
    let stale: Vec<String> = lock
        .keys()
        .filter(|k| !universe.contains(k.as_str()))
        .cloned()
        .collect();
    for url in stale {
        lock.remove(&url);
        outcomes.push(DebUpgrade::Pruned { url });
    }

    for url in &declared {
        let previous = lock.get(url).map(|p| p.hash.clone());
        match resolve(nix, layout, url) {
            Ok(hash) => {
                let outcome = match &previous {
                    Some(old) if old == &hash => DebUpgrade::Unchanged {
                        url: url.clone(),
                        hash: hash.clone(),
                    },
                    Some(old) => DebUpgrade::Rolled {
                        url: url.clone(),
                        from: old.clone(),
                        to: hash.clone(),
                    },
                    None => DebUpgrade::Pinned {
                        url: url.clone(),
                        hash: hash.clone(),
                    },
                };
                lock.insert(url.clone(), DebPin { hash });
                outcomes.push(outcome);
            }
            Err(e) => outcomes.push(DebUpgrade::Failed {
                url: url.clone(),
                error: e.to_string(),
            }),
        }
    }

    write_pins(layout, project_id.as_str(), &lock)?;
    Ok(outcomes)
}

/// The two views `ops upgrade deb` needs of a project's declared `deb:` URLs, collected in one pass
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
/// universe — so `ops upgrade` walks the apps once, not twice.
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
/// each app. A count only (the per-package reason is warned on the launch path), so `ops upgrade`
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
    fn is_sri_accepts_prefetch_output_and_rejects_junk() {
        assert!(is_sri(HASH));
        assert!(!is_sri("jBGtMS5l"));
        assert!(!is_sri("sha256-"));
        assert!(!is_sri("md5-abc"));
    }

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
        // unpack-only, no build script (safe host-side); the Electron lib set is present
        assert!(expr.contains("dpkg-deb -x $src extracted"));
        assert!(expr.contains("dontBuild = true;"));
        assert!(expr.contains("nss") && expr.contains("gtk3") && expr.contains("xorg.libX11"));
        // generic Electron install: find the app by its app.asar, wrap the launcher as bin/<name>
        assert!(expr.contains("resources/"));
        assert!(expr.contains("app.asar"));
        assert!(expr.contains("$out/bin/opencode-desktop"));
        assert!(expr.contains("meta.mainProgram = \"opencode-desktop\";"));
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
            "https://example.com/a.deb".to_string(),
            DebPin {
                hash: HASH.to_string(),
            },
        );
        write_pins(&layout, id, &lock).expect("write the lock");

        let read = pins(&layout, id);
        assert_eq!(read.len(), 1);
        assert_eq!(read["https://example.com/a.deb"].hash, HASH);

        // a corrupt (non-SRI) line is dropped, not surfaced
        std::fs::write(
            lock_path(&layout, id),
            format!("https://example.com/a.deb\t{HASH}\nhttps://bad.example/b.deb\tnot-a-hash\n"),
        )
        .unwrap();
        let read = pins(&layout, id);
        assert_eq!(read.len(), 1, "the corrupt line must self-heal (drop)");
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
            limits: Default::default(),
            forward: vec![],
            secrets: vec![],
            default_methods: crate::allowlist::Methods::Unspecified,
            cmd_origin: Default::default(),
            network_origin: Default::default(),
            gui_origin: Default::default(),
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
        // untrusted — else `ops upgrade deb` on a Changed project unpins it. Unlike the trusted roll
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
}
