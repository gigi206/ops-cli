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

/// Write the per-project deb lock atomically (temp + rename), so a concurrent same-project launch
/// never observes a half-written file.
fn write_pins(
    layout: &Layout,
    project_id: &str,
    lock: &BTreeMap<String, DebPin>,
) -> io::Result<()> {
    let path = lock_path(layout, project_id);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
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
  unpackPhase = "dpkg-deb -x $src .";
  dontConfigure = true;
  dontBuild = true;
  installPhase = ''
    mkdir -p $out
    cp -r opt $out/ 2>/dev/null || true
    cp -r usr $out/ 2>/dev/null || true
    asar=$(find $out -type f -name app.asar -path '*/resources/*' | head -1)
    [ -n "$asar" ] || { echo "deb: no Electron resources/app.asar found in @NAME@" >&2; exit 1; }
    appdir=$(dirname "$(dirname "$asar")")
    main=$(find "$appdir" -maxdepth 1 -type f -executable \
      ! -name 'chrome-sandbox' ! -name 'chrome_crashpad_handler' \
      ! -name '*.so' ! -name '*.so.*' | head -1)
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
    let declared = declared_urls(cfg);
    let mut lock = pins(layout, project_id.as_str());
    let mut outcomes = Vec::new();

    // Prune entries whose URL is no longer declared (across ALL layers regardless of trust, so a
    // withheld project's still-declared package keeps its pin rather than being silently unpinned).
    let universe = all_declared_urls(cfg);
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

/// The deduplicated `deb:` URLs a project declares (trusted), across the baseline and each app —
/// the set `ops upgrade` rolls forward. Deterministic order (baseline first, then apps by name).
pub(crate) fn declared_urls(cfg: &crate::config::Resolved) -> Vec<String> {
    let mut seen = std::collections::BTreeSet::new();
    let mut urls = Vec::new();
    let mut push = |url: String| {
        if seen.insert(url.clone()) {
            urls.push(url);
        }
    };
    for (_, url) in super::packages::deb_packages(&cfg.packages) {
        push(url);
    }
    for app in cfg.apps.values() {
        let mut merged = cfg.clone();
        merged.merge_app(app.clone());
        for (_, url) in super::packages::deb_packages(&merged.packages) {
            push(url);
        }
    }
    urls
}

/// Every declared `deb:` URL across all layers regardless of trust — the universe `ops upgrade`
/// prunes the lock against (so an untrusted project's still-declared package is not unpinned).
fn all_declared_urls(cfg: &crate::config::Resolved) -> std::collections::BTreeSet<String> {
    let mut set = std::collections::BTreeSet::new();
    let mut collect = |pkgs: &[crate::config::Package]| {
        for p in pkgs {
            if let crate::config::Backend::Deb(url) = &p.backend {
                set.insert(url.clone());
            }
        }
    };
    collect(&cfg.packages);
    for app in cfg.apps.values() {
        let mut merged = cfg.clone();
        merged.merge_app(app.clone());
        collect(&merged.packages);
    }
    set
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
        assert!(expr.contains("dpkg-deb -x $src ."));
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
}
