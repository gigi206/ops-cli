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
//! Two source forms (both trusted-only, like every `[packages]` backend):
//!   * `deb:<https url>` — a fixed `.deb` URL. A GitHub `…/releases/latest/download/<stable>.deb`
//!     URL already rolls forward via the redirect; a version-embedding URL does not.
//!   * `deb:github:<owner>/<repo>` — query the repo's latest release and select its linux `.deb`
//!     asset, so even a project whose asset name embeds the version rolls forward.
//!
//! Update model: pin-on-first-use. A launch resolves the source to a concrete `.deb` URL and its
//! content hash, records both in a per-project lock (`deb-packages.lock`), and later launches reuse
//! the pin offline — the launch hot path never touches GitHub. `ops upgrade` re-resolves each
//! declared source forward (re-querying GitHub for the `github:` form) and rewrites the lock.

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
    "libcap_ng",
    "libdrm",
    "libGL",
    "libnotify",
    "libseccomp",
    "libsecret",
    "libxkbcommon",
    "mesa",
    "musl",
    "ncurses",
    "nspr",
    "nss",
    "pango",
    "libx11",
    "libxcb",
    "libxcomposite",
    "libxdamage",
    "libxext",
    "libxfixes",
    "libxrandr",
    "libxshmfence",
];

/// A locked `deb:` package, keyed in the lock by its declared *locator* (the `.deb` URL, or a
/// `github:<owner>/<repo>`). `url` is the concrete `.deb` the pin resolved to (== the locator for a
/// direct URL, the selected release asset for a `github:` locator), and `hash` its SRI content hash
/// — so a warm launch fetches and builds the pinned asset offline without re-querying GitHub.
#[derive(Clone)]
pub(crate) struct DebPin {
    pub(crate) hash: String,
    pub(crate) url: String,
}

/// The two shapes a declared `deb:` locator can take, dispatched from its prefix.
enum DebSource {
    /// A direct `https://…/….deb` URL — resolved to itself.
    Url(String),
    /// `github:<owner>/<repo>` — resolved via the repo's latest release.
    Github { owner: String, repo: String },
}

/// Parse a declared locator (already validated by `config::parse_backend`) into its [`DebSource`].
fn parse_source(locator: &str) -> DebSource {
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
            if !key.is_empty() && is_sri(hash) {
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
/// the generated derivation. `fresh` bypasses the fetch cache (set on `ops upgrade`, so it sees a
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
                    deb_arch_label(system)
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
    };
    let hash = prefetch_hash(nix, layout, &url)?;
    Ok((url, hash))
}

/// Select the linux `.deb` asset URL matching `system` from a GitHub release's JSON. A `.deb` is a
/// Linux package by definition, so the discriminant is CPU architecture, not the OS: an asset whose
/// name names a *foreign* arch is dropped, then one positively naming this arch is chosen
/// (deterministic by name); a single unambiguous `.deb` with no arch token is the fallback for a
/// single-arch repo. Pure, so selection is testable against captured release JSON.
fn select_deb_asset(json: &serde_json::Value, system: &str) -> Option<String> {
    let (accept, reject) = arch_tokens(system);
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

/// The architecture name tokens for `system`: `(accepted, rejected)`. An asset whose lowercased
/// name contains an accepted token is a native build; one containing a rejected token is foreign.
fn arch_tokens(system: &str) -> (Vec<&'static str>, Vec<&'static str>) {
    let x86 = vec!["amd64", "x86_64", "x86-64", "x64"];
    let arm = vec!["arm64", "aarch64"];
    let other = vec![
        "armhf", "armv7", "armv7l", "i386", "i686", "riscv64", "ppc64", "s390x",
    ];
    if system.starts_with("aarch64") {
        (arm, [x86, other].concat())
    } else {
        (x86, [arm, other].concat())
    }
}

/// The Debian architecture label for `system`, for the "no matching asset" error message.
fn deb_arch_label(system: &str) -> &'static str {
    if system.starts_with("aarch64") {
        "arm64"
    } else {
        "amd64"
    }
}

/// Resolve a concrete `.deb` URL to its SRI content hash via `nix store prefetch-file`, which
/// follows redirects (so a `…/releases/latest/download/…` URL resolves to the current asset) and
/// adds the file to ops's store. Pure fetch — no code runs.
fn prefetch_hash(nix: &Path, layout: &Layout, url: &str) -> io::Result<String> {
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
            DebSource::Url(_) => panic!("github locator misparsed as a URL"),
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
