//! Shared building blocks for the "prebuilt host-side package" backends — `deb:`, `appimage:` and
//! `tarball:`. Each fetches a prebuilt bundle from an `https://` source, unpacks it (no build script
//! runs — safe to evaluate host-side, unlike an arbitrary `flake:`), autoPatchelfs the ELF binaries
//! against a curated library set, and wraps the launcher located by its `resources/app.asar`
//! signature. Only two decisions are a backend's own: *where the artefact comes from* (its locator
//! forms) and *how it is unpacked* (a `dpkg-deb` data tarball, an AppImage squashfs, a plain
//! `.tar.gz`). Everything else — the library set, the app-locating/launcher-wrapping install phase,
//! the fetch-to-hash helper, the release-asset arch tokens, and the per-project pin lock — lives
//! here so the backends cannot silently diverge.
//!
//! **Why unpack at BUILD time, never at runtime.** `wrapType2`, `appimage-run`, and running the raw
//! `.AppImage` all create a mount/user namespace at runtime (a `bwrap` or a FUSE self-mount). The
//! cage's seccomp denylist EPERMs `unshare`/`mount`/`pivot_root` and arg-filters
//! `clone(CLONE_NEWUSER|CLONE_NEWNS)`, and the FUSE mount is blocked too — so every runtime-namespace
//! approach is a hard block in-cage, not merely inelegant. Build-time extraction (`unsquashfs` /
//! `dpkg-deb`, no runtime namespace op) plus a plain autoPatchelf'd ELF is the only mechanism that
//! runs inside the cage, which is exactly why the `.deb` approach ports to the AppImage.

use crate::store::{self, Layout};
use std::collections::BTreeMap;
use std::io;
use std::path::{Path, PathBuf};
use std::process::Stdio;

/// The Electron/Chromium runtime library set the generated derivations autoPatchelf a desktop bundle
/// against — nixpkgs attribute paths, grounded on a working Electron app's dependency set. `musl`
/// satisfies the musl-variant native node addons that ship beside the glibc ones; each derivation
/// additionally ignores the musl *loader* reference (and, for an AppImage, the bundled legacy
/// tray/indicator shims — see [`super::appimage`]).
pub(crate) const ELECTRON_LIBS: &[&str] = &[
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
    "libxkbfile",
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

/// The generic install phase (a shell snippet), embedded by each backend's generated derivation into
/// its `installPhase` after the archive has been copied into `$out`. It finds the program to wrap in
/// two passes, and the order matters: the **bundle** shape first, the **bare-binary** shape only when
/// there is no bundle.
///
/// A bundle is located by its `resources/` signature — either a packed `resources/app.asar` file or,
/// for an asar-less build (some modern VS Code forks ship the app as a loose `resources/app/`
/// directory), the `resources/app` directory itself; both resolve to the same bundle root. The
/// launcher is then the executable beside it that is not a `.so`, a Chromium helper, or the AppImage
/// `AppRun` script. Excluding `AppRun` is load-bearing for an AppImage (its squashfs carries an
/// `AppRun` launcher that sorts *before* the real binary) and harmless for a `.deb` (which has no
/// `AppRun`), so one snippet serves both.
///
/// The fallback covers the plainest shape a vendor ships: an archive whose root holds one executable
/// and nothing else to choose from — a self-contained CLI rather than a desktop bundle. It applies
/// the *same* exclusions, and requires **exactly one** candidate: two would be an ambiguity, and
/// picking the first of them is how a build silently wraps the wrong program. The search is
/// deliberately `-maxdepth 1`, so an archive that unpacks into a versioned sub-directory fails here
/// with a message naming what it found rather than reaching in and guessing.
///
/// Two placeholders: `@NAME@` (the wrapped launcher name — the `[packages]` key, which is also the
/// derivation's `meta.mainProgram`, so the command a profile writes is that key) and `@LDPREFIX@`
/// (the `LD_LIBRARY_PATH` prefix value — a backend chooses whether to prepend the bundle root for
/// sibling `.so`s).
pub(crate) const LAUNCHER_WRAP: &str = r#"    app=$(find $out -type f -path '*/resources/app.asar' | sort | head -1)
    [ -n "$app" ] || app=$(find $out -type d -path '*/resources/app' | sort | head -1)
    if [ -n "$app" ]; then
      appdir=$(dirname "$(dirname "$app")")
      main=$(find "$appdir" -maxdepth 1 -type f -executable \
        ! -name 'AppRun' ! -name 'chrome-sandbox' ! -name 'chrome_crashpad_handler' \
        ! -name '*.so' ! -name '*.so.*' | sort | head -1)
      [ -n "$main" ] || { echo "@NAME@: no launcher binary found in $appdir" >&2; exit 1; }
    else
      cands=$(find $out -maxdepth 1 -type f -executable \
        ! -name 'AppRun' ! -name 'chrome-sandbox' ! -name 'chrome_crashpad_handler' \
        ! -name '*.so' ! -name '*.so.*' | sort)
      [ -n "$cands" ] || { echo "@NAME@: no Electron resources/app(.asar), and no executable at the archive root" >&2; exit 1; }
      count=$(printf '%s\n' "$cands" | wc -l)
      [ "$count" -eq 1 ] || { echo "@NAME@: no Electron resources/app(.asar), and $count executables at the archive root (need exactly 1):" >&2; printf '%s\n' "$cands" >&2; exit 1; }
      main=$cands
    fi
    mkdir -p $out/bin
    makeWrapper "$main" "$out/bin/@NAME@" \
      --prefix LD_LIBRARY_PATH : "@LDPREFIX@""#;

/// Fill [`LAUNCHER_WRAP`]'s two placeholders. `ld_prefix` is the `LD_LIBRARY_PATH` prefix value: a
/// `.deb` passes just the `makeLibraryPath` of its `buildInputs`; an AppImage prepends `$out` (its
/// bundle root holds the Chromium sibling `.so`s — `libEGL.so`, `libffmpeg.so`, …).
pub(crate) fn launcher_wrap(name: &str, ld_prefix: &str) -> String {
    LAUNCHER_WRAP
        .replace("@NAME@", name)
        .replace("@LDPREFIX@", ld_prefix)
}

/// An SRI SHA-256 hash string as `nix store prefetch-file` emits (`sha256-<base64>`).
pub(crate) fn is_sri(s: &str) -> bool {
    s.strip_prefix("sha256-").is_some_and(|b| {
        !b.is_empty()
            && b.chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '/' | '='))
    })
}

/// A locked prebuilt package, keyed in its backend's lock by the declared *locator*. `url` is the
/// concrete artefact the pin resolved to — equal to the key when the locator already IS the download
/// URL, and the separately resolved asset otherwise (a `github:` release asset, an `apt:` index
/// selection, a `resolve:` command's output) — and `hash` its SRI content hash. Together they let a
/// warm launch fetch and build the pinned artefact offline, without re-querying the source.
#[derive(Clone)]
pub(crate) struct Pin {
    pub(crate) hash: String,
    pub(crate) url: String,
}

/// One backend's per-project lock file, named by `lock_file` (`deb-packages.lock`,
/// `tarball-packages.lock`, …). A file per backend keeps their key spaces disjoint, so the same
/// URL declared under two backends pins independently.
pub(crate) fn lock_path(layout: &Layout, project_id: &str, lock_file: &str) -> PathBuf {
    layout
        .data_dir()
        .join("projects")
        .join(project_id)
        .join(lock_file)
}

/// Read one backend's per-project lock. Each line is `key\thash` or `key\thash\turl`: a two-column
/// line (the locator IS its resolved URL, and the legacy format) takes the key as that URL; a
/// three-column line carries the separately resolved URL. A corrupt line self-heals by being
/// dropped; an absent lock is an empty map — the unpinned state.
pub(crate) fn pins(layout: &Layout, project_id: &str, lock_file: &str) -> BTreeMap<String, Pin> {
    let mut map = BTreeMap::new();
    let Ok(text) = std::fs::read_to_string(lock_path(layout, project_id, lock_file)) else {
        return map;
    };
    for line in text.lines() {
        let mut it = line.splitn(3, '\t');
        if let (Some(key), Some(hash)) = (it.next(), it.next()) {
            if !key.is_empty() && is_sri(hash) {
                let url = it.next().filter(|u| !u.is_empty()).unwrap_or(key);
                map.insert(
                    key.to_string(),
                    Pin {
                        hash: hash.to_string(),
                        url: url.to_string(),
                    },
                );
            }
        }
    }
    map
}

/// Write one backend's per-project lock atomically (temp + rename), so a concurrent same-project
/// launch never observes a half-written file.
pub(crate) fn write_pins(
    layout: &Layout,
    project_id: &str,
    lock_file: &str,
    lock: &BTreeMap<String, Pin>,
) -> io::Result<()> {
    let path = lock_path(layout, project_id, lock_file);
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
        // A pin whose locator is its own download URL keeps the compact two-column form,
        // byte-identical to the legacy lock; one whose resolved URL differs from its key needs the
        // third column.
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

/// The pinned content hashes for a project's packages under one backend, keyed by the declared
/// locator (so `sbx config` can look each up directly) and shortened for display. Reads only the
/// per-project lock — surfaces a pin without resolving or building — so the config view stays
/// side-effect-free, exactly like [`super::flake::pinned_revs`].
pub(crate) fn pinned_hashes(cwd: &Path, lock_file: &str) -> BTreeMap<String, String> {
    let Some(layout) = Layout::from_env() else {
        return BTreeMap::new();
    };
    let Ok(id) = super::binds::project_runtime_id(cwd) else {
        return BTreeMap::new();
    };
    pins(&layout, &id, lock_file)
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

/// A nix store-path name derived from a URL's last path segment, sanitized to the store's legal
/// name set (`[A-Za-z0-9+._?=-]`, every other byte → `-`). `nix store prefetch-file` otherwise
/// derives the store name from the URL and **percent-decodes** it — so a vendor filename carrying an
/// encoded space (`My%20App.tar.gz` → `My App.tar.gz`) yields an illegal store name (a space) and the
/// prefetch fails. The name is cosmetic (only labels the fetched store
/// entry; the returned hash is content-addressed and the generated derivation re-fetches by hash), so
/// a lossy sanitization is safe; an empty segment falls back to `source`.
pub(crate) fn prefetch_name(url: &str) -> String {
    let base = url.rsplit('/').next().unwrap_or("").trim();
    let name: String = base
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '+' | '.' | '_' | '?' | '=' | '-') {
                c
            } else {
                '-'
            }
        })
        .collect();
    let trimmed = name.trim_matches('-');
    if trimmed.is_empty() {
        "source".to_string()
    } else {
        trimmed.to_string()
    }
}

/// Resolve a concrete `https://` URL to its SRI content hash via `nix store prefetch-file`, which
/// follows redirects (so a `…/releases/latest/download/…` URL resolves to the current asset) and
/// adds the file to sbx's store. An explicit `--name` is passed so a URL whose last segment
/// percent-decodes to an illegal store name (e.g. an encoded space) still resolves — see
/// [`prefetch_name`]. Pure fetch — no code runs.
///
/// `quiet` governs nix's own download output. A first launch (`quiet = false`) downloads the
/// asset — often a large `.deb` — so nix's progress is streamed live (`stderr` inherited) as
/// feedback. An `sbx upgrade` re-resolve (`quiet = true`) instead **captures** stderr and folds
/// the real failure cause into the returned error, so the summary reads `re-resolve failed —
/// <cause>` in place, rather than nix's multi-line retry warnings spilling out of order above the
/// section header.
pub(crate) fn prefetch_hash(
    nix: &Path,
    layout: &Layout,
    url: &str,
    quiet: bool,
) -> io::Result<String> {
    let mut cmd = store::nix_command(nix, layout);
    cmd.args(["--extra-experimental-features", "nix-command flakes"])
        .args(["store", "prefetch-file", "--json"])
        .args(["--name", &prefetch_name(url)])
        .arg(url)
        .stdout(Stdio::piped())
        .stderr(if quiet {
            Stdio::piped()
        } else {
            Stdio::inherit()
        });
    let out = cmd.spawn()?.wait_with_output()?;
    if !out.status.success() {
        // On the quiet path (an `sbx upgrade` re-resolve) stderr was captured and the summary
        // already frames the line with `re-resolve failed — `, so the returned error is the folded
        // cause alone. On the live path stderr has streamed to the terminal, so the bare step name
        // is the right context for the launch failure that bubbles up.
        if quiet {
            let cause = fold_prefetch_cause(&String::from_utf8_lossy(&out.stderr));
            return Err(io::Error::other(if cause.is_empty() {
                "nix store prefetch-file failed".to_string()
            } else {
                cause
            }));
        }
        return Err(io::Error::other("nix store prefetch-file failed"));
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

/// Reduce nix's captured prefetch stderr to a single actionable cause for the summary line. nix
/// emits one `error:` line at the end of a failed download (after any retry `warning:` lines), so
/// the last `error:` line — with its prefix stripped — is the real reason (`unable to download
/// '…': Could not resolve host: github.com`). Falls back to the whole trimmed stderr when there is
/// no `error:` line, and to the empty string when there is nothing at all. Pure, so it is unit-tested
/// against real nix output without invoking nix.
fn fold_prefetch_cause(stderr: &str) -> String {
    stderr
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .rev()
        .find_map(|l| l.strip_prefix("error:").map(|r| r.trim().to_string()))
        .unwrap_or_else(|| stderr.trim().to_string())
}

/// The architecture name tokens for `system`: `(accepted, rejected)`. A release asset whose lowercased
/// name contains an accepted token is a native build; one containing a rejected token is foreign. Used
/// to pick the linux `.deb`/`.AppImage` asset for this host from a GitHub release's asset set.
pub(crate) fn arch_tokens(system: &str) -> (Vec<&'static str>, Vec<&'static str>) {
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

/// A human-readable architecture label for `system`, for a "no matching asset" error message.
pub(crate) fn arch_label(system: &str) -> &'static str {
    if system.starts_with("aarch64") {
        "arm64"
    } else {
        "amd64"
    }
}

/// One prebuilt host-side package backend: `deb:`, `appimage:` or `tarball:`. The three share their
/// whole lifecycle — pin the source on first use, build offline from that pin ever after, one gcroot
/// per package — and differ only in where the artefact comes from and how the generated derivation
/// unpacks it. Implementing this on a unit struct per backend is what lets that lifecycle be written
/// once below rather than three times, so the three cannot silently drift apart.
pub(crate) trait Kind {
    /// `deb` / `appimage` / `tarball`. **On-disk state, not a label**: it spells this backend's
    /// per-project lock (`<name>-packages.lock`) and every package's gcroot (`<name>-<package>`), so
    /// renaming it strands every existing pin and every existing gcroot. [`super::packages`] and
    /// [`super::inspect`] spell the same two strings out independently, which is why a test pins them.
    fn name(&self) -> &'static str;

    /// How this backend's artefact is named when a resolve command's output is refused — `` `.deb` ``,
    /// `` `.AppImage` ``, `` `.tar.gz` ``. See [`super::resolve::resolve_url`].
    fn artefact(&self) -> &'static str;

    /// The charset barrier a resolve command's URL must pass before sbx fetches it or interpolates it
    /// into a generated derivation, so an arbitrary command cannot point sbx at a non-`https` or
    /// injecting source.
    fn url_validator(&self) -> fn(&str) -> bool;

    /// Resolve a declared locator to `(concrete artefact url, SRI content hash)`. A direct URL
    /// resolves to itself; a `github:`/`apt:` locator queries its source and re-validates what comes
    /// back. `fresh` bypasses the fetch cache (set on `sbx upgrade`, so a new release is seen).
    /// `system` selects the release asset for this host — a backend with a single asset form ignores
    /// it.
    fn resolve_source(
        &self,
        nix: &Path,
        layout: &Layout,
        locator: &str,
        system: &str,
        fresh: bool,
    ) -> io::Result<(String, String)>;

    /// The generated nix expression that fetches the pinned artefact, unpacks it this backend's own
    /// way (a `dpkg-deb` data tarball, an AppImage squashfs, a plain `.tar.gz`) and autoPatchelfs the
    /// result — the one step that is genuinely a backend's own.
    fn derivation_expr(
        &self,
        nixpkgs: &str,
        system: &str,
        name: &str,
        url: &str,
        hash: &str,
    ) -> String;

    /// This backend's **trusted** direct packages as `(package name, declared locator)` — the form
    /// whose locator is resolved by [`Kind::resolve_source`].
    fn packages(&self, packages: &[crate::config::Package]) -> Vec<(String, String)>;

    /// This backend's **trusted** `<backend>:resolve` packages as `(package name, resolve command)` —
    /// the form whose download URL is re-derived by running a command in a sandbox.
    fn resolve_packages(&self, packages: &[crate::config::Package]) -> Vec<(String, Vec<String>)>;

    /// The per-project lock key this package occupies, or `None` when the package belongs to another
    /// backend. **Deliberately trust-agnostic**, unlike [`Kind::packages`]: it answers "does this
    /// config still declare that lock entry", which is what the prune universe asks, and pruning must
    /// not depend on trust (see [`declared`]).
    fn lock_key(&self, package: &crate::config::Package) -> Option<String>;
}

/// The host-side context every prebuilt package build shares: sbx's nix engine and store layout, the
/// project whose lock and gcroots are keyed by it, and the pinned `nixpkgs` the generated derivation
/// evaluates against. They are always all four or none, so they travel as one value.
pub(crate) struct Ctx<'a> {
    pub(crate) nix: &'a Path,
    pub(crate) layout: &'a Layout,
    pub(crate) project: &'a Path,
    pub(crate) nixpkgs: &'a str,
}

/// One declared reference of a prebuilt backend, in the form it was declared. Both forms end up at
/// the same place (a pinned `(url, hash)` in the per-project lock); they differ only in how the
/// concrete download URL is reached.
pub(crate) enum Ref {
    /// A locator resolved by [`Kind::resolve_source`] — a direct URL, or a source that is queried
    /// (`github:<owner>/<repo>`, `apt:<index>`). A direct URL resolves to itself. Its concrete
    /// artefact URL and content hash are re-derived on every upgrade, because the source can move.
    Locator(String),
    /// A `<backend>:resolve` — its download URL is re-derived by re-running the resolve command in a
    /// sandbox, and the heavy artefact prefetch runs only when that URL differs from the stored pin.
    Resolve { name: String, command: Vec<String> },
}

impl Ref {
    /// The per-project lock key: the declared locator, or `resolve:<name>`.
    pub(crate) fn key(&self) -> String {
        match self {
            Ref::Locator(locator) => locator.clone(),
            Ref::Resolve { name, .. } => resolve_key(name),
        }
    }
}

/// The two views `sbx upgrade <backend>` needs of a project's declared references, collected in one
/// pass over the baseline and each app overlay (see [`declared`]).
pub(crate) struct Declared {
    /// Deterministic, deduplicated, **trusted-only** — the set to roll forward, each in its declared
    /// form.
    pub(crate) trusted: Vec<Ref>,
    /// Every declared lock key **regardless of trust** — the universe the lock is pruned against, so
    /// an untrusted/Changed project's still-declared package keeps its pin instead of being unpinned.
    pub(crate) all: std::collections::BTreeSet<String>,
}

/// Collect both views in a single walk of the layers. Each app overlay is materialized once (a
/// `merge_app` clone), then contributes to both the trusted roll set and the trust-agnostic prune
/// universe — so `sbx upgrade` walks the apps once, not twice.
///
/// The order of `trusted` is load-bearing for reproducibility: the baseline first, then the apps in
/// name order, first occurrence kept. The two forms share **one** `seen` set, so a locator spelled
/// literally `resolve:foo` and a resolver named `foo` collide on their single lock key rather than
/// both claiming it.
pub(crate) fn declared(kind: &dyn Kind, cfg: &crate::config::Resolved) -> Declared {
    let mut seen = std::collections::BTreeSet::new();
    let mut trusted = Vec::new();
    let mut all = std::collections::BTreeSet::new();
    let mut absorb = |pkgs: &[crate::config::Package]| {
        for (_, locator) in kind.packages(pkgs) {
            if seen.insert(locator.clone()) {
                trusted.push(Ref::Locator(locator));
            }
        }
        for (name, command) in kind.resolve_packages(pkgs) {
            if seen.insert(resolve_key(&name)) {
                trusted.push(Ref::Resolve { name, command });
            }
        }
        all.extend(pkgs.iter().filter_map(|p| kind.lock_key(p)));
    };
    absorb(&cfg.packages);
    for app in cfg.apps.values() {
        let mut merged = cfg.clone();
        merged.merge_app(app.clone());
        absorb(&merged.packages);
    }
    Declared { trusted, all }
}

/// How many of this backend's declared packages are withheld for being untrusted — across the
/// project baseline and each app's own overlay. A count only (the per-package reason is already
/// warned on the launch path), so `sbx upgrade` does not read as "none declared" when an untrusted
/// project declares one. Each app is counted on its **own** package list rather than on the merged
/// overlay, so a baseline package is not re-counted once per app.
pub(crate) fn withheld(kind: &dyn Kind, cfg: &crate::config::Resolved) -> usize {
    let untrusted = |pkgs: &[crate::config::Package]| {
        pkgs.iter()
            .filter(|p| kind.lock_key(p).is_some() && p.state != crate::trust::TrustState::Trusted)
            .count()
    };
    untrusted(&cfg.packages)
        + cfg
            .apps
            .values()
            .map(|app| untrusted(&app.packages))
            .sum::<usize>()
}

/// Whether the project (baseline or any app) declares a trusted `<backend>:resolve` package — so the
/// upgrade path builds the (heavy) resolver sandbox only when it is actually needed.
pub(crate) fn has_resolve_ref(kind: &dyn Kind, cfg: &crate::config::Resolved) -> bool {
    let any = |pkgs: &[crate::config::Package]| !kind.resolve_packages(pkgs).is_empty();
    any(&cfg.packages)
        || cfg.apps.values().any(|app| {
            let mut merged = cfg.clone();
            merged.merge_app(app.clone());
            any(&merged.packages)
        })
}

/// One backend's per-project lock file name, derived from [`Kind::name`] — see [`lock_path`].
pub(crate) fn lock_file(kind: &dyn Kind) -> String {
    format!("{}-packages.lock", kind.name())
}

/// The per-project lock key of a `<backend>:resolve` package: prefixed by `resolve:` so its key space
/// is disjoint from a direct package's download URL (which never carries a bare `resolve:` prefix),
/// and keyed by the package name (unique per resolved config) rather than a URL, so a warm launch and
/// `sbx gc`/`sbx upgrade` find the pin without re-running the resolve command.
pub(crate) fn resolve_key(name: &str) -> String {
    format!("resolve:{name}")
}

/// Build one already-resolved package (either form) into sbx's store and return `(bin dir, store
/// root)`. Every provisioning entry point below funnels through here, so the generated derivation and
/// the per-package gcroot (`<backend>-<name>`) are identical whichever form pinned it.
fn build_pinned(
    kind: &dyn Kind,
    ctx: &Ctx,
    project_id: &str,
    name: &str,
    url: &str,
    hash: &str,
) -> io::Result<(PathBuf, PathBuf)> {
    let system = super::current_system();
    let expr = kind.derivation_expr(ctx.nixpkgs, &system, name, url, hash);
    let gcroot = ctx
        .layout
        .data_dir()
        .join("gcroots")
        .join("projects")
        .join(project_id)
        .join(format!("{}-{name}", kind.name()));
    let logical = store::provision_expr(ctx.nix, ctx.layout, &gcroot, &expr, name, "bin")?;
    Ok((logical.join("bin"), logical))
}

/// Provision one declared package host-side: resolve its locator to a hash (pinning it on first use),
/// build the generated derivation into sbx's store, and return `(bin directory, store root)` — the
/// bin dir to prepend to the sandbox `PATH`, the root whose closure the project store seeds. Mirrors
/// [`super::packages::provision`]'s per-package gcroot, name-keyed under the project.
pub(crate) fn provision(
    kind: &dyn Kind,
    ctx: &Ctx,
    name: &str,
    locator: &str,
) -> io::Result<(PathBuf, PathBuf)> {
    let project_id = super::binds::project_runtime_id(ctx.project)?;
    let lock_file = lock_file(kind);
    let mut lock = pins(ctx.layout, project_id.as_str(), &lock_file);
    let (url, hash) = match lock.get(locator) {
        Some(pin) => (pin.url.clone(), pin.hash.clone()),
        None => {
            let system = super::current_system();
            let (u, h) = kind.resolve_source(ctx.nix, ctx.layout, locator, &system, false)?;
            lock.insert(
                locator.to_string(),
                Pin {
                    hash: h.clone(),
                    url: u.clone(),
                },
            );
            write_pins(ctx.layout, project_id.as_str(), &lock_file, &lock)?;
            (u, h)
        }
    };
    build_pinned(kind, ctx, project_id.as_str(), name, &url, &hash)
}

/// Provision one `<backend>:resolve` package host-side — the auto-upgrade twin of [`provision`]. The
/// per-project lock is keyed by [`resolve_key`]; on a **warm** launch the pinned `(url, hash)` is
/// reused offline and the resolve command is **not run** (the offline invariant), so only a first
/// launch or `sbx upgrade` runs it. Builds the same derivation and per-package gcroot as the direct
/// form, so the two forms provision identically once resolved.
pub(crate) fn provision_resolve(
    kind: &dyn Kind,
    ctx: &Ctx,
    name: &str,
    command: &[String],
    cage: &super::resolve::ResolveCage,
) -> io::Result<(PathBuf, PathBuf)> {
    let project_id = super::binds::project_runtime_id(ctx.project)?;
    let lock_file = lock_file(kind);
    let key = resolve_key(name);
    let mut lock = pins(ctx.layout, project_id.as_str(), &lock_file);
    let (url, hash) = match lock.get(&key) {
        Some(pin) => (pin.url.clone(), pin.hash.clone()),
        None => {
            let u = super::resolve::resolve_url(
                cage,
                name,
                command,
                kind.url_validator(),
                kind.artefact(),
            )?;
            let h = prefetch_hash(ctx.nix, ctx.layout, &u, false)?;
            lock.insert(
                key,
                Pin {
                    hash: h.clone(),
                    url: u.clone(),
                },
            );
            write_pins(ctx.layout, project_id.as_str(), &lock_file, &lock)?;
            (u, h)
        }
    };
    build_pinned(kind, ctx, project_id.as_str(), name, &url, &hash)
}

/// Build a `<backend>:resolve` package from its EXISTING pin only — for the gc keep path, which must
/// never run the resolve command or touch the network. Returns `None` when the package is not yet
/// pinned (nothing has been built to keep), so gc skips it rather than resolving.
pub(crate) fn provision_resolve_pinned(
    kind: &dyn Kind,
    ctx: &Ctx,
    name: &str,
) -> io::Result<Option<(PathBuf, PathBuf)>> {
    let project_id = super::binds::project_runtime_id(ctx.project)?;
    let Some(pin) =
        pins(ctx.layout, project_id.as_str(), &lock_file(kind)).remove(&resolve_key(name))
    else {
        return Ok(None);
    };
    build_pinned(kind, ctx, project_id.as_str(), name, &pin.url, &pin.hash).map(Some)
}

#[cfg(test)]
mod tests {
    use super::super::appimage::AppImage;
    use super::super::deb::Deb;
    use super::super::tarball::Tarball;
    use super::*;

    #[test]
    fn is_sri_accepts_prefetch_output_and_rejects_junk() {
        assert!(is_sri(
            "sha256-jBGtMS5lpJWVXe+KzQgRSho8BcaEzGvONzIbAWled0w="
        ));
        assert!(!is_sri("jBGtMS5l"));
        assert!(!is_sri("sha256-"));
        assert!(!is_sri("md5-abc"));
    }

    #[test]
    fn prefetch_name_sanitizes_an_illegal_store_name_and_keeps_clean_ones() {
        // A percent-encoded space (as a vendor filename like `My%20App.tar.gz` carries) would
        // percent-decode to a space — an illegal store name — so `%` is sanitized to `-`, keeping the
        // prefetch working.
        assert_eq!(
            prefetch_name("https://example.com/x/My%20App.tar.gz"),
            "My-20App.tar.gz"
        );
        // A clean `.deb`/`.AppImage` name is unchanged, so the shared prefetch keeps deb/appimage
        // behavior byte-identical.
        assert_eq!(
            prefetch_name("https://example.com/pool/demo-app_1.2_amd64.deb"),
            "demo-app_1.2_amd64.deb"
        );
        assert_eq!(
            prefetch_name("https://example.com/Demo-App-1.0-x86_64.AppImage"),
            "Demo-App-1.0-x86_64.AppImage"
        );
        // A degenerate URL with no last segment falls back to a fixed safe name.
        assert_eq!(prefetch_name("https://example.com/"), "source");
    }

    #[test]
    fn fold_prefetch_cause_keeps_the_final_error_line_over_the_retry_warnings() {
        // The shape nix emits for a failed download: several retry `warning:` lines, then one
        // `error:` line carrying the real cause. Only the last is folded into the summary.
        let stderr = "\
warning: unable to download 'https://example.com/app.deb': Could not resolve hostname (6) Could not resolve host: example.com; retrying in 349 ms (attempt 1/5)
warning: unable to download 'https://example.com/app.deb': Could not resolve hostname (6) Could not resolve host: example.com; retrying in 561 ms (attempt 2/5)
error: unable to download 'https://example.com/app.deb': Could not resolve hostname (6) Could not resolve host: example.com
";
        assert_eq!(
            fold_prefetch_cause(stderr),
            "unable to download 'https://example.com/app.deb': Could not resolve hostname (6) Could not resolve host: example.com"
        );
    }

    #[test]
    fn fold_prefetch_cause_falls_back_when_there_is_no_error_line() {
        // No `error:` line: keep the whole trimmed stderr rather than dropping the cause.
        assert_eq!(
            fold_prefetch_cause("  something went wrong  "),
            "something went wrong"
        );
        // Nothing captured at all → empty, so the caller omits the `: <cause>` suffix.
        assert_eq!(fold_prefetch_cause("   \n  \n"), "");
    }

    #[test]
    fn launcher_wrap_fills_both_placeholders_and_excludes_apprun() {
        let wrap = launcher_wrap("demo-app", "$out:/lib");
        assert!(wrap.contains("$out/bin/demo-app"));
        assert!(wrap.contains("--prefix LD_LIBRARY_PATH : \"$out:/lib\""));
        // AppRun exclusion is what makes one snippet serve both backends.
        assert!(wrap.contains("! -name 'AppRun'"));
        // The app is located by a packed `resources/app.asar` OR, for an asar-less VS Code fork
        // (some ship `resources/app/` as a loose directory), the `resources/app` directory.
        assert!(wrap.contains("resources/app.asar"));
        assert!(wrap.contains("-type d -path '*/resources/app'"));
        assert!(!wrap.contains('@'), "unfilled placeholder in:\n{wrap}");
    }

    #[test]
    fn launcher_wrap_falls_back_to_a_lone_top_level_binary_only_when_there_is_no_bundle() {
        let wrap = launcher_wrap("demo-cli", "/lib");
        // The bundle probe still runs FIRST and unchanged: a backend that works today must take the
        // identical path. The fallback lives in the `else` arm, so it is unreachable for a bundle.
        let bundle_probe = wrap.find("resources/app.asar").expect("bundle probe");
        let fallback = wrap.find("cands=").expect("bare-binary fallback");
        assert!(
            bundle_probe < fallback,
            "the bare-binary fallback must come after the bundle probe:\n{wrap}"
        );
        assert!(wrap.contains("if [ -n \"$app\" ]; then"));

        // Same exclusions as the bundle arm — an AppImage root carries `AppRun` beside the real
        // binary, so taking the first of them would wrap the launcher script instead.
        let arm = &wrap[fallback..];
        for excluded in [
            "! -name 'AppRun'",
            "! -name 'chrome-sandbox'",
            "! -name '*.so'",
        ] {
            assert!(arm.contains(excluded), "fallback drops {excluded}:\n{arm}");
        }

        // Exactly one candidate, or the build fails: two executables at the root is an ambiguity,
        // and `sort | head -1` on it is how the wrong program gets wrapped silently.
        assert!(arm.contains("[ \"$count\" -eq 1 ]"));
        assert!(
            !arm.contains("head -1"),
            "the fallback must not pick a first candidate:\n{arm}"
        );
        // Both refusals name the package, so a build log says which one failed and why.
        assert_eq!(wrap.matches("demo-cli: no Electron").count(), 2);
        // The wrapper is named after the `[packages]` key, which is the derivation's mainProgram —
        // so a profile's `cmd` is that key, whatever the vendor called the file inside the archive.
        assert!(wrap.contains("$out/bin/demo-cli"));
    }

    #[test]
    fn the_derived_lock_and_gcroot_names_are_the_ones_already_on_disk() {
        // `Kind::name` is on-disk state: it spells the per-project lock a project's existing pins
        // live in, and the prefix of every per-package gcroot. Nothing else pins those strings --
        // every lock test round-trips through `pins`/`write_pins`, which both read the derived
        // name, so renaming `name()` would strand a user's pins and gcroots with the whole suite
        // still green.
        assert_eq!(lock_file(&Deb), "deb-packages.lock");
        assert_eq!(lock_file(&AppImage), "appimage-packages.lock");
        assert_eq!(lock_file(&Tarball), "tarball-packages.lock");
        assert_eq!(
            [Deb.name(), AppImage.name(), Tarball.name()],
            ["deb", "appimage", "tarball"]
        );
    }

    #[test]
    fn the_readers_of_a_pin_derive_the_same_names_the_writers_do() {
        // The gc keep set and the config view both name a prebuilt package's lock and gcroot from
        // their own side. They used to spell the strings out as literals that merely happened to
        // agree with the write side; both now derive from `Kind::name`, and this asserts against
        // what each actually returns rather than against a literal, so a rename cannot leave one
        // side behind.
        let pkg = |name: &str, backend| crate::config::Package {
            name: name.to_string(),
            backend,
            state: crate::trust::TrustState::Trusted,
        };
        let url = "https://example.com/app".to_string();
        for (kind, backend) in [
            (&Deb as &dyn Kind, crate::config::Backend::Deb(url.clone())),
            (&AppImage, crate::config::Backend::AppImage(url.clone())),
            (&Tarball, crate::config::Backend::Tarball(url.clone())),
        ] {
            assert_eq!(
                super::super::inspect::prebuilt_lockfile(&backend).as_deref(),
                Some(lock_file(kind).as_str())
            );
            assert_eq!(
                super::super::packages::project_gcroot_names(&[pkg("demo-app", backend)]),
                vec![format!("{}-demo-app", kind.name())]
            );
        }
    }

    #[test]
    fn arch_tokens_flip_by_host_and_label_matches() {
        let (accept, reject) = arch_tokens("x86_64-linux");
        assert!(accept.contains(&"amd64") && reject.contains(&"arm64"));
        assert_eq!(arch_label("x86_64-linux"), "amd64");
        let (accept, reject) = arch_tokens("aarch64-linux");
        assert!(accept.contains(&"arm64") && reject.contains(&"amd64"));
        assert_eq!(arch_label("aarch64-linux"), "arm64");
    }
}
