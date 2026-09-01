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
/// three passes, and the order matters: the **bundle** shape first, then the **named binary**, and
/// the **lone bare binary** only when neither matched.
///
/// A bundle is located by its `resources/` signature — either a packed `resources/app.asar` file or,
/// for an asar-less build (some modern VS Code forks ship the app as a loose `resources/app/`
/// directory), the `resources/app` directory itself; both resolve to the same bundle root. The
/// launcher is then the executable beside it that is not a `.so`, a Chromium helper, or the AppImage
/// `AppRun` script. Excluding `AppRun` is load-bearing for an AppImage (its squashfs carries an
/// `AppRun` launcher that sorts *before* the real binary) and harmless for a `.deb` (which has no
/// `AppRun`), so one snippet serves both.
///
/// The second pass covers the shape a non-Electron desktop package ships: an FHS tree whose program
/// sits at `usr/bin/<name>` beside its siblings (a vendor `.deb` routinely carries a CLI and an
/// updater there too). It matches on the *declared* name — the `[packages]` key, which the profile
/// also writes as its `cmd` — so a tree holding several binaries is unambiguous by construction
/// rather than by counting. More than one match anywhere in the tree is not a guess to make, so it
/// falls through to the last pass instead.
///
/// That search excludes the wrapper's own destination, `$out/bin/<name>`, because `makeWrapper`
/// writes there — but an archive whose *own* root is an FHS tree (`bin/<name>` + `share/`, the
/// shape a self-contained CLI with man pages ships in) lands its program on exactly that path, and
/// dropping it would refuse a perfectly unambiguous layout. So it gets its own arm: the program is
/// moved to `$out/libexec/<name>` and wrapped from there, which frees the destination instead of
/// overwriting the binary being wrapped. A `bin/<name>` that is a *symlink* into the tree is
/// resolved rather than moved, since the wrapper may replace the link without touching its target.
///
/// The last pass covers the plainest shape a vendor ships: an archive whose root holds one executable
/// and nothing else to choose from — a self-contained CLI rather than a desktop bundle. It applies
/// the *same* exclusions, and requires **exactly one** candidate: two would be an ambiguity, and
/// picking the first of them is how a build silently wraps the wrong program. The search is
/// deliberately `-maxdepth 1`, so an archive that unpacks into a versioned sub-directory fails here
/// with a message naming what it found rather than reaching in and guessing.
///
/// Beyond `LD_LIBRARY_PATH`, the wrapper prefixes three runtime lookup paths from the same
/// `buildInputs`: `GST_PLUGIN_SYSTEM_PATH_1_0` (`lib/gstreamer-1.0`), `GIO_EXTRA_MODULES`
/// (`lib/gio/modules`) and `XDG_DATA_DIRS` (`share`). What they have in common is that the things
/// they point at are **dlopen'd or looked up by path**, never linked, so `LD_LIBRARY_PATH` finds
/// none of them: a WebKit app reports `GStreamer element appsink not found` on its first media
/// page, `glib-networking`'s TLS backend is a GIO module without which HTTPS fails outright, and
/// GSettings schemas live under `share`. All three are unconditional because they cost nothing when
/// no such package is among the inputs — the directories simply do not exist, and each consumer
/// skips a missing one.
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
      named=$(find $out -type f -executable -path '*/bin/@NAME@' ! -path "$out/bin/@NAME@" | sort)
      if [ -n "$named" ] && [ "$(printf '%s\n' "$named" | wc -l)" -eq 1 ]; then
        main=$named
      elif [ -x "$out/bin/@NAME@" ]; then
        if [ -L "$out/bin/@NAME@" ]; then
          main=$(readlink -f "$out/bin/@NAME@")
        else
          mkdir -p $out/libexec
          mv "$out/bin/@NAME@" "$out/libexec/@NAME@"
          main=$out/libexec/@NAME@
        fi
      else
        cands=$(find $out -maxdepth 1 -type f -executable \
          ! -name 'AppRun' ! -name 'chrome-sandbox' ! -name 'chrome_crashpad_handler' \
          ! -name '*.so' ! -name '*.so.*' | sort)
        [ -n "$cands" ] || { echo "@NAME@: no Electron resources/app(.asar), no */bin/@NAME@, and no executable at the archive root" >&2; exit 1; }
        count=$(printf '%s\n' "$cands" | wc -l)
        [ "$count" -eq 1 ] || { echo "@NAME@: no Electron resources/app(.asar), no single */bin/@NAME@, and $count executables at the archive root (need exactly 1):" >&2; printf '%s\n' "$cands" >&2; exit 1; }
        main=$cands
      fi
    fi
    mkdir -p $out/bin
    makeWrapper "$main" "$out/bin/@NAME@" \
      --prefix LD_LIBRARY_PATH : "@LDPREFIX@" \
      --prefix GST_PLUGIN_SYSTEM_PATH_1_0 : "@GSTPREFIX@" \
      --prefix GIO_EXTRA_MODULES : "@GIOPREFIX@" \
      --prefix XDG_DATA_DIRS : "@DATAPREFIX@""#;

/// `@GSTPREFIX@`: the `lib/gstreamer-1.0` of every `buildInputs` entry. Named here rather than
/// inlined so the snippet stays runnable shell once the placeholder is filled with a plain path,
/// which is what lets a test execute it against a real directory tree. Every backend embedding the
/// snippet builds with `mkDerivation (finalAttrs: …)` and has `pkgs` in scope.
const GST_SEARCH_PATH: &str =
    r#"${pkgs.lib.makeSearchPathOutput "lib" "lib/gstreamer-1.0" finalAttrs.buildInputs}"#;

/// `@GIOPREFIX@`: the GIO module directory of every `buildInputs` entry. `glib-networking` ships
/// GIO's TLS backend as a module, so without this a GTK/libsoup app resolves no HTTPS at all — the
/// same dlopen'd-not-linked shape as the GStreamer elements above.
const GIO_SEARCH_PATH: &str =
    r#"${pkgs.lib.makeSearchPathOutput "lib" "lib/gio/modules" finalAttrs.buildInputs}"#;

/// `@DATAPREFIX@`: the `share` directory of every `buildInputs` entry — where GSettings schemas,
/// icon themes and the rest of the XDG data a GTK application looks up at runtime live.
const XDG_DATA_SEARCH_PATH: &str =
    r#"${pkgs.lib.makeSearchPathOutput "out" "share" finalAttrs.buildInputs}"#;

/// Fill [`LAUNCHER_WRAP`]'s two placeholders. `ld_prefix` is the `LD_LIBRARY_PATH` prefix value: a
/// `.deb` passes just the `makeLibraryPath` of its `buildInputs`; an AppImage prepends `$out` (its
/// bundle root holds the Chromium sibling `.so`s — `libEGL.so`, `libffmpeg.so`, …).
pub(crate) fn launcher_wrap(name: &str, ld_prefix: &str) -> String {
    LAUNCHER_WRAP
        .replace("@NAME@", name)
        .replace("@LDPREFIX@", ld_prefix)
        .replace("@GSTPREFIX@", GST_SEARCH_PATH)
        .replace("@GIOPREFIX@", GIO_SEARCH_PATH)
        .replace("@DATAPREFIX@", XDG_DATA_SEARCH_PATH)
}

/// The extra library attributes the package called `name` declared, or none when it declared any.
/// The collectors on [`Kind`] answer `(name, locator)` — deliberately, since the prune and count
/// paths want exactly that — so the provisioning sites read the package's `libs` back through here
/// rather than widening every tuple in the crate.
pub(crate) fn libs_of(packages: &[crate::config::Package], name: &str) -> Vec<String> {
    packages
        .iter()
        .find(|p| p.name == name)
        .map(|p| p.libs.clone())
        .unwrap_or_default()
}

/// The nixpkgs attributes one prebuilt package is autoPatchelf'd against: the built-in
/// Electron/Chromium set plus whatever its own table declared, space-joined for the generated
/// derivation's `buildInputs`. Deduplicated and order-stable so an attribute named in both lands
/// once and the expression (and therefore the store path) does not churn on a re-declaration.
pub(crate) fn lib_set(extra: &[String]) -> String {
    let mut names: Vec<&str> = ELECTRON_LIBS.to_vec();
    for attr in extra {
        if !names.contains(&attr.as_str()) {
            names.push(attr);
        }
    }
    names.join(" ")
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
///
/// Compared as a whole where a writer has to tell "the entry I read" from "an entry somebody wrote
/// since" — see the reconcile at the end of [`upgrade`].
#[derive(Clone, PartialEq, Eq)]
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
        if let (Some(key), Some(hash)) = (it.next(), it.next())
            && !key.is_empty()
            && is_sri(hash)
        {
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
    super::atomicfile::write_atomic(&path, body.as_bytes())
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
/// **The declared scheme governs the first hop only.** nix's downloader follows a redirect out of
/// `https://` into `http://` and reports nothing, so a URL this function was handed as TLS can be
/// answered in plaintext by a later hop, and the hash pinned is then the hash of bytes an on-path
/// observer could have chosen. Nothing here can see it: nix exposes no setting constraining the
/// protocols a redirect may reach, and `prefetch-file --json` returns the hash and store path
/// without the URL that finally answered. What the `https://` requirement on a declared locator
/// buys is therefore real but bounded — it keeps a config author from naming plaintext outright,
/// which is a different actor at a different moment from a vendor whose own redirect leaves TLS.
/// Closing the rest means carrying the fetch over a transport sbx controls rather than nix's, which
/// is why it is written here rather than worked around: the lock records the URL sbx **asked for**,
/// never the one that answered.
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
    expected_sha256: Option<&str>,
) -> io::Result<String> {
    let mut cmd = store::nix_command(nix, layout);
    cmd.args(["--extra-experimental-features", "nix-command flakes"])
        .args(["store", "prefetch-file", "--json"])
        .args(["--name", &prefetch_name(url)]);
    // A digest an *independent, attested* source published for this artifact, when the caller has
    // one. It is handed to nix rather than compared afterwards, so a mismatched artifact never
    // enters the store: nix fails the fetch with `hash mismatch` and there is nothing to clean up.
    // `sha256:<hex>` is the spelling an apt `Packages` stanza carries, and nix takes it as-is, so
    // no conversion stands between what the index published and what is enforced.
    //
    // `None` means "nothing attests this artifact independently", which is the honest answer for a
    // plain URL, a GitHub release asset and every backend that pins on first sight: their hash
    // records what arrived rather than what was promised.
    if let Some(hex) = expected_sha256 {
        cmd.args(["--expected-hash", &format!("sha256:{hex}")]);
    }
    cmd.arg(url).stdout(Stdio::piped()).stderr(if quiet {
        Stdio::piped()
    } else {
        Stdio::inherit()
    });
    let out = cmd.spawn()?.wait_with_output()?;
    if !out.status.success() {
        // `quiet` decides this on its own, through what it captured. On the quiet path (an
        // `sbx upgrade` re-resolve) stderr is in hand and the summary already frames the line with
        // `re-resolve failed — `, so the returned error is the folded cause alone. On the live path
        // nothing was captured — it streamed to the terminal as it happened — so the fold finds
        // nothing and the bare step name is what bubbles up, which is the right context for a
        // failure the user has just watched scroll past.
        let cause = fold_prefetch_cause(&String::from_utf8_lossy(&out.stderr));
        return Err(io::Error::other(if cause.is_empty() {
            "nix store prefetch-file failed".to_string()
        } else {
            cause
        }));
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

/// Select the linux asset URL matching `system` and `ext` from a GitHub release's JSON, where `ext`
/// is the lowercased artefact suffix (`".deb"`, `".appimage"`). A release names its assets for every
/// platform it ships, so the discriminant is CPU architecture, not the OS: an asset whose name names
/// a *foreign* arch is dropped, then the survivors are ranked in three tiers.
///
/// The tiers are the whole point, and the first one is a fix rather than a nicety. An architecture
/// token is preferred where it is **terminal** — `…_amd64.deb`, not `…_amd64-vulkan.deb` /
/// `…_amd64-cuda.deb` — so a repo shipping GPU or feature variants beside the plain build resolves
/// to the plain build, which is the sensible default. Without that tier the naive first-match takes
/// the variant, because `sort()` orders `amd64-vulkan` before `amd64` (`-` sorts before `.`). The
/// second tier accepts any asset positively naming this architecture (the token appears mid-name),
/// and the third accepts a single unambiguous artefact with no arch token at all, for a single-arch
/// repo. `sort()` makes the choice deterministic when several candidates tie within a tier.
///
/// One function and not one per backend: this ranking was fixed once for `deb:` and the `appimage:`
/// copy did not receive the fix, so an AppImage repo publishing a same-arch feature variant selected
/// the variant. Every backend now asks the same question, and the catalogue freshness check asks it
/// too, so a catalogue check cannot pass a release whose asset the launch would refuse.
///
/// Pure, so selection is testable against captured release JSON.
pub(crate) fn select_release_asset(
    json: &serde_json::Value,
    system: &str,
    ext: &str,
) -> Option<String> {
    let (accept, reject) = arch_tokens(system);
    let mut native: Vec<(String, String)> = json
        .get("assets")?
        .as_array()?
        .iter()
        .filter_map(|a| {
            let name = a.get("name")?.as_str()?.to_ascii_lowercase();
            let url = a.get("browser_download_url")?.as_str()?;
            (name.ends_with(ext) && !reject.iter().any(|t| name.contains(t)))
                .then(|| (name, url.to_string()))
        })
        .collect();
    native.sort();
    native
        .iter()
        .find(|(name, _)| accept.iter().any(|t| name.ends_with(&format!("{t}{ext}"))))
        .or_else(|| {
            native
                .iter()
                .find(|(name, _)| accept.iter().any(|t| name.contains(t)))
        })
        .or_else(|| native.first().filter(|_| native.len() == 1))
        .map(|(_, url)| url.clone())
}

/// Split a `github:<owner>/<repo>` locator into its two halves, or `None` for any other locator
/// shape (a direct URL, an `apt:` root).
///
/// One definition because every prebuilt backend that offers the `github:` form parses it
/// identically, and a backend that grew its own copy would be free to disagree about what counts as
/// the form.
pub(crate) fn github_locator(locator: &str) -> Option<(&str, &str)> {
    locator.strip_prefix("github:")?.split_once('/')
}

/// The artefact URL a `github:<owner>/<repo>` release names, given the API document, checked against
/// this backend's own charset barrier.
///
/// Pure, so the barrier can be tested without a network. [`github_release_asset`] is this plus the
/// fetch.
pub(crate) fn validate_release_asset(
    kind: &dyn Kind,
    json: &serde_json::Value,
    owner: &str,
    repo: &str,
    system: &str,
) -> io::Result<String> {
    let ext = format!(".{}", kind.name());
    let artefact = kind.artefact();
    let url = select_release_asset(json, system, &ext).ok_or_else(|| {
        io::Error::other(format!(
            "no linux {} {artefact} asset in the latest release of {owner}/{repo}",
            arch_label(system)
        ))
    })?;
    if !kind.url_validator()(&url, false) {
        return Err(io::Error::other(format!(
            "the latest release of {owner}/{repo} selected an asset URL that is not a \
             valid `https://` {artefact} URL: {url}"
        )));
    }
    Ok(url)
}

/// The artefact URL a `github:<owner>/<repo>` locator's newest release names, validated.
///
/// **`allow_insecure_http` deliberately does not reach here, and `deb:`'s `apt:` sibling is the
/// contrast that argues it.** An `apt:` locator names its own repository root, so a user who wrote
/// `apt:http://…` chose plaintext and the `.deb` URL derived from that root inherits the choice;
/// the flag must follow it there or the opt-in would not work at all. A `github:` locator names no
/// scheme. This URL is a field in a JSON document fetched from `api.github.com` over TLS, chosen by
/// GitHub and not by the config, so a plaintext value in it is an anomaly in a third party's answer
/// rather than a posture anyone here asked for. Opting into plaintext for your own server is not
/// opting into following whatever scheme a remote API hands back, and one switch cannot honestly
/// mean both.
///
/// `appimage:` used to pass the launch's flag through, which made the same release asset https-only
/// for one backend and plaintext-acceptable for the other. That is why the query, the selection and
/// the barrier are one function rather than one per backend.
///
/// The asset extension comes from [`Kind::name`] rather than from a parameter: `deb` and `appimage`
/// are exactly the `.deb` / `.appimage` suffixes in use, and passing both would invite the mismatch
/// this consolidation exists to prevent.
pub(crate) fn github_release_asset(
    kind: &dyn Kind,
    nix: &Path,
    layout: &Layout,
    owner: &str,
    repo: &str,
    system: &str,
    fresh: bool,
) -> io::Result<String> {
    let api = format!("https://api.github.com/repos/{owner}/{repo}/releases/latest");
    let json = super::nixhub::fetch_url_json(nix, layout, &api, fresh)?;
    validate_release_asset(kind, &json, owner, repo, system)
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
    ///
    /// The `bool` the returned validator takes is the launch's resolved `allow_insecure_http`. It is
    /// carried rather than baked in because the URL checked here is the one a *resolve command*
    /// printed — a value that did not exist when the config was read, so it gets the same answer the
    /// declared locator got, from the same definition
    /// ([`crate::config`]'s `strip_fetch_scheme`), instead of a second rule that could drift.
    fn url_validator(&self) -> fn(&str, bool) -> bool;

    /// Resolve a declared locator to `(concrete artefact url, SRI content hash)`. A direct URL
    /// resolves to itself; a `github:`/`apt:` locator queries its source and re-validates what comes
    /// back. `fresh` marks an `sbx upgrade` re-resolve: a backend that queries a source bypasses
    /// nix's metadata cache so a new release or index entry is seen, and every backend keeps the
    /// artefact fetch quiet so the upgrade summary frames its own failures. `system` selects the
    /// release asset for this host — a backend with a single asset form ignores it.
    fn resolve_source(
        &self,
        nix: &Path,
        layout: &Layout,
        locator: &str,
        system: &str,
        fresh: bool,
        allow_insecure_http: bool,
    ) -> io::Result<(String, String)>;

    /// The generated nix expression that fetches the pinned artefact, unpacks it this backend's own
    /// way (a `dpkg-deb` data tarball, an AppImage squashfs, a plain `.tar.gz`) and autoPatchelfs the
    /// result — the one step that is genuinely a backend's own.
    ///
    /// `libs` are the package's own extra nixpkgs attributes (its table's `libs`), unioned with the
    /// built-in Electron/Chromium set by [`lib_set`]: that set is shared by all three backends, so a
    /// GTK/WebKit app names what it needs here rather than growing every other app's closure.
    fn derivation_expr(
        &self,
        nixpkgs: &str,
        system: &str,
        name: &str,
        url: &str,
        hash: &str,
        libs: &[String],
    ) -> String;

    /// Which of this backend's two declaration forms `package` uses, or `None` when it belongs to
    /// another backend. The one place a backend reads a [`crate::config::Backend`], and the only one
    /// that has to be kept exhaustive: everything below is derived from it.
    ///
    /// It answers about the *declaration*, never about trust — the trust filter belongs to the two
    /// collectors below, because [`Kind::lock_key`] must stay trust-agnostic.
    fn form(&self, package: &crate::config::Package) -> Option<Form>;

    /// This backend's **trusted** direct packages as `(package name, declared locator)` — the form
    /// whose locator is resolved by [`Kind::resolve_source`].
    fn packages(&self, packages: &[crate::config::Package]) -> Vec<(String, String)> {
        packages
            .iter()
            .filter(|p| p.state == crate::trust::TrustState::Trusted)
            .filter_map(|p| match self.form(p) {
                Some(Form::Direct(locator)) => Some((p.name.clone(), locator)),
                Some(Form::Resolve(_)) | None => None,
            })
            .collect()
    }

    /// This backend's **trusted** `<backend>:resolve` packages as `(package name, resolve command)` —
    /// the form whose download URL is re-derived by running a command in a sandbox. Withholding an
    /// untrusted one here is what keeps its command from ever being executed.
    fn resolve_packages(&self, packages: &[crate::config::Package]) -> Vec<(String, Vec<String>)> {
        packages
            .iter()
            .filter(|p| p.state == crate::trust::TrustState::Trusted)
            .filter_map(|p| match self.form(p) {
                Some(Form::Resolve(command)) => Some((p.name.clone(), command)),
                Some(Form::Direct(_)) | None => None,
            })
            .collect()
    }

    /// The per-project lock key this package occupies, or `None` when the package belongs to another
    /// backend. **Deliberately trust-agnostic**, unlike [`Kind::packages`]: it answers "does this
    /// config still declare that lock entry", which is what the prune universe asks, and pruning must
    /// not depend on trust (see [`declared`]).
    fn lock_key(&self, package: &crate::config::Package) -> Option<String> {
        match self.form(package)? {
            Form::Direct(locator) => Some(locator),
            Form::Resolve(_) => Some(resolve_key(&package.name)),
        }
    }
}

/// How a package declared one of the prebuilt backends: a locator resolved by
/// [`Kind::resolve_source`], or a command run in a sandbox to print the newest download URL. The
/// distinction a backend's own `match` on [`crate::config::Backend`] draws, lifted out so the three
/// things that follow from it — the two admitted-package lists and the lock key — are written once.
pub(crate) enum Form {
    Direct(String),
    Resolve(Vec<String>),
}

/// The four backends in the order a launch provisions their **direct** packages. Both arrays must
/// name every backend — one missing entry means its packages are silently never provisioned — and
/// their order is load-bearing twice over: each provisioned `bin` directory is pushed onto the list
/// that becomes the sandbox `PATH`, so this order arbitrates between two packages shipping the same
/// binary name, and everything here is provisioned **before** anything in [`RESOLVE_ORDER`] because
/// the resolve cage is built from the bins collected so far — a resolve command runs with every
/// direct package's bin on `PATH`. The two groups therefore cannot be interleaved into one walk.
/// [`super::launch`]'s gc seed walks the same two arrays for consistency, but there the order is
/// cosmetic: it collects store roots (a set), and its resolve path never builds a cage.
pub(crate) const DIRECT_ORDER: [&dyn Kind; 4] = [
    &super::deb::Deb,
    &super::appimage::AppImage,
    &super::tarball::Tarball,
    &super::binary::Binary,
];

/// The four backends in the order a launch provisions their `<backend>:resolve` packages. Differs
/// from [`DIRECT_ORDER`] — see there for what the order decides.
pub(crate) const RESOLVE_ORDER: [&dyn Kind; 4] = [
    &super::tarball::Tarball,
    &super::deb::Deb,
    &super::appimage::AppImage,
    &super::binary::Binary,
];

/// The host-side context every prebuilt package build shares: sbx's nix engine and store layout, the
/// project whose lock and gcroots are keyed by it, and the pinned `nixpkgs` the generated derivation
/// evaluates against. They are always all four or none, so they travel as one value.
pub(crate) struct Ctx<'a> {
    pub(crate) nix: &'a Path,
    pub(crate) layout: &'a Layout,
    pub(crate) project: &'a Path,
    pub(crate) nixpkgs: &'a str,
    /// The launch's resolved `allow_insecure_http`, carried so the URL a resolve command prints is
    /// judged by the same rule the declared locator was.
    pub(crate) allow_insecure_http: bool,
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
    libs: &[String],
) -> io::Result<(PathBuf, PathBuf)> {
    let system = super::current_system();
    let expr = kind.derivation_expr(ctx.nixpkgs, &system, name, url, hash, libs);
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

/// The pinned `(url, hash)` for `key`, minting and recording one only when the lock has none.
///
/// **`mint` runs only on a miss.** That is the offline invariant a warm launch rests on: once a
/// package is pinned, provisioning it must not reach the network — no resolve command, no release
/// query — so the mint is taken lazily and never merely as a fallback value. Returns whether a new
/// pin was recorded, which is what tells the caller the lock is worth writing back.
///
/// Split out from [`provision_pinned`] so the invariant is testable: the caller's real mint builds
/// a derivation, but this takes any closure.
fn pinned_or_mint<F>(
    lock: &mut BTreeMap<String, Pin>,
    key: &str,
    mint: F,
) -> io::Result<((String, String), bool)>
where
    F: FnOnce() -> io::Result<(String, String)>,
{
    if let Some(pin) = lock.get(key) {
        return Ok(((pin.url.clone(), pin.hash.clone()), false));
    }
    let (url, hash) = mint()?;
    lock.insert(
        key.to_string(),
        Pin {
            hash: hash.clone(),
            url: url.clone(),
        },
    );
    Ok(((url, hash), true))
}

/// Provision one package from its per-project pin, minting the pin on first use — the sequence the
/// direct and `:resolve` forms share. They differ only in how a missing pin is minted, which is
/// `mint`, and in the lock key: the locator itself for the direct form, [`resolve_key`] for the
/// other. The lock is written back only when a pin was actually minted.
fn provision_pinned<F>(
    kind: &dyn Kind,
    ctx: &Ctx,
    name: &str,
    key: &str,
    libs: &[String],
    mint: F,
) -> io::Result<(PathBuf, PathBuf)>
where
    F: FnOnce() -> io::Result<(String, String)>,
{
    let project_id = super::binds::project_runtime_id(ctx.project)?;
    let lock_file = lock_file(kind);
    let mut lock = pins(ctx.layout, project_id.as_str(), &lock_file);
    let ((url, hash), minted) = pinned_or_mint(&mut lock, key, mint)?;
    if minted {
        // Written ADDITIVELY, the way `nixhub::provision` persists a freshly-resolved pin and for
        // the same reason: minting is the slow part (a download and a hash, or a resolve command in
        // a cage), so a concurrent cold provision of the same project has a wide window to pin a
        // *different* package while this one is still working. Writing the snapshot taken before
        // the mint would drop that pin, and the package would silently re-resolve and re-pin on the
        // next launch — a second trust-on-first-use, and a network round-trip on a path documented
        // as offline. Re-reading and merging just this key keeps the other one.
        let mut disk = pins(ctx.layout, project_id.as_str(), &lock_file);
        if let Some(entry) = lock.get(key) {
            disk.insert(key.to_string(), entry.clone());
        }
        write_pins(ctx.layout, project_id.as_str(), &lock_file, &disk)?;
    }
    build_pinned(kind, ctx, project_id.as_str(), name, &url, &hash, libs)
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
    libs: &[String],
) -> io::Result<(PathBuf, PathBuf)> {
    provision_pinned(kind, ctx, name, locator, libs, || {
        let system = super::current_system();
        kind.resolve_source(
            ctx.nix,
            ctx.layout,
            locator,
            &system,
            false,
            ctx.allow_insecure_http,
        )
    })
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
    libs: &[String],
) -> io::Result<(PathBuf, PathBuf)> {
    provision_pinned(kind, ctx, name, &resolve_key(name), libs, || {
        let url = super::resolve::resolve_url(
            cage,
            name,
            command,
            kind.url_validator(),
            ctx.allow_insecure_http,
            kind.artefact(),
        )?;
        let hash = prefetch_hash(ctx.nix, ctx.layout, &url, false, None)?;
        Ok((url, hash))
    })
}

/// Build a `<backend>:resolve` package from its EXISTING pin only — for the gc keep path, which must
/// never run the resolve command or touch the network. Returns `None` when the package is not yet
/// pinned (nothing has been built to keep), so gc skips it rather than resolving.
pub(crate) fn provision_resolve_pinned(
    kind: &dyn Kind,
    ctx: &Ctx,
    name: &str,
    libs: &[String],
) -> io::Result<Option<(PathBuf, PathBuf)>> {
    let project_id = super::binds::project_runtime_id(ctx.project)?;
    let Some(pin) =
        pins(ctx.layout, project_id.as_str(), &lock_file(kind)).remove(&resolve_key(name))
    else {
        return Ok(None);
    };
    build_pinned(
        kind,
        ctx,
        project_id.as_str(),
        name,
        &pin.url,
        &pin.hash,
        libs,
    )
    .map(Some)
}

/// The outcome of re-resolving one declared reference during `sbx upgrade`. `url` is the lock *key*
/// (the declared locator, or `resolve:<name>`) rather than the resolved download URL, so the summary
/// names each entry the way the config declared it.
pub(crate) enum Upgrade {
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

/// Re-resolve a project's declared references for one backend and rewrite its per-project lock —
/// pinning new ones, rolling changed ones forward, and pruning entries no longer declared (so a
/// removed-then-readded package never reuses a stale pin). Resolution is best-effort per reference:
/// a failure keeps the prior pin and is reported, and the lock is reconciled once at the end.
///
/// That reconcile applies **only what this roll decided** — the entries it resolved, and the entries
/// it pruned — to the lock as it stands when the roll finishes, the way `nixhub::provision` persists
/// a freshly-resolved pin. It is not a write-back of the snapshot read at the top: every resolution
/// below is a network round-trip (a release query, a resolve command in a cage, an artefact
/// prefetch), so a cold launch of the same project has a wide window in which to mint a pin of its
/// own, and a whole-map write of the pre-network snapshot would drop it — the package would then
/// re-resolve and re-pin on the next launch, a second trust-on-first-use and a network round-trip on
/// a path documented as offline.
///
/// Every resolution here runs with `fresh` set, which is what makes this an *upgrade* rather than a
/// re-read: it bypasses nix's metadata cache, so a locator's source query sees a new GitHub release
/// or a new apt index entry instead of the copy the last hour's query left behind. The provisioning
/// path deliberately does the opposite. A `<backend>:resolve` whose command prints the URL already
/// pinned keeps that pin's hash rather than fetching the artefact again, so a change of URL is what
/// makes it look at the bytes at all: content that moves behind an unchanged URL is never seen.
///
/// `cage` is the sandbox resolve commands run in. When it is `None` (the host cannot sandbox), a
/// resolver reference is reported as failed rather than silently frozen at its current pin.
pub(crate) fn upgrade(
    kind: &dyn Kind,
    nix: &Path,
    layout: &Layout,
    project: &Path,
    cfg: &crate::config::Resolved,
    cage: Option<&super::resolve::ResolveCage>,
) -> io::Result<Vec<Upgrade>> {
    let project_id = super::binds::project_runtime_id(project)?;
    let project_id = project_id.as_str();
    let lock_file = lock_file(kind);
    // One walk of the layers yields both the trusted roll set and the trust-agnostic prune universe.
    let Declared {
        trusted: declared,
        all: universe,
    } = declared(kind, cfg);
    let system = super::current_system();
    // The lock as it stood before any network work: what each reference is compared against, and
    // what the reconcile at the end treats as this roll's (by then possibly stale) knowledge.
    let snapshot = pins(layout, project_id, &lock_file);
    let mut outcomes = Vec::new();
    // This roll's decisions, applied to the on-disk lock once the resolutions are done.
    let mut resolved_pins: BTreeMap<String, Pin> = BTreeMap::new();
    let mut pruned: Vec<(String, Pin)> = Vec::new();

    // Prune entries whose locator is no longer declared (across ALL layers regardless of trust, so a
    // withheld project's still-declared package keeps its pin rather than being silently unpinned).
    for (key, pin) in &snapshot {
        if !universe.contains(key.as_str()) {
            pruned.push((key.clone(), pin.clone()));
            outcomes.push(Upgrade::Pruned { url: key.clone() });
        }
    }

    for reference in &declared {
        let key = reference.key();
        let previous = snapshot.get(&key).cloned();
        let resolved = match reference {
            // A locator: always re-resolve, since its source can move (a `latest` alias, a new
            // release, a new apt index entry) and even a fixed URL's content can change.
            Ref::Locator(locator) => {
                kind.resolve_source(nix, layout, locator, &system, true, cfg.allow_insecure_http)
            }
            // A resolver: re-run its command for the concrete URL. If it equals the stored pin's URL,
            // reuse the pinned hash rather than prefetching the (large) artefact again.
            Ref::Resolve { name, command } => match cage {
                None => Err(io::Error::other(
                    "cannot run the resolve command (no usable sandbox on this host)",
                )),
                Some(cage) => match super::resolve::resolve_url(
                    cage,
                    name,
                    command,
                    kind.url_validator(),
                    cfg.allow_insecure_http,
                    kind.artefact(),
                ) {
                    Ok(url) => match &previous {
                        Some(pin) if pin.url == url => Ok((url, pin.hash.clone())),
                        _ => prefetch_hash(nix, layout, &url, true, None).map(|h| (url, h)),
                    },
                    Err(e) => Err(e),
                },
            },
        };
        match resolved {
            Ok((url, hash)) => {
                let outcome = match &previous {
                    Some(pin) if pin.hash == hash => Upgrade::Unchanged {
                        url: key.clone(),
                        hash: hash.clone(),
                    },
                    Some(pin) => Upgrade::Rolled {
                        url: key.clone(),
                        from: pin.hash.clone(),
                        to: hash.clone(),
                    },
                    None => Upgrade::Pinned {
                        url: key.clone(),
                        hash: hash.clone(),
                    },
                };
                resolved_pins.insert(key, Pin { hash, url });
                outcomes.push(outcome);
            }
            Err(e) => outcomes.push(Upgrade::Failed {
                url: key,
                error: e.to_string(),
            }),
        }
    }

    let mut disk = pins(layout, project_id, &lock_file);
    for (key, previous) in pruned {
        // Compare and swap, key by key. An entry that changed while this roll resolved was written
        // by a process whose config read is newer than this one's, so its pin outranks this roll's
        // "no longer declared" — only an entry still exactly as the snapshot found it is pruned.
        if disk.get(&key) == Some(&previous) {
            disk.remove(&key);
        }
    }
    // A resolution that just happened is the freshest statement about its key there is, so it lands
    // over whatever the entry currently holds. Every key this roll decided nothing about — one whose
    // resolution failed, one another process pinned meanwhile — is left exactly as found.
    disk.extend(resolved_pins);
    write_pins(layout, project_id, &lock_file, &disk)?;
    Ok(outcomes)
}

/// `sbx upgrade <backend>`: roll a project's declared packages forward. Builds the resolver sandbox
/// only when a `<backend>:resolve` package is actually declared, so a locator-only project keeps the
/// cheap path (no base-userland build), then delegates to [`upgrade`].
///
/// When the sandbox is needed but cannot be built, the `None` is handed to [`upgrade`] rather than
/// short-circuiting: the resolver references are then reported as failed, which is the fail-closed
/// reading. Skipping them would leave a project looking rolled while its resolvers stood still.
pub(crate) fn upgrade_project(
    kind: &dyn Kind,
    nix: &Path,
    layout: &Layout,
    project: &Path,
    cfg: &crate::config::Resolved,
) -> io::Result<Vec<Upgrade>> {
    let held = if has_resolve_ref(kind, cfg) {
        super::resolve::UpgradeCage::build(nix, layout, project, cfg)
    } else {
        None
    };
    let cage = held.as_ref().map(super::resolve::UpgradeCage::as_cage);
    upgrade(kind, nix, layout, project, cfg, cage.as_ref())
}

#[cfg(test)]
mod tests {

    /// The offline invariant, stated by `provision_resolve`'s docstring and until now pinned by
    /// nothing: on a warm launch the pinned `(url, hash)` is reused and the mint — the resolve
    /// command, the release query, the prefetch — is **not run**. A regression here would put a
    /// network call on every launch of an already-pinned package.
    #[test]
    fn a_warm_pin_is_reused_without_running_the_mint() {
        use std::sync::atomic::{AtomicBool, Ordering};
        let mut lock = BTreeMap::new();
        lock.insert(
            "deb:demo".to_string(),
            Pin {
                hash: "sha256-AAAA".to_string(),
                url: "https://e/demo_1.0_amd64.deb".to_string(),
            },
        );
        let ran = AtomicBool::new(false);
        let ((url, hash), minted) = super::pinned_or_mint(&mut lock, "deb:demo", || {
            ran.store(true, Ordering::SeqCst);
            Ok(("https://e/other.deb".to_string(), "sha256-BBBB".to_string()))
        })
        .expect("a warm pin resolves");
        assert!(!ran.load(Ordering::SeqCst), "the mint ran on a warm pin");
        assert_eq!(url, "https://e/demo_1.0_amd64.deb");
        assert_eq!(hash, "sha256-AAAA");
        // Nothing was minted, so the caller must not rewrite the lock.
        assert!(!minted);
        assert_eq!(lock.len(), 1);
    }

    /// The other half: a cold key runs the mint exactly once, records it, and reports that the lock
    /// is now worth writing back.
    #[test]
    fn a_cold_pin_mints_once_and_records_it() {
        let mut lock: BTreeMap<String, Pin> = BTreeMap::new();
        let mut calls = 0usize;
        let ((url, hash), minted) = super::pinned_or_mint(&mut lock, "deb:demo", || {
            calls += 1;
            Ok(("https://e/demo.deb".to_string(), "sha256-CCCC".to_string()))
        })
        .expect("a cold pin mints");
        assert_eq!(calls, 1);
        assert!(minted);
        assert_eq!(url, "https://e/demo.deb");
        assert_eq!(hash, "sha256-CCCC");
        assert_eq!(lock["deb:demo"].url, "https://e/demo.deb");
        assert_eq!(lock["deb:demo"].hash, "sha256-CCCC");
    }

    /// Minting is the slow part — a download and a hash, or a resolve command in a cage — so a
    /// concurrent cold provision of the same project has a wide window to pin a *different*
    /// package while this one works. Writing back the snapshot taken before the mint dropped that
    /// pin, and the package then re-resolved and re-pinned on the next launch: a second
    /// trust-on-first-use and a network round-trip on a path documented as offline. The write is
    /// additive against what is on disk at the moment it happens.
    #[test]
    fn a_pin_written_after_a_slow_mint_keeps_one_a_concurrent_launch_recorded() {
        let tmp = TmpDir::new();
        let layout = crate::store::Layout::under(tmp.path());
        let lock_file = "prebuilt.lock";
        let id = "proj";
        std::fs::create_dir_all(lock_path(&layout, id, lock_file).parent().unwrap()).unwrap();

        // This launch's snapshot: empty, taken before its mint.
        let stale: BTreeMap<String, Pin> = BTreeMap::new();

        // A concurrent launch pins a different package while the mint is still running.
        let mut theirs: BTreeMap<String, Pin> = BTreeMap::new();
        theirs.insert(
            "deb:other".to_string(),
            Pin {
                url: "https://e/other.deb".to_string(),
                hash: "sha256-OOOO".to_string(),
            },
        );
        write_pins(&layout, id, lock_file, &theirs).unwrap();

        // This launch's mint completes and records only its own key against the current disk.
        let mut mine = stale.clone();
        mine.insert(
            "deb:demo".to_string(),
            Pin {
                url: "https://e/demo.deb".to_string(),
                hash: "sha256-DDDD".to_string(),
            },
        );
        let mut disk = pins(&layout, id, lock_file);
        disk.insert("deb:demo".to_string(), mine["deb:demo"].clone());
        write_pins(&layout, id, lock_file, &disk).unwrap();

        let back = pins(&layout, id, lock_file);
        assert_eq!(
            back["deb:demo"].hash, "sha256-DDDD",
            "this launch's pin is recorded"
        );
        assert_eq!(
            back["deb:other"].hash, "sha256-OOOO",
            "the concurrent launch's pin survives — writing the pre-mint snapshot would drop it"
        );
    }
    use super::super::appimage::AppImage;
    use super::super::deb::Deb;
    use super::super::tarball::Tarball;
    use super::*;
    use crate::testutil::{TmpDir, resolved};

    /// A backend that records what [`upgrade`] asked of it and answers with a canned pin, so the
    /// generic roll can be exercised without a nix engine or a network. It borrows `tarball:`'s
    /// config shape (the plainest of the three) and nothing else.
    #[derive(Default)]
    struct Recording {
        fresh: std::cell::Cell<Option<bool>>,
        /// Run once, inside the first source resolution, standing in for whatever another process
        /// writes to the lock during the network work a roll does.
        meanwhile: std::cell::Cell<Option<Box<dyn FnOnce()>>>,
    }

    const RECORDED_HASH: &str = "sha256-jBGtMS5lpJWVXe+KzQgRSho8BcaEzGvONzIbAWled0w=";

    impl Kind for Recording {
        fn name(&self) -> &'static str {
            "recording"
        }
        fn artefact(&self) -> &'static str {
            "`.tar.gz`"
        }
        fn url_validator(&self) -> fn(&str, bool) -> bool {
            crate::config::is_valid_tarball_url
        }
        fn resolve_source(
            &self,
            _nix: &Path,
            _layout: &Layout,
            locator: &str,
            _system: &str,
            fresh: bool,
            _allow_insecure_http: bool,
        ) -> io::Result<(String, String)> {
            self.fresh.set(Some(fresh));
            if let Some(meanwhile) = self.meanwhile.take() {
                meanwhile();
            }
            Ok((locator.to_string(), RECORDED_HASH.to_string()))
        }
        fn derivation_expr(
            &self,
            _nixpkgs: &str,
            _system: &str,
            _name: &str,
            _url: &str,
            _hash: &str,
            _libs: &[String],
        ) -> String {
            unreachable!("upgrade never builds a derivation")
        }
        /// Reads a config exactly as `tarball:` does, so the three lists derived from it are the real
        /// ones — the fake diverges from a production backend only where a test needs it to.
        fn form(&self, package: &crate::config::Package) -> Option<Form> {
            Tarball.form(package)
        }
    }

    #[test]
    fn a_roll_resolves_past_the_fetch_cache_and_records_the_pin() {
        let data = TmpDir::new();
        let project = TmpDir::new();
        let layout = Layout::under(data.path());
        let kind = Recording::default();
        let url = "https://example.com/demo-app.tar.gz";
        let cfg = resolved(
            vec![crate::config::Package {
                name: "demo-app".to_string(),
                backend: crate::config::Backend::Tarball(url.to_string()),
                state: crate::trust::TrustState::Trusted,
                libs: Vec::new(),
            }],
            vec![],
        );

        let outcomes = upgrade(
            &kind,
            Path::new("/nonexistent/nix"),
            &layout,
            project.path(),
            &cfg,
            None,
        )
        .expect("the roll writes its lock");

        // `fresh` is what separates an upgrade from a re-read: without it a backend's source query
        // answers from nix's metadata cache and a no-op `sbx upgrade` stops seeing new releases.
        // Nothing else fails when it flips, which is why it is asserted here rather than trusted.
        assert_eq!(
            kind.fresh.get(),
            Some(true),
            "an upgrade must resolve past the fetch cache"
        );
        assert!(
            matches!(outcomes.as_slice(), [Upgrade::Pinned { url: u, hash }]
                     if u == url && hash == RECORDED_HASH),
            "a first roll pins the declared locator"
        );

        let id = super::super::binds::project_runtime_id(project.path()).unwrap();
        let lock = pins(&layout, &id, &lock_file(&kind));
        assert_eq!(
            lock.get(url).map(|p| p.hash.as_str()),
            Some(RECORDED_HASH),
            "the pin reached the lock the backend's name spells"
        );
    }

    /// Every resolution in a roll is a network round-trip — a release query, a resolve command in a
    /// cage, a whole artefact prefetch — so a cold launch of the same project has a wide window in
    /// which to mint a pin of its own. Writing the snapshot read before that work back over the lock
    /// dropped the launch's pin, and the package then re-resolved and re-pinned on the next launch:
    /// a second trust-on-first-use, and a network round-trip on a path documented as offline. What
    /// the roll writes is what it decided, applied to the lock as it stands when it finishes.
    #[test]
    fn a_roll_keeps_a_pin_recorded_while_it_was_resolving() {
        let data = TmpDir::new();
        let project = TmpDir::new();
        let layout = Layout::under(data.path());
        let id = super::super::binds::project_runtime_id(project.path()).unwrap();
        let lock_name = lock_file(&Recording::default());
        let url = "https://example.com/demo-app.tar.gz";
        let gone = "https://example.com/gone.tar.gz";
        let cfg = resolved(
            vec![
                pkg(
                    "demo-app",
                    crate::config::Backend::Tarball(url.to_string()),
                    true,
                ),
                pkg(
                    "other-app",
                    crate::config::Backend::TarballResolve {
                        command: vec!["print-the-newest-url".to_string()],
                    },
                    true,
                ),
            ],
            vec![],
        );

        // An entry nothing declares any more, and nothing touches while the roll runs.
        let stale = BTreeMap::from([(
            gone.to_string(),
            Pin {
                hash: RECORDED_HASH.to_string(),
                url: gone.to_string(),
            },
        )]);
        write_pins(&layout, &id, &lock_name, &stale).unwrap();

        // A cold launch of the same project mints `other-app`'s pin while this roll is off resolving
        // `demo-app`, and records it the way `provision_pinned` does: additively, against the lock as
        // it stands at that moment.
        let kind = Recording::default();
        let concurrent = {
            let layout = layout.clone();
            let id = id.clone();
            let lock_name = lock_name.clone();
            move || {
                let mut disk = pins(&layout, &id, &lock_name);
                disk.insert(
                    resolve_key("other-app"),
                    Pin {
                        hash: "sha256-OOOO".to_string(),
                        url: "https://example.com/other-app.tar.gz".to_string(),
                    },
                );
                write_pins(&layout, &id, &lock_name, &disk).unwrap();
            }
        };
        kind.meanwhile.set(Some(Box::new(concurrent)));

        let outcomes = upgrade(
            &kind,
            Path::new("/nonexistent/nix"),
            &layout,
            project.path(),
            &cfg,
            None,
        )
        .expect("the roll reconciles its lock");

        // No sandbox on this host, so the resolver could not be re-run: the roll decided nothing
        // about that key, which is what leaves the launch's pin the only statement about it.
        assert!(
            outcomes
                .iter()
                .any(|o| matches!(o, Upgrade::Failed { url, .. }
                                             if url == &resolve_key("other-app"))),
            "the resolver reference must be reported failed"
        );
        let after = pins(&layout, &id, &lock_name);
        assert_eq!(
            after.get(url).map(|p| p.hash.as_str()),
            Some(RECORDED_HASH),
            "the roll records the pin it resolved"
        );
        assert_eq!(
            after
                .get(&resolve_key("other-app"))
                .map(|p| p.hash.as_str()),
            Some("sha256-OOOO"),
            "the concurrent launch's pin survives — writing the pre-network snapshot would drop it"
        );
        assert!(
            !after.contains_key(gone),
            "an entry no longer declared, and unchanged since the snapshot, is still pruned"
        );
    }

    #[test]
    fn a_resolver_with_no_sandbox_is_reported_failed_rather_than_left_standing() {
        let data = TmpDir::new();
        let project = TmpDir::new();
        let layout = Layout::under(data.path());
        let kind = Recording::default();
        let cfg = resolved(
            vec![crate::config::Package {
                name: "demo-app".to_string(),
                backend: crate::config::Backend::TarballResolve {
                    command: vec!["sh".into(), "-c".into(), "echo https://e/a.tar.gz".into()],
                },
                state: crate::trust::TrustState::Trusted,
                libs: Vec::new(),
            }],
            vec![],
        );

        let outcomes = upgrade(
            &kind,
            Path::new("/nonexistent/nix"),
            &layout,
            project.path(),
            &cfg,
            None,
        )
        .expect("the roll still rewrites its lock");

        // A host that cannot sandbox cannot re-run a resolve command. Reporting that as a failure is
        // the fail-closed reading; skipping the reference instead would leave the summary looking
        // rolled while the package stood still at whatever it was last pinned to.
        assert!(
            matches!(outcomes.as_slice(), [Upgrade::Failed { url, .. }]
                     if url == &resolve_key("demo-app")),
            "a resolver must be reported, not silently skipped: got {} outcome(s)",
            outcomes.len()
        );
        assert_eq!(
            kind.fresh.get(),
            None,
            "a resolver never reaches the locator resolver"
        );
    }

    /// One package of every prebuilt form, declared in an order that matches neither walk, so a test
    /// reading the walks back cannot pass by echoing the declaration order.
    fn one_of_each_form() -> Vec<crate::config::Package> {
        use crate::config::Backend;
        let command = || vec!["print-the-newest-url".to_string()];
        [
            (
                "one",
                Backend::Tarball("https://example.com/x.tar.gz".into()),
            ),
            ("two", Backend::Deb("https://example.com/x.deb".into())),
            (
                "three",
                Backend::AppImage("https://example.com/x.AppImage".into()),
            ),
            ("four", Backend::AppImageResolve { command: command() }),
            ("five", Backend::TarballResolve { command: command() }),
            ("six", Backend::DebResolve { command: command() }),
        ]
        .into_iter()
        .map(|(name, backend)| pkg(name, backend, true))
        .collect()
    }

    fn pkg(name: &str, backend: crate::config::Backend, trusted: bool) -> crate::config::Package {
        crate::config::Package {
            name: name.into(),
            backend,
            state: if trusted {
                crate::trust::TrustState::Trusted
            } else {
                crate::trust::TrustState::Untrusted
            },
            libs: Vec::new(),
        }
    }

    /// The trust filter lives in the two admitted-package lists and nowhere else — [`Kind::lock_key`]
    /// deliberately answers for untrusted packages too. These two tests hold that line from the
    /// admitted side: a package the config withheld must not reach the launcher. They run through
    /// `Tarball`, whose [`Kind::form`] is the same three-line dispatch its two siblings implement.
    #[test]
    fn the_direct_list_keeps_only_trusted_packages_of_that_form() {
        let pkgs = [
            pkg(
                "app",
                crate::config::Backend::Tarball("https://example.com/app.tar.gz".into()),
                true,
            ),
            // a nix package belongs to no prebuilt backend
            pkg(
                "node",
                crate::config::Backend::Nix("nodejs_20".into()),
                true,
            ),
            pkg(
                "evil",
                crate::config::Backend::Tarball("https://example.com/evil.tar.gz".into()),
                false,
            ),
            // the resolve form is not a direct locator
            pkg(
                "rz",
                crate::config::Backend::TarballResolve {
                    command: vec!["print-the-newest-url".into()],
                },
                true,
            ),
        ];
        assert_eq!(
            Tarball.packages(&pkgs),
            vec![(
                "app".to_string(),
                "https://example.com/app.tar.gz".to_string()
            )],
            "only the trusted DIRECT locator, keyed by name; nix, resolve and untrusted excluded"
        );
    }

    #[test]
    fn the_resolver_list_keeps_only_trusted_packages_of_that_form() {
        let command = || vec!["print-the-newest-url".to_string()];
        let pkgs = [
            pkg(
                "keep",
                crate::config::Backend::TarballResolve { command: command() },
                true,
            ),
            pkg(
                "direct",
                crate::config::Backend::Tarball("https://example.com/app.tar.gz".into()),
                true,
            ),
            // withheld here is what keeps an untrusted project's command from ever being executed
            pkg(
                "drop",
                crate::config::Backend::TarballResolve { command: command() },
                false,
            ),
        ];
        assert_eq!(
            Tarball.resolve_packages(&pkgs),
            vec![("keep".to_string(), command())],
            "only the trusted resolver (name, command); the direct form and untrusted excluded"
        );
    }

    /// The two walk orders are what the launcher provisions through, and neither property they carry
    /// is checked by the compiler: a backend missing from an array would simply never be provisioned,
    /// and a reordered array would silently change which of two packages shipping the same binary name
    /// wins on `PATH`. One assertion per array pins both — the set and the sequence.
    #[test]
    fn the_two_walk_orders_cover_every_backend_and_hold_their_path_precedence() {
        let packages = one_of_each_form();
        let walk = |order: [&dyn Kind; 4], resolve: bool| -> Vec<String> {
            order
                .into_iter()
                .flat_map(|kind| {
                    let names = if resolve {
                        kind.resolve_packages(&packages)
                            .into_iter()
                            .map(|(name, _)| name)
                            .collect::<Vec<_>>()
                    } else {
                        kind.packages(&packages)
                            .into_iter()
                            .map(|(name, _)| name)
                            .collect::<Vec<_>>()
                    };
                    names
                        .into_iter()
                        .map(|name| format!("{}:{name}", kind.name()))
                        .collect::<Vec<_>>()
                })
                .collect()
        };
        assert_eq!(
            walk(DIRECT_ORDER, false),
            ["deb:two", "appimage:three", "tarball:one"]
        );
        assert_eq!(
            walk(RESOLVE_ORDER, true),
            ["tarball:five", "deb:six", "appimage:four"]
        );
    }

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
    fn prefetch_hash_folds_the_cause_when_quiet_and_names_the_step_when_loud() {
        use std::os::unix::fs::PermissionsExt;

        let data = TmpDir::new();
        let layout = Layout::under(data.path());
        // A stand-in for the engine, failing the way nix does: a retry `warning:` ahead of the one
        // `error:` line carrying the cause. Both arms run it, so the framing is the only variable.
        // The loud arm inherits its `stderr`, so these two lines reach the terminal during a run.
        let nix = data.path().join("fake-nix");
        std::fs::write(
            &nix,
            "#!/bin/sh\n\
             echo \"warning: unable to download 'https://example.com/demo-app.tar.gz': \
             retrying (attempt 1/5)\" >&2\n\
             echo \"error: unable to download 'https://example.com/demo-app.tar.gz': \
             HTTP error 404\" >&2\n\
             exit 1\n",
        )
        .expect("the stand-in engine is written");
        std::fs::set_permissions(&nix, std::fs::Permissions::from_mode(0o755))
            .expect("the stand-in engine is made executable");
        let url = "https://example.com/demo-app.tar.gz";

        // An `sbx upgrade` re-resolve captures stderr, so its summary prints the cause in place of
        // the fetch's own multi-line output.
        let quiet =
            prefetch_hash(&nix, &layout, url, true, None).expect_err("the stand-in engine fails");
        assert_eq!(
            quiet.to_string(),
            "unable to download 'https://example.com/demo-app.tar.gz': HTTP error 404"
        );

        // A first launch has already streamed that output to the terminal, so its error names the
        // step alone rather than repeating what the user just read.
        let loud =
            prefetch_hash(&nix, &layout, url, false, None).expect_err("the stand-in engine fails");
        assert_eq!(loud.to_string(), "nix store prefetch-file failed");
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
    fn launcher_wrap_takes_a_named_bin_before_scanning_the_archive_root() {
        // The shape this pass exists for: a vendor `.deb` unpacking to an FHS tree, whose program is
        // `usr/bin/<name>` beside a CLI and an updater. Nothing sits at the archive root, and three
        // executables sit below it, so the root scan would refuse on both counts — the declared name
        // is what makes the choice unambiguous.
        let wrap = launcher_wrap("demo-app", "/lib");
        let bundle = wrap.find("resources/app.asar").expect("bundle probe");
        let named = wrap.find("named=").expect("named-bin probe");
        let root_scan = wrap.find("cands=").expect("root scan");
        assert!(
            bundle < named && named < root_scan,
            "order must be bundle, then named bin, then root scan:\n{wrap}"
        );
        assert!(wrap.contains("-path '*/bin/demo-app'"));
        // The wrapper's own destination is excluded: an archive already unpacking to `bin/<name>`
        // would otherwise have makeWrapper overwrite the binary it is wrapping.
        assert!(
            wrap.contains("! -path \"$out/bin/demo-app\""),
            "the named-bin search must exclude the wrapper's own path:\n{wrap}"
        );
        assert!(wrap.contains("| wc -l)\" -eq 1 ]"));
    }

    #[test]
    fn launcher_wrap_points_every_dlopen_lookup_at_the_build_inputs() {
        // The three paths nothing else resolves: GStreamer elements, GIO modules (glib-networking's
        // TLS backend — no HTTPS without it) and the XDG data dirs holding GSettings schemas. All
        // are looked up by path at runtime, so a package present in `buildInputs` is still invisible
        // unless the wrapper says where it is.
        let wrap = launcher_wrap("demo-app", "/lib");
        for (var, expr) in [
            ("GST_PLUGIN_SYSTEM_PATH_1_0", GST_SEARCH_PATH),
            ("GIO_EXTRA_MODULES", GIO_SEARCH_PATH),
            ("XDG_DATA_DIRS", XDG_DATA_SEARCH_PATH),
        ] {
            assert!(
                wrap.contains(&format!("--prefix {var} : ")),
                "{var} missing"
            );
            assert!(wrap.contains(expr), "{var} points nowhere");
        }
        assert!(!wrap.contains('@'), "unfilled placeholder in:\n{wrap}");
    }

    #[test]
    fn the_lib_set_unions_the_builtin_one_with_the_packages_own_and_dedups() {
        // A package's own attributes come after the built-in set, and an attribute named in both
        // lands once: the joined string goes straight into the derivation, so a duplicate would
        // change the expression (hence the store path) for no reason.
        let set = lib_set(&["webkitgtk_4_1".into(), "gtk3".into(), "libsoup_3".into()]);
        let names: Vec<&str> = set.split(' ').collect();
        assert_eq!(names.iter().filter(|n| **n == "gtk3").count(), 1);
        for builtin in ELECTRON_LIBS {
            assert!(names.contains(builtin), "{builtin} missing from {set}");
        }
        assert!(names.ends_with(&["webkitgtk_4_1", "libsoup_3"]));
        // No declaration is the common case, and it must leave the built-in set exactly as it was.
        assert_eq!(lib_set(&[]), ELECTRON_LIBS.join(" "));
    }

    /// Run the launcher snippet against a real directory tree and report what it wrapped.
    ///
    /// The assertions above pin the snippet's *text*; this runs it. `makeWrapper` is a shell
    /// function printing its source and destination, and the nix interpolations are filled with
    /// plain paths — everything else (the `find` passes, the counting, the refusals) is the shipped
    /// snippet verbatim, so a layout that breaks here breaks a real build.
    fn wrap_on(tree: &std::path::Path, files: &[(&str, bool)]) -> Result<String, String> {
        wrap_tree(tree, files, None)
    }

    /// [`wrap_on`] plus one symlink, for the layout whose `bin/<name>` points into the tree.
    fn wrap_on_with_link(
        tree: &std::path::Path,
        files: &[(&str, bool)],
        link: &str,
        target: &str,
    ) -> Result<String, String> {
        wrap_tree(tree, files, Some((link, target)))
    }

    fn wrap_tree(
        tree: &std::path::Path,
        files: &[(&str, bool)],
        link: Option<(&str, &str)>,
    ) -> Result<String, String> {
        use std::os::unix::fs::PermissionsExt;
        for (rel, executable) in files {
            let path = tree.join(rel);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(&path, b"#!/bin/sh\n").unwrap();
            let mode = if *executable { 0o755 } else { 0o644 };
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
        }
        if let Some((rel, target)) = link {
            let path = tree.join(rel);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::os::unix::fs::symlink(target, &path).unwrap();
        }
        let snippet = launcher_wrap("demo-app", "/lib")
            .replace(GST_SEARCH_PATH, "/gst")
            .replace(GIO_SEARCH_PATH, "/gio")
            .replace(XDG_DATA_SEARCH_PATH, "/share");
        let script = format!(
            "set -e\nout={}\nmakeWrapper() {{ echo \"WRAPPED $1\"; }}\n{snippet}\n",
            tree.display()
        );
        let out = std::process::Command::new("bash")
            .arg("-c")
            .arg(&script)
            .output()
            .expect("bash runs");
        if out.status.success() {
            Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
        } else {
            Err(String::from_utf8_lossy(&out.stderr).trim().to_string())
        }
    }

    #[test]
    fn the_launcher_snippet_resolves_each_real_layout_and_refuses_the_ambiguous_ones() {
        let tmp = crate::testutil::TmpDir::new();

        // (a) Electron bundle: the launcher sits beside `resources/`, and the Chromium helper next
        // to it must not be picked.
        let electron = tmp.join("electron");
        assert_eq!(
            wrap_on(
                &electron,
                &[
                    ("opt/demo/resources/app.asar", false),
                    ("opt/demo/demo-app", true),
                    ("opt/demo/chrome-sandbox", true),
                ]
            ),
            Ok(format!("WRAPPED {}/opt/demo/demo-app", electron.display()))
        );

        // (b) The shape this pass was added for: a vendor `.deb` FHS tree. Nothing at the root and
        // three executables below it, so the root scan alone would refuse — the declared name picks
        // the shell, not the CLI beside it.
        let fhs = tmp.join("fhs");
        assert_eq!(
            wrap_on(
                &fhs,
                &[
                    ("usr/bin/demo-app", true),
                    ("usr/bin/demo-app-cli", true),
                    ("usr/lib/demo/updater", true),
                ]
            ),
            Ok(format!("WRAPPED {}/usr/bin/demo-app", fhs.display()))
        );

        // (c) The plain archive: one executable at the root, which is still what gets wrapped.
        let bare = tmp.join("bare");
        assert_eq!(
            wrap_on(&bare, &[("demo-app", true), ("README", false)]),
            Ok(format!("WRAPPED {}/demo-app", bare.display()))
        );

        // (d) No bundle, no `bin/demo-app`, nothing at the root: refused, and the message names all
        // three shapes it looked for rather than guessing at one of the binaries below.
        let ambiguous = tmp.join("ambiguous");
        let err = wrap_on(
            &ambiguous,
            &[("usr/bin/other", true), ("usr/bin/another", true)],
        )
        .expect_err("an unresolvable tree must fail the build");
        assert!(err.contains("no executable at the archive root"), "{err}");

        // (e) An archive whose own root is an FHS tree, so its program lands on the wrapper's own
        // destination. Wrapping it in place would have makeWrapper overwrite the binary it wraps,
        // so the program is moved aside first and wrapped from there — the destination is freed,
        // not clobbered.
        let collide = tmp.join("collide");
        assert_eq!(
            wrap_on(
                &collide,
                &[("bin/demo-app", true), ("share/man/man1/demo-app.1", false)]
            ),
            Ok(format!("WRAPPED {}/libexec/demo-app", collide.display()))
        );
        assert!(
            !collide.join("bin/demo-app").exists(),
            "the program must be moved off the wrapper's destination, not copied"
        );

        // (f) The same shape, but `bin/<name>` is a symlink into the tree: the link is resolved
        // rather than moved, since the wrapper may replace a link without touching its target.
        let linked = tmp.join("linked");
        std::fs::create_dir_all(linked.join("bin")).unwrap();
        assert_eq!(
            wrap_on_with_link(
                &linked,
                &[("libexec/demo-app", true)],
                "bin/demo-app",
                "../libexec/demo-app",
            ),
            Ok(format!("WRAPPED {}/libexec/demo-app", linked.display()))
        );
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
            libs: Vec::new(),
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

    /// Every backend's derivation is text until nix reads it, and nothing here asked nix whether it
    /// would: see [`crate::testutil::assert_nix_parses`] for what a `contains` assertion leaves
    /// standing and why `--parse` is the depth that answers it.
    ///
    /// Driven by [`DIRECT_ORDER`] rather than a list written here, so a fifth backend is covered by
    /// existing on the same terms as the other four.
    #[test]
    fn every_backend_emits_an_expression_nix_accepts() {
        let Some(instantiate) = crate::testutil::nix_instantiate() else {
            skip_incapable!("skipping derivation parse: no nix-instantiate on this host");
            return;
        };
        // A URL carrying the characters the validators admit beyond alphanumerics, so the quoting is
        // exercised on the shapes a real release index produces rather than on a tidy one.
        const URL: &str = "https://example.com/d/v1.2.3/demo~app_x86_64-linux%2Ebin";
        const HASH: &str = "sha256-jBGtMS5lpJWVXe+KzQgRSho8BcaEzGvONzIbAWled0w=";

        for kind in DIRECT_ORDER {
            // Both shapes of the library list: an empty `buildInputs` is its own syntax case.
            for libs in [Vec::new(), vec!["gtk3".to_string(), "nss".to_string()]] {
                let expr = kind.derivation_expr(
                    "github:NixOS/nixpkgs/abc",
                    "x86_64-linux",
                    "demo-app",
                    URL,
                    HASH,
                    &libs,
                );
                crate::testutil::assert_nix_parses(
                    &instantiate,
                    &format!("{} ({} libs)", kind.name(), libs.len()),
                    &expr,
                );
            }
        }
    }
}
