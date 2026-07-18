//! Shared building blocks for the two "prebuilt host-side desktop package" backends — `deb:` and
//! `appimage:`. Both fetch a prebuilt Electron/Chromium bundle from an `https://` source, unpack it
//! (no build script runs — safe to evaluate host-side, unlike an arbitrary `flake:`), autoPatchelf
//! the ELF binaries against a curated library set, and wrap the launcher located by its
//! `resources/app.asar` signature. Only the *unpack* differs between the two backends (a `dpkg-deb`
//! data tarball vs an AppImage squashfs); everything drift-dangerous — the library set, the
//! app-locating/launcher-wrapping install phase, the fetch-to-hash helper, the release-asset arch
//! tokens — lives here so the two backends cannot silently diverge.
//!
//! **Why unpack at BUILD time, never at runtime.** `wrapType2`, `appimage-run`, and running the raw
//! `.AppImage` all create a mount/user namespace at runtime (a `bwrap` or a FUSE self-mount). The
//! cage's seccomp denylist EPERMs `unshare`/`mount`/`pivot_root` and arg-filters
//! `clone(CLONE_NEWUSER|CLONE_NEWNS)`, and the FUSE mount is blocked too — so every runtime-namespace
//! approach is a hard block in-cage, not merely inelegant. Build-time extraction (`unsquashfs` /
//! `dpkg-deb`, no runtime namespace op) plus a plain autoPatchelf'd ELF is the only mechanism that
//! runs inside the cage, which is exactly why the `.deb` approach ports to the AppImage.

use crate::store::{self, Layout};
use std::io;
use std::path::Path;
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

/// The generic Electron install phase (a shell snippet), embedded by each backend's generated
/// derivation into its `installPhase` after the bundle has been copied into `$out`. It locates the
/// app directory by its `resources/` signature — either a packed `resources/app.asar` file or, for an
/// asar-less build (modern VS Code forks such as Cursor ship the app as a loose `resources/app/`
/// directory), the `resources/app` directory itself; both resolve to the same bundle root — and wraps
/// the launcher, the executable beside it that is not a `.so`, a Chromium helper, or the AppImage
/// `AppRun` script. Excluding `AppRun` is load-bearing for an AppImage (its squashfs carries an
/// `AppRun` launcher that sorts *before* the real binary) and harmless for a `.deb` (which has no
/// `AppRun`), so one snippet serves both. Two placeholders: `@NAME@` (the wrapped launcher name) and
/// `@LDPREFIX@` (the `LD_LIBRARY_PATH` prefix value — a backend chooses whether to prepend the bundle
/// root for sibling `.so`s).
pub(crate) const ELECTRON_WRAP: &str = r#"    app=$(find $out -type f -path '*/resources/app.asar' | sort | head -1)
    [ -n "$app" ] || app=$(find $out -type d -path '*/resources/app' | sort | head -1)
    [ -n "$app" ] || { echo "@NAME@: no Electron resources/app(.asar) found" >&2; exit 1; }
    appdir=$(dirname "$(dirname "$app")")
    main=$(find "$appdir" -maxdepth 1 -type f -executable \
      ! -name 'AppRun' ! -name 'chrome-sandbox' ! -name 'chrome_crashpad_handler' \
      ! -name '*.so' ! -name '*.so.*' | sort | head -1)
    [ -n "$main" ] || { echo "@NAME@: no launcher binary found in $appdir" >&2; exit 1; }
    mkdir -p $out/bin
    makeWrapper "$main" "$out/bin/@NAME@" \
      --prefix LD_LIBRARY_PATH : "@LDPREFIX@""#;

/// Fill [`ELECTRON_WRAP`]'s two placeholders. `ld_prefix` is the `LD_LIBRARY_PATH` prefix value: a
/// `.deb` passes just the `makeLibraryPath` of its `buildInputs`; an AppImage prepends `$out` (its
/// bundle root holds the Chromium sibling `.so`s — `libEGL.so`, `libffmpeg.so`, …).
pub(crate) fn electron_wrap(name: &str, ld_prefix: &str) -> String {
    ELECTRON_WRAP
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
pub(crate) fn prefetch_hash(nix: &Path, layout: &Layout, url: &str) -> io::Result<String> {
    let mut cmd = store::nix_command(nix, layout);
    cmd.args(["--extra-experimental-features", "nix-command flakes"])
        .args(["store", "prefetch-file", "--json"])
        .args(["--name", &prefetch_name(url)])
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

#[cfg(test)]
mod tests {
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
    fn electron_wrap_fills_both_placeholders_and_excludes_apprun() {
        let wrap = electron_wrap("demo-app", "$out:/lib");
        assert!(wrap.contains("$out/bin/demo-app"));
        assert!(wrap.contains("--prefix LD_LIBRARY_PATH : \"$out:/lib\""));
        // AppRun exclusion is what makes one snippet serve both backends.
        assert!(wrap.contains("! -name 'AppRun'"));
        // The app is located by a packed `resources/app.asar` OR, for an asar-less VS Code fork
        // (Cursor ships `resources/app/` as a loose directory), the `resources/app` directory.
        assert!(wrap.contains("resources/app.asar"));
        assert!(wrap.contains("-type d -path '*/resources/app'"));
        assert!(!wrap.contains('@'), "unfilled placeholder in:\n{wrap}");
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
