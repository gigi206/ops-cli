//! `binary:` packages — a prebuilt program downloaded as itself, provisioned host-side.
//!
//! The fourth prebuilt backend, and the one for a vendor that publishes a **bare executable** at an
//! `https://` URL: no `.deb`, no `.AppImage`, no archive of any kind, no nixpkgs attribute and no
//! official flake. The other three all unpack something, so none of them fits — `tarball:` would
//! `tar -xz` a file that is not an archive and fail at build time.
//!
//! Everything else is shared with them, deliberately: resolve the URL to a content hash, build a
//! generated derivation that installs the file and `autoPatchelfHook`s it against the same curated
//! library set, pin it in a per-project lock on first use, rebuild offline ever after, one gcroot per
//! package. **No build script runs** (`dontBuild`), so evaluating and building it host-side is safe.
//!
//! Two source forms:
//! * `binary:<https url>` — a direct URL. It is worth being blunt about what this form does: a bare
//!   executable's URL is version-stamped by construction, because there is no archive name for the
//!   version to hide in, so a direct locator freezes the package at whatever it named. Use it only
//!   when the vendor publishes a stable alias.
//! * `binary:resolve` (paired with a `[binary.<name>]` table carrying a `resolve` **command**) — the
//!   auto-upgrade form, and the one this backend is really for. sbx runs the command in a hermetic
//!   bubblewrap cage (sbx's base tools plus the app's `nix:` bins on `PATH`, sbx's store + CA bundle
//!   bound, shared network so it can reach a vendor version API), captures the URL it prints,
//!   validates it, and pins it, so `sbx upgrade binary` rolls the package forward automatically. The
//!   command is arbitrary code — honored only from a trusted layer, never run for an untrusted one —
//!   and its printed URL is re-validated by [`is_valid_binary_url`] before any fetch.
//!
//! **What this backend's URL check can and cannot do.** The other three require the URL to end in
//! their artefact's extension, which reads like a content check but is not one: a `.tar.gz` suffix
//! proves nothing about the bytes. Here there is no extension to require, so the barrier is what it
//! always really was — `https://` and an injection-free charset — plus the content hash, which is
//! the check that actually binds a pin to a specific artefact. A resolve command is arbitrary code
//! from a trusted layer either way; the suffix was never what contained it.

use super::prebuilt;
use crate::config::is_valid_binary_url;
use crate::store::Layout;
use std::collections::BTreeMap;
use std::io;
use std::path::Path;

/// A locked `binary:` package, keyed in the lock by its declared *locator* — the URL for a direct
/// package, or `resolve:<name>` for a `binary:resolve` package, whose `url` is then the
/// command-resolved download URL. See [`prebuilt::Pin`].
#[cfg(test)]
type BinaryPin = prebuilt::Pin;

/// The outcome of re-resolving one declared `binary:` reference during `sbx upgrade`.
///
/// See [`prebuilt::Upgrade`].
pub(crate) type BinaryUpgrade = prebuilt::Upgrade;

/// Where this backend's lock lives. Production reads and writes it through [`prebuilt`]; this names
/// the same path for the tests that assert the on-disk format.
#[cfg(test)]
fn lock_path(layout: &Layout, project_id: &str) -> std::path::PathBuf {
    prebuilt::lock_path(layout, project_id, &prebuilt::lock_file(&Binary))
}

/// Read the per-project binary lock. A three-column line is a `binary:resolve` pin
/// (`resolve:<name>` key, hash, the command-resolved URL); see [`prebuilt::pins`] for the format.
#[cfg(test)]
fn pins(layout: &Layout, project_id: &str) -> BTreeMap<String, BinaryPin> {
    prebuilt::pins(layout, project_id, &prebuilt::lock_file(&Binary))
}

/// The pinned content hashes for a project's `binary:` packages, keyed by the declared locator.
/// See [`prebuilt::pinned_hashes`].
pub(crate) fn pinned_hashes(cwd: &Path) -> BTreeMap<String, String> {
    prebuilt::pinned_hashes(cwd, &prebuilt::lock_file(&Binary))
}

/// Write the per-project binary lock atomically, for the tests that assert the on-disk format.
///
/// Production writes it through [`prebuilt::upgrade`].
#[cfg(test)]
fn write_pins(
    layout: &Layout,
    project_id: &str,
    lock: &BTreeMap<String, BinaryPin>,
) -> io::Result<()> {
    prebuilt::write_pins(layout, project_id, &prebuilt::lock_file(&Binary), lock)
}

/// Resolve a declared `binary:` locator to `(concrete url, SRI content hash)`. A direct URL resolves
/// to itself; the hash is fetched via [`prebuilt::prefetch_hash`], which follows redirects and adds
/// the file to sbx's store, and whose docstring carries what following them costs. `fresh` marks an `sbx upgrade` re-resolve: with no source query of its own,
/// this backend has no metadata cache to bypass, so it uses the flag only to keep nix's download
/// output out of the upgrade summary. The locator was already validated injection-free by
/// `config::parse_backend`, so it is safe to fetch and later interpolate into the generated
/// derivation.
pub(crate) fn resolve_source(
    nix: &Path,
    layout: &Layout,
    locator: &str,
    fresh: bool,
) -> io::Result<(String, String)> {
    prebuilt::resolve_direct_url(nix, layout, locator, fresh)
}

/// The generated nix expression building one `binary:` package: fetch the pinned file, install it as
/// the program, and autoPatchelf it against [`prebuilt::ELECTRON_LIBS`] from the pinned `nixpkgs`.
///
/// There is no unpack phase, which is the whole difference from [`super::tarball`], and no launcher
/// wrap: the three archive backends have to *locate* a program inside a tree, whereas here the
/// download IS the program, so it is installed straight at `bin/<name>` under the `[packages]` key.
/// That key is what a profile's `cmd` names, whatever the vendor called the file in its URL.
///
/// `src` is fetched with an explicit `name`, because a URL with no extension often ends in a
/// version-stamped path segment that nix would otherwise refuse as a store-path name.
///
/// Every interpolated value is sbx-controlled and charset-validated (`name`, `url`, `hash`, the
/// pinned `nixpkgs`, the `system`), so the expression carries nothing to escape; placeholders keep
/// nix's `${…}`/`{…}` out of Rust's formatter.
fn derivation_expr(
    nixpkgs: &str,
    system: &str,
    name: &str,
    url: &str,
    hash: &str,
    decor: &prebuilt::Decor<'_>,
) -> String {
    const TEMPLATE: &str = r#"let pkgs = (builtins.getFlake "@NIXPKGS@").legacyPackages.@SYSTEM@;
in pkgs.stdenvNoCC.mkDerivation (finalAttrs: {
  name = "@NAME@";
  src = pkgs.fetchurl { name = "@NAME@-download"; url = "@URL@"; hash = "@HASH@"; };
  nativeBuildInputs = with pkgs; [ makeWrapper autoPatchelfHook ];
  buildInputs = with pkgs; [ @LIBS@ ];
  # Ignore unresolved deps, as the other prebuilt backends do: a vendor binary commonly links
  # OPTIONAL libraries for features a given run never reaches, and forcing every one to resolve
  # would refuse to build the whole program over one of them. The libraries it genuinely needs are
  # in `@LIBS@` and are patched in; a missing core library surfaces at first launch.
  autoPatchelfIgnoreMissingDeps = true;
  # The download is the program, so there is nothing to unpack — `fetchurl` hands over a single
  # file and `dontUnpack` keeps stdenv from trying to treat it as an archive.
  dontUnpack = true;
  dontConfigure = true;
  dontBuild = true;
  # Installed under the `[packages]` KEY rather than the vendor's file name: that key is what the
  # profile's `cmd` names and what every other backend wraps to, so a package behaves the same
  # whatever the URL happened to call it.
  installPhase = ''
    install -Dm755 $src "$out/bin/@NAME@"
  '';
  postFixup = ''
    wrapProgram "$out/bin/@NAME@" \
      --prefix LD_LIBRARY_PATH : "${pkgs.lib.makeLibraryPath finalAttrs.buildInputs}"
  '';
  meta.mainProgram = "@NAME@";
})
"#;
    TEMPLATE
        .replace("@NIXPKGS@", nixpkgs)
        .replace("@SYSTEM@", system)
        .replace("@LIBS@", &prebuilt::lib_set(decor.libs))
        .replace("@URL@", url)
        .replace("@HASH@", hash)
        .replace("@NAME@", name)
}

/// The `binary:` backend — the two decisions [`prebuilt::Kind`] leaves to it are its locator form (a
/// direct URL, always its own download URL) and an install with no unpack at all. Like `tarball:` it
/// takes no `system`: a URL names one artefact, with no asset to select.
pub(crate) struct Binary;

impl prebuilt::Kind for Binary {
    fn name(&self) -> &'static str {
        "binary"
    }

    fn artefact(&self) -> &'static str {
        "`a program`"
    }

    fn url_validator(&self) -> fn(&str, bool) -> bool {
        is_valid_binary_url
    }

    fn resolve_source(
        &self,
        nix: &Path,
        layout: &Layout,
        locator: &str,
        _system: &str,
        fresh: bool,
        // This backend's locator *is* its URL, validated when the config was read; there is no
        // second, command-chosen URL here to re-judge.
        _allow_insecure_http: bool,
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
        decor: &prebuilt::Decor<'_>,
    ) -> String {
        derivation_expr(nixpkgs, system, name, url, hash, decor)
    }

    fn form(&self, package: &crate::config::Package) -> Option<prebuilt::Form> {
        match &package.backend {
            crate::config::Backend::Binary(locator) => {
                Some(prebuilt::Form::Direct(locator.clone()))
            }
            crate::config::Backend::BinaryResolve { command } => {
                Some(prebuilt::Form::Resolve(command.clone()))
            }
            // Spelled out rather than `_`: a new backend variant must fail to compile here. Falling
            // through to `None` would leave its packages out of the prune universe, and `upgrade`
            // would drop a still-declared pin without a word.
            crate::config::Backend::Nix(_)
            | crate::config::Backend::Mise(_)
            | crate::config::Backend::Flake(_)
            | crate::config::Backend::FlakeInline { .. }
            | crate::config::Backend::Deb(_)
            | crate::config::Backend::DebResolve { .. }
            | crate::config::Backend::AppImage(_)
            | crate::config::Backend::AppImageResolve { .. }
            | crate::config::Backend::Tarball(_)
            | crate::config::Backend::TarballResolve { .. } => None,
        }
    }
}

/// `sbx upgrade binary`: roll a project's declared `binary:` packages forward. See
/// [`prebuilt::upgrade_project`].
pub(crate) fn upgrade_project(
    nix: &Path,
    layout: &Layout,
    project: &Path,
    cfg: &crate::config::Resolved,
) -> io::Result<Vec<BinaryUpgrade>> {
    prebuilt::upgrade_project(&Binary, nix, layout, project, cfg)
}

/// How many declared `binary:` packages are withheld for being untrusted. See [`prebuilt::withheld`].
pub(crate) fn withheld(cfg: &crate::config::Resolved) -> usize {
    prebuilt::withheld(&Binary, cfg)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::TmpDir;

    const HASH: &str = "sha256-jBGtMS5lpJWVXe+KzQgRSho8BcaEzGvONzIbAWled0w=";

    /// The one thing this backend does differently from the other three, asserted as such: the
    /// download is installed as the program instead of being unpacked.
    #[test]
    fn the_generated_derivation_installs_the_download_as_the_program() {
        let expr = derivation_expr(
            "github:NixOS/nixpkgs/abc",
            "x86_64-linux",
            "demo-app",
            "https://example.com/cli/demo-1.2.3-linux-x86_64",
            HASH,
            &prebuilt::Decor {
                libs: &[],
                main: "",
            },
        );

        // The pin is what binds this build to one artefact — the URL alone never did.
        assert!(expr.contains("url = \"https://example.com/cli/demo-1.2.3-linux-x86_64\";"));
        assert!(expr.contains(&format!("hash = \"{HASH}\";")));

        // No unpack, and said so explicitly: stdenv would otherwise try to treat the file as an
        // archive and fail the build on a program that is perfectly fine.
        assert!(expr.contains("dontUnpack = true;"), "{expr}");
        assert!(
            !expr.contains("tar -xz"),
            "nothing is extracted here: {expr}"
        );

        // Installed under the `[packages]` key, not the vendor's file name, so a profile's `cmd`
        // names the same thing whatever the URL called it.
        assert!(
            expr.contains("install -Dm755 $src \"$out/bin/demo-app\""),
            "{expr}"
        );
        assert!(expr.contains("meta.mainProgram = \"demo-app\";"));

        // The download is given a name of sbx's choosing: a URL with no extension ends in a
        // version-stamped segment nix would otherwise refuse as a store-path name.
        assert!(expr.contains("name = \"demo-app-download\";"), "{expr}");
    }

    /// The lock this backend writes is its own. Its name spells the on-disk state, so a rename
    /// strands every existing pin, and [`super::super::packages`] spells it out independently.
    #[test]
    fn the_lock_and_the_backend_name_are_the_ones_the_rest_of_the_tree_spells() {
        use prebuilt::Kind;
        assert_eq!(Binary.name(), "binary");
        assert_eq!(prebuilt::lock_file(&Binary), "binary-packages.lock");
    }

    /// A direct locator and a resolve sentinel are the two forms, and every other backend's packages
    /// stay out of this one's universe.
    #[test]
    fn only_this_backends_packages_are_claimed() {
        use crate::config::{Backend, Package};
        use prebuilt::Kind;

        let pkg = |backend| Package {
            name: "demo".to_string(),
            backend,
            state: crate::trust::TrustState::Trusted,
            libs: Vec::new(),
            main: String::new(),
        };

        assert!(matches!(
            Binary.form(&pkg(Backend::Binary("https://example.com/x".into()))),
            Some(prebuilt::Form::Direct(_))
        ));
        assert!(matches!(
            Binary.form(&pkg(Backend::BinaryResolve {
                command: vec!["true".into()]
            })),
            Some(prebuilt::Form::Resolve(_))
        ));
        // A sibling backend's package is not this one's to prune or roll.
        assert!(
            Binary
                .form(&pkg(Backend::Tarball(
                    "https://example.com/x.tar.gz".into()
                )))
                .is_none()
        );
    }

    /// The lock round-trips through the shared reader and writer, keyed by declared locator.
    #[test]
    fn a_pin_round_trips_through_the_lock() {
        let data = TmpDir::new();
        let layout = Layout::under(data.path());
        let id = "binproj";
        let url = "https://example.com/cli/demo-1.2.3-linux-x86_64";
        let mut lock = BTreeMap::new();
        lock.insert(
            url.to_string(),
            BinaryPin {
                hash: HASH.to_string(),
                url: url.to_string(),
            },
        );
        write_pins(&layout, id, &lock).expect("write the lock");

        let raw = std::fs::read_to_string(lock_path(&layout, id)).unwrap();
        assert!(
            raw.contains(&format!("{url}\t{HASH}\n")),
            "a direct-URL pin keeps the two-column form:\n{raw}"
        );
        assert!(lock_path(&layout, id).ends_with("binary-packages.lock"));

        let read = pins(&layout, id);
        assert_eq!(read[url].hash, HASH);
    }
}
