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
//! One shape correction happens between the unpack and the shared install phase: an archive whose
//! root is a **single directory** — the platform slug or `<name>-<version>/` prefix a vendor
//! commonly wraps its tree in — is hoisted, so the program lands at the root the install phase
//! scans. It is the one unambiguous case (exactly one entry, and a *real* directory), which is why
//! it needs no per-package declaration. A lone root **symlink** is declined rather than hoisted:
//! hoisting one would copy the tree it points at — a path the archive chooses — in place of the
//! tree the archive ships.
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

use super::prebuilt;
use crate::config::is_valid_tarball_url;
use crate::store::Layout;
use std::collections::BTreeMap;
use std::io;
use std::path::Path;

/// A locked `tarball:` package, keyed in the lock by its declared *locator* — the `.tar.gz` URL for
/// a direct package, or `resolve:<name>` for a `tarball:resolve` package, whose `url` is then the
/// command-resolved download URL. See [`prebuilt::Pin`].
#[cfg(test)]
type TarballPin = prebuilt::Pin;

/// The outcome of re-resolving one declared `tarball:` reference during `sbx upgrade`.
///
/// See [`prebuilt::Upgrade`].
pub(crate) type TarballUpgrade = prebuilt::Upgrade;

/// Where this backend's lock lives. Production reads and writes it through [`prebuilt`]; this names
/// the same path for the tests that assert the on-disk format.
#[cfg(test)]
fn lock_path(layout: &Layout, project_id: &str) -> std::path::PathBuf {
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
/// resolves to itself; the hash is fetched via [`prebuilt::prefetch_hash`], which follows redirects
/// and adds the file to sbx's store, and whose docstring carries what following them costs. `fresh` marks an `sbx upgrade` re-resolve: with no source query of
/// its own, this backend has no metadata cache to bypass, so it uses the flag only to keep nix's
/// download output out of the upgrade summary. The locator
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
    let hash = prebuilt::prefetch_hash(nix, layout, &url, fresh, None)?;
    Ok((url, hash))
}

/// The generated nix expression building one `tarball:` package: fetch the pinned `.tar.gz`, extract
/// it, and autoPatchelf it against [`prebuilt::ELECTRON_LIBS`] from the pinned `nixpkgs`. The
/// install phase is generic for an Electron layout — [`prebuilt::launcher_wrap`] locates the app
/// directory by its `resources/` signature (a packed `resources/app.asar` or, for an asar-less VS
/// Code fork, the `resources/app/` directory) and wraps the app's own launcher, so no per-app path
/// is hardcoded. Every interpolated value is sbx-controlled and charset-validated (`name`, `url`,
/// `hash`, the pinned `nixpkgs`, the `system`), so the expression carries nothing to escape;
/// placeholders keep nix's `${…}`/`{…}` out of Rust's formatter.
fn derivation_expr(
    nixpkgs: &str,
    system: &str,
    name: &str,
    url: &str,
    hash: &str,
    libs: &[String],
) -> String {
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
    # Hoist a lone top-level directory. A vendor tarball routinely unpacks into ONE directory —
    # a platform slug (`linux-x64/`), a `<name>-<version>/` prefix — instead of spilling its tree
    # at the archive root, and the generic install phase below scans `$out` itself: without this
    # the program sits one level too deep and the build refuses it. The condition is "exactly one
    # entry, and it is a real directory", which is unambiguous by construction — there is nothing
    # to guess, so it needs no per-package knob. The `! -L` is what makes "real" hold: `-d`
    # resolves a symlink and the copy's trailing `/.` traverses one, so hoisting a root symlink
    # would splice the tree it points at — a path the archive picks, outside the unpacked one —
    # into $out in place of the tree the archive ships. An archive whose single root entry is a
    # link has nothing of its own to hoist, so declining it loses no vendor layout. Every other
    # root (a bare binary beside its data files, an FHS tree, an Electron bundle) has more than
    # one entry and is copied unchanged.
    root=extracted
    only=$(find extracted -mindepth 1 -maxdepth 1)
    if [ "$(printf '%s\n' "$only" | wc -l)" -eq 1 ] && [ -d "$only" ] && [ ! -L "$only" ]; then
      root=$only
    fi
    cp -r "$root"/. "$out"
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
        .replace("@LIBS@", &prebuilt::lib_set(libs))
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

    fn url_validator(&self) -> fn(&str, bool) -> bool {
        is_valid_tarball_url
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
        libs: &[String],
    ) -> String {
        derivation_expr(nixpkgs, system, name, url, hash, libs)
    }

    fn form(&self, package: &crate::config::Package) -> Option<prebuilt::Form> {
        match &package.backend {
            crate::config::Backend::Tarball(locator) => {
                Some(prebuilt::Form::Direct(locator.clone()))
            }
            crate::config::Backend::TarballResolve { command } => {
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
            | crate::config::Backend::Binary(_)
            | crate::config::Backend::BinaryResolve { .. } => None,
        }
    }
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
    use crate::testutil::{TmpDir, app_with, resolved};

    const HASH: &str = "sha256-jBGtMS5lpJWVXe+KzQgRSho8BcaEzGvONzIbAWled0w=";

    /// Run the generated `installPhase` against a real `extracted/` tree and report what it wrapped.
    ///
    /// The text assertions elsewhere pin the expression; this runs the half of it that decides
    /// where the program ends up. `makeWrapper` is a shell function printing its source, `$out` is
    /// a plain directory and nix's `${…}` interpolations are flattened to a literal path —
    /// everything else (the hoist, the `find` passes, the refusals) is the shipped snippet
    /// verbatim, so a layout that breaks here breaks a real build.
    fn install_on(work: &Path, files: &[(&str, bool)]) -> Result<String, String> {
        install_on_tree(work, files, &[])
    }

    /// [`install_on`] for a root that also holds symbolic links: each `(path, target)` is planted
    /// under `extracted/` as a link, the one entry shape a list of files cannot express.
    fn install_on_tree(
        work: &Path,
        files: &[(&str, bool)],
        links: &[(&str, &str)],
    ) -> Result<String, String> {
        let extracted = work.join("extracted");
        std::fs::create_dir_all(&extracted).unwrap();
        for (rel, executable) in files {
            plant(&extracted.join(rel), *executable);
        }
        for (rel, target) in links {
            std::os::unix::fs::symlink(target, extracted.join(rel)).unwrap();
        }
        let expr = derivation_expr(
            "github:NixOS/nixpkgs/abc",
            "x86_64-linux",
            NAME,
            URL,
            HASH,
            &[],
        );
        let body = expr
            .split_once("installPhase = ''\n")
            .expect("the expression carries an installPhase")
            .1
            .split_once("\n  '';")
            .expect("the installPhase is terminated")
            .0;
        let script = format!(
            "set -e\ncd {}\nout=$PWD/out\nmakeWrapper() {{ echo \"WRAPPED $1\"; }}\n{}\n",
            work.display(),
            flatten_nix_interpolations(body),
        );
        let out = std::process::Command::new("bash")
            .arg("-c")
            .arg(&script)
            .output()
            .expect("bash runs");
        let text = |bytes: &[u8]| String::from_utf8_lossy(bytes).trim().to_string();
        if out.status.success() {
            Ok(text(&out.stdout).replace(&format!("{}/", work.display()), ""))
        } else {
            Err(text(&out.stderr).replace(&format!("{}/", work.display()), ""))
        }
    }

    /// Write `path` as a stub program, executable or not, creating its parent directories. The
    /// install phase decides on the mode bit alone, so the bytes are the same everywhere.
    fn plant(path: &Path, executable: bool) {
        use std::os::unix::fs::PermissionsExt;
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, b"#!/bin/sh\n").unwrap();
        let mode = if executable { 0o755 } else { 0o644 };
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
    }

    /// Replace every `${…}` (the wrapper's four nixpkgs search paths) with a literal, so the
    /// snippet is runnable shell. Nix does not nest braces inside these, so the first `}` closes.
    fn flatten_nix_interpolations(snippet: &str) -> String {
        let mut out = String::new();
        let mut rest = snippet;
        while let Some((before, after)) = rest.split_once("${") {
            out.push_str(before);
            out.push_str("/lib");
            rest = after.split_once('}').expect("a closed interpolation").1;
        }
        out.push_str(rest);
        out
    }

    /// The `[packages]` key the install phase wraps, and a source URL, for the tests that build a
    /// whole expression. Both are arbitrary; only the shapes around them are under test.
    const NAME: &str = "demo-app";
    const URL: &str = "https://example.com/x/1.0/linux-x64/Demo%20App.tar.gz";

    /// The shape this backend refused before the hoist, and the ones it must keep resolving the
    /// way it already did. Every case but the last is a layout a vendor actually ships; the last
    /// is the root a hostile archive would build to make the hoist reach outside itself.
    #[test]
    fn the_install_phase_hoists_a_lone_top_level_directory_and_leaves_every_other_root_alone() {
        let tmp = TmpDir::new();

        // (a) The shape the hoist exists for: one directory at the archive root, holding the
        // program beside its support files. Without the hoist the program sits at depth 2 and the
        // root scan finds nothing to wrap.
        let slug = tmp.join("slug");
        assert_eq!(
            install_on(
                &slug,
                &[
                    ("linux-x64/demo-app", true),
                    ("linux-x64/README.txt", false),
                    ("linux-x64/vendor/rg", true),
                ]
            ),
            Ok("WRAPPED out/demo-app".to_string()),
            "a lone top-level directory must be hoisted into $out"
        );
        // The support files come with it — a program that reads its siblings by relative path
        // (a grammar, a bundled tool) is why the hoist copies the directory rather than the binary.
        assert!(slug.join("out/vendor/rg").exists());
        assert!(!slug.join("out/linux-x64").exists());

        // (b) A root with more than one entry is not the hoist's case, and takes the path it
        // always took: the single executable at the root gets wrapped.
        let flat = tmp.join("flat");
        assert_eq!(
            install_on(&flat, &[("demo-app", true), ("README", false)]),
            Ok("WRAPPED out/demo-app".to_string())
        );

        // (c) A root holding one FILE — the plainest archive of all — is not a directory, so the
        // hoist declines it. The refusal has to be a decline, not a build abort: the shell runs
        // under `set -e`, where a bare `[ -d … ] && …` would have taken the whole build down.
        let lone = tmp.join("lone");
        assert_eq!(
            install_on(&lone, &[("demo-app", true)]),
            Ok("WRAPPED out/demo-app".to_string())
        );

        // (d) An Electron bundle wrapped in its own directory resolved BEFORE the hoist (that pass
        // has no depth limit) and must still resolve to the same launcher after it.
        let electron = tmp.join("electron");
        assert_eq!(
            install_on(
                &electron,
                &[
                    ("Demo App/resources/app.asar", false),
                    ("Demo App/demo-app", true),
                    ("Demo App/chrome-sandbox", true),
                ]
            ),
            Ok("WRAPPED out/demo-app".to_string())
        );

        // (e) An FHS tree wrapped in its own directory also resolved before the hoist, via the
        // `*/bin/<name>` pass. Hoisting moves it onto `$out/bin/<name>` — the one path that pass
        // excludes, because the wrapper's own destination is there — so it lands in the arm that
        // moves the program to `libexec` and wraps it from there. Same program, and its siblings
        // are still one level up from it.
        let fhs = tmp.join("fhs");
        assert_eq!(
            install_on(
                &fhs,
                &[
                    ("demo-1.2/bin/demo-app", true),
                    ("demo-1.2/lib/support.so", false),
                ]
            ),
            Ok("WRAPPED out/libexec/demo-app".to_string())
        );
        assert!(fhs.join("out/lib/support.so").exists());

        // (f) The ambiguity the install phase refuses is untouched: hoisting a directory that
        // holds two executables still leaves two candidates, and picking one is the silent
        // mis-wrap this whole snippet is written to avoid.
        let ambiguous = tmp.join("ambiguous");
        let refusal = install_on(
            &ambiguous,
            &[("pkg/demo-app", true), ("pkg/demo-helper", true)],
        )
        .expect_err("two executables at the hoisted root is an ambiguity");
        assert!(
            refusal.contains("2 executables at the archive root"),
            "the refusal must name what it found:\n{refusal}"
        );

        // (g) A lone top-level symlink is the shape the hoist must NOT take, however
        // directory-like it looks: `[ -d ]` resolves it and the copy's trailing `/.` traverses
        // it, so hoisting one would put a tree the archive merely points at into `$out` in place
        // of the tree it ships. It is declined — the link is copied as a link, nothing is
        // followed, and the root scan then refuses because it has no executable to wrap.
        let linked = tmp.join("linked");
        plant(&linked.join("outside/demo-app"), true);
        let declined = install_on_tree(&linked, &[], &[("linux-x64", "../outside")])
            .expect_err("a lone root symlink leaves the root with nothing to wrap");
        assert!(
            declined.contains("no executable at the archive root"),
            "the refusal must report an empty root:\n{declined}"
        );
        assert!(
            !linked.join("out/demo-app").exists(),
            "nothing from the link's target may be copied into $out"
        );
    }

    #[test]
    fn the_generated_derivation_pins_the_source_and_wraps_the_electron_launcher() {
        let expr = derivation_expr(
            "github:NixOS/nixpkgs/abc",
            "x86_64-linux",
            "demo-app",
            "https://example.com/x/1.0/linux-x64/Demo%20App.tar.gz",
            HASH,
            &[],
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
            libs: Vec::new(),
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
            libs: Vec::new(),
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
