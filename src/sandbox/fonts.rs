//! Fonts for the Wayland GUI hole.
//!
//! A hermetic cage carries no fonts and no `/etc/fonts`, so a graphical app renders
//! boxes instead of text. When `gui = "wayland"` is open, the hole provisions a base
//! font set into sbx's own store and generates a self-contained fontconfig
//! configuration pointing at it (named to the cage's fontconfig via `FONTCONFIG_FILE`),
//! so text renders without the user declaring anything.
//!
//! A font package ships no `bin/`, so it cannot ride the user-facing `[packages]` field
//! (which selects a bin-bearing output); the hole provisions it directly, like the base
//! userland. The provisioned store paths join the project store's seed (so the cage reads
//! them through `/nix`), and the generated configuration is staged read-only outside every
//! writable mount.
//!
//! Scope boundary: the hole provides the font *files* and the *configuration*. The
//! fontconfig *library* an app uses to read them is the app's own (a nix-packaged app
//! carries it in its closure; a probe like `fc-list` brings it via `[packages]`).

use crate::store::{self, Layout};
use sha2::{Digest, Sha256};
use std::io;
use std::path::{Path, PathBuf};

/// The base font set the GUI hole provisions: `(nixpkgs attribute, a directory the output
/// must contain, gcroot name)`. DejaVu covers the Latin sans/serif/monospace families a
/// general UI needs; Noto Color Emoji covers the emoji codepoints a modern chat/GUI renders
/// (without it, a `👋` in a message shows as a tofu box — the hermetic cage has no emoji font).
/// Broader script coverage (CJK, Arabic, …) is a per-need extension, not a default (font
/// closures are large). The marker is a directory (`share/fonts`), since a font package has
/// no binary to key on.
const GUI_FONTS: &[(&str, &str, &str)] = &[
    ("dejavu_fonts", "share/fonts", "dejavu"),
    ("noto-fonts-color-emoji", "share/fonts", "noto-emoji"),
];

/// Where the cage's fontconfig keeps its on-disk cache: a path on the cage's private tmpfs
/// `/tmp`, always writable and self-contained (no dependency on the home layout). The cache
/// is rebuilt each launch from the handful of provisioned fonts — negligible.
const FONT_CACHE_DIR: &str = "/tmp/.sbx-fontconfig";

/// Where the generated fontconfig configuration is bound read-only in the cage. Under
/// `/opt/sbx`, beside the mise plugin and the shell rc, colliding with no structural mount.
pub(crate) const FONTS_CONF_INCAGE: &str = "/opt/sbx/fonts.conf";

/// The provisioned font set: the store roots whose closures the project store must seed,
/// and the font directories the generated configuration lists.
pub(crate) struct FontLayer {
    /// Logical store roots (the font packages), to seed into the project store so the cage
    /// reads them through `/nix`.
    pub(crate) roots: Vec<PathBuf>,
    /// Logical font directories, one `<dir>` entry per provisioned package.
    pub(crate) dirs: Vec<PathBuf>,
}

/// Provision the GUI font set into sbx's store against the pinned `nixpkgs`. The gcroots are
/// keyed by revision (`<data>/gcroots/gui/<rev>/`), so the set is shared across every project
/// on the same channel — like the base userland — rather than copied per project.
pub(crate) fn provision(nix: &Path, layout: &Layout, nixpkgs: &str) -> io::Result<FontLayer> {
    let roots_dir = layout
        .data_dir()
        .join("gcroots")
        .join("gui")
        .join(store::revision_of(nixpkgs));
    let mut roots = Vec::with_capacity(GUI_FONTS.len());
    let mut dirs = Vec::with_capacity(GUI_FONTS.len());
    for (attr, marker, name) in GUI_FONTS {
        let logical = store::provision(nix, layout, &roots_dir.join(name), nixpkgs, attr, marker)?;
        dirs.push(logical.join("share/fonts"));
        roots.push(logical);
    }
    Ok(FontLayer { roots, dirs })
}

/// Generate a self-contained fontconfig configuration: a `<dir>` per provisioned font
/// directory, a writable `<cachedir>`, and generic-family aliases so an app requesting
/// `sans-serif`/`serif`/`monospace` gets a real font rather than nothing.
///
/// Self-contained on purpose: `FONTCONFIG_FILE` makes fontconfig read *only* this file, so it
/// must not rely on the host's `/etc/fonts` (absent in the cage). Every interpolated value is
/// sbx-controlled — nix store paths (the unreserved character set) and fixed strings — so
/// there is no XML metacharacter to escape. Pure, so it is unit-tested.
pub(crate) fn fonts_conf(dirs: &[PathBuf], cache_dir: &str) -> String {
    let mut s = String::new();
    s.push_str("<?xml version=\"1.0\"?>\n");
    s.push_str("<!DOCTYPE fontconfig SYSTEM \"urn:fontconfig:fonts.dtd\">\n");
    s.push_str("<fontconfig>\n");
    for dir in dirs {
        s.push_str(&format!("  <dir>{}</dir>\n", dir.display()));
    }
    s.push_str(&format!("  <cachedir>{cache_dir}</cachedir>\n"));
    // Map the generic families to concrete DejaVu faces so a request for a generic family
    // resolves to a real font. With a single provisioned family these aliases are not
    // *functionally* distinguishable from fontconfig's own fallback (it would pick the only
    // font anyway); they earn their keep once more than one family is provisioned.
    for (generic, concrete) in [
        ("sans-serif", "DejaVu Sans"),
        ("serif", "DejaVu Serif"),
        ("monospace", "DejaVu Sans Mono"),
        // The `emoji` generic family maps to the provisioned color-emoji face, so an app that
        // requests it resolves a real font; fontconfig's own charset matching then falls emoji
        // codepoints in ordinary text back to it too (so `👋` renders in a chat message).
        ("emoji", "Noto Color Emoji"),
    ] {
        s.push_str(&format!(
            "  <alias><family>{generic}</family><prefer><family>{concrete}</family></prefer></alias>\n"
        ));
    }
    s.push_str("</fontconfig>\n");
    s
}

/// Generate the configuration for `layer` (with the cage's tmpfs cache directory).
pub(crate) fn fonts_conf_for(layer: &FontLayer) -> String {
    fonts_conf(&layer.dirs, FONT_CACHE_DIR)
}

/// Materialize the generated configuration into sbx's data directory and return the host
/// file (ready to bind read-only at [`FONTS_CONF_INCAGE`]).
///
/// Content-keyed and atomic, like the staged mise plugin: the filename is a hash of the
/// contents, so a given font set always stages to the same path (idempotent) while a changed
/// set stages beside it; the file is written to a unique temp sibling and `rename`d into
/// place, so a concurrent launch of the same project never observes a half-written file (a
/// lost rename race just means the other launch wrote the identical bytes first).
pub(crate) fn stage(data_dir: &Path, contents: &str) -> io::Result<PathBuf> {
    let base = data_dir.join("fontconfig");
    std::fs::create_dir_all(&base)?;
    let file = base.join(format!("{}.conf", content_hash(contents)));
    if file.is_file() {
        return Ok(file);
    }

    let tmp = base.join(format!(".tmp-{}-{}", std::process::id(), unique()));
    if let Err(e) = std::fs::write(&tmp, contents) {
        let _ = std::fs::remove_file(&tmp);
        return Err(e);
    }
    match std::fs::rename(&tmp, &file) {
        Ok(()) => Ok(file),
        // Lost the race (another launch wrote the identical file) or it already existed:
        // discard the redundant temp and use the winner.
        Err(_) if file.is_file() => {
            let _ = std::fs::remove_file(&tmp);
            Ok(file)
        }
        Err(e) => {
            let _ = std::fs::remove_file(&tmp);
            Err(e)
        }
    }
}

/// A short hex hash of the configuration bytes, so the staging file name changes exactly
/// when the configuration does.
fn content_hash(contents: &str) -> String {
    let mut h = Sha256::new();
    h.update(contents.as_bytes());
    let digest = h.finalize();
    let mut s = String::with_capacity(16);
    for b in &digest[..8] {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// A per-call-unique suffix for the staging temp file (pid alone is not enough if a process
/// stages twice). Monotonic process-local counter, so it needs no clock or RNG.
fn unique() -> u64 {
    use std::sync::atomic::{AtomicU64, Ordering};
    static SEQ: AtomicU64 = AtomicU64::new(0);
    SEQ.fetch_add(1, Ordering::Relaxed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::TmpDir;

    #[test]
    fn the_generated_config_points_at_the_fonts_and_is_self_contained() {
        let dirs = [
            PathBuf::from("/nix/store/aaa-dejavu-fonts-2.37/share/fonts"),
            PathBuf::from("/nix/store/bbb-noto-fonts/share/fonts"),
        ];
        let conf = fonts_conf(&dirs, "/tmp/.sbx-fontconfig");

        // a <dir> per provisioned font directory — the logical store paths the cage reads
        // through `/nix`, so fontconfig finds exactly what the hole seeded
        assert!(conf.contains("<dir>/nix/store/aaa-dejavu-fonts-2.37/share/fonts</dir>"));
        assert!(conf.contains("<dir>/nix/store/bbb-noto-fonts/share/fonts</dir>"));
        // a writable cache directory on the cage tmpfs
        assert!(conf.contains("<cachedir>/tmp/.sbx-fontconfig</cachedir>"));
        // generic-family aliases to a concrete face (the functional effect is not isolable
        // with a single provisioned family; their presence is what is asserted here)
        assert!(conf.contains("<family>sans-serif</family>"));
        assert!(conf.contains("<family>DejaVu Sans</family>"));
        assert!(conf.contains("<family>monospace</family>"));
        assert!(conf.contains("<family>DejaVu Sans Mono</family>"));
        // the emoji generic maps to the color-emoji face, so `👋` in a message renders
        assert!(conf.contains("<family>emoji</family>"));
        assert!(conf.contains("<family>Noto Color Emoji</family>"));
        // self-contained: a well-formed fontconfig document, no <include> of a host path
        assert!(conf.starts_with("<?xml version=\"1.0\"?>"));
        assert!(conf.trim_end().ends_with("</fontconfig>"));
        assert!(!conf.contains("<include"));
    }

    #[test]
    fn stage_writes_the_config_content_keyed_and_idempotent() {
        let data = TmpDir::new();
        let conf = fonts_conf(&[PathBuf::from("/nix/store/x/share/fonts")], FONT_CACHE_DIR);

        let first = stage(data.path(), &conf).expect("stage the config");
        assert_eq!(std::fs::read_to_string(&first).unwrap(), conf);

        // content-keyed and idempotent: re-staging the same bytes returns the same path and
        // leaves no temp behind
        let second = stage(data.path(), &conf).expect("re-stage the config");
        assert_eq!(first, second);
        let leaked: Vec<_> = std::fs::read_dir(data.path().join("fontconfig"))
            .unwrap()
            .flatten()
            .filter(|e| e.file_name().to_string_lossy().starts_with(".tmp-"))
            .collect();
        assert!(leaked.is_empty(), "a staging temp leaked: {leaked:?}");

        // different contents stage to a different file (so a changed font set never reuses a
        // stale config)
        let other = fonts_conf(&[PathBuf::from("/nix/store/y/share/fonts")], FONT_CACHE_DIR);
        let third = stage(data.path(), &other).expect("stage a different config");
        assert_ne!(first, third);
    }
}
