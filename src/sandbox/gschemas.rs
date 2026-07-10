//! GSettings schemas for the Wayland GUI hole.
//!
//! A hermetic cage carries no GSettings schemas. A GTK-based dialog — the file chooser
//! Electron/Chromium falls back to when no desktop portal is present on the session bus —
//! calls `g_settings_new(...)` when it opens and aborts **FATAL** (`No GSettings schemas
//! are installed on the system`) when none are found, so the app crashes on "browse for a
//! folder". When `gui = "wayland"` is open, the hole provisions a compiled schema set (the
//! GNOME desktop schemas plus GTK's own, including `org.gtk.Settings.FileChooser`) into
//! ops's store and points the cage's `XDG_DATA_DIRS` at it so glib finds them.
//!
//! Like the fonts, the schema output is built host-side against the pinned nixpkgs and its
//! store root joins the project store's seed (so the cage reads it through `/nix`). The
//! compiled output is a single small data file with no runtime closure, so seeding it is
//! negligible.

use crate::store::{self, Layout};
use std::io;
use std::path::{Path, PathBuf};

/// The provisioned schema set: the store root to seed and the env pointing the cage's glib at it.
pub(crate) struct SchemaLayer {
    /// Logical store root (the compiled schema output), to seed into the project store.
    pub(crate) root: PathBuf,
    /// The env pointing the cage's glib at the schemas (`XDG_DATA_DIRS`).
    pub(crate) env: Vec<(String, String)>,
}

/// Provision the compiled GSettings schema set into ops's store against the pinned `nixpkgs`. The
/// gcroot is keyed by revision (`<data>/gcroots/gui/<rev>/gschemas`), shared across every project
/// on the same channel — like the fonts.
pub(crate) fn provision(nix: &Path, layout: &Layout, nixpkgs: &str) -> io::Result<SchemaLayer> {
    let gcroot = layout
        .data_dir()
        .join("gcroots")
        .join("gui")
        .join(store::revision_of(nixpkgs))
        .join("gschemas");
    let expr = derivation_expr(nixpkgs, &super::current_system());
    let root = store::provision_expr(
        nix,
        layout,
        &gcroot,
        &expr,
        "ops-gsettings-schemas",
        "share/glib-2.0/schemas",
    )?;
    let env = schema_env(&root);
    Ok(SchemaLayer { root, env })
}

/// The env that points the cage's glib at the provisioned schemas: `XDG_DATA_DIRS` at the output's
/// `share`, where glib finds `glib-2.0/schemas/gschemas.compiled`. A hermetic cage has no other
/// data dirs, so setting it is enough; an app's own launcher that prepends its GTK data dirs
/// appends to this value, keeping the schemas reachable.
fn schema_env(root: &Path) -> Vec<(String, String)> {
    vec![(
        "XDG_DATA_DIRS".to_string(),
        root.join("share").display().to_string(),
    )]
}

/// The generated derivation: collect every `.gschema.xml` from the GNOME desktop schemas and GTK
/// (whose `org.gtk.Settings.FileChooser` the file dialog reads) and compile them into one
/// `gschemas.compiled`. The placeholders are substituted (`@NIXPKGS@`/`@SYSTEM@`); every
/// interpolated value is ops-controlled, so the expression carries nothing to escape.
fn derivation_expr(nixpkgs: &str, system: &str) -> String {
    const TEMPLATE: &str = r#"let pkgs = (builtins.getFlake "@NIXPKGS@").legacyPackages.@SYSTEM@;
in pkgs.runCommand "ops-gsettings-schemas" { nativeBuildInputs = [ pkgs.glib ]; } ''
  mkdir -p $out/share/glib-2.0/schemas
  for p in ${pkgs.gsettings-desktop-schemas} ${pkgs.gtk3}; do
    find "$p/share/gsettings-schemas" -name "*.gschema.xml" -exec cp -f -t $out/share/glib-2.0/schemas {} + 2>/dev/null || true
  done
  glib-compile-schemas $out/share/glib-2.0/schemas
''"#;
    TEMPLATE
        .replace("@NIXPKGS@", nixpkgs)
        .replace("@SYSTEM@", system)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_expr_pins_nixpkgs_and_compiles_the_gtk_filechooser_schema() {
        let expr = derivation_expr("github:NixOS/nixpkgs/abc", "x86_64-linux");
        assert!(expr.contains(
            "(builtins.getFlake \"github:NixOS/nixpkgs/abc\").legacyPackages.x86_64-linux"
        ));
        // it draws from the GNOME desktop schemas + GTK (the source of org.gtk.Settings.FileChooser)
        assert!(expr.contains("gsettings-desktop-schemas"));
        assert!(expr.contains("gtk3"));
        assert!(expr.contains("glib-compile-schemas"));
        // every placeholder is substituted
        assert!(!expr.contains("@NIXPKGS@") && !expr.contains("@SYSTEM@"));
    }

    #[test]
    fn the_env_points_xdg_data_dirs_at_the_schema_share() {
        let env = schema_env(Path::new("/nix/store/abc-ops-gsettings-schemas"));
        assert_eq!(
            env,
            vec![(
                "XDG_DATA_DIRS".to_string(),
                "/nix/store/abc-ops-gsettings-schemas/share".to_string()
            )]
        );
    }
}
