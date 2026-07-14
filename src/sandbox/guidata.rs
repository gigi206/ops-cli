//! GSettings schemas and GTK themes for the Wayland GUI hole.
//!
//! A hermetic cage carries no GSettings schemas and no GTK themes. Two GTK behaviours depend on
//! them, so the hole provisions one small data set carrying both and points the cage's
//! `XDG_DATA_DIRS` at it:
//!
//! * **Schemas.** A GTK dialog calls `g_settings_new(...)` when it opens and aborts **FATAL**
//!   (`No GSettings schemas are installed on the system`) when none are found, so the app crashes
//!   on "browse for a folder". The set compiles the GNOME desktop schemas plus GTK's own
//!   (including `org.gtk.Settings.FileChooser`).
//! * **Themes.** GTK renders every widget with light Adwaita unless a *named* dark theme is
//!   selected. GTK3's dark Adwaita is a separate theme directory (`Adwaita-dark`, shipped by
//!   `gnome-themes-extra` — GTK itself carries only the light built-in), so the set also stages
//!   `gnome-themes-extra`'s `share/themes`. The in-cage portal names `gtk-theme='Adwaita-dark'` in
//!   the GSettings keyfile (see [`super::portal`]); GTK finds the theme here on `XDG_DATA_DIRS` and
//!   follows a live keyfile change, so the file dialog matches the host light/dark theme and tracks
//!   a switch made while it is open.
//!
//! Both live under one output `share`, so a single `XDG_DATA_DIRS` entry reaches the schemas
//! (`share/glib-2.0/schemas`) and the themes (`share/themes`). Like the fonts, the output is built
//! host-side against the pinned nixpkgs and its store root joins the project store's seed (so the
//! cage reads it through `/nix`). The compiled schemas are one small data file; the themes are a
//! few CSS files whose real styling lives in libgtk-3's own resources (an `@import` of a
//! `resource://` path), so the closure stays negligible.

use crate::store::{self, Layout};
use std::io;
use std::path::{Path, PathBuf};

/// The provisioned GUI data set: the store root to seed and the env pointing the cage's glib/GTK at
/// it.
pub(crate) struct GuiDataLayer {
    /// Logical store root (the compiled schemas + staged themes), to seed into the project store.
    pub(crate) root: PathBuf,
    /// The env pointing the cage's glib/GTK at the data (`XDG_DATA_DIRS`).
    pub(crate) env: Vec<(String, String)>,
}

/// Provision the compiled GSettings schemas plus the GTK themes into ops's store against the pinned
/// `nixpkgs`. The gcroot is keyed by revision (`<data>/gcroots/gui/<rev>/guidata`), shared across
/// every project on the same channel — like the fonts.
pub(crate) fn provision(nix: &Path, layout: &Layout, nixpkgs: &str) -> io::Result<GuiDataLayer> {
    let gcroot = layout
        .data_dir()
        .join("gcroots")
        .join("gui")
        .join(store::revision_of(nixpkgs))
        .join("guidata");
    let expr = derivation_expr(nixpkgs, &super::current_system());
    let root = store::provision_expr(
        nix,
        layout,
        &gcroot,
        &expr,
        "ops-gui-data",
        "share/glib-2.0/schemas",
    )?;
    let env = data_env(&root);
    Ok(GuiDataLayer { root, env })
}

/// The env that points the cage's glib/GTK at the provisioned data: `XDG_DATA_DIRS` at the output's
/// `share`, where glib finds `glib-2.0/schemas/gschemas.compiled` and GTK finds `themes/Adwaita-dark`.
/// A hermetic cage has no other data dirs, so setting it is enough; an app's own launcher that
/// prepends its GTK data dirs appends to this value, keeping both reachable.
fn data_env(root: &Path) -> Vec<(String, String)> {
    vec![(
        "XDG_DATA_DIRS".to_string(),
        root.join("share").display().to_string(),
    )]
}

/// The generated derivation: collect every `.gschema.xml` from the GNOME desktop schemas and GTK
/// (whose `org.gtk.Settings.FileChooser` the file dialog reads), compile them into one
/// `gschemas.compiled`, and stage `gnome-themes-extra`'s `share/themes` (the source of the named
/// `Adwaita-dark` theme the file dialog uses). The placeholders are substituted
/// (`@NIXPKGS@`/`@SYSTEM@`); every interpolated value is ops-controlled, so the expression carries
/// nothing to escape.
fn derivation_expr(nixpkgs: &str, system: &str) -> String {
    const TEMPLATE: &str = r#"let pkgs = (builtins.getFlake "@NIXPKGS@").legacyPackages.@SYSTEM@;
in pkgs.runCommand "ops-gui-data" { nativeBuildInputs = [ pkgs.glib ]; } ''
  mkdir -p $out/share/glib-2.0/schemas
  for p in ${pkgs.gsettings-desktop-schemas} ${pkgs.gtk3}; do
    find "$p/share/gsettings-schemas" -name "*.gschema.xml" -exec cp -f -t $out/share/glib-2.0/schemas {} + 2>/dev/null || true
  done
  glib-compile-schemas $out/share/glib-2.0/schemas
  cp -r ${pkgs.gnome-themes-extra}/share/themes $out/share/themes
''"#;
    TEMPLATE
        .replace("@NIXPKGS@", nixpkgs)
        .replace("@SYSTEM@", system)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_expr_pins_nixpkgs_and_carries_the_filechooser_schema_and_dark_theme() {
        let expr = derivation_expr("github:NixOS/nixpkgs/abc", "x86_64-linux");
        assert!(expr.contains(
            "(builtins.getFlake \"github:NixOS/nixpkgs/abc\").legacyPackages.x86_64-linux"
        ));
        // it draws from the GNOME desktop schemas + GTK (the source of org.gtk.Settings.FileChooser)
        assert!(expr.contains("gsettings-desktop-schemas"));
        assert!(expr.contains("gtk3"));
        assert!(expr.contains("glib-compile-schemas"));
        // and stages the named dark theme (Adwaita-dark ships in gnome-themes-extra) into share/themes
        assert!(expr.contains("gnome-themes-extra"));
        assert!(expr.contains("$out/share/themes"));
        // every placeholder is substituted
        assert!(!expr.contains("@NIXPKGS@") && !expr.contains("@SYSTEM@"));
    }

    #[test]
    fn the_env_points_xdg_data_dirs_at_the_output_share() {
        let env = data_env(Path::new("/nix/store/abc-ops-gui-data"));
        assert_eq!(
            env,
            vec![(
                "XDG_DATA_DIRS".to_string(),
                "/nix/store/abc-ops-gui-data/share".to_string()
            )]
        );
    }
}
