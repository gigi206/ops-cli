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

/// Provision the compiled GSettings schemas plus the GTK themes into sbx's store against the pinned
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
        "sbx-gui-data",
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

/// The generated derivation: the pinned nixpkgs' `runCommand` around [`BUILD_SCRIPT`], given the
/// three packages it draws from by their store paths. The placeholders are substituted
/// (`@NIXPKGS@`/`@SYSTEM@`); `nixpkgs` is a channel name, a 40-hex revision or a pinned GitHub
/// reference by the grammars the config holds it to, and `system` is sbx's own, so neither carries
/// a character a Nix string would read as anything but itself.
fn derivation_expr(nixpkgs: &str, system: &str) -> String {
    const TEMPLATE: &str = r#"let pkgs = (builtins.getFlake "@NIXPKGS@").legacyPackages.@SYSTEM@;
in pkgs.runCommand "sbx-gui-data" { nativeBuildInputs = [ pkgs.glib ]; } ''
@SCRIPT@''"#;
    TEMPLATE
        .replace(
            "@SCRIPT@",
            &build_script(
                "${pkgs.gsettings-desktop-schemas}",
                "${pkgs.gtk3}",
                "${pkgs.gnome-themes-extra}",
            ),
        )
        .replace("@NIXPKGS@", nixpkgs)
        .replace("@SYSTEM@", system)
}

/// What the derivation runs, with `$out` set: collect every `.gschema.xml` from the GNOME desktop
/// schemas and GTK, compile them into one `gschemas.compiled`, and stage `gnome-themes-extra`'s
/// `share/themes`, the source of the named `Adwaita-dark` theme the file dialog uses.
///
/// Every piece the cage depends on is checked before the output is let through, and its absence
/// fails the build by name. The schemas the portal's keyfile and the file dialog read are
/// `org.gnome.desktop.interface` and `org.gtk.Settings.FileChooser`; without either, GTK aborts
/// **FATAL** at the dialog's first `g_settings_new`, so a set that compiled without them would be
/// a crash shipped as a success. The same holds for a compile that wrote nothing and for a theme
/// directory without `Adwaita-dark`. A nixpkgs that moved one of these is then a failed provision,
/// which the launch reports, rather than an output reused on every launch after.
const BUILD_SCRIPT: &str = r#"mkdir -p "$out/share/glib-2.0/schemas"
for p in @SCHEMAS@ @GTK@; do
  find "$p/share/gsettings-schemas" -name "*.gschema.xml" -exec cp -f -t "$out/share/glib-2.0/schemas" {} + \
    || { echo "sbx-gui-data: no GSettings schemas under $p" >&2; exit 1; }
done
for schema in org.gnome.desktop.interface org.gtk.Settings.FileChooser; do
  test -e "$out/share/glib-2.0/schemas/$schema.gschema.xml" \
    || { echo "sbx-gui-data: the $schema schema is missing" >&2; exit 1; }
done
glib-compile-schemas "$out/share/glib-2.0/schemas"
test -s "$out/share/glib-2.0/schemas/gschemas.compiled" \
  || { echo "sbx-gui-data: the schemas compiled to nothing" >&2; exit 1; }
cp -r @THEMES@/share/themes "$out/share/themes"
test -d "$out/share/themes/Adwaita-dark" \
  || { echo "sbx-gui-data: Adwaita-dark is missing from the themes" >&2; exit 1; }
"#;

/// [`BUILD_SCRIPT`] with the roots of the three packages it draws from: the desktop schemas, GTK
/// and the themes. The derivation passes Nix antiquotations; a test passes directories of its own.
fn build_script(schemas: &str, gtk: &str, themes: &str) -> String {
    BUILD_SCRIPT
        .replace("@SCHEMAS@", schemas)
        .replace("@GTK@", gtk)
        .replace("@THEMES@", themes)
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

    /// The test above asserts the pieces; this one asks nix whether what carries them is an
    /// expression. See [`crate::testutil::assert_nix_parses`] for why a `contains` cannot.
    #[test]
    fn the_expr_is_one_nix_accepts() {
        let Some(instantiate) = crate::testutil::nix_instantiate() else {
            skip_incapable!("skipping gui-data derivation parse: no nix-instantiate on this host");
            return;
        };
        let expr = derivation_expr("github:NixOS/nixpkgs/abc", "x86_64-linux");
        crate::testutil::assert_nix_parses(&instantiate, "guidata::derivation_expr", &expr);
    }

    /// The build step, run under `bash` over three package directories of its own and a stand-in
    /// `glib-compile-schemas`: a complete set builds, and a set missing any piece the cage depends
    /// on fails rather than ships. Each shape takes away one piece of the complete set.
    #[test]
    fn the_build_step_fails_rather_than_ship_a_set_missing_a_piece() {
        use crate::testutil::{TmpDir, write_script};
        for missing in [
            None,
            Some("the desktop schemas"),
            Some("the file chooser schema"),
            Some("the compiled schemas"),
            Some("the dark theme"),
        ] {
            let tmp = TmpDir::new();
            let root = tmp.path();
            let schemas = root.join("schemas/share/gsettings-schemas/d/glib-2.0/schemas");
            let gtk = root.join("gtk/share/gsettings-schemas/g/glib-2.0/schemas");
            let themes = root.join("themes/share/themes");
            std::fs::create_dir_all(&gtk).unwrap();
            if missing != Some("the desktop schemas") {
                std::fs::create_dir_all(&schemas).unwrap();
                std::fs::write(schemas.join("org.gnome.desktop.interface.gschema.xml"), "x")
                    .unwrap();
            }
            if missing != Some("the file chooser schema") {
                std::fs::write(gtk.join("org.gtk.Settings.FileChooser.gschema.xml"), "x").unwrap();
            }
            std::fs::create_dir_all(themes.join("Adwaita")).unwrap();
            if missing != Some("the dark theme") {
                std::fs::create_dir_all(themes.join("Adwaita-dark")).unwrap();
            }
            let bin = root.join("bin");
            std::fs::create_dir_all(&bin).unwrap();
            let compile = bin.join("glib-compile-schemas");
            write_script(
                &compile,
                if missing == Some("the compiled schemas") {
                    ":"
                } else {
                    "printf 'compiled' > \"$1/gschemas.compiled\""
                },
            );
            // Run once on its own, so a fork in another test still holding the descriptor that
            // wrote it is waited out here rather than met by the script, which would read as a
            // failed compile.
            crate::testutil::output_past_etxtbsy(std::process::Command::new(&compile).arg(&bin));
            let _ = std::fs::remove_file(bin.join("gschemas.compiled"));

            let out = root.join("out");
            let word = |p: &Path| crate::testutil::sh_word(p);
            let script = build_script(
                &word(&root.join("schemas")),
                &word(&root.join("gtk")),
                &word(&root.join("themes")),
            );
            let ran = crate::testutil::run_within(
                std::process::Command::new("/bin/bash")
                    .args(["-c", &script])
                    .env_clear()
                    .env("out", &out)
                    .env("PATH", format!("{}:/usr/bin:/bin", bin.display())),
                "the gui data build step",
            );
            match missing {
                None => {
                    assert!(
                        ran.status.success(),
                        "the complete set builds: {}",
                        ran.stderr
                    );
                    assert!(
                        out.join("share/glib-2.0/schemas/gschemas.compiled")
                            .is_file()
                    );
                    assert!(out.join("share/themes/Adwaita-dark").is_dir());
                }
                Some(piece) => assert!(
                    !ran.status.success(),
                    "a set without {piece} must fail its build: {}",
                    ran.stderr
                ),
            }
        }
    }

    #[test]
    fn the_env_points_xdg_data_dirs_at_the_output_share() {
        let env = data_env(Path::new("/nix/store/abc-sbx-gui-data"));
        assert_eq!(
            env,
            vec![(
                "XDG_DATA_DIRS".to_string(),
                "/nix/store/abc-sbx-gui-data/share".to_string()
            )]
        );
    }
}
