//! The in-cage desktop portal (`dbus = true`).
//!
//! A Chromium/Electron app on Linux opens its file chooser through the desktop portal
//! (`org.freedesktop.portal.FileChooser`). Under the filtered *host* bus (`dbus = true`) that
//! portal is the **host's**, whose dialog is a host-privileged file manager the cage must not be
//! able to summon — so sbx refuses the FileChooser interface, and the app's "browse for a folder"
//! then fails (recent Chromium commits to the portal and no longer falls back to its in-process
//! GTK dialog once a portal advertises a new-enough version).
//!
//! `dbus = true` gives the cage its **own** portal instead: a private D-Bus session bus runs
//! inside the cage carrying sbx-provisioned `xdg-desktop-portal` with the reference GTK backend
//! (`xdg-desktop-portal-gtk`). The app probes *that* portal, gets a real version, and the file
//! chooser it opens is rendered **in-cage** by the GTK backend — a dialog that by construction sees
//! only the cage's own filesystem (the app's isolated home, the project, the `[binds]` mounts),
//! since the backend runs in the cage's mount namespace. It is the Flatpak model with the cage as
//! the world, and it is **not tied to GNOME**: `xdg-desktop-portal-gtk` is the freedesktop
//! *reference* backend (the universal fallback used by sway/XFCE/MATE), depending only on the GTK
//! library the Electron app already carries.
//!
//! The bus carries only in-cage services and never connects to the host session bus, so — unlike
//! the filtered host bus — it is unaffected by the network posture. Its socket, however, lives on a
//! host directory sbx bind-mounts into the cage (at [`CAGE_DIR`]): the in-cage `dbus-daemon` creates
//! it there, so a host-side process can reach the private bus. That is what lets the desktop
//! notifications relay (`org.freedesktop.Notifications`, forwarded to the host daemon) attach to the
//! bus. The exposure is benign under sbx's same-uid model: the directory is owner-only (0700), the
//! only host process that connects is sbx's own relay, and every portal backend on the bus is
//! confined to the cage (the socket carries no reach the user's own uid does not already have). The
//! host light/dark theme is seeded into the cage at launch (read host-side, best-effort) so both the
//! app and the file dialog open in the right theme, and a later host switch is followed live by the
//! theme relay (see [`super::theme_relay`]) rewriting the GSettings keyfile both surfaces watch.
//!
//! Needs `gui = "wayland"`: the GTK backend renders through the compositor, so without a display it
//! cannot start and the FileChooser interface never appears.
//!
//! Security note: the in-cage front-end activates *every* portal backend interface in-cage
//! (Screenshot, ScreenCast, …), not only the file chooser. This is **not** a new capability — those
//! backends reach nothing the cage does not already hold (PipeWire is unconnected, everything is
//! confined to the cage's mount/network namespaces), and the only host resource in the cage is the
//! Wayland socket, which `gui = "wayland"` already bound. So the compositor-dependent isolation
//! caveat for the Wayland socket (Mutter safe; wlroots exposes screen-capture/input-injection —
//! see `docs-site/docs/guide/configuration/gui.md`) governs these interfaces too; the
//! in-cage portal adds no reach beyond the socket the display hole already grants.

use crate::store::{self, Layout};
use std::ffi::OsString;
use std::io;
use std::os::unix::fs::DirBuilderExt;
use std::path::{Path, PathBuf};

/// The packages the in-cage portal needs, each `(nixpkgs attribute, the marker its output must
/// carry, gcroot name)`. `dbus` supplies the session-bus daemon; `xdg-desktop-portal` is the portal front-end; `xdg-desktop-portal-gtk` is the
/// GTK backend that renders the file dialog; `desktop-file-utils` supplies `update-desktop-database`,
/// which builds the desktop-database index the portal's `OpenURI` needs to resolve a custom-scheme
/// deep-link handler an app registers (a `.desktop` with a `MimeType=x-scheme-handler/<scheme>`) — the
/// portal launches only an app in the *registered/recommended* list, which that index (not the bare
/// `mimeapps.list` default) populates. They share the revision-keyed `gui` gcroot directory with the
/// fonts/certutil/GUI data (all GUI-hole provisions on the same channel), so `sbx gc` keeps or drops
/// them together.
const PACKAGES: &[(&str, &str, &str)] = &[
    ("dbus", "bin/dbus-daemon", "dbus"),
    (
        "xdg-desktop-portal",
        "libexec/xdg-desktop-portal",
        "xdg-desktop-portal",
    ),
    (
        "xdg-desktop-portal-gtk",
        "libexec/xdg-desktop-portal-gtk",
        "xdg-desktop-portal-gtk",
    ),
    (
        "desktop-file-utils",
        "bin/update-desktop-database",
        "desktop-file-utils",
    ),
];

/// The cage-side mount point of the portal runtime directory: sbx bind-mounts a host directory here
/// (read-write), so the private bus socket the in-cage `dbus-daemon` creates under it is reachable
/// from the host (the notifications relay connects to it). Under `/run/sbx-portal` — sbx's own path,
/// not `$XDG_RUNTIME_DIR` (which holds the pulse/gpg/ssh sockets) — it holds the generated bus config
/// and the socket.
pub(crate) const CAGE_DIR: &str = "/run/sbx-portal";
/// The private session-bus socket, at its cage path. Through the bind this is the same file as
/// [`HostDir::socket`] on the host.
const CAGE_SOCK: &str = "/run/sbx-portal/bus";

/// The host directory bind-mounted into the cage at [`CAGE_DIR`]. Per-launch (the pid keeps
/// concurrent launches from colliding), under `<data>/portal`.
fn host_dir(layout: &Layout) -> PathBuf {
    layout
        .data_dir()
        .join("portal")
        .join(std::process::id().to_string())
}

/// Owns the host portal directory bound into the cage. Creating it (0700) sets up the shared runtime
/// dir; dropping it removes the socket and the generated config the cage wrote there. Its presence in
/// the launch guard forces the supervised path — the in-cage bus (and, once wired, the host-side
/// relay attached to it) must be cleaned up when the launch ends rather than leaked by an exec.
pub(crate) struct HostDir {
    dir: PathBuf,
}

impl HostDir {
    /// Create the per-launch host portal directory (0700, owner-only), clearing any stale
    /// predecessor from a crashed prior launch of the same pid.
    pub(crate) fn create(layout: &Layout) -> io::Result<HostDir> {
        let dir = host_dir(layout);
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&dir)?;
        Ok(HostDir { dir })
    }

    /// The host path of the directory, to bind into the cage at [`CAGE_DIR`].
    pub(crate) fn dir(&self) -> &Path {
        &self.dir
    }

    /// The host path of the private bus socket (the in-cage `dbus-daemon` creates it here through the
    /// bind), for the notifications relay to connect to.
    pub(crate) fn socket(&self) -> PathBuf {
        self.dir.join("bus")
    }
}

impl Drop for HostDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// The provisioned in-cage portal: the store roots to seed and the logical paths the cage uses.
pub(crate) struct Provision {
    /// Logical store roots (dbus, xdg-desktop-portal, the GTK backend), to seed into the project
    /// store so the cage reads them through `/nix`.
    pub(crate) roots: Vec<PathBuf>,
    /// Logical path of `dbus-daemon` (run inside the cage).
    pub(crate) dbus_daemon: PathBuf,
    /// Logical root of `xdg-desktop-portal` (its `share/dbus-1/services` is a bus servicedir).
    pub(crate) xdp_root: PathBuf,
    /// Logical root of `xdg-desktop-portal-gtk` (its servicedir plus the `gtk.portal` descriptor).
    pub(crate) gtk_root: PathBuf,
    /// Logical path of `update-desktop-database` (run in-cage from the wrap preamble to index any
    /// deep-link handler an app registers, so the portal's `OpenURI` can resolve it).
    pub(crate) update_desktop_db: PathBuf,
}

/// Provision the three portal packages into sbx's store against the pinned `nixpkgs`, sharing the
/// revision-keyed `gui` gcroot directory with the other GUI-hole provisions.
pub(crate) fn provision(nix: &Path, layout: &Layout, nixpkgs: &str) -> io::Result<Provision> {
    let base = layout
        .data_dir()
        .join("gcroots")
        .join("gui")
        .join(store::revision_of(nixpkgs));
    let mut roots: Vec<PathBuf> = Vec::new();
    let mut resolved: Vec<PathBuf> = Vec::new();
    for (attr, marker, name) in PACKAGES {
        let root = store::provision(nix, layout, &base.join(name), nixpkgs, attr, marker)?;
        resolved.push(root.clone());
        roots.push(root);
    }
    // `resolved` is in `PACKAGES` order: dbus, xdg-desktop-portal, xdg-desktop-portal-gtk,
    // desktop-file-utils.
    let dbus_root = &resolved[0];
    Ok(Provision {
        dbus_daemon: dbus_root.join("bin/dbus-daemon"),
        xdp_root: resolved[1].clone(),
        gtk_root: resolved[2].clone(),
        update_desktop_db: resolved[3].join("bin/update-desktop-database"),
        roots,
    })
}

/// The cage environment pointing a D-Bus/portal client at the private bus and the GTK backend:
/// the bus address, the keyfile GSettings backend (no dconf daemon in the cage), the settings
/// portal opt-in, the portal directory carrying the GTK backend's `gtk.portal`, and the config
/// directory carrying the generated `portals.conf`. `XDG_*` are data paths, not code-load paths,
/// so an untrusted `[env]` that re-points them only sabotages the cage's own portal lookup
/// (self-DoS), never an escape — like `WAYLAND_DISPLAY`, they need no denylist entry.
pub(crate) fn env(gtk_root: &Path) -> Vec<(String, String)> {
    vec![
        (
            "DBUS_SESSION_BUS_ADDRESS".to_string(),
            format!("unix:path={CAGE_SOCK}"),
        ),
        ("GSETTINGS_BACKEND".to_string(), "keyfile".to_string()),
        // Make GDK read its settings from the portal. A Chromium/Electron app is its own portal
        // client and picks the theme up unaided, but GDK only consults the settings portal when it
        // believes it is sandboxed — which it detects from this variable or from a Flatpak marker
        // the cage does not carry. Without it a GTK app ignores the light/dark preference the
        // portal is already serving it: the seed lands in the keyfile, the relay rewrites it on
        // every host switch, the in-cage portal re-emits `SettingChanged`, and the window stays on
        // its default theme regardless. With it, a GTK app opens in the host scheme and follows a
        // switch live, like an Electron one. It also routes GTK's own dialogs (file chooser, print)
        // through the portal, which is where the cage renders them anyway.
        ("GTK_USE_PORTAL".to_string(), "1".to_string()),
        (
            "XDG_DESKTOP_PORTAL_DIR".to_string(),
            gtk_root
                .join("share/xdg-desktop-portal/portals")
                .display()
                .to_string(),
        ),
        ("XDG_CONFIG_DIRS".to_string(), CAGE_DIR.to_string()),
    ]
}

/// The private session-bus configuration: listen on the cage-tmpfs socket, activate the portal
/// services from the two portal packages' `share/dbus-1/services`, and default-allow (every peer on
/// this bus is the same uid inside the same cage — one trust domain). Every interpolated value is an
/// sbx-controlled store path or a fixed literal, so the document carries nothing to escape. Pure.
fn session_conf(sock: &str, xdp_root: &Path, gtk_root: &Path) -> String {
    format!(
        "<!DOCTYPE busconfig PUBLIC \"-//freedesktop//DTD D-Bus Bus Configuration 1.0//EN\" \
         \"http://www.freedesktop.org/standards/dbus/1.0/busconfig.dtd\">\n\
         <busconfig>\n\
         \x20 <type>session</type>\n\
         \x20 <listen>unix:path={sock}</listen>\n\
         \x20 <servicedir>{xdp}/share/dbus-1/services</servicedir>\n\
         \x20 <servicedir>{gtk}/share/dbus-1/services</servicedir>\n\
         \x20 <policy context=\"default\">\n\
         \x20   <allow own=\"*\"/>\n\
         \x20   <allow send_destination=\"*\"/>\n\
         \x20   <allow receive_sender=\"*\"/>\n\
         \x20 </policy>\n\
         </busconfig>\n",
        xdp = xdp_root.display(),
        gtk = gtk_root.display(),
    )
}

/// The portal front-end's backend selection: prefer the GTK backend for every interface. This is
/// the load-bearing key that makes the front-end route the file chooser to the in-cage GTK backend
/// (a "last-resort" fallback it honours), rather than needing `XDG_CURRENT_DESKTOP`.
const PORTALS_CONF: &str = "[preferred]\ndefault=gtk\n";

/// The in-cage GSettings keyfile, relative to the cage's `$HOME`. The launch seed writes it in-cage;
/// the live-theme relay rewrites it host-side through the home bind. The in-cage GSettings keyfile
/// backend watches this file, so a rewrite makes `xdg-desktop-portal-gtk` re-emit `SettingChanged`.
pub(crate) const KEYFILE_REL: &str = ".config/glib-2.0/settings/keyfile";

/// The keyfile body seeding the host theme so the app and the file dialog open in the right
/// light/dark scheme. Maps a color-scheme name to its GSettings keyfile form. Shared by the launch
/// seed and the theme relay so the two write byte-identical content, and rewritten live by the relay
/// so both surfaces follow a host light/dark switch. Pure.
///
/// Two keys, one for each surface. `color-scheme` drives the **app** (Chromium reads it from the
/// portal). `gtk-theme` drives the **file dialog** rendered by `xdg-desktop-portal-gtk`: GTK3 has no
/// GSettings key for "the dark variant of the current theme" (`gtk-application-prefer-dark-theme` is
/// not a key in `org.gnome.desktop.interface`, and `color-scheme` is inert on GTK3's own theming),
/// so the dark scheme must name a *distinct* dark theme — `Adwaita-dark`, the standalone theme the
/// GUI-data hole stages from `gnome-themes-extra` (GTK itself carries only the light built-in). GTK3
/// watches this key live via the keyfile backend, so a relay rewrite re-themes the open dialog.
pub(crate) fn keyfile_body(color_scheme: &str) -> String {
    format!(
        "[org/gnome/desktop/interface]\ncolor-scheme='{color_scheme}'\ngtk-theme='{gtk}'\n",
        gtk = gtk_theme_for(color_scheme),
    )
}

/// The named GTK theme for a color scheme: the standalone `Adwaita-dark` under `prefer-dark`, else
/// the light `Adwaita` (`prefer-light` and the no-preference `default` both open light, matching the
/// host desktop's own no-preference behaviour). Pure.
fn gtk_theme_for(color_scheme: &str) -> &'static str {
    if color_scheme == "prefer-dark" {
        "Adwaita-dark"
    } else {
        "Adwaita"
    }
}

/// Wrap `cmd` so the cage stands up its private portal before the app runs: write the generated bus
/// config and `portals.conf`, seed the host theme (when `color_scheme` is `Some`), start
/// `dbus-daemon --fork` (which blocks until the socket is ready, then returns — no race), and
/// `exec "$@"`. The command rides `"$@"` positionally, so nothing from it is re-parsed by the shell;
/// every value baked into the script is an sbx-controlled store path or a fixed literal. The heredoc
/// bodies use a quoted delimiter so the shell performs no expansion on the (already-substituted)
/// config. Pure over its inputs, so the shape is unit-tested without launching a cage.
pub(crate) fn wrap_command(
    bash: &Path,
    dbus_daemon: &Path,
    xdp_root: &Path,
    gtk_root: &Path,
    update_desktop_db: &Path,
    color_scheme: Option<&str>,
    cmd: Vec<OsString>,
) -> Vec<OsString> {
    let session = session_conf(CAGE_SOCK, xdp_root, gtk_root);
    let seed = match color_scheme {
        Some(scheme) => {
            // The keyfile is shared with the theme relay via `KEYFILE_REL` (its parent is the dir to
            // create) so the seed and the live rewrites target the same file. It carries both surface
            // keys: `color-scheme` (the app follows it) and `gtk-theme` (the file dialog follows it),
            // and GTK3 watches the keyfile backend so a relay rewrite re-themes an open dialog live —
            // no static `GTK_THEME` env, which GTK reads once at start and could not follow a switch.
            let kf_parent = KEYFILE_REL.rsplit_once('/').map_or(KEYFILE_REL, |(p, _)| p);
            format!(
                "mkdir -p \"$HOME/{kf_parent}\" 2>/dev/null\n\
                 cat > \"$HOME/{KEYFILE_REL}\" <<'SBXPORTALKF' 2>/dev/null || true\n\
                 {keyfile}SBXPORTALKF\n",
                keyfile = keyfile_body(scheme),
            )
        }
        None => String::new(),
    };
    // A quoted heredoc delimiter (`'SBXPORTALCF'`) disables every shell expansion, so the config —
    // already fully substituted host-side — is written verbatim.
    // Index the app's desktop-database in the background so the portal's `OpenURI` can resolve a
    // deep-link handler the app registers (a `.desktop` with `MimeType=x-scheme-handler/<scheme>`,
    // e.g. an OAuth-callback scheme): the portal launches only an app in the *registered/recommended*
    // list, which `update-desktop-database` builds — the bare `mimeapps.list` default is not enough.
    // The app writes its `.desktop` in its OWN command preamble (which `exec "$@"` runs AFTER this),
    // then opens the URL only much later (at login), so a short bounded retry catches the file whenever
    // it lands. Best-effort, never blocks; the background job dies with the cage (its PID-1 reaper).
    let index = format!(
        "( for _ in 1 2 3; do \"{udd}\" \"$HOME/.local/share/applications\" >/dev/null 2>&1; \
         sleep 1; done ) &\n",
        udd = update_desktop_db.display(),
    );
    let preamble = format!(
        "mkdir -p {dir}/xdg-desktop-portal 2>/dev/null\n\
         cat > {dir}/session.conf <<'SBXPORTALCF'\n{session}SBXPORTALCF\n\
         cat > {dir}/xdg-desktop-portal/portals.conf <<'SBXPORTALPF'\n{portals}SBXPORTALPF\n\
         {seed}\
         {daemon} --config-file={dir}/session.conf --fork </dev/null >/dev/null 2>&1 || true\n\
         {index}",
        dir = CAGE_DIR,
        daemon = dbus_daemon.display(),
        portals = PORTALS_CONF,
    );
    super::egress::wrap_background(bash, &preamble, "sbx-incage-portal", cmd)
}

/// The GSettings keyfile value for a freedesktop `appearance color-scheme` `uint32`: `1` =
/// prefer-dark, `2` = prefer-light, anything else (`0`/no-preference) = default. Shared by the
/// launch-time read and the live theme relay so the two cannot map the same value differently.
pub(crate) fn color_scheme_name(n: u32) -> &'static str {
    match n {
        1 => "prefer-dark",
        2 => "prefer-light",
        _ => "default",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_conf_lists_both_servicedirs_and_the_cage_socket_only() {
        let conf = session_conf(
            CAGE_SOCK,
            Path::new("/nix/store/aaa-xdg-desktop-portal"),
            Path::new("/nix/store/bbb-xdg-desktop-portal-gtk"),
        );
        // listens on the portal runtime socket (a host dir bound into the cage at /run/sbx-portal)
        assert!(conf.contains("<listen>unix:path=/run/sbx-portal/bus</listen>"));
        // both portal packages' service dirs are activation sources
        assert!(conf.contains("/nix/store/aaa-xdg-desktop-portal/share/dbus-1/services"));
        assert!(conf.contains("/nix/store/bbb-xdg-desktop-portal-gtk/share/dbus-1/services"));
        // a session bus (not the system bus) with an internal default-allow policy
        assert!(conf.contains("<type>session</type>"));
        assert!(conf.contains("<allow own=\"*\"/>"));
        // well-formed enough to be a single busconfig document
        assert!(conf.trim_start().starts_with("<!DOCTYPE busconfig"));
        assert!(conf.trim_end().ends_with("</busconfig>"));
    }

    #[test]
    fn env_points_the_client_at_the_private_bus_and_the_gtk_backend() {
        let env = env(Path::new("/nix/store/bbb-xdg-desktop-portal-gtk"));
        let get = |k: &str| env.iter().find(|(x, _)| x == k).map(|(_, v)| v.clone());
        assert_eq!(
            get("DBUS_SESSION_BUS_ADDRESS").as_deref(),
            Some("unix:path=/run/sbx-portal/bus")
        );
        assert_eq!(get("GSETTINGS_BACKEND").as_deref(), Some("keyfile"));
        // Without this opt-in GDK never asks the portal for the light/dark preference, so a GTK
        // app stays on its default theme while an Electron one in the same cage follows the host.
        assert_eq!(get("GTK_USE_PORTAL").as_deref(), Some("1"));
        assert_eq!(
            get("XDG_DESKTOP_PORTAL_DIR").as_deref(),
            Some("/nix/store/bbb-xdg-desktop-portal-gtk/share/xdg-desktop-portal/portals")
        );
        assert_eq!(get("XDG_CONFIG_DIRS").as_deref(), Some("/run/sbx-portal"));
    }

    #[test]
    fn wrap_command_starts_the_daemon_positionally_and_seeds_the_theme() {
        let cmd = vec![OsString::from("demo-app"), OsString::from("--flag")];
        let argv = wrap_command(
            Path::new("/bin/bash"),
            Path::new("/nix/store/ddd-dbus/bin/dbus-daemon"),
            Path::new("/nix/store/aaa-xdg-desktop-portal"),
            Path::new("/nix/store/bbb-xdg-desktop-portal-gtk"),
            Path::new("/nix/store/eee-dfu/bin/update-desktop-database"),
            Some("prefer-dark"),
            cmd,
        );
        // bash -c <script> <label> then the command positionally
        assert_eq!(argv[0], OsString::from("/bin/bash"));
        assert_eq!(argv[1], OsString::from("-c"));
        let script = argv[2].to_string_lossy();
        // the daemon is started with --fork (blocks until the socket is ready), config from the cage
        assert!(script.contains(
            "/nix/store/ddd-dbus/bin/dbus-daemon --config-file=/run/sbx-portal/session.conf --fork"
        ));
        // portals.conf selects the gtk backend
        assert!(script.contains("default=gtk"));
        // the theme is seeded into the keyfile: color-scheme (the app follows it) AND a named
        // gtk-theme (the file dialog follows it), both live-switchable via the keyfile backend
        assert!(script.contains("color-scheme='prefer-dark'"));
        assert!(script.contains("gtk-theme='Adwaita-dark'"));
        // no static GTK_THEME env — GTK reads it once at start and could not follow a live switch;
        // the dialog's dark theme comes from the live-watched gtk-theme keyfile key instead
        assert!(!script.contains("GTK_THEME"));
        // the daemon is started plainly (no env prefix), config from the cage
        assert!(script.contains("\n/nix/store/ddd-dbus/bin/dbus-daemon --config-file="));
        // the desktop-database indexer is backgrounded (so it runs after the app registers its
        // deep-link handler), by absolute store path, targeting the cage home's applications dir
        assert!(script.contains(
            "\"/nix/store/eee-dfu/bin/update-desktop-database\" \"$HOME/.local/share/applications\""
        ));
        assert!(
            script.contains("done ) &"),
            "the indexer must be backgrounded: {script}"
        );
        // the command runs as "$@", never spliced into the script text
        assert!(script.trim_end().ends_with("exec \"$@\""));
        assert_eq!(argv[3], OsString::from("sbx-incage-portal"));
        assert_eq!(argv[4], OsString::from("demo-app"));
        assert_eq!(argv[5], OsString::from("--flag"));
    }

    #[test]
    fn wrap_command_without_a_theme_writes_no_keyfile() {
        let argv = wrap_command(
            Path::new("/bin/bash"),
            Path::new("/nix/store/ddd-dbus/bin/dbus-daemon"),
            Path::new("/nix/store/aaa-xdg-desktop-portal"),
            Path::new("/nix/store/bbb-xdg-desktop-portal-gtk"),
            Path::new("/nix/store/eee-dfu/bin/update-desktop-database"),
            None,
            vec![OsString::from("x")],
        );
        let script = argv[2].to_string_lossy();
        assert!(!script.contains("color-scheme"));
        assert!(!script.contains("gtk-theme"));
        assert!(!script.contains("keyfile"));
    }

    #[test]
    fn keyfile_body_pairs_the_color_scheme_with_a_named_gtk_theme() {
        // prefer-dark selects the standalone dark theme for the file dialog...
        let dark = keyfile_body("prefer-dark");
        assert!(dark.contains("color-scheme='prefer-dark'"));
        assert!(dark.contains("gtk-theme='Adwaita-dark'"));
        // ...while every non-dark scheme opens light Adwaita (prefer-light and the no-preference
        // default alike), never the nonexistent dark variant.
        for scheme in ["prefer-light", "default"] {
            let body = keyfile_body(scheme);
            assert!(body.contains(&format!("color-scheme='{scheme}'")));
            assert!(body.contains("gtk-theme='Adwaita'"));
            assert!(!body.contains("Adwaita-dark"));
        }
    }

    #[test]
    fn host_dir_is_per_launch_and_the_socket_sits_under_it() {
        let layout = Layout::under(Path::new("/data"));
        let dir = host_dir(&layout);
        // under <data>/portal, keyed by pid so concurrent launches never collide
        assert!(dir.starts_with(Path::new("/data").join("portal")));
        assert_eq!(
            dir.file_name().unwrap().to_string_lossy(),
            std::process::id().to_string()
        );
    }

    #[test]
    fn host_dir_create_makes_an_owner_only_dir_and_drop_removes_it() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = crate::testutil::TmpDir::new();
        let layout = Layout::under(tmp.path());
        let path;
        {
            let hd = HostDir::create(&layout).expect("create host dir");
            path = hd.dir().to_path_buf();
            assert!(path.is_dir());
            // owner-only
            let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o700);
            // the socket path is `bus` under the dir
            assert_eq!(hd.socket(), path.join("bus"));
        }
        // dropped → removed
        assert!(!path.exists());
    }
}
