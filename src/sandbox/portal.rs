//! The in-cage desktop portal (`dbus = "incage"`).
//!
//! A Chromium/Electron app on Linux opens its file chooser through the desktop portal
//! (`org.freedesktop.portal.FileChooser`). Under the filtered *host* bus (`dbus = true`) that
//! portal is the **host's**, whose dialog is a host-privileged file manager the cage must not be
//! able to summon — so ops refuses the FileChooser interface, and the app's "browse for a folder"
//! then fails (recent Chromium commits to the portal and no longer falls back to its in-process
//! GTK dialog once a portal advertises a new-enough version).
//!
//! `dbus = "incage"` gives the cage its **own** portal instead: a private D-Bus session bus runs
//! inside the cage carrying ops-provisioned `xdg-desktop-portal` with the reference GTK backend
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
//! host directory ops bind-mounts into the cage (at [`CAGE_DIR`]): the in-cage `dbus-daemon` creates
//! it there, so a host-side process can reach the private bus. That is what lets the desktop
//! notifications relay (`org.freedesktop.Notifications`, forwarded to the host daemon) attach to the
//! bus. The exposure is benign under ops's same-uid model: the directory is owner-only (0700), the
//! only host process that connects is ops's own relay, and every portal backend on the bus is
//! confined to the cage (the socket carries no reach the user's own uid does not already have). The
//! host light/dark theme is seeded into the cage at launch (read host-side, best-effort) so the
//! window opens in the right theme; live theme following is a further follow-up.
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
//! see `docs/guide/configuration/gui.md`) governs these interfaces too; the in-cage portal adds no
//! reach beyond the socket the display hole already grants.

use crate::store::{self, Layout};
use std::ffi::OsString;
use std::io;
use std::os::unix::fs::DirBuilderExt;
use std::path::{Path, PathBuf};
use std::process::Command;

/// The packages the in-cage portal needs, each `(nixpkgs attribute, the marker its output must
/// carry, gcroot name)`. `dbus` supplies the session-bus daemon (and `dbus-send`, used host-side to
/// read the theme); `xdg-desktop-portal` is the portal front-end; `xdg-desktop-portal-gtk` is the
/// GTK backend that renders the file dialog. They share the revision-keyed `gui` gcroot directory
/// with the fonts/certutil/gschemas (all GUI-hole provisions on the same channel), so `ops gc`
/// keeps or drops them together.
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
];

/// The cage-side mount point of the portal runtime directory: ops bind-mounts a host directory here
/// (read-write), so the private bus socket the in-cage `dbus-daemon` creates under it is reachable
/// from the host (the notifications relay connects to it). Under `/run/ops-portal` — ops's own path,
/// not `$XDG_RUNTIME_DIR` (which holds the pulse/gpg/ssh sockets) — it holds the generated bus config
/// and the socket.
pub(crate) const CAGE_DIR: &str = "/run/ops-portal";
/// The private session-bus socket, at its cage path. Through the bind this is the same file as
/// [`HostDir::socket`] on the host.
const CAGE_SOCK: &str = "/run/ops-portal/bus";

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
    /// Logical path of `dbus-send` (its *physical* form is run host-side to read the theme).
    pub(crate) dbus_send: PathBuf,
    /// Logical root of `xdg-desktop-portal` (its `share/dbus-1/services` is a bus servicedir).
    pub(crate) xdp_root: PathBuf,
    /// Logical root of `xdg-desktop-portal-gtk` (its servicedir plus the `gtk.portal` descriptor).
    pub(crate) gtk_root: PathBuf,
}

/// Provision the three portal packages into ops's store against the pinned `nixpkgs`, sharing the
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
    // `resolved` is in `PACKAGES` order: dbus, xdg-desktop-portal, xdg-desktop-portal-gtk.
    let dbus_root = &resolved[0];
    Ok(Provision {
        dbus_daemon: dbus_root.join("bin/dbus-daemon"),
        dbus_send: dbus_root.join("bin/dbus-send"),
        xdp_root: resolved[1].clone(),
        gtk_root: resolved[2].clone(),
        roots,
    })
}

/// The cage environment pointing a D-Bus/portal client at the private bus and the GTK backend:
/// the bus address, the keyfile GSettings backend (no dconf daemon in the cage), the portal
/// directory carrying the GTK backend's `gtk.portal`, and the config directory carrying the
/// generated `portals.conf`. `XDG_*` are data paths, not code-load paths, so an untrusted `[env]`
/// that re-points them only sabotages the cage's own portal lookup (self-DoS), never an escape —
/// like `WAYLAND_DISPLAY`, they need no denylist entry.
pub(crate) fn env(gtk_root: &Path) -> Vec<(String, String)> {
    vec![
        (
            "DBUS_SESSION_BUS_ADDRESS".to_string(),
            format!("unix:path={CAGE_SOCK}"),
        ),
        ("GSETTINGS_BACKEND".to_string(), "keyfile".to_string()),
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
/// ops-controlled store path or a fixed literal, so the document carries nothing to escape. Pure.
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

/// The keyfile body seeding the host theme so the app opens in the right light/dark scheme. Maps a
/// color-scheme name to its GSettings keyfile form. Shared by the launch seed and the theme relay so
/// the two write byte-identical content. Pure.
pub(crate) fn keyfile_body(color_scheme: &str) -> String {
    format!("[org/gnome/desktop/interface]\ncolor-scheme='{color_scheme}'\n")
}

/// Wrap `cmd` so the cage stands up its private portal before the app runs: write the generated bus
/// config and `portals.conf`, seed the host theme (when `color_scheme` is `Some`), start
/// `dbus-daemon --fork` (which blocks until the socket is ready, then returns — no race), and
/// `exec "$@"`. The command rides `"$@"` positionally, so nothing from it is re-parsed by the shell;
/// every value baked into the script is an ops-controlled store path or a fixed literal. The heredoc
/// bodies use a quoted delimiter so the shell performs no expansion on the (already-substituted)
/// config. Pure over its inputs, so the shape is unit-tested without launching a cage.
pub(crate) fn wrap_command(
    bash: &Path,
    dbus_daemon: &Path,
    xdp_root: &Path,
    gtk_root: &Path,
    color_scheme: Option<&str>,
    cmd: Vec<OsString>,
) -> Vec<OsString> {
    let session = session_conf(CAGE_SOCK, xdp_root, gtk_root);
    let seed = match color_scheme {
        Some(scheme) => {
            // The keyfile color-scheme drives the *app* (Chromium/GTK4 read it), but the portal's
            // GTK3 file-dialog backend does not follow it for its own theme — so under a dark host
            // force the dark variant of its Adwaita theme, so the in-cage dialog matches the app
            // rather than opening light against a dark app. `export` in the preamble reaches both
            // the app and the dbus-daemon-activated backend; light/default leaves Adwaita default.
            let gtk_dark = if scheme == "prefer-dark" {
                "export GTK_THEME=Adwaita:dark\n"
            } else {
                ""
            };
            // The keyfile path is shared with the theme relay via `KEYFILE_REL` (its parent is the
            // dir to create) so the seed and the live rewrites always target the same file.
            let kf_parent = KEYFILE_REL.rsplit_once('/').map_or(KEYFILE_REL, |(p, _)| p);
            format!(
                "{gtk_dark}mkdir -p \"$HOME/{kf_parent}\" 2>/dev/null\n\
                 cat > \"$HOME/{KEYFILE_REL}\" <<'OPSPORTALKF' 2>/dev/null || true\n\
                 {keyfile}OPSPORTALKF\n",
                keyfile = keyfile_body(scheme),
            )
        }
        None => String::new(),
    };
    // A quoted heredoc delimiter (`'OPSPORTALCF'`) disables every shell expansion, so the config —
    // already fully substituted host-side — is written verbatim.
    let preamble = format!(
        "mkdir -p {dir}/xdg-desktop-portal 2>/dev/null\n\
         cat > {dir}/session.conf <<'OPSPORTALCF'\n{session}OPSPORTALCF\n\
         cat > {dir}/xdg-desktop-portal/portals.conf <<'OPSPORTALPF'\n{portals}OPSPORTALPF\n\
         {seed}\
         {daemon} --config-file={dir}/session.conf --fork </dev/null >/dev/null 2>&1 || true\n",
        dir = CAGE_DIR,
        daemon = dbus_daemon.display(),
        portals = PORTALS_CONF,
    );
    super::egress::wrap_background(bash, &preamble, "ops-incage-portal", cmd)
}

/// Read the host's light/dark preference, best-effort, by running the provisioned `dbus-send`
/// host-side against the real session bus (`org.freedesktop.appearance color-scheme`). Returns the
/// GSettings keyfile value (`prefer-dark`/`prefer-light`/`default`), or `None` when there is no
/// session bus, the binary cannot run host-side (its interpreter lives under a store `/nix` this
/// host may not have), or the reply cannot be parsed — in which case the app simply opens in its
/// default theme. `dbus_send` is the **physical** host path of the provisioned binary.
pub(crate) fn read_host_color_scheme(dbus_send: &Path) -> Option<String> {
    if std::env::var_os("DBUS_SESSION_BUS_ADDRESS").is_none()
        && std::env::var_os("XDG_RUNTIME_DIR").is_none()
    {
        return None;
    }
    let out = Command::new(dbus_send)
        .args([
            "--session",
            "--print-reply",
            // Fail fast: this is a best-effort read at launch, so a host with the portal present but
            // unresponsive must not stall every launch on `dbus-send`'s ~25s default timeout.
            "--reply-timeout=1000",
            "--dest=org.freedesktop.portal.Desktop",
            "/org/freedesktop/portal/desktop",
            "org.freedesktop.portal.Settings.Read",
            "string:org.freedesktop.appearance",
            "string:color-scheme",
        ])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    parse_color_scheme(&String::from_utf8_lossy(&out.stdout))
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

/// Parse the `org.freedesktop.appearance color-scheme` reply into its GSettings keyfile value. The
/// value is a nested variant carrying a `uint32`. `None` when no `uint32` is present. Pure.
fn parse_color_scheme(reply: &str) -> Option<String> {
    let n: u32 = reply
        .split_whitespace()
        .skip_while(|t| *t != "uint32")
        .nth(1)?
        .parse()
        .ok()?;
    Some(color_scheme_name(n).to_string())
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
        // listens on the portal runtime socket (a host dir bound into the cage at /run/ops-portal)
        assert!(conf.contains("<listen>unix:path=/run/ops-portal/bus</listen>"));
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
            Some("unix:path=/run/ops-portal/bus")
        );
        assert_eq!(get("GSETTINGS_BACKEND").as_deref(), Some("keyfile"));
        assert_eq!(
            get("XDG_DESKTOP_PORTAL_DIR").as_deref(),
            Some("/nix/store/bbb-xdg-desktop-portal-gtk/share/xdg-desktop-portal/portals")
        );
        assert_eq!(get("XDG_CONFIG_DIRS").as_deref(), Some("/run/ops-portal"));
    }

    #[test]
    fn wrap_command_starts_the_daemon_positionally_and_seeds_the_theme() {
        let cmd = vec![OsString::from("claude-desktop"), OsString::from("--flag")];
        let argv = wrap_command(
            Path::new("/bin/bash"),
            Path::new("/nix/store/ddd-dbus/bin/dbus-daemon"),
            Path::new("/nix/store/aaa-xdg-desktop-portal"),
            Path::new("/nix/store/bbb-xdg-desktop-portal-gtk"),
            Some("prefer-dark"),
            cmd,
        );
        // bash -c <script> <label> then the command positionally
        assert_eq!(argv[0], OsString::from("/bin/bash"));
        assert_eq!(argv[1], OsString::from("-c"));
        let script = argv[2].to_string_lossy();
        // the daemon is started with --fork (blocks until the socket is ready), config from the cage
        assert!(script.contains(
            "/nix/store/ddd-dbus/bin/dbus-daemon --config-file=/run/ops-portal/session.conf --fork"
        ));
        // portals.conf selects the gtk backend
        assert!(script.contains("default=gtk"));
        // the theme is seeded into the keyfile GSettings store
        assert!(script.contains("color-scheme='prefer-dark'"));
        // and the GTK3 dialog backend is forced to the dark Adwaita variant to match the app
        assert!(script.contains("export GTK_THEME=Adwaita:dark"));
        // the command runs as "$@", never spliced into the script text
        assert!(script.trim_end().ends_with("exec \"$@\""));
        assert_eq!(argv[3], OsString::from("ops-incage-portal"));
        assert_eq!(argv[4], OsString::from("claude-desktop"));
        assert_eq!(argv[5], OsString::from("--flag"));
    }

    #[test]
    fn wrap_command_without_a_theme_writes_no_keyfile() {
        let argv = wrap_command(
            Path::new("/bin/bash"),
            Path::new("/nix/store/ddd-dbus/bin/dbus-daemon"),
            Path::new("/nix/store/aaa-xdg-desktop-portal"),
            Path::new("/nix/store/bbb-xdg-desktop-portal-gtk"),
            None,
            vec![OsString::from("x")],
        );
        let script = argv[2].to_string_lossy();
        assert!(!script.contains("color-scheme"));
        assert!(!script.contains("keyfile"));
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
        let tmp = std::env::temp_dir().join(format!("ops-portal-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        let layout = Layout::under(&tmp);
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
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn parse_color_scheme_maps_the_variant_uint() {
        // a real reply nests the uint in two variants
        let dark = "   variant       variant          uint32 1\n";
        assert_eq!(parse_color_scheme(dark).as_deref(), Some("prefer-dark"));
        assert_eq!(
            parse_color_scheme("variant variant uint32 2").as_deref(),
            Some("prefer-light")
        );
        assert_eq!(
            parse_color_scheme("variant variant uint32 0").as_deref(),
            Some("default")
        );
        // no uint present → cannot read
        assert_eq!(parse_color_scheme("method return\n"), None);
    }
}
