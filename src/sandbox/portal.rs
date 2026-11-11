//! The in-cage desktop portal (`dbus = true`).
//!
//! A Chromium/Electron app on Linux opens its file chooser through the desktop portal
//! (`org.freedesktop.portal.FileChooser`). If that portal were the **host's**, its dialog would be
//! a host-privileged file manager the cage must not be able to summon, so no cage is given the host
//! session bus.
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
//! The bus carries only in-cage services and never connects to the host session bus, so it is
//! unaffected by the network posture. Its socket, however, lives on a host directory sbx
//! bind-mounts into the cage (at [`CAGE_DIR`]): the in-cage `dbus-daemon` creates it there, so a
//! host-side process can reach the private bus. That is what lets the desktop notifications relay
//! (`org.freedesktop.Notifications`, forwarded to the host daemon) attach to the bus. The exposure
//! is benign under sbx's same-uid model: the directory is owner-only (0700), the only host process
//! that connects is sbx's own relay, and every portal backend on the bus is confined to the cage
//! (the socket carries no reach the user's own uid does not already have). The host light/dark
//! theme is seeded into the cage at launch (read host-side, best-effort) so both the app and the
//! file dialog open in the right theme, and a later host switch is followed live by the theme relay
//! (see [`super::theme_relay`]) rewriting the GSettings keyfile both surfaces watch.
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
/// `mimeapps.list` default) populates. `gnome-keyring` supplies `gnome-keyring-daemon`, which puts a
/// **Secret Service** (`org.freedesktop.secrets`) on the private bus: an Electron app asks
/// `safeStorage` where to keep its session token, and on Linux that question is answered by the
/// Secret Service. With none on the bus the app falls back to a plaintext store, and an app that
/// treats that fallback as fatal never finishes rendering. They share the revision-keyed `gui` gcroot directory with the
/// fonts/certutil/GUI data (all GUI-hole provisions on the same channel), so `sbx gc` keeps or drops
/// them together.
const PACKAGES: [(&str, &str, &str); 5] = [
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
    ("gnome-keyring", "bin/gnome-keyring-daemon", "gnome-keyring"),
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

/// The host directory bind-mounted into the cage at [`CAGE_DIR`], under `<data>/portal`, named by
/// the launcher pid alone: `sbx gc` reads the pid off the name to sweep a dead launch's directory.
/// Two launches of one process would name the same directory, which [`HostDir::create`] refuses.
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
    /// This process's hold on `dir`, given back once `Drop` has removed it: a field drops after
    /// the body of `Drop::drop`.
    _live: super::launchdir::LiveDir,
}

impl HostDir {
    /// Create the per-launch host portal directory, owner-only and empty, in an owner-only
    /// `<data>/portal`.
    ///
    /// A directory already at the name is a crashed predecessor's of the same pid, whose cage could
    /// write anything into it: [`super::launchdir::fresh_dir`] removes it, a read-only directory
    /// inside included, and makes it again, never adopting what sits at the name. A failure is
    /// returned rather than the directory reused as found, so the launch runs without a portal
    /// rather than in a directory that is not its own.
    ///
    /// A second launch of this process is refused while the first holds the directory
    /// ([`super::launchdir::LiveDir`]), rather than emptying the first's bus socket from under it.
    pub(crate) fn create(layout: &Layout) -> io::Result<HostDir> {
        use std::os::unix::fs::PermissionsExt;
        let dir = host_dir(layout);
        if let Some(parent) = dir.parent() {
            std::fs::DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(parent)?;
            std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700))?;
        }
        let live = super::launchdir::LiveDir::take(&dir)?;
        super::launchdir::fresh_dir(&dir)?;
        Ok(HostDir { dir, _live: live })
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
    /// Removed the way it was emptied: the cage may have left a read-only directory inside.
    fn drop(&mut self) {
        let _ = super::gc::force_remove_dir_all(&self.dir);
    }
}

/// The provisioned in-cage portal: the store roots to seed and the logical paths the cage uses.
pub(crate) struct Provision {
    /// Logical store roots of every package in [`PACKAGES`], in its order, to seed into the project
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
    /// Logical path of `gnome-keyring-daemon` (run in-cage from the wrap preamble, so the private
    /// bus carries a Secret Service the app's credential storage can use).
    pub(crate) keyring_daemon: PathBuf,
}

/// Provision the five portal packages into sbx's store against the pinned `nixpkgs`, sharing the
/// revision-keyed `gui` gcroot directory with the other GUI-hole provisions.
///
/// Each package is named where it is used: [`PACKAGES`] is taken apart by position into one binding
/// per package, so a list that gained or lost an entry no longer compiles, where reading the roots
/// back by index panicked at the missing one or handed one package's root to another's field.
pub(crate) fn provision(nix: &Path, layout: &Layout, nixpkgs: &str) -> io::Result<Provision> {
    let base = layout
        .data_dir()
        .join("gcroots")
        .join("gui")
        .join(store::revision_of(nixpkgs));
    let get = |(attr, marker, name): (&str, &str, &str)| {
        store::provision(nix, layout, &base.join(name), nixpkgs, attr, marker)
    };
    let [dbus, xdp, gtk, dfu, keyring] = PACKAGES;
    let dbus = get(dbus)?;
    let xdp = get(xdp)?;
    let gtk = get(gtk)?;
    let dfu = get(dfu)?;
    let keyring = get(keyring)?;
    Ok(Provision {
        dbus_daemon: dbus.join("bin/dbus-daemon"),
        update_desktop_db: dfu.join("bin/update-desktop-database"),
        keyring_daemon: keyring.join("bin/gnome-keyring-daemon"),
        roots: vec![dbus, xdp.clone(), gtk.clone(), dfu, keyring],
        xdp_root: xdp,
        gtk_root: gtk,
    })
}

/// The variable that points the cage's clients at its session bus. Named because a broker plugin's
/// manifest may not claim it ([`super::CHANNEL_ENV_KEYS`]).
pub(crate) const BUS_ADDRESS_ENV: &str = "DBUS_SESSION_BUS_ADDRESS";

/// The cage environment pointing a D-Bus/portal client at the private bus and the GTK backend:
/// the bus address, the keyfile GSettings backend (no dconf daemon in the cage), the settings
/// portal opt-in, the portal directory carrying the GTK backend's `gtk.portal`, and the config
/// directory carrying the generated `portals.conf`. Most of `XDG_*` are data paths, not code-load
/// paths, so an untrusted `[env]` that re-points them only sabotages the cage's own portal lookup
/// (self-DoS), never an escape — like `WAYLAND_DISPLAY`, they need no denylist entry.
///
/// **`XDG_DATA_HOME` and `XDG_CONFIG_HOME` are the exception, and they are reserved**
/// ([`crate::config::is_reserved_env_key`]). The self-DoS reasoning holds only while nothing
/// *else* is resolved through those two directories, and [`super::openuri`] is: it freezes the
/// OpenURI route by binding its desktop entry and `mimeapps.list` read-only at the locations the
/// XDG lookup prefers, which outranks a copy elsewhere only while these stay unset. Re-pointing
/// them substitutes the handler that answers a sign-in click the user made, which is not the
/// cage sabotaging itself.
pub(crate) fn env(gtk_root: &Path) -> Vec<(String, String)> {
    vec![
        (
            BUS_ADDRESS_ENV.to_string(),
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

/// The largest message the private bus carries, in bytes; the in-cage `dbus-daemon` disconnects a
/// peer that sends a larger one.
///
/// Defense in depth for the notifications relay ([`super::notify_relay`]), which reads this bus from
/// the supervisor and weighs each call whole before decoding it: this ceiling is what keeps the
/// calls queued ahead of that check small. It is not the relay's own ceiling, because the portal's
/// traffic crosses this bus too, and it cannot be the relay's only one either: the configuration
/// is written inside the cage, which can start a server of its own in place of this daemon.
pub(super) const BUS_MESSAGE_MAX: usize = 4 << 20;

/// The private session-bus configuration: listen on the cage-tmpfs socket, activate the portal
/// services from the two portal packages' `share/dbus-1/services`, default-allow (every peer on
/// this bus is the same uid inside the same cage — one trust domain), and refuse a message over
/// [`BUS_MESSAGE_MAX`]. Pure.
///
/// The socket is written as a D-Bus address, which escapes every byte the address grammar reserves:
/// `dbus-daemon` refuses a space or a quote there, and decodes a `%`. The service directories are
/// written as XML text, with `&`, `<` and `>` escaped. XML holds UTF-8 only, so a directory whose
/// name is not UTF-8 is written with U+FFFD in place of its invalid bytes, which names another
/// directory. The launch passes a constant and two store paths, which hold none of these bytes.
pub(super) fn session_conf(sock: &str, xdp_root: &Path, gtk_root: &Path) -> String {
    use zbus::address::transport::{Transport, Unix, UnixSocket};
    let listen = Transport::Unix(Unix::new(UnixSocket::File(PathBuf::from(sock))));
    format!(
        "<!DOCTYPE busconfig PUBLIC \"-//freedesktop//DTD D-Bus Bus Configuration 1.0//EN\" \
         \"http://www.freedesktop.org/standards/dbus/1.0/busconfig.dtd\">\n\
         <busconfig>\n\
         \x20 <type>session</type>\n\
         \x20 <listen>{listen}</listen>\n\
         \x20 <servicedir>{xdp}/share/dbus-1/services</servicedir>\n\
         \x20 <servicedir>{gtk}/share/dbus-1/services</servicedir>\n\
         \x20 <policy context=\"default\">\n\
         \x20   <allow own=\"*\"/>\n\
         \x20   <allow send_destination=\"*\"/>\n\
         \x20   <allow receive_sender=\"*\"/>\n\
         \x20 </policy>\n\
         \x20 <limit name=\"max_message_size\">{BUS_MESSAGE_MAX}</limit>\n\
         </busconfig>\n",
        xdp = xml_text(&xdp_root.display().to_string()),
        gtk = xml_text(&gtk_root.display().to_string()),
    )
}

/// `text` as XML character data: `&`, `<` and `>` escaped, every other character as it is.
fn xml_text(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            c => out.push(c),
        }
    }
    out
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
///
/// `None` for anything but the three names [`color_scheme_name`] maps to. The scheme is written
/// between quotes into this body, and the launch seed writes the body into a heredoc its preamble
/// runs: a quote there adds a GSettings key, and a line holding the heredoc's delimiter ends it
/// early and runs what follows as shell. Every source of a scheme yields one of the three names,
/// so a value outside them seeds nothing rather than being written as found.
pub(crate) fn keyfile_body(color_scheme: &str) -> Option<String> {
    let gtk = gtk_theme_for(color_scheme)?;
    Some(format!(
        "[org/gnome/desktop/interface]\ncolor-scheme='{color_scheme}'\ngtk-theme='{gtk}'\n"
    ))
}

/// The named GTK theme for a color scheme: the standalone `Adwaita-dark` under `prefer-dark`, the
/// light `Adwaita` under `prefer-light` and the no-preference `default` (both open light, matching
/// the host desktop's own no-preference behaviour), and `None` for any other name. Pure.
fn gtk_theme_for(color_scheme: &str) -> Option<&'static str> {
    match color_scheme {
        "prefer-dark" => Some("Adwaita-dark"),
        "prefer-light" | "default" => Some("Adwaita"),
        _ => None,
    }
}

/// Wrap `cmd` so the cage stands up its private portal before the app runs: write the generated bus
/// config and `portals.conf`, seed the host theme (when `color_scheme` is one of the names
/// [`keyfile_body`] writes), start
/// `dbus-daemon --fork` (which blocks until the socket is ready, then returns — no race), and
/// `exec "$@"`. The command rides `"$@"` positionally, so nothing from it is re-parsed by the shell;
/// every value baked into the script is an sbx-controlled store path or a fixed literal, and each
/// path is written as one single-quoted word, so the shell reads it back as itself whatever it
/// holds. The heredoc bodies use a quoted delimiter so the shell performs no expansion on the
/// (already-substituted) config. Pure over its inputs, so the shape is unit-tested without launching
/// a cage, and the script it writes is run under `bash` with stand-ins for every program it names.
pub(crate) fn wrap_command(
    bash: &Path,
    env_bin: &Path,
    provision: &Provision,
    color_scheme: Option<&str>,
    cmd: Vec<OsString>,
) -> Vec<OsString> {
    wrap_command_at(
        Path::new(CAGE_DIR),
        bash,
        env_bin,
        provision,
        color_scheme,
        cmd,
    )
}

/// [`wrap_command`] with the portal directory at `dir`. The launch passes [`CAGE_DIR`]; a test
/// passes a directory of its own, so the script it writes can be run outside a cage.
fn wrap_command_at(
    dir: &Path,
    bash: &Path,
    env_bin: &Path,
    provision: &Provision,
    color_scheme: Option<&str>,
    cmd: Vec<OsString>,
) -> Vec<OsString> {
    // The coreutils this preamble does its housekeeping with, by absolute store path like the bus
    // daemon and the keyring: the preamble is the cage's first process and runs before the `[proc]`
    // shim installs its filter, while the cage's PATH leads through directories the cage itself can
    // write (its own store, its mise shims) — so a bare name would let in-cage code pick what runs
    // unfiltered. `plumbing_pins` pins the store root they live in read-only.
    //
    // Each path is written as one shell word, quoted, whatever bytes it holds: a store path never
    // carries a quote, a space or a `$`, but nothing in this function is what says so.
    let word = |path: &Path| super::shell_quote(&path.display().to_string());
    let mkdir = word(&env_bin.with_file_name("mkdir"));
    let cat = word(&env_bin.with_file_name("cat"));
    let sleep = word(&env_bin.with_file_name("sleep"));
    let send = word(&provision.dbus_daemon.with_file_name("dbus-send"));
    let Provision {
        dbus_daemon,
        xdp_root,
        gtk_root,
        update_desktop_db,
        keyring_daemon,
        ..
    } = provision;
    let session = session_conf(&dir.join("bus").display().to_string(), xdp_root, gtk_root);
    let seed = match color_scheme.and_then(keyfile_body) {
        Some(keyfile) => {
            // The keyfile is shared with the theme relay via `KEYFILE_REL` (its parent is the dir to
            // create) so the seed and the live rewrites target the same file. It carries both surface
            // keys: `color-scheme` (the app follows it) and `gtk-theme` (the file dialog follows it),
            // and GTK3 watches the keyfile backend so a relay rewrite re-themes an open dialog live —
            // no static `GTK_THEME` env, which GTK reads once at start and could not follow a switch.
            let kf_parent = KEYFILE_REL.rsplit_once('/').map_or(KEYFILE_REL, |(p, _)| p);
            format!(
                "{mkdir} -p \"$HOME/{kf_parent}\" 2>/dev/null\n\
                 {cat} > \"$HOME/{KEYFILE_REL}\" <<'SBXPORTALKF' 2>/dev/null || true\n\
                 {keyfile}SBXPORTALKF\n"
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
        "( for _ in 1 2 3; do {udd} \"$HOME/.local/share/applications\" >/dev/null 2>&1; \
         {sleep} 1; done ) &\n",
        udd = word(update_desktop_db),
    );
    // The Secret Service, started AFTER the bus it registers on. `--daemonize` returns once the
    // daemon has read the passphrase and forked, but before it claims `org.freedesktop.secrets`,
    // which it does from its main loop: the name is not on the bus when the foreground process
    // exits. So the preamble then waits for the name to have an owner, asking the bus through the
    // `dbus-send` beside the daemon, for at most five seconds, and the app that `exec "$@"` runs
    // next finds the service there. The passphrase arrives on stdin (never in the argv a `[proc]`
    // lens would record), and `--components=secrets` starts only the Secret Service: no ssh-agent
    // (sbx brokers that one), no PKCS#11. The keyring file lands in the app's isolated home, so a
    // login stored on one launch is still there on the next. Best-effort like the rest of the
    // preamble: a cage whose keyring will not open still launches, with the app back on whatever
    // fallback it chooses.
    let keyring = format!(
        "if printf %s {pass} | {kr} --unlock --components=secrets --daemonize \
         >/dev/null 2>&1; then\n\
         for _ in {{1..50}}; do\n\
         case \"$({send} --session --print-reply --dest=org.freedesktop.DBus /org/freedesktop/DBus \
         org.freedesktop.DBus.NameHasOwner string:{SECRETS_NAME} 2>/dev/null)\" in\n\
         *'boolean true'*) break ;;\n\
         esac\n\
         {sleep} 0.1\n\
         done\n\
         fi\n",
        pass = super::shell_quote(KEYRING_PASSPHRASE),
        kr = word(keyring_daemon),
    );
    let preamble = format!(
        "{mkdir} -p {portal_dir} 2>/dev/null\n\
         {cat} > {session_file} <<'SBXPORTALCF'\n{session}SBXPORTALCF\n\
         {cat} > {portals_file} <<'SBXPORTALPF'\n{portals}SBXPORTALPF\n\
         {seed}\
         {daemon} --config-file={session_file} --fork </dev/null >/dev/null 2>&1 || true\n\
         {keyring}\
         {index}",
        portal_dir = word(&dir.join("xdg-desktop-portal")),
        session_file = word(&dir.join("session.conf")),
        portals_file = word(&dir.join("xdg-desktop-portal/portals.conf")),
        daemon = word(dbus_daemon),
        portals = PORTALS_CONF,
    );
    super::egress::wrap_background(bash, &preamble, "sbx-incage-portal", cmd)
}

/// The bus name the in-cage Secret Service claims, which the preamble waits on.
const SECRETS_NAME: &str = "org.freedesktop.secrets";

/// The passphrase the in-cage keyring is unlocked with. A fixed literal on purpose: the keyring
/// file lives in the app's isolated cage home and must reopen on every later launch, so the
/// passphrase has to be stable and nobody is there to type one. That makes it a weak key, at exactly
/// the trust level the plaintext fallback it replaces already had — what it buys is not secrecy
/// against someone who can read that home (they can read the home either way, and under sbx's
/// same-uid model that is the user themselves) but a **working** Secret Service, which several apps
/// now require to start at all.
const KEYRING_PASSPHRASE: &str = "sbx-in-cage";

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
        // a message ceiling, so the calls queued for the notifications relay stay small
        assert!(conf.contains("<limit name=\"max_message_size\">4194304</limit>"));
        // well-formed enough to be a single busconfig document
        assert!(conf.trim_start().starts_with("<!DOCTYPE busconfig"));
        assert!(conf.trim_end().ends_with("</busconfig>"));
    }

    /// The socket is written as a D-Bus address and each service directory as XML text, so a byte
    /// either grammar reserves reaches `dbus-daemon` as itself: unescaped, a space or a quote makes
    /// the daemon refuse the address, and a `%` names another path once decoded.
    #[test]
    fn session_conf_escapes_the_socket_as_an_address_and_the_servicedirs_as_xml() {
        let conf = session_conf(
            "/r/a b/\"q\"/%41/x&y/bus",
            Path::new("/s/x&y<z>"),
            Path::new("/s/plain"),
        );
        assert!(
            conf.contains("<listen>unix:path=/r/a%20b/%22q%22/%2541/x%26y/bus</listen>"),
            "{conf}"
        );
        assert!(
            conf.contains("<servicedir>/s/x&amp;y&lt;z&gt;/share/dbus-1/services</servicedir>"),
            "{conf}"
        );
        assert!(
            conf.contains("<servicedir>/s/plain/share/dbus-1/services</servicedir>"),
            "{conf}"
        );
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

    /// The store paths a `wrap_command` test needs, as one value: the function reads them off a
    /// [`Provision`], so a test that built them separately would be asserting against a shape the
    /// caller does not have.
    fn demo_provision() -> Provision {
        Provision {
            roots: Vec::new(),
            dbus_daemon: PathBuf::from("/nix/store/ddd-dbus/bin/dbus-daemon"),
            xdp_root: PathBuf::from("/nix/store/aaa-xdg-desktop-portal"),
            gtk_root: PathBuf::from("/nix/store/bbb-xdg-desktop-portal-gtk"),
            update_desktop_db: PathBuf::from("/nix/store/eee-dfu/bin/update-desktop-database"),
            keyring_daemon: PathBuf::from("/nix/store/fff-gk/bin/gnome-keyring-daemon"),
        }
    }

    #[test]
    fn wrap_command_starts_the_daemon_positionally_and_seeds_the_theme() {
        let cmd = vec![OsString::from("demo-app"), OsString::from("--flag")];
        let argv = wrap_command(
            Path::new("/bin/bash"),
            Path::new("/nix/store/hash-coreutils/bin/env"),
            &demo_provision(),
            Some("prefer-dark"),
            cmd,
        );
        // bash -c <script> <label> then the command positionally
        assert_eq!(argv[0], OsString::from("/bin/bash"));
        assert_eq!(argv[1], OsString::from("-c"));
        let script = argv[2].to_string_lossy();
        // the daemon is started with --fork (blocks until the socket is ready), config from the cage
        assert!(script.contains(
            "'/nix/store/ddd-dbus/bin/dbus-daemon' --config-file='/run/sbx-portal/session.conf' --fork"
        ));
        // the bus listens on the socket under the portal directory, the one the cage's clients
        // are pointed at
        assert!(script.contains(&format!("<listen>unix:path={CAGE_SOCK}</listen>")));
        // portals.conf selects the gtk backend
        assert!(script.contains("default=gtk"));
        // every helper the preamble runs is an absolute store path, never a bare name: the
        // preamble is the cage's first process, before the `[proc]` shim filters anything, and
        // the cage's own PATH leads through directories the cage can write
        assert!(script.contains("'/nix/store/hash-coreutils/bin/mkdir' -p '/run/sbx-portal"));
        assert!(
            script.contains("'/nix/store/hash-coreutils/bin/cat' > '/run/sbx-portal/session.conf'")
        );
        assert!(script.contains("'/nix/store/hash-coreutils/bin/sleep' 1"));
        for bare in ["mkdir ", "cat ", "sleep "] {
            assert!(
                !script.contains(bare),
                "{bare} is run by name, which the cage's PATH decides: {script}"
            );
        }
        // the theme is seeded into the keyfile: color-scheme (the app follows it) AND a named
        // gtk-theme (the file dialog follows it), both live-switchable via the keyfile backend
        assert!(script.contains("color-scheme='prefer-dark'"));
        assert!(script.contains("gtk-theme='Adwaita-dark'"));
        // no static GTK_THEME env — GTK reads it once at start and could not follow a live switch;
        // the dialog's dark theme comes from the live-watched gtk-theme keyfile key instead
        assert!(!script.contains("GTK_THEME"));
        // the daemon is started plainly (no env prefix), config from the cage
        assert!(script.contains("\n'/nix/store/ddd-dbus/bin/dbus-daemon' --config-file="));
        // the desktop-database indexer is backgrounded (so it runs after the app registers its
        // deep-link handler), by absolute store path, targeting the cage home's applications dir
        assert!(script.contains(
            "'/nix/store/eee-dfu/bin/update-desktop-database' \"$HOME/.local/share/applications\""
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

    /// The Secret Service is what several Electron apps now consult before they finish rendering, so
    /// the preamble must start it — after the bus that carries it — and wait until it owns its name,
    /// so the app `exec "$@"` runs next cannot beat it there.
    #[test]
    fn the_preamble_starts_the_keyring_after_the_bus_and_waits_for_it() {
        let argv = wrap_command(
            Path::new("/bin/bash"),
            Path::new("/nix/store/hash-coreutils/bin/env"),
            &demo_provision(),
            None,
            vec![OsString::from("x")],
        );
        let script = argv[2].to_string_lossy();
        let bus = script
            .find("dbus-daemon' --config-file=")
            .expect("the bus is started");
        let keyring = script
            .find("gnome-keyring-daemon")
            .expect("the keyring is started");
        assert!(
            bus < keyring,
            "the keyring registers ON the bus, so it must start after it: {script}"
        );
        assert!(
            script.contains("--unlock --components=secrets --daemonize"),
            "the keyring must be started with only the Secret Service: {script}"
        );
        assert!(
            !script.contains("gnome-keyring-daemon --unlock --components=secrets --daemonize &"),
            "backgrounding it would let the app run before the daemon has even forked: {script}"
        );
        // `--daemonize` returns before the daemon claims its name, so the wait on the name is the
        // synchronization, and it asks the bus the daemon started through the `dbus-send` beside it.
        let wait = script
            .find(&format!("NameHasOwner string:{SECRETS_NAME}"))
            .expect("the preamble waits for the Secret Service's name");
        assert!(
            keyring < wait,
            "the wait follows the keyring's start: {script}"
        );
        assert!(
            script.contains("/nix/store/ddd-dbus/bin/dbus-send' --session"),
            "the name is asked of the private bus by the store's own dbus-send: {script}"
        );
        assert!(
            script.contains("for _ in {1..50}; do"),
            "the wait is bounded: {script}"
        );
    }

    /// A passphrase on the command line would be recorded verbatim by the `[proc]` lens, which
    /// writes the full argv of every exec it observes. Feeding it on stdin keeps it out of that
    /// record; the value is weak by design, but weak is not the same as published.
    #[test]
    fn the_keyring_passphrase_never_rides_the_argv() {
        let argv = wrap_command(
            Path::new("/bin/bash"),
            Path::new("/nix/store/hash-coreutils/bin/env"),
            &demo_provision(),
            None,
            vec![OsString::from("x")],
        );
        let script = argv[2].to_string_lossy();
        let start = script
            .find("gnome-keyring-daemon")
            .expect("the keyring is started");
        let line_end = script[start..]
            .find('\n')
            .map_or(script.len(), |n| start + n);
        let invocation = &script[start..line_end];
        assert!(
            !invocation.contains(KEYRING_PASSPHRASE),
            "the passphrase must not follow the binary on its own line: {invocation}"
        );
        assert!(
            script.contains(&format!("printf %s '{KEYRING_PASSPHRASE}' |")),
            "the passphrase must arrive on stdin: {script}"
        );
    }

    /// What running the preamble outside a cage left: how `bash` ended, and every line the
    /// stand-ins logged, one per run, each the path it was run by followed by its arguments.
    struct Preamble {
        ran: crate::testutil::Ran,
        log: String,
    }

    /// The stand-ins [`run_preamble`] installs under its root, by their place in a [`Provision`].
    fn stand_in_provision(root: &Path) -> (PathBuf, Provision) {
        let env_bin = root.join("coreutils/bin/env");
        let provision = Provision {
            roots: Vec::new(),
            dbus_daemon: root.join("dbus/bin/dbus-daemon"),
            xdp_root: root.join("xdp"),
            gtk_root: root.join("gtk"),
            update_desktop_db: root.join("dfu/bin/update-desktop-database"),
            keyring_daemon: root.join("gk/bin/gnome-keyring-daemon"),
        };
        (env_bin, provision)
    }

    /// Run the preamble [`wrap_command_at`] writes under a real `bash`, outside any cage, with its
    /// portal directory at `<root>/run` and `$HOME` at `<root>/home`. Every program it names is a
    /// stand-in under `root` that logs how it was run; `mkdir` and `cat` then do their real work,
    /// `sleep` returns at once, `dbus-send` answers that the name has an owner, and the bus daemon
    /// and the keyring exit 1 when named in `failing`, 0 otherwise. The command is a stand-in too,
    /// `<root>/app`.
    ///
    /// The environment is cleared, so nothing the script does can reach the real home. The run is
    /// made again while a stand-in it executes is still held open for writing by a fork in another
    /// test (`ETXTBSY`), and the background indexing loop is waited out before the log is read.
    fn run_preamble(root: &Path, scheme: Option<&str>, failing: &[&str]) -> Preamble {
        use crate::testutil::write_script;
        let (env_bin, provision) = stand_in_provision(root);
        let log = root.join("log");
        let log_line = "printf '%s\\n' \"$0 $*\" >> \"$SBX_TEST_LOG\"";
        let exit = |name: &str| {
            if failing.contains(&name) {
                "exit 1"
            } else {
                "exit 0"
            }
        };
        let programs: [(PathBuf, String); 9] = [
            (env_bin.clone(), format!("{log_line}\nexec env \"$@\"")),
            (
                env_bin.with_file_name("mkdir"),
                format!("{log_line}\nexec mkdir \"$@\""),
            ),
            (
                env_bin.with_file_name("cat"),
                format!("{log_line}\nexec cat \"$@\""),
            ),
            (env_bin.with_file_name("sleep"), log_line.to_string()),
            (
                provision.dbus_daemon.clone(),
                format!("{log_line}\n{}", exit("dbus-daemon")),
            ),
            (
                provision.dbus_daemon.with_file_name("dbus-send"),
                format!("{log_line}\nprintf 'boolean true\\n'"),
            ),
            (
                provision.update_desktop_db.clone(),
                format!("{log_line}\nexit 1"),
            ),
            (
                provision.keyring_daemon.clone(),
                format!("{log_line}\n{}", exit("gnome-keyring-daemon")),
            ),
            (root.join("app"), log_line.to_string()),
        ];
        for (path, body) in &programs {
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            write_script(path, body);
        }
        let dir = root.join("run");
        let home = root.join("home");
        let argv = wrap_command_at(
            &dir,
            Path::new("/bin/bash"),
            &env_bin,
            &provision,
            scheme,
            vec![root.join("app").into_os_string()],
        );
        for _ in 0..50 {
            let _ = std::fs::remove_file(&log);
            let _ = crate::sandbox::gc::force_remove_dir_all(&dir);
            let _ = crate::sandbox::gc::force_remove_dir_all(&home);
            std::fs::create_dir_all(&home).unwrap();
            let ran = crate::testutil::run_within(
                std::process::Command::new(&argv[0])
                    .args(&argv[1..])
                    .env_clear()
                    .env("PATH", "/usr/bin:/bin")
                    .env("HOME", &home)
                    .env("SBX_TEST_LOG", &log)
                    .current_dir(root)
                    .stdin(std::process::Stdio::null()),
                "the portal preamble",
            );
            if ran.stderr.contains("Text file busy") {
                std::thread::sleep(std::time::Duration::from_millis(20));
                continue;
            }
            // The indexer runs three times in the background, after `exec "$@"` has ended the
            // script; its last run is the last line any stand-in writes.
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
            let read = || std::fs::read_to_string(&log).unwrap_or_default();
            while read().matches("update-desktop-database ").count() < 3
                && std::time::Instant::now() < deadline
            {
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
            return Preamble { ran, log: read() };
        }
        panic!("a stand-in stayed held open for writing by another test's fork");
    }

    /// Every path the preamble names reaches the shell as one word, whatever it holds: a space, a
    /// quote of either kind, a command substitution. A path the shell split, ended early or ran a
    /// command from would leave the portal unstarted, or run something the path only names.
    #[test]
    fn every_path_the_preamble_names_reaches_the_shell_as_itself() {
        for shape in [" ", "'", "\"", "$(touch pwned)", "`touch pwned`"] {
            let tmp = crate::testutil::TmpDir::new();
            let root = tmp.path().join(format!("x{shape}y"));
            std::fs::create_dir(&root).unwrap();
            let Preamble { ran, log } = run_preamble(&root, Some("prefer-dark"), &[]);
            let (env_bin, provision) = stand_in_provision(&root);
            let dir = root.join("run");
            let expected = [
                format!(
                    "{} -p {}",
                    env_bin.with_file_name("mkdir").display(),
                    dir.join("xdg-desktop-portal").display()
                ),
                format!(
                    "{} --config-file={} --fork",
                    provision.dbus_daemon.display(),
                    dir.join("session.conf").display()
                ),
                format!(
                    "{} --unlock --components=secrets --daemonize",
                    provision.keyring_daemon.display()
                ),
                format!(
                    "{} --session --print-reply",
                    provision.dbus_daemon.with_file_name("dbus-send").display()
                ),
                format!(
                    "{} {}",
                    provision.update_desktop_db.display(),
                    root.join("home/.local/share/applications").display()
                ),
                format!("{} 1", env_bin.with_file_name("sleep").display()),
                root.join("app").display().to_string(),
            ];
            for line in &expected {
                assert!(
                    log.lines().any(|l| l.starts_with(line.as_str())),
                    "{shape:?}: no run of `{line}`:\n{log}\n{}",
                    ran.stderr
                );
            }
            assert!(
                std::fs::read_to_string(dir.join("session.conf"))
                    .is_ok_and(|c| c.contains("<busconfig>")),
                "{shape:?}: the bus configuration is not where the daemon is told to read it:\n{}",
                ran.stderr
            );
            assert!(
                std::fs::read_to_string(root.join("home").join(KEYFILE_REL))
                    .is_ok_and(|k| k.contains("color-scheme='prefer-dark'")),
                "{shape:?}: the theme is not seeded:\n{}",
                ran.stderr
            );
            assert!(
                !root.join("pwned").exists() && !tmp.path().join("pwned").exists(),
                "{shape:?}: a path ran a command"
            );
        }
    }

    #[test]
    fn wrap_command_without_a_theme_writes_no_keyfile() {
        let argv = wrap_command(
            Path::new("/bin/bash"),
            Path::new("/nix/store/hash-coreutils/bin/env"),
            &demo_provision(),
            None,
            vec![OsString::from("x")],
        );
        let script = argv[2].to_string_lossy();
        assert!(!script.contains("color-scheme"));
        assert!(!script.contains("gtk-theme"));
        assert!(!script.contains("keyfile"));
    }

    /// A color scheme is one of three names, and only those are seeded. Anything else would be
    /// written into the keyfile between quotes and into a heredoc the preamble runs, where a quote
    /// adds a GSettings key and a line holding the heredoc's delimiter ends it early, running what
    /// follows as shell.
    #[test]
    fn a_color_scheme_outside_the_three_names_seeds_nothing() {
        for scheme in [
            "prefer-dark'\ngtk-theme='Evil",
            "prefer-dark\nSBXPORTALKF\necho escaped",
            "",
        ] {
            let argv = wrap_command(
                Path::new("/bin/bash"),
                Path::new("/nix/store/hash-coreutils/bin/env"),
                &demo_provision(),
                Some(scheme),
                vec![OsString::from("x")],
            );
            let script = argv[2].to_string_lossy();
            assert!(
                !script.contains("SBXPORTALKF"),
                "{scheme:?} is seeded: {script}"
            );
        }
    }

    #[test]
    fn keyfile_body_pairs_the_color_scheme_with_a_named_gtk_theme() {
        // prefer-dark selects the standalone dark theme for the file dialog...
        let dark = keyfile_body("prefer-dark").expect("a scheme name");
        assert!(dark.contains("color-scheme='prefer-dark'"));
        assert!(dark.contains("gtk-theme='Adwaita-dark'"));
        // ...while every non-dark scheme opens light Adwaita (prefer-light and the no-preference
        // default alike), never the nonexistent dark variant.
        for scheme in ["prefer-light", "default"] {
            let body = keyfile_body(scheme).expect("a scheme name");
            assert!(body.contains(&format!("color-scheme='{scheme}'")));
            assert!(body.contains("gtk-theme='Adwaita'"));
            assert!(!body.contains("Adwaita-dark"));
        }
        // ...and a value outside the three names has no body at all.
        assert_eq!(keyfile_body("prefer-dark'\ngtk-theme='Evil"), None);
    }

    #[test]
    fn host_dir_is_per_launch_and_the_socket_sits_under_it() {
        let layout = Layout::under(Path::new("/data"));
        let dir = host_dir(&layout);
        // under <data>/portal, named by the pid alone, which `sbx gc` reads
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

    /// A second launch of this process is refused the portal directory while the first holds it,
    /// rather than emptying the first's bus socket from under it, and admitted once the first has
    /// ended. The name is the pid alone, which `sbx gc` reads.
    #[test]
    fn a_second_launch_of_the_process_is_refused_the_portal_directory_while_the_first_holds_it() {
        let tmp = crate::testutil::TmpDir::new();
        let layout = Layout::under(tmp.path());
        let first = HostDir::create(&layout).expect("create host dir");
        std::fs::write(first.socket(), b"").unwrap();

        let e = HostDir::create(&layout)
            .err()
            .expect("a second launch is refused");
        assert_eq!(e.kind(), io::ErrorKind::AlreadyExists, "{e}");
        assert!(
            first.socket().exists(),
            "the first launch's socket is left alone"
        );
        drop(first);
        let second = HostDir::create(&layout).expect("admitted once the first has ended");
        drop(second);
    }

    /// A portal directory already at the launch's name is a dead predecessor's, whose cage could
    /// widen its mode and leave a read-only directory with an entry in it, which a plain
    /// `remove_dir_all` cannot empty. The launch still gets it back empty and `0700`, rather than
    /// reusing it as found with the socket it will hold readable to others.
    #[test]
    fn a_portal_directory_a_dead_cage_left_is_made_again_empty_and_private() {
        use std::os::unix::fs::PermissionsExt as _;
        let tmp = crate::testutil::TmpDir::new();
        let layout = Layout::under(tmp.path());
        let stale = host_dir(&layout);
        let locked = stale.join("xdg-desktop-portal");
        std::fs::create_dir_all(&locked).unwrap();
        std::fs::write(locked.join("portals.conf"), b"").unwrap();
        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o555)).unwrap();
        std::fs::set_permissions(&stale, std::fs::Permissions::from_mode(0o755)).unwrap();

        let made = HostDir::create(&layout);
        // Widened again whatever happened, so the fixture can be removed after a red run.
        let _ = std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o700));
        let hd = made.expect("create host dir");
        let mode = std::fs::metadata(hd.dir()).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o700, "the directory is owner-only again");
        assert_eq!(
            std::fs::read_dir(hd.dir()).unwrap().count(),
            0,
            "nothing the dead cage left is still there"
        );
    }

    /// The directory the per-launch ones sit in is owner-only too, including one found looser.
    #[test]
    fn the_portal_parent_is_owner_only_even_when_found_looser() {
        use std::os::unix::fs::PermissionsExt as _;
        let tmp = crate::testutil::TmpDir::new();
        let layout = Layout::under(tmp.path());
        let parent = layout.data_dir().join("portal");
        std::fs::create_dir(&parent).unwrap();
        std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o755)).unwrap();

        let _hd = HostDir::create(&layout).expect("create host dir");
        let mode = std::fs::metadata(&parent).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o700);
    }

    /// The cage can make a read-only directory with an entry inside the one bound to it, and the
    /// end of the launch still removes the whole directory.
    #[test]
    fn a_portal_directory_the_cage_made_read_only_inside_is_removed_at_the_end() {
        use std::os::unix::fs::PermissionsExt as _;
        let tmp = crate::testutil::TmpDir::new();
        let layout = Layout::under(tmp.path());
        let hd = HostDir::create(&layout).expect("create host dir");
        let path = hd.dir().to_path_buf();
        let locked = path.join("xdg-desktop-portal");
        std::fs::create_dir(&locked).unwrap();
        std::fs::write(locked.join("portals.conf"), b"").unwrap();
        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o555)).unwrap();

        drop(hd);
        let left = path.exists();
        // Widened again whatever happened, so the fixture can be removed after a red run.
        let _ = std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o700));
        assert!(!left, "the launch's portal directory outlives it");
    }
}
