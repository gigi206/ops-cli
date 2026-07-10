//! The filtered D-Bus session-bus hole (`dbus = true`).
//!
//! A hermetic cage carries no D-Bus session bus, so a graphical app cannot follow the host's
//! light/dark theme (the desktop `appearance` portal), raise desktop notifications, or reach any
//! other bus service. Exposing the *raw* session bus would be unsafe — it carries the login keyring
//! (`org.freedesktop.secrets`, i.e. every saved password) and every desktop portal (file chooser,
//! screenshot, screencast). When `dbus = true` a trusted config opens a **filtered** view of the
//! session bus through `xdg-dbus-proxy` (the mechanism Flatpak uses): a default-deny proxy that
//! forwards ONLY a small curated allowlist —
//!
//! - `org.freedesktop.portal.Desktop`, scoped **by method** to the `Settings` interface
//!   (`Read`/`ReadAll` plus the `SettingChanged` broadcast) — so the app can read and live-follow the
//!   `appearance` color-scheme (light/dark) — plus the standard read-only `Properties.Get`/`GetAll`
//!   a portal client (Chromium/Electron) probes to read an interface's `version` before using it. The
//!   file chooser, screenshot, and screencast interfaces of the same service stay refused — the file
//!   chooser in particular because its host-rendered dialog is a full host-privileged file manager
//!   (browse/create/delete anywhere), which the caged app must not be able to summon (a GUI app that
//!   needs a folder renders its picker inside the cage, under `dbus = false`, seeing only the cage FS);
//! - `org.freedesktop.Notifications`, so the app can raise desktop notifications.
//!
//! Everything else — the keyring/secrets service, every other portal, and every other client on the
//! bus — is refused (an unlisted name is not even visible to the cage).
//!
//! The filter is only a boundary under an **isolated** network namespace. The launch wires this
//! proxy only when the cage's netns is empty (every posture but `network = "shared"`); under a
//! shared netns the host session bus is reachable directly (abstract-namespace sockets are
//! netns-scoped), so the filter would be bypassable and is not wired (see `dbus_filter_enforceable`
//! in the launch path).
//!
//! The proxy runs host-side (like the egress proxy, it is trusted ops infrastructure) inside its own
//! minimal bubblewrap cage: a store-provisioned binary resolves its interpreter through ops's `/nix`,
//! so the cage binds ops's shared store read-only at `/nix`, the host session-bus socket read-only,
//! and a writable output directory where the proxy creates the filtered socket. That filtered socket
//! — and only it — is then bound into the agent's cage, with `DBUS_SESSION_BUS_ADDRESS` pointed at
//! it. The proxy's own netns is empty: D-Bus is a Unix socket, so it needs no network.

use super::binds::ExtraBind;
use super::spec::{Mount, NetPolicy, SandboxSpec};
use crate::store::{self, Layout};
use std::ffi::OsString;
use std::io;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

/// The `xdg-dbus-proxy` package: `(nixpkgs attribute, the binary its output must carry, gcroot
/// name)`. Shares the revision-keyed `gui` gcroot directory with the fonts and certutil (all are
/// GUI-hole provisions on the same channel), so `ops gc` keeps or drops it with them.
const XDG_DBUS_PROXY: (&str, &str, &str) =
    ("xdg-dbus-proxy", "bin/xdg-dbus-proxy", "xdg-dbus-proxy");

/// Where the filtered session-bus socket appears inside the agent's cage. Under `/run/ops-dbus`
/// (ops's own directory, not `$XDG_RUNTIME_DIR`, which holds the pulse/gpg/ssh sockets), so the
/// cage cannot rewrite it and a client reaches the bus only through the filter.
pub(crate) const CAGE_BUS: &str = "/run/ops-dbus/bus";

/// How long to wait for the proxy to create its socket before giving up (best-effort: on timeout
/// the launch runs without a bus rather than failing). The proxy binds in well under this.
const READY_TIMEOUT: Duration = Duration::from_secs(5);

/// What a `dbus = true` launch injects into the agent's cage: the bind of the filtered socket and
/// the environment pointing a D-Bus client at it.
pub(crate) struct Wiring {
    pub(crate) binds: Vec<ExtraBind>,
    pub(crate) env: Vec<(String, String)>,
}

/// A running filtered-bus proxy: the `xdg-dbus-proxy` child (under its own bubblewrap) and the
/// host socket it created. Dropping it kills the child — `--die-with-parent` already ties the proxy
/// to ops, this makes a clean supervised exit tear it down promptly — and unlinks the socket.
pub(crate) struct DbusProxy {
    child: Child,
    socket: PathBuf,
}

impl Drop for DbusProxy {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_file(&self.socket);
    }
}

/// Provision `xdg-dbus-proxy` into ops's store against the pinned `nixpkgs`, returning the logical
/// path of its binary (a `/nix/store/...` path, run under a cage that binds ops's store at `/nix`).
/// The gcroot is shared with the other GUI-hole provisions (`gcroots/gui/<rev>/`), keyed by
/// revision — like the fonts and certutil.
pub(crate) fn provision(nix: &Path, layout: &Layout, nixpkgs: &str) -> io::Result<PathBuf> {
    let (attr, marker, name) = XDG_DBUS_PROXY;
    let root_dir = layout
        .data_dir()
        .join("gcroots")
        .join("gui")
        .join(store::revision_of(nixpkgs));
    let root = store::provision(nix, layout, &root_dir.join(name), nixpkgs, attr, marker)?;
    Ok(root.join(marker))
}

/// Stand up the filtered bus proxy: resolve the host session bus, spawn `xdg-dbus-proxy` under a
/// minimal host-side cage with the curated filter, wait for its socket, and return the agent-cage
/// wiring plus a guard owning the child and the socket. Fails (so the caller can warn and run
/// without a bus) when no session bus is found, the cage cannot be built, the proxy cannot spawn, or
/// it does not create its socket in time.
pub(crate) fn start(
    layout: &Layout,
    proxy_bin: &Path,
    bwrap: &Path,
) -> io::Result<(DbusProxy, Wiring)> {
    use std::fs::DirBuilder;
    use std::os::unix::fs::DirBuilderExt;

    let bus = host_bus_path().ok_or_else(|| {
        io::Error::other(
            "no D-Bus session bus found ($DBUS_SESSION_BUS_ADDRESS is unset or not a unix path, \
             and $XDG_RUNTIME_DIR/bus is absent)",
        )
    })?;
    if !bus.exists() {
        return Err(io::Error::other(format!(
            "the D-Bus session bus socket {} does not exist",
            bus.display()
        )));
    }

    let dir = layout.data_dir().join("dbus");
    DirBuilder::new().recursive(true).mode(0o700).create(&dir)?;
    // Per-launch name (the pid keeps concurrent launches from colliding); clear a stale predecessor.
    let host_sock = dir.join(format!("proxy-{}.sock", std::process::id()));
    let _ = std::fs::remove_file(&host_sock);

    let spec = proxy_spec(layout, proxy_bin, &bus, &host_sock, &dir)?;
    let mut child = Command::new(bwrap)
        .args(super::argv::to_argv(&spec))
        // The proxy reads no input and its diagnostics are not wanted on the terminal; the socket
        // wait below is how a failure surfaces.
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| io::Error::other(format!("could not start the dbus proxy: {e}")))?;

    if !wait_for_socket(&host_sock, READY_TIMEOUT) {
        let _ = child.kill();
        let _ = child.wait();
        let _ = std::fs::remove_file(&host_sock);
        return Err(io::Error::other(
            "the dbus proxy did not create its socket in time",
        ));
    }
    // The socket exists — but the proxy could have created it and then died (a bad upstream connect,
    // a filter it rejected). An already-exited child means the socket is dead, so fail closed rather
    // than wire a bus that refuses every connection.
    if matches!(child.try_wait(), Ok(Some(_))) {
        let _ = std::fs::remove_file(&host_sock);
        return Err(io::Error::other(
            "the dbus proxy exited immediately after creating its socket",
        ));
    }

    let binds = vec![ExtraBind {
        // Writable so a `connect()` is never refused on a permission subtlety; the cage can talk
        // to the filtered bus (that is the point) but cannot unlink a bind-mount target.
        src: host_sock.clone(),
        dest: PathBuf::from(CAGE_BUS),
        writable: true,
    }];
    let env = vec![(
        "DBUS_SESSION_BUS_ADDRESS".to_string(),
        format!("unix:path={CAGE_BUS}"),
    )];
    Ok((
        DbusProxy {
            child,
            socket: host_sock,
        },
        Wiring { binds, env },
    ))
}

/// Build the minimal host-side cage for the proxy: ops's store at `/nix` (its interpreter and
/// closure), the host bus socket read-only, the output directory writable (so the created socket is
/// a real host file), and the structural pseudo-filesystems. Isolated netns — D-Bus is Unix-socket
/// only. Pure over its inputs, so the bind/command shape is unit-tested without launching bubblewrap.
fn proxy_spec(
    layout: &Layout,
    proxy_bin: &Path,
    bus: &Path,
    host_sock: &Path,
    dir: &Path,
) -> io::Result<SandboxSpec> {
    let mounts = vec![
        // ops's shared store, where the proxy binary and its closure live.
        Mount::RoBind {
            src: layout.store_dir().join("nix"),
            dest: PathBuf::from("/nix"),
        },
        // The host session bus, at its real path so the address the proxy connects to resolves.
        Mount::RoBind {
            src: bus.to_path_buf(),
            dest: bus.to_path_buf(),
        },
        // The output directory, writable and at its real path, so the socket the proxy creates
        // under it is the same host file the agent cage binds. Nothing else in it is exposed.
        Mount::Bind {
            src: dir.to_path_buf(),
            dest: dir.to_path_buf(),
        },
        Mount::Proc {
            dest: PathBuf::from("/proc"),
        },
        Mount::Dev {
            dest: PathBuf::from("/dev"),
        },
        Mount::Tmpfs {
            dest: PathBuf::from("/tmp"),
        },
    ];

    let mut cmd: Vec<OsString> = vec![
        proxy_bin.as_os_str().to_os_string(),
        // The bus to proxy, and the filtered socket to create.
        OsString::from(format!("unix:path={}", bus.display())),
        host_sock.as_os_str().to_os_string(),
    ];
    cmd.extend(filter_args().into_iter().map(OsString::from));

    SandboxSpec::new(
        PathBuf::from("/tmp"),
        mounts,
        Vec::new(),
        NetPolicy::Isolated,
        cmd,
    )
    .map_err(|e| io::Error::other(format!("cannot build the dbus proxy cage: {e:?}")))
}

/// The curated `xdg-dbus-proxy` filter: default-deny (`--filter`), then the exact allowlist. The
/// portal is scoped **by method** to the `Settings` interface (theme read + the live-change
/// broadcast) — so the file-chooser/screenshot/screencast interfaces of the same service stay
/// refused — plus whole-name talk to the benign notifications service. Every string is a fixed
/// literal (no interpolation), so nothing a config controls reaches these arguments. Pure.
fn filter_args() -> Vec<String> {
    const PORTAL: &str = "org.freedesktop.portal.Desktop";
    const PATH: &str = "@/org/freedesktop/portal/desktop";
    vec![
        "--filter".to_string(),
        // The appearance/theme portal: the Settings interface (read the color-scheme + follow its
        // live change).
        format!("--call={PORTAL}=org.freedesktop.portal.Settings.Read{PATH}"),
        format!("--call={PORTAL}=org.freedesktop.portal.Settings.ReadAll{PATH}"),
        format!("--broadcast={PORTAL}=org.freedesktop.portal.Settings.SettingChanged{PATH}"),
        // The standard D-Bus Properties reads, scoped to the portal object: a portal client
        // (Chromium/Electron) reads an interface's `version` property before using it. These are
        // read-only interface metadata (a uint version), not a setting value or a capability — the
        // object-path scope keeps them to the portal, and no property on it is sensitive.
        format!("--call={PORTAL}=org.freedesktop.DBus.Properties.Get{PATH}"),
        format!("--call={PORTAL}=org.freedesktop.DBus.Properties.GetAll{PATH}"),
        // The file-chooser interface is deliberately NOT allowed. Its dialog is rendered host-side by
        // the portal backend with the user's full privileges — a complete host file manager that can
        // browse, create, rename and delete anywhere on the host FS. Even though the caged app gains
        // no *direct* file access from it (the returned path is only reachable if it is a `binds`
        // mount — the cage has no document-portal fuse), letting the caged app *summon* a
        // host-privileged file manager is a real reduction of isolation (host-FS visibility + user-
        // driven host-FS writes), so it stays refused. A GUI app that needs a folder should render
        // its picker INSIDE the cage (a GTK dialog under `dbus = false`), which sees only the cage's
        // own filesystem (its home + `[binds]` mounts).
        // Desktop notifications.
        "--talk=org.freedesktop.Notifications".to_string(),
    ]
}

/// The filesystem path of the host D-Bus session bus socket: the `unix:path=` of
/// `$DBUS_SESSION_BUS_ADDRESS` when set, else the well-known `$XDG_RUNTIME_DIR/bus`. `None` when
/// neither yields a path (e.g. an `abstract`-only address with no runtime dir), so the caller can
/// warn and run without a bus.
fn host_bus_path() -> Option<PathBuf> {
    if let Ok(addr) = std::env::var("DBUS_SESSION_BUS_ADDRESS") {
        if let Some(path) = parse_unix_path(&addr) {
            return Some(path);
        }
    }
    std::env::var("XDG_RUNTIME_DIR")
        .ok()
        .map(|xdg| PathBuf::from(xdg).join("bus"))
}

/// Extract the `path=` value of the first `unix:` address in a D-Bus address string. Addresses are
/// `;`-separated; within one, `key=value` pairs are `,`-separated (so a `unix:path=/run/…,guid=…`
/// address yields the path, ignoring the guid). An `abstract=`-only address (no filesystem path to
/// bind) or a non-unix transport yields `None`. Pure.
fn parse_unix_path(addr: &str) -> Option<PathBuf> {
    for one in addr.split(';') {
        if let Some(rest) = one.strip_prefix("unix:") {
            for kv in rest.split(',') {
                if let Some(path) = kv.strip_prefix("path=") {
                    if !path.is_empty() {
                        return Some(PathBuf::from(path));
                    }
                }
            }
        }
    }
    None
}

/// Poll for the proxy's socket to appear, up to `timeout`. Returns whether it did. The proxy binds
/// in a few milliseconds; a short poll avoids threading a readiness fd through bubblewrap.
fn wait_for_socket(path: &Path, timeout: Duration) -> bool {
    let start = Instant::now();
    while start.elapsed() < timeout {
        if path.exists() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    path.exists()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filter_args_allow_only_theme_and_notifications() {
        let args = filter_args();
        // default-deny
        assert!(args.iter().any(|a| a == "--filter"));
        // theme: the Settings interface (read + live change), scoped to the portal object path
        assert!(args.iter().any(|a| a
            == "--call=org.freedesktop.portal.Desktop=org.freedesktop.portal.Settings.Read@/org/freedesktop/portal/desktop"));
        assert!(args
            .iter()
            .any(|a| a.contains("Settings.ReadAll@/org/freedesktop/portal/desktop")));
        assert!(args
            .iter()
            .any(|a| a.contains("Settings.SettingChanged@/org/freedesktop/portal/desktop")));
        // the standard Properties reads a portal client probes with, scoped to the portal object
        assert!(args.iter().any(|a| a
            == "--call=org.freedesktop.portal.Desktop=org.freedesktop.DBus.Properties.Get@/org/freedesktop/portal/desktop"));
        assert!(args
            .iter()
            .any(|a| a.contains("DBus.Properties.GetAll@/org/freedesktop/portal/desktop")));
        // notifications
        assert!(args
            .iter()
            .any(|a| a == "--talk=org.freedesktop.Notifications"));
        // NOT the keyring, and NOT the other (dangerous) portal interfaces — the file chooser in
        // particular, whose host-rendered dialog is a full host-privileged file manager.
        let joined = args.join(" ");
        assert!(
            !joined.contains("secrets"),
            "the keyring must never be allowed"
        );
        assert!(
            !joined.contains("FileChooser"),
            "the file chooser must stay refused (a host-privileged file manager)"
        );
        assert!(
            !joined.contains("Screenshot"),
            "screenshot must stay refused"
        );
        assert!(
            !joined.contains("ScreenCast"),
            "screencast must stay refused"
        );
        // the portal is scoped by --call (per method), never a whole-name --talk that would open
        // every interface (including the file chooser/screenshot) of the portal service.
        assert!(
            !joined.contains("--talk=org.freedesktop.portal.Desktop"),
            "the portal must be method-scoped, not whole-name talk"
        );
    }

    #[test]
    fn parse_unix_path_extracts_the_path_ignoring_guid_and_transport() {
        assert_eq!(
            parse_unix_path("unix:path=/run/user/1000/bus"),
            Some(PathBuf::from("/run/user/1000/bus"))
        );
        // a guid pair after the path is ignored
        assert_eq!(
            parse_unix_path("unix:path=/run/user/1000/bus,guid=abc123"),
            Some(PathBuf::from("/run/user/1000/bus"))
        );
        // several addresses: the first unix:path wins
        assert_eq!(
            parse_unix_path("unix:abstract=/tmp/dbus-xyz;unix:path=/run/user/1000/bus"),
            Some(PathBuf::from("/run/user/1000/bus"))
        );
        // an abstract-only address has no filesystem path to bind
        assert_eq!(parse_unix_path("unix:abstract=/tmp/dbus-xyz"), None);
        // a non-unix transport
        assert_eq!(parse_unix_path("tcp:host=localhost,port=1234"), None);
        // an empty path is not a path
        assert_eq!(parse_unix_path("unix:path="), None);
    }

    #[test]
    fn proxy_spec_binds_the_store_bus_and_output_and_runs_the_filtered_proxy() {
        let layout = Layout::under(Path::new("/data"));
        let bus = PathBuf::from("/run/user/1000/bus");
        let sock = PathBuf::from("/data/ops/dbus/proxy-42.sock");
        let dir = PathBuf::from("/data/ops/dbus");
        let spec = proxy_spec(
            &layout,
            Path::new("/nix/store/abc-xdg-dbus-proxy/bin/xdg-dbus-proxy"),
            &bus,
            &sock,
            &dir,
        )
        .expect("build the proxy spec");

        // ops's store is bound read-only at /nix (the proxy's interpreter + closure)
        assert!(spec.mounts.iter().any(|m| matches!(m,
            Mount::RoBind { src, dest } if dest == Path::new("/nix") && src == &layout.store_dir().join("nix"))));
        // the host bus is bound read-only at its real path
        assert!(spec.mounts.iter().any(|m| matches!(m,
            Mount::RoBind { src, dest } if src == &bus && dest == &bus)));
        // the output dir is bound WRITABLE (so the created socket is a host file)
        assert!(spec.mounts.iter().any(|m| matches!(m,
            Mount::Bind { src, dest } if src == &dir && dest == &dir)));
        // no network — D-Bus is a Unix socket
        assert!(matches!(spec.net, NetPolicy::Isolated));
        // the command is the proxy, the bus address, the socket, then the filter
        assert_eq!(
            spec.cmd[0],
            OsString::from("/nix/store/abc-xdg-dbus-proxy/bin/xdg-dbus-proxy")
        );
        assert_eq!(spec.cmd[1], OsString::from("unix:path=/run/user/1000/bus"));
        assert_eq!(spec.cmd[2], OsString::from("/data/ops/dbus/proxy-42.sock"));
        assert!(spec.cmd.iter().any(|a| a.as_os_str() == "--filter"));
    }
}
