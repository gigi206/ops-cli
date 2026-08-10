//! The in-cage live-theme relay (`dbus = true`).
//!
//! The in-cage portal ([`super::portal`]) seeds the host light/dark theme into the cage **once** at
//! launch (so the app opens in the right scheme), but does not follow a host theme switch made
//! afterwards. This relay closes that gap. It runs **host-side** (sbx's own trusted infrastructure,
//! like the notifications relay and the egress proxy), connects to the real host session bus,
//! subscribes to the desktop portal's `org.freedesktop.portal.Settings.SettingChanged` signal for
//! the `org.freedesktop.appearance` `color-scheme` key, and on each change **rewrites the in-cage
//! GSettings keyfile** through the home bind. The keyfile carries both surface keys
//! ([`super::portal::keyfile_body`]):
//! `color-scheme`, which the in-cage portal re-emits so the Chromium/Electron **app** follows the new
//! scheme live; and `gtk-theme`, which GTK3 watches through the same keyfile backend so the **file
//! dialog** rendered by `xdg-desktop-portal-gtk` re-themes itself live.
//!
//! It adds no capability: the values written are only a light/dark preference and its matching GTK
//! theme name, into the app's own isolated home; the relay reads one host setting and touches no
//! other bus service. Best-effort
//! throughout — no host session bus, no host portal, or a home that cannot be written simply leaves
//! the app on its at-launch theme (the seed), never blocking the launch.
//!
//! Lifecycle mirrors [`super::notify_relay`]: [`ThemeRelay::start`] spawns a dedicated thread driving
//! the async work with `async_io::block_on` (no tokio); the guard's `Drop` closes a shutdown channel
//! and joins the thread.

use crate::diag;
use futures_util::{FutureExt, StreamExt};
use std::path::{Path, PathBuf};
use std::thread::JoinHandle;
use zbus::proxy;
use zbus::zvariant::Value;

/// Client proxy onto the **host** desktop portal's Settings interface, for the appearance
/// `color-scheme` `SettingChanged` signal.
#[proxy(
    interface = "org.freedesktop.portal.Settings",
    default_service = "org.freedesktop.portal.Desktop",
    default_path = "/org/freedesktop/portal/desktop"
)]
pub(crate) trait HostSettings {
    /// The current value of one setting. Used for the at-launch read; the signal below carries
    /// every later change.
    fn read(&self, namespace: &str, key: &str) -> zbus::Result<zbus::zvariant::OwnedValue>;

    #[zbus(signal)]
    fn setting_changed(
        &self,
        namespace: String,
        key: String,
        value: zbus::zvariant::OwnedValue,
    ) -> zbus::Result<()>;
}

/// How long the at-launch read waits on the host portal before giving up. It runs on the launch
/// path, so an unresponsive portal must cost a bounded pause and not the D-Bus default (tens of
/// seconds) — the price of giving up is the app opening in its default theme, not a failed launch.
const READ_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(2);

/// Read the host's current light/dark preference, for seeding the cage's theme at launch. Returns
/// the GSettings keyfile value (`prefer-dark`/`prefer-light`/`default`), or `None` when there is no
/// session bus, no desktop portal, or the reply carries no `uint32` — in which case the app opens
/// in its default theme.
///
/// Deliberately the same D-Bus client, proxy and value unwrapping the relay uses for the change
/// signal: the value read once at launch and the values mirrored afterwards must be the same
/// setting read the same way, or the app would open on one interpretation and switch to another.
pub(crate) fn read_host_color_scheme() -> Option<String> {
    async_io::block_on(async {
        futures_util::select! {
            scheme = current_color_scheme().fuse() => scheme,
            // `Timer` is both a `Future` and a `Stream`, so name the trait rather than let
            // `.fuse()` resolve to the stream one.
            _ = FutureExt::fuse(async_io::Timer::after(READ_TIMEOUT)) => None,
        }
    })
}

/// The read itself: connect to the host session bus, ask its portal for the appearance
/// `color-scheme`, and map the `uint32` to its keyfile value. Every failure is `None` (best-effort).
async fn current_color_scheme() -> Option<String> {
    let conn = zbus::Connection::session().await.ok()?;
    color_scheme_over(&conn).await
}

/// The same read over a connection the caller **already holds**, binding a proxy for the one read.
///
/// For the callers that ask once. A caller that asks repeatedly should bind with
/// [`bind_host_settings`] and keep the proxy: binding is not free next to the read it serves, so
/// re-binding per read is the one shape to avoid.
pub(crate) async fn color_scheme_over(conn: &zbus::Connection) -> Option<String> {
    color_scheme_of(&bind_host_settings(conn).await?).await
}

/// Bind the portal's Settings interface on an existing connection, to be held by a caller that
/// reads the preference more than once — the notification sink asks on every announcement, so that
/// it always signs itself in the theme the desktop is wearing *now* rather than the one it wore
/// when the launch started.
pub(crate) async fn bind_host_settings(
    conn: &zbus::Connection,
) -> Option<HostSettingsProxy<'static>> {
    HostSettingsProxy::new(conn).await.ok()
}

/// The read itself, over an already-bound proxy. Every failure is `None` (best-effort): no portal,
/// no such setting, or a reply carrying something other than the `uint32` the spec defines.
///
/// This is the single place the appearance setting is turned into a value, so the read at launch
/// and the reads during a session cannot end up interpreting it two different ways.
pub(crate) async fn color_scheme_of(settings: &HostSettingsProxy<'_>) -> Option<String> {
    let value = settings
        .read("org.freedesktop.appearance", "color-scheme")
        .await
        .ok()?;
    extract_u32(&value).map(|n| super::portal::color_scheme_name(n).to_string())
}

/// A running theme relay: the shutdown channel signalling its thread to stop, and the thread handle.
/// Dropping it closes the channel (breaking the relay's loop) and joins the thread.
pub(crate) struct ThemeRelay {
    shutdown: async_channel::Sender<()>,
    handle: Option<JoinHandle<()>>,
}

impl ThemeRelay {
    /// Spawn the relay thread. `keyfile` is the **host** path of the in-cage GSettings keyfile
    /// (`<home>/<KEYFILE_REL>`), which the cage reads through the home bind. Infallible — any failure
    /// inside the thread warns and leaves the app on its at-launch theme (best-effort).
    pub(crate) fn start(keyfile: PathBuf) -> ThemeRelay {
        let (shutdown, rx) = async_channel::bounded::<()>(1);
        let handle = std::thread::Builder::new()
            .name("sbx-theme-relay".to_string())
            .spawn(move || {
                if let Err(e) = async_io::block_on(run(keyfile, rx)) {
                    // A connection error is almost always the session ending (the host bus went away)
                    // — a benign teardown race, not worth alarming the user. Only a genuinely
                    // unexpected failure warns.
                    let msg = e.to_string();
                    if !msg.contains("Connection refused")
                        && !msg.contains("Broken pipe")
                        && !msg.contains("reset by peer")
                    {
                        diag::warn(&format!(
                            "`dbus = true`: the live-theme relay stopped ({e}) — the app keeps its \
                             at-launch theme"
                        ));
                    }
                }
            })
            .ok();
        ThemeRelay { shutdown, handle }
    }
}

impl Drop for ThemeRelay {
    fn drop(&mut self) {
        self.shutdown.close();
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

/// The relay body: connect to the host session bus, subscribe to the appearance color-scheme signal,
/// and mirror each change into the in-cage keyfile until shutdown.
async fn run(
    keyfile: PathBuf,
    shutdown: async_channel::Receiver<()>,
) -> Result<(), Box<dyn std::error::Error>> {
    // Host session bus (ambient $DBUS_SESSION_BUS_ADDRESS) and a proxy onto its desktop portal.
    let host_conn = zbus::Connection::session().await?;
    let settings = HostSettingsProxy::new(&host_conn).await?;
    let mut changes = settings.receive_setting_changed().await?;
    loop {
        futures_util::select! {
            _ = shutdown.recv().fuse() => break,
            sig = changes.next().fuse() => match sig {
                Some(sig) => {
                    if let Ok(args) = sig.args()
                        && args.namespace == "org.freedesktop.appearance"
                        && args.key == "color-scheme"
                        && let Some(n) = extract_u32(&args.value)
                    {
                        write_keyfile(&keyfile, super::portal::color_scheme_name(n));
                    }
                }
                None => break,
            },
        }
    }
    Ok(())
}

/// Unwrap the `color-scheme` value to its `uint32`, tolerating a nested variant (`v(v(u))`). Pure.
fn extract_u32(value: &Value) -> Option<u32> {
    match value {
        Value::U32(n) => Some(*n),
        Value::Value(inner) => extract_u32(inner),
        _ => None,
    }
}

/// Rewrite the in-cage keyfile atomically (temp + rename) with `scheme`'s GSettings body. Atomic so
/// the cage never reads a half-written file; the in-cage GSettings keyfile backend watches the parent
/// directory, so the rename fires its reload. Best-effort — any I/O error is swallowed, leaving the
/// previous theme in place.
fn write_keyfile(keyfile: &Path, scheme: &str) {
    if let Some(parent) = keyfile.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let tmp = keyfile.with_extension("sbx-tmp");
    if std::fs::write(&tmp, super::portal::keyfile_body(scheme)).is_ok() {
        let _ = std::fs::rename(&tmp, keyfile);
    } else {
        let _ = std::fs::remove_file(&tmp);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Whether this host runs a desktop portal, decided *without* the code under test: ask the bus
    /// daemon who owns the portal's name. So a host with no portal skips, while a host that has one
    /// must produce a scheme — the two cases cannot be confused, which is the whole point (a read
    /// that silently answers `None` everywhere would otherwise look like "no portal here").
    fn host_portal_present() -> bool {
        async_io::block_on(async {
            let Ok(conn) = zbus::Connection::session().await else {
                return false;
            };
            let Ok(dbus) = zbus::fdo::DBusProxy::new(&conn).await else {
                return false;
            };
            matches!(
                dbus.name_has_owner("org.freedesktop.portal.Desktop".try_into().unwrap())
                    .await,
                Ok(true)
            )
        })
    }

    #[test]
    fn the_at_launch_read_returns_the_hosts_scheme_when_a_portal_is_present() {
        // The value seeded into the cage at launch, so the app opens in the host's light/dark
        // scheme instead of its default. Reading it must not depend on executing anything from
        // sbx's store: those binaries name an interpreter under a `/nix` the host need not have, so
        // a read that shells out to one fails on an ordinary host and every launch silently loses
        // the theme.
        if !host_portal_present() {
            eprintln!("skipping host theme read: no desktop portal on the session bus");
            return;
        }
        let scheme = read_host_color_scheme();
        assert!(
            matches!(
                scheme.as_deref(),
                Some("prefer-dark" | "prefer-light" | "default")
            ),
            "a host with a desktop portal must yield a scheme, got {scheme:?}"
        );
    }

    #[test]
    fn extract_u32_reads_a_bare_or_nested_variant() {
        assert_eq!(extract_u32(&Value::U32(1)), Some(1));
        // The appearance value can arrive wrapped in an extra variant (`v(v(u))`).
        let nested = Value::Value(Box::new(Value::U32(2)));
        assert_eq!(extract_u32(&nested), Some(2));
        // A non-uint value yields nothing rather than a bogus scheme.
        assert_eq!(extract_u32(&Value::Bool(true)), None);
    }

    #[test]
    fn write_keyfile_writes_the_scheme_body_atomically_and_creates_the_dir() {
        let tmp = crate::testutil::TmpDir::new();
        let keyfile = tmp.path().join(super::super::portal::KEYFILE_REL);

        // First write creates the nested parent dirs and the file.
        write_keyfile(&keyfile, super::super::portal::color_scheme_name(1));
        assert_eq!(
            std::fs::read_to_string(&keyfile).unwrap(),
            super::super::portal::keyfile_body("prefer-dark")
        );

        // A second write replaces the content and leaves no temp file behind.
        write_keyfile(&keyfile, super::super::portal::color_scheme_name(2));
        assert_eq!(
            std::fs::read_to_string(&keyfile).unwrap(),
            super::super::portal::keyfile_body("prefer-light")
        );
        assert!(!keyfile.with_extension("sbx-tmp").exists());
    }
}
