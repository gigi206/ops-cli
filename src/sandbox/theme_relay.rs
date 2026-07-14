//! The in-cage live-theme relay (`dbus = "incage"`).
//!
//! The in-cage portal ([`super::portal`]) seeds the host light/dark theme into the cage **once** at
//! launch (so the app opens in the right scheme), but does not follow a host theme switch made
//! afterwards. This relay closes that gap. It runs **host-side** (ops's own trusted infrastructure,
//! like the notifications relay and the egress proxy), connects to the real host session bus,
//! subscribes to the desktop portal's `org.freedesktop.portal.Settings.SettingChanged` signal for
//! the `org.freedesktop.appearance` `color-scheme` key (the same signal the filtered host bus
//! `dbus = true` forwards), and on each change **rewrites the in-cage GSettings keyfile** through the
//! home bind. The in-cage keyfile backend watches that file, so `xdg-desktop-portal-gtk` re-emits its
//! own `SettingChanged` on the private bus and the Chromium/Electron app follows the new scheme live.
//!
//! It adds no capability: the value written is only a light/dark preference, into the app's own
//! isolated home; the relay reads one host setting and touches no other bus service. Best-effort
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
trait HostSettings {
    #[zbus(signal)]
    fn setting_changed(
        &self,
        namespace: String,
        key: String,
        value: zbus::zvariant::OwnedValue,
    ) -> zbus::Result<()>;
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
            .name("ops-theme-relay".to_string())
            .spawn(move || {
                if let Err(e) = async_io::block_on(run(keyfile, rx)) {
                    // A connection error is almost always the session ending (the host bus went away)
                    // — a benign teardown race, not worth alarming the user. Only a genuinely
                    // unexpected failure warns.
                    let msg = e.to_string();
                    if !msg.contains("Connection refused") && !msg.contains("Broken pipe") {
                        diag::warn(&format!(
                            "`dbus = \"incage\"`: the live-theme relay stopped ({e}) — the app keeps \
                             its at-launch theme"
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
                Some(sig) => if let Ok(args) = sig.args() {
                    if args.namespace == "org.freedesktop.appearance" && args.key == "color-scheme" {
                        if let Some(n) = extract_u32(&args.value) {
                            write_keyfile(&keyfile, super::portal::color_scheme_name(n));
                        }
                    }
                },
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
    let tmp = keyfile.with_extension("ops-tmp");
    if std::fs::write(&tmp, super::portal::keyfile_body(scheme)).is_ok() {
        let _ = std::fs::rename(&tmp, keyfile);
    } else {
        let _ = std::fs::remove_file(&tmp);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
        assert!(!keyfile.with_extension("ops-tmp").exists());
    }
}
