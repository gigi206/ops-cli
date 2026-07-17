//! The in-cage desktop notifications relay (`dbus = true`).
//!
//! The in-cage portal ([`super::portal`]) gives a Chromium/Electron app its own private D-Bus bus so
//! its file chooser renders in-cage. That private bus carries the portal, but nothing serves
//! `org.freedesktop.Notifications` on it, so the app cannot raise a desktop notification. This relay
//! bridges the gap: it runs **host-side** (sbx's own trusted infrastructure, like the egress and
//! filtered-D-Bus proxies), connects both to the private bus (through the socket the portal exposes
//! on a host path) and to the real host session bus, **owns `org.freedesktop.Notifications` on the
//! private bus**, and forwards every call to the host daemon — re-emitting the host's `ActionInvoked`
//! and `NotificationClosed` signals back onto the private bus so click-to-focus and notification
//! actions work end to end. The notification id the host returns is passed through verbatim, so a
//! signal carrying that id routes back to the right notification with no remapping.
//!
//! It adds no capability beyond what the filtered host bus (`dbus = true`) already grants — that
//! posture likewise allows `org.freedesktop.Notifications` — so the accepted notification-spoofing
//! residual is the same, and no keyring/portal/other service is reachable through this relay (it
//! forwards only the notifications interface).
//!
//! Lifecycle: [`NotifyRelay::start`] spawns a dedicated thread that drives the async work with
//! `async_io::block_on` (the pure-Rust async-io backend — no tokio, and the runtime never leaves this
//! module). The thread waits for the in-cage `dbus-daemon` to create the private-bus socket (the
//! portal's command wrap starts it before the app runs), then attaches. The guard's `Drop` closes a
//! shutdown channel and joins the thread, so the relay is torn down before the portal's host
//! directory (and its socket) is removed. Everything is **best-effort**: no host bus, a socket that
//! never appears, or a failed connection warns and the app simply runs without notifications (the
//! picker and at-launch theme, served entirely in-cage, are unaffected).

use crate::diag;
use futures_util::{FutureExt, StreamExt};
use std::collections::HashMap;
use std::path::PathBuf;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};
use zbus::zvariant::OwnedValue;
use zbus::{connection, fdo, interface, proxy};

/// The notifications service name and object path (identical on the host and the private bus).
const IFACE: &str = "org.freedesktop.Notifications";
const OBJECT: &str = "/org/freedesktop/Notifications";
/// How long to wait for the in-cage `dbus-daemon` to create the private-bus socket before giving up
/// (best-effort: the portal's wrap starts the daemon before the app, so the socket appears within
/// milliseconds; this bound only guards against a portal that failed to come up).
const SOCKET_WAIT: Duration = Duration::from_secs(10);
const POLL_INTERVAL: Duration = Duration::from_millis(50);

/// Client proxy onto the **host** notifications daemon. Owned argument types (`Vec<String>`,
/// `HashMap<String, OwnedValue>`) so a forwarded call needs no lifetime juggling — the `a{sv}` hints
/// dictionary serialises identically whether its values are borrowed or owned.
#[proxy(
    interface = "org.freedesktop.Notifications",
    default_service = "org.freedesktop.Notifications",
    default_path = "/org/freedesktop/Notifications"
)]
trait HostNotifications {
    #[allow(clippy::too_many_arguments)]
    fn notify(
        &self,
        app_name: &str,
        replaces_id: u32,
        app_icon: &str,
        summary: &str,
        body: &str,
        actions: Vec<String>,
        hints: HashMap<String, OwnedValue>,
        expire_timeout: i32,
    ) -> zbus::Result<u32>;
    fn close_notification(&self, id: u32) -> zbus::Result<()>;
    fn get_capabilities(&self) -> zbus::Result<Vec<String>>;
    fn get_server_information(&self) -> zbus::Result<(String, String, String, String)>;

    #[zbus(signal)]
    fn action_invoked(&self, id: u32, action_key: String) -> zbus::Result<()>;
    #[zbus(signal)]
    fn notification_closed(&self, id: u32, reason: u32) -> zbus::Result<()>;
}

/// The interface served on the **private** bus: every method is forwarded to the host proxy. A
/// forwarding error becomes an `fdo` error reply so the caged app sees a clean failure rather than a
/// dropped call.
struct Served {
    host: HostNotificationsProxy<'static>,
}

#[interface(name = "org.freedesktop.Notifications")]
impl Served {
    #[allow(clippy::too_many_arguments)]
    async fn notify(
        &self,
        app_name: String,
        replaces_id: u32,
        app_icon: String,
        summary: String,
        body: String,
        actions: Vec<String>,
        hints: HashMap<String, OwnedValue>,
        expire_timeout: i32,
    ) -> fdo::Result<u32> {
        self.host
            .notify(
                &app_name,
                replaces_id,
                &app_icon,
                &summary,
                &body,
                actions,
                hints,
                expire_timeout,
            )
            .await
            .map_err(|e| fdo::Error::Failed(format!("forward Notify: {e}")))
    }

    async fn close_notification(&self, id: u32) -> fdo::Result<()> {
        self.host
            .close_notification(id)
            .await
            .map_err(|e| fdo::Error::Failed(format!("forward CloseNotification: {e}")))
    }

    async fn get_capabilities(&self) -> fdo::Result<Vec<String>> {
        self.host
            .get_capabilities()
            .await
            .map_err(|e| fdo::Error::Failed(format!("forward GetCapabilities: {e}")))
    }

    async fn get_server_information(&self) -> fdo::Result<(String, String, String, String)> {
        self.host
            .get_server_information()
            .await
            .map_err(|e| fdo::Error::Failed(format!("forward GetServerInformation: {e}")))
    }
}

/// A running notifications relay: the shutdown channel signalling its thread to stop, and the thread
/// handle. Dropping it closes the channel (breaking the relay's loop) and joins the thread, so the
/// relay disconnects before the portal's host directory is removed.
pub(crate) struct NotifyRelay {
    shutdown: async_channel::Sender<()>,
    handle: Option<JoinHandle<()>>,
}

impl NotifyRelay {
    /// Spawn the relay thread. `private_socket` is the host path of the private-bus socket the portal
    /// exposes (the in-cage `dbus-daemon` creates it there through the bind); the thread waits for it
    /// to appear, then attaches. Infallible — a failure inside the thread warns and leaves the app
    /// without notifications (best-effort), never blocking the launch.
    pub(crate) fn start(private_socket: PathBuf) -> NotifyRelay {
        let (shutdown, rx) = async_channel::bounded::<()>(1);
        let handle = std::thread::Builder::new()
            .name("sbx-notify-relay".to_string())
            .spawn(move || {
                if let Err(e) = async_io::block_on(run(private_socket, rx)) {
                    // A connection error to the private bus is almost always the cage tearing down
                    // (the in-cage dbus-daemon went away) — a benign teardown race on a short-lived
                    // launch, not worth alarming the user. Only a genuinely unexpected failure (e.g.
                    // no host session bus) warns.
                    let msg = e.to_string();
                    if !msg.contains("Connection refused")
                        && !msg.contains("Broken pipe")
                        && !msg.contains("reset by peer")
                    {
                        diag::warn(&format!(
                            "`dbus = true`: the notifications relay stopped ({e}) — the app \
                             runs without desktop notifications"
                        ));
                    }
                }
            })
            .ok();
        NotifyRelay { shutdown, handle }
    }
}

impl Drop for NotifyRelay {
    fn drop(&mut self) {
        // Closing the channel makes the relay's `shutdown.recv()` branch fire, breaking its loop so
        // `run` returns and the thread exits; then join it, so the relay has disconnected from the
        // private bus before the portal's host directory (holding the socket) is removed.
        self.shutdown.close();
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

/// The relay body: wait for the private-bus socket, connect both buses, own the notifications name on
/// the private bus, and pump the host's signals back onto it until shutdown.
async fn run(
    private_socket: PathBuf,
    shutdown: async_channel::Receiver<()>,
) -> Result<(), Box<dyn std::error::Error>> {
    // Wait for the in-cage dbus-daemon to create its socket (the portal wrap starts it before the
    // app). Give up quietly after the bound — a portal that never came up already warned elsewhere.
    let start = Instant::now();
    while !private_socket.exists() {
        if shutdown.is_closed() || start.elapsed() > SOCKET_WAIT {
            return Ok(());
        }
        async_io::Timer::after(POLL_INTERVAL).await;
    }

    // Host session bus (ambient $DBUS_SESSION_BUS_ADDRESS) and a proxy onto its notifications daemon.
    let host_conn = zbus::Connection::session().await?;
    let host = HostNotificationsProxy::new(&host_conn).await?;

    // Private bus: own the notifications name and serve the forwarding interface. zbus dispatches the
    // served interface's method calls on its own internal executor, so this future only pumps signals.
    let served = Served { host: host.clone() };
    let address = format!("unix:path={}", private_socket.display());
    let private_conn = connection::Builder::address(address.as_str())?
        .name(IFACE)?
        .serve_at(OBJECT, served)?
        .build()
        .await?;

    let mut actions = host.receive_action_invoked().await?;
    let mut closed = host.receive_notification_closed().await?;
    loop {
        futures_util::select! {
            _ = shutdown.recv().fuse() => break,
            sig = actions.next().fuse() => match sig {
                Some(sig) => if let Ok(a) = sig.args() {
                    // Verbatim id → the app matches the signal to its own notification.
                    let (id, key) = (a.id, a.action_key.to_string());
                    let _ = private_conn
                        .emit_signal(None::<&str>, OBJECT, IFACE, "ActionInvoked", &(id, key.as_str()))
                        .await;
                },
                None => break,
            },
            sig = closed.next().fuse() => match sig {
                Some(sig) => if let Ok(a) = sig.args() {
                    let (id, reason) = (a.id, a.reason);
                    let _ = private_conn
                        .emit_signal(None::<&str>, OBJECT, IFACE, "NotificationClosed", &(id, reason))
                        .await;
                },
                None => break,
            },
        }
    }
    Ok(())
}
