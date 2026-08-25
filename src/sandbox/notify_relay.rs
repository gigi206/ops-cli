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
//! What that forwarding costs is stated here rather than justified away. This section used to argue
//! that the relay adds no capability beyond what the filtered host bus already grants, but under
//! `dbus = true` the cage gets a private bus and no host bus at all, so the relay is its *only*
//! route to the host daemon and everything the relay forwards is capability it would otherwise not
//! have. What it forwards is the notifications interface alone (no keyring, no portal, no other host
//! service). The residual accepted is notification **spoofing**: the cage picks the app name, icon
//! and text of a toast the user reads as the desktop's. Notification **hijacking** is not accepted —
//! `Notify`'s `replaces_id` and `CloseNotification` are checked against the ids the host daemon
//! actually returned for this cage's own calls ([`OwnedIds`]), so the cage cannot overwrite or
//! dismiss a notification it never raised, sbx's own refusal toasts ([`super::notify_sink`])
//! included.
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
use crate::sandbox::locks::locked;
use futures_util::{FutureExt, StreamExt};
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
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
///
/// Shared with [`super::notify_sink`], which raises sbx's *own* refusal notifications on the host
/// bus. The two have nothing else in common — this relay exists only under a private in-cage bus,
/// the sink runs on any launch — so what is shared is the interface declaration alone, not a
/// lifecycle.
#[proxy(
    interface = "org.freedesktop.Notifications",
    default_service = "org.freedesktop.Notifications",
    default_path = "/org/freedesktop/Notifications"
)]
pub(crate) trait HostNotifications {
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

/// The notification ids the host daemon returned for *this* cage's `Notify` calls, minus those it
/// has since reported closed — the whole of what the relay knows about which notifications on the
/// host belong to the cage.
///
/// A notification id is a host-wide `u32` counter, so an id the cage guesses (or reads off a
/// forwarded `NotificationClosed`) names some other app's notification just as well as its own, and
/// `replaces_id` on a foreign id overwrites it in place. Every id the cage names is checked here
/// first.
///
/// Takes [`locked`] rather than `lock().unwrap()`: this guards a decision rather than a record, so
/// it owes that argument where it lives. Its mutations are a single `insert`/`remove` of a `u32`,
/// which an unwind cannot leave half-applied, and panicking instead would end the thread serving the
/// private bus — removing the check rather than tightening it. Poisoning cannot arise from this
/// module in any case: nothing that can panic runs while the guard is held.
#[derive(Default)]
struct OwnedIds(Mutex<HashSet<u32>>);

impl OwnedIds {
    /// Record an id the host daemon just returned for one of this cage's `Notify` calls.
    fn record(&self, id: u32) {
        locked(&self.0).insert(id);
    }

    /// Forget an id the host reported closed. Keeps the set to the cage's *live* notifications, so a
    /// long-running app does not accumulate ids for the whole launch.
    fn forget(&self, id: u32) {
        locked(&self.0).remove(&id);
    }

    /// Whether `id` is one of this cage's own live notifications. `0` is never owned — in the
    /// notifications spec it is the "not a replacement" sentinel, never a real id.
    fn owns(&self, id: u32) -> bool {
        id != 0 && locked(&self.0).contains(&id)
    }
}

/// The interface served on the **private** bus: every method is forwarded to the host proxy. A
/// forwarding error becomes an `fdo` error reply so the caged app sees a clean failure rather than a
/// dropped call.
struct Served {
    host: HostNotificationsProxy<'static>,
    /// Shared with the signal pump in [`run`], which forgets an id when the host reports it closed.
    ours: Arc<OwnedIds>,
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
        // An id the relay never handed out is not the cage's to overwrite, so it is downgraded to the
        // spec's "no replacement" sentinel rather than refused: the app still gets its notification,
        // it just gets a new one instead of taking over somebody else's.
        let replaces_id = if self.ours.owns(replaces_id) {
            replaces_id
        } else {
            0
        };
        let id = self
            .host
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
            .map_err(|e| fdo::Error::Failed(format!("forward Notify: {e}")))?;
        self.ours.record(id);
        Ok(id)
    }

    async fn close_notification(&self, id: u32) -> fdo::Result<()> {
        // Same rule as `replaces_id`: an id outside the set is either foreign — the cage must not
        // dismiss what it never raised — or one of the cage's own that the host has already closed
        // (`forget` dropped it then). Answered `Ok` rather than as an error because of the second
        // case: an app closing a notification that has just expired must not start seeing failures,
        // and closing an already-closed notification is a no-op on the host daemon too.
        if !self.ours.owns(id) {
            return Ok(());
        }
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
    let ours = Arc::new(OwnedIds::default());
    let served = Served {
        host: host.clone(),
        ours: Arc::clone(&ours),
    };
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
                    // Whoever raised it, this id now names nothing: drop it so the set stays the
                    // cage's live notifications, and an id the host later recycles for another app's
                    // notification is not still claimed as the cage's.
                    ours.forget(id);
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn owned_ids_admits_only_the_ids_the_relay_handed_out() {
        let ours = OwnedIds::default();
        ours.record(7);

        // What the guard must permit: the cage replacing and closing its own notification.
        assert!(ours.owns(7), "an id this relay returned is the cage's own");

        // What it must refuse: a host-wide id the cage never obtained from us — `replaces_id` on one
        // of these overwrites another app's notification in place, sbx's own refusal toasts included.
        assert!(
            !ours.owns(8),
            "an id the relay never returned is not the cage's"
        );
        assert!(
            !ours.owns(0),
            "0 is the no-replacement sentinel, never an id"
        );

        // Once the host reports it closed the id names nothing, and may be recycled for someone else.
        ours.forget(7);
        assert!(!ours.owns(7), "a closed id is no longer the cage's");
    }
}
