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
//! service). The residual accepted is notification **spoofing**: the cage picks the *text* of a
//! toast the user reads as the desktop's. Three things are held back from it, because each of them
//! turns spoofing into something else:
//!
//! - **Identity.** The application name is written by the supervisor first and by the cage only
//!   after it ([`relayed_app_name`]). sbx raises its own refusal toasts on this same host daemon,
//!   under `sbx` or `sbx · <session>` ([`super::notify_sink`]), and those carry the copy-and-paste
//!   command that widens a launch's network policy — so a cage free to spell its own `app_name`
//!   could ask the user, in sbx's own voice, to open a hole for it.
//! - **Host files.** The icon a daemon renders is a path *the daemon* opens, host-side, in its own
//!   process. A relayed `app_icon` is therefore reduced to a bare theme name and the hints that name
//!   a file are dropped ([`relayed_app_icon`], [`HOST_PATH_HINTS`]); a caged app has no host path
//!   worth naming in any case, since everything it can see is inside the cage.
//! - **Other applications' notifications.** `Notify`'s `replaces_id` and `CloseNotification` are
//!   checked against the ids the host daemon actually returned for this cage's own calls
//!   ([`OwnedIds`]), so the cage can neither overwrite nor dismiss a notification it never raised,
//!   sbx's own refusal toasts included; and the host's `ActionInvoked`/`NotificationClosed` cross
//!   back onto the private bus only for those same ids, so the rest of the desktop's notification
//!   traffic is not a stream the cage can subscribe to.
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
use futures_util::future::BoxFuture;
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

/// One `Notify` as it leaves the relay — which is not one `Notify` as the cage made it. The fields
/// the guards in [`Served::notify`] settle (`replaces_id`, `app_name`, `app_icon` and the hints that
/// name a host file) already hold what will go on the host bus, not what the cage spelled.
struct NotifyCall {
    app_name: String,
    replaces_id: u32,
    app_icon: String,
    summary: String,
    body: String,
    actions: Vec<String>,
    hints: HashMap<String, OwnedValue>,
    expire_timeout: i32,
}

/// Where the relay forwards to: the host notifications daemon.
///
/// A trait for the reason [`super::notify_sink::Sink`] is one. What this module is worth is its
/// forwarding *decisions* — which `replaces_id` reaches the daemon, which `CloseNotification` is
/// dropped — and behind a bare proxy those would be reachable only from a live session bus, so they
/// would go untested on every machine that runs the suite. The one production implementation is
/// [`HostNotificationsProxy`]; the tests drive [`Served`]'s own methods, which is what the private
/// bus dispatches to, against a recording double.
///
/// Boxed futures rather than a trait `async fn`: an interface served on a connection needs futures
/// that are `Send`, which an `async fn` in a trait cannot promise for an arbitrary implementor.
trait HostBus: Send + Sync {
    /// Forward a `Notify`, answering with the id the host daemon assigned to it.
    fn notify(&self, call: NotifyCall) -> BoxFuture<'_, zbus::Result<u32>>;
    /// Forward a `CloseNotification` for an id the host daemon handed out.
    fn close_notification(&self, id: u32) -> BoxFuture<'_, zbus::Result<()>>;
    /// Forward a `GetCapabilities`.
    fn get_capabilities(&self) -> BoxFuture<'_, zbus::Result<Vec<String>>>;
    /// Forward a `GetServerInformation`.
    fn get_server_information(
        &self,
    ) -> BoxFuture<'_, zbus::Result<(String, String, String, String)>>;
}

impl HostBus for HostNotificationsProxy<'static> {
    fn notify(&self, call: NotifyCall) -> BoxFuture<'_, zbus::Result<u32>> {
        Box::pin(async move {
            HostNotificationsProxy::notify(
                self,
                &call.app_name,
                call.replaces_id,
                &call.app_icon,
                &call.summary,
                &call.body,
                call.actions,
                call.hints,
                call.expire_timeout,
            )
            .await
        })
    }

    fn close_notification(&self, id: u32) -> BoxFuture<'_, zbus::Result<()>> {
        Box::pin(HostNotificationsProxy::close_notification(self, id))
    }

    fn get_capabilities(&self) -> BoxFuture<'_, zbus::Result<Vec<String>>> {
        Box::pin(HostNotificationsProxy::get_capabilities(self))
    }

    fn get_server_information(
        &self,
    ) -> BoxFuture<'_, zbus::Result<(String, String, String, String)>> {
        Box::pin(HostNotificationsProxy::get_server_information(self))
    }
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

    /// Rule on a host `NotificationClosed` for `id`: whether it named one of this cage's own
    /// notifications — and therefore crosses back onto the private bus — while dropping the id from
    /// the live set either way. Keeps the set to the cage's *live* notifications, so a long-running
    /// app does not accumulate ids for the whole launch, and so an id the host later recycles for
    /// another application is not still claimed as the cage's.
    ///
    /// One method rather than a test and a `forget` spelled out at the call site, because the order
    /// is the whole of it: forgetting first answers `false` for the cage's own notification, and the
    /// app never learns its own toast was dismissed.
    fn closing(&self, id: u32) -> bool {
        id != 0 && locked(&self.0).remove(&id)
    }

    /// Whether `id` is one of this cage's own live notifications. `0` is never owned — in the
    /// notifications spec it is the "not a replacement" sentinel, never a real id.
    fn owns(&self, id: u32) -> bool {
        id != 0 && locked(&self.0).contains(&id)
    }
}

/// What the supervisor writes at the front of every relayed notification's application name.
///
/// The daemon gives the sending application a line of its own and shows it whole, so this is the
/// one field of a toast whose author the user can rely on. sbx's own refusal toasts occupy the same
/// line under `sbx` or `sbx · <session>` ([`super::notify_sink`]) and carry the command that widens
/// a launch's network policy; a cage that could spell that line could ask the user to run it.
///
/// Deliberately not a name beginning with `sbx`: the point is that the two are told apart at a
/// glance, and a marker that starts the same way as the thing it is distinguishing from is not one.
const RELAYED_BY: &str = "sandboxed";

/// Hints that name a **file for the host daemon to open**, dropped from every relayed call.
///
/// A notification daemon fetches an `image-path` (and its deprecated `image_path` spelling) and a
/// `sound-file` itself, host-side, in its own process — so a hint forwarded verbatim points a host
/// process at a host path the cage chose, sbx's own mark under the data directory included. Nothing
/// legitimate is lost: a caged app's paths name files inside the cage, where the host daemon cannot
/// follow them anyway.
///
/// The in-band pixel hints (`image-data`, `icon_data`) are deliberately **not** here: they carry the
/// image rather than a path to one, so they open nothing, and they are how an ordinary application
/// puts an avatar or a cover on its own notification.
const HOST_PATH_HINTS: &[&str] = &["image-path", "image_path", "sound-file"];

/// The application name a relayed notification is announced under: [`RELAYED_BY`], then whatever the
/// caged app called itself. The cage writes the tail of the line and can never reach in front of the
/// head, so no toast the relay forwards presents itself as sbx's own or as another application's.
fn relayed_app_name(app_name: &str) -> String {
    if app_name.is_empty() {
        RELAYED_BY.to_string()
    } else {
        format!("{RELAYED_BY} · {app_name}")
    }
}

/// The icon a relayed notification is announced with: a bare freedesktop theme name, or none.
///
/// `app_icon` is either a theme name the daemon resolves or a filename the daemon **opens**, and the
/// daemon is a host process — so a path here is the cage naming a host file for something else to
/// read. Anything shaped like a path or a URI is therefore dropped and the toast simply carries no
/// icon; a bare name is kept, since resolving it against the user's own theme reaches nothing the
/// cage chose. See [`HOST_PATH_HINTS`] for the hints that carry the same thing by another route.
fn relayed_app_icon(app_icon: &str) -> &str {
    // A path and a URI both carry a separator; a theme name never does.
    if app_icon.contains('/') {
        return "";
    }
    app_icon
}

/// The interface served on the **private** bus: every method is forwarded to the host proxy. A
/// forwarding error becomes an `fdo` error reply so the caged app sees a clean failure rather than a
/// dropped call.
struct Served {
    host: Box<dyn HostBus>,
    /// Shared with the signal pump in [`run`], which rules the host's close signals on it and drops
    /// each id as it goes.
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
        // The identity fields are the supervisor's to write, not the cage's: see the module header
        // for what a verbatim `app_name` and a verbatim icon path each buy an agent inside the cage.
        let mut relayed_hints = hints;
        relayed_hints.retain(|hint, _| !HOST_PATH_HINTS.contains(&hint.as_str()));
        let id = self
            .host
            .notify(NotifyCall {
                app_name: relayed_app_name(&app_name),
                replaces_id,
                app_icon: relayed_app_icon(&app_icon).to_string(),
                summary,
                body,
                actions,
                hints: relayed_hints,
                expire_timeout,
            })
            .await
            .map_err(|e| fdo::Error::Failed(format!("forward Notify: {e}")))?;
        self.ours.record(id);
        Ok(id)
    }

    async fn close_notification(&self, id: u32) -> fdo::Result<()> {
        // Same rule as `replaces_id`: an id outside the set is either foreign — the cage must not
        // dismiss what it never raised — or one of the cage's own that the host has already closed
        // (`OwnedIds::closing` dropped it then). Answered `Ok` rather than as an error because of
        // the second case: an app closing a notification that has just expired must not start seeing
        // failures, and closing an already-closed notification is a no-op on the host daemon too.
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
        host: Box::new(host.clone()),
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
                    // The host daemon's signals are desktop-wide: they fire for every application on
                    // the user's session, not for this cage. `emit_signal(None, …)` is a broadcast
                    // and the private bus lets any process receive it, so a foreign signal relayed
                    // in is a live host→cage channel — which buttons a human is clicking elsewhere,
                    // and an id counter whose deltas count the desktop's notification volume. The
                    // set that decides `replaces_id` decides this too, at no functional cost: the
                    // cage's own click-to-focus and action buttons are precisely the owned ids.
                    if ours.owns(id) {
                        let _ = private_conn
                            .emit_signal(None::<&str>, OBJECT, IFACE, "ActionInvoked", &(id, key.as_str()))
                            .await;
                    }
                },
                None => break,
            },
            sig = closed.next().fuse() => match sig {
                Some(sig) => if let Ok(a) = sig.args() {
                    let (id, reason) = (a.id, a.reason);
                    // Whoever raised it, this id now names nothing, so it leaves the set either way;
                    // only the cage's own closures cross back. A desktop-wide close signal tells a
                    // watching agent whether a human dismissed a toast (reason 2) or it expired
                    // unread (reason 1) — a presence-and-attention oracle, and one that answers for
                    // sbx's *own* refusal toasts, so the cage could tell whether its blocked request
                    // was seen before deciding what to try next.
                    if ours.closing(id) {
                        let _ = private_conn
                            .emit_signal(None::<&str>, OBJECT, IFACE, "NotificationClosed", &(id, reason))
                            .await;
                    }
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

    /// The first id the double hands out. Well away from `0` and from any small number a test
    /// writes by hand, so an id the cage guessed is never accidentally one of the cage's own.
    const FIRST_ID: u32 = 4200;

    /// A recording stand-in for the host daemon: it assigns ids the way a real one does and keeps
    /// what actually reached it, so a test can ask what the relay forwarded rather than what the
    /// cage asked for. No session bus, so the whole cage-facing path runs on any machine.
    #[derive(Clone, Default)]
    struct FakeHost {
        /// Every forwarded `Notify` as it actually reached the daemon, in order — what the relay
        /// put on the host bus, never what the cage asked it to.
        calls: Arc<Mutex<Vec<NotifyCall>>>,
        /// The id of every forwarded `CloseNotification`, in order.
        closed: Arc<Mutex<Vec<u32>>>,
    }

    impl FakeHost {
        fn replaced(&self) -> Vec<u32> {
            locked(&self.calls).iter().map(|c| c.replaces_id).collect()
        }

        fn closed(&self) -> Vec<u32> {
            locked(&self.closed).clone()
        }
    }

    impl HostBus for FakeHost {
        fn notify(&self, call: NotifyCall) -> BoxFuture<'_, zbus::Result<u32>> {
            let mut calls = locked(&self.calls);
            calls.push(call);
            let id = FIRST_ID + calls.len() as u32 - 1;
            drop(calls);
            Box::pin(std::future::ready(Ok(id)))
        }

        fn close_notification(&self, id: u32) -> BoxFuture<'_, zbus::Result<()>> {
            locked(&self.closed).push(id);
            Box::pin(std::future::ready(Ok(())))
        }

        fn get_capabilities(&self) -> BoxFuture<'_, zbus::Result<Vec<String>>> {
            Box::pin(std::future::ready(Ok(Vec::new())))
        }

        fn get_server_information(
            &self,
        ) -> BoxFuture<'_, zbus::Result<(String, String, String, String)>> {
            Box::pin(std::future::ready(Ok(Default::default())))
        }
    }

    /// The interface the private bus serves, in front of a recording host.
    fn served(host: &FakeHost) -> Served {
        Served {
            host: Box::new(host.clone()),
            ours: Arc::new(OwnedIds::default()),
        }
    }

    /// One `Notify` as the caged app makes it, answered with the id the relay returns to the cage.
    fn notify(served: &Served, replaces_id: u32) -> u32 {
        notify_as(served, "caged-app", replaces_id, "", HashMap::new())
    }

    /// The same, with the identity fields the cage chooses spelled out: the application name it
    /// claims, the icon it names, and the hints it sends.
    fn notify_as(
        served: &Served,
        app_name: &str,
        replaces_id: u32,
        app_icon: &str,
        hints: HashMap<String, OwnedValue>,
    ) -> u32 {
        async_io::block_on(served.notify(
            app_name.to_string(),
            replaces_id,
            app_icon.to_string(),
            "summary".to_string(),
            "body".to_string(),
            Vec::new(),
            hints,
            -1,
        ))
        .expect("the recording host accepts every call forwarded to it")
    }

    /// A hint value, as a caged app would send one.
    fn hint(value: &str) -> OwnedValue {
        zbus::zvariant::Value::from(value)
            .try_into()
            .expect("a string is a hint value")
    }

    #[test]
    fn notify_does_not_forward_a_replaces_id_the_relay_never_handed_out() {
        let host = FakeHost::default();
        let served = served(&host);

        // A host-wide id the cage names without ever having been given it: on the real bus this
        // overwrites whatever app owns it, sbx's own refusal toasts included.
        let mine = notify(&served, 4242);
        assert_eq!(
            host.replaced(),
            vec![0],
            "a `replaces_id` the relay never handed out must reach the host daemon as the spec's \
             no-replacement sentinel, not as the cage spelled it"
        );

        // What the guard must still permit: the cage revising its own notification in place.
        notify(&served, mine);
        assert_eq!(
            host.replaced(),
            vec![0, mine],
            "an id this relay returned is the cage's own and is forwarded verbatim"
        );
    }

    #[test]
    fn close_notification_is_dropped_for_an_id_the_relay_never_handed_out() {
        let host = FakeHost::default();
        let served = served(&host);
        let mine = notify(&served, 0);

        // Answered `Ok` — an app closing a notification the host already expired must not start
        // seeing failures — but nothing reaches the daemon.
        async_io::block_on(served.close_notification(mine + 1))
            .expect("closing an id the cage does not own is a no-op, not an error");
        assert!(
            host.closed().is_empty(),
            "a `CloseNotification` for an id the relay never handed out must not reach the host \
             daemon: got {:?}",
            host.closed()
        );

        async_io::block_on(served.close_notification(mine))
            .expect("closing the cage's own notification forwards cleanly");
        assert_eq!(
            host.closed(),
            vec![mine],
            "the cage dismissing its own notification is still forwarded"
        );
    }

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
        assert!(ours.closing(7), "the cage's own notification closing");
        assert!(!ours.owns(7), "a closed id is no longer the cage's");
    }

    /// A host signal crosses into the cage only for a notification the cage itself raised.
    ///
    /// The host daemon's `ActionInvoked` and `NotificationClosed` fire for every application on the
    /// user's desktop, and the relay re-emitted both onto the private bus unfiltered — a broadcast
    /// any process in the cage can subscribe to. What that carried is small but real: whether a
    /// human dismissed a toast or let it expire (a presence-and-attention oracle, answered for
    /// sbx's own refusal toasts as much as for anyone's), other applications' action keys, and an id
    /// stream whose deltas count how many notifications the rest of the desktop raised. The set that
    /// already decides `replaces_id` is the filter, and it costs the cage nothing it is entitled to:
    /// its own click-to-focus and action buttons are precisely the ids it owns.
    ///
    /// The close rule is the one with an order inside it — ownership has to be read *before* the id
    /// is dropped, or the cage never learns that its own notification was dismissed.
    #[test]
    fn a_host_signal_crosses_into_the_cage_only_for_a_notification_the_cage_raised() {
        let ours = OwnedIds::default();
        ours.record(FIRST_ID);

        // `ActionInvoked`: the cage's own button click crosses back; another application's does not.
        assert!(ours.owns(FIRST_ID), "the cage's own notification");
        assert!(
            !ours.owns(FIRST_ID + 1),
            "a button clicked on another application's notification is not the cage's business"
        );

        // `NotificationClosed`: a foreign close is dropped, and the cage's own crosses back.
        assert!(
            !ours.closing(FIRST_ID + 1),
            "the desktop closing someone else's notification must not reach the cage"
        );
        assert!(
            ours.closing(FIRST_ID),
            "the cage must still learn that its own notification was dismissed"
        );
        // And once only: the id now names nothing and the host may recycle it for another app.
        assert!(
            !ours.closing(FIRST_ID),
            "a closed id is no longer the cage's"
        );
        assert!(!ours.owns(FIRST_ID), "nor may it be replaced afterwards");
    }

    /// The application name a relayed toast is announced under is written by the supervisor first.
    ///
    /// `app_name` is the one line of a notification a desktop shows whole and attributes to a
    /// sender, and sbx raises its own refusal toasts on this same daemon under `sbx · <session>`,
    /// with a body that ends "· allow it: sbx net allow <host>". Forwarded verbatim, a caged agent
    /// could reproduce that line exactly and ask the user, in the supervisor's voice, to widen the
    /// network policy for a host it picked. The cage still names itself — that is what the line is
    /// for — but only after a marker it cannot get in front of.
    #[test]
    fn notify_announces_a_relayed_toast_under_a_name_the_cage_cannot_write_the_front_of() {
        let host = FakeHost::default();
        let served = served(&host);

        notify_as(&served, "Slack", 0, "", HashMap::new());
        // sbx's own line, spelled by the cage exactly as `notify_sink` composes it.
        notify_as(&served, "sbx · kiro@ops-cli[4242]", 0, "", HashMap::new());
        notify_as(&served, "", 0, "", HashMap::new());

        let calls = locked(&host.calls);
        let announced: Vec<&str> = calls.iter().map(|c| c.app_name.as_str()).collect();
        assert_eq!(
            announced,
            vec![
                "sandboxed · Slack",
                "sandboxed · sbx · kiro@ops-cli[4242]",
                "sandboxed"
            ],
            "every relayed name is the supervisor's marker followed by the cage's own"
        );
        for name in announced {
            assert!(
                !name.starts_with("sbx"),
                "no relayed toast may occupy the line sbx's own announcements use: {name}"
            );
        }
    }

    /// A relayed toast names no host file for the daemon to open.
    ///
    /// The daemon resolves `app_icon` and the `image-path`/`sound-file` hints **itself**, host-side,
    /// in its own process — the cage needs no access to the file it names. Forwarded verbatim they
    /// let a caged agent point a host process at a host path of its choosing, sbx's own mark under
    /// the data directory included, which is what would make a forged refusal toast look right. A
    /// bare theme name is kept (it resolves against the user's own theme and reaches nothing the
    /// cage chose), and hints that carry an image rather than a path to one are left alone.
    #[test]
    fn notify_forwards_no_host_path_for_the_daemon_to_open() {
        let host = FakeHost::default();
        let served = served(&host);

        let mut hints = HashMap::new();
        hints.insert(
            "image-path".to_string(),
            hint("/home/user/.local/share/sbx/sbx.png"),
        );
        hints.insert("image_path".to_string(), hint("/etc/hostname"));
        hints.insert("sound-file".to_string(), hint("/home/user/secret.wav"));
        hints.insert("category".to_string(), hint("device.error"));
        notify_as(
            &served,
            "Slack",
            0,
            "/home/user/.local/share/sbx/sbx.png",
            hints,
        );
        // A theme name is not a path, and is what `app_icon` is for.
        notify_as(&served, "Slack", 0, "dialog-warning", HashMap::new());

        let calls = locked(&host.calls);
        assert_eq!(
            calls[0].app_icon, "",
            "an `app_icon` naming a host file must not reach the daemon, which opens the path in \
             its own process"
        );
        let mut forwarded: Vec<&str> = calls[0].hints.keys().map(String::as_str).collect();
        forwarded.sort_unstable();
        assert_eq!(
            forwarded,
            vec!["category"],
            "every hint naming a file the daemon opens must be dropped, and nothing else"
        );
        assert_eq!(
            calls[1].app_icon, "dialog-warning",
            "a bare theme name resolves against the user's own theme and is still forwarded"
        );
    }
}
