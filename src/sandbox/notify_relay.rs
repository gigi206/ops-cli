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
//! actions work end to end (for this cage's own notifications; see below). The notification id the
//! host returns is passed through verbatim, so a signal carrying that id routes back to the right
//! notification with no remapping.
//!
//! What that forwarding costs is stated here rather than justified away. This section used to argue
//! that the relay adds no capability beyond what the filtered host bus already grants, but under
//! `dbus = true` the cage gets a private bus and no host bus at all, so the relay is its *only*
//! route to the host daemon and everything the relay forwards is capability it would otherwise not
//! have. What it forwards is the notifications interface alone (no keyring, no portal, no other host
//! service). The residual accepted is notification **spoofing**: the cage picks the app name, icon
//! and text of a toast the user reads as the desktop's, within the bounds the relay puts on how much
//! of each it may write ([`SUMMARY_MAX`] and its neighbours). Notification **hijacking** is not
//! accepted — `Notify`'s `replaces_id` and `CloseNotification` are checked against the ids the host
//! daemon actually returned for this cage's own calls ([`OwnedIds`]), so the cage cannot overwrite or
//! dismiss a notification it never raised, sbx's own refusal toasts ([`super::notify_sink`])
//! included.
//!
//! The host→cage direction is checked against the same set. `ActionInvoked` and `NotificationClosed`
//! are broadcasts: per the notifications spec they carry no destination, so the host daemon delivers
//! them for *every* notification it serves, not only this relay's. Re-emitting them all would give
//! the cage a live feed of the user's interaction with unrelated desktop applications (which app
//! notified, when, which action was clicked) and enumerate the host-wide id counter, so the pump
//! emits only the signals whose id this relay itself raised.
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

/// The largest cage-authored `Notify` field the relay forwards, in bytes; longer is truncated. The
/// cage writes every field of a `Notify`, and the host daemon (plus, on daemons that journal
/// notifications, the journal) allocates and lays out whatever it is handed, in a process the cage's
/// own cgroup limits do not cover. Nothing a user reads off a toast needs a megabyte, so these sit
/// far above what any daemon displays and far below what hurts one.
///
/// What is bounded is what *leaves* the relay. The message is already deserialised host-side by the
/// time a method body runs, so this is not a bound on the relay's own transient allocation: a ceiling
/// on what the cage can put on the wire at all belongs to the private bus's own message limits, not
/// here. Nor is there a rate limit: the cage may still notify as fast as the host daemon accepts.
const APP_NAME_MAX: usize = 256;
/// The largest `app_icon` forwarded (an icon name or a path). See [`APP_NAME_MAX`].
const APP_ICON_MAX: usize = 512;
/// The largest `summary` (the toast's title line) forwarded. See [`APP_NAME_MAX`].
const SUMMARY_MAX: usize = 1024;
/// The largest `body` forwarded. See [`APP_NAME_MAX`].
const BODY_MAX: usize = 16 * 1024;
/// The most `actions` entries forwarded. The list is flat `(key, label)` pairs, so the cap is even:
/// truncating to an odd length would hand the daemon a key with no label. See [`APP_NAME_MAX`].
const ACTIONS_MAX: usize = 32;
/// The largest single `actions` entry (one key or one label) forwarded. See [`APP_NAME_MAX`].
const ACTION_MAX: usize = 256;
/// The most `hints` entries forwarded. Hints are optional by spec, so an entry over any of the hint
/// caps is dropped rather than truncated; which entries survive is decided by sorted key so the same
/// call is bounded the same way twice. See [`APP_NAME_MAX`].
const HINTS_MAX: usize = 32;
/// The largest hint key forwarded; a longer-keyed hint is dropped. See [`APP_NAME_MAX`].
const HINT_KEY_MAX: usize = 128;
/// The largest hint value forwarded, as a string's byte length or a container's element count; a
/// larger one is dropped. Only the value itself is measured, not values nested inside a structure,
/// so this bounds the hint shapes the spec defines (`image-path`, `sound-file`, `image-data`'s
/// pixel array) rather than every value D-Bus can express. See [`APP_NAME_MAX`].
const HINT_VALUE_MAX: usize = 4 * 1024 * 1024;

/// Truncate `s` to at most `max` bytes, cutting on a char boundary (a D-Bus string is UTF-8 and must
/// stay valid UTF-8 to serialise).
fn clamp(mut s: String, max: usize) -> String {
    if s.len() <= max {
        return s;
    }
    let mut end = max;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    s.truncate(end);
    s
}

/// One `Notify` as it leaves the relay: the caged app's arguments, with `replaces_id` already
/// settled by the guard in [`Served::notify`] rather than as the cage spelled it.
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

impl NotifyCall {
    /// Apply the forwarding caps ([`APP_NAME_MAX`] and its neighbours) to one cage-authored call.
    /// Text fields are truncated (the app still gets its notification, just not an unbounded one);
    /// hints, being optional by spec, are dropped when they exceed a cap.
    fn bounded(mut self) -> NotifyCall {
        self.app_name = clamp(self.app_name, APP_NAME_MAX);
        self.app_icon = clamp(self.app_icon, APP_ICON_MAX);
        self.summary = clamp(self.summary, SUMMARY_MAX);
        self.body = clamp(self.body, BODY_MAX);
        self.actions.truncate(ACTIONS_MAX);
        self.actions = self
            .actions
            .into_iter()
            .map(|a| clamp(a, ACTION_MAX))
            .collect();
        self.hints
            .retain(|k, v| k.len() <= HINT_KEY_MAX && hint_value_is_bounded(v));
        if self.hints.len() > HINTS_MAX {
            let mut keys: Vec<String> = self.hints.keys().cloned().collect();
            keys.sort();
            for key in keys.into_iter().skip(HINTS_MAX) {
                self.hints.remove(&key);
            }
        }
        self
    }
}

/// Whether one hint value is within [`HINT_VALUE_MAX`]: a string by its byte length, a container by
/// its element count. Any other value is a fixed-size scalar and is always within the cap.
fn hint_value_is_bounded(v: &OwnedValue) -> bool {
    use zbus::zvariant::Value;
    match &**v {
        Value::Str(s) => s.len() <= HINT_VALUE_MAX,
        Value::ObjectPath(p) => p.len() <= HINT_VALUE_MAX,
        Value::Array(a) => a.len() <= HINT_VALUE_MAX,
        Value::Dict(d) => d.iter().count() <= HINT_VALUE_MAX,
        _ => true,
    }
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

    /// Forget an id the host reported closed, answering whether it *was* one of this cage's own.
    /// Keeps the set to the cage's *live* notifications, so a long-running app does not accumulate
    /// ids for the whole launch; the answer is what decides whether the closure is re-emitted into
    /// the cage, and it has to be read before the id is dropped.
    fn forget(&self, id: u32) -> bool {
        id != 0 && locked(&self.0).remove(&id)
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
    host: Box<dyn HostBus>,
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
                NotifyCall {
                    app_name,
                    replaces_id,
                    app_icon,
                    summary,
                    body,
                    actions,
                    hints,
                    expire_timeout,
                }
                .bounded(),
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
                    // Verbatim id → the app matches the signal to its own notification. Only its
                    // own: the host daemon broadcasts this for every notification it serves, and
                    // another application's is not the cage's to see.
                    let (id, key) = (a.id, a.action_key.to_string());
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
                    // Whoever raised it, this id now names nothing: drop it so the set stays the
                    // cage's live notifications, and an id the host later recycles for another app's
                    // notification is not still claimed as the cage's. Whether it *was* the cage's
                    // is also what decides the re-emission — this too is a broadcast, so the cage
                    // would otherwise watch every host notification's lifecycle.
                    if ours.forget(id) {
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
        /// Every forwarded `Notify`, as it left the relay, in order.
        calls: Arc<Mutex<Vec<NotifyCall>>>,
        /// The id of every forwarded `CloseNotification`, in order.
        closed: Arc<Mutex<Vec<u32>>>,
    }

    impl FakeHost {
        /// The `replaces_id` of every forwarded `Notify`, in order.
        fn replaced(&self) -> Vec<u32> {
            locked(&self.calls).iter().map(|c| c.replaces_id).collect()
        }

        /// Read the `index`-th forwarded call under the lock: a [`NotifyCall`] is not `Clone`, so
        /// it is inspected in place rather than handed out.
        fn with_call<R>(&self, index: usize, f: impl FnOnce(&NotifyCall) -> R) -> R {
            f(&locked(&self.calls)[index])
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
        async_io::block_on(served.notify(
            "caged-app".to_string(),
            replaces_id,
            String::new(),
            "summary".to_string(),
            "body".to_string(),
            Vec::new(),
            HashMap::new(),
            -1,
        ))
        .expect("the recording host accepts every call forwarded to it")
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
        assert!(ours.forget(7), "the closed id was the cage's own");
        assert!(!ours.owns(7), "a closed id is no longer the cage's");
    }

    #[test]
    fn only_signals_for_the_cages_own_notifications_cross_back_into_it() {
        // `ActionInvoked`/`NotificationClosed` are broadcasts: the host daemon delivers them for
        // every notification it serves. The pump re-emits a signal onto the private bus only when
        // its id is one this relay raised, so the cage does not watch the user's interaction with
        // unrelated desktop applications. `forget` answers that question for the closed case, and
        // has to answer it while dropping the id (afterwards nothing remembers whose it was).
        let ours = OwnedIds::default();
        ours.record(FIRST_ID);

        // A host notification the cage never raised: neither its action nor its closure crosses.
        assert!(!ours.owns(4711), "a foreign action is not re-emitted");
        assert!(!ours.forget(4711), "a foreign closure is not re-emitted");

        // The cage's own still does, exactly once — the closure both re-emits and drops the id.
        assert!(ours.owns(FIRST_ID), "the cage's own action is re-emitted");
        assert!(
            ours.forget(FIRST_ID),
            "the cage's own closure is re-emitted"
        );
        assert!(
            !ours.forget(FIRST_ID),
            "a second closure for the same id names nothing this relay raised"
        );
    }

    #[test]
    fn notify_bounds_every_cage_written_field_before_it_reaches_the_host_daemon() {
        // Every field of a `Notify` is written by the cage, and the host daemon (plus the journal,
        // on daemons that log notifications) allocates and lays out whatever it is handed, in a
        // process the cage's own cgroup limits do not cover. Forwarding a body, an actions list or
        // a hints map of arbitrary size makes the caged app a lever on the user's desktop session.
        use zbus::zvariant::Value;
        let host = FakeHost::default();
        let served = served(&host);

        let value = |v: &str| {
            OwnedValue::try_from(Value::from(v.to_string())).expect("a string is an owned value")
        };
        let mut hints: HashMap<String, OwnedValue> = (0..HINTS_MAX + 8)
            .map(|i| (format!("hint-{i:03}"), value("v")))
            .collect();
        hints.insert("k".repeat(HINT_KEY_MAX + 1), value("v"));
        hints.insert("huge".to_string(), value(&"v".repeat(HINT_VALUE_MAX + 1)));

        async_io::block_on(
            served.notify(
                "n".repeat(APP_NAME_MAX + 10),
                0,
                "i".repeat(APP_ICON_MAX + 10),
                "summary".to_string(),
                // A 3-byte char, so the cap does not fall on a char boundary: the cut must still leave
                // valid UTF-8 (a `String` that is not would not survive the round-trip at all).
                "\u{20ac}".repeat(BODY_MAX),
                (0..ACTIONS_MAX + 4)
                    .map(|_| "a".repeat(ACTION_MAX + 10))
                    .collect(),
                hints,
                -1,
            ),
        )
        .expect("the recording host accepts every call forwarded to it");

        host.with_call(0, |call| {
            assert_eq!(call.app_name.len(), APP_NAME_MAX);
            assert_eq!(call.app_icon.len(), APP_ICON_MAX);
            assert_eq!(
                call.summary, "summary",
                "a field within its cap is forwarded unchanged"
            );
            assert!(
                call.body.len() <= BODY_MAX && call.body.len() > BODY_MAX - 3,
                "the body is cut to the cap, on the char boundary below it: {}",
                call.body.len()
            );
            assert_eq!(call.actions.len(), ACTIONS_MAX);
            assert!(
                call.actions.iter().all(|a| a.len() == ACTION_MAX),
                "each action label is capped too, not just their number"
            );
            assert_eq!(
                call.hints.len(),
                HINTS_MAX,
                "an over-long key and an over-large value are dropped, then the map is cut to \
                 the cap by sorted key"
            );
            assert!(
                call.hints.contains_key("hint-000") && !call.hints.contains_key("hint-039"),
                "which hints survive is decided by sorted key, so it is the same twice"
            );
            assert!(
                !call.hints.contains_key("huge"),
                "a hint value over the cap is dropped (hints are optional by spec)"
            );
        });
    }
}
