//! The in-cage desktop notifications relay (`dbus = true`).
//!
//! The in-cage portal ([`super::portal`]) gives a Chromium/Electron app its own private D-Bus bus so
//! its file chooser renders in-cage. That private bus carries the portal, but nothing serves
//! `org.freedesktop.Notifications` on it, so the app cannot raise a desktop notification. This relay
//! bridges the gap: it runs **host-side**, in the supervisor's own process, connects both to the
//! private bus (through the socket the portal exposes on a host path) and to the real host session
//! bus, **owns `org.freedesktop.Notifications` on the private bus**, and forwards every call to the
//! host daemon — re-emitting the host's `ActionInvoked` and `NotificationClosed` signals back onto
//! the private bus so click-to-focus and notification actions work end to end. The notification id
//! the host returns is passed through verbatim, so a signal carrying that id routes back to the
//! right notification with no remapping.
//!
//! **It runs in the supervisor, not in a caged helper.** The reasons, and what would change them,
//! are written in [`crate::sandbox::selfcage`].
//!
//! What that forwarding costs is stated here rather than justified away. Under `dbus = true` the
//! cage gets a private bus and no host bus at all, so the relay is its *only* route to the host
//! daemon and everything the relay forwards is capability it would otherwise not have. What it
//! forwards is the notifications interface alone (no keyring, no portal, no other host service).
//! The residual accepted is notification **spoofing**: the cage picks the *text* of a toast the
//! user reads as the desktop's. What follows is held back from it, because each turns spoofing into
//! something else:
//!
//! - **Identity.** The application name is written by the supervisor first and by the cage only
//!   after it ([`relayed_app_name`]). sbx raises its own refusal toasts on this same host daemon,
//!   under `sbx` or `sbx · <session>` ([`super::notify_sink`]), and those carry the copy-and-paste
//!   command that widens a launch's network policy — so a cage free to spell its own `app_name`
//!   could ask the user, in sbx's own voice, to open a hole for it. The same line is reachable by a
//!   second route, and it is closed with it: a daemon that is handed a `desktop-entry` hint resolves
//!   it to an installed host application and renders the toast under *that* application's name and
//!   icon, ahead of the arguments it was called with, so those hints are dropped
//!   ([`HOST_IDENTITY_HINTS`]).
//! - **Host files.** The icon a daemon renders is a path *the daemon* opens, host-side, in its own
//!   process. A relayed `app_icon` is therefore reduced to a bare theme name and the hints that name
//!   a file are dropped ([`relayed_app_icon`], [`HOST_PATH_HINTS`]); a caged app has no host path
//!   worth naming in any case, since everything it can see is inside the cage.
//! - **Unbounded text.** The cage writes the words of a toast; it does not get to decide how many
//!   are rendered. The summary, the body and each action label are cut to a ceiling, and the action
//!   list to a length ([`bounded`], [`SUMMARY_MAX`], [`BODY_MAX`], [`ACTIONS_MAX`]). Without one,
//!   spoofing a toast becomes displacing the desktop's: a summary long enough pushes every other
//!   notification's text out of the area the user reads, and the cost of rendering it is paid in a
//!   host process rather than in the cage's cgroup. The ceilings count **characters**, because the
//!   quantity they are about is rendered length rather than bytes; they are far above any real
//!   notification, so what they refuse is only the shape that was never one.
//!
//!   `hints` is not cut hint by hint, and the reason holds: `image-data` carries a notification's
//!   icon as raw pixel data, so "large" is what a legitimate hint looks like, and a cap on one hint
//!   would refuse the real case while an attacker moved the same bytes into the next hint name.
//!   What bounds them is a ceiling on the **whole call**, weighed before any of it is decoded
//!   ([`CALL_MESSAGE_MAX`]): no hint name carries bytes past it, and a call over it is answered
//!   with `LimitsExceeded` and forwarded nowhere. The legitimate case it refuses is stated rather
//!   than implied: an `image-data` icon of 512 by 512 RGBA pixels no longer fits, where a 256 by
//!   256 one takes a quarter of the ceiling. What *is* ruled on hint by hint is which hints cross
//!   at all: those that name a host file for the daemon to open ([`HOST_PATH_HINTS`]) and those
//!   that name the application the daemon renders the toast as ([`HOST_IDENTITY_HINTS`]), and, for
//!   one of the rest, which value ([`capped_urgency`]). The trigger to revisit: a hint the cage can
//!   make the host daemon persist or execute, or one that decides something the arguments above
//!   were held to, where the question stops being size.
//! - **Insistence.** Two fields ask the desktop to keep a toast on screen until a person clicks it
//!   away: `urgency = critical` and `expire_timeout = 0`. Neither is something sbx sends for its
//!   own announcements — [`super::notify_sink`] writes the reason, that a toast which must be
//!   dismissed by hand, repeated, is what makes a person turn notifications off — so neither is
//!   something a cage may ask for through this relay. The urgency hint is dropped at `critical` and
//!   `0` becomes the daemon's own default ([`capped_urgency`], [`relayed_expire_timeout`]); a lower
//!   urgency and a finite lifetime are the ordinary case and cross untouched.
//! - **Other applications' notifications.** `Notify`'s `replaces_id` and `CloseNotification` are
//!   checked against the ids the host daemon actually returned for this cage's own calls
//!   ([`OwnedIds`]), so the cage can neither overwrite nor dismiss a notification it never raised,
//!   sbx's own refusal toasts included; and the host's `ActionInvoked`/`NotificationClosed` cross
//!   back onto the private bus only for those same ids, so the rest of the desktop's notification
//!   traffic is not a stream the cage can subscribe to.
//! - **The host's machine id.** The calls the relay answers itself (`Peer`, `Introspectable`,
//!   `Properties`) answer for the relay's own connection, which runs on the host:
//!   `Peer.GetMachineId` is refused rather than answered, because the id it would read is the
//!   host's, the one the cage's own `/etc/machine-id` is synthesized to withhold.
//!
//! **What a call costs the supervisor.** The relay decodes the cage's calls in the supervisor,
//! outside the cage's memory limit, so what they take is the host's. Calls are read off a queue
//! [`CALLS_QUEUED`] deep and served one at a time; while the queue is full zbus stops reading the
//! private bus, and what the cage sends next waits in the in-cage daemon, under the cage's own
//! limit. A call is weighed whole before it is decoded ([`CALL_MESSAGE_MAX`]), and one forwarded to
//! the host waits at most [`HOST_CALL_DEADLINE`] for its answer. That leaves a bound rather than
//! nothing. The call being served decodes to as much as 64 times its size when its hints carry
//! byte arrays, one value per byte. The messages queued ahead of the weighing, and the one zbus
//! holds while the queue is full, are each as large as the bus lets through:
//! [`super::portal::BUS_MESSAGE_MAX`] from the in-cage daemon. That ceiling is set on the cage's
//! side, though: a cage that puts a server of its own at the socket before the relay dials it is
//! held only by zbus's ceiling of 128 MiB per message, and the bound becomes [`CALLS_QUEUED`] plus
//! two such messages.
//!
//! **A host whose desktop is not on its session bus.** A Lima guest on a Mac runs no
//! notifications daemon: the desktop is the Mac's. When none answers there and the guest mounts the
//! Mac's notification directory ([`super::notify_sink::desktop_without_daemon`], the decision sbx's
//! own refusals take too), each call is written into that directory as a note instead
//! ([`MacQueue`]), every guard above applied first. The Mac shows a note as a title, a subtitle and
//! a body under sbx's own icon, with no separate line for the sending application, so the
//! supervisor's application name becomes the title: a relayed note always opens with
//! [`RELAYED_BY`], where sbx's own notes open with what was refused. Nothing comes back from the
//! Mac, so a relayed note offers no actions and is never reported closed, and the app's icon and
//! pixel hints are not shown.
//!
//! Lifecycle:[`NotifyRelay::start`] spawns a dedicated thread that drives the async work with
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
use futures_util::stream::BoxStream;
use futures_util::{FutureExt, StreamExt};
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};
use zbus::message::{Flags, Header, Type};
use zbus::zvariant::{DynamicDeserialize, DynamicType, OwnedValue};
use zbus::{MatchRule, Message, MessageStream, connection, fdo, proxy};

/// The notifications service name and object path (identical on the host and the private bus).
const IFACE: &str = "org.freedesktop.Notifications";
const OBJECT: &str = "/org/freedesktop/Notifications";
/// The standard interfaces every object answers on D-Bus, which the relay answers itself.
const PEER: &str = "org.freedesktop.DBus.Peer";
const INTROSPECTABLE: &str = "org.freedesktop.DBus.Introspectable";
const PROPERTIES: &str = "org.freedesktop.DBus.Properties";

/// The largest call from the private bus the relay decodes, in bytes, counted on the whole message
/// before any of it is decoded.
///
/// A call's arguments are the cage's to write, and they are decoded in the supervisor, outside the
/// cage's memory limit. A byte array inside a hint decodes to one value per byte, as much as 64
/// times its encoded size, so this ceiling is also what holds the call being served to tens of
/// mebibytes. A call over it is answered with `LimitsExceeded` and forwarded nowhere; the module
/// header states the one legitimate case that refuses.
const CALL_MESSAGE_MAX: usize = 1 << 20;

/// How many calls from the private bus may wait for the relay at once.
///
/// While the queue is full zbus stops reading the private bus, so what the cage sends next stays
/// in the in-cage daemon, under the cage's own memory limit, rather than in the supervisor. Calls
/// are served one at a time and an application raises a notification at human pace, so two is
/// ample. zbus's own object server queues 64 calls and cannot be told otherwise, which is why the
/// relay reads its calls itself.
const CALLS_QUEUED: usize = 2;

/// The longest a call forwarded to the host daemon may wait for its answer.
///
/// The relay serves the cage's calls one at a time, so a host daemon slow to answer would otherwise
/// hold every call behind it. Wide enough that a live daemon always answers inside it. What the
/// bound gives up is stated rather than implied: a `Notify` that times out may still reach the
/// screen, since the daemon may only have been slow, and the id it then hands out never enters
/// [`OwnedIds`], so the cage can neither replace nor close that notification, and its signals do
/// not cross back.
const HOST_CALL_DEADLINE: Duration = Duration::from_secs(5);
/// How long to wait for the in-cage `dbus-daemon` to create the private-bus socket before giving up
/// (best-effort: the portal's wrap starts the daemon before the app, so the socket appears within
/// milliseconds; this bound only guards against a portal that failed to come up).
const SOCKET_WAIT: Duration = Duration::from_secs(10);
const POLL_INTERVAL: Duration = Duration::from_millis(50);

/// The longest a relayed signal may take to reach the private bus before the relay gives up on it.
///
/// This is the bound the teardown's `join` inherits. Emitting a signal is a write with no reply, so
/// what can hold it is the socket buffer filling — a cage that has stopped reading its end. Wide
/// enough that a busy but live cage is never cut (the buffer drains in microseconds when anything
/// is reading), short enough that a session's teardown is not held by a cage that has stopped.
const EMIT_DEADLINE: Duration = Duration::from_secs(5);

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
/// [`HostNotificationsProxy`]; the tests drive [`Served`]'s own methods, which is what [`answer`]
/// routes the private bus's calls to, against a recording double.
///
/// Boxed futures rather than a trait `async fn`: [`Served`] holds its host as a `dyn HostBus`, and a
/// trait with an `async fn` cannot be made into one.
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

/// The relay's destination on a Lima guest on a Mac: the Mac's notification directory, written one
/// note per `Notify`, in place of a daemon the guest does not run.
///
/// What reaches it has been through [`Served::notify`] already, so its fields hold what the guards
/// left of the cage's call; the note's own sanitising and length ceiling apply on top. The ids it
/// answers with are its own count, never `0`, so [`OwnedIds`] still rules on `replaces_id` and
/// `CloseNotification`; a replacement is a new note, since a raised note cannot be revised. The
/// capabilities name the body alone: no action is offered, because no click comes back.
struct MacQueue {
    /// The notification channel's root, [`super::lima_mac::NOTIFY_MOUNT`] outside tests.
    dir: PathBuf,
    next: AtomicU32,
}

impl MacQueue {
    fn new(dir: PathBuf) -> MacQueue {
        MacQueue {
            dir,
            next: AtomicU32::new(1),
        }
    }
}

impl HostBus for MacQueue {
    fn notify(&self, call: NotifyCall) -> BoxFuture<'_, zbus::Result<u32>> {
        let id = self.next.fetch_add(1, Ordering::Relaxed);
        let written = super::lima_mac::queue_note(
            &self.dir,
            super::lima_mac::NoteSource::App,
            &call.app_name,
            &call.summary,
            &call.body,
        );
        Box::pin(std::future::ready(match written {
            Ok(true) => Ok(id),
            Ok(false) => Err(zbus::Error::Failure(
                "the Mac's notification queue is full".to_string(),
            )),
            Err(e) => Err(zbus::Error::Failure(format!(
                "the Mac's notification queue: {e}"
            ))),
        }))
    }

    fn close_notification(&self, _id: u32) -> BoxFuture<'_, zbus::Result<()>> {
        Box::pin(std::future::ready(Ok(())))
    }

    fn get_capabilities(&self) -> BoxFuture<'_, zbus::Result<Vec<String>>> {
        Box::pin(std::future::ready(Ok(vec!["body".to_string()])))
    }

    fn get_server_information(
        &self,
    ) -> BoxFuture<'_, zbus::Result<(String, String, String, String)>> {
        Box::pin(std::future::ready(Ok((
            "sbx".to_string(),
            "sbx".to_string(),
            env!("CARGO_PKG_VERSION").to_string(),
            "1.2".to_string(),
        ))))
    }
}

/// The host daemon's `ActionInvoked` signals as the relay reads them: the id and the action key, or
/// `None` for a signal whose arguments did not decode.
type ActionSignals = BoxStream<'static, Option<(u32, String)>>;

/// The host daemon's `NotificationClosed` signals as the relay reads them: the id and the reason, or
/// `None` for a signal whose arguments did not decode.
type ClosedSignals = BoxStream<'static, Option<(u32, u32)>>;

/// Where the relay sends a cage's notifications.
#[derive(Debug, PartialEq, Eq)]
enum RelayTarget {
    /// The daemon on the host's session bus.
    Daemon,
    /// The Mac's notification directory ([`MacQueue`]).
    Mac,
}

/// Where the relay sends: the host daemon whenever one answered, the Mac's directory only when none
/// did and `fallback`, asked only then, names the Mac. Pure apart from `fallback`.
fn relay_target(
    daemon_answered: bool,
    fallback: impl FnOnce() -> super::notify_sink::DaemonlessDesktop,
) -> RelayTarget {
    if !daemon_answered && fallback() == super::notify_sink::DaemonlessDesktop::Mac {
        RelayTarget::Mac
    } else {
        RelayTarget::Daemon
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
///
/// The limit, since a set of numbers cannot see it: the ids are the *host daemon's*, and a daemon
/// that restarts begins counting again. Ids this set still holds then name notifications the new
/// daemon handed to somebody else, so the check that keeps the cage off a foreign notification
/// reads them as the cage's own and lets it replace or close one. Following that needs a
/// `NameOwnerChanged` subscription on the notifications bus name, emptying the set when the owner
/// changes; the connection this relay already holds is where it would go. Not built here, and said
/// rather than left for a reader to discover: the window is a daemon restart during one session,
/// and what it costs is a foreign toast dismissed.
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

/// Hints that name an **installed host application** for the daemon to render the toast as, dropped
/// from every relayed call.
///
/// A daemon resolves `desktop-entry` (and the vendor spellings of the same hint) to a `.desktop`
/// file installed on the host, and then draws the notification under *that* application's name and
/// icon — ahead of the `app_name` and `app_icon` arguments it was called with. Forwarded verbatim it
/// hands the cage the one line [`relayed_app_name`] exists to own, and loads a host file of the
/// cage's choosing by the same route [`HOST_PATH_HINTS`] closes. Nothing legitimate is lost: a caged
/// app's own desktop entry lives inside the cage, where the host daemon has nothing to resolve.
const HOST_IDENTITY_HINTS: &[&str] = &[
    "desktop-entry",
    "desktop_entry",
    "x-gnome-desktop-entry",
    "x-kde-desktop-entry",
];

/// `urgency = critical`, the level that pins a toast on screen until it is dismissed by hand.
///
/// The same number [`crate::sandbox::notify_sink`] refuses to send for sbx's own announcements, and
/// for the reason written there: a toast that has to be clicked away, repeated, is what makes a
/// person turn notifications off altogether. A refusal sbx raises itself is worth seeing and is
/// still not an emergency, so a toast the *cage* asked for cannot be more insistent than that.
const URGENCY_CRITICAL: u8 = 2;

/// The hints of a relayed call with `urgency` held to what sbx allows its own toasts.
///
/// Only the one hint is touched, and only downwards: `low` and `normal` cross unchanged, and a
/// value of any other type is left alone because it is not an urgency the daemon will read. The
/// hint is dropped rather than rewritten when it asks for `critical`, which lands the toast on the
/// daemon's own default, the same place sbx's announcements sit.
fn capped_urgency(mut hints: HashMap<String, OwnedValue>) -> HashMap<String, OwnedValue> {
    let asked: Option<u8> = hints.get("urgency").and_then(|v| v.downcast_ref().ok());
    if asked.is_some_and(|u| u >= URGENCY_CRITICAL) {
        hints.remove("urgency");
    }
    hints
}

/// The expiry a relayed notification is forwarded with.
///
/// `0` means "never expires" in the specification, which is the other way to pin a toast on screen,
/// and it arrives from the cage. It becomes `-1`, "let the daemon decide", which is what
/// [`crate::sandbox::notify_sink`] sends for sbx's own toasts. Every other value is a finite
/// lifetime the app chose and goes through: a notification that expires on its own is the ordinary
/// case this exists to keep working.
fn relayed_expire_timeout(asked: i32) -> i32 {
    if asked == 0 { -1 } else { asked }
}

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

/// The most characters a relayed notification's summary may carry. A summary is the one line a
/// daemon renders large, and no real one approaches this. Characters, not bytes: the ceiling is
/// about what the user is shown, and the worst case in bytes is still bounded by four times this.
const SUMMARY_MAX: usize = 200;

/// The most characters a relayed notification's body may carry. Generous — a body may legitimately
/// run to several paragraphs — and still a ceiling. Characters, as for the summary.
const BODY_MAX: usize = 4096;

/// The most characters a relayed notification's identity fields may carry.
///
/// The daemon gives the sending application a line of its own and shows it whole, so an `app_name`
/// the cage chose is the one field a length ceiling was missing from while the summary, the body
/// and every action label had one. The icon is a theme name here (a path is replaced before this),
/// and no theme name is anywhere near this. Short on purpose: this names an application, not
/// content.
const APP_IDENTITY_MAX: usize = 128;

/// The most action entries a relayed notification may carry. The list is `(id, label)` pairs, so
/// this is even on purpose: an odd cut would hand the daemon half a pair, which is a malformed
/// action rather than one fewer. A list the cage sent odd stays as the cage sent it — that is its
/// own malformed input and not something a ceiling should quietly repair.
const ACTIONS_MAX: usize = 32;

/// Cut `s` to at most `max` characters, on a character boundary.
///
/// Characters rather than bytes, because the ceiling is about what a daemon renders and a byte cut
/// through a multi-byte character is not a string at all. A value already within the ceiling is
/// returned untouched, so the common path allocates nothing.
fn bounded(s: String, max: usize) -> String {
    match s.char_indices().nth(max) {
        None => s,
        Some((cut, _)) => s[..cut].to_string(),
    }
}

/// What the relay answers on the **private** bus: each notifications call [`answer`] routes here is
/// forwarded to the host daemon. A forwarding error becomes an `fdo` error reply so the caged app
/// sees a clean failure rather than a dropped call.
struct Served {
    host: Box<dyn HostBus>,
    /// Shared with the signal pump in [`run`], which rules the host's close signals on it and drops
    /// each id as it goes.
    ours: Arc<OwnedIds>,
    /// The launch's credential set, filled in by the egress proxy once it has resolved this
    /// launch's secrets and shared by `Arc`, exactly as the refusal notifier holds it. Empty until
    /// then, and empty for a launch with no secrets.
    needles: crate::sandbox::notify_sink::Needles,
}

impl Served {
    /// Replace this launch's credentials with their placeholders before a string leaves for the
    /// host daemon.
    ///
    /// The relay carries text the *cage* wrote to a daemon that journals it, and journald keeps it
    /// on the host after the cage is gone. sbx's own announcements have been held to this from the
    /// start, in the words of [`crate::sandbox::notify_sink`]'s module header: agent-chosen text is
    /// redacted before it reaches a daemon. The app's own notifications travel the same road to the
    /// same daemon and were the half nobody had held to it. Nothing legitimate is lost: a needle is
    /// a credential sbx itself injected, matched whole, so an app's real message is untouched.
    fn redacted(&self, text: String) -> String {
        let Ok(needles) = self.needles.read() else {
            // A poisoned lock is not a reason to forward a credential: an empty needle set would
            // redact nothing, so the text is dropped to its placeholder-free skeleton instead.
            return String::new();
        };
        if needles.is_empty() {
            return text;
        }
        crate::sandbox::redact::redact_string(
            &text,
            &needles,
            &crate::sandbox::redact::Placeholder::Plain,
        )
        .0
    }

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
        relayed_hints.retain(|hint, _| {
            let hint = hint.as_str();
            !HOST_PATH_HINTS.contains(&hint) && !HOST_IDENTITY_HINTS.contains(&hint)
        });
        relayed_hints = capped_urgency(relayed_hints);
        let id = self
            .host
            .notify(NotifyCall {
                app_name: bounded(relayed_app_name(&app_name), APP_IDENTITY_MAX),
                replaces_id,
                app_icon: bounded(relayed_app_icon(&app_icon).to_string(), APP_IDENTITY_MAX),
                summary: bounded(self.redacted(summary), SUMMARY_MAX),
                body: bounded(self.redacted(body), BODY_MAX),
                actions: actions
                    .into_iter()
                    .take(ACTIONS_MAX)
                    .map(|a| bounded(self.redacted(a), SUMMARY_MAX))
                    .collect(),
                hints: relayed_hints,
                expire_timeout: relayed_expire_timeout(expire_timeout),
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

/// The arguments of `Notify`, in the order the specification gives them.
type NotifyArgs = (
    String,
    u32,
    String,
    String,
    String,
    Vec<String>,
    HashMap<String, OwnedValue>,
    i32,
);

/// The line every introspection document opens with.
const INTROSPECTION_DOCTYPE: &str = "<!DOCTYPE node PUBLIC \"-//freedesktop//DTD D-BUS Object \
     Introspection 1.0//EN\"\n \"http://www.freedesktop.org/standards/dbus/1.0/introspect.dtd\">\n";

/// What the relay answers to `Introspect` on [`OBJECT`]: the interfaces it answers there, and only
/// what it answers. `Peer` lists `Ping` alone, since `GetMachineId` is refused.
const OBJECT_INTROSPECTION: &str = r#"<node>
  <interface name="org.freedesktop.DBus.Introspectable">
    <method name="Introspect">
      <arg type="s" direction="out"/>
    </method>
  </interface>
  <interface name="org.freedesktop.DBus.Peer">
    <method name="Ping">
    </method>
  </interface>
  <interface name="org.freedesktop.DBus.Properties">
    <method name="Get">
      <arg name="interface_name" type="s" direction="in"/>
      <arg name="property_name" type="s" direction="in"/>
      <arg type="v" direction="out"/>
    </method>
    <method name="Set">
      <arg name="interface_name" type="s" direction="in"/>
      <arg name="property_name" type="s" direction="in"/>
      <arg name="value" type="v" direction="in"/>
    </method>
    <method name="GetAll">
      <arg name="interface_name" type="s" direction="in"/>
      <arg type="a{sv}" direction="out"/>
    </method>
    <signal name="PropertiesChanged">
      <arg name="interface_name" type="s"/>
      <arg name="changed_properties" type="a{sv}"/>
      <arg name="invalidated_properties" type="as"/>
    </signal>
  </interface>
  <interface name="org.freedesktop.Notifications">
    <method name="Notify">
      <arg name="app_name" type="s" direction="in"/>
      <arg name="replaces_id" type="u" direction="in"/>
      <arg name="app_icon" type="s" direction="in"/>
      <arg name="summary" type="s" direction="in"/>
      <arg name="body" type="s" direction="in"/>
      <arg name="actions" type="as" direction="in"/>
      <arg name="hints" type="a{sv}" direction="in"/>
      <arg name="expire_timeout" type="i" direction="in"/>
      <arg type="u" direction="out"/>
    </method>
    <method name="CloseNotification">
      <arg name="id" type="u" direction="in"/>
    </method>
    <method name="GetCapabilities">
      <arg type="as" direction="out"/>
    </method>
    <method name="GetServerInformation">
      <arg type="s" direction="out"/>
      <arg type="s" direction="out"/>
      <arg type="s" direction="out"/>
      <arg type="s" direction="out"/>
    </method>
  </interface>
</node>
"#;

/// The introspection document for `path`: the notifications object in full, and each of its parents
/// as a node that leads to it, so a client walking the tree from `/` finds the object. `None` for
/// any other path.
fn introspection(path: &str) -> Option<String> {
    if path == OBJECT {
        return Some(format!("{INTROSPECTION_DOCTYPE}{OBJECT_INTROSPECTION}"));
    }
    let below = if path == "/" {
        OBJECT
    } else {
        OBJECT.strip_prefix(path)?
    };
    let child = below.strip_prefix('/')?.split('/').next()?;
    Some(format!(
        "{INTROSPECTION_DOCTYPE}<node>\n  <node name=\"{child}\"/>\n</node>\n"
    ))
}

/// Whether a call from the private bus is small enough to be decoded: `LimitsExceeded` when the
/// whole message is over [`CALL_MESSAGE_MAX`].
fn within_call_ceiling(call: &Message) -> fdo::Result<()> {
    let size = call.data().len();
    if size > CALL_MESSAGE_MAX {
        return Err(fdo::Error::LimitsExceeded(format!(
            "a call of {size} bytes is over the relay's ceiling of {CALL_MESSAGE_MAX}"
        )));
    }
    Ok(())
}

/// The arguments of `call`, or the `InvalidArgs` its caller is answered with.
fn arguments<T>(call: &Message) -> fdo::Result<T>
where
    T: for<'b> DynamicDeserialize<'b>,
{
    call.body()
        .deserialize()
        .map_err(|e| fdo::Error::InvalidArgs(e.to_string()))
}

/// Send `outcome` back to the caller of `call`, unless the caller asked for no reply.
async fn respond<B>(
    conn: &zbus::Connection,
    call: &Header<'_>,
    outcome: fdo::Result<B>,
) -> zbus::Result<()>
where
    B: serde::Serialize + DynamicType,
{
    if call.primary().flags().contains(Flags::NoReplyExpected) {
        return Ok(());
    }
    match outcome {
        Ok(body) => conn.reply(call, &body).await,
        Err(e) => conn.reply_dbus_error(call, e).await,
    }
}

/// Answer one call from the private bus.
///
/// The order is the bound: the call is weighed whole before any of it is decoded, so one over
/// [`CALL_MESSAGE_MAX`] costs the supervisor nothing past what the bus already handed it. The
/// notifications methods are forwarded through [`Served`]. The standard interfaces are answered
/// here, for the relay's own connection, which is why `Peer.GetMachineId` is refused (see the
/// module header). Anything else gets the error a D-Bus object answers it with.
async fn answer(conn: &zbus::Connection, served: &Served, call: &Message) -> zbus::Result<()> {
    let hdr = call.header();
    if let Err(e) = within_call_ceiling(call) {
        return respond(conn, &hdr, Err::<(), _>(e)).await;
    }
    let path = hdr.path().map_or("", |p| p.as_str());
    let interface = hdr.interface().map(|i| i.as_str());
    let member = hdr.member().map_or("", |m| m.as_str());
    let unknown_method = || fdo::Error::UnknownMethod(format!("Unknown method '{member}'"));
    let unknown_object = || fdo::Error::UnknownObject(format!("Unknown object '{path}'"));
    match interface {
        // `Peer` speaks for the connection rather than for an object, so it answers at any path.
        Some(PEER) if member == "Ping" => respond(conn, &hdr, Ok(())).await,
        Some(INTROSPECTABLE) if member == "Introspect" => {
            respond(conn, &hdr, introspection(path).ok_or_else(unknown_object)).await
        }
        Some(PEER) => respond(conn, &hdr, Err::<(), _>(unknown_method())).await,
        _ if path != OBJECT => respond(conn, &hdr, Err::<(), _>(unknown_object())).await,
        Some(IFACE) => match member {
            "Notify" => {
                let outcome = async {
                    let (app_name, replaces_id, app_icon, summary, body, actions, hints, expire) =
                        arguments::<NotifyArgs>(call)?;
                    served
                        .notify(
                            app_name,
                            replaces_id,
                            app_icon,
                            summary,
                            body,
                            actions,
                            hints,
                            expire,
                        )
                        .await
                };
                respond(conn, &hdr, outcome.await).await
            }
            "CloseNotification" => {
                let outcome = async { served.close_notification(arguments(call)?).await };
                respond(conn, &hdr, outcome.await).await
            }
            "GetCapabilities" => respond(conn, &hdr, served.get_capabilities().await).await,
            "GetServerInformation" => {
                respond(conn, &hdr, served.get_server_information().await).await
            }
            _ => respond(conn, &hdr, Err::<(), _>(unknown_method())).await,
        },
        // The notifications object has no properties, which is what a client that loads them as it
        // connects is told.
        Some(PROPERTIES) => match member {
            "GetAll" => {
                let outcome = arguments::<String>(call).and_then(|asked| {
                    if asked == IFACE {
                        Ok(HashMap::<String, OwnedValue>::new())
                    } else {
                        Err(fdo::Error::UnknownInterface(format!(
                            "Unknown interface '{asked}'"
                        )))
                    }
                });
                respond(conn, &hdr, outcome).await
            }
            "Get" | "Set" => {
                let none = fdo::Error::UnknownProperty("this object has no properties".to_string());
                respond(conn, &hdr, Err::<(), _>(none)).await
            }
            _ => respond(conn, &hdr, Err::<(), _>(unknown_method())).await,
        },
        Some(INTROSPECTABLE) | None => respond(conn, &hdr, Err::<(), _>(unknown_method())).await,
        Some(other) => {
            let unknown = fdo::Error::UnknownInterface(format!("Unknown interface '{other}'"));
            respond(conn, &hdr, Err::<(), _>(unknown)).await
        }
    }
}

/// Serve the calls the private bus routes to the relay, one at a time and in order, until the bus
/// goes or a reply cannot be written.
///
/// One at a time is the point: a call is taken off the queue only once the one before it has been
/// answered, so what the cage has sent and the relay has not answered yet stays in the in-cage
/// daemon rather than in the supervisor (see [`CALLS_QUEUED`]).
async fn serve_calls(conn: &zbus::Connection, served: &Served, mut calls: MessageStream) {
    while let Some(Ok(call)) = calls.next().await {
        if answer(conn, served, &call).await.is_err() {
            break;
        }
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
    pub(crate) fn start(
        private_socket: PathBuf,
        needles: crate::sandbox::notify_sink::Needles,
    ) -> NotifyRelay {
        NotifyRelay::start_on(private_socket, None, needles)
    }

    /// [`NotifyRelay::start`] towards the host daemon on the bus at `host_bus`, the session bus the
    /// supervisor was given when `None`, so a test can stand a daemon of its own in for the user's.
    fn start_on(
        private_socket: PathBuf,
        host_bus: Option<String>,
        needles: crate::sandbox::notify_sink::Needles,
    ) -> NotifyRelay {
        let (shutdown, rx) = async_channel::bounded::<()>(1);
        let handle = std::thread::Builder::new()
            .name("sbx-notify-relay".to_string())
            .spawn(move || {
                if let Err(e) = async_io::block_on(run(private_socket, host_bus, rx, needles)) {
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
        //
        // Two kinds of write go to the private bus, and one of them can hold this join. A reply to
        // a call is written inside the call loop, which is a future the shutdown branch races, so a
        // reply parked on a cage that has stopped reading is dropped with the loop, and so is a
        // call still waiting on the host daemon. A relayed signal is emitted with an `await` inside
        // a branch, outside the select, so a cage that has stopped reading its end and filled the
        // socket buffer would park the task there; that write is bounded instead. The bound is on
        // the emit rather than on this join (`EMIT_DEADLINE`), because
        // detaching instead would leave the connection live while the directory holding its socket
        // is removed — the ordering this join exists to guarantee. An emit that times out ends the
        // loop rather than continuing it: an abandoned write may have left a partial message, and
        // the next one would append to a fragment.
        self.shutdown.close();
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

/// Emit one signal onto the private bus under [`EMIT_DEADLINE`], answering whether it got out.
///
/// `false` means the write did not complete in time, and the caller's only correct response is to
/// stop relaying: an abandoned emit may have left a partial message on the connection, so a second
/// one would append to a fragment and hand the cage bytes it cannot frame. Ending the loop instead
/// closes the connection, which is both the honest thing to do with a peer that is no longer
/// reading and what releases the teardown waiting on this thread.
async fn emit_bounded<B>(conn: &zbus::Connection, member: &str, body: &B) -> bool
where
    B: serde::Serialize + zbus::zvariant::DynamicType,
{
    emit_bounded_within(conn, member, body, EMIT_DEADLINE).await
}

/// [`emit_bounded`] with the bound as an argument, so a test can drive the giving-up branch against
/// a real connection without waiting the real window out.
async fn emit_bounded_within<B>(
    conn: &zbus::Connection,
    member: &str,
    body: &B,
    deadline: Duration,
) -> bool
where
    B: serde::Serialize + zbus::zvariant::DynamicType,
{
    let write = async {
        conn.emit_signal(None::<&str>, OBJECT, IFACE, member, body)
            .await
            .is_ok()
    };
    completes_within(write, deadline).await
}

/// Whether `write` finished inside `deadline`, `false` if it did not.
///
/// Split from [`emit_bounded_within`] so the giving-up branch is reachable from a test: driving it
/// through a real connection would mean a peer that accepts bytes and never reads them, which needs
/// zbus's `p2p` feature (and the `uuid` dependency behind it) that this crate deliberately does not
/// take. What a test can hold to is the rule itself — a write that does not finish in the window is
/// reported as one that did not happen.
async fn completes_within(
    write: impl std::future::Future<Output = bool>,
    deadline: Duration,
) -> bool {
    futures_util::select! {
        wrote = write.fuse() => wrote,
        // `Timer` is both a `Future` and a `Stream`, so the future's `fuse` is named explicitly.
        _ = FutureExt::fuse(async_io::Timer::after(deadline)) => false,
    }
}

/// The relay body: wait for the private-bus socket, connect both buses, own the notifications name on
/// the private bus, serve its calls and pump the host's signals back onto it until shutdown, or
/// until the private bus goes or the cage stops reading its end, which [`emit_bounded`] turns into
/// the same clean return. `host_bus` is the address of the bus the host daemon is on, `None` for
/// the session bus the supervisor was given.
async fn run(
    private_socket: PathBuf,
    host_bus: Option<String>,
    shutdown: async_channel::Receiver<()>,
    needles: crate::sandbox::notify_sink::Needles,
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

    // The private bus's socket sits in a directory bound into the cage read-write, so the name is the
    // cage's to replace. It is dialed first, through the inode it resolves to: a link, or anything
    // but a socket, left at the name is refused there rather than followed to whatever it names on
    // the host (see `forward::dial_cage_socket`, which the forward's own sockets are dialed through).
    let private_stream = super::forward::dial_cage_socket(&private_socket)?;

    // The host bus (the ambient $DBUS_SESSION_BUS_ADDRESS unless told otherwise) and a proxy onto
    // its notifications daemon, every call to which gives up after `HOST_CALL_DEADLINE`.
    let host_conn = match host_bus.as_deref() {
        Some(address) => connection::Builder::address(address)?,
        None => connection::Builder::session()?,
    }
    .method_timeout(HOST_CALL_DEADLINE)
    .build()
    .await?;
    let host = HostNotificationsProxy::new(&host_conn).await?;
    let target = relay_target(
        host.get_server_information().await.is_ok(),
        super::notify_sink::desktop_without_daemon,
    );

    // Private bus. Its calls are read off a stream of the relay's own, `CALLS_QUEUED` deep, rather
    // than served by zbus's object server, whose queue is 64 calls deep and which decodes a call
    // before any method sees it. The stream listens with the rule that server uses, and is in place
    // before the name is requested, so no call addressed to the name arrives with nothing to take it.
    let private_conn = connection::Builder::async_io_unix_stream(private_stream)
        .build()
        .await?;
    let unique = private_conn
        .unique_name()
        .ok_or("the private bus assigned the relay no unique name")?;
    let to_relay = MatchRule::builder()
        .msg_type(Type::MethodCall)
        .destination(unique.as_str())?
        .build();
    let calls = MessageStream::for_match_rule(to_relay, &private_conn, Some(CALLS_QUEUED)).await?;
    private_conn.request_name(IFACE).await?;
    let ours = Arc::new(OwnedIds::default());
    let destination: Box<dyn HostBus> = match target {
        RelayTarget::Daemon => Box::new(host.clone()),
        RelayTarget::Mac => Box::new(MacQueue::new(PathBuf::from(super::lima_mac::NOTIFY_MOUNT))),
    };
    let served = Served {
        host: destination,
        ours: Arc::clone(&ours),
        needles,
    };
    // A future of its own, polled beside the signal pump and raced with the shutdown, never awaited
    // inside a branch: a call waiting on the host daemon holds neither the host's signals nor the
    // teardown.
    let serving = serve_calls(&private_conn, &served, calls).fuse();
    futures_util::pin_mut!(serving);

    // The daemon's signals, each reduced to its arguments. The Mac sends none back, so there the
    // two streams never yield and the loop waits on the calls and the shutdown alone.
    let (mut actions, mut closed): (ActionSignals, ClosedSignals) = match target {
        RelayTarget::Daemon => (
            host.receive_action_invoked()
                .await?
                .map(|sig| sig.args().ok().map(|a| (a.id, a.action_key.to_string())))
                .boxed(),
            host.receive_notification_closed()
                .await?
                .map(|sig| sig.args().ok().map(|a| (a.id, a.reason)))
                .boxed(),
        ),
        RelayTarget::Mac => (
            futures_util::stream::pending().boxed(),
            futures_util::stream::pending().boxed(),
        ),
    };
    loop {
        futures_util::select! {
            _ = shutdown.recv().fuse() => break,
            // The call loop ends once the private bus has gone, or a reply could not be written to it.
            () = serving => break,
            sig = actions.next().fuse() => match sig {
                Some(sig) => if let Some((id, key)) = sig {
                    // Verbatim id → the app matches the signal to its own notification.
                    // The host daemon's signals are desktop-wide: they fire for every application on
                    // the user's session, not for this cage. `emit_signal(None, …)` is a broadcast
                    // and the private bus lets any process receive it, so a foreign signal relayed
                    // in is a live host→cage channel — which buttons a human is clicking elsewhere,
                    // and an id counter whose deltas count the desktop's notification volume. The
                    // set that decides `replaces_id` decides this too, at no functional cost: the
                    // cage's own click-to-focus and action buttons are precisely the owned ids.
                    if ours.owns(id)
                        && !emit_bounded(&private_conn, "ActionInvoked", &(id, key.as_str())).await
                    {
                        break;
                    }
                },
                None => break,
            },
            sig = closed.next().fuse() => match sig {
                Some(sig) => if let Some((id, reason)) = sig {
                    // Whoever raised it, this id now names nothing, so it leaves the set either way;
                    // only the cage's own closures cross back. A desktop-wide close signal tells a
                    // watching agent whether a human dismissed a toast (reason 2) or it expired
                    // unread (reason 1) — a presence-and-attention oracle, and one that answers for
                    // sbx's *own* refusal toasts, so the cage could tell whether its blocked request
                    // was seen before deciding what to try next.
                    if ours.closing(id)
                        && !emit_bounded(&private_conn, "NotificationClosed", &(id, reason)).await
                    {
                        break;
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

    /// The private bus's socket is in a directory the cage writes, so a link left at its name must
    /// not carry the relay to the socket the link names. The refusal comes before the host's own
    /// session bus is asked for, so it holds on a host that has none.
    ///
    /// Bounded: a relay that followed the link would wait on a handshake the socket it reached
    /// never gives, and the test has to fail rather than wait with it.
    #[test]
    fn a_link_at_the_private_bus_name_is_refused_rather_than_followed() {
        let dir = crate::testutil::TmpDir::new();
        let target = dir.join("target.sock");
        let listener = std::os::unix::net::UnixListener::bind(&target).unwrap();
        listener.set_nonblocking(true).unwrap();
        let bus = dir.join("bus");
        std::os::unix::fs::symlink(&target, &bus).unwrap();
        let (_keep, shutdown) = async_channel::bounded::<()>(1);

        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let outcome = async_io::block_on(run(bus, None, shutdown, Default::default()));
            let _ = tx.send(outcome.map_err(|e| e.to_string()));
        });
        let err = rx
            .recv_timeout(std::time::Duration::from_secs(10))
            .expect("the relay followed the link and waited on the socket it names")
            .expect_err("a link at the bus name must not be dialed");

        assert!(err.contains("not a socket"), "{err}");
        assert!(
            matches!(listener.accept(), Err(e) if e.kind() == std::io::ErrorKind::WouldBlock),
            "nothing may reach the socket the link named"
        );
    }

    /// A write no one is reading is reported as one that did not happen.
    ///
    /// The cage owns the far end of the private bus. If it stops reading and the transport fills,
    /// the emit parks — and it parks *inside* a select branch, so the shutdown branch is never
    /// reached and `Drop`'s join waits on a thread that will not return. The bound is what turns
    /// that into a `false` the loop can act on; a write that answers in time is untouched, so a
    /// busy-but-live cage is never cut.
    #[test]
    fn a_write_that_never_finishes_is_given_up_on_rather_than_parking() {
        async_io::block_on(async {
            let bound = Duration::from_millis(50);

            let started = std::time::Instant::now();
            assert!(
                !completes_within(std::future::pending::<bool>(), bound).await,
                "a write that never finishes must be given up on"
            );
            assert!(
                started.elapsed() >= bound,
                "it must wait the window out rather than answering straight away"
            );

            // The ordinary case is untouched, and a failed write stays a failed write: only the
            // parked one is turned into `false` by the clock.
            assert!(completes_within(std::future::ready(true), Duration::from_secs(30)).await);
            assert!(!completes_within(std::future::ready(false), Duration::from_secs(30)).await);
        });
    }

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

    /// The relay in front of the Mac's notification directory at `dir`.
    fn served_by_mac(dir: &std::path::Path) -> Served {
        Served {
            host: Box::new(MacQueue::new(dir.to_path_buf())),
            ours: Arc::new(OwnedIds::default()),
            needles: Arc::new(std::sync::RwLock::new(Vec::new())),
        }
    }

    /// Every note the relay queued under `dir`, as text.
    fn queued_notes(dir: &std::path::Path) -> Vec<String> {
        let mut notes: Vec<String> = std::fs::read_dir(dir.join("queue"))
            .map(|entries| {
                entries
                    .map(|e| std::fs::read_to_string(e.unwrap().path()).unwrap())
                    .collect()
            })
            .unwrap_or_default();
        notes.sort();
        notes
    }

    /// A host whose daemon answers keeps it, whatever else it mounts; the Mac's directory is taken
    /// only when no daemon answered on a Mac guest, and the fallback is not even asked otherwise.
    #[test]
    fn the_mac_directory_is_taken_only_where_no_daemon_answered() {
        use crate::sandbox::notify_sink::DaemonlessDesktop;
        let unasked = || -> DaemonlessDesktop { panic!("asked although a daemon answered") };
        assert_eq!(relay_target(true, unasked), RelayTarget::Daemon);
        assert_eq!(
            relay_target(false, || DaemonlessDesktop::Mac),
            RelayTarget::Mac
        );
        assert_eq!(
            relay_target(false, || DaemonlessDesktop::Windows),
            RelayTarget::Daemon
        );
        assert_eq!(
            relay_target(false, || DaemonlessDesktop::None),
            RelayTarget::Daemon
        );
    }

    /// On the Mac every note shows under sbx's icon with no line of its own for the sender, so the
    /// title is the one place a caged app's note can be told from sbx's refusal. A cage that writes
    /// a refusal's words, and names itself sbx, still gets a title that opens with the relay's mark
    /// and never the refusal's own title.
    #[test]
    fn a_caged_app_cannot_title_its_mac_note_as_sbxs_refusal() {
        let dir = crate::testutil::TmpDir::new();
        let served = served_by_mac(dir.path());
        let refusal = "Blocked: evil.com:443";
        async_io::block_on(served.notify(
            "sbx".to_string(),
            0,
            String::new(),
            refusal.to_string(),
            "allow it: sbx net allow evil.com".to_string(),
            Vec::new(),
            HashMap::new(),
            -1,
        ))
        .expect("the queue takes the note");

        let notes = queued_notes(dir.path());
        assert_eq!(notes.len(), 1, "{notes:?}");
        let title = notes[0].lines().next().unwrap();
        assert!(title.starts_with(RELAYED_BY), "{title:?}");
        assert_ne!(title, refusal);
        assert_eq!(
            notes[0].lines().nth(1),
            Some(refusal),
            "the cage's summary is the subtitle"
        );
    }

    /// The Mac queue answers like a daemon the relay can hold to its rules: ids that are never `0`
    /// and never repeat, so a cage's replacement and close are still ruled on, and no action
    /// offered, since no click comes back from the Mac.
    #[test]
    fn the_mac_queue_hands_out_ids_the_relay_can_rule_on() {
        let dir = crate::testutil::TmpDir::new();
        let served = served_by_mac(dir.path());
        let first = notify(&served, 0);
        let second = notify(&served, first);
        assert!(first != 0 && second != 0 && first != second);
        assert!(served.ours.owns(first) && served.ours.owns(second));
        assert_eq!(
            queued_notes(dir.path()).len(),
            2,
            "a replacement is a new note"
        );

        let caps = async_io::block_on(served.get_capabilities()).unwrap();
        assert!(!caps.iter().any(|c| c == "actions"), "{caps:?}");
        async_io::block_on(served.close_notification(first)).unwrap();
    }

    /// The interface the private bus serves, in front of a recording host.
    fn served(host: &FakeHost) -> Served {
        Served {
            host: Box::new(host.clone()),
            ours: Arc::new(OwnedIds::default()),
            needles: Arc::new(std::sync::RwLock::new(Vec::new())),
        }
    }

    /// A relay whose launch has resolved one credential, so a test can watch what leaves for the
    /// host daemon.
    fn served_with_needle(host: &FakeHost, name: &str, value: &str) -> Served {
        Served {
            host: Box::new(host.clone()),
            ours: Arc::new(OwnedIds::default()),
            needles: Arc::new(std::sync::RwLock::new(vec![
                crate::sandbox::proxy::SecretNeedle::named(name, value.as_bytes().to_vec()),
            ])),
        }
    }

    /// The relay carries text the *cage* wrote to a daemon that journals it, and journald keeps it
    /// on the host after the cage is gone. sbx's own announcements have been redacted before
    /// reaching a daemon from the start, in the words of `notify_sink`'s module header; the app's
    /// own notifications travel the same road to the same daemon and were the half that was not.
    #[test]
    fn a_credential_in_a_caged_apps_notification_does_not_reach_the_host_daemon() {
        let host = FakeHost::default();
        let with_secret = served_with_needle(&host, "gh_token", "ghp-abcdefghij");
        async_io::block_on(with_secret.notify(
            "caged-app".to_string(),
            0,
            String::new(),
            "token ghp-abcdefghij".to_string(),
            "and again ghp-abcdefghij here".to_string(),
            vec!["open ghp-abcdefghij".to_string()],
            HashMap::new(),
            -1,
        ))
        .expect("the recording host accepts the call");

        let calls = locked(&host.calls);
        let call = calls.first().expect("one forwarded call");
        assert_eq!(call.summary, "token ${gh_token}");
        assert_eq!(call.body, "and again ${gh_token} here");
        assert_eq!(call.actions, vec!["open ${gh_token}".to_string()]);
        drop(calls);

        // Witness: a launch that resolved no credential forwards the app's text untouched, so the
        // redaction is not a filter on ordinary messages.
        let host = FakeHost::default();
        let plain = served(&host);
        notify(&plain, 0);
        let calls = locked(&host.calls);
        let call = calls.first().expect("one forwarded call");
        assert_eq!(
            (call.summary.as_str(), call.body.as_str()),
            ("summary", "body")
        );
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

    /// The cage writes the words of a toast; it does not decide how many reach the host daemon.
    ///
    /// The strings are relayed into a host process that renders them, so an unbounded body costs
    /// host memory outside the cage's cgroup, and a summary long enough pushes every other
    /// notification's text out of the area the user reads. Spoofing a toast is the accepted
    /// residual; displacing the desktop's is not the same thing.
    #[test]
    fn a_relayed_notification_is_cut_to_its_ceilings() {
        let host = FakeHost::default();
        let served = served(&host);
        let long = |n: usize| "x".repeat(n);
        async_io::block_on(
            served.notify(
                "caged-app".to_string(),
                0,
                String::new(),
                long(SUMMARY_MAX * 10),
                long(BODY_MAX * 10),
                (0..ACTIONS_MAX * 4)
                    .map(|_| long(SUMMARY_MAX * 2))
                    .collect(),
                HashMap::new(),
                -1,
            ),
        )
        .expect("the recording host accepts every call forwarded to it");

        let calls = locked(&host.calls);
        let call = calls.first().expect("one call reached the host");
        assert_eq!(call.summary.chars().count(), SUMMARY_MAX);
        assert_eq!(call.body.chars().count(), BODY_MAX);
        assert_eq!(call.actions.len(), ACTIONS_MAX);
        assert!(
            call.actions
                .iter()
                .all(|a| a.chars().count() == SUMMARY_MAX),
            "an action label is a line of text like a summary, and is cut like one"
        );
    }

    /// A value already inside its ceiling crosses untouched, so the bound cannot be satisfied by
    /// cutting everything, and a multi-byte character is never cut through.
    #[test]
    fn a_value_within_its_ceiling_is_unchanged_and_the_cut_is_on_a_character() {
        assert_eq!(bounded("short".to_string(), 200), "short");
        assert_eq!(bounded("héllo wörld".to_string(), 200), "héllo wörld");
        assert_eq!(bounded("héllo".to_string(), 2), "hé");
        assert_eq!(bounded(String::new(), 0), "");
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

    /// A relayed toast names no host application for the daemon to render it as.
    ///
    /// A daemon handed a `desktop-entry` hint looks the entry up among the host's installed
    /// applications and draws the notification under that application's name and icon, ahead of the
    /// `app_name` and `app_icon` it was called with. Forwarded verbatim it would give the cage back
    /// the line `relayed_app_name` exists to own — the head a forged refusal toast needs — and load a
    /// host file the cage named, the same shape `HOST_PATH_HINTS` closes.
    #[test]
    fn notify_forwards_no_desktop_entry_for_the_daemon_to_resolve() {
        let host = FakeHost::default();
        let served = served(&host);

        let mut hints = HashMap::new();
        hints.insert("desktop-entry".to_string(), hint("org.gnome.Settings"));
        hints.insert("desktop_entry".to_string(), hint("org.gnome.Settings"));
        hints.insert(
            "x-gnome-desktop-entry".to_string(),
            hint("org.gnome.Settings"),
        );
        hints.insert("x-kde-desktop-entry".to_string(), hint("systemsettings"));
        hints.insert("category".to_string(), hint("device.error"));
        notify_as(&served, "", 0, "", hints);

        let calls = locked(&host.calls);
        let mut forwarded: Vec<&str> = calls[0].hints.keys().map(String::as_str).collect();
        forwarded.sort_unstable();
        assert_eq!(
            forwarded,
            vec!["category"],
            "every hint naming the application the daemon renders the toast as must be dropped, and \
             nothing else"
        );
        assert!(
            calls[0].app_name.starts_with(RELAYED_BY),
            "the application name the daemon shows stays the supervisor's to write"
        );
    }

    /// A caged app cannot ask the desktop for more insistence than sbx asks for itself.
    ///
    /// Two fields say "keep this on screen until a person clicks it": `urgency = critical` and
    /// `expire_timeout = 0`. `notify_sink` sends neither for sbx's own announcements, and writes
    /// the reason — a toast that has to be dismissed by hand, repeated, is what makes a person
    /// turn notifications off. Everything else in a relayed call is already bounded; these two
    /// crossed verbatim, so a cage could pin a toast on the host's screen and repeat it.
    #[test]
    fn a_relayed_notification_cannot_outrank_sbxs_own() {
        let host = FakeHost::default();
        let served = served(&host);

        let urgency = |level: u8| -> HashMap<String, OwnedValue> {
            let mut h = HashMap::new();
            h.insert(
                "urgency".to_string(),
                zbus::zvariant::Value::from(level)
                    .try_into()
                    .expect("a byte is a hint value"),
            );
            h
        };
        // Critical is dropped; normal crosses untouched, so the cap is a ceiling and not a purge.
        notify_as(&served, "Slack", 0, "", urgency(2));
        notify_as(&served, "Slack", 0, "", urgency(1));
        // A value of another type is not an urgency the daemon reads, and is left alone.
        let mut typed = HashMap::new();
        typed.insert("urgency".to_string(), hint("critical"));
        notify_as(&served, "Slack", 0, "", typed);

        let calls = locked(&host.calls);
        assert!(
            !calls[0].hints.contains_key("urgency"),
            "a critical urgency must not reach the host daemon: {:?}",
            calls[0].hints
        );
        assert!(
            calls[1].hints.contains_key("urgency"),
            "a normal urgency is an ordinary notification and still crosses"
        );
        assert!(
            calls[2].hints.contains_key("urgency"),
            "a hint of another type is not the urgency the cap is about"
        );
        drop(calls);

        // `0` is the specification's "never expires", and becomes the daemon's own default.
        assert_eq!(relayed_expire_timeout(0), -1);
        assert_eq!(relayed_expire_timeout(-1), -1);
        assert_eq!(
            relayed_expire_timeout(5000),
            5000,
            "a finite lifetime the app chose is the ordinary case, and goes through"
        );
    }

    /// The identity fields are bounded like every other field the cage chooses.
    ///
    /// The daemon gives the sending application a line of its own and shows it whole, and the
    /// summary, the body and each action label already had a ceiling. A name a cage sends is as
    /// much its own text as a summary is. The witnesses are the shapes a real notification carries,
    /// which must pass through unchanged.
    #[test]
    fn a_cage_chosen_app_name_and_icon_are_bounded_like_the_rest() {
        let long = "n".repeat(APP_IDENTITY_MAX * 4);
        let relayed = bounded(relayed_app_name(&long), APP_IDENTITY_MAX);
        assert_eq!(relayed.chars().count(), APP_IDENTITY_MAX);
        assert!(
            relayed.starts_with(RELAYED_BY),
            "and the supervisor's own prefix survives the cut: {relayed}"
        );

        let icon = bounded(
            relayed_app_icon(&"i".repeat(APP_IDENTITY_MAX * 4)).to_string(),
            APP_IDENTITY_MAX,
        );
        assert_eq!(icon.chars().count(), APP_IDENTITY_MAX);

        for (name, icon) in [("Claude", "dialog-information"), ("", "")] {
            assert_eq!(
                bounded(relayed_app_name(name), APP_IDENTITY_MAX),
                relayed_app_name(name),
                "an ordinary app name is untouched"
            );
            assert_eq!(
                bounded(relayed_app_icon(icon).to_string(), APP_IDENTITY_MAX),
                relayed_app_icon(icon),
                "and so is a theme name"
            );
        }
    }

    /// The arguments of a `Notify` as a caged app sends one, with one byte-array hint of
    /// `hint_bytes` bytes, the shape an `image-data` icon has.
    type NotifyCallArgs = (
        &'static str,
        u32,
        &'static str,
        &'static str,
        &'static str,
        Vec<&'static str>,
        HashMap<&'static str, zbus::zvariant::Value<'static>>,
        i32,
    );

    fn notify_args(hint_bytes: usize) -> NotifyCallArgs {
        let mut hints = HashMap::new();
        hints.insert("x-blob", zbus::zvariant::Value::from(vec![0u8; hint_bytes]));
        ("caged-app", 0, "", "summary", "body", Vec::new(), hints, -1)
    }

    /// A `Notify` from `app`, answered.
    async fn call_notify(app: &zbus::Connection, hint_bytes: usize) -> zbus::Result<Message> {
        let args = notify_args(hint_bytes);
        app.call_method(Some(IFACE), OBJECT, Some(IFACE), "Notify", &args)
            .await
    }

    fn notify_message(hint_bytes: usize) -> Message {
        Message::method_call(OBJECT, "Notify")
            .and_then(|m| m.destination(IFACE))
            .and_then(|m| m.interface(IFACE))
            .and_then(|m| m.build(&notify_args(hint_bytes)))
            .expect("a well-formed call")
    }

    /// A call is weighed whole: one whose single hint already carries the ceiling is refused, and
    /// one well inside it is not. The weighing happens on the bytes the bus delivered, so no hint
    /// name and no number of hints moves a call under it.
    #[test]
    fn a_call_is_weighed_whole_before_any_of_it_is_decoded() {
        assert!(matches!(
            within_call_ceiling(&notify_message(CALL_MESSAGE_MAX)),
            Err(fdo::Error::LimitsExceeded(_))
        ));
        assert!(within_call_ceiling(&notify_message(CALL_MESSAGE_MAX - 4096)).is_ok());
    }

    /// The tree a client walks from `/` leads to the notifications object, the object advertises
    /// what it answers and not the method it refuses, and no other path is answered.
    #[test]
    fn introspection_leads_from_the_root_to_the_object_and_nowhere_else() {
        for (path, child) in [
            ("/", "org"),
            ("/org", "freedesktop"),
            ("/org/freedesktop", "Notifications"),
        ] {
            let doc = introspection(path).expect("a parent of the object");
            assert!(
                doc.contains(&format!("<node name=\"{child}\"/>")),
                "{path}: {doc}"
            );
        }
        let object = introspection(OBJECT).expect("the object itself");
        assert!(object.contains("<method name=\"Notify\">"), "{object}");
        assert!(
            !object.contains("GetMachineId"),
            "a refused method is not advertised: {object}"
        );
        for path in ["/or", "/nowhere", "/org/freedesktop/Notifications/x"] {
            assert_eq!(introspection(path), None, "{path}");
        }
    }

    /// A `dbus-daemon` of the test's own, killed when the test ends however it ends.
    struct TestBus(std::process::Child);

    impl Drop for TestBus {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    /// A bus of the test's own listening at `sock`, up by the time it is returned; `None` when this
    /// machine has no `dbus-daemon`.
    ///
    /// Both sides of a relay run on one, the cage's private bus and the bus standing in for the
    /// host's, and both are configured by the document the portal writes: a configuration the
    /// daemon refuses fails here before it fails a launch, and the test reads no configuration of
    /// the machine's own, which a `dbus-daemon` from the nix store would look for under `/etc`.
    fn test_bus(sock: &std::path::Path) -> Option<TestBus> {
        let dir = sock.parent().expect("a socket inside the test's directory");
        let conf = sock.with_extension("conf");
        let path = sock.to_str().expect("a UTF-8 test path");
        std::fs::write(&conf, super::super::portal::session_conf(path, dir, dir))
            .expect("the configuration is written");
        let bus = TestBus(
            std::process::Command::new("dbus-daemon")
                .arg(format!("--config-file={}", conf.display()))
                .arg("--nofork")
                .stdout(std::process::Stdio::null())
                .spawn()
                .ok()?,
        );
        let started = Instant::now();
        while !sock.exists() {
            assert!(
                started.elapsed() < SOCKET_WAIT,
                "the bus at {} never came up",
                sock.display()
            );
            std::thread::sleep(POLL_INTERVAL);
        }
        Some(bus)
    }

    /// The address of the bus listening at `sock`.
    fn address_of(sock: &std::path::Path) -> String {
        format!("unix:path={}", sock.display())
    }

    /// A host notifications daemon on the bus at `address` that counts every `Notify` as it
    /// arrives, and answers it with an id or, `stalled`, never at all.
    struct FakeDaemon {
        seen: Arc<std::sync::atomic::AtomicUsize>,
        stalled: bool,
    }

    #[zbus::interface(name = "org.freedesktop.Notifications")]
    impl FakeDaemon {
        #[allow(clippy::too_many_arguments)]
        async fn notify(
            &self,
            _app_name: String,
            _replaces_id: u32,
            _app_icon: String,
            _summary: String,
            _body: String,
            _actions: Vec<String>,
            _hints: HashMap<String, OwnedValue>,
            _expire_timeout: i32,
        ) -> u32 {
            self.seen.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            if self.stalled {
                std::future::pending::<()>().await;
            }
            FIRST_ID
        }
    }

    fn fake_daemon(
        address: &str,
        seen: &Arc<std::sync::atomic::AtomicUsize>,
        stalled: bool,
    ) -> zbus::Connection {
        let daemon = FakeDaemon {
            seen: Arc::clone(seen),
            stalled,
        };
        async_io::block_on(
            connection::Builder::address(address)
                .and_then(|b| b.name(IFACE))
                .and_then(|b| b.serve_at(OBJECT, daemon))
                .expect("a well-formed daemon")
                .build(),
        )
        .expect("the fake daemon owns the name")
    }

    /// A caged app's connection to the private bus at `sock`, once the relay owns the
    /// notifications name there.
    async fn cage_app(sock: &std::path::Path) -> zbus::Connection {
        let started = Instant::now();
        let app = connection::Builder::address(address_of(sock).as_str())
            .expect("a well-formed address")
            .build()
            .await
            .expect("the private bus accepts the app");
        let bus = fdo::DBusProxy::new(&app).await.expect("the bus answers");
        let name = zbus::names::BusName::try_from(IFACE).expect("a bus name");
        while !bus.name_has_owner(name.clone()).await.unwrap_or(false) {
            assert!(
                started.elapsed() < SOCKET_WAIT,
                "the relay never took the notifications name"
            );
            async_io::Timer::after(POLL_INTERVAL).await;
        }
        app
    }

    /// The relay serves a cage's calls one at a time, and its teardown does not wait on the one in
    /// flight.
    ///
    /// zbus's own object server took every call the cage sent, up to 64 queued and as many in
    /// flight as the cage cared to send, each decoded and held in the supervisor while the host
    /// daemon took its time; a cage could hold gigabytes of the host's memory that way. Here the
    /// host daemon never answers, so what the relay does with the calls behind the first is the
    /// whole of what is measured: it must not forward a second one while the first waits. Driven
    /// end to end, through the relay's own startup and the private bus's real configuration.
    ///
    /// The same run checks that the relay does not hand the cage the host's machine id, which the
    /// object server's `Peer` interface read from the host's `/etc/machine-id` and answered with.
    #[test]
    fn the_relay_serves_one_call_at_a_time_and_its_teardown_does_not_wait_on_it() {
        let dir = crate::testutil::TmpDir::new();
        let (host, sock) = (dir.join("host"), dir.join("bus"));
        let (Some(_host_bus), Some(_private_bus)) = (test_bus(&host), test_bus(&sock)) else {
            skip_incapable!("skipping: no dbus-daemon on PATH");
            return;
        };
        let host_address = address_of(&host);
        let seen = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let _daemon = fake_daemon(&host_address, &seen, true);
        let relay = NotifyRelay::start_on(sock.clone(), Some(host_address), Default::default());

        async_io::block_on(async {
            let app = cage_app(&sock).await;
            let asked = app
                .call_method(Some(IFACE), OBJECT, Some(PEER), "GetMachineId", &())
                .await
                .expect_err("the relay must not answer with the machine id of the host it runs on");
            assert!(
                asked
                    .to_string()
                    .starts_with("org.freedesktop.DBus.Error.UnknownMethod"),
                "{asked}"
            );

            for _ in 0..8 {
                app.send(&notify_message(64))
                    .await
                    .expect("the call is sent");
            }
            let started = Instant::now();
            while seen.load(std::sync::atomic::Ordering::SeqCst) == 0 {
                assert!(
                    started.elapsed() < SOCKET_WAIT,
                    "no call ever reached the host daemon"
                );
                async_io::Timer::after(POLL_INTERVAL).await;
            }
            async_io::Timer::after(Duration::from_millis(500)).await;
        });
        assert_eq!(
            seen.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "a call waiting on the host daemon must hold the ones behind it in the queue, not in \
             flight beside it"
        );

        // Dropped on a thread of its own and waited for under a bound, so a teardown that waits on
        // the call fails the test rather than hanging it.
        let (torn_down, done) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            drop(relay);
            let _ = torn_down.send(());
        });
        done.recv_timeout(HOST_CALL_DEADLINE / 2)
            .expect("the teardown waited on a call the host daemon never answered");
    }

    /// A call over the relay's ceiling is answered `LimitsExceeded` and forwarded nowhere, while an
    /// ordinary one beside it is answered with the host's id. One past the private bus's own
    /// ceiling never reaches the relay at all: the in-cage daemon drops the app that sent it.
    #[test]
    fn a_call_over_the_ceiling_is_refused_whole_and_forwarded_nowhere() {
        let dir = crate::testutil::TmpDir::new();
        let (host, sock) = (dir.join("host"), dir.join("bus"));
        let (Some(_host_bus), Some(_private_bus)) = (test_bus(&host), test_bus(&sock)) else {
            skip_incapable!("skipping: no dbus-daemon on PATH");
            return;
        };
        let host_address = address_of(&host);
        let seen = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let _daemon = fake_daemon(&host_address, &seen, false);
        let _relay = NotifyRelay::start_on(sock.clone(), Some(host_address), Default::default());

        async_io::block_on(async {
            let app = cage_app(&sock).await;

            let id: u32 = call_notify(&app, 64)
                .await
                .expect("an ordinary call is forwarded")
                .body()
                .deserialize()
                .expect("an id");
            assert_eq!(id, FIRST_ID);

            let refused = call_notify(&app, CALL_MESSAGE_MAX)
                .await
                .expect_err("a call over the ceiling must be refused");
            assert!(
                refused
                    .to_string()
                    .starts_with("org.freedesktop.DBus.Error.LimitsExceeded"),
                "{refused}"
            );
            assert_eq!(seen.load(std::sync::atomic::Ordering::SeqCst), 1);

            let dropped = call_notify(&app, super::super::portal::BUS_MESSAGE_MAX)
                .await
                .expect_err("a message over the bus's own ceiling must not be delivered");
            // Dropped by the daemon, which closes the app's connection, rather than refused by the
            // relay with a reply: the relay never saw it.
            assert!(
                matches!(dropped, zbus::Error::InputOutput(_)),
                "{dropped:?}"
            );
            assert_eq!(seen.load(std::sync::atomic::Ordering::SeqCst), 1);
        });
    }
}
