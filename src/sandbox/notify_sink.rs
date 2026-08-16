//! Where a refusal notification actually goes: the host desktop, or stderr.
//!
//! The policy half lives in [`crate::notify`] and is pure. This is the I/O half — the piece that
//! carries an announcement out of the process — and it is built around three constraints.
//!
//! **It never runs on the thread that refused.** An egress verdict is rendered inside a proxy
//! connection's own thread, an exec verdict inside the seccomp supervisor's receive loop; both are on
//! the critical path of a syscall or a request the cage is blocked on. So [`Notifier::block`] only
//! hands the block to a bounded channel and returns: the refusal reaches the cage at once, and the
//! announcement is composed, redacted and delivered on a dedicated thread. A notification daemon that
//! hangs therefore cannot stall enforcement — the sink's worst case is a queue that fills.
//!
//! **It is host-side, and adds nothing to the cage.** The supervisor is bwrap's parent: it holds the
//! session bus address the cage never sees (`dbus = true` is a different mechanism entirely — a
//! *private* in-cage bus). The side that decided the refusal is the side that announces it, so an
//! agent can neither forge an "sbx blocked …" notification nor dismiss one that names it.
//!
//! **Everything it emits is redacted.** A block carries agent-chosen text — the host it asked for, the
//! path it ran — which can carry an injected credential, and a desktop daemon may journal a
//! notification body. So both the summary and the body pass through [`crate::sandbox::redact`] before
//! they leave the process, exactly like every other text sink.
//!
//! Best-effort throughout, in the shape the other host-side relays use: no session bus (ssh, cron,
//! a headless host) falls back to stderr with one warning, never a repeated one, and never a failure
//! — a launch must not break because a notification could not be delivered.

use futures_util::FutureExt;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{RecvTimeoutError, SyncSender, TrySendError, sync_channel};
use std::sync::{Arc, RwLock};
use std::thread::JoinHandle;
use std::time::Duration;

use crate::notify::{Block, Coalescer, NotifyPolicy, Speak};
use crate::sandbox::proxy::SecretNeedle;
use crate::sandbox::redact::{Placeholder, redact_string};

/// How many pending announcements the queue holds before it starts dropping.
///
/// Bounded because the producer is an untrusted agent's behaviour: a loop retrying a blocked host
/// can generate refusals far faster than a desktop daemon renders them, and an unbounded queue would
/// turn that into unbounded memory in the supervisor. What is lost when it fills is a *repeat* — the
/// first of each distinct problem is long delivered by then — and the count is reported at teardown
/// rather than silently swallowed.
const QUEUE_CAP: usize = 256;

/// The application name every sbx notification carries, alone when there is no session to name.
const APP_NAME: &str = "sbx";

/// The application name a notification is sent under: `sbx`, or `sbx · kiro@ops-cli[4242]` once
/// there is a session to name.
///
/// The session rides here rather than in the summary because a desktop gives the sending
/// application a line of its own and shows it whole, while it truncates the summary. With two or
/// three sandboxes running at once, "which one was that?" is the first question a toast has to
/// answer, and answering it in the summary meant the answer was the first thing cut.
fn app_name(context: &str) -> String {
    if context.is_empty() {
        APP_NAME.to_string()
    } else {
        format!("{APP_NAME} · {context}")
    }
}

/// The icon asked for when the mark cannot be put on disk — a freedesktop name resolved from the
/// user's theme, which is what this sink sent before it carried a mark of its own. A refusal still
/// reads as a warning, which is the part that matters.
const FALLBACK_ICON: &str = "dialog-warning";

/// The mark itself, in the two fills it is drawn in: the canonical one, and the lighter twin meant
/// for a dark desktop. Raster rather than the SVG they are drawn from, because several daemons
/// decode icons through gdk-pixbuf, which will not touch an SVG unless librsvg is installed — and
/// an icon that fails to decode is worse than one that was never sent.
///
/// Carried in the binary because the daemon is a *separate process* that opens the file itself:
/// there is no way to hand it an image held in memory. `assets/render-logo.py` regenerates both by
/// parsing the SVG, so the drawing stays the single source of truth.
static LOGO_LIGHT: &[u8] = include_bytes!("../../assets/sbx.png");
static LOGO_DARK: &[u8] = include_bytes!("../../assets/sbx-dark.png");

/// How long one announcement waits on the desktop portal for the light/dark preference before
/// signing itself in the canonical fill.
///
/// The read is a sub-millisecond round trip on a live connection, so this is not a budget — it is
/// the guard for a portal that has stopped answering, which must cost a bounded pause rather than
/// an announcement that never arrives.
const THEME_READ_TIMEOUT: Duration = Duration::from_millis(250);

/// How often the delivery thread wakes to re-check the stop flag while the queue is empty.
///
/// The channel closing is the normal way the thread ends, but a notifier reached through an `Arc`
/// that some launch path holds a moment longer would keep the sender alive and the join waiting. The
/// flag makes teardown depend on an explicit signal rather than on drop order — the same arrangement
/// the exec supervisor uses — and a quarter-second tick on an idle thread costs nothing measurable.
const STOP_POLL: Duration = Duration::from_millis(250);

/// `urgency = normal`. A refusal is worth seeing but is not an emergency, and `critical` (2) would
/// pin the toast on screen until it is dismissed by hand — which, repeated, is what makes a person
/// turn the whole thing off.
const URGENCY_NORMAL: u8 = 1;

/// The credential set every announcement is redacted against, shared with the launch.
///
/// Shared and interior-mutable because the notifier is stood up **before** the egress proxy resolves
/// the launch's credentials — the exec supervisor needs it earlier — so the set is filled in once,
/// after the fact, rather than making the notifier's construction wait on a resolution it does not
/// otherwise depend on. Read only on the delivery thread.
pub(crate) type Needles = Arc<RwLock<Vec<SecretNeedle>>>;

/// The launch's notification wiring, passed as one value so the notifier and the credential set it
/// redacts against cannot be handed over separately — a notifier attached without its needles would
/// announce unredacted text, which is the failure this whole path is built to avoid.
///
/// Its `Debug` deliberately omits the needle set: those are the credential values themselves, and a
/// derived `Debug` would print them into whatever line a caller formatted.
pub(crate) struct NotifyWiring {
    pub(crate) notifier: Arc<Notifier>,
    pub(crate) needles: Needles,
}

impl std::fmt::Debug for NotifyWiring {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NotifyWiring")
            .field("notifier", &self.notifier)
            .field("needles", &"<redacted>")
            .finish()
    }
}

/// The queue's consumer side: where a block is delivered once the policy has decided to speak.
///
/// A trait so the delivery mechanism is swappable, and so the tests exercise the whole
/// decide-render-redact-deliver path against a recording sink — no notification daemon on the
/// machine running them.
pub(crate) trait Sink: Send {
    /// Deliver one announcement. `replaces` is the id of this problem's previous notification, when
    /// there was one, so a repeat updates that toast in place.
    ///
    /// `Ok(Some(id))` is the id the transport assigned; `Ok(None)` a delivery by a transport that has
    /// no ids to revise (stderr). `Err(())` means the transport is **gone** — not that this one
    /// announcement failed — and the caller replaces the sink rather than going quiet, which is the
    /// difference between "your daemon restarted" and "you stopped being told anything".
    fn deliver(
        &mut self,
        summary: &str,
        body: &str,
        replaces: Option<u32>,
    ) -> Result<Option<u32>, ()>;
}

/// The fallback sink: one stderr line per announcement, in the diagnostic family's shape.
///
/// Used when there is no session bus to reach. It has no ids and no replacement, so an `always` event
/// prints a line per occurrence — on a terminal that is the expected behaviour, and the desktop
/// sink's in-place update has no meaning here.
/// One stderr line for an announcement: `session: summary: body`, dropping whichever part is
/// absent. Pure, so the empty cases are pinned by tests rather than read off a terminal.
///
/// A refusal with nothing to add has an empty body, and a launch that is not a session has no
/// context, so both ends have to disappear cleanly instead of stranding a separator.
fn stderr_line(context: &str, summary: &str, body: &str) -> String {
    match (context, body) {
        ("", "") => summary.to_string(),
        ("", _) => format!("{summary}: {body}"),
        (ctx, "") => format!("{ctx}: {summary}"),
        (ctx, _) => format!("{ctx}: {summary}: {body}"),
    }
}

struct StderrSink {
    /// The session this sink speaks for. A terminal has no application header to carry it, so what
    /// the desktop shows beside the icon is prefixed onto the line here — otherwise falling back to
    /// stderr would quietly lose which sandbox a refusal came from.
    context: String,
}

impl Sink for StderrSink {
    fn deliver(
        &mut self,
        summary: &str,
        body: &str,
        _replaces: Option<u32>,
    ) -> Result<Option<u32>, ()> {
        crate::diag::warn(&stderr_line(&self.context, summary, body));
        // stderr cannot go away, so this sink never asks to be replaced — it is what replacement
        // falls back *to*.
        Ok(None)
    }
}

/// The desktop sink: `org.freedesktop.Notifications.Notify` on the host session bus.
///
/// Holds the connection for the session's lifetime — one connection, one thread, and the async work
/// driven by `async_io::block_on` so nothing async escapes this module (the same arrangement the
/// in-cage relays use; sbx's own world is std threads).
struct DesktopSink {
    proxy: crate::sandbox::notify_relay::HostNotificationsProxy<'static>,
    /// The desktop portal's Settings interface on the same connection, for the light/dark
    /// preference. Bound once and held: binding is not free next to the read it serves, and this is
    /// read on every announcement. `None` when there is no portal — the ordinary case on a plain
    /// window manager — and the mark is then sent in its canonical fill.
    settings: Option<crate::sandbox::theme_relay::HostSettingsProxy<'static>>,
    /// The name this sink announces under, session included. Fixed for the session: which sandbox
    /// is speaking cannot change under a running launch.
    app_name: String,
    /// The bus this sink is bound to, so a reconnect goes back to the **same** bus rather than to
    /// whatever the ambient environment names. `None` is the session bus, which is the production
    /// case; a test binds a private one and must not have its retry escape onto the user's desktop.
    address: Option<String>,
}

/// One notification call over already-bound proxies. Separated from [`DesktopSink::deliver`] so the
/// retry after a reconnect runs exactly the same code as the first attempt.
async fn notify_over(
    proxy: &crate::sandbox::notify_relay::HostNotificationsProxy<'static>,
    settings: Option<&crate::sandbox::theme_relay::HostSettingsProxy<'static>>,
    app_name: &str,
    summary: &str,
    body: &str,
    replaces: Option<u32>,
) -> Result<u32, ()> {
    let icon = icon_for(settings).await;
    let mut hints = std::collections::HashMap::new();
    if let Ok(v) = zbus::zvariant::Value::from(URGENCY_NORMAL).try_into() {
        hints.insert("urgency".to_string(), v);
    }
    if let Ok(v) = zbus::zvariant::Value::from("security").try_into() {
        hints.insert("category".to_string(), v);
    }
    // The same icon under the 1.2 hint as well as the `app_icon` argument, because daemons differ
    // in which of the two they read. Only when it is a real file: a theme name is what `app_icon`
    // is for, and a daemon that failed to resolve it under `image-path` could render nothing at
    // all rather than falling back.
    if icon != FALLBACK_ICON
        && let Ok(v) = zbus::zvariant::Value::from(icon).try_into()
    {
        hints.insert("image-path".to_string(), v);
    }
    proxy
        .notify(
            app_name,
            replaces.unwrap_or(0),
            icon,
            summary,
            body,
            // No action buttons: an action needs a live `ActionInvoked` subscription to mean
            // anything, and a one-click "allow" on a security refusal is a decision that belongs at
            // a prompt, not on a toast.
            Vec::new(),
            hints,
            // Let the daemon apply its own default timeout.
            -1,
        )
        .await
        .map_err(|_| ())
}

/// The icon one announcement is signed with: the mark in the fill the desktop is wearing **now**,
/// or [`FALLBACK_ICON`] when it could not be put on disk.
///
/// The preference is read per announcement rather than resolved once, so a desktop switched from
/// light to dark mid-session is followed rather than remembered. That costs one round trip on a
/// connection this sink already holds — less than the `Notify` call it accompanies — and it happens
/// only when there is something to announce, which the coalescer already makes rare.
async fn icon_for(
    settings: Option<&crate::sandbox::theme_relay::HostSettingsProxy<'static>>,
) -> &'static str {
    mark_for(marks(), prefers_dark(settings).await)
}

/// Which mark to send for a desktop that is (or is not) dark. Pure, so the fallback ladder is
/// pinned by tests without a portal, a bus, or a disk.
///
/// Either fill beats a theme name, so a missing twin falls back to the other one before giving up
/// on the mark entirely: the point of the two files is the *nuance*, and losing the nuance is not a
/// reason to lose the identity.
fn mark_for(marks: &'static Marks, dark: bool) -> &'static str {
    let (first, second) = if dark {
        (&marks.dark, &marks.light)
    } else {
        (&marks.light, &marks.dark)
    };
    first
        .as_deref()
        .or(second.as_deref())
        .unwrap_or(FALLBACK_ICON)
}

/// Whether the desktop says it is dark, bounded by [`THEME_READ_TIMEOUT`]. Anything else — no
/// portal, no answer, an answer that is not `prefer-dark` — is light, which is the canonical fill.
async fn prefers_dark(
    settings: Option<&crate::sandbox::theme_relay::HostSettingsProxy<'static>>,
) -> bool {
    let Some(settings) = settings else {
        return false;
    };
    let scheme = futures_util::select! {
        scheme = crate::sandbox::theme_relay::color_scheme_of(settings).fuse() => scheme,
        _ = futures_util::FutureExt::fuse(async_io::Timer::after(THEME_READ_TIMEOUT)) => None,
    };
    scheme.as_deref() == Some("prefer-dark")
}

/// Where each fill of the mark ended up on disk, `None` for one that could not be written.
#[derive(Debug, Default, PartialEq, Eq)]
struct Marks {
    light: Option<String>,
    dark: Option<String>,
}

/// The marks on disk, written on first use and remembered for the process.
///
/// Both fills are written, not just the one the desktop wants right now: they cost a kilobyte
/// between them, and having both means switching theme mid-session changes which path is sent
/// rather than rewriting a file a daemon may be reading.
fn marks() -> &'static Marks {
    static WRITTEN: std::sync::OnceLock<Marks> = std::sync::OnceLock::new();
    WRITTEN.get_or_init(|| {
        let Some(layout) = crate::store::Layout::from_env() else {
            return Marks::default();
        };
        Marks {
            light: write_mark(&layout.icon_path(false), LOGO_LIGHT),
            dark: write_mark(&layout.icon_path(true), LOGO_DARK),
        }
    })
}

/// Put `bytes` at `path` and answer with the path, or `None` if it could not be placed there.
///
/// Split from [`marks`] so the whole write is testable against a directory of the test's choosing,
/// without an environment variable a parallel test would race on.
///
/// Two properties matter here and neither is decoration. The write is **atomic** — a private name
/// then a rename — because a daemon may be opening the previous copy at that moment, and half a
/// PNG renders as nothing. And it is **skipped when the bytes already match**, which is the
/// ordinary case: the file is only rewritten on the first launch after the mark itself changes.
fn write_mark(path: &std::path::Path, bytes: &[u8]) -> Option<String> {
    let named = path.to_str()?.to_string();
    if std::fs::read(path).is_ok_and(|on_disk| on_disk == bytes) {
        return Some(named);
    }
    std::fs::create_dir_all(path.parent()?).ok()?;
    // The pid makes the temporary name private to this process, so two launches writing the mark at
    // once cannot interleave into one file. Whichever renames last wins, and both wrote the same
    // bytes.
    let tmp = path.with_extension(format!("png.{}", std::process::id()));
    std::fs::write(&tmp, bytes).ok()?;
    if std::fs::rename(&tmp, path).is_err() {
        let _ = std::fs::remove_file(&tmp);
        return None;
    }
    Some(named)
}

impl DesktopSink {
    /// Connect to the session bus and bind the notifications proxy, or `None` when there is no bus to
    /// reach (a headless or `ssh` session, a cron run) or no daemon serving the interface.
    fn connect(context: &str) -> Option<DesktopSink> {
        DesktopSink::connect_to(None, app_name(context))
    }

    /// [`connect`](DesktopSink::connect) against a named bus address rather than the ambient session
    /// one — the seam the reconnect test drives, so that path is exercised against a real bus and a
    /// real daemon going away, without touching the user's desktop.
    fn connect_to(address: Option<&str>, app_name: String) -> Option<DesktopSink> {
        async_io::block_on(async {
            let conn = match address {
                Some(addr) => zbus::connection::Builder::address(addr)
                    .ok()?
                    .build()
                    .await
                    .ok()?,
                None => zbus::Connection::session().await.ok()?,
            };
            let proxy = crate::sandbox::notify_relay::HostNotificationsProxy::new(&conn)
                .await
                .ok()?;
            // Ask the daemon what it is: proof that something actually serves the interface, rather
            // than discovering it at the first refusal — when the fallback would be too late to warn
            // about. The answer itself is not used.
            proxy.get_server_information().await.ok()?;
            // The portal is optional: a desktop without one simply never says it is dark. Bound
            // here so a reconnect rebinds it alongside the notifications proxy, on the same
            // connection, rather than leaving a proxy pointing at a connection that has gone.
            let settings = crate::sandbox::theme_relay::bind_host_settings(&conn).await;
            Some(DesktopSink {
                proxy,
                settings,
                app_name,
                address: address.map(str::to_string),
            })
        })
    }
}

impl Sink for DesktopSink {
    /// Deliver, and on failure **reconnect once** before giving up on the transport.
    ///
    /// The connection is bound once, at launch, and a session outlives a great deal: restart
    /// `gnome-shell` (or any other daemon serving the interface) and every later call on the old
    /// connection fails. Without this, a sandbox would simply stop announcing refusals — silently,
    /// which is the one failure mode this whole path exists to prevent. So a failed call is retried
    /// on a fresh connection, and only a failed *reconnect* reports the transport gone.
    fn deliver(
        &mut self,
        summary: &str,
        body: &str,
        replaces: Option<u32>,
    ) -> Result<Option<u32>, ()> {
        let sent = async_io::block_on(notify_over(
            &self.proxy,
            self.settings.as_ref(),
            &self.app_name,
            summary,
            body,
            replaces,
        ));
        if let Ok(id) = sent {
            return Ok(Some(id));
        }
        let fresh =
            DesktopSink::connect_to(self.address.as_deref(), self.app_name.clone()).ok_or(())?;
        self.proxy = fresh.proxy;
        // The portal proxy rides the connection that just went away, so it is replaced along with
        // the notifications one rather than left pointing at a dead connection.
        self.settings = fresh.settings;
        // The id the old daemon handed out means nothing to a new one, so a retry after a reconnect
        // posts a fresh notification rather than trying to revise one that no longer exists.
        async_io::block_on(notify_over(
            &self.proxy,
            self.settings.as_ref(),
            &self.app_name,
            summary,
            body,
            None,
        ))
        .map(Some)
    }
}

/// The launch-held handle a refusal site announces through.
///
/// Cheap to hold and cheap to call: an event whose mode is `off` is dropped in the caller without
/// touching the queue, and a policy with nothing enabled builds no thread and opens no connection at
/// all.
///
/// Its `Debug` shows the policy and whether delivery is live — never a queued block, which carries
/// the agent-chosen text that has not been redacted yet.
#[derive(Debug)]
pub(crate) struct Notifier {
    policy: NotifyPolicy,
    /// `None` when nothing is enabled — [`Notifier::block`] then returns immediately.
    tx: Option<SyncSender<Block>>,
    /// Announcements dropped because the queue was full, reported once at teardown.
    dropped: Arc<AtomicU64>,
    /// Set at teardown; the delivery thread drains what is queued and then exits.
    stop: Arc<AtomicBool>,
    handle: Option<JoinHandle<()>>,
}

impl Notifier {
    /// A notifier that announces nothing — for the launch paths with no notification policy to
    /// honour, and the natural value in a test that is not exercising this.
    pub(crate) fn disabled() -> Notifier {
        Notifier {
            policy: NotifyPolicy::uniform(crate::notify::NotifyMode::Off),
            tx: None,
            dropped: Arc::new(AtomicU64::new(0)),
            stop: Arc::new(AtomicBool::new(false)),
            handle: None,
        }
    }

    /// Start the delivery thread for `policy`, redacting every announcement against `needles`.
    ///
    /// Returns a disabled notifier when the policy silences everything, so the common
    /// nothing-to-announce case costs one comparison and no resources.
    pub(crate) fn start(
        policy: NotifyPolicy,
        needles: Needles,
        origin: &crate::notify::Origin,
    ) -> Notifier {
        if !policy.any_enabled() {
            return Notifier::disabled();
        }
        Notifier::with_sink(policy, needles, origin.label(), None)
    }

    /// A notifier delivering into `sink` — the seam a test in another module drives to assert what
    /// its refusal path actually announces, without a session bus.
    #[cfg(test)]
    pub(crate) fn recording(policy: NotifyPolicy, sink: Box<dyn Sink>) -> Notifier {
        Notifier::with_sink(
            policy,
            Arc::new(RwLock::new(Vec::new())),
            String::new(),
            Some(sink),
        )
    }

    /// [`start`](Notifier::start) with the sink supplied rather than discovered — the seam the tests
    /// drive, and the one place the desktop/stderr choice is made.
    fn with_sink(
        policy: NotifyPolicy,
        needles: Needles,
        context: String,
        sink: Option<Box<dyn Sink>>,
    ) -> Notifier {
        // The label belongs to the delivery thread alone — it is only ever read while composing a
        // summary, which happens nowhere else.
        let (tx, rx) = sync_channel::<Block>(QUEUE_CAP);
        let dropped = Arc::new(AtomicU64::new(0));
        let stop = Arc::new(AtomicBool::new(false));
        let thread_stop = Arc::clone(&stop);
        let handle = std::thread::spawn(move || {
            // Connecting here, on the delivery thread, keeps the bus handshake off the launch path.
            let mut sink: Box<dyn Sink> = match sink {
                Some(s) => s,
                None => match DesktopSink::connect(&context) {
                    Some(d) => Box::new(d),
                    None => {
                        crate::diag::note(
                            "no desktop notification daemon reachable — reporting blocked \
                             requests on stderr instead",
                        );
                        Box::new(StderrSink {
                            context: context.clone(),
                        })
                    }
                },
            };
            let mut coalescer = Coalescer::default();
            // Ends when the channel closes *or* the stop flag is set and nothing is left queued —
            // whichever comes first. A refusal that fired in a session's last moments is still
            // delivered, but teardown never waits on a sender some other path is still holding.
            loop {
                let block = match rx.recv_timeout(STOP_POLL) {
                    Ok(b) => b,
                    Err(RecvTimeoutError::Timeout) => {
                        if thread_stop.load(Ordering::Relaxed) {
                            break;
                        }
                        continue;
                    }
                    Err(RecvTimeoutError::Disconnected) => break,
                };
                let Speak::Say { replaces } =
                    coalescer.decide(policy, &block, std::time::Instant::now())
                else {
                    continue;
                };
                let (summary, body) = block.render();
                // Read under the lock only here, on the delivery thread — never on the thread that
                // refused. The set is filled once, when the proxy resolves the launch's credentials.
                let (summary, body) = match needles.read() {
                    Ok(n) => (
                        redact_string(&summary, &n, &Placeholder::Plain).0,
                        redact_string(&body, &n, &Placeholder::Plain).0,
                    ),
                    // A poisoned lock means a writer panicked mid-update. The needle set is then of
                    // unknown completeness, so the only safe move is to say nothing rather than emit
                    // text that may carry a credential.
                    Err(_) => continue,
                };
                match sink.deliver(&summary, &body, replaces) {
                    Ok(Some(id)) => coalescer.record_id(&block, id),
                    Ok(None) => {}
                    // The transport is gone and could not be re-established. Fall back to stderr for
                    // the rest of the session rather than going quiet: a person who can no longer be
                    // shown a toast can still be told, and silence here would look exactly like a
                    // sandbox that refused nothing.
                    Err(()) => {
                        crate::diag::warn(
                            "the desktop notification daemon went away — reporting blocked \
                             requests on stderr for the rest of this session",
                        );
                        sink = Box::new(StderrSink {
                            context: context.clone(),
                        });
                        let _ = sink.deliver(&summary, &body, None);
                    }
                }
            }
        });
        Notifier {
            policy,
            tx: Some(tx),
            dropped,
            stop,
            handle: Some(handle),
        }
    }

    /// Announce a refusal — or decide, for free, that this one is not announced.
    ///
    /// Never blocks and never fails: the mode check is a comparison on a `Copy` policy (no lock), and
    /// a full queue drops the block rather than making the refusing thread wait on a notification
    /// daemon. Called from the proxy's connection threads and the exec supervisor, so both properties
    /// are load-bearing rather than merely tidy.
    pub(crate) fn block(&self, block: Block) {
        if self.policy.mode_for(block.event) == crate::notify::NotifyMode::Off {
            return;
        }
        let Some(tx) = &self.tx else { return };
        match tx.try_send(block) {
            Ok(()) => {}
            Err(TrySendError::Full(_)) => {
                self.dropped.fetch_add(1, Ordering::Relaxed);
            }
            // The delivery thread is gone (it only ends when the channel closes, so this means the
            // notifier is being torn down). Nothing to report and nothing to do.
            Err(TrySendError::Disconnected(_)) => {}
        }
    }
}

/// The teardown advisory for `n` announcements the queue could not hold, or `None` when none were.
/// Pure, so the wording is pinned without provoking a real overflow.
fn drop_report(n: u64) -> Option<String> {
    (n > 0).then(|| {
        format!(
            "{n} blocked-request notification(s) were dropped: they arrived faster than the \
             desktop could show them (the logs — `sbx net logs`, `sbx proc logs` — are complete)"
        )
    })
}

impl Notifier {
    /// Stop delivering, drain what is queued, and report anything the queue could not hold.
    ///
    /// Called explicitly by the launch rather than left to [`Drop`]: the notifier is reached through
    /// an `Arc` held by the proxy, the exec supervisor, the agent ring and the task engine, so
    /// whether `drop` runs at all depends on which of those outlives the launch — and an advisory
    /// that only fires when the reference graph happens to unwind in the right order is one that
    /// never fires. Idempotent, so the `Drop` below stays a safety net.
    pub(crate) fn finish(&self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(msg) = drop_report(self.dropped.swap(0, Ordering::Relaxed)) {
            crate::diag::warn(&msg);
        }
    }
}

impl Drop for Notifier {
    fn drop(&mut self) {
        // Signal, close this notifier's own sender, then wait for the thread to finish what is
        // queued: a refusal that fired in the last moments of a session is still worth hearing about,
        // and the flag bounds the wait whatever else is holding the channel open.
        self.stop.store(true, Ordering::Relaxed);
        self.tx = None;
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
        // A safety net for a path that never called `finish`; `swap` makes the pair idempotent, so
        // whichever runs second reports nothing rather than repeating the advisory.
        if let Some(msg) = drop_report(self.dropped.swap(0, Ordering::Relaxed)) {
            crate::diag::warn(&msg);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::notify::{NotifyEvent, NotifyMode};
    use std::sync::Mutex;

    /// One recorded delivery: what the sink was asked to show, and which notification it revised.
    type Delivery = (String, String, Option<u32>);

    /// A sink that records what it was asked to deliver, and hands out ids like a daemon would, so a
    /// test can assert on the whole path without a session bus.
    #[derive(Clone, Default)]
    struct Recorder {
        /// Each delivery, in order.
        seen: Arc<Mutex<Vec<Delivery>>>,
        /// Whether this sink hands out ids (a desktop daemon does, stderr does not).
        ids: bool,
    }

    impl Sink for Recorder {
        fn deliver(
            &mut self,
            summary: &str,
            body: &str,
            replaces: Option<u32>,
        ) -> Result<Option<u32>, ()> {
            let mut seen = self.seen.lock().unwrap();
            seen.push((summary.to_string(), body.to_string(), replaces));
            Ok(self.ids.then(|| seen.len() as u32))
        }
    }

    /// Run `blocks` through a notifier under `policy` against a recording sink, and return what the
    /// sink was asked to deliver. Drops the notifier, so the assertions run after the delivery thread
    /// has drained.
    fn deliveries(
        policy: NotifyPolicy,
        needles: Vec<SecretNeedle>,
        ids: bool,
        blocks: Vec<Block>,
    ) -> Vec<Delivery> {
        let rec = Recorder {
            seen: Arc::new(Mutex::new(Vec::new())),
            ids,
        };
        let seen = Arc::clone(&rec.seen);
        {
            let n = Notifier::with_sink(
                policy,
                Arc::new(RwLock::new(needles)),
                String::new(),
                Some(Box::new(rec)),
            );
            for b in blocks {
                n.block(b);
            }
        }

        seen.lock().unwrap().clone()
    }

    fn net_block(subject: &str, reason: &str) -> Block {
        Block {
            event: NotifyEvent::Network,
            subject: subject.to_string(),
            reason: reason.to_string(),
            detail: String::new(),
            fix: String::new(),
        }
    }

    #[test]
    fn a_blocked_request_reaches_the_sink() {
        let out = deliveries(
            NotifyPolicy::uniform(NotifyMode::Once),
            Vec::new(),
            true,
            vec![net_block("api.example.com:443", "denied-default")],
        );
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].0, "Blocked: api.example.com:443");
        assert_eq!(out[0].1, "");
        assert_eq!(out[0].2, None);
    }

    #[test]
    fn once_delivers_a_repeat_no_further_than_the_queue() {
        let b = net_block("api.example.com:443", "denied-default");
        let out = deliveries(
            NotifyPolicy::uniform(NotifyMode::Once),
            Vec::new(),
            true,
            vec![b.clone(), b.clone(), b],
        );
        assert_eq!(out.len(), 1, "the sink must be asked exactly once");
    }

    #[test]
    fn always_replaces_the_previous_notification_of_the_same_problem() {
        let b = net_block("api.example.com:443", "denied-default");
        let out = deliveries(
            NotifyPolicy::uniform(NotifyMode::Always),
            Vec::new(),
            true,
            vec![b.clone(), b.clone(), b],
        );
        assert_eq!(out.len(), 3);
        // The first has nothing to replace; each later one revises the toast the daemon assigned.
        assert_eq!(out[0].2, None);
        assert_eq!(out[1].2, Some(1));
        assert_eq!(out[2].2, Some(2));
    }

    #[test]
    fn a_sink_without_ids_still_delivers_every_repeat() {
        // stderr has no notification to revise, so `always` prints a line per occurrence rather than
        // falling silent because it had no id to replace.
        let b = net_block("api.example.com:443", "denied-default");
        let out = deliveries(
            NotifyPolicy::uniform(NotifyMode::Always),
            Vec::new(),
            false,
            vec![b.clone(), b],
        );
        assert_eq!(out.len(), 2);
        assert!(out.iter().all(|d| d.2.is_none()));
    }

    #[test]
    fn an_off_event_never_reaches_the_sink() {
        let policy = NotifyPolicy::uniform(NotifyMode::Always)
            .with_event(NotifyEvent::Network, NotifyMode::Off);
        let out = deliveries(
            policy,
            Vec::new(),
            true,
            vec![
                net_block("api.example.com:443", "denied-default"),
                Block {
                    event: NotifyEvent::Proc,
                    subject: "/usr/bin/curl".to_string(),
                    reason: "denied-by-rule".to_string(),
                    detail: String::new(),
                    fix: String::new(),
                },
            ],
        );
        assert_eq!(out.len(), 1, "only the proc block is announced");
        assert_eq!(out[0].0, "Blocked: /usr/bin/curl");
    }

    #[test]
    fn a_credential_in_a_blocked_request_never_reaches_the_notification() {
        // The failure this guards: an agent puts a token in a query string, the request is refused,
        // and the refusal's own notification carries the token to a desktop daemon that journals it.
        let token = "super-secret-token-value";
        let needles = vec![SecretNeedle::named("gh_token", token.as_bytes().to_vec())];
        let out = deliveries(
            NotifyPolicy::uniform(NotifyMode::Once),
            needles,
            true,
            vec![Block {
                event: NotifyEvent::Network,
                subject: "api.example.com:443".to_string(),
                reason: "denied-default".to_string(),
                detail: format!("GET /repos?access_token={token}"),
                fix: String::new(),
            }],
        );
        assert_eq!(out.len(), 1);
        let body = &out[0].1;
        assert!(
            !body.contains(token),
            "the credential must not be in {body:?}"
        );
        assert!(
            body.contains("${gh_token}"),
            "the withheld value must be named, not merely removed: {body:?}"
        );
    }

    #[test]
    fn teardown_finishes_even_while_a_sender_is_still_held() {
        // The hang this guards: a refusal site keeps a live sender (a proxy connection thread that
        // outlives the launch's drop point), so the channel never closes. Teardown must be bounded by
        // the stop flag, not by drop order — a `sbx run` that will not exit is far worse than a
        // missed toast.
        let rec = Recorder {
            seen: Arc::new(Mutex::new(Vec::new())),
            ids: true,
        };
        let seen = Arc::clone(&rec.seen);
        let n = Notifier::with_sink(
            NotifyPolicy::uniform(NotifyMode::Once),
            Arc::new(RwLock::new(Vec::new())),
            String::new(),
            Some(Box::new(rec)),
        );
        n.block(net_block("api.example.com:443", "denied-default"));
        // A second sender, alive across the teardown.
        let held = n.tx.clone().expect("an enabled notifier has a sender");
        drop(n);
        assert_eq!(
            seen.lock().unwrap().len(),
            1,
            "the queued block was delivered"
        );
        // The sender outlived the notifier; sending on it now simply finds no reader.
        let _ = held.try_send(net_block("late.example.com:443", "denied-default"));
    }

    /// A sink whose transport is gone: every delivery reports the transport lost.
    struct DeadSink(Arc<AtomicU64>);

    impl Sink for DeadSink {
        fn deliver(&mut self, _: &str, _: &str, _: Option<u32>) -> Result<Option<u32>, ()> {
            self.0.fetch_add(1, Ordering::Relaxed);
            Err(())
        }
    }

    #[test]
    fn a_lost_transport_falls_back_instead_of_going_quiet() {
        // The failure this guards: the notification daemon restarts mid-session, every later call on
        // the bound connection fails, and the sandbox simply stops announcing refusals — silently,
        // which is indistinguishable from a sandbox that refused nothing.
        let attempts = Arc::new(AtomicU64::new(0));
        {
            let n = Notifier::with_sink(
                NotifyPolicy::uniform(NotifyMode::Always),
                Arc::new(RwLock::new(Vec::new())),
                String::new(),
                Some(Box::new(DeadSink(Arc::clone(&attempts)))),
            );
            n.block(net_block("a.example.com:443", "denied-default"));
            n.block(net_block("b.example.com:443", "denied-default"));
            n.block(net_block("c.example.com:443", "denied-default"));
        }
        // Exactly one attempt on the dead transport: it is replaced after the first failure rather
        // than retried for every later refusal (which would mean one hung call each).
        assert_eq!(
            attempts.load(Ordering::Relaxed),
            1,
            "the dead sink must be replaced, not retried"
        );
    }

    #[test]
    fn the_teardown_advisory_reports_only_what_was_actually_dropped() {
        assert_eq!(drop_report(0), None, "nothing dropped, nothing said");
        let msg = drop_report(7).expect("a drop is reported");
        assert!(msg.starts_with("7 blocked-request notification(s) were dropped"));
        // It points at the record that *is* complete, so the reader knows nothing was actually lost.
        assert!(msg.contains("sbx net logs"));
    }

    #[test]
    fn finish_reports_once_and_drop_does_not_repeat_it() {
        // `finish` and `Drop` both report, and both run in a real launch. The count is taken, not
        // read, so the advisory appears once rather than twice.
        let n = Notifier::disabled();
        n.dropped.store(3, Ordering::Relaxed);
        n.finish();
        assert_eq!(
            n.dropped.load(Ordering::Relaxed),
            0,
            "finish takes the count, so the Drop that follows reports nothing"
        );
        assert_eq!(drop_report(n.dropped.load(Ordering::Relaxed)), None);
    }

    #[test]
    fn the_session_names_the_sender_and_a_launch_without_one_is_just_sbx() {
        assert_eq!(app_name("kiro@ops-cli[4242]"), "sbx · kiro@ops-cli[4242]");
        // No session to name: the bare product name, never a dangling separator.
        assert_eq!(app_name(""), "sbx");
    }

    #[test]
    fn the_stderr_fallback_keeps_the_session_a_desktop_would_have_shown() {
        // A terminal has no application header, so dropping to stderr would lose which sandbox
        // refused if the line did not carry it. Every combination is spelled out because the empty
        // cases are where a separator strands itself.
        assert_eq!(
            stderr_line(
                "kiro@ops-cli[4242]",
                "Blocked: api.example.com:443",
                "no rule"
            ),
            "kiro@ops-cli[4242]: Blocked: api.example.com:443: no rule"
        );
        // A refusal with nothing to add, and a launch that is not a session: both ends have to
        // disappear without stranding the separator that joined them.
        assert_eq!(
            stderr_line("kiro@ops-cli[4242]", "Blocked: x", ""),
            "kiro@ops-cli[4242]: Blocked: x"
        );
        assert_eq!(stderr_line("", "Blocked: x", "why"), "Blocked: x: why");
        assert_eq!(stderr_line("", "Blocked: x", ""), "Blocked: x");

        // And the sink itself uses it, rather than composing a second line of its own.
        let mut sink = StderrSink {
            context: "kiro@ops-cli[4242]".to_string(),
        };
        assert_eq!(sink.deliver("Blocked: x", "why", None), Ok(None));
    }

    #[test]
    fn both_marks_are_pngs_and_are_not_the_same_image() {
        // The two fills are separate files generated from separate drawings, and the build would be
        // just as happy if one were missing and the other included twice — which would silently
        // undo the whole light/dark distinction.
        for (name, bytes) in [("light", LOGO_LIGHT), ("dark", LOGO_DARK)] {
            assert_eq!(
                &bytes[..8],
                b"\x89PNG\r\n\x1a\x0a",
                "{name}: a daemon decodes this through gdk-pixbuf, so it must be a real PNG"
            );
        }
        assert_ne!(
            LOGO_LIGHT, LOGO_DARK,
            "the dark twin must be its own image, not a second copy of the canonical fill"
        );
    }

    #[test]
    fn a_mark_is_written_once_and_is_the_bytes_that_were_embedded() {
        let tmp = crate::testutil::TmpDir::new();
        let path = tmp.path().join("sub").join("sbx.png");

        // The parent does not exist yet: a first launch must create it rather than give up.
        let named = write_mark(&path, LOGO_LIGHT).expect("the mark is written");
        assert_eq!(named, path.to_str().expect("a UTF-8 temp path"));
        assert_eq!(
            std::fs::read(&path).expect("the mark is on disk"),
            LOGO_LIGHT,
            "what a daemon opens must be exactly what was embedded"
        );

        // Writing again is a no-op: the file is only rewritten when the mark itself changes, so a
        // launch does not disturb a copy a daemon may be reading.
        let before = std::fs::metadata(&path).expect("stat").modified().ok();
        assert_eq!(write_mark(&path, LOGO_LIGHT).as_deref(), Some(&*named));
        assert_eq!(
            std::fs::metadata(&path).expect("stat").modified().ok(),
            before,
            "an unchanged mark must not be rewritten"
        );

        // Different bytes at the same path do replace it — the upgrade case — and nothing is left
        // beside it, because the write goes through a private name and a rename.
        assert!(write_mark(&path, LOGO_DARK).is_some());
        assert_eq!(std::fs::read(&path).expect("the new mark"), LOGO_DARK);
        let strays: Vec<_> = std::fs::read_dir(path.parent().expect("a parent"))
            .expect("the directory")
            .filter_map(|e| e.ok().map(|e| e.file_name()))
            .filter(|n| n != "sbx.png")
            .collect();
        assert!(
            strays.is_empty(),
            "the temporary copy must not survive: {strays:?}"
        );
    }

    #[test]
    fn a_refused_write_falls_back_to_the_theme_name_rather_than_to_nothing() {
        // A read-only data directory is the case this must survive: the announcement still has to
        // go out, carrying the warning icon it carried before the mark existed.
        let tmp = crate::testutil::TmpDir::new();
        let dir = tmp.path().join("locked");
        std::fs::create_dir_all(&dir).expect("the directory");
        let mut perms = std::fs::metadata(&dir).expect("stat").permissions();
        perms.set_readonly(true);
        std::fs::set_permissions(&dir, perms).expect("lock the directory");

        let refused = write_mark(&dir.join("sbx.png"), LOGO_LIGHT);

        // Restore before asserting, so a failure does not leave an undeletable directory behind.
        let mut perms = std::fs::metadata(&dir).expect("stat").permissions();
        #[allow(clippy::permissions_set_readonly_false)]
        perms.set_readonly(false);
        std::fs::set_permissions(&dir, perms).expect("unlock the directory");

        assert_eq!(
            refused, None,
            "an unwritable mark is reported, not invented"
        );
        assert_eq!(
            mark_for(Box::leak(Box::new(Marks::default())), false),
            FALLBACK_ICON,
            "with no mark at all, the announcement still carries a warning icon"
        );
    }

    #[test]
    fn the_fill_follows_the_desktop_and_degrades_to_whichever_mark_exists() {
        let both: &'static Marks = Box::leak(Box::new(Marks {
            light: Some("/data/sbx.png".to_string()),
            dark: Some("/data/sbx-dark.png".to_string()),
        }));
        assert_eq!(mark_for(both, false), "/data/sbx.png");
        assert_eq!(mark_for(both, true), "/data/sbx-dark.png");

        // One fill missing: the nuance is lost, the identity is not. Losing the twin must never
        // send a desktop back to an anonymous theme icon.
        let light_only: &'static Marks = Box::leak(Box::new(Marks {
            light: Some("/data/sbx.png".to_string()),
            dark: None,
        }));
        assert_eq!(mark_for(light_only, true), "/data/sbx.png");
        let dark_only: &'static Marks = Box::leak(Box::new(Marks {
            light: None,
            dark: Some("/data/sbx-dark.png".to_string()),
        }));
        assert_eq!(mark_for(dark_only, false), "/data/sbx-dark.png");
    }

    /// A stand-in notifications daemon on a private bus: it owns the interface and counts calls, so
    /// a test can serve real `Notify` requests and then take the server away.
    ///
    /// It also records each call's `app_icon` and hint keys. Those are built inside `notify_over`
    /// and are invisible to a caller holding a `Sink`, so serving the call is the only place they
    /// can be observed as the daemon actually receives them.
    struct FakeDaemon {
        calls: Arc<AtomicU64>,
        seen: Arc<RwLock<Vec<Served>>>,
    }

    /// One served `Notify`, in the parts a test asserts on: the application name, the icon
    /// argument, the hint keys, and the `image-path` hint's value.
    type Served = (String, String, Vec<String>, Option<String>);

    #[zbus::interface(name = "org.freedesktop.Notifications")]
    impl FakeDaemon {
        #[allow(clippy::too_many_arguments)]
        async fn notify(
            &self,
            app_name: String,
            replaces_id: u32,
            app_icon: String,
            _summary: String,
            _body: String,
            _actions: Vec<String>,
            hints: std::collections::HashMap<String, zbus::zvariant::OwnedValue>,
            _expire_timeout: i32,
        ) -> u32 {
            self.calls.fetch_add(1, Ordering::Relaxed);
            let mut keys: Vec<String> = hints.keys().cloned().collect();
            keys.sort();
            let image_path = hints
                .get("image-path")
                .and_then(|v| String::try_from(v.clone()).ok());
            if let Ok(mut seen) = self.seen.write() {
                seen.push((app_name, app_icon, keys, image_path));
            }
            if replaces_id != 0 { replaces_id } else { 77 }
        }

        async fn get_server_information(&self) -> (String, String, String, String) {
            ("fake".into(), "sbx-test".into(), "1".into(), "1.2".into())
        }
    }

    /// The desktop sink against a **real** bus and a real daemon that goes away mid-session.
    ///
    /// This is the path no recording sink can stand in for: the zbus call itself, and what happens
    /// to it when the server that was answering disappears. Exercised on a private `dbus-daemon` so
    /// it never touches the user's desktop — on a Wayland session the notification daemon *is* the
    /// compositor, and restarting it to find out would take the session down.
    #[test]
    fn the_desktop_sink_reconnects_when_the_daemon_is_replaced() {
        let Ok(bus) = std::process::Command::new("dbus-daemon")
            .args(["--session", "--print-address", "--nofork"])
            .stdout(std::process::Stdio::piped())
            .spawn()
        else {
            skip_incapable!("skipping: no dbus-daemon on PATH");
            return;
        };
        let mut bus = ChildGuard(bus);
        let address = {
            use std::io::BufRead as _;
            let out = bus.0.stdout.take().expect("piped stdout");
            let mut line = String::new();
            std::io::BufReader::new(out)
                .read_line(&mut line)
                .expect("the bus prints its address");
            line.trim().to_string()
        };

        let calls = Arc::new(AtomicU64::new(0));
        let seen: Arc<RwLock<Vec<Served>>> = Arc::new(RwLock::new(Vec::new()));
        // First server: owns the interface and answers.
        let server = serve_fake(&address, Arc::clone(&calls), Arc::clone(&seen));
        let mut sink = DesktopSink::connect_to(Some(&address), app_name("kiro@demo-app[4242]"))
            .expect("the fake daemon is reachable");
        assert_eq!(
            sink.deliver("s", "b", None),
            Ok(Some(77)),
            "a live daemon answers with its id"
        );

        // What crossed the bus, as the daemon received it. Asserted against literal file names
        // rather than against what the code under test computes: deriving the expectation from
        // `marks()` would let a run where nothing could be written agree with itself and pass.
        //
        // The mark is written to the real data directory here, because that is the whole point —
        // the path handed to a daemon has to be one that exists outside this process. It is the
        // same file a launch would write, so the test leaves nothing a run would not have left.
        {
            let seen = seen.read().expect("the recording survives the call");
            let (name, icon, hints, image_path) = seen.first().expect("the call was served");
            // Which sandbox spoke rides the application name, on the line a desktop shows whole.
            assert_eq!(
                name, "sbx · kiro@demo-app[4242]",
                "the session names the sender, not the summary that gets truncated"
            );
            assert_ne!(
                icon, FALLBACK_ICON,
                "a run with a resolvable data directory must sign with the mark, not a theme name"
            );
            let sent = std::path::Path::new(icon);
            let name = sent.file_name().and_then(|n| n.to_str());
            assert!(
                matches!(name, Some("sbx.png" | "sbx-dark.png")),
                "one of the two fills, named as it is on disk: {icon}"
            );
            assert!(
                sent.is_absolute() && sent.exists(),
                "a daemon opens this path itself, in another process: {icon}"
            );
            // `image-path` rides along only when the icon is a file, and must name the same file:
            // a hint pointing somewhere the `app_icon` argument does not is how a daemon ends up
            // rendering one image and journalling another.
            assert_eq!(
                image_path.as_deref(),
                Some(icon.as_str()),
                "a file icon travels in both slots and names the same file, since daemons differ \
                 on which of the two they read: {hints:?}"
            );
            assert!(
                hints.iter().any(|k| k == "urgency") && hints.iter().any(|k| k == "category"),
                "the hints that classify a refusal must survive the icon work: {hints:?}"
            );
        }

        // Take the server away, and wait for the *bus* to agree the name is unowned: closing a
        // connection releases its names asynchronously, so asserting straight after the drop races
        // the daemon and would fail for a reason that has nothing to do with the sink.
        drop(server);
        wait_until_unowned(&address);
        // With no owner of the name, delivery fails and the reconnect finds no daemon either: the
        // sink reports the transport gone rather than pretending it delivered.
        assert_eq!(
            sink.deliver("s", "b", None),
            Err(()),
            "a vanished daemon must be reported, not swallowed"
        );

        // A replacement daemon appears (the `gnome-shell` restart case): the very next delivery
        // reconnects and succeeds, which is the whole point of the retry.
        let _server = serve_fake(&address, Arc::clone(&calls), Arc::clone(&seen));
        assert_eq!(
            sink.deliver("s", "b", None),
            Ok(Some(77)),
            "a fresh daemon must be found without restarting the launch"
        );
        assert_eq!(
            calls.load(Ordering::Relaxed),
            2,
            "one call served by each daemon"
        );
    }

    /// A stand-in desktop portal, answering the appearance `color-scheme` read with whatever the
    /// test currently wants. Shared and mutable so one test can change the desktop's mind between
    /// two announcements.
    struct FakePortal {
        scheme: Arc<AtomicU64>,
    }

    #[zbus::interface(name = "org.freedesktop.portal.Settings")]
    impl FakePortal {
        async fn read(
            &self,
            _namespace: String,
            _key: String,
        ) -> zbus::fdo::Result<zbus::zvariant::OwnedValue> {
            let n = self.scheme.load(Ordering::Relaxed) as u32;
            zbus::zvariant::Value::from(n)
                .try_into()
                .map_err(|_| zbus::fdo::Error::Failed("cannot build the reply".into()))
        }
    }

    /// The fill that is sent follows the desktop, and follows it **per announcement**.
    ///
    /// This is the property the whole two-file arrangement exists for, and it is invisible to every
    /// other test here: `mark_for` proves the choice is made correctly given an answer, and the
    /// reconnect test proves a mark crosses the bus, but neither shows the portal's answer reaching
    /// the choice. A stand-in portal on the private bus closes that, and changing its answer between
    /// two deliveries is what distinguishes "read once and remembered" from "read every time".
    #[test]
    fn the_fill_sent_follows_the_portal_and_is_re_read_per_announcement() {
        let Ok(bus) = std::process::Command::new("dbus-daemon")
            .args(["--session", "--print-address", "--nofork"])
            .stdout(std::process::Stdio::piped())
            .spawn()
        else {
            skip_incapable!("skipping: no dbus-daemon on PATH");
            return;
        };
        let mut bus = ChildGuard(bus);
        let address = {
            use std::io::BufRead as _;
            let out = bus.0.stdout.take().expect("piped stdout");
            let mut line = String::new();
            std::io::BufReader::new(out)
                .read_line(&mut line)
                .expect("the bus prints its address");
            line.trim().to_string()
        };

        // Both fills must exist for this test to mean anything: with one missing the ladder would
        // send the survivor whatever the portal said, and the assertions would pass for the wrong
        // reason. On this machine that means the data directory has to be resolvable.
        let marks = marks();
        assert!(
            marks.light.is_some() && marks.dark.is_some(),
            "both fills must be on disk for the choice to be observable: {marks:?}"
        );

        let calls = Arc::new(AtomicU64::new(0));
        let seen: Arc<RwLock<Vec<Served>>> = Arc::new(RwLock::new(Vec::new()));
        let _daemon = serve_fake(&address, Arc::clone(&calls), Arc::clone(&seen));

        // `prefer-light` (2) to begin with. Owning the portal name here also keeps the bus from
        // activating the real one behind our back.
        let scheme = Arc::new(AtomicU64::new(2));
        let _portal = async_io::block_on(async {
            zbus::connection::Builder::address(address.as_str())
                .unwrap()
                .name("org.freedesktop.portal.Desktop")
                .unwrap()
                .serve_at(
                    "/org/freedesktop/portal/desktop",
                    FakePortal {
                        scheme: Arc::clone(&scheme),
                    },
                )
                .unwrap()
                .build()
                .await
                .expect("the fake portal owns the name")
        });

        let mut sink = DesktopSink::connect_to(Some(&address), app_name(""))
            .expect("the fake daemon is reachable");
        assert!(sink.deliver("s", "b", None).is_ok());

        // The desktop switches to dark *after* the sink was built and has already announced once.
        scheme.store(1, Ordering::Relaxed);
        assert!(sink.deliver("s", "b", None).is_ok());

        let seen = seen.read().expect("the recording survives the calls");
        let names: Vec<Option<&str>> = seen
            .iter()
            .map(|(_, icon, _, _)| {
                std::path::Path::new(icon)
                    .file_name()
                    .and_then(|n| n.to_str())
            })
            .collect();
        assert_eq!(
            names,
            vec![Some("sbx.png"), Some("sbx-dark.png")],
            "the first announcement is light, and the second follows the switch to dark"
        );
    }

    /// Block until nobody owns the notifications name on `address`, or a bounded wait elapses.
    fn wait_until_unowned(address: &str) {
        async_io::block_on(async {
            let conn = zbus::connection::Builder::address(address)
                .unwrap()
                .build()
                .await
                .expect("the bus is up");
            let dbus = zbus::fdo::DBusProxy::new(&conn)
                .await
                .expect("the bus daemon");
            for _ in 0..100 {
                let owned = dbus
                    .name_has_owner("org.freedesktop.Notifications".try_into().unwrap())
                    .await
                    .unwrap_or(false);
                if !owned {
                    return;
                }
                async_io::Timer::after(Duration::from_millis(20)).await;
            }
            panic!("the name was still owned after the wait");
        });
    }

    /// Own `org.freedesktop.Notifications` on `address` until the returned connection is dropped,
    /// recording each call's icon and hint keys into `seen`.
    fn serve_fake(
        address: &str,
        calls: Arc<AtomicU64>,
        seen: Arc<RwLock<Vec<Served>>>,
    ) -> zbus::Connection {
        async_io::block_on(async {
            zbus::connection::Builder::address(address)
                .unwrap()
                .name("org.freedesktop.Notifications")
                .unwrap()
                .serve_at("/org/freedesktop/Notifications", FakeDaemon { calls, seen })
                .unwrap()
                .build()
                .await
                .expect("the fake daemon owns the name")
        })
    }

    /// Kills the bus when the test ends, however it ends.
    struct ChildGuard(std::process::Child);

    impl Drop for ChildGuard {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    #[test]
    fn a_disabled_notifier_holds_no_thread_and_accepts_blocks() {
        // The common case: nothing enabled, so `block` is a no-op that must not panic or block.
        let n = Notifier::disabled();
        assert!(n.handle.is_none());
        n.block(net_block("api.example.com:443", "denied-default"));
        // And `start` on an all-off policy takes the same path rather than spawning a thread.
        let started = Notifier::start(
            NotifyPolicy::uniform(NotifyMode::Off),
            Arc::new(RwLock::new(Vec::new())),
            &crate::notify::Origin::default(),
        );
        assert!(started.handle.is_none());
    }
}
