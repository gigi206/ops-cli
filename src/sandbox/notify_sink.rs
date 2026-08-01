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

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{sync_channel, RecvTimeoutError, SyncSender, TrySendError};
use std::sync::{Arc, RwLock};
use std::thread::JoinHandle;
use std::time::Duration;

use crate::notify::{Block, Coalescer, NotifyPolicy, Speak};
use crate::sandbox::proxy::SecretNeedle;
use crate::sandbox::redact::{redact_string, Placeholder};

/// How many pending announcements the queue holds before it starts dropping.
///
/// Bounded because the producer is an untrusted agent's behaviour: a loop retrying a blocked host
/// can generate refusals far faster than a desktop daemon renders them, and an unbounded queue would
/// turn that into unbounded memory in the supervisor. What is lost when it fills is a *repeat* — the
/// first of each distinct problem is long delivered by then — and the count is reported at teardown
/// rather than silently swallowed.
const QUEUE_CAP: usize = 256;

/// The application name every sbx notification carries, and the icon it asks for (a freedesktop icon
/// name resolved from the user's theme — sbx ships no image of its own).
const APP_NAME: &str = "sbx";
const APP_ICON: &str = "dialog-warning";

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
struct StderrSink;

impl Sink for StderrSink {
    fn deliver(
        &mut self,
        summary: &str,
        body: &str,
        _replaces: Option<u32>,
    ) -> Result<Option<u32>, ()> {
        crate::diag::warn(&format!("{summary}: {body}"));
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
    /// The bus this sink is bound to, so a reconnect goes back to the **same** bus rather than to
    /// whatever the ambient environment names. `None` is the session bus, which is the production
    /// case; a test binds a private one and must not have its retry escape onto the user's desktop.
    address: Option<String>,
}

/// One notification call over an already-bound proxy. Separated from [`DesktopSink::deliver`] so the
/// retry after a reconnect runs exactly the same code as the first attempt.
fn notify_over(
    proxy: &crate::sandbox::notify_relay::HostNotificationsProxy<'static>,
    summary: &str,
    body: &str,
    replaces: Option<u32>,
) -> Result<u32, ()> {
    let mut hints = std::collections::HashMap::new();
    if let Ok(v) = zbus::zvariant::Value::from(URGENCY_NORMAL).try_into() {
        hints.insert("urgency".to_string(), v);
    }
    if let Ok(v) = zbus::zvariant::Value::from("security").try_into() {
        hints.insert("category".to_string(), v);
    }
    async_io::block_on(proxy.notify(
        APP_NAME,
        replaces.unwrap_or(0),
        APP_ICON,
        summary,
        body,
        // No action buttons: an action needs a live `ActionInvoked` subscription to mean anything,
        // and a one-click "allow" on a security refusal is a decision that belongs at a prompt, not
        // on a toast.
        Vec::new(),
        hints,
        // Let the daemon apply its own default timeout.
        -1,
    ))
    .map_err(|_| ())
}

impl DesktopSink {
    /// Connect to the session bus and bind the notifications proxy, or `None` when there is no bus to
    /// reach (a headless or `ssh` session, a cron run) or no daemon serving the interface.
    fn connect() -> Option<DesktopSink> {
        DesktopSink::connect_to(None)
    }

    /// [`connect`](DesktopSink::connect) against a named bus address rather than the ambient session
    /// one — the seam the reconnect test drives, so that path is exercised against a real bus and a
    /// real daemon going away, without touching the user's desktop.
    fn connect_to(address: Option<&str>) -> Option<DesktopSink> {
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
            Some(DesktopSink {
                proxy,
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
        if let Ok(id) = notify_over(&self.proxy, summary, body, replaces) {
            return Ok(Some(id));
        }
        let fresh = DesktopSink::connect_to(self.address.as_deref()).ok_or(())?;
        self.proxy = fresh.proxy;
        // The id the old daemon handed out means nothing to a new one, so a retry after a reconnect
        // posts a fresh notification rather than trying to revise one that no longer exists.
        notify_over(&self.proxy, summary, body, None).map(Some)
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
                None => match DesktopSink::connect() {
                    Some(d) => Box::new(d),
                    None => {
                        crate::diag::note(
                            "no desktop notification daemon reachable — reporting blocked \
                             requests on stderr instead",
                        );
                        Box::new(StderrSink)
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
                let (summary, body) = block.render(&context);
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
                        sink = Box::new(StderrSink);
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
        let out = seen.lock().unwrap().clone();
        out
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
        assert_eq!(out[0].0, "sbx blocked a network request");
        assert_eq!(out[0].1, "api.example.com:443");
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
        assert_eq!(out[0].0, "sbx blocked a program from running");
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

    /// A stand-in notifications daemon on a private bus: it owns the interface and counts calls, so
    /// a test can serve real `Notify` requests and then take the server away.
    struct FakeDaemon {
        calls: Arc<AtomicU64>,
    }

    #[zbus::interface(name = "org.freedesktop.Notifications")]
    impl FakeDaemon {
        #[allow(clippy::too_many_arguments)]
        async fn notify(
            &self,
            _app_name: String,
            replaces_id: u32,
            _app_icon: String,
            _summary: String,
            _body: String,
            _actions: Vec<String>,
            _hints: std::collections::HashMap<String, zbus::zvariant::OwnedValue>,
            _expire_timeout: i32,
        ) -> u32 {
            self.calls.fetch_add(1, Ordering::Relaxed);
            if replaces_id != 0 {
                replaces_id
            } else {
                77
            }
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
            eprintln!("skipping: no dbus-daemon on PATH");
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
        // First server: owns the interface and answers.
        let server = serve_fake(&address, Arc::clone(&calls));
        let mut sink =
            DesktopSink::connect_to(Some(&address)).expect("the fake daemon is reachable");
        assert_eq!(
            sink.deliver("s", "b", None),
            Ok(Some(77)),
            "a live daemon answers with its id"
        );

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
        let _server = serve_fake(&address, Arc::clone(&calls));
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

    /// Own `org.freedesktop.Notifications` on `address` until the returned connection is dropped.
    fn serve_fake(address: &str, calls: Arc<AtomicU64>) -> zbus::Connection {
        async_io::block_on(async {
            zbus::connection::Builder::address(address)
                .unwrap()
                .name("org.freedesktop.Notifications")
                .unwrap()
                .serve_at("/org/freedesktop/Notifications", FakeDaemon { calls })
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
