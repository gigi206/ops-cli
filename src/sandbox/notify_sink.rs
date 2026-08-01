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
    /// there was one, so a repeat updates that toast in place. Returns the id the transport assigned,
    /// when it has ids at all — `None` from a sink whose output cannot be revised (stderr).
    fn deliver(&mut self, summary: &str, body: &str, replaces: Option<u32>) -> Option<u32>;
}

/// The fallback sink: one stderr line per announcement, in the diagnostic family's shape.
///
/// Used when there is no session bus to reach. It has no ids and no replacement, so an `always` event
/// prints a line per occurrence — on a terminal that is the expected behaviour, and the desktop
/// sink's in-place update has no meaning here.
struct StderrSink;

impl Sink for StderrSink {
    fn deliver(&mut self, summary: &str, body: &str, _replaces: Option<u32>) -> Option<u32> {
        crate::diag::warn(&format!("{summary}: {body}"));
        None
    }
}

/// The desktop sink: `org.freedesktop.Notifications.Notify` on the host session bus.
///
/// Holds the connection for the session's lifetime — one connection, one thread, and the async work
/// driven by `async_io::block_on` so nothing async escapes this module (the same arrangement the
/// in-cage relays use; sbx's own world is std threads).
struct DesktopSink {
    proxy: crate::sandbox::notify_relay::HostNotificationsProxy<'static>,
}

impl DesktopSink {
    /// Connect to the session bus and bind the notifications proxy, or `None` when there is no bus to
    /// reach (a headless or `ssh` session, a cron run) or no daemon serving the interface.
    fn connect() -> Option<DesktopSink> {
        async_io::block_on(async {
            let conn = zbus::Connection::session().await.ok()?;
            let proxy = crate::sandbox::notify_relay::HostNotificationsProxy::new(&conn)
                .await
                .ok()?;
            // Ask the daemon what it is: proof that something actually serves the interface, rather
            // than discovering it at the first refusal — when the fallback would be too late to warn
            // about. The answer itself is not used.
            proxy.get_server_information().await.ok()?;
            Some(DesktopSink { proxy })
        })
    }
}

impl Sink for DesktopSink {
    fn deliver(&mut self, summary: &str, body: &str, replaces: Option<u32>) -> Option<u32> {
        let hints = std::collections::HashMap::from([
            (
                "urgency".to_string(),
                zbus::zvariant::Value::from(URGENCY_NORMAL)
                    .try_into()
                    .ok()?,
            ),
            (
                "category".to_string(),
                zbus::zvariant::Value::from("security").try_into().ok()?,
            ),
        ]);
        async_io::block_on(self.proxy.notify(
            APP_NAME,
            replaces.unwrap_or(0),
            APP_ICON,
            summary,
            body,
            // No action buttons: an action needs a live `ActionInvoked` subscription to mean
            // anything, and a one-click "allow" on a security refusal is a decision that belongs at a
            // prompt, not on a toast.
            Vec::new(),
            hints,
            // Let the daemon apply its own default timeout.
            -1,
        ))
        .ok()
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
                let Speak::Say { replaces } = coalescer.decide(policy, &block) else {
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
                if let Some(id) = sink.deliver(&summary, &body, replaces) {
                    coalescer.record_id(&block, id);
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
        let dropped = self.dropped.load(Ordering::Relaxed);
        if dropped > 0 {
            crate::diag::warn(&format!(
                "{dropped} blocked-request notification(s) were dropped: they arrived faster than \
                 the desktop could show them (the logs — `sbx net logs`, `sbx proc logs` — are complete)"
            ));
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
        fn deliver(&mut self, summary: &str, body: &str, replaces: Option<u32>) -> Option<u32> {
            let mut seen = self.seen.lock().unwrap();
            seen.push((summary.to_string(), body.to_string(), replaces));
            self.ids.then(|| seen.len() as u32)
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
