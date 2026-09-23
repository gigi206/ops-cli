//! What the proxy reports about its own work, as messages to the process that supervises it.
//!
//! The proxy is to run in a process of its own, holding none of the session's shared state. What it
//! reports — a decision counted, a refusal to announce, a credential a signer formed — therefore
//! leaves it as owned values on a bounded queue ([`Emitter`]), and one thread on the supervisor's
//! side ([`spawn`]) applies them to the structures a reader consults. The queue is in-process today;
//! when the proxy moves, the applying side stays as it is and reads a socket instead, so this is the
//! one path, not a second one kept beside the direct calls it replaces.
//!
//! **Delivery is asynchronous, and backpressure blocks.** A full queue makes the sender wait rather
//! than lose an event: the supervisor's memory stays bounded, only the proxy slows down, and that is
//! the semantics the socket will have. A reader that needs every event sent so far to be applied —
//! the session's end, a test reading a count — asks for it with [`Emitter::flush`].
//!
//! **The applying side reads data the proxy chose.** Once the proxy runs apart, it may be the thing
//! an attacker controls, so what arrives here is an account, not a verdict: it is bounded on arrival
//! and never trusted for more than what it says. The decisions that bind — which host the proxy may
//! reach — are taken by the supervisor itself.

use crate::notify::Block;
use crate::sandbox::egress_stats::{EgressStats, StatKind};
use crate::sandbox::notify_sink::Notifier;
use crate::sandbox::signer_control::{SignerKind, SignerRing};
use std::sync::mpsc::{Receiver, SyncSender, sync_channel};
use std::sync::{Arc, Condvar, Mutex};

/// How many events may wait for the applying side before a sender waits for room.
const QUEUE: usize = 4096;

/// The longest host an event may name. A DNS name is at most 253 bytes; a longer one is no
/// destination the proxy can have reached, so an event naming it is dropped on arrival.
const MAX_HOST: usize = 253;

/// One thing the proxy did, as the supervisor learns it.
pub(crate) enum ProxyEvent {
    /// A decision, counted for `sbx net stats`.
    Stat { host: String, kind: StatKind },
    /// A refusal to announce on the desktop.
    Refusal(Block),
    /// A credential a signer formed, or one it would not form. `detail` is already redacted
    /// against the launch's credential needles: no value a signer was handed leaves the proxy in
    /// the clear.
    Signer { kind: SignerKind, detail: String },
}

/// The structures the applying side writes to, each present only when the launch keeps it.
#[derive(Default)]
pub(crate) struct Sinks {
    pub(crate) stats: Option<Arc<EgressStats>>,
    pub(crate) notifier: Option<Arc<Notifier>>,
    pub(crate) signer_log: Option<Arc<SignerRing>>,
}

/// How far the applying side has got, for [`Emitter::flush`].
#[derive(Default)]
struct Progress {
    state: Mutex<Applied>,
    advanced: Condvar,
}

/// What [`Progress`] guards: the applying side's count, and whether it has ended.
#[derive(Default)]
struct Applied {
    /// Events applied so far.
    count: u64,
    /// The applying side has ended, and nothing more will be applied.
    closed: bool,
}

/// The proxy's end of the queue. Cheap to clone: every connection thread holds the same queue.
#[derive(Clone)]
pub(crate) struct Emitter {
    tx: SyncSender<ProxyEvent>,
    /// Which kinds of event the launch keeps a structure for, fixed at [`spawn`], so the proxy
    /// neither composes nor queues an event nothing would apply.
    keeps: Keeps,
    /// Events accepted by the queue so far, across every clone.
    sent: Arc<Mutex<u64>>,
    progress: Arc<Progress>,
}

/// Which kinds of event a launch keeps a structure for.
#[derive(Clone, Copy)]
pub(crate) struct Keeps {
    pub(crate) stats: bool,
    pub(crate) refusals: bool,
    pub(crate) signatures: bool,
}

impl Emitter {
    /// Which kinds of event this launch keeps.
    pub(crate) fn keeps(&self) -> Keeps {
        self.keeps
    }

    /// Queue `event`, waiting for room when the queue is full. An event the applying side can no
    /// longer take — it has ended — has nobody left to apply it and is dropped.
    pub(crate) fn send(&self, event: ProxyEvent) {
        // Counted under the lock the send happens under, so `flush` never waits for an event that
        // was counted and then not queued.
        let mut sent = lock(&self.sent);
        if self.tx.send(event).is_ok() {
            *sent += 1;
        }
    }

    /// Wait until every event queued before this call has been applied, or until the applying
    /// side has ended.
    pub(crate) fn flush(&self) {
        let target = *lock(&self.sent);
        let mut applied = lock(&self.progress.state);
        while applied.count < target && !applied.closed {
            applied = self
                .progress
                .advanced
                .wait(applied)
                .unwrap_or_else(std::sync::PoisonError::into_inner);
        }
    }
}

/// Start the applying side for one proxy, returning the proxy's end of its queue. The thread ends
/// once every clone of the returned [`Emitter`] is dropped, after applying what they queued.
pub(crate) fn spawn(sinks: Sinks) -> Emitter {
    start(sinks).0
}

/// [`spawn`], keeping the applying thread's handle: a caller that joins it knows the structures it
/// was handed are no longer held.
fn start(sinks: Sinks) -> (Emitter, std::thread::JoinHandle<()>) {
    let keeps = Keeps {
        stats: sinks.stats.is_some(),
        refusals: sinks.notifier.is_some(),
        signatures: sinks.signer_log.is_some(),
    };
    let (tx, rx) = sync_channel(QUEUE);
    let progress = Arc::new(Progress::default());
    let applier = Arc::clone(&progress);
    let handle = std::thread::spawn(move || apply_all(&rx, &sinks, &applier));
    let emitter = Emitter {
        tx,
        keeps,
        sent: Arc::new(Mutex::new(0)),
        progress,
    };
    (emitter, handle)
}

/// Apply every event until the queue closes, reporting progress as it goes.
fn apply_all(rx: &Receiver<ProxyEvent>, sinks: &Sinks, progress: &Progress) {
    // Marks the end even when an apply panics, so a `flush` waiting on this thread returns.
    struct Closing<'a>(&'a Progress);
    impl Drop for Closing<'_> {
        fn drop(&mut self) {
            lock(&self.0.state).closed = true;
            self.0.advanced.notify_all();
        }
    }
    let _closing = Closing(progress);
    for event in rx {
        apply(sinks, event);
        lock(&progress.state).count += 1;
        progress.advanced.notify_all();
    }
}

/// Apply one event to the structure it concerns, if the launch keeps that structure.
fn apply(sinks: &Sinks, event: ProxyEvent) {
    match event {
        ProxyEvent::Stat { host, kind } => {
            if let Some(stats) = &sinks.stats
                && host.len() <= MAX_HOST
            {
                stats.record(&host, kind);
            }
        }
        ProxyEvent::Refusal(block) => {
            if let Some(notifier) = &sinks.notifier {
                notifier.block(block);
            }
        }
        ProxyEvent::Signer { kind, detail } => {
            if let Some(ring) = &sinks.signer_log {
                ring.push_detail(kind, &detail);
            }
        }
    }
}

/// A lock that a panicking holder does not take down with it: every value guarded here stays
/// consistent whatever a panic interrupted.
fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// [`spawn`] with the applying thread's handle, for a test that must know the structures it handed
/// over are released: join the handle once every clone of the reporter is dropped.
#[cfg(test)]
pub(crate) fn spawn_joinable(sinks: Sinks) -> (Emitter, std::thread::JoinHandle<()>) {
    start(sinks)
}

/// An applying side that keeps only decision counters, for the tests of the paths that count.
#[cfg(test)]
pub(crate) fn for_stats(stats: Arc<EgressStats>) -> Emitter {
    spawn(Sinks {
        stats: Some(stats),
        ..Sinks::default()
    })
}

/// Waits, when dropped, for every event the held reporter queued to be applied — for a test helper
/// that drives a request through a proxy it hands away, so the caller reads settled counts.
#[cfg(test)]
pub(crate) struct Settle(pub(crate) Option<Emitter>);

#[cfg(test)]
impl Drop for Settle {
    fn drop(&mut self) {
        if let Some(events) = &self.0 {
            events.flush();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sandbox::signer_control::SIGNER_RING_CAP;
    use crate::testutil::TmpDir;

    fn stats(dir: &TmpDir) -> Arc<EgressStats> {
        Arc::new(EgressStats::new(dir.join("stats"), "/t".into(), None))
    }

    /// What was queued before a `flush` is applied when it returns, whichever structure it goes
    /// to: the proxy reports asynchronously, and a reader that asks for settled counts gets them.
    #[test]
    fn a_flush_returns_once_everything_queued_before_it_is_applied() {
        let dir = TmpDir::new();
        let counts = stats(&dir);
        let ring = Arc::new(SignerRing::new(SIGNER_RING_CAP));
        let events = spawn(Sinks {
            stats: Some(Arc::clone(&counts)),
            signer_log: Some(Arc::clone(&ring)),
            ..Sinks::default()
        });
        for _ in 0..500 {
            events.send(ProxyEvent::Stat {
                host: "api.example.com".into(),
                kind: StatKind::Allow,
            });
        }
        events.send(ProxyEvent::Signer {
            kind: SignerKind::Sign,
            detail: "demo: GET api.example.com/ set Authorization".into(),
        });
        events.flush();
        assert_eq!(counts.snapshot()["api.example.com"].allow, 500);
        assert_eq!(ring.snapshot(None).events.len(), 1);
    }

    /// The reporter says which structures the launch keeps, so the proxy composes no event nothing
    /// would apply.
    #[test]
    fn the_reporter_names_what_the_launch_keeps() {
        let dir = TmpDir::new();
        let only_stats = spawn(Sinks {
            stats: Some(stats(&dir)),
            ..Sinks::default()
        });
        let keeps = only_stats.keeps();
        assert!(keeps.stats && !keeps.refusals && !keeps.signatures);
        let none = spawn(Sinks::default()).keeps();
        assert!(!none.stats && !none.refusals && !none.signatures);
    }

    /// A host no proxy could have reached is not counted: what arrives here is the proxy's account,
    /// bounded on arrival.
    #[test]
    fn a_host_longer_than_any_name_is_not_counted() {
        let dir = TmpDir::new();
        let counts = stats(&dir);
        let events = for_stats(Arc::clone(&counts));
        events.send(ProxyEvent::Stat {
            host: "a".repeat(MAX_HOST + 1),
            kind: StatKind::Deny,
        });
        events.send(ProxyEvent::Stat {
            host: "b".repeat(MAX_HOST),
            kind: StatKind::Deny,
        });
        events.flush();
        let snap = counts.snapshot();
        assert_eq!(snap.len(), 1, "{:?}", snap.keys().collect::<Vec<_>>());
        assert!(snap.contains_key(&"b".repeat(MAX_HOST)));
    }

    /// A `flush` never waits on an applying side that has ended: the reporter's queue is then
    /// closed, and nothing sent to it can be applied any more.
    #[test]
    fn a_flush_does_not_wait_on_an_applying_side_that_has_ended() {
        let (events, applier) = spawn_joinable(Sinks::default());
        let (tx, rx) = sync_channel::<ProxyEvent>(1);
        drop(rx);
        // A reporter whose queue nobody reads any more, sharing the ended thread's progress.
        let orphan = Emitter {
            tx,
            keeps: events.keeps(),
            sent: Arc::clone(&events.sent),
            progress: Arc::clone(&events.progress),
        };
        drop(events);
        applier.join().unwrap();
        orphan.send(ProxyEvent::Stat {
            host: "api.example.com".into(),
            kind: StatKind::Allow,
        });
        orphan.flush();
    }
}
