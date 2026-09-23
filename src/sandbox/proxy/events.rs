//! What the proxy reports about its own work, as messages to the process that supervises it.
//!
//! The proxy is to run in a process of its own, holding none of the session's shared state. What it
//! reports — a decision counted, a refusal to announce, a credential a signer formed, a decision
//! logged and what later completes it — therefore leaves it as owned values on a bounded queue
//! ([`Emitter`]), and one thread on the supervisor's side ([`spawn`]) applies them to the structures
//! a reader consults. The queue is in-process today; when the proxy moves, the applying side stays
//! as it is and reads a socket instead, so this is the one path, not a second one kept beside the
//! direct calls it replaces.
//!
//! **Delivery is asynchronous, and backpressure blocks.** A full queue makes the sender wait rather
//! than lose an event: the supervisor's memory stays bounded, only the proxy slows down, and that is
//! the semantics the socket will have. The queue is bounded twice, in events ([`QUEUE`]) and in the
//! bytes they own ([`QUEUE_BYTES`]), because an event can carry a captured exchange. A reader that
//! needs every event sent so far to be applied — the session's end, `--net-learn`, a test reading a
//! count — asks for it with [`Emitter::flush`].
//!
//! **A logged decision is numbered by the proxy.** The event ring numbers what it holds, and it is
//! shared with other proxies of the same session, so the number it assigns is not one the proxy can
//! know when it sends the decision. The proxy numbers its own ([`Emitter::log`]), the amendments
//! that follow — the upstream status, the capture, a secret seen in a tunnel — name that number, and
//! the applying side keeps the correspondence to the ring's. A proxy can therefore amend only the
//! events it logged itself. The time an event carries is the supervisor's, taken when it is applied.
//!
//! **The applying side reads data the proxy chose.** Once the proxy runs apart, it may be the thing
//! an attacker controls, so what arrives here is an account, not a verdict: it is bounded on arrival
//! and never trusted for more than what it says. The decisions that bind — which host the proxy may
//! reach — are taken by the supervisor itself, and so is the plane an event is recorded under: which
//! proxy this is, is not the proxy's to say.

use crate::notify::Block;
use crate::sandbox::control::{
    CaptureCaps, CaptureRing, FlowRegistry, HttpVer, LogRing, LogVerdict, Masked, Plane, Proto,
    RpcKind, SecretWay,
};
use crate::sandbox::egress_stats::{EgressStats, StatKind};
use crate::sandbox::notify_sink::Notifier;
use crate::sandbox::signer_control::{SignerKind, SignerRing};
use std::collections::VecDeque;
use std::sync::mpsc::{Receiver, SyncSender, sync_channel};
use std::sync::{Arc, Condvar, Mutex};

/// How many events may wait for the applying side before a sender waits for room.
const QUEUE: usize = 4096;

/// How many bytes the waiting events may own together before a sender waits for room. A count alone
/// stops bounding memory once an event carries a captured exchange, whose parts reach a mebibyte
/// each at the highest `capture_max_kb`. An event heavier than this on its own is queued once
/// nothing else is waiting, rather than never.
const QUEUE_BYTES: usize = 16 * 1024 * 1024;

/// The longest host an event may name. A DNS name is at most 253 bytes; a longer one is no
/// destination the proxy can have reached, so an event naming it is dropped on arrival.
const MAX_HOST: usize = 253;

/// The longest text a logged decision may carry in any one field. Every such field is cut from a
/// request head the proxy read, and the largest head it reads is an HTTP/2 header list of 64 KiB,
/// so a longer field is no request the proxy can have decided and the event is dropped on arrival.
/// Not [`MAX_HOST`]: a refusal logs the host the cage *asked* for, which need not be a name at all.
const MAX_FIELD: usize = 64 * 1024;

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
    /// A decision for `sbx net logs`, under the number the proxy gave it ([`Emitter::log`]).
    Logged { id: u64, entry: LogEntry },
    /// The upstream status of the exchange logged as `id`.
    Status { id: u64, status: u16 },
    /// A capture of the exchange logged as `id` is coming, so an arriving status waits for it.
    CaptureExpected { id: u64 },
    /// The exchange logged as `id` is over: what was captured of it, possibly nothing, masked by the
    /// proxy and filed once.
    CaptureFiled { id: u64, capture: Masked },
    /// The WebSocket logged as `id` carried more after its handshake was filed.
    CaptureGrew { id: u64, capture: Masked },
    /// The configured secret `name` crossed the tunnel logged as `id`, in the direction `way`.
    SecretSeen {
        id: u64,
        name: String,
        way: SecretWay,
    },
    /// A permitted tunnel opened, numbered `id` by the proxy for its later reports
    /// ([`super::flows`]).
    FlowOpened {
        id: u64,
        host: String,
        port: u16,
        proto: Proto,
    },
    /// The absolute byte totals `(id, up, down)` of the open flows that moved since their last
    /// report.
    FlowCounts(Vec<(u64, u64, u64)>),
    /// The tunnel `id` closed.
    FlowClosed { id: u64 },
}

impl ProxyEvent {
    /// The bytes this event owns, what it weighs against [`QUEUE_BYTES`].
    fn weight(&self) -> usize {
        match self {
            ProxyEvent::Stat { host, .. } => host.len(),
            ProxyEvent::Refusal(block) => {
                block.subject.len() + block.reason.len() + block.detail.len() + block.fix.len()
            }
            ProxyEvent::Signer { detail, .. } => detail.len(),
            ProxyEvent::Logged { entry, .. } => entry.weight(),
            ProxyEvent::Status { .. } | ProxyEvent::CaptureExpected { .. } => 0,
            ProxyEvent::CaptureFiled { capture, .. } | ProxyEvent::CaptureGrew { capture, .. } => {
                capture.weight()
            }
            ProxyEvent::SecretSeen { name, .. } => name.len(),
            ProxyEvent::FlowOpened { host, .. } => host.len(),
            ProxyEvent::FlowCounts(moved) => std::mem::size_of_val(moved.as_slice()),
            ProxyEvent::FlowClosed { .. } => 0,
        }
    }
}

/// One decision for the live log, as the proxy composes it. What the ring adds — its own number,
/// the time, and the plane — is the supervisor's.
pub(crate) struct LogEntry {
    /// A denial a `mute` rule keeps out of the default view.
    pub(crate) muted: bool,
    pub(crate) host: String,
    pub(crate) port: u16,
    pub(crate) method: Option<String>,
    /// Already masked against the launch's credential needles.
    pub(crate) path: Option<String>,
    pub(crate) verdict: LogVerdict,
    pub(crate) reason: String,
    pub(crate) proto: Proto,
    pub(crate) http_ver: HttpVer,
    pub(crate) rpc: RpcKind,
}

impl LogEntry {
    /// The bytes this entry owns.
    fn weight(&self) -> usize {
        self.host.len()
            + self.method.as_ref().map_or(0, String::len)
            + self.path.as_ref().map_or(0, String::len)
            + self.reason.len()
    }

    /// Whether every field is one a request the proxy read can have produced.
    fn is_bounded(&self) -> bool {
        [
            Some(&self.host),
            self.method.as_ref(),
            self.path.as_ref(),
            Some(&self.reason),
        ]
        .into_iter()
        .flatten()
        .all(|field| field.len() <= MAX_FIELD)
    }
}

/// The structures the applying side writes to, each present only when the launch keeps it, and the
/// plane the logged decisions are recorded under.
pub(crate) struct Sinks {
    pub(crate) stats: Option<Arc<EgressStats>>,
    pub(crate) notifier: Option<Arc<Notifier>>,
    pub(crate) signer_log: Option<Arc<SignerRing>>,
    pub(crate) log: Option<Arc<LogRing>>,
    /// Kept only beside a `log`: a capture is filed under the number of its logged decision.
    pub(crate) capture: Option<Arc<CaptureRing>>,
    /// The tunnels open right now, for `sbx net live`.
    pub(crate) flows: Option<Arc<FlowRegistry>>,
    pub(crate) plane: Plane,
}

/// Nothing kept, under the session's own plane: what a test that attaches only some structures
/// starts from.
#[cfg(test)]
impl Default for Sinks {
    fn default() -> Self {
        Sinks {
            stats: None,
            notifier: None,
            signer_log: None,
            log: None,
            capture: None,
            flows: None,
            plane: Plane::Agent,
        }
    }
}

/// How far the applying side has got, for [`Emitter::flush`] and [`QUEUE_BYTES`].
#[derive(Default)]
struct Progress {
    state: Mutex<Applied>,
    advanced: Condvar,
}

/// What [`Progress`] guards: the applying side's count, the bytes still waiting, and whether it has
/// ended.
#[derive(Default)]
struct Applied {
    /// Events applied so far.
    count: u64,
    /// The bytes owned by events queued and not yet applied.
    in_flight: usize,
    /// The applying side has ended, and nothing more will be applied.
    closed: bool,
}

/// What [`Emitter::sent`] guards.
#[derive(Default)]
struct Sent {
    /// Events accepted by the queue so far, across every clone.
    events: u64,
    /// The last number given to a logged decision. Given under the lock the event is queued under,
    /// so the numbers reach the applying side in increasing order.
    logged: u64,
}

/// The proxy's end of the queue. Cheap to clone: every connection thread holds the same queue.
#[derive(Clone)]
pub(crate) struct Emitter {
    tx: SyncSender<ProxyEvent>,
    /// Which kinds of event the launch keeps a structure for, fixed at [`spawn`], so the proxy
    /// neither composes nor queues an event nothing would apply.
    keeps: Keeps,
    sent: Arc<Mutex<Sent>>,
    progress: Arc<Progress>,
}

/// Which kinds of event a launch keeps a structure for.
#[derive(Clone, Copy)]
pub(crate) struct Keeps {
    pub(crate) stats: bool,
    pub(crate) refusals: bool,
    pub(crate) signatures: bool,
    pub(crate) log: bool,
    /// The caps a capture is taken at, when the launch captures.
    pub(crate) capture: Option<CaptureCaps>,
    pub(crate) flows: bool,
}

impl Emitter {
    /// Which kinds of event this launch keeps.
    pub(crate) fn keeps(&self) -> Keeps {
        self.keeps
    }

    /// Queue `event`, waiting for room when the queue is full. An event the applying side can no
    /// longer take — it has ended — has nobody left to apply it and is dropped.
    pub(crate) fn send(&self, event: ProxyEvent) {
        self.queue(event.weight(), |_| event);
    }

    /// Queue a decision for the live log, returning the number the amendments that follow name it
    /// by. Numbers start at 1 and increase with every decision this proxy logs.
    pub(crate) fn log(&self, entry: LogEntry) -> u64 {
        let mut id = 0;
        self.queue(entry.weight(), |sent| {
            sent.logged += 1;
            id = sent.logged;
            ProxyEvent::Logged { id, entry }
        });
        id
    }

    /// Queue the event `compose` builds, once `weight` bytes of room are free.
    fn queue(&self, weight: usize, compose: impl FnOnce(&mut Sent) -> ProxyEvent) {
        self.reserve(weight);
        // Counted under the lock the send happens under, so `flush` never waits for an event that
        // was counted and then not queued.
        let mut sent = lock(&self.sent);
        let event = compose(&mut sent);
        if self.tx.send(event).is_ok() {
            sent.events += 1;
        }
    }

    /// Wait until `weight` more bytes fit in [`QUEUE_BYTES`], or nothing is waiting, or the applying
    /// side has ended, then count them as waiting.
    fn reserve(&self, weight: usize) {
        let mut applied = lock(&self.progress.state);
        while applied.in_flight > 0
            && applied.in_flight.saturating_add(weight) > QUEUE_BYTES
            && !applied.closed
        {
            applied = self
                .progress
                .advanced
                .wait(applied)
                .unwrap_or_else(std::sync::PoisonError::into_inner);
        }
        applied.in_flight = applied.in_flight.saturating_add(weight);
    }

    /// Wait until every event queued before this call has been applied, or until the applying
    /// side has ended.
    pub(crate) fn flush(&self) {
        let target = lock(&self.sent).events;
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
    let log = sinks.log.is_some();
    let keeps = Keeps {
        stats: sinks.stats.is_some(),
        refusals: sinks.notifier.is_some(),
        signatures: sinks.signer_log.is_some(),
        log,
        capture: sinks.capture.as_ref().filter(|_| log).map(|c| c.caps()),
        flows: sinks.flows.is_some(),
    };
    let (tx, rx) = sync_channel(QUEUE);
    let progress = Arc::new(Progress::default());
    let applier = Arc::clone(&progress);
    let handle = std::thread::spawn(move || apply_all(&rx, Applier::new(sinks), &applier));
    let emitter = Emitter {
        tx,
        keeps,
        sent: Arc::new(Mutex::new(Sent::default())),
        progress,
    };
    (emitter, handle)
}

/// Apply every event until the queue closes, reporting progress as it goes.
fn apply_all(rx: &Receiver<ProxyEvent>, mut applier: Applier, progress: &Progress) {
    // Marks the end even when an apply panics, so a `flush` or a sender waiting on this thread
    // returns.
    struct Closing<'a>(&'a Progress);
    impl Drop for Closing<'_> {
        fn drop(&mut self) {
            lock(&self.0.state).closed = true;
            self.0.advanced.notify_all();
        }
    }
    let _closing = Closing(progress);
    for event in rx {
        let weight = event.weight();
        applier.apply(event);
        {
            let mut state = lock(&progress.state);
            state.count += 1;
            state.in_flight = state.in_flight.saturating_sub(weight);
        }
        progress.advanced.notify_all();
    }
}

/// The applying side of one proxy: the structures it writes to, and the correspondence between the
/// numbers the proxy gave its logged decisions and the ones the ring gave them.
struct Applier {
    sinks: Sinks,
    /// `(proxy's number, ring's number)` for every logged decision an amendment can still reach, in
    /// increasing order of the first. Bounded by the ring's capacity, and exactly: the entries hold
    /// only decisions the ring keeps in its main view, which it evicts oldest first, so once more
    /// than its capacity of them are newer an entry names an event the ring no longer holds. A muted
    /// denial has no entry, since nothing amends it.
    ids: VecDeque<(u64, u64)>,
    /// The highest number a logged decision has arrived with. A decision arriving with one no
    /// higher is recorded but gets no entry, so the order the lookup relies on holds whatever the
    /// proxy sends.
    last_id: u64,
}

impl Applier {
    fn new(sinks: Sinks) -> Self {
        Applier {
            sinks,
            ids: VecDeque::new(),
            last_id: 0,
        }
    }

    /// The ring's number for the decision the proxy numbered `id`, while the ring may still hold it.
    fn seq(&self, id: u64) -> Option<u64> {
        self.ids
            .binary_search_by_key(&id, |&(proxy, _)| proxy)
            .ok()
            .map(|at| self.ids[at].1)
    }

    /// File `capture` for the decision the ring numbered `seq`, if the launch captures and the
    /// capture is one the proxy can have taken. Reports whether it was filed.
    fn file(&self, seq: u64, capture: Masked) -> bool {
        let Some(ring) = &self.sinks.capture else {
            return false;
        };
        let caps = ring.caps();
        // Each part is cut at its cap before it is sent: the two heads at the head cap (the response
        // one shares its buffer with the start of the body), the three bodies and the two tunnel
        // directions at the body cap, and the injected header names bounded like any logged field.
        let most = 2 * caps.head + 4 * caps.body + MAX_FIELD;
        if capture.is_empty() || capture.weight() > most {
            return false;
        }
        ring.insert(capture.filed_as(seq));
        true
    }

    /// Apply one event to the structure it concerns, if the launch keeps that structure.
    fn apply(&mut self, event: ProxyEvent) {
        let sinks = &self.sinks;
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
            ProxyEvent::Logged { id, entry } => {
                let Some(log) = &sinks.log else {
                    return;
                };
                if !entry.is_bounded() {
                    return;
                }
                let seq = log.push(
                    entry.muted,
                    &entry.host,
                    entry.port,
                    entry.method.as_deref(),
                    entry.path.as_deref(),
                    entry.verdict,
                    &entry.reason,
                    entry.proto,
                    entry.http_ver,
                    entry.rpc,
                    sinks.plane,
                );
                if id <= self.last_id {
                    return;
                }
                self.last_id = id;
                if !entry.muted {
                    self.ids.push_back((id, seq));
                    while self.ids.len() > log.cap() {
                        self.ids.pop_front();
                    }
                }
            }
            ProxyEvent::Status { id, status } => {
                if let (Some(log), Some(seq)) = (&sinks.log, self.seq(id)) {
                    log.set_status(seq, status);
                }
            }
            ProxyEvent::CaptureExpected { id } => {
                if let (Some(log), Some(seq)) = (&sinks.log, self.seq(id)) {
                    log.expect_capture(seq);
                }
            }
            ProxyEvent::CaptureFiled { id, capture } => {
                if let (Some(log), Some(seq)) = (&sinks.log, self.seq(id)) {
                    // Settled whether or not anything was filed: a status that arrived while the
                    // capture was pending is held back until now, and would otherwise never show.
                    let filed = self.file(seq, capture);
                    log.capture_settled(seq, filed);
                }
            }
            ProxyEvent::CaptureGrew { id, capture } => {
                if let (Some(log), Some(seq)) = (&sinks.log, self.seq(id))
                    && self.file(seq, capture)
                {
                    log.capture_grew(seq);
                }
            }
            ProxyEvent::SecretSeen { id, name, way } => {
                if let (Some(log), Some(seq)) = (&sinks.log, self.seq(id))
                    && name.len() <= MAX_FIELD
                {
                    log.secret_seen(seq, &name, way);
                }
            }
            // One registry serves one proxy, so the proxy's own numbers key it: a proxy can open,
            // count and close only flows in its own view.
            ProxyEvent::FlowOpened {
                id,
                host,
                port,
                proto,
            } => {
                if let Some(flows) = &sinks.flows
                    && host.len() <= MAX_FIELD
                {
                    flows.open(id, &host, port, proto);
                }
            }
            ProxyEvent::FlowCounts(moved) => {
                if let Some(flows) = &sinks.flows {
                    for (id, up, down) in moved {
                        flows.count(id, up, down);
                    }
                }
            }
            ProxyEvent::FlowClosed { id } => {
                if let Some(flows) = &sinks.flows {
                    flows.close(id);
                }
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

/// An applying side that keeps the live log, and the decision counters when `stats` is given, for
/// the tests that read what a request logged.
#[cfg(test)]
pub(crate) fn for_log(log: Arc<LogRing>, stats: Option<Arc<EgressStats>>) -> Emitter {
    spawn(Sinks {
        stats,
        log: Some(log),
        ..Sinks::default()
    })
}

/// An applying side that keeps the live log and files captures into `store`, for the tests that
/// read what an exchange carried.
#[cfg(test)]
pub(crate) fn for_capture(log: Arc<LogRing>, store: Arc<CaptureRing>) -> Emitter {
    spawn(Sinks {
        log: Some(log),
        capture: Some(store),
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
    use crate::sandbox::control::{CaptureBytes, CaptureLevel, LOG_RING_CAP};
    use crate::sandbox::signer_control::SIGNER_RING_CAP;
    use crate::testutil::TmpDir;

    fn stats(dir: &TmpDir) -> Arc<EgressStats> {
        Arc::new(EgressStats::new(dir.join("stats"), "/t".into(), None))
    }

    fn entry(host: &str, verdict: LogVerdict, muted: bool) -> LogEntry {
        LogEntry {
            muted,
            host: host.into(),
            port: 443,
            method: Some("GET".into()),
            path: Some("/".into()),
            verdict,
            reason: "allowed".into(),
            proto: Proto::Https,
            http_ver: HttpVer::H1,
            rpc: RpcKind::None,
        }
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
    /// would apply. A capture is kept only beside a log, since it is filed under a logged decision.
    #[test]
    fn the_reporter_names_what_the_launch_keeps() {
        let dir = TmpDir::new();
        let only_stats = spawn(Sinks {
            stats: Some(stats(&dir)),
            ..Sinks::default()
        });
        let keeps = only_stats.keeps();
        assert!(keeps.stats && !keeps.refusals && !keeps.signatures && !keeps.log);
        let none = spawn(Sinks::default()).keeps();
        assert!(!none.stats && !none.refusals && !none.signatures && !none.log);

        let caps = CaptureCaps::new(CaptureLevel::Headers, 8);
        let capture = || Some(Arc::new(CaptureRing::new(caps)));
        let unlogged = spawn(Sinks {
            capture: capture(),
            ..Sinks::default()
        });
        assert!(unlogged.keeps().capture.is_none());
        let logged = spawn(Sinks {
            log: Some(Arc::new(LogRing::new(LOG_RING_CAP))),
            capture: capture(),
            ..Sinks::default()
        });
        assert_eq!(logged.keeps().capture, Some(caps));
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

    /// An amendment reaches the event the proxy numbered, even when the ring numbers it otherwise:
    /// the ring is shared with the session's other proxies, whose events take numbers in between.
    #[test]
    fn an_amendment_reaches_the_event_its_proxy_numbered_in_a_shared_ring() {
        let ring = Arc::new(LogRing::new(LOG_RING_CAP));
        let agent = for_log(Arc::clone(&ring), None);
        let task = spawn(Sinks {
            log: Some(Arc::clone(&ring)),
            plane: Plane::Task,
            ..Sinks::default()
        });
        let first = task.log(entry("task.example.com", LogVerdict::Allow, false));
        task.flush();
        let mine = agent.log(entry("api.example.com", LogVerdict::Allow, false));
        assert_eq!(
            (first, mine),
            (1, 1),
            "each proxy numbers its own decisions"
        );
        agent.send(ProxyEvent::Status {
            id: mine,
            status: 204,
        });
        agent.flush();

        let events = ring.snapshot(None, None, false).events;
        let find = |host: &str| events.iter().find(|e| e.host == host).unwrap();
        assert_eq!(find("api.example.com").status, Some(204));
        assert_eq!(find("api.example.com").plane, Plane::Agent);
        assert_eq!(
            find("task.example.com").status,
            None,
            "never the other proxy's"
        );
        assert_eq!(find("task.example.com").plane, Plane::Task);
    }

    /// A capture is filed under the ring's number for its decision, which is the number a reader
    /// asks the capture store for, and it releases the status that waited for it.
    #[test]
    fn a_capture_is_filed_under_the_rings_number_and_releases_the_status() {
        let ring = Arc::new(LogRing::new(LOG_RING_CAP));
        let store = Arc::new(CaptureRing::new(CaptureCaps::new(CaptureLevel::Headers, 8)));
        // The ring already holds another proxy's decision, so the two numbers differ.
        ring.push(
            false,
            "other.example.com",
            443,
            None,
            None,
            LogVerdict::Deny,
            "denied-default",
            Proto::Https,
            HttpVer::Unknown,
            RpcKind::None,
            Plane::Task,
        );
        let events = spawn(Sinks {
            log: Some(Arc::clone(&ring)),
            capture: Some(Arc::clone(&store)),
            ..Sinks::default()
        });
        let id = events.log(entry("api.example.com", LogVerdict::Allow, false));
        events.send(ProxyEvent::CaptureExpected { id });
        events.send(ProxyEvent::Status { id, status: 200 });
        events.flush();
        let pending = ring.snapshot(Some(2), Some(0), false);
        assert!(
            pending.events.is_empty(),
            "the status waits for the capture"
        );

        let mut capture = crate::sandbox::control::Capture::new(id);
        capture.req_head = CaptureBytes {
            bytes: b"GET / HTTP/1.1\r\n\r\n".to_vec(),
            truncated: false,
        };
        events.send(ProxyEvent::CaptureFiled {
            id,
            capture: capture.mask(&[], "api.example.com"),
        });
        events.flush();
        let (found, _) = store.get(&[2]);
        assert_eq!(found.len(), 1, "filed under the ring's number");
        let released = ring.snapshot(Some(2), Some(0), false).events;
        assert_eq!(released.len(), 1);
        assert_eq!(released[0].status, Some(200));
    }

    /// An amendment naming a number the proxy never logged, or one past what the ring still holds,
    /// changes nothing: the correspondence is bounded like the ring, and a late status is ignored as
    /// the ring already ignores one for an evicted event.
    #[test]
    fn an_amendment_for_an_unknown_or_evicted_number_changes_nothing() {
        let ring = Arc::new(LogRing::new(2));
        let events = for_log(Arc::clone(&ring), None);
        let oldest = events.log(entry("a.example.com", LogVerdict::Allow, false));
        for host in ["b.example.com", "c.example.com"] {
            events.log(entry(host, LogVerdict::Allow, false));
        }
        events.send(ProxyEvent::Status {
            id: oldest,
            status: 200,
        });
        events.send(ProxyEvent::Status {
            id: 99,
            status: 200,
        });
        events.flush();
        let applied = ring.snapshot(None, None, false).events;
        assert!(applied.iter().all(|e| e.status.is_none()), "{applied:?}");
    }

    /// A decision whose field no request the proxy read can have produced is dropped on arrival.
    #[test]
    fn a_logged_field_longer_than_any_head_is_dropped() {
        let ring = Arc::new(LogRing::new(LOG_RING_CAP));
        let events = for_log(Arc::clone(&ring), None);
        let mut long = entry("api.example.com", LogVerdict::Allow, false);
        long.path = Some("/".repeat(MAX_FIELD + 1));
        events.log(long);
        // A refusal logs the host the cage asked for, which need not be a name: kept up to the
        // bound, well past a DNS name's length.
        events.log(entry(&"h".repeat(MAX_HOST + 1), LogVerdict::Deny, false));
        events.flush();
        let kept = ring.snapshot(None, None, false).events;
        assert_eq!(kept.len(), 1);
        assert_eq!(kept[0].host.len(), MAX_HOST + 1);
    }

    /// The queue holds a bounded number of bytes: a sender waits while the events already queued own
    /// too many, and goes on once they are applied. One event heavier than the whole bound is queued
    /// when nothing else is waiting, rather than never.
    #[test]
    fn a_sender_waits_while_the_queued_events_own_too_many_bytes() {
        let (tx, rx) = sync_channel::<ProxyEvent>(QUEUE);
        let emitter = Emitter {
            tx,
            keeps: spawn(Sinks::default()).keeps(),
            sent: Arc::new(Mutex::new(Sent::default())),
            progress: Arc::new(Progress::default()),
        };
        let heavy = || ProxyEvent::Signer {
            kind: SignerKind::Sign,
            detail: "x".repeat(QUEUE_BYTES + 1),
        };
        emitter.send(heavy());
        let (done, finished) = std::sync::mpsc::channel();
        let second = emitter.clone();
        let waiting = std::thread::spawn(move || {
            second.send(heavy());
            done.send(()).unwrap();
        });
        assert!(
            finished
                .recv_timeout(std::time::Duration::from_millis(300))
                .is_err(),
            "a second heavy event must wait for the first to be applied"
        );
        let progress = Arc::clone(&emitter.progress);
        drop(emitter);
        let applier =
            std::thread::spawn(move || apply_all(&rx, Applier::new(Sinks::default()), &progress));
        finished
            .recv_timeout(std::time::Duration::from_secs(30))
            .expect("the waiting sender goes on once the first event is applied");
        waiting.join().unwrap();
        applier.join().unwrap();
    }
}
