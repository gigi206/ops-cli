//! What the proxy reports about its own work, as messages to the process that supervises it.
//!
//! The proxy runs in a process of its own ([`super::child`]), holding none of the session's shared
//! state. What it reports (a decision counted, a refusal to announce, a credential a signer
//! formed, a decision logged and what later completes it) therefore leaves it as owned values on a
//! bounded queue ([`Emitter`]), written to a socket, and one thread on the supervisor's side
//! ([`applying`]) reads them and applies them to the structures a reader consults. A test joins both
//! ends within one process, and every test that reads a count reads it through the bytes.
//!
//! **Delivery is asynchronous, and backpressure blocks.** A full queue makes the sender wait rather
//! than lose an event: the proxy's memory stays bounded, only the proxy slows down, and the
//! supervisor reads one frame at a time, each held to [`wire::MAX_FRAME`]. The queue is bounded
//! twice, in events ([`QUEUE`]) and in the bytes they own ([`QUEUE_BYTES`]), because an event can
//! carry a captured exchange. A reader that needs every event sent so far to be applied — the
//! session's end, `--net-learn`, a test reading a count — asks for it with [`Emitter::flush`].
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

mod wire;

use crate::notify::{Block, NotifyEvent};
use crate::sandbox::control::{
    CaptureCaps, CaptureRing, FlowRegistry, HttpVer, LogRing, LogVerdict, Masked, Plane, Proto,
    RpcKind, SecretWay,
};
use crate::sandbox::egress_stats::{EgressStats, StatKind};
use crate::sandbox::notify_sink::Notifier;
use crate::sandbox::signer_control::{SignerKind, SignerRing};
use std::collections::VecDeque;
use std::io::{self, Read, Write};
use std::os::unix::net::UnixStream;
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
/// destination the proxy can have reached, so an event naming it is dropped on arrival. A counted
/// decision and an opened flow are held to it: the [`FlowRegistry`] keeps the host of every flow it
/// lists for as long as the flow is open, so its cap on open flows bounds its memory only once each
/// host is bounded.
const MAX_HOST: usize = 253;

/// The longest text a logged decision may carry in any one field. Every such field is cut from a
/// request head the proxy read, and the largest head it reads is an HTTP/2 header list of 64 KiB,
/// so a longer field is no request the proxy can have decided and the event is dropped on arrival.
/// Not [`MAX_HOST`]: a refusal logs the host the cage *asked* for, which need not be a name at all.
const MAX_FIELD: usize = 64 * 1024;

/// The longest subject or suggested fix a refusal's announcement may carry. Each holds a host the
/// proxy read, at most [`MAX_FIELD`], with the text the proxy puts around it: the port, a scheme,
/// the brackets of an address, the `sbx net allow` command, and the app's name, a file name of at
/// most 255 bytes.
const MAX_ANNOUNCED: usize = MAX_FIELD + 512;

/// The longest detail a signer's record may carry: the proxy cuts it as the record keeps it
/// ([`crate::sandbox::lens::sanitize_detail`]), at most that many characters of up to four bytes.
const MAX_SIGNER_DETAIL: usize = 4 * crate::sandbox::lens::DETAIL_MAX;

/// The most flow counts one report carries. The proxy sends a tick's counts in reports of at most
/// this many ([`super::flows::LiveFlows::report`]), so a report carrying more is none it made, and
/// it is refused while it is read: a count takes a few bytes as JSON and twenty-four once read, so
/// a frame of them would otherwise be held at several times its size.
pub(super) const MAX_FLOW_COUNTS: usize = 4096;

/// One thing the proxy did, as the supervisor learns it, with its capture as `C`: the proxy's
/// [`Masked`], or the form it crosses in ([`wire`]).
#[derive(serde::Serialize, serde::Deserialize)]
#[cfg_attr(test, derive(Clone, Debug, PartialEq))]
pub(crate) enum ProxyEvent<C = Masked> {
    /// A decision, counted for `sbx net stats`.
    Stat { host: String, kind: StatKind },
    /// A refusal to announce on the desktop, one of the network's.
    Refusal(Block),
    /// A credential a signer formed, or one it would not form. `detail` is already redacted
    /// against the launch's credential needles, then cut as the record keeps it: no value a signer
    /// was handed leaves the proxy in the clear.
    Signer { kind: SignerKind, detail: String },
    /// A decision for `sbx net logs`, under the number the proxy gave it ([`Emitter::log`]).
    Logged { id: u64, entry: LogEntry },
    /// The upstream status of the exchange logged as `id`.
    Status { id: u64, status: u16 },
    /// A capture of the exchange logged as `id` is coming, so an arriving status waits for it.
    CaptureExpected { id: u64 },
    /// The exchange logged as `id` is over: what was captured of it, possibly nothing, masked by the
    /// proxy and filed once.
    CaptureFiled { id: u64, capture: C },
    /// The WebSocket logged as `id` carried more after its handshake was filed.
    CaptureGrew { id: u64, capture: C },
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
    /// report, at most [`MAX_FLOW_COUNTS`] of them.
    FlowCounts(#[serde(deserialize_with = "at_most_flow_counts")] Vec<(u64, u64, u64)>),
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

impl<C> ProxyEvent<C> {
    /// This event with its capture, if it carries one, turned into a `D` by `convert`: how the
    /// capture's bytes are taken out of the document that crosses, and put back.
    fn try_map_capture<D, E>(
        self,
        convert: impl FnOnce(C) -> Result<D, E>,
    ) -> Result<ProxyEvent<D>, E> {
        Ok(match self {
            ProxyEvent::Stat { host, kind } => ProxyEvent::Stat { host, kind },
            ProxyEvent::Refusal(block) => ProxyEvent::Refusal(block),
            ProxyEvent::Signer { kind, detail } => ProxyEvent::Signer { kind, detail },
            ProxyEvent::Logged { id, entry } => ProxyEvent::Logged { id, entry },
            ProxyEvent::Status { id, status } => ProxyEvent::Status { id, status },
            ProxyEvent::CaptureExpected { id } => ProxyEvent::CaptureExpected { id },
            ProxyEvent::CaptureFiled { id, capture } => ProxyEvent::CaptureFiled {
                id,
                capture: convert(capture)?,
            },
            ProxyEvent::CaptureGrew { id, capture } => ProxyEvent::CaptureGrew {
                id,
                capture: convert(capture)?,
            },
            ProxyEvent::SecretSeen { id, name, way } => ProxyEvent::SecretSeen { id, name, way },
            ProxyEvent::FlowOpened {
                id,
                host,
                port,
                proto,
            } => ProxyEvent::FlowOpened {
                id,
                host,
                port,
                proto,
            },
            ProxyEvent::FlowCounts(moved) => ProxyEvent::FlowCounts(moved),
            ProxyEvent::FlowClosed { id } => ProxyEvent::FlowClosed { id },
        })
    }
}

/// The counts of a [`ProxyEvent::FlowCounts`], refused at the first past [`MAX_FLOW_COUNTS`]
/// rather than once all of them are held.
fn at_most_flow_counts<'de, D>(deserializer: D) -> Result<Vec<(u64, u64, u64)>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    struct Counts;
    impl<'de> serde::de::Visitor<'de> for Counts {
        type Value = Vec<(u64, u64, u64)>;

        fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "at most {MAX_FLOW_COUNTS} flow counts")
        }

        fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
        where
            A: serde::de::SeqAccess<'de>,
        {
            let mut counts = Vec::new();
            while let Some(count) = seq.next_element()? {
                if counts.len() == MAX_FLOW_COUNTS {
                    return Err(serde::de::Error::invalid_length(counts.len() + 1, &self));
                }
                counts.push(count);
            }
            Ok(counts)
        }
    }
    deserializer.deserialize_seq(Counts)
}

/// One decision for the live log, as the proxy composes it. What the ring adds — its own number,
/// the time, and the plane — is the supervisor's.
#[derive(serde::Serialize, serde::Deserialize)]
#[cfg_attr(test, derive(Clone, Debug, PartialEq))]
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

/// How far the proxy's report has got, for [`Emitter::flush`] and [`QUEUE_BYTES`].
#[derive(Default)]
struct Progress {
    state: Mutex<Applied>,
    advanced: Condvar,
}

/// What [`Progress`] guards.
#[derive(Default)]
struct Applied {
    /// The last barrier the applying side acknowledged: everything queued before it is applied.
    acked: u64,
    /// The bytes owned by events queued and not yet written to the channel.
    in_flight: usize,
    /// The channel has ended, and nothing more will be written, applied or acknowledged.
    closed: bool,
}

/// What [`Emitter::sent`] guards.
#[derive(Default)]
struct Sent {
    /// The last number given to a logged decision. Given under the lock the event is queued under,
    /// so the numbers reach the applying side in increasing order.
    logged: u64,
    /// The last barrier queued, under the same lock, so a barrier follows every event queued before
    /// it.
    barriers: u64,
}

// An event runs to a few hundred bytes against a barrier's eight, which the size lint flags. The
// queue's slots held a whole event before barriers crossed it, and a barrier is one per flush, so a
// slot is the size of an event either way; boxing would add an allocation to every event the proxy
// reports for no memory saved. Written above the doc block rather than under it: a `//` between the
// `///` and the item severs the two.
/// What the queue carries to the thread writing the channel.
#[allow(clippy::large_enum_variant)]
enum Outgoing {
    /// An event, with the bytes it holds against [`QUEUE_BYTES`] until it is written.
    Event { event: ProxyEvent, weight: usize },
    /// A mark for [`Emitter::flush`] to wait on.
    Barrier(u64),
}

/// The proxy's end of the queue. Cheap to clone: every connection thread holds the same queue.
#[derive(Clone)]
pub(crate) struct Emitter {
    tx: SyncSender<Outgoing>,
    /// Which kinds of event the launch keeps a structure for, fixed when the queue is made, so the
    /// proxy neither composes nor queues an event nothing would apply.
    keeps: Keeps,
    sent: Arc<Mutex<Sent>>,
    progress: Arc<Progress>,
}

/// Which kinds of event a launch keeps a structure for.
#[derive(Clone, Copy, serde::Serialize, serde::Deserialize)]
pub(crate) struct Keeps {
    pub(crate) stats: bool,
    pub(crate) refusals: bool,
    pub(crate) signatures: bool,
    pub(crate) log: bool,
    /// The caps a capture is taken at, when the launch captures.
    pub(crate) capture: Option<CaptureCaps>,
    pub(crate) flows: bool,
}

impl Keeps {
    /// What `sinks` keeps: a capture only beside a log, since it is filed under a logged decision.
    fn of(sinks: &Sinks) -> Self {
        let log = sinks.log.is_some();
        Keeps {
            stats: sinks.stats.is_some(),
            refusals: sinks.notifier.is_some(),
            signatures: sinks.signer_log.is_some(),
            log,
            capture: sinks.capture.as_ref().filter(|_| log).map(|c| c.caps()),
            flows: sinks.flows.is_some(),
        }
    }
}

impl Emitter {
    /// Which kinds of event this launch keeps.
    pub(crate) fn keeps(&self) -> Keeps {
        self.keeps
    }

    /// Queue `event`, waiting for room when the queue is full. An event the channel can no longer
    /// carry (it has ended) has nobody left to apply it and is dropped.
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
        let mut sent = lock(&self.sent);
        let event = compose(&mut sent);
        if self.tx.send(Outgoing::Event { event, weight }).is_err() {
            release(&self.progress, weight);
        }
    }

    /// Wait until `weight` more bytes fit in [`QUEUE_BYTES`], or nothing is waiting, or the channel
    /// has ended, then count them as waiting.
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

    /// Wait until every event queued before this call has been applied, or until the channel has
    /// ended.
    pub(crate) fn flush(&self) {
        let barrier = {
            let mut sent = lock(&self.sent);
            sent.barriers += 1;
            if self.tx.send(Outgoing::Barrier(sent.barriers)).is_err() {
                return;
            }
            sent.barriers
        };
        let mut applied = lock(&self.progress.state);
        while applied.acked < barrier && !applied.closed {
            applied = self
                .progress
                .advanced
                .wait(applied)
                .unwrap_or_else(std::sync::PoisonError::into_inner);
        }
    }
}

/// Start the applying side for one proxy, returning the proxy's end of its queue. The two ends are a
/// socket pair within this process; the applying thread ends once every clone of the returned
/// [`Emitter`] is dropped, after applying what they queued.
#[cfg(test)]
pub(crate) fn spawn(sinks: Sinks) -> io::Result<Emitter> {
    Ok(start(sinks)?.0)
}

/// [`spawn`], keeping the applying thread's handle: a caller that joins it knows the structures it
/// was handed are no longer held.
#[cfg(test)]
fn start(sinks: Sinks) -> io::Result<(Emitter, std::thread::JoinHandle<()>)> {
    let (proxy, keeps, applier) = applied(sinks)?;
    Ok((emitter(proxy, keeps)?, applier))
}

/// Start the applying side for one proxy that runs apart: the proxy's end of the channel, to hand
/// over with what the launch keeps, and the applying thread, which ends once the proxy has let go
/// of its end, after applying what it wrote.
pub(crate) fn applied(
    sinks: Sinks,
) -> io::Result<(UnixStream, Keeps, std::thread::JoinHandle<()>)> {
    let keeps = Keeps::of(&sinks);
    let (proxy, supervisor) = UnixStream::pair()?;
    let applier = applying(sinks, supervisor)?;
    Ok((proxy, keeps, applier))
}

/// The proxy's end of a report written to `channel`, for a launch that keeps what `keeps` says.
///
/// Two threads serve it: one writes what the queue holds, in order, and one reads the applying
/// side's acknowledgements. Both end with the channel, the writer once every clone of the returned
/// [`Emitter`] is dropped, after writing what they queued.
pub(crate) fn emitter(channel: UnixStream, keeps: Keeps) -> io::Result<Emitter> {
    let (tx, rx) = sync_channel(QUEUE);
    let progress = Arc::new(Progress::default());
    let acks = channel.try_clone()?;
    let writing = Arc::clone(&progress);
    std::thread::Builder::new()
        .name("sbx-report".into())
        .spawn(move || write_all(&rx, channel, &writing))?;
    let acknowledged = Arc::clone(&progress);
    std::thread::Builder::new()
        .name("sbx-report-acks".into())
        .spawn(move || read_acks(acks, &acknowledged))?;
    Ok(Emitter {
        tx,
        keeps,
        sent: Arc::new(Mutex::new(Sent::default())),
        progress,
    })
}

/// Write every event the queue holds to `channel`, in the order it was queued, until every sender is
/// gone, then end the channel's writing side so the applying side finishes.
fn write_all(rx: &Receiver<Outgoing>, mut channel: UnixStream, progress: &Progress) {
    for outgoing in rx {
        let (frame, weight) = match outgoing {
            Outgoing::Event { event, weight } => (wire::Frame::Event(event), weight),
            Outgoing::Barrier(n) => (wire::Frame::Barrier(n), 0),
        };
        // An event too large to cross is one no request can have produced (see
        // [`wire::MAX_FRAME`]), and the applying side would drop it and the channel with it: it is
        // dropped here instead, and what follows it still crosses.
        let written = match wire::encode(frame) {
            Ok(Some(bytes)) => channel.write_all(&bytes).is_ok(),
            Ok(None) | Err(_) => true,
        };
        release(progress, weight);
        if !written {
            // Returning drops the queue's receiver, so a sender waiting for room is let go.
            close(progress);
            return;
        }
    }
    let _ = channel.shutdown(std::net::Shutdown::Write);
}

/// Record each barrier the applying side acknowledges, until the channel ends.
fn read_acks(mut channel: UnixStream, progress: &Progress) {
    let mut ack = [0u8; 8];
    while channel.read_exact(&mut ack).is_ok() {
        {
            let mut applied = lock(&progress.state);
            applied.acked = applied.acked.max(u64::from_le_bytes(ack));
        }
        progress.advanced.notify_all();
    }
    close(progress);
}

/// Count `weight` bytes as no longer waiting.
fn release(progress: &Progress, weight: usize) {
    {
        let mut applied = lock(&progress.state);
        applied.in_flight = applied.in_flight.saturating_sub(weight);
    }
    progress.advanced.notify_all();
}

/// Mark the channel ended, so no sender or `flush` waits on it any more.
fn close(progress: &Progress) {
    lock(&progress.state).closed = true;
    progress.advanced.notify_all();
}

/// Apply what a proxy reports on `channel` to `sinks`, on a thread of its own.
///
/// The thread ends with the channel: when the proxy's end has written its last event, or at the
/// first frame that cannot be read, since past it there is no telling where the next one starts.
pub(crate) fn applying(
    sinks: Sinks,
    channel: UnixStream,
) -> io::Result<std::thread::JoinHandle<()>> {
    let acks = channel.try_clone()?;
    std::thread::Builder::new()
        .name("sbx-apply".into())
        .spawn(move || apply_all(channel, acks, Applier::new(sinks)))
}

/// Apply every frame until the channel ends, acknowledging each barrier once everything before it
/// is applied.
fn apply_all(channel: UnixStream, mut acks: UnixStream, mut applier: Applier) {
    let mut frames = io::BufReader::new(channel);
    while let Ok(Some(frame)) = wire::read(&mut frames) {
        match frame {
            wire::Frame::Event(event) => applier.apply(event),
            wire::Frame::Barrier(n) => {
                if acks.write_all(&n.to_le_bytes()).is_err() {
                    return;
                }
            }
        }
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
                if let Some(notifier) = &sinks.notifier
                    && announceable(&block)
                {
                    notifier.block(block);
                }
            }
            ProxyEvent::Signer { kind, detail } => {
                if let Some(ring) = &sinks.signer_log
                    && detail.len() <= MAX_SIGNER_DETAIL
                {
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
                    && host.len() <= MAX_HOST
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

/// Whether `block` is an announcement the proxy can have made: a refusal of the network's (which
/// lens refused is no more the proxy's to say than the plane its decisions are recorded under), its
/// subject and fix within [`MAX_ANNOUNCED`], and its reason, the one its decision is logged with, and
/// its detail within [`MAX_FIELD`].
fn announceable(block: &Block) -> bool {
    block.event == NotifyEvent::Network
        && block.subject.len() <= MAX_ANNOUNCED
        && block.fix.len() <= MAX_ANNOUNCED
        && block.reason.len() <= MAX_FIELD
        && block.detail.len() <= MAX_FIELD
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
    start(sinks).unwrap()
}

/// An applying side that keeps only decision counters, for the tests of the paths that count.
#[cfg(test)]
pub(crate) fn for_stats(stats: Arc<EgressStats>) -> Emitter {
    spawn(Sinks {
        stats: Some(stats),
        ..Sinks::default()
    })
    .unwrap()
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
    .unwrap()
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
    .unwrap()
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
    use crate::sandbox::control::{CAPTURE_PARTS, CaptureBytes, CaptureLevel, LOG_RING_CAP};
    use crate::sandbox::signer_control::SIGNER_RING_CAP;
    use crate::testutil::{TmpDir, Trickle};
    use proptest::prelude::{Just, Strategy, any, prop_oneof};
    use proptest::sample::{Index, select};

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
        })
        .unwrap();
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
        })
        .unwrap();
        let keeps = only_stats.keeps();
        assert!(keeps.stats && !keeps.refusals && !keeps.signatures && !keeps.log);
        let none = spawn(Sinks::default()).unwrap().keeps();
        assert!(!none.stats && !none.refusals && !none.signatures && !none.log);

        let caps = CaptureCaps::new(CaptureLevel::Headers, 8);
        let capture = || Some(Arc::new(CaptureRing::new(caps)));
        let unlogged = spawn(Sinks {
            capture: capture(),
            ..Sinks::default()
        })
        .unwrap();
        assert!(unlogged.keeps().capture.is_none());
        let logged = spawn(Sinks {
            log: Some(Arc::new(LogRing::new(LOG_RING_CAP))),
            capture: capture(),
            ..Sinks::default()
        })
        .unwrap();
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

    /// A flow opened to a host longer than any name is not listed: the proxy opens one only for a
    /// tunnel the supervisor dialled, to a host it resolved, and the registry keeps each host it
    /// lists for as long as the flow is open.
    #[test]
    fn a_flow_to_a_host_longer_than_any_name_is_not_listed() {
        let registry = Arc::new(FlowRegistry::new());
        let events = spawn(Sinks {
            flows: Some(Arc::clone(&registry)),
            ..Sinks::default()
        })
        .unwrap();
        for (id, host) in [(1, "a".repeat(MAX_HOST + 1)), (2, "b".repeat(MAX_HOST))] {
            events.send(ProxyEvent::FlowOpened {
                id,
                host,
                port: 443,
                proto: Proto::Https,
            });
        }
        events.flush();
        let hosts: Vec<String> = registry.snapshot().into_iter().map(|f| f.host).collect();
        assert_eq!(hosts, ["b".repeat(MAX_HOST)]);
    }

    /// A `flush` never waits on an applying side that has ended: the channel is then closed, and
    /// nothing sent to it can be applied any more.
    #[test]
    fn a_flush_does_not_wait_on_an_applying_side_that_has_ended() {
        let (proxy, supervisor) = UnixStream::pair().unwrap();
        let mut unreadable = proxy.try_clone().unwrap();
        let events = emitter(proxy, Keeps::of(&Sinks::default())).unwrap();
        let applier = applying(Sinks::default(), supervisor).unwrap();
        // A frame claiming more pieces than any event carries: the applying side stops at it.
        unreadable.write_all(&[0, 0, 0, 0, 0xff, 0, 0, 0]).unwrap();
        applier.join().unwrap();
        let (done, returned) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            events.send(ProxyEvent::Stat {
                host: "api.example.com".into(),
                kind: StatKind::Allow,
            });
            events.flush();
            let _ = done.send(());
        });
        returned
            .recv_timeout(std::time::Duration::from_secs(10))
            .expect("the flush returned");
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
        })
        .unwrap();
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
        })
        .unwrap();
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

    /// What a notifier in a test was handed: the summary of each announcement, in order.
    struct Announced(Arc<Mutex<Vec<String>>>);

    impl crate::sandbox::notify_sink::Sink for Announced {
        fn deliver(&mut self, summary: &str, _: &str, _: Option<u32>) -> Result<Option<u32>, ()> {
            lock(&self.0).push(summary.to_string());
            Ok(None)
        }
    }

    /// The summaries of what `blocks` announce, sent as the proxy sends them.
    fn announced(blocks: Vec<Block>) -> Vec<String> {
        use crate::notify::{NotifyMode, NotifyPolicy};
        let seen = Arc::new(Mutex::new(Vec::new()));
        let notifier = Arc::new(Notifier::recording(
            NotifyPolicy::uniform(NotifyMode::Once),
            Box::new(Announced(Arc::clone(&seen))),
        ));
        let (events, applier) = spawn_joinable(Sinks {
            notifier: Some(Arc::clone(&notifier)),
            ..Sinks::default()
        });
        for block in blocks {
            events.send(ProxyEvent::Refusal(block));
        }
        // Every reporter gone, the applying side ends and lets go of the notifier, whose drop
        // delivers what it holds.
        drop(events);
        applier.join().unwrap();
        drop(
            Arc::try_unwrap(notifier)
                .map_err(|_| "the notifier is still shared")
                .unwrap(),
        );
        lock(&seen).clone()
    }

    /// A network refusal of `subject`, as the proxy announces one.
    fn refusal(subject: &str) -> Block {
        Block {
            event: NotifyEvent::Network,
            subject: subject.into(),
            reason: "denied-default".into(),
            detail: "no rule in the network policy allows this host".into(),
            fix: String::new(),
        }
    }

    /// An announcement no proxy can have made is dropped on arrival: another lens's refusal, or a
    /// field longer than any the proxy writes. The longest the proxy writes is still announced.
    #[test]
    fn an_announcement_no_proxy_can_have_made_is_dropped() {
        // `tag`, padded to `len` bytes.
        let sized = |tag: &str, len: usize| format!("{tag}{}", "x".repeat(len - tag.len()));
        let host = sized("honest-", MAX_FIELD);
        let mut blocks = vec![Block {
            subject: format!("{host}:65535"),
            fix: format!(
                "sbx net allow http://[{host}]:65535 --app {}",
                "a".repeat(255)
            ),
            ..refusal("")
        }];
        blocks.push(refusal(&sized("subject-at-", MAX_ANNOUNCED)));
        blocks.push(refusal(&sized("subject-over-", MAX_ANNOUNCED + 1)));
        for (tag, len, admitted) in [
            ("fix", MAX_ANNOUNCED, "at"),
            ("fix", MAX_ANNOUNCED + 1, "over"),
            ("reason", MAX_FIELD, "at"),
            ("reason", MAX_FIELD + 1, "over"),
            ("detail", MAX_FIELD, "at"),
            ("detail", MAX_FIELD + 1, "over"),
        ] {
            let mut block = refusal(&format!("{tag}-{admitted}.example.com:443"));
            let field = match tag {
                "fix" => &mut block.fix,
                "reason" => &mut block.reason,
                _ => &mut block.detail,
            };
            *field = "x".repeat(len);
            blocks.push(block);
        }
        for event in NotifyEvent::ALL
            .into_iter()
            .filter(|e| *e != NotifyEvent::Network)
        {
            blocks.push(Block {
                event,
                ..refusal(&format!("{}.example.com:443", event.as_str()))
            });
        }

        let out = announced(blocks);
        let summaries: Vec<&str> = out
            .iter()
            .map(|s| s.strip_prefix("Blocked: ").unwrap_or(s))
            .collect();
        let expected = [
            "honest-",
            "subject-at-",
            "fix-at.",
            "reason-at.",
            "detail-at.",
        ];
        assert_eq!(summaries.len(), expected.len(), "{:?}", summaries);
        for (summary, expected) in summaries.iter().zip(expected) {
            assert!(
                summary.starts_with(expected),
                "{summary:.40} for {expected}"
            );
        }
    }

    /// A signer's record longer than the proxy cuts one is dropped on arrival; the longest the proxy
    /// sends is kept.
    #[test]
    fn a_signer_detail_longer_than_the_proxy_cuts_one_is_dropped() {
        let ring = Arc::new(SignerRing::new(SIGNER_RING_CAP));
        let events = spawn(Sinks {
            signer_log: Some(Arc::clone(&ring)),
            ..Sinks::default()
        })
        .unwrap();
        let longest = crate::sandbox::signer_control::signer_detail(
            "demo",
            "GET api.example.com/",
            Some(&"\u{1f980}".repeat(100_000)),
            &[],
        );
        assert!(longest.len() <= MAX_SIGNER_DETAIL, "{}", longest.len());
        for detail in [
            longest,
            "x".repeat(MAX_SIGNER_DETAIL),
            "y".repeat(MAX_SIGNER_DETAIL + 1),
        ] {
            events.send(ProxyEvent::Signer {
                kind: SignerKind::Sign,
                detail,
            });
        }
        events.flush();
        let kept = ring.snapshot(None).events;
        assert_eq!(kept.len(), 2, "{kept:?}");
        assert!(kept[1].detail.starts_with('x'));
    }

    /// The queue holds a bounded number of bytes: a sender waits while the events already queued own
    /// too many, and goes on once they are written. One event heavier than the whole bound is queued
    /// when nothing else is waiting, rather than never.
    #[test]
    fn a_sender_waits_while_the_queued_events_own_too_many_bytes() {
        let (proxy, supervisor) = UnixStream::pair().unwrap();
        // Nothing reads the channel yet, so the first event stays in flight: the socket's own buffer
        // holds its writer until the applying side starts.
        let emitter = emitter(proxy, Keeps::of(&Sinks::default())).unwrap();
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
            "a second heavy event must wait for the first to be written"
        );
        let applier = applying(Sinks::default(), supervisor).unwrap();
        finished
            .recv_timeout(std::time::Duration::from_secs(30))
            .expect("the waiting sender goes on once the first event is written");
        waiting.join().unwrap();
        drop(emitter);
        applier.join().unwrap();
    }

    /// Every part of a capture carrying something the others do not: bytes that are no UTF-8, a
    /// length of its own, and a cut flag that alternates.
    fn captured(seq: u64) -> Masked {
        let part = |n: u8| CaptureBytes {
            bytes: (0..=255u8)
                .cycle()
                .skip(usize::from(n))
                .take(300 + usize::from(n))
                .collect(),
            truncated: n.is_multiple_of(2),
        };
        crate::sandbox::control::Capture {
            seq,
            req_head: part(0),
            injected: part(1),
            req_body: part(2),
            res_head: part(3),
            res_body: part(4),
            ws_up: part(5),
            ws_down: part(6),
        }
        .mask(&[], "api.example.com")
    }

    /// One event of each kind, every field away from its default and every text field holding
    /// something JSON has to escape.
    fn one_of_each() -> Vec<ProxyEvent> {
        vec![
            ProxyEvent::Stat {
                host: "api.example.com".into(),
                kind: StatKind::Blocked,
            },
            ProxyEvent::Refusal(Block {
                event: crate::notify::NotifyEvent::Network,
                subject: "api.example.com:8443".into(),
                reason: "denied-default".into(),
                detail: "a \"quoted\" \u{1b}[31m sentence\n".into(),
                fix: "sbx net allow api.example.com:8443".into(),
            }),
            ProxyEvent::Signer {
                kind: SignerKind::Refuse,
                detail: "demo: GET api.example.com/ \u{0}".into(),
            },
            ProxyEvent::Logged {
                id: 7,
                entry: LogEntry {
                    muted: true,
                    host: "api.example.com".into(),
                    port: 8443,
                    method: Some("PATCH".into()),
                    path: Some("/v1/é?q=\u{7f}".into()),
                    verdict: LogVerdict::Resolved,
                    reason: "outbound-secret".into(),
                    proto: Proto::Dns,
                    http_ver: HttpVer::H2,
                    rpc: RpcKind::GrpcWeb,
                },
            },
            ProxyEvent::Status { id: 7, status: 418 },
            ProxyEvent::CaptureExpected { id: 7 },
            ProxyEvent::CaptureFiled {
                id: 7,
                capture: captured(7),
            },
            ProxyEvent::CaptureGrew {
                id: 8,
                capture: captured(8),
            },
            ProxyEvent::SecretSeen {
                id: 7,
                name: "GITHUB_TOKEN".into(),
                way: SecretWay::Back,
            },
            ProxyEvent::FlowOpened {
                id: 3,
                host: "db.internal".into(),
                port: 5432,
                proto: Proto::Tcp,
            },
            ProxyEvent::FlowCounts(vec![(3, u64::MAX, 0), (4, 1, 2)]),
            ProxyEvent::FlowClosed { id: 3 },
        ]
    }

    /// The kind of `event`. Exhaustive, so a kind added to [`ProxyEvent`] fails to compile here
    /// until it is named, and then [`one_of_each`] has to carry it for the count below to hold.
    fn kind(event: &ProxyEvent) -> &'static str {
        match event {
            ProxyEvent::Stat { .. } => "stat",
            ProxyEvent::Refusal(_) => "refusal",
            ProxyEvent::Signer { .. } => "signer",
            ProxyEvent::Logged { .. } => "logged",
            ProxyEvent::Status { .. } => "status",
            ProxyEvent::CaptureExpected { .. } => "capture-expected",
            ProxyEvent::CaptureFiled { .. } => "capture-filed",
            ProxyEvent::CaptureGrew { .. } => "capture-grew",
            ProxyEvent::SecretSeen { .. } => "secret-seen",
            ProxyEvent::FlowOpened { .. } => "flow-opened",
            ProxyEvent::FlowCounts(_) => "flow-counts",
            ProxyEvent::FlowClosed { .. } => "flow-closed",
        }
    }

    /// Every kind of event crosses the channel as it was sent, capture bytes included, and frames
    /// written one after another are read back one by one, up to a clean end.
    #[test]
    fn every_kind_of_event_crosses_the_channel_unchanged() {
        let sent = one_of_each();
        let kinds: std::collections::BTreeSet<_> = sent.iter().map(kind).collect();
        assert_eq!(kinds.len(), 12, "one event of each kind: {kinds:?}");

        let mut stream = Vec::new();
        for event in one_of_each() {
            stream.extend(wire::encode(wire::Frame::Event(event)).unwrap().unwrap());
        }
        stream.extend(wire::encode(wire::Frame::Barrier(9)).unwrap().unwrap());
        let mut reading = stream.as_slice();
        for expected in sent {
            let what = kind(&expected);
            assert_eq!(
                wire::read(&mut reading).unwrap(),
                Some(wire::Frame::Event(expected)),
                "{what}"
            );
        }
        assert_eq!(
            wire::read(&mut reading).unwrap(),
            Some(wire::Frame::Barrier(9))
        );
        assert!(wire::read(&mut reading).unwrap().is_none(), "a clean end");
    }

    /// A frame the supervisor cannot read is refused, whatever is wrong with it: the channel then
    /// ends, and nothing after it is applied.
    #[test]
    fn a_frame_that_cannot_be_read_is_refused_and_ends_the_channel() {
        let frame = |event: ProxyEvent| wire::encode(wire::Frame::Event(event)).unwrap().unwrap();
        let stat = || ProxyEvent::Stat {
            host: "api.example.com".into(),
            kind: StatKind::Allow,
        };
        let header = |doc: u32, pieces: u32| -> Vec<u8> {
            let mut h = doc.to_le_bytes().to_vec();
            h.extend(pieces.to_le_bytes());
            h
        };
        // A capture event with one piece short, and a plain event with one piece too many.
        let short = {
            let whole = frame(ProxyEvent::CaptureFiled {
                id: 1,
                capture: captured(1),
            });
            let mut doc_len = [0u8; 4];
            doc_len.copy_from_slice(&whole[..4]);
            let doc_len = u32::from_le_bytes(doc_len) as usize;
            let mut cut = header(doc_len as u32, 6);
            cut.extend(&whole[8..8 + doc_len]);
            let mut rest = &whole[8 + doc_len..];
            for _ in 0..6 {
                let mut len = [0u8; 4];
                len.copy_from_slice(&rest[..4]);
                let len = u32::from_le_bytes(len) as usize;
                cut.extend(&rest[..4 + len]);
                rest = &rest[4 + len..];
            }
            cut
        };
        let extra = {
            let mut plain = frame(stat());
            plain[4] = 1;
            plain.extend(3u32.to_le_bytes());
            plain.extend(b"abc");
            plain
        };
        // A document whose length alone crosses the bound, though every byte of it is valid.
        let oversized_doc = {
            let doc = serde_json::to_vec(&wire::Frame::<wire::CaptureDoc>::Barrier(1)).unwrap();
            let len = wire::MAX_FRAME;
            let mut f = header(len as u32, 0);
            f.extend(&doc);
            f.resize(8 + len, b' ');
            f
        };
        // A piece whose length takes the frame past the bound.
        let oversized_piece = {
            let whole = frame(ProxyEvent::CaptureFiled {
                id: 1,
                capture: captured(1),
            });
            let mut f = whole.clone();
            let mut doc_len = [0u8; 4];
            doc_len.copy_from_slice(&whole[..4]);
            let at = 8 + u32::from_le_bytes(doc_len) as usize;
            f[at..at + 4].copy_from_slice(&(wire::MAX_FRAME as u32).to_le_bytes());
            f
        };
        // Each named by the refusal it must meet, so a check that went missing is not hidden by
        // another one failing further on.
        let cases: [(&str, Vec<u8>); 7] = [
            ("unexpected end of file", vec![1, 0, 0]),
            ("more pieces than any event carries", header(2, 8)),
            ("fewer pieces than the capture has parts", short),
            ("pieces the document does not name", extra),
            ("a document larger than a frame carries", oversized_doc),
            ("a frame larger than the channel carries", oversized_piece),
            ("a document that does not parse", {
                let mut f = header(5, 0);
                f.extend(b"{nope");
                f
            }),
        ];
        for (what, bytes) in cases {
            let refused = wire::read(&mut bytes.as_slice())
                .expect_err(what)
                .to_string();
            assert!(
                refused.contains(what),
                "{what}: refused for another reason: {refused}"
            );

            // Through the applying side: the frame after it is never applied, and the thread ends.
            let dir = TmpDir::new();
            let counts = stats(&dir);
            let (mut proxy, supervisor) = UnixStream::pair().unwrap();
            let applier = applying(
                Sinks {
                    stats: Some(Arc::clone(&counts)),
                    ..Sinks::default()
                },
                supervisor,
            )
            .unwrap();
            let mut after = bytes;
            after.extend(frame(stat()));
            // Written from a thread of its own: past the refused frame nothing reads the channel,
            // so a write larger than its buffer would never finish.
            let writer = std::thread::spawn(move || {
                let _ = proxy.write_all(&after);
            });
            applier.join().unwrap();
            writer.join().unwrap();
            assert!(counts.snapshot().is_empty(), "{what}: applied past it");
        }
    }

    /// An event too large to cross is one no request can have produced: the proxy drops it rather
    /// than write a frame the supervisor would refuse, and what follows it still crosses.
    #[test]
    fn an_event_too_large_to_cross_is_dropped_and_what_follows_still_crosses() {
        let dir = TmpDir::new();
        let counts = stats(&dir);
        let ring = Arc::new(SignerRing::new(SIGNER_RING_CAP));
        let events = spawn(Sinks {
            stats: Some(Arc::clone(&counts)),
            signer_log: Some(Arc::clone(&ring)),
            ..Sinks::default()
        })
        .unwrap();
        events.send(ProxyEvent::Signer {
            kind: SignerKind::Sign,
            detail: "x".repeat(wire::MAX_FRAME),
        });
        events.send(ProxyEvent::Stat {
            host: "api.example.com".into(),
            kind: StatKind::Allow,
        });
        events.flush();
        assert!(ring.snapshot(None).events.is_empty());
        assert_eq!(
            counts.snapshot().get("api.example.com").map(|c| c.allow),
            Some(1),
            "the event after the dropped one was applied"
        );
    }

    /// A report carrying more flow counts than the proxy sends in one is refused as it is read,
    /// before the counts past the bound are held; one carrying the bound crosses whole.
    #[test]
    fn a_report_of_more_flow_counts_than_the_proxy_sends_in_one_is_refused() {
        let counts = |n: usize| ProxyEvent::FlowCounts(vec![(1, 2, 3); n]);
        let frame = |n: usize| {
            wire::encode(wire::Frame::Event(counts(n)))
                .unwrap()
                .unwrap()
        };
        // Compared rather than printed: a failure would list thousands of counts.
        let read = wire::read(&mut frame(MAX_FLOW_COUNTS).as_slice()).unwrap();
        assert!(
            read == Some(wire::Frame::Event(counts(MAX_FLOW_COUNTS))),
            "the bound itself crosses whole"
        );
        let refused = wire::read(&mut frame(MAX_FLOW_COUNTS + 1).as_slice())
            .map(drop)
            .expect_err("one count past the bound was read")
            .to_string();
        assert!(
            refused.contains("a document that does not parse"),
            "refused for another reason: {refused}"
        );
    }

    /// A number, its two ends often: a generator of `u64` alone reaches neither.
    fn numbers() -> impl Strategy<Value = u64> {
        prop_oneof![Just(0), Just(u64::MAX), any::<u64>()]
    }

    /// Text a field may carry, of any characters: `\0`, the ones JSON escapes and the multi-byte
    /// ones among them.
    fn text() -> impl Strategy<Value = String> {
        proptest::collection::vec(any::<char>(), 0..24).prop_map(String::from_iter)
    }

    /// A transport, any of them.
    fn protos() -> impl Strategy<Value = Proto> {
        select(vec![
            Proto::Https,
            Proto::Http,
            Proto::Tcp,
            Proto::Other,
            Proto::Dns,
        ])
    }

    /// A capture as the proxy sends one: parts of any bytes, empty ones among them, each cut at its
    /// cap or not.
    fn masked() -> impl Strategy<Value = Masked> {
        let part = (
            prop_oneof![
                Just(Vec::new()),
                proptest::collection::vec(any::<u8>(), 1..48)
            ],
            any::<bool>(),
        )
            .prop_map(|(bytes, truncated)| CaptureBytes { bytes, truncated });
        (
            numbers(),
            proptest::array::uniform::<_, CAPTURE_PARTS>(part),
        )
            .prop_map(|(seq, parts)| Masked::received(seq, parts))
    }

    /// A logged decision, every field drawn.
    fn log_entries() -> impl Strategy<Value = LogEntry> {
        (
            any::<bool>(),
            text(),
            any::<u16>(),
            proptest::option::of(text()),
            proptest::option::of(text()),
            select(LogVerdict::ALL.to_vec()),
            text(),
            protos(),
            select(vec![HttpVer::H1, HttpVer::H2, HttpVer::Unknown]),
            select(vec![
                RpcKind::Grpc,
                RpcKind::GrpcWeb,
                RpcKind::Connect,
                RpcKind::None,
            ]),
        )
            .prop_map(
                |(muted, host, port, method, path, verdict, reason, proto, http_ver, rpc)| {
                    LogEntry {
                        muted,
                        host,
                        port,
                        method,
                        path,
                        verdict,
                        reason,
                        proto,
                        http_ver,
                        rpc,
                    }
                },
            )
    }

    /// An event of any kind, every field drawn. A flow report carries from none to the most one
    /// carries, the bound itself included.
    fn events() -> impl Strategy<Value = ProxyEvent> {
        let count = || (numbers(), numbers(), numbers());
        let counts = prop_oneof![
            proptest::collection::vec(count(), 0..8),
            count().prop_map(|count| vec![count; MAX_FLOW_COUNTS]),
        ];
        prop_oneof![
            (
                text(),
                select(vec![StatKind::Allow, StatKind::Deny, StatKind::Blocked])
            )
                .prop_map(|(host, kind)| ProxyEvent::Stat { host, kind }),
            (
                select(NotifyEvent::ALL.to_vec()),
                text(),
                text(),
                text(),
                text()
            )
                .prop_map(|(event, subject, reason, detail, fix)| {
                    ProxyEvent::Refusal(Block {
                        event,
                        subject,
                        reason,
                        detail,
                        fix,
                    })
                }),
            (select(vec![SignerKind::Sign, SignerKind::Refuse]), text())
                .prop_map(|(kind, detail)| ProxyEvent::Signer { kind, detail }),
            (numbers(), log_entries()).prop_map(|(id, entry)| ProxyEvent::Logged { id, entry }),
            (numbers(), any::<u16>()).prop_map(|(id, status)| ProxyEvent::Status { id, status }),
            numbers().prop_map(|id| ProxyEvent::CaptureExpected { id }),
            (numbers(), masked())
                .prop_map(|(id, capture)| ProxyEvent::CaptureFiled { id, capture }),
            (numbers(), masked()).prop_map(|(id, capture)| ProxyEvent::CaptureGrew { id, capture }),
            (
                numbers(),
                text(),
                select(vec![SecretWay::Out, SecretWay::Back])
            )
                .prop_map(|(id, name, way)| ProxyEvent::SecretSeen { id, name, way }),
            (numbers(), text(), any::<u16>(), protos()).prop_map(|(id, host, port, proto)| {
                ProxyEvent::FlowOpened {
                    id,
                    host,
                    port,
                    proto,
                }
            }),
            counts.prop_map(ProxyEvent::FlowCounts),
            numbers().prop_map(|id| ProxyEvent::FlowClosed { id }),
        ]
    }

    /// A frame of either kind, mostly events.
    fn frames() -> impl Strategy<Value = wire::Frame<Masked>> {
        prop_oneof![
            8 => events().prop_map(wire::Frame::Event),
            1 => numbers().prop_map(wire::Frame::Barrier),
        ]
    }

    /// What `frame` is, to name it in a failure without printing what it carries.
    fn frame_kind(frame: &wire::Frame<Masked>) -> &'static str {
        match frame {
            wire::Frame::Event(event) => kind(event),
            wire::Frame::Barrier(_) => "barrier",
        }
    }

    /// `frames` as they cross, one after another, and the offset each ends at, after the stream's
    /// start.
    fn stream_of(frames: &[wire::Frame<Masked>]) -> (Vec<u8>, Vec<usize>) {
        let mut stream = Vec::new();
        let mut ends = vec![0];
        for frame in frames.iter().cloned() {
            stream.extend(
                wire::encode(frame)
                    .unwrap()
                    .expect("a generated frame crosses"),
            );
            ends.push(stream.len());
        }
        (stream, ends)
    }

    /// Where a stream whose frames end at `ends` is cut, as `how` says: where a frame ends (the
    /// stream's start and its end among them), inside the header of one, or anywhere. A cut drawn
    /// anywhere seldom falls where a frame ends, too seldom to find what a clean end gets wrong.
    fn cut_at(ends: &[usize], &(how, which, within): &(u8, Index, Index)) -> usize {
        match how {
            0 => ends[which.index(ends.len())],
            1 if ends.len() > 1 => ends[which.index(ends.len() - 1)] + 1 + within.index(7),
            _ => which.index(ends[ends.len() - 1] + 1),
        }
    }

    /// `stream`, each of `mutations` made to it in turn: a byte replaced, the document length or
    /// the piece count of a frame starting at one of `starts` replaced, the stream cut, or bytes
    /// inserted into it.
    fn mutated(mut stream: Vec<u8>, starts: &[usize], mutations: &[(u8, Index, u32)]) -> Vec<u8> {
        for &(how, at, value) in mutations {
            let field = starts
                .get(at.index(starts.len().max(1)))
                .map(|start| start + if how == 1 { 0 } else { 4 })
                .filter(|field| field + 4 <= stream.len());
            match (how, field) {
                (0, _) if !stream.is_empty() => {
                    let at = at.index(stream.len());
                    stream[at] = value.to_le_bytes()[0];
                }
                (1, Some(field)) => {
                    stream[field..field + 4].copy_from_slice(&(value % 1024).to_le_bytes());
                }
                (2, Some(field)) => {
                    stream[field..field + 4].copy_from_slice(&(value % 9).to_le_bytes());
                }
                (3, _) => stream.truncate(at.index(stream.len() + 1)),
                _ => {
                    let at = at.index(stream.len() + 1);
                    stream.splice(at..at, value.to_le_bytes());
                }
            }
        }
        stream
    }

    proptest::proptest! {
        #![proptest_config(proptest::prelude::ProptestConfig::with_cases(512))]

        /// Frames written one after another read back as they were sent however the channel hands
        /// out their bytes, up to where it ends: each frame whole before that point comes back
        /// unchanged, then a clean end where the channel ends between two frames, and an early end
        /// of file anywhere else, never a frame made of part of one.
        #[test]
        fn frames_read_back_unchanged_in_any_pieces_up_to_where_the_channel_ends(
            sent in proptest::collection::vec(frames(), 0..6),
            sizes in proptest::collection::vec(1usize..64, 1..8),
            interrupts in proptest::collection::vec(proptest::bool::weighted(0.2), 1..8),
            cut in (0u8..3, any::<Index>(), any::<Index>()),
        ) {
            let (stream, ends) = stream_of(&sent);
            let cut = cut_at(&ends, &cut);
            let mut channel = Trickle::new(&stream[..cut], sizes, interrupts);
            for (i, expected) in sent.iter().enumerate().take_while(|&(i, _)| ends[i + 1] <= cut) {
                let read = wire::read(&mut channel);
                proptest::prop_assert!(
                    matches!(&read, Ok(Some(frame)) if frame == expected),
                    "frame {} ({}) read back as {:?}",
                    i,
                    frame_kind(expected),
                    read.map(|frame| frame.as_ref().map(frame_kind))
                );
            }
            let last = wire::read(&mut channel);
            if ends.contains(&cut) {
                proptest::prop_assert!(
                    matches!(last, Ok(None)),
                    "a stream ending between two frames, at {}, read as {:?}",
                    cut,
                    last.map(|frame| frame.as_ref().map(frame_kind))
                );
            } else {
                proptest::prop_assert!(
                    matches!(&last, Err(e) if e.kind() == io::ErrorKind::UnexpectedEof),
                    "a stream ending inside a frame, at {}, read as {:?}",
                    cut,
                    last.map(|frame| frame.as_ref().map(frame_kind))
                );
            }
        }

        /// Whatever bytes arrive, reading them comes to an end without a panic: each read returns a
        /// frame, a clean end or a refusal, and a frame takes at least its eight-byte header. The
        /// bytes are frames the proxy writes, then changed: a byte, a length, a piece count, the
        /// stream cut short or lengthened.
        #[test]
        fn any_bytes_are_read_to_an_end_without_a_panic(
            sent in proptest::collection::vec(frames(), 0..4),
            mutations in proptest::collection::vec((0u8..5, any::<Index>(), any::<u32>()), 1..5),
        ) {
            let (stream, ends) = stream_of(&sent);
            let stream = mutated(stream, &ends[..ends.len() - 1], &mutations);
            let mut channel = stream.as_slice();
            let mut read = 0;
            while let Ok(Some(_)) = wire::read(&mut channel) {
                read += 1;
                proptest::prop_assert!(
                    read <= stream.len() / 8,
                    "{} frames out of {} bytes",
                    read,
                    stream.len()
                );
            }
        }

        /// A frame announcing more than a frame carries is refused once the length that takes it
        /// past the bound is read, before any byte it announces: nothing is held for them. A frame
        /// reaching the bound exactly is not refused for its size. The length is the document's,
        /// or that of one of a capture's parts.
        #[test]
        fn a_frame_announcing_more_than_the_bound_is_refused_before_its_bytes_are_read(
            capture in masked(),
            part in 0..=CAPTURE_PARTS,
            over in prop_oneof![Just(0u32), Just(1), any::<u32>()],
        ) {
            let mut frame = wire::encode(wire::Frame::Event(ProxyEvent::CaptureFiled {
                id: 1,
                capture,
            }))
            .unwrap()
            .unwrap();
            let length_at = |at: usize| -> usize {
                let mut bytes = [0u8; 4];
                bytes.copy_from_slice(&frame[at..at + 4]);
                u32::from_le_bytes(bytes) as usize
            };
            proptest::prop_assert_eq!(length_at(4), CAPTURE_PARTS, "a capture crosses as its parts");
            // Where the length sits, how many bytes are read once it is, and the most it may say:
            // the document's is read with the piece count, eight bytes in all.
            let (field, read_by_then) = if part == CAPTURE_PARTS {
                (0, 8)
            } else {
                let mut at = 8 + length_at(0);
                for _ in 0..part {
                    at += 4 + length_at(at);
                }
                (at, at + 4)
            };
            let most = wire::MAX_FRAME - read_by_then;
            let announced = u32::try_from(most).unwrap().saturating_add(over);
            frame[field..field + 4].copy_from_slice(&announced.to_le_bytes());
            let mut rest = frame.as_slice();
            let read = wire::read(&mut rest).map(|frame| frame.as_ref().map(frame_kind));
            let consumed = frame.len() - rest.len();
            if over == 0 {
                proptest::prop_assert!(
                    matches!(&read, Err(e) if e.kind() == io::ErrorKind::UnexpectedEof),
                    "a frame at the bound read as {:?}",
                    read
                );
            } else {
                proptest::prop_assert!(
                    matches!(&read, Err(e) if e.kind() == io::ErrorKind::InvalidData),
                    "a frame past the bound read as {:?}",
                    read
                );
                proptest::prop_assert_eq!(consumed, read_by_then, "bytes read past the length");
            }
        }
    }
}
