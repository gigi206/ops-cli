//! What the supervisor tells the proxy about the state it decides with, and what the proxy answers.
//!
//! [`super::events`] carries the proxy's account of its own work, one way. This carries the other
//! direction: state the supervisor owns and the proxy decides with — the rules an operator loads
//! into a running session (`sbx net allow|deny|mute --session`, or an `ask` answered with
//! `--session`), and the answer to a request the proxy parks under `ask`. The proxy is to run in a
//! process of its own, so neither side holds the other's structures: each end reads its own end of
//! a socket ([`wire`]) on a thread of its own. Until the proxy moves the two ends are a pair within
//! one process, so every message already crosses as the bytes it will cross in then.
//!
//! **A rule is in force when the supervisor hears that it is.** The supervisor sends the whole
//! overlay under a version ([`Supervisor::push`]); the proxy's reader installs it and then says which
//! version it has installed; the supervisor waits for that before it answers the operator. So a
//! `--session` command that returns has a rule deciding the next request, and one whose proxy did
//! not confirm it says so rather than reporting a rule it cannot vouch for. The whole overlay rather
//! than the change, so a push that went unconfirmed is repaired by the next one.
//!
//! **What the proxy says is an account.** Once it runs apart it may be what an attacker controls,
//! and a proxy that confirms a rule it then ignores cannot be told apart from one that honours it.
//! What the confirmation buys is the ordering an honest proxy owes the operator; what binds a
//! compromised one is the supervisor's own check of every connection it makes on the proxy's behalf.
//! A confirmation is therefore never believed beyond the last version sent, and a message the
//! supervisor cannot read (one that does not parse, is longer than it reads, or hands it a
//! descriptor) ends the link: past it, the supervisor no longer knows what the proxy meant.
//!
//! **A parked request waits on the supervisor.** The proxy says what it would park
//! ([`Link::park`]) and blocks until the answer comes back. The supervisor lets it into the queue
//! the operator answers from, or denies it at once past the cap, and waits for the answer on a
//! thread of its own, up to the `ask_timeout`: the cap, the timeout and the notice announcing the
//! request are the supervisor's, and a proxy that sends more than it is owed only fills its own
//! queue. The reader that takes in parks is the one that takes in confirmations, so it waits on
//! nothing but the socket: a park it could not let in at once would hold every `--session` answer
//! behind it. What it answers on the spot, a deny or a declined refresh, waits at most
//! [`SEND_WAIT`] for room on the socket; a proxy that leaves no room for that long has stopped
//! reading, and the link ends.

mod wire;

use super::events::Emitter;
use super::inject::{CredentialRefresh, Started, Transfer};
use crate::allowlist::Rule;
use crate::sandbox::control::{PendingState, Verdict};
use crate::sandbox::locks::{locked, read_locked, write_locked};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io;
use std::os::fd::OwnedFd;
use std::sync::mpsc::{Receiver, Sender, channel};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, RwLock};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

/// How long the supervisor waits for the proxy to confirm an overlay, or a flush, before telling
/// whoever asked that it could not. The proxy's reader installs and confirms without waiting on
/// anything, so this is only ever reached by a proxy that has stopped reading. Below the control
/// socket's own ten-second bound, so the operator is told why rather than timing out.
const CONFIRM_WAIT: Duration = Duration::from_secs(5);

/// How long the supervisor waits for room to send the proxy one message before it takes the proxy
/// for one that has stopped reading, and ends the link. An honest proxy's reader hands whatever
/// could keep it from reading to a thread of its own. No longer than [`CONFIRM_WAIT`], so a push
/// that waited for room still answers the operator within it.
const SEND_WAIT: Duration = Duration::from_secs(5);
const _: () = assert!(SEND_WAIT.as_millis() <= CONFIRM_WAIT.as_millis());

/// The live `--session` rules, as the proxy folds them into the policy it decides with.
#[derive(Clone, Default, Serialize, Deserialize)]
pub(crate) struct Overlay {
    pub(crate) allow: Vec<Rule>,
    pub(crate) deny: Vec<Rule>,
    /// `dontaudit` rules: a denied request matching one is still refused, only its log line is
    /// suppressed.
    pub(crate) mute: Vec<Rule>,
}

impl Overlay {
    /// Whether no rule is loaded — the common case, in which the proxy decides with its policy as it
    /// was handed and builds nothing per request.
    pub(crate) fn is_empty(&self) -> bool {
        self.allow.is_empty() && self.deny.is_empty() && self.mute.is_empty()
    }
}

/// How the supervisor serves the requests a proxy parks: the queue the operator answers them from,
/// and the bounds the supervisor holds them to.
pub(crate) struct Parks {
    pub(crate) pending: Arc<PendingState>,
    /// The most requests parked at once; one more is denied without entering the queue.
    pub(crate) cap: usize,
    /// How long a parked request waits for its answer before it is denied (`[network]
    /// ask_timeout`); `None` waits until it is answered.
    pub(crate) timeout: Option<Duration>,
    /// Whether a parked request is announced on stderr (`[network] ask_notice`).
    pub(crate) notices: bool,
}

/// What the supervisor tells the proxy, with a re-resolved credential set as `S`: the [`Transfer`]
/// handed over, or, in the document that crosses, that transfer's own document as text, its
/// descriptors beside the message.
#[derive(Serialize, Deserialize)]
enum ToProxy<S = Transfer> {
    /// The whole overlay, as of `version`.
    Overlay { version: u64, overlay: Overlay },
    /// The answer to the request the proxy parked as `id`.
    Answer { id: u64, verdict: Verdict },
    /// The answer to the refresh the proxy asked for as `id`: the re-resolved set, or nothing when
    /// the supervisor declined or found nothing new.
    Refreshed { id: u64, set: Option<S> },
    /// Apply everything reported so far, then say so under the same `id`.
    Flush { id: u64 },
}

impl<S> ToProxy<S> {
    /// This message with the set it carries, if any, made into what `f` makes of it.
    fn try_map_set<T, E>(self, f: impl FnOnce(S) -> Result<T, E>) -> Result<ToProxy<T>, E> {
        Ok(match self {
            ToProxy::Overlay { version, overlay } => ToProxy::Overlay { version, overlay },
            ToProxy::Answer { id, verdict } => ToProxy::Answer { id, verdict },
            ToProxy::Refreshed { id, set } => ToProxy::Refreshed {
                id,
                set: set.map(f).transpose()?,
            },
            ToProxy::Flush { id } => ToProxy::Flush { id },
        })
    }
}

impl ToProxy {
    /// This message as it crosses: its document, and the descriptors it hands over beside it.
    fn encode(self) -> io::Result<(Vec<u8>, Vec<OwnedFd>)> {
        let mut handed = Vec::new();
        let doc = self.try_map_set(|set| {
            let (bytes, fds) = set.into_parts();
            handed = fds;
            String::from_utf8(bytes)
                .map_err(|_| wire::invalid("a credential document that is not text"))
        })?;
        let doc = serde_json::to_vec(&doc)
            .map_err(|_| wire::invalid("a message that does not encode"))?;
        Ok((doc, handed))
    }

    /// The message `doc` holds, with the descriptors `fds` handed over beside it. Those of a message
    /// that hands over none are closed.
    fn decode(doc: &[u8], fds: Vec<OwnedFd>) -> io::Result<Self> {
        let doc: ToProxy<String> = serde_json::from_slice(doc)
            .map_err(|_| wire::invalid("a message that does not parse"))?;
        let mut fds = Some(fds);
        doc.try_map_set(|text| {
            Ok(Transfer::from_parts(
                text.into_bytes(),
                fds.take().unwrap_or_default(),
            ))
        })
    }
}

/// What the proxy tells the supervisor.
#[derive(Serialize, Deserialize)]
enum ToSupervisor {
    /// The overlay in force is the one sent as `version`, or a later one.
    Installed { version: u64 },
    /// A request no rule decides, to be asked about; answered under the same `id`. `path` is
    /// already masked of the credentials the proxy knows.
    Park {
        id: u64,
        host: String,
        port: u16,
        path: String,
    },
    /// An injection target refused the credential it was given: re-resolve, if the supervisor's
    /// bounds allow. Answered under the same `id`.
    Refresh { id: u64 },
    /// Everything the proxy reported before the flush the supervisor asked for as `id` is applied.
    Flushed { id: u64 },
}

/// An answer the proxy waits for, handed to the request that asked.
enum Reply {
    Verdict(Verdict),
    Refreshed(Option<Transfer>),
}

/// The proxy's end: the overlay in force, and the way back to the supervisor.
pub(crate) struct Link {
    side: Arc<ProxySide>,
}

/// What the proxy's end shares with its reader.
struct ProxySide {
    /// The overlay in force and the version it was sent as, swapped whole so a request reads one
    /// coherent overlay with one lock.
    overlay: RwLock<(u64, Arc<Overlay>)>,
    /// This end of the link, or `None` for an end no supervisor reaches.
    socket: Option<wire::Socket>,
    /// What this proxy has asked and not yet heard back about, each waiting for the answer sent
    /// under its id.
    waiting: Mutex<Waiting>,
}

/// The questions a proxy has asked the supervisor and not yet heard back about.
#[derive(Default)]
struct Waiting {
    /// The id the next one is sent under.
    next: u64,
    /// Where each one's answer is handed over, by id.
    replies: HashMap<u64, Sender<Reply>>,
}

impl ProxySide {
    /// An end on `socket`, holding an empty overlay until the supervisor sends one.
    fn on(socket: Option<wire::Socket>) -> Self {
        ProxySide {
            overlay: RwLock::new((0, Arc::new(Overlay::default()))),
            socket,
            waiting: Mutex::new(Waiting::default()),
        }
    }

    /// Send `message` to the supervisor. An error when this end reaches none, or the link has ended.
    fn say(&self, message: &ToSupervisor) -> io::Result<()> {
        let socket = self
            .socket
            .as_ref()
            .ok_or_else(|| io::Error::from(io::ErrorKind::NotConnected))?;
        let doc = serde_json::to_vec(message)
            .map_err(|_| wire::invalid("a message that does not encode"))?;
        socket.send_up(&doc)
    }
}

impl Link {
    /// An end no supervisor reaches: its overlay is empty for good. What a proxy is built with
    /// before a launch wires it, and all a test that loads no rule needs.
    pub(crate) fn detached() -> Self {
        Link {
            side: Arc::new(ProxySide::on(None)),
        }
    }

    /// The overlay in force. Taken once per decision, so a push landing mid-decision is the next
    /// decision's.
    pub(crate) fn overlay(&self) -> Arc<Overlay> {
        Arc::clone(&read_locked(&self.side.overlay).1)
    }

    /// Ask the supervisor about a request no rule decides, and wait for the answer — as long as the
    /// supervisor lets it wait. A deny when the answer cannot come: an end no supervisor reaches, or
    /// a link that closed while the request waited.
    ///
    /// `path` arrives masked of the credentials the proxy knows, and both it and `host` are sent cut
    /// to what the supervisor's queue shows of them ([`shown`]), so the cut never leaves part of a
    /// credential behind unmasked.
    pub(crate) fn park(&self, host: &str, port: u16, path: &str) -> Verdict {
        match self.ask(|id| ToSupervisor::Park {
            id,
            host: shown(host).to_string(),
            port,
            path: shown(path).to_string(),
        }) {
            Some(Reply::Verdict(verdict)) => verdict,
            _ => Verdict::Deny,
        }
    }

    /// Ask the supervisor to re-resolve the credentials, and wait for the set it hands back: nothing
    /// when it declined, found nothing new, or cannot answer.
    pub(crate) fn refresh(&self) -> Option<Transfer> {
        match self.ask(|id| ToSupervisor::Refresh { id }) {
            Some(Reply::Refreshed(set)) => set,
            _ => None,
        }
    }

    /// Send the question `message` builds under a fresh id, and wait for its answer. `None` when the
    /// answer cannot come: an end no supervisor reaches, or a link that closed meanwhile.
    fn ask(&self, message: impl FnOnce(u64) -> ToSupervisor) -> Option<Reply> {
        let (id, reply) = {
            let mut waiting = locked(&self.side.waiting);
            waiting.next += 1;
            let id = waiting.next;
            let (tx, rx) = channel();
            waiting.replies.insert(id, tx);
            (id, rx)
        };
        // Registered before it is sent, so an answer arriving at once finds where to go.
        if self.side.say(&message(id)).is_err() {
            locked(&self.side.waiting).replies.remove(&id);
            return None;
        }
        reply.recv().ok()
    }

    /// Keep the reader from installing what it is sent, and so from confirming it, until the guard
    /// is dropped: how a test holds a push unconfirmed for as long as it needs.
    #[cfg(test)]
    pub(crate) fn stall_installs(&self) -> std::sync::RwLockReadGuard<'_, (u64, Arc<Overlay>)> {
        read_locked(&self.side.overlay)
    }
}

impl Drop for Link {
    fn drop(&mut self) {
        // The supervisor's reader reads the end of the link on this, and ends the link with it, so
        // both readers end with the proxy.
        if let Some(socket) = &self.side.socket {
            socket.shutdown_write();
        }
    }
}

/// `text` cut to as much of it as the supervisor's queue shows. The queue keeps
/// [`SANITIZED_CHARS`](crate::sandbox::SANITIZED_CHARS) characters and marks a longer value as cut
/// ([`crate::sandbox::sanitize`]), so one character more shows the same row, and a message never
/// outgrows the link however long the value is.
fn shown(text: &str) -> &str {
    text.char_indices()
        .nth(crate::sandbox::SANITIZED_CHARS + 1)
        .map_or(text, |(at, _)| &text[..at])
}

/// The supervisor's end: how it reaches the proxy it serves.
#[derive(Clone)]
pub(crate) struct Supervisor {
    side: Arc<SupervisorSide>,
}

/// What the supervisor's end shares with its reader.
struct SupervisorSide {
    /// The way to the proxy, until the link ends: taken out then, so nothing is sent after it.
    down: Mutex<Option<Arc<wire::Socket>>>,
    heard: Mutex<Heard>,
    changed: Condvar,
    /// How the requests this proxy parks are served, or `None` when nobody answers them: each is
    /// then denied as it arrives.
    parks: Option<Parks>,
    /// How the proxy's requests to re-resolve its credentials are served, or `None` when the
    /// launch has nothing to re-resolve: each is then declined as it arrives.
    refresh: Option<Arc<CredentialRefresh>>,
    /// How a thread of this end is started: [`named_thread`], or in a test one the host refuses.
    threads: fn(&str) -> std::thread::Builder,
    /// The way to the one thread that runs the admitted refreshes, while it runs.
    refreshes: Mutex<Option<Sender<(u64, Started)>>>,
}

/// What the supervisor knows of the proxy's overlay and of its flushes.
#[derive(Default)]
struct Heard {
    /// The last version sent, the most a confirmation is believed for.
    sent: u64,
    /// The version the proxy last said it has installed.
    installed: u64,
    /// The last flush asked for, the most an answer is believed for.
    flushes: u64,
    /// The last flush the proxy said it has done.
    flushed: u64,
    /// The link has ended: nothing more will be installed or flushed.
    closed: bool,
}

impl Supervisor {
    /// The version the proxy last confirmed, so an overlay it already holds is not sent again.
    pub(crate) fn installed(&self) -> u64 {
        locked(&self.side.heard).installed
    }

    /// Send the overlay as `version` and wait until the proxy confirms it is in force. An error
    /// when the proxy is gone or has not confirmed within [`CONFIRM_WAIT`]: the overlay may then not
    /// be deciding its requests, and whoever asked for it must be told so.
    pub(crate) fn push(&self, version: u64, overlay: Overlay) -> io::Result<()> {
        // Taken before the send, which may itself wait for room, so the whole push is bounded.
        let deadline = Instant::now() + CONFIRM_WAIT;
        // Counted as sent before it is, so a confirmation that arrives the instant it is installed
        // is already believed.
        {
            let mut heard = locked(&self.side.heard);
            heard.sent = heard.sent.max(version);
        }
        send(&self.side, ToProxy::Overlay { version, overlay }).map_err(|_| gone())?;
        let heard = self.until(deadline, |heard| heard.installed >= version);
        if heard.installed >= version {
            return Ok(());
        }
        if heard.closed {
            return Err(gone());
        }
        Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "the proxy did not confirm the session rules",
        ))
    }

    /// Wait until everything the proxy reported before this call is applied, the link has ended, or
    /// [`CONFIRM_WAIT`] has passed: what the proxy reports is applied on this side, and a reader of
    /// it (the session's end, `--net-learn`) needs what the proxy decided, not what had arrived.
    pub(crate) fn flush(&self) {
        let deadline = Instant::now() + CONFIRM_WAIT;
        let id = {
            let mut heard = locked(&self.side.heard);
            heard.flushes += 1;
            heard.flushes
        };
        if send(&self.side, ToProxy::Flush { id }).is_ok() {
            drop(self.until(deadline, |heard| heard.flushed >= id));
        }
    }

    /// What this end has heard, once `reached` holds of it, the link has ended, or `deadline` has
    /// passed.
    fn until(&self, deadline: Instant, reached: impl Fn(&Heard) -> bool) -> MutexGuard<'_, Heard> {
        let mut heard = locked(&self.side.heard);
        loop {
            if reached(&heard) || heard.closed {
                return heard;
            }
            let Some(left) = deadline
                .checked_duration_since(Instant::now())
                .filter(|left| !left.is_zero())
            else {
                return heard;
            };
            heard = self
                .side
                .changed
                .wait_timeout(heard, left)
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .0;
        }
    }
}

/// What a push meets once the proxy has let go of its end.
fn gone() -> io::Error {
    io::Error::new(io::ErrorKind::BrokenPipe, "the proxy is gone")
}

/// Join a proxy to the supervisor that serves it, starting the reader on each side, with the
/// requests the proxy parks served as `parks` says, its refreshes by `refresh`, and its flushes of
/// what it reported through `events`. Both readers end once the proxy lets go of its [`Link`], and
/// so does every thread waiting on a request it parked.
pub(crate) fn serving(
    parks: Parks,
    refresh: Option<Arc<CredentialRefresh>>,
    events: Option<Emitter>,
) -> io::Result<(Link, Supervisor)> {
    let (link, supervisor, _) = start(Some(parks), refresh, events, named_thread)?;
    Ok((link, supervisor))
}

/// [`serving`] with nobody to answer a parked request or a refresh: all a test of the rules alone
/// needs.
#[cfg(test)]
pub(crate) fn pair() -> (Link, Supervisor) {
    let (link, supervisor, _) = start(None, None, None, named_thread).expect("a link starts");
    (link, supervisor)
}

/// [`serving`] with only the refreshes served: all a test of the refresh needs.
#[cfg(test)]
pub(crate) fn refreshing(refresh: Arc<CredentialRefresh>) -> (Link, Supervisor) {
    let (link, supervisor, _) =
        start(None, Some(refresh), None, named_thread).expect("a link starts");
    (link, supervisor)
}

/// A thread of the supervisor's end, named for what it waits on.
fn named_thread(name: &str) -> std::thread::Builder {
    std::thread::Builder::new().name(name.to_string())
}

/// The two readers of a link: the proxy's, and the supervisor's, which returns why the link ended
/// when the proxy's end is not what ended it.
type Readers = (JoinHandle<()>, JoinHandle<io::Result<()>>);

/// [`serving`], keeping the two readers' handles, with the way the supervisor's end starts its
/// threads passed in.
fn start(
    parks: Option<Parks>,
    refresh: Option<Arc<CredentialRefresh>>,
    events: Option<Emitter>,
    threads: fn(&str) -> std::thread::Builder,
) -> io::Result<(Link, Supervisor, Readers)> {
    let (down, up) = wire::Socket::pair()?;
    let (supervisor, supervisor_reader) = supervise(down, parks, refresh, threads)?;
    let (link, proxy_reader) = attend(up, events)?;
    Ok((link, supervisor, (proxy_reader, supervisor_reader)))
}

/// The proxy's half of a link, on its end `socket`: the reader that installs and hands over what
/// the supervisor sends, and the thread that answers the supervisor's flushes of what `events`
/// reported. Both end with the link.
fn attend(socket: wire::Socket, events: Option<Emitter>) -> io::Result<(Link, JoinHandle<()>)> {
    let side = Arc::new(ProxySide::on(Some(socket)));
    let (flushes, asked) = channel();
    {
        let side = Arc::clone(&side);
        named_thread("sbx-link-flush")
            .spawn(move || run_flushes(&side, events.as_ref(), &asked))?;
    }
    let reader = {
        let side = Arc::clone(&side);
        named_thread("sbx-link-proxy").spawn(move || read_supervisor(&side, &flushes))?
    };
    Ok((Link { side }, reader))
}

/// The supervisor's half of a link, on its end `socket`: the reader that takes in what the proxy
/// says, with the requests it parks served as `parks` says and its refreshes by `refresh`, and the
/// thread that runs the refreshes.
fn supervise(
    socket: wire::Socket,
    parks: Option<Parks>,
    refresh: Option<Arc<CredentialRefresh>>,
    threads: fn(&str) -> std::thread::Builder,
) -> io::Result<(Supervisor, JoinHandle<io::Result<()>>)> {
    socket.send_wait(SEND_WAIT)?;
    let socket = Arc::new(socket);
    let side = Arc::new(SupervisorSide {
        down: Mutex::new(Some(Arc::clone(&socket))),
        heard: Mutex::new(Heard::default()),
        changed: Condvar::new(),
        parks,
        refresh,
        threads,
        refreshes: Mutex::new(None),
    });
    // One thread runs every refresh, started here and ended with the link, rather than one per
    // refresh: a process a refresh starts — a signer handed a new key — is tied to the thread that
    // started it, since its cage arms the parent-death signal, which follows that thread and not
    // the process. A thread that ended with its refresh would take the new signer down with it.
    if let Some(refresh) = side.refresh.clone() {
        let (jobs, queued) = channel();
        let running = Arc::clone(&side);
        if threads("sbx-refresh")
            .spawn(move || run_refreshes(&running, &refresh, &queued))
            .is_ok()
        {
            *locked(&side.refreshes) = Some(jobs);
        }
    }
    let reading = Arc::clone(&side);
    match named_thread("sbx-link-supervisor").spawn(move || read_proxy(&reading, &socket)) {
        Ok(reader) => Ok((Supervisor { side }, reader)),
        Err(e) => {
            // The refresh thread ends once nothing can queue a refresh for it.
            locked(&side.refreshes).take();
            Err(e)
        }
    }
}

/// The proxy's reader: install what the supervisor sends, then say so, hand each answer to the
/// request waiting on it, and each flush to the flush thread. Ends with the link, or at the first
/// message it cannot read, and ends the link then; a request still waiting is denied.
fn read_supervisor(side: &ProxySide, flushes: &Sender<u64>) {
    let Some(socket) = &side.socket else {
        return;
    };
    while let Ok(Some((doc, fds))) = socket.recv_down() {
        let Ok(message) = ToProxy::decode(&doc, fds) else {
            break;
        };
        match message {
            ToProxy::Overlay { version, overlay } => {
                let installed = {
                    let mut current = write_locked(&side.overlay);
                    if version > current.0 {
                        *current = (version, Arc::new(overlay));
                    }
                    current.0
                };
                // Confirmed only once installed: the supervisor answers the operator on this, and
                // the next request must be decided with what it confirmed.
                let _ = side.say(&ToSupervisor::Installed { version: installed });
            }
            ToProxy::Answer { id, verdict } => hand_over(side, id, Reply::Verdict(verdict)),
            ToProxy::Refreshed { id, set } => hand_over(side, id, Reply::Refreshed(set)),
            // Not flushed here: the reader would stop reading for as long as the flush takes.
            ToProxy::Flush { id } => {
                let _ = flushes.send(id);
            }
        }
    }
    // Ended before the waiting requests are let go, so one that asks from here on fails to send
    // rather than waiting for an answer nobody will read.
    socket.shutdown();
    locked(&side.waiting).replies.clear();
}

/// Hand the answer sent under `id` to the request waiting for it, if one still is.
fn hand_over(side: &ProxySide, id: u64, reply: Reply) {
    if let Some(waiting) = locked(&side.waiting).replies.remove(&id) {
        let _ = waiting.send(reply);
    }
}

/// The proxy's flush thread: for each flush the supervisor asks for, wait until everything
/// reported through `events` before it is applied, then say so. With nothing reporting there is
/// nothing to wait for. Ends with the reader.
fn run_flushes(side: &ProxySide, events: Option<&Emitter>, asked: &Receiver<u64>) {
    for id in asked {
        if let Some(events) = events {
            events.flush();
        }
        let _ = side.say(&ToSupervisor::Flushed { id });
    }
}

/// The supervisor's reader: take in what the proxy confirms, the requests it parks, its refreshes
/// and its flushes. Ends with the link, or at the first message it cannot read, which it returns.
/// Either way it then ends the link, which ends the proxy's reader, and lets go of the requests the
/// proxy had parked, which ends the threads waiting on them.
fn read_proxy(side: &Arc<SupervisorSide>, socket: &wire::Socket) -> io::Result<()> {
    let ended = loop {
        let doc = match socket.recv_up() {
            Ok(Some(doc)) => doc,
            Ok(None) => break Ok(()),
            Err(e) => break Err(e),
        };
        let Ok(message) = serde_json::from_slice(&doc) else {
            break Err(wire::invalid("a message that does not parse"));
        };
        match message {
            ToSupervisor::Installed { version } => {
                let mut heard = locked(&side.heard);
                heard.installed = heard.installed.max(version.min(heard.sent));
                side.changed.notify_all();
            }
            ToSupervisor::Park {
                id,
                host,
                port,
                path,
            } => serve_park(side, id, &host, port, &path),
            ToSupervisor::Refresh { id } => serve_refresh(side, id),
            ToSupervisor::Flushed { id } => {
                let mut heard = locked(&side.heard);
                heard.flushed = heard.flushed.max(id.min(heard.flushes));
                side.changed.notify_all();
            }
        }
    };
    locked(&side.down).take();
    socket.shutdown();
    locked(&side.heard).closed = true;
    side.changed.notify_all();
    // The refresh thread ends once the refresh it may be running does.
    locked(&side.refreshes).take();
    // Nobody is left to hear these answers, and a thread waiting without a timeout would otherwise
    // outlive the proxy that parked the request.
    if let Some(parks) = &side.parks {
        parks.pending.answer_all(Verdict::Deny);
    }
    ended
}

/// Let a request the proxy parked into the queue and wait for its answer on a thread of its own, or
/// deny it at once: nobody serves parks, or the queue is full. When no thread can be started, the
/// request leaves the queue with whatever answer it was given in between.
fn serve_park(side: &Arc<SupervisorSide>, id: u64, host: &str, port: u16, path: &str) {
    let Some(parks) = &side.parks else {
        return answer(side, id, Verdict::Deny);
    };
    let Some(parked) = parks.pending.enqueue(host, port, path, parks.cap) else {
        return answer(side, id, Verdict::Deny);
    };
    let (pending, timeout, notices) = (Arc::clone(&parks.pending), parks.timeout, parks.notices);
    let waiter = Arc::clone(side);
    // Handed over once the thread exists: a thread that cannot be started leaves the request here,
    // with the answer an operator may already have given it.
    let (hand, handed) = channel::<crate::sandbox::control::Parked>();
    let started = (side.threads)("sbx-park-wait").spawn(move || {
        let Ok(parked) = handed.recv() else {
            return;
        };
        // Printed here rather than by the reader, which must not wait on a stderr that blocks.
        if notices {
            let (head, allow, deny) = park_notice(
                &crate::sandbox::control::format_id(
                    std::process::id(),
                    parked.seq,
                    crate::sandbox::control::incarnation(),
                ),
                &parked,
            );
            super::print_egress_notice(&head, &[("allow", &allow), ("deny", &deny)]);
        }
        let verdict = pending.wait(parked, timeout);
        answer(&waiter, id, verdict);
    });
    match started {
        Ok(_) => {
            let _ = hand.send(parked);
        }
        Err(_) => answer(side, id, parks.pending.withdraw(parked)),
    }
}

/// Hand a refresh the proxy asked for to the refresh thread, or decline at once: nothing to
/// re-resolve, the refresher's bounds refuse it ([`CredentialRefresh::start`]), or no refresh thread
/// could be started.
fn serve_refresh(side: &SupervisorSide, id: u64) {
    let Some(refresh) = &side.refresh else {
        return refreshed(side, id, None);
    };
    let Some(started) = refresh.start() else {
        return refreshed(side, id, None);
    };
    // A refresh that cannot be handed over drops its admission with it, so the next is admitted.
    let queued = locked(&side.refreshes)
        .as_ref()
        .is_some_and(|jobs| jobs.send((id, started)).is_ok());
    if !queued {
        refreshed(side, id, None);
    }
}

/// The refresh thread: run each admitted refresh in turn and answer it. Ends when the link does.
fn run_refreshes(
    side: &SupervisorSide,
    refresh: &CredentialRefresh,
    queued: &Receiver<(u64, Started)>,
) {
    for (id, started) in queued {
        // A resolver that panics is answered like one that failed: the proxy waits for this answer,
        // and nothing else will send it.
        let set =
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| refresh.finish(started)))
                .unwrap_or(None);
        refreshed(side, id, set);
    }
}

/// Send the answer to the request the proxy parked as `id`, unless the link has ended.
fn answer(side: &SupervisorSide, id: u64, verdict: Verdict) {
    let _ = send(side, ToProxy::Answer { id, verdict });
}

/// Answer the refresh the proxy asked for as `id` with `set`, or with nothing when the set cannot
/// cross (it names more plugins than one message hands over): the proxy waits for an answer, and
/// nothing else will send it.
fn refreshed(side: &SupervisorSide, id: u64, set: Option<Transfer>) {
    if send(side, ToProxy::Refreshed { id, set }).is_err() {
        let _ = send(side, ToProxy::Refreshed { id, set: None });
    }
}

/// Send `message` to the proxy. An error when the link has ended, or when the proxy leaves no room
/// for the message within [`SEND_WAIT`], which ends the link: that proxy has stopped reading.
fn send(side: &SupervisorSide, message: ToProxy) -> io::Result<()> {
    // Taken out of the lock before sending, so a send waiting for room holds up no other.
    let socket = locked(&side.down).clone().ok_or_else(gone)?;
    let (doc, fds) = message.encode()?;
    let sent = socket.send_down(&doc, &fds);
    if sent
        .as_ref()
        .is_err_and(|e| e.kind() == io::ErrorKind::WouldBlock)
    {
        // Wakes this end's reader, which ends the link the one way a link ends.
        socket.shutdown();
    }
    sent
}

/// The notice announcing a parked request, and the two commands that answer it, composed from the
/// forms the queue stores: what the proxy sent is the cage's choice, and the operator's terminal
/// prints only what the queue filtered.
fn park_notice(id: &str, parked: &crate::sandbox::control::Parked) -> (String, String, String) {
    (
        format!(
            "egress decision needed [{id}] {}:{}{}",
            parked.host, parked.port, parked.path
        ),
        format!("sbx net pending allow {id}"),
        format!("sbx net pending deny {id}"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn overlay(allow: &str) -> Overlay {
        Overlay {
            allow: vec![crate::allowlist::classify(allow).unwrap()],
            ..Overlay::default()
        }
    }

    /// A confirmed push is the overlay the proxy decides with: nothing is left to arrive after the
    /// supervisor has heard back.
    #[test]
    fn a_confirmed_overlay_is_already_in_force() {
        let (link, supervisor) = pair();
        assert!(link.overlay().is_empty());
        supervisor.push(1, overlay("api.test")).unwrap();
        assert_eq!(supervisor.installed(), 1);
        assert_eq!(link.overlay().allow, overlay("api.test").allow);
    }

    /// An older overlay arriving after a newer one does not replace it.
    #[test]
    fn a_stale_overlay_does_not_replace_a_newer_one() {
        let (link, supervisor) = pair();
        supervisor.push(2, overlay("new.test")).unwrap();
        supervisor.push(1, overlay("old.test")).unwrap();
        assert_eq!(link.overlay().allow, overlay("new.test").allow);
        assert_eq!(supervisor.installed(), 2);
    }

    /// A proxy that is gone cannot confirm, and the supervisor says so rather than waiting.
    #[test]
    fn a_push_to_a_proxy_that_is_gone_is_an_error() {
        let (link, supervisor, (proxy_reader, supervisor_reader)) =
            start(None, None, None, named_thread).unwrap();
        drop(link);
        supervisor_reader.join().unwrap().unwrap();
        proxy_reader.join().unwrap();
        let e = supervisor.push(1, overlay("api.test")).unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::BrokenPipe);
    }

    /// Both readers end with the proxy, whatever the supervisor's end is doing: a process that
    /// stands up a proxy per app keeps no thread per proxy it is done with.
    #[test]
    fn both_readers_end_once_the_proxy_lets_go() {
        let (link, supervisor, (proxy_reader, supervisor_reader)) =
            start(None, None, None, named_thread).unwrap();
        supervisor.push(1, overlay("api.test")).unwrap();
        drop(link);
        supervisor_reader.join().unwrap().unwrap();
        proxy_reader.join().unwrap();
        drop(supervisor);
    }

    /// A confirmation is not believed beyond what was sent: a proxy claiming a version the
    /// supervisor never sent is taken at no more than the last version the supervisor did send, so
    /// it cannot make every later push look confirmed in advance.
    #[test]
    fn a_confirmation_beyond_what_was_sent_is_not_believed() {
        let (link, supervisor) = pair();
        link.side
            .say(&ToSupervisor::Installed { version: u64::MAX })
            .unwrap();
        supervisor.push(1, overlay("api.test")).unwrap();
        assert_eq!(supervisor.installed(), 1);
    }

    #[test]
    fn a_detached_end_holds_an_empty_overlay() {
        assert!(Link::detached().overlay().is_empty());
    }

    /// How long a test waits for an answer it expects. Generous: what is asserted is which answer
    /// comes, and a defect that sends none fails here instead of hanging the suite.
    const ANSWER_WAIT: Duration = Duration::from_secs(10);

    /// Parks served into `pending`, with no notice.
    fn parks(pending: &Arc<PendingState>, cap: usize, timeout: Option<Duration>) -> Parks {
        Parks {
            pending: Arc::clone(pending),
            cap,
            timeout,
            notices: false,
        }
    }

    /// Park `host` through `link` from a thread of its own; the verdict arrives on the receiver.
    fn park_on(link: &Arc<Link>, host: &'static str) -> Receiver<Verdict> {
        let (tx, rx) = channel();
        let link = Arc::clone(link);
        std::thread::spawn(move || {
            let _ = tx.send(link.park(host, 443, "/v1"));
        });
        rx
    }

    /// The requests `pending` lists, once there are `n` of them.
    fn listed(pending: &PendingState, n: usize) -> Vec<crate::sandbox::control::PendingRow> {
        let deadline = Instant::now() + ANSWER_WAIT;
        loop {
            let rows = pending.list();
            if rows.len() >= n || Instant::now() >= deadline {
                return rows;
            }
            std::thread::sleep(Duration::from_millis(1));
        }
    }

    /// A request the proxy parks is queued on the supervisor's side, where the operator answers it,
    /// and the answer is what the proxy's request is decided with.
    #[test]
    fn a_parked_request_is_decided_by_the_answer_given_to_the_supervisors_queue() {
        for verdict in [Verdict::Allow, Verdict::Deny] {
            let pending = Arc::new(PendingState::new());
            let link = Arc::new(serving(parks(&pending, 4, None), None, None).unwrap().0);
            let asking = park_on(&link, "api.test");
            let rows = listed(&pending, 1);
            assert_eq!(
                rows.iter()
                    .map(|r| (r.host.as_str(), r.port, r.path.as_str()))
                    .collect::<Vec<_>>(),
                [("api.test", 443, "/v1")]
            );
            assert_eq!(
                pending.answer_like(rows[0].seq, verdict),
                Some(("api.test".to_string(), 443, 1))
            );
            assert_eq!(asking.recv_timeout(ANSWER_WAIT), Ok(verdict));
            assert!(pending.list().is_empty());
        }
    }

    /// The `ask_timeout` is the supervisor's: a request nobody answers is denied when the
    /// supervisor stops waiting, and leaves the queue.
    #[test]
    fn the_supervisor_times_a_parked_request_out() {
        let pending = Arc::new(PendingState::new());
        let link = Arc::new(
            serving(
                parks(&pending, 4, Some(Duration::from_millis(50))),
                None,
                None,
            )
            .unwrap()
            .0,
        );
        assert_eq!(
            park_on(&link, "api.test").recv_timeout(ANSWER_WAIT),
            Ok(Verdict::Deny)
        );
        assert!(
            pending.list().is_empty(),
            "a timed-out request leaves the queue"
        );
    }

    /// The cap is the supervisor's: past it, a request is denied at once and never listed.
    #[test]
    fn a_request_parked_past_the_cap_is_denied_without_entering_the_queue() {
        let pending = Arc::new(PendingState::new());
        let link = Arc::new(serving(parks(&pending, 1, None), None, None).unwrap().0);
        let first = park_on(&link, "first.test");
        let rows = listed(&pending, 1);
        assert_eq!(
            park_on(&link, "second.test").recv_timeout(ANSWER_WAIT),
            Ok(Verdict::Deny)
        );
        let hosts: Vec<String> = pending.list().into_iter().map(|r| r.host).collect();
        assert_eq!(hosts, ["first.test"]);
        pending.answer_like(rows[0].seq, Verdict::Allow);
        assert_eq!(first.recv_timeout(ANSWER_WAIT), Ok(Verdict::Allow));
    }

    /// A request parked where nobody answers is denied at once rather than left waiting.
    #[test]
    fn a_request_parked_where_nobody_answers_is_denied() {
        assert_eq!(
            park_on(&Arc::new(Link::detached()), "api.test").recv_timeout(ANSWER_WAIT),
            Ok(Verdict::Deny)
        );
        assert_eq!(
            park_on(&Arc::new(pair().0), "api.test").recv_timeout(ANSWER_WAIT),
            Ok(Verdict::Deny)
        );
    }

    /// A request still parked when its proxy lets go of the link is taken out of the queue, and the
    /// supervisor's thread waiting on it is let go with it: nobody is left to hear the answer.
    #[test]
    fn a_request_parked_by_a_proxy_that_is_gone_leaves_the_queue() {
        let pending = Arc::new(PendingState::new());
        let (link, supervisor, (proxy_reader, supervisor_reader)) =
            start(Some(parks(&pending, 4, None)), None, None, named_thread).unwrap();
        // Sent as the proxy sends it, straight on the socket: a request parked with `park` would
        // hold the end this test lets go of.
        link.side
            .say(&ToSupervisor::Park {
                id: 1,
                host: "api.test".to_string(),
                port: 443,
                path: "/".to_string(),
            })
            .unwrap();
        assert_eq!(listed(&pending, 1).len(), 1);
        drop(link);
        supervisor_reader.join().unwrap().unwrap();
        proxy_reader.join().unwrap();
        assert!(pending.list().is_empty());
        drop(supervisor);
    }

    /// A thread the host is certain to refuse: a stack larger than any address space, still small
    /// enough for the C library to accept as a size, so it is the mapping that fails.
    fn refused_thread(_: &str) -> std::thread::Builder {
        std::thread::Builder::new().stack_size(usize::MAX / 8)
    }

    /// A request whose waiting thread cannot be started is answered at once, a deny since nobody
    /// answered it meanwhile, and does not stay listed as a request nobody will hear back on.
    #[test]
    fn a_request_whose_thread_cannot_start_is_denied_and_leaves_the_queue() {
        let pending = Arc::new(PendingState::new());
        let (link, _supervisor, _) =
            start(Some(parks(&pending, 4, None)), None, None, refused_thread).unwrap();
        assert_eq!(
            park_on(&Arc::new(link), "api.test").recv_timeout(ANSWER_WAIT),
            Ok(Verdict::Deny)
        );
        assert!(pending.list().is_empty());
    }

    /// A refresher over `value`, counting its runs; each run resolves `Bearer <value>-<run>`, so no
    /// two runs return the same value and the unchanged-value stop never answers for the gap.
    fn counting_refresh(
        value: &str,
    ) -> (Arc<CredentialRefresh>, Arc<std::sync::atomic::AtomicUsize>) {
        use super::super::inject::{Credentials, HeaderInjection};
        let injection = |v: String| {
            HeaderInjection::fixed(
                crate::allowlist::classify("api.test").unwrap(),
                "authorization".to_string(),
                v,
            )
        };
        let credentials = Arc::new(Credentials::new(
            vec![injection(format!("Bearer {value}"))],
            Vec::new(),
            crate::sandbox::redact::MIN_LEN_DEFAULT,
            Vec::new(),
        ));
        let runs = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let counted = Arc::clone(&runs);
        let value = value.to_string();
        let refresh = CredentialRefresh::new(
            credentials,
            Box::new(move |_| {
                let run = counted.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1;
                Ok((vec![injection(format!("Bearer {value}-{run}"))], Vec::new()))
            }),
        );
        (Arc::new(refresh), runs)
    }

    /// Ask for a refresh through `link` from a thread of its own, and return what it was handed
    /// back — or fail the test when no answer comes, rather than hang the suite.
    fn refresh_on(link: &Arc<Link>) -> Option<String> {
        let (tx, rx) = channel();
        let link = Arc::clone(link);
        std::thread::spawn(move || {
            let _ = tx.send(link.refresh().map(injected));
        });
        rx.recv_timeout(ANSWER_WAIT)
            .expect("the supervisor answers a refresh")
    }

    /// The value a handed-back set injects.
    fn injected(set: Transfer) -> String {
        super::super::inject::CredentialSet::decode(set)
            .unwrap()
            .injections[0]
            .value()
            .to_string()
    }

    /// A refresh the proxy asks for is re-resolved by the supervisor and handed back as the new set.
    #[test]
    fn a_refresh_the_supervisor_resolves_is_handed_back_to_the_proxy() {
        let (refresh, runs) = counting_refresh("old");
        let link = Arc::new(refreshing(refresh).0);
        assert_eq!(refresh_on(&link).as_deref(), Some("Bearer old-1"));
        assert_eq!(runs.load(std::sync::atomic::Ordering::SeqCst), 1);
    }

    /// A proxy asking for refreshes in a loop is held to the supervisor's gap: one re-resolution,
    /// and every later request declined without reaching the source. Nothing on the proxy's side
    /// counts or waits.
    #[test]
    fn a_proxy_asking_for_refreshes_in_a_loop_is_held_to_the_supervisors_gap() {
        let (refresh, runs) = counting_refresh("old");
        let link = Arc::new(refreshing(refresh).0);
        let answers: Vec<Option<String>> = (0..20).map(|_| refresh_on(&link)).collect();
        assert_eq!(answers[0].as_deref(), Some("Bearer old-1"));
        assert!(
            answers[1..].iter().all(Option::is_none),
            "every refresh inside the gap is declined: {answers:?}"
        );
        assert_eq!(
            runs.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "the source ran once"
        );
    }

    /// A refresh asked for while one is under way is declined at once rather than queued behind it,
    /// even with no gap to hold it: one re-resolution at a time.
    #[test]
    fn a_refresh_asked_while_one_runs_is_declined_at_once() {
        use super::super::inject::{Credentials, HeaderInjection};
        let injection = |v: &str| {
            HeaderInjection::fixed(
                crate::allowlist::classify("api.test").unwrap(),
                "authorization".to_string(),
                v.to_string(),
            )
        };
        let (entered, running) = channel();
        let (release, released) = channel::<()>();
        let released = Mutex::new(released);
        let runs = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let counted = Arc::clone(&runs);
        let refresh = CredentialRefresh::new(
            Arc::new(Credentials::new(
                vec![injection("Bearer old")],
                Vec::new(),
                crate::sandbox::redact::MIN_LEN_DEFAULT,
                Vec::new(),
            )),
            Box::new(move |_| {
                counted.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                let _ = entered.send(());
                let _ = locked(&released).recv();
                Ok((vec![injection("Bearer new")], Vec::new()))
            }),
        )
        .with_gap(Duration::ZERO);
        let link = Arc::new(refreshing(Arc::new(refresh)).0);
        let first = {
            let link = Arc::clone(&link);
            std::thread::spawn(move || link.refresh().map(injected))
        };
        running
            .recv_timeout(ANSWER_WAIT)
            .expect("the first re-resolution runs");
        let (tx, second) = channel();
        {
            let link = Arc::clone(&link);
            std::thread::spawn(move || {
                let _ = tx.send(link.refresh().is_none());
            });
        }
        assert_eq!(
            second.recv_timeout(ANSWER_WAIT),
            Ok(true),
            "declined while the first still runs"
        );
        assert_eq!(runs.load(std::sync::atomic::Ordering::SeqCst), 1);
        release.send(()).unwrap();
        assert_eq!(first.join().unwrap().as_deref(), Some("Bearer new"));
    }

    /// A refresh nobody serves is declined rather than left waiting.
    #[test]
    fn a_refresh_nobody_serves_is_declined() {
        assert_eq!(refresh_on(&Arc::new(Link::detached())), None);
        assert_eq!(refresh_on(&Arc::new(pair().0)), None);
    }

    /// A refresh whose thread cannot be started, or whose source panics, is declined, and does not
    /// leave the supervisor believing one is still under way: the next is admitted.
    #[test]
    fn a_refresh_that_could_not_run_does_not_block_the_next() {
        let (refresh, _) = counting_refresh("old");
        let refresh = Arc::new(Arc::into_inner(refresh).unwrap().with_gap(Duration::ZERO));
        let (link, _supervisor, _) =
            start(None, Some(Arc::clone(&refresh)), None, refused_thread).unwrap();
        assert_eq!(refresh_on(&Arc::new(link)), None, "no thread, no refresh");
        assert!(refresh.start().is_some(), "and the next one is admitted");

        let panicking = Arc::new(
            CredentialRefresh::new(
                Arc::new(super::super::inject::Credentials::new(
                    Vec::new(),
                    Vec::new(),
                    crate::sandbox::redact::MIN_LEN_DEFAULT,
                    Vec::new(),
                )),
                Box::new(|_| panic!("a resolver that panics")),
            )
            .with_gap(Duration::ZERO),
        );
        let link = Arc::new(refreshing(Arc::clone(&panicking)).0);
        let (tx, answer) = channel();
        {
            let link = Arc::clone(&link);
            std::thread::spawn(move || {
                let _ = tx.send(link.refresh().is_none());
            });
        }
        assert_eq!(
            answer.recv_timeout(ANSWER_WAIT),
            Ok(true),
            "a panicking source is answered, not left waiting"
        );
        assert!(panicking.start().is_some(), "and the next one is admitted");
    }

    /// A process a refresh starts lives as long as the link, not as long as the refresh: a signer
    /// handed a new key is tied to the thread that started it by the parent-death signal its cage
    /// arms, so the thread running refreshes must outlive each of them. Once the proxy lets go of
    /// the link, that thread ends and the process with it.
    #[test]
    fn a_process_a_refresh_starts_lives_as_long_as_the_link() {
        use super::super::inject::{Credentials, HeaderInjection};
        use std::os::unix::process::CommandExt;
        let injection = |v: &str| {
            HeaderInjection::fixed(
                crate::allowlist::classify("api.test").unwrap(),
                "authorization".to_string(),
                v.to_string(),
            )
        };
        let child: Arc<Mutex<Option<std::process::Child>>> = Arc::default();
        let slot = Arc::clone(&child);
        let refresh = CredentialRefresh::new(
            Arc::new(Credentials::new(
                vec![injection("Bearer old")],
                Vec::new(),
                crate::sandbox::redact::MIN_LEN_DEFAULT,
                Vec::new(),
            )),
            Box::new(move |_| {
                let mut sleep = std::process::Command::new("sleep");
                sleep.arg("120");
                // SAFETY: the hook runs between fork and exec and calls `prctl` alone, which is
                // async-signal-safe. It arms what a plugin cage's `--die-with-parent` arms.
                unsafe {
                    sleep.pre_exec(
                        || match libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) {
                            0 => Ok(()),
                            _ => Err(std::io::Error::last_os_error()),
                        },
                    );
                }
                *locked(&slot) = Some(sleep.spawn()?);
                Ok((vec![injection("Bearer new")], Vec::new()))
            }),
        );
        let (link, _supervisor, (proxy_reader, supervisor_reader)) =
            start(None, Some(Arc::new(refresh)), None, named_thread).unwrap();
        let link = Arc::new(link);
        assert_eq!(refresh_on(&link).as_deref(), Some("Bearer new"));
        let exited = || {
            locked(&child)
                .as_mut()
                .expect("the refresh started its process")
                .try_wait()
                .unwrap()
                .is_some()
        };
        // Answered: a thread that ran this refresh alone would be ending now, its process with it.
        let window = Instant::now() + Duration::from_secs(1);
        while Instant::now() < window {
            assert!(
                !exited(),
                "the process a refresh started died with the refresh"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
        let deadline = Instant::now() + ANSWER_WAIT;
        while Arc::strong_count(&link) > 1 && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(1));
        }
        drop(link);
        supervisor_reader.join().unwrap().unwrap();
        proxy_reader.join().unwrap();
        while !exited() {
            assert!(
                Instant::now() < deadline,
                "the process a refresh started outlived the link"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    /// The notice is composed from what the queue stores, never from what the proxy sent: a host
    /// and a path carrying terminal escapes reach the operator's terminal filtered.
    #[test]
    fn a_park_notice_prints_what_the_queue_stores() {
        let pending = PendingState::new();
        let parked = pending
            .enqueue("evil\u{1b}[2J.test", 443, "/x\u{1b}]0;title\u{7}", 4)
            .unwrap();
        assert_eq!(
            park_notice("7.1@9", &parked),
            (
                "egress decision needed [7.1@9] evil [2J.test:443/x ]0;title ".to_string(),
                "sbx net pending allow 7.1@9".to_string(),
                "sbx net pending deny 7.1@9".to_string(),
            )
        );
    }

    /// A proxy's end on one side of a fresh socket, and the other side, for a test to play the
    /// supervisor with.
    fn attended(events: Option<Emitter>) -> (Arc<Link>, Arc<wire::Socket>) {
        let (down, up) = wire::Socket::pair().unwrap();
        let (link, _reader) = attend(up, events).unwrap();
        (Arc::new(link), Arc::new(down))
    }

    /// A supervisor's end on one side of a fresh socket, its reader, and the other side, for a test
    /// to play the proxy with, keeping to the link's rules or not.
    fn supervised() -> (Supervisor, JoinHandle<io::Result<()>>, Arc<wire::Socket>) {
        let (down, up) = wire::Socket::pair().unwrap();
        let (supervisor, reader) = supervise(down, None, None, named_thread).unwrap();
        (supervisor, reader, Arc::new(up))
    }

    /// What `reader` returned, or a failed test when it has not ended within [`ANSWER_WAIT`].
    fn ended(reader: JoinHandle<io::Result<()>>) -> io::Result<()> {
        let (tx, rx) = channel();
        std::thread::spawn(move || {
            let _ = tx.send(reader.join().unwrap());
        });
        rx.recv_timeout(ANSWER_WAIT)
            .expect("the supervisor's reader ended")
    }

    /// The next message the supervisor sends `proxy`, or a failed test when none comes within
    /// [`ANSWER_WAIT`].
    fn next_down(proxy: &Arc<wire::Socket>) -> (ToProxy, usize) {
        let (tx, rx) = channel();
        let proxy = Arc::clone(proxy);
        std::thread::spawn(move || {
            let _ = tx.send(
                proxy
                    .recv_down()
                    .unwrap()
                    .map(|(doc, fds)| (fds.len(), ToProxy::decode(&doc, fds).unwrap())),
            );
        });
        let (count, message) = rx
            .recv_timeout(ANSWER_WAIT)
            .expect("the supervisor sent a message")
            .expect("the link is still open");
        (message, count)
    }

    /// Where a descriptor points: its device and inode.
    fn inode(fd: &OwnedFd) -> (u64, u64) {
        use std::os::unix::fs::MetadataExt;
        let meta = std::fs::File::from(fd.try_clone().unwrap())
            .metadata()
            .unwrap();
        (meta.dev(), meta.ino())
    }

    /// A message the supervisor cannot read ends the link, for its own reason: past it, the
    /// supervisor no longer knows what the proxy meant, and a push after it is refused.
    #[test]
    fn a_message_the_supervisor_cannot_read_ends_the_link() {
        let installed = b"{\"Installed\":{\"version\":1}}";
        let mut padded = installed.to_vec();
        padded.resize(wire::MAX_UP + 100, b' ');
        let (_read, write) = std::io::pipe().unwrap();
        let write = OwnedFd::from(write);
        for (bytes, fds, why) in [
            (
                &b"not a message"[..],
                vec![],
                "link: a message that does not parse",
            ),
            (
                &padded[..],
                vec![],
                "link: a message larger than the link carries",
            ),
            (
                &installed[..],
                vec![std::os::fd::AsRawFd::as_raw_fd(&write)],
                "link: a message handing over a descriptor",
            ),
        ] {
            let (supervisor, reader, proxy) = supervised();
            proxy.send_raw(bytes, &fds).unwrap();
            assert_eq!(ended(reader).unwrap_err().to_string(), why);
            let e = supervisor.push(1, overlay("api.test")).unwrap_err();
            assert_eq!(e.kind(), io::ErrorKind::BrokenPipe, "{why}");
        }
    }

    /// A set the supervisor hands back crosses with its descriptors: the proxy receives the same
    /// files, close-on-exec, beside the document they belong to.
    #[test]
    fn a_refreshed_set_crosses_with_its_descriptors() {
        let (link, supervisor) = attended(None);
        let (tx, handed) = channel();
        {
            let link = Arc::clone(&link);
            std::thread::spawn(move || {
                let _ = tx.send(link.refresh().map(Transfer::into_parts));
            });
        }
        let asked = supervisor.recv_up().unwrap().unwrap();
        let Ok(ToSupervisor::Refresh { id }) = serde_json::from_slice(&asked) else {
            panic!("the proxy asked for a refresh");
        };
        let (_read, write) = std::io::pipe().unwrap();
        let write = OwnedFd::from(write);
        let set = Transfer::from_parts(b"{\"set\":1}".to_vec(), vec![write.try_clone().unwrap()]);
        let (doc, fds) = ToProxy::Refreshed { id, set: Some(set) }.encode().unwrap();
        supervisor.send_down(&doc, &fds).unwrap();
        let (doc, fds) = handed
            .recv_timeout(ANSWER_WAIT)
            .unwrap()
            .expect("the proxy was handed a set");
        assert_eq!(doc, b"{\"set\":1}");
        assert_eq!(fds.len(), 1);
        assert_eq!(inode(&fds[0]), inode(&write));
        // SAFETY: reading the flags of a descriptor this test holds.
        let flags = unsafe { libc::fcntl(std::os::fd::AsRawFd::as_raw_fd(&fds[0]), libc::F_GETFD) };
        assert_ne!(
            flags & libc::FD_CLOEXEC,
            0,
            "a descriptor arrived inheritable"
        );
    }

    /// A set naming more plugins than one message hands over is answered as none rather than cut,
    /// and the link goes on serving: the next push is confirmed.
    #[test]
    fn a_set_too_many_plugins_to_cross_is_answered_as_none_and_the_link_serves_on() {
        let (supervisor, _reader, proxy) = supervised();
        let (_read, write) = std::io::pipe().unwrap();
        let write = OwnedFd::from(write);
        let many = (0..254).map(|_| write.try_clone().unwrap()).collect();
        refreshed(
            &supervisor.side,
            7,
            Some(Transfer::from_parts(b"{}".to_vec(), many)),
        );
        let (message, fds) = next_down(&proxy);
        assert!(
            matches!(message, ToProxy::Refreshed { id: 7, set: None }),
            "the refresh is answered as none"
        );
        assert_eq!(fds, 0);

        let pushing = {
            let supervisor = supervisor.clone();
            std::thread::spawn(move || supervisor.push(1, overlay("api.test")))
        };
        let (message, _) = next_down(&proxy);
        assert!(matches!(message, ToProxy::Overlay { version: 1, .. }));
        proxy.send_up(br#"{"Installed":{"version":1}}"#).unwrap();
        pushing.join().unwrap().unwrap();
    }

    /// A flush asked through the link returns once what the proxy reported before it is applied,
    /// with the applying side slowed so that an answer sent before applying would be seen early.
    #[test]
    fn a_flush_through_the_link_waits_for_what_was_reported_before_it() {
        use super::super::events::{Keeps, ProxyEvent, Sinks, applying, emitter};
        use crate::sandbox::egress_stats::{EgressStats, StatKind};
        use std::os::unix::net::UnixStream;
        let dir = crate::testutil::TmpDir::new();
        let counts = Arc::new(EgressStats::new(dir.join("stats"), "/t".into(), None));
        // The proxy writes to one pair, the applying side reads another, and a relay between them
        // holds the reports back while letting the acknowledgements through at once.
        let (reports, relay_in) = UnixStream::pair().unwrap();
        let (relay_out, applied) = UnixStream::pair().unwrap();
        {
            let (mut from, mut to) = (
                relay_in.try_clone().unwrap(),
                relay_out.try_clone().unwrap(),
            );
            std::thread::spawn(move || {
                std::thread::sleep(Duration::from_millis(300));
                let _ = std::io::copy(&mut from, &mut to);
                let _ = to.shutdown(std::net::Shutdown::Write);
            });
        }
        {
            let (mut from, mut to) = (relay_out, relay_in);
            std::thread::spawn(move || {
                let _ = std::io::copy(&mut from, &mut to);
            });
        }
        let keeps = Keeps {
            stats: true,
            refusals: false,
            signatures: false,
            log: false,
            capture: None,
            flows: false,
        };
        let events = emitter(reports, keeps).unwrap();
        let _applier = applying(
            Sinks {
                stats: Some(Arc::clone(&counts)),
                ..Sinks::default()
            },
            applied,
        )
        .unwrap();
        let (_link, supervisor, _) = start(None, None, Some(events.clone()), named_thread).unwrap();
        for _ in 0..50 {
            events.send(ProxyEvent::Stat {
                host: "api.example.com".into(),
                kind: StatKind::Allow,
            });
        }
        supervisor.flush();
        assert_eq!(
            counts.snapshot().get("api.example.com").map(|c| c.allow),
            Some(50)
        );
    }

    /// A flush the proxy never answers returns within its bound, and an answer for a flush never
    /// asked is not believed for the next one.
    #[test]
    fn a_flush_the_proxy_does_not_answer_returns_within_its_bound() {
        let (supervisor, _reader, proxy) = supervised();
        proxy
            .send_up(br#"{"Flushed":{"id":18446744073709551615}}"#)
            .unwrap();
        // The reader takes messages in order, so once the park sent after the answer is denied, the
        // answer has been taken in, before any flush was asked.
        proxy
            .send_up(br#"{"Park":{"id":1,"host":"api.test","port":443,"path":"/"}}"#)
            .unwrap();
        assert!(matches!(
            next_down(&proxy).0,
            ToProxy::Answer {
                id: 1,
                verdict: Verdict::Deny
            }
        ));
        let (tx, returned) = channel();
        std::thread::spawn(move || {
            supervisor.flush();
            let _ = tx.send(());
        });
        assert!(
            returned.recv_timeout(Duration::from_secs(1)).is_err(),
            "a flush returned on an answer given before it was asked"
        );
        returned
            .recv_timeout(ANSWER_WAIT)
            .expect("a flush the proxy does not answer returns");
    }

    /// A proxy that stops reading does not hold the supervisor's reader: the answers it leaves no
    /// room for end the link within the wait for room, and the reader with it.
    #[test]
    fn a_proxy_that_stops_reading_does_not_hold_the_supervisors_reader() {
        let (_supervisor, reader, proxy) = supervised();
        let park = br#"{"Park":{"id":1,"host":"api.test","port":443,"path":"/"}}"#;
        // Each park is denied on the spot, and the proxy never reads the denials.
        let flooding = std::thread::spawn(move || {
            for _ in 0..100_000 {
                if proxy.send_up(park).is_err() {
                    return;
                }
            }
        });
        ended(reader).unwrap();
        flooding.join().unwrap();
    }

    /// A park is listed as the queue shows the whole of its host and path, however long they are:
    /// what the proxy sends is cut to one character past what the queue keeps, by characters.
    #[test]
    fn a_park_is_listed_as_the_queue_shows_the_whole_of_it() {
        let long_path = format!("/{}", "a".repeat(600));
        let straddling = format!("{}é{}", "a".repeat(crate::sandbox::SANITIZED_CHARS), "é");
        let controls = "\u{1b}".repeat(100_000);
        for (host, path) in [
            (
                "api.test".to_string(),
                "a".repeat(crate::sandbox::SANITIZED_CHARS),
            ),
            (
                "api.test".to_string(),
                "a".repeat(crate::sandbox::SANITIZED_CHARS + 1),
            ),
            ("api.test".to_string(), long_path),
            ("api.test".to_string(), straddling),
            (controls.clone(), controls),
        ] {
            let pending = Arc::new(PendingState::new());
            let link = Arc::new(serving(parks(&pending, 4, None), None, None).unwrap().0);
            let (tx, answered) = channel();
            {
                let (link, host, path) = (Arc::clone(&link), host.clone(), path.clone());
                std::thread::spawn(move || {
                    let _ = tx.send(link.park(&host, 443, &path));
                });
            }
            let rows = listed(&pending, 1);
            assert_eq!(
                rows.iter()
                    .map(|r| (r.host.clone(), r.path.clone()))
                    .collect::<Vec<_>>(),
                [(
                    crate::sandbox::sanitize(&host),
                    crate::sandbox::sanitize(&path)
                )],
                "a {}-character path",
                path.chars().count()
            );
            pending.answer_like(rows[0].seq, Verdict::Allow);
            assert_eq!(answered.recv_timeout(ANSWER_WAIT), Ok(Verdict::Allow));
        }
    }
}
