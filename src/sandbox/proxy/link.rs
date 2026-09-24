//! What the supervisor tells the proxy about the state it decides with, and what the proxy answers.
//!
//! [`super::events`] carries the proxy's account of its own work, one way. This carries the other
//! direction: state the supervisor owns and the proxy decides with — the rules an operator loads
//! into a running session (`sbx net allow|deny|mute --session`, or an `ask` answered with
//! `--session`), and the answer to a request the proxy parks under `ask`. The proxy is to run in a
//! process of its own, so neither side holds the other's structures: each end reads its own
//! channel on a thread of its own, and the socket that replaces the channels when the proxy moves
//! changes what carries the messages, not who reads them.
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
//! A confirmation is therefore never believed beyond the last version sent.
//!
//! **A parked request waits on the supervisor.** The proxy says what it would park
//! ([`Link::park`]) and blocks until the answer comes back. The supervisor lets it into the queue
//! the operator answers from, or denies it at once past the cap, and waits for the answer on a
//! thread of its own, up to the `ask_timeout`: the cap, the timeout and the notice announcing the
//! request are the supervisor's, and a proxy that sends more than it is owed only fills its own
//! queue. The reader that takes in parks is the one that takes in confirmations, so it never waits
//! on anything: a park it could not let in at once would hold every `--session` answer behind it.

use crate::allowlist::Rule;
use crate::sandbox::control::{PendingState, Verdict};
use crate::sandbox::locks::{locked, read_locked, write_locked};
use std::collections::HashMap;
use std::io;
use std::sync::mpsc::{Receiver, Sender, channel};
use std::sync::{Arc, Condvar, Mutex, RwLock};
use std::time::{Duration, Instant};

/// How long the supervisor waits for the proxy to confirm an overlay before telling the operator it
/// could not. The reader installs and confirms without waiting on anything, so this is only ever
/// reached by a proxy that has stopped reading. Below the control socket's own ten-second bound, so
/// the operator is told why rather than timing out.
const CONFIRM_WAIT: Duration = Duration::from_secs(5);

/// The live `--session` rules, as the proxy folds them into the policy it decides with.
#[derive(Clone, Default)]
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

/// What the supervisor tells the proxy.
enum ToProxy {
    /// The whole overlay, as of `version`.
    Overlay { version: u64, overlay: Overlay },
    /// The answer to the request the proxy parked as `id`.
    Answer { id: u64, verdict: Verdict },
}

/// What the proxy tells the supervisor.
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
    /// The way back, until the proxy lets go of its end ([`Link`]'s `Drop`), which is what tells
    /// the supervisor's reader that nothing more will come.
    up: Mutex<Option<Sender<ToSupervisor>>>,
    /// The requests this proxy has parked, each waiting for the answer sent under its id.
    parked: Mutex<Parked>,
}

/// The requests a proxy has parked and not yet heard back about.
#[derive(Default)]
struct Parked {
    /// The id the next one is sent under.
    next: u64,
    /// Where each one's answer is handed over, by id.
    answers: HashMap<u64, Sender<Verdict>>,
}

impl Link {
    /// An end no supervisor reaches: its overlay is empty for good. What a proxy is built with
    /// before a launch wires it, and all a test that loads no rule needs.
    pub(crate) fn detached() -> Self {
        Link {
            side: Arc::new(ProxySide {
                overlay: RwLock::new((0, Arc::new(Overlay::default()))),
                up: Mutex::new(None),
                parked: Mutex::new(Parked::default()),
            }),
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
    pub(crate) fn park(&self, host: &str, port: u16, path: &str) -> Verdict {
        let (id, answer) = {
            let mut parked = locked(&self.side.parked);
            parked.next += 1;
            let id = parked.next;
            let (tx, rx) = channel();
            parked.answers.insert(id, tx);
            (id, rx)
        };
        // Registered before it is sent, so an answer arriving at once finds where to go.
        let sent = locked(&self.side.up).as_ref().is_some_and(|up| {
            up.send(ToSupervisor::Park {
                id,
                host: host.to_string(),
                port,
                path: path.to_string(),
            })
            .is_ok()
        });
        if !sent {
            locked(&self.side.parked).answers.remove(&id);
            return Verdict::Deny;
        }
        answer.recv().unwrap_or(Verdict::Deny)
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
        // The supervisor's reader ends on this, and takes the channel to the proxy's reader with it,
        // so both threads end with the proxy.
        locked(&self.side.up).take();
    }
}

/// The supervisor's end: how it reaches the proxy it serves.
pub(crate) struct Supervisor {
    side: Arc<SupervisorSide>,
}

/// What the supervisor's end shares with its reader.
struct SupervisorSide {
    /// The way to the proxy, until the proxy has let go of its end. Never cloned: the proxy's
    /// reader ends when this one sender is dropped.
    down: Mutex<Option<Sender<ToProxy>>>,
    heard: Mutex<Heard>,
    changed: Condvar,
    /// How the requests this proxy parks are served, or `None` when nobody answers them: each is
    /// then denied as it arrives.
    parks: Option<Parks>,
}

/// What the supervisor knows of the proxy's overlay.
#[derive(Default)]
struct Heard {
    /// The last version sent, the most a confirmation is believed for.
    sent: u64,
    /// The version the proxy last said it has installed.
    installed: u64,
    /// The proxy has let go of its end: nothing more will be installed.
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
        // Counted as sent before it is, so a confirmation that arrives the instant it is installed
        // is already believed.
        {
            let mut heard = locked(&self.side.heard);
            heard.sent = heard.sent.max(version);
        }
        let sent = locked(&self.side.down)
            .as_ref()
            .is_some_and(|down| down.send(ToProxy::Overlay { version, overlay }).is_ok());
        if !sent {
            return Err(gone());
        }
        let deadline = Instant::now() + CONFIRM_WAIT;
        let mut heard = locked(&self.side.heard);
        loop {
            if heard.installed >= version {
                return Ok(());
            }
            if heard.closed {
                return Err(gone());
            }
            let Some(left) = deadline
                .checked_duration_since(Instant::now())
                .filter(|left| !left.is_zero())
            else {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "the proxy did not confirm the session rules",
                ));
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
/// requests the proxy parks served as `parks` says. Both readers end once the proxy lets go of its
/// [`Link`], and so does every thread waiting on a request it parked.
pub(crate) fn serving(parks: Parks) -> (Link, Supervisor) {
    let (link, supervisor, _) = start(Some(parks));
    (link, supervisor)
}

/// [`serving`] with nobody to answer a parked request: all a test of the rules alone needs.
#[cfg(test)]
pub(crate) fn pair() -> (Link, Supervisor) {
    let (link, supervisor, _) = start(None);
    (link, supervisor)
}

/// [`serving`], keeping the two readers' handles.
fn start(parks: Option<Parks>) -> (Link, Supervisor, [std::thread::JoinHandle<()>; 2]) {
    let (down_tx, down_rx) = channel();
    let (up_tx, up_rx) = channel();
    let proxy = Arc::new(ProxySide {
        overlay: RwLock::new((0, Arc::new(Overlay::default()))),
        up: Mutex::new(Some(up_tx)),
        parked: Mutex::new(Parked::default()),
    });
    let supervisor = Arc::new(SupervisorSide {
        down: Mutex::new(Some(down_tx)),
        heard: Mutex::new(Heard::default()),
        changed: Condvar::new(),
        parks,
    });
    let readers = [
        {
            let proxy = Arc::clone(&proxy);
            std::thread::spawn(move || read_supervisor(&down_rx, &proxy))
        },
        {
            let supervisor = Arc::clone(&supervisor);
            std::thread::spawn(move || read_proxy(&up_rx, &supervisor))
        },
    ];
    (
        Link { side: proxy },
        Supervisor { side: supervisor },
        readers,
    )
}

/// The proxy's reader: install what the supervisor sends, then say so, and hand each answer to the
/// request waiting on it. Ends when the supervisor's reader lets go of the channel, which it does
/// once the proxy has let go of its end; a request still waiting is then denied.
fn read_supervisor(rx: &Receiver<ToProxy>, side: &ProxySide) {
    for message in rx {
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
                if let Some(up) = locked(&side.up).as_ref() {
                    let _ = up.send(ToSupervisor::Installed { version: installed });
                }
            }
            ToProxy::Answer { id, verdict } => {
                if let Some(waiting) = locked(&side.parked).answers.remove(&id) {
                    let _ = waiting.send(verdict);
                }
            }
        }
    }
    locked(&side.parked).answers.clear();
}

/// The supervisor's reader: take in what the proxy confirms, and the requests it parks. Ends when
/// the proxy lets go of its end, and then lets go of the way to the proxy, which ends the proxy's
/// reader, and of the requests the proxy had parked, which ends the threads waiting on them.
fn read_proxy(rx: &Receiver<ToSupervisor>, side: &Arc<SupervisorSide>) {
    for message in rx {
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
        }
    }
    locked(&side.down).take();
    locked(&side.heard).closed = true;
    side.changed.notify_all();
    // Nobody is left to hear these answers, and a thread waiting without a timeout would otherwise
    // outlive the proxy that parked the request.
    if let Some(parks) = &side.parks {
        parks.pending.answer_all(Verdict::Deny);
    }
}

/// Let a request the proxy parked into the queue and wait for its answer on a thread of its own, or
/// deny it at once: nobody serves parks, the queue is full, or no thread could be started.
fn serve_park(side: &Arc<SupervisorSide>, id: u64, host: &str, port: u16, path: &str) {
    let Some(parks) = &side.parks else {
        return answer(side, id, Verdict::Deny);
    };
    let Some(parked) = parks.pending.enqueue(host, port, path, parks.cap) else {
        return answer(side, id, Verdict::Deny);
    };
    let seq = parked.seq;
    let (pending, timeout, notices) = (Arc::clone(&parks.pending), parks.timeout, parks.notices);
    let waiter = Arc::clone(side);
    let started = std::thread::Builder::new()
        .name("sbx-park-wait".to_string())
        .spawn(move || {
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
    if started.is_err() {
        parks.pending.forget(seq);
        answer(side, id, Verdict::Deny);
    }
}

/// Send the answer to the request the proxy parked as `id`, unless the proxy is gone.
fn answer(side: &SupervisorSide, id: u64, verdict: Verdict) {
    if let Some(down) = locked(&side.down).as_ref() {
        let _ = down.send(ToProxy::Answer { id, verdict });
    }
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
        let (link, supervisor, [proxy_reader, supervisor_reader]) = start(None);
        drop(link);
        supervisor_reader.join().unwrap();
        proxy_reader.join().unwrap();
        let e = supervisor.push(1, overlay("api.test")).unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::BrokenPipe);
    }

    /// Both readers end with the proxy, whatever the supervisor's end is doing: a process that
    /// stands up a proxy per app keeps no thread per proxy it is done with.
    #[test]
    fn both_readers_end_once_the_proxy_lets_go() {
        let (link, supervisor, [proxy_reader, supervisor_reader]) = start(None);
        supervisor.push(1, overlay("api.test")).unwrap();
        drop(link);
        supervisor_reader.join().unwrap();
        proxy_reader.join().unwrap();
        drop(supervisor);
    }

    /// A confirmation is not believed beyond what was sent: a proxy claiming a version the
    /// supervisor never sent is taken at no more than the last version the supervisor did send, so
    /// it cannot make every later push look confirmed in advance.
    #[test]
    fn a_confirmation_beyond_what_was_sent_is_not_believed() {
        let (link, supervisor) = pair();
        if let Some(up) = locked(&link.side.up).as_ref() {
            up.send(ToSupervisor::Installed { version: u64::MAX })
                .unwrap();
        }
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
            let link = Arc::new(serving(parks(&pending, 4, None)).0);
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
        let link = Arc::new(serving(parks(&pending, 4, Some(Duration::from_millis(50)))).0);
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
        let link = Arc::new(serving(parks(&pending, 1, None)).0);
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
        let (link, supervisor, [proxy_reader, supervisor_reader]) =
            start(Some(parks(&pending, 4, None)));
        // Sent as the proxy sends it, straight on the channel: a request parked with `park` would
        // hold the end this test lets go of.
        locked(&link.side.up)
            .as_ref()
            .unwrap()
            .send(ToSupervisor::Park {
                id: 1,
                host: "api.test".to_string(),
                port: 443,
                path: "/".to_string(),
            })
            .unwrap();
        assert_eq!(listed(&pending, 1).len(), 1);
        drop(link);
        supervisor_reader.join().unwrap();
        proxy_reader.join().unwrap();
        assert!(pending.list().is_empty());
        drop(supervisor);
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
}
