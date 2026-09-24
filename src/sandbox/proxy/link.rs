//! What the supervisor tells the proxy about the state it decides with, and what the proxy answers.
//!
//! [`super::events`] carries the proxy's account of its own work, one way. This carries the other
//! direction: state the supervisor owns and the proxy decides with, beginning with the rules an
//! operator loads into a running session (`sbx net allow|deny|mute --session`, or an `ask` answered
//! with `--session`). The proxy is to run in a process of its own, so neither side holds the other's
//! structures: each end reads its own channel on a thread of its own, and the socket that replaces
//! the channels when the proxy moves changes what carries the messages, not who reads them.
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

use crate::allowlist::Rule;
use crate::sandbox::locks::{locked, read_locked, write_locked};
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

/// What the supervisor tells the proxy.
enum ToProxy {
    /// The whole overlay, as of `version`.
    Overlay { version: u64, overlay: Overlay },
}

/// What the proxy tells the supervisor.
enum ToSupervisor {
    /// The overlay in force is the one sent as `version`, or a later one.
    Installed { version: u64 },
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
}

impl Link {
    /// An end no supervisor reaches: its overlay is empty for good. What a proxy is built with
    /// before a launch wires it, and all a test that loads no rule needs.
    pub(crate) fn detached() -> Self {
        Link {
            side: Arc::new(ProxySide {
                overlay: RwLock::new((0, Arc::new(Overlay::default()))),
                up: Mutex::new(None),
            }),
        }
    }

    /// The overlay in force. Taken once per decision, so a push landing mid-decision is the next
    /// decision's.
    pub(crate) fn overlay(&self) -> Arc<Overlay> {
        Arc::clone(&read_locked(&self.side.overlay).1)
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
    /// The way to the proxy, until the proxy has let go of its end.
    down: Mutex<Option<Sender<ToProxy>>>,
    heard: Mutex<Heard>,
    changed: Condvar,
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

/// Join a proxy to the supervisor that serves it, starting the reader on each side. Both readers end
/// once the proxy lets go of its [`Link`].
pub(crate) fn pair() -> (Link, Supervisor) {
    let (link, supervisor, _) = start();
    (link, supervisor)
}

/// [`pair`], keeping the two readers' handles.
fn start() -> (Link, Supervisor, [std::thread::JoinHandle<()>; 2]) {
    let (down_tx, down_rx) = channel();
    let (up_tx, up_rx) = channel();
    let proxy = Arc::new(ProxySide {
        overlay: RwLock::new((0, Arc::new(Overlay::default()))),
        up: Mutex::new(Some(up_tx)),
    });
    let supervisor = Arc::new(SupervisorSide {
        down: Mutex::new(Some(down_tx)),
        heard: Mutex::new(Heard::default()),
        changed: Condvar::new(),
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

/// The proxy's reader: install what the supervisor sends, then say so. Ends when the supervisor's
/// reader lets go of the channel, which it does once the proxy has let go of its end.
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
        }
    }
}

/// The supervisor's reader: take in what the proxy confirms. Ends when the proxy lets go of its end,
/// and then lets go of the way to the proxy, which ends the proxy's reader.
fn read_proxy(rx: &Receiver<ToSupervisor>, side: &SupervisorSide) {
    for message in rx {
        match message {
            ToSupervisor::Installed { version } => {
                let mut heard = locked(&side.heard);
                heard.installed = heard.installed.max(version.min(heard.sent));
                side.changed.notify_all();
            }
        }
    }
    locked(&side.down).take();
    locked(&side.heard).closed = true;
    side.changed.notify_all();
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
        let (link, supervisor, [proxy_reader, supervisor_reader]) = start();
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
        let (link, supervisor, [proxy_reader, supervisor_reader]) = start();
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
}
