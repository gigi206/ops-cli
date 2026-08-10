//! The ssh-agent broker's control plane: a bounded, in-RAM ring of the decisions the broker made on
//! the cage's behalf, plus the per-session Unix socket a host-side `sbx ssh-agent log` reaches to
//! read them.
//!
//! The broker itself ([`super::sshagent`]) decides one request at a time and forgets it. That left
//! the one thing a credential channel must not leave unrecorded: *what was signed, with which key,
//! and what was turned away*. A grant is reported at launch, but a launch note cannot say whether
//! the cage signed once or a thousand times, nor that it tried a key it was never given.
//!
//! Same shape and the same security as the filesystem and exec lenses ([`super::fs_control`],
//! [`super::proc_control`]): the socket is bound under the `0700` data dir and is **never** bound
//! into the cage — in Mode B the in-cage agent is the adversary, so it must not read (or amend) the
//! record of what it asked for. The ring is never written to disk, is owner-only RAM for the
//! session's lifetime, and dies with it.
//!
//! The wire protocol is the line-based one its siblings use (one command per connection): `LOG`
//! returns the retained events (a `dropped=` line when a `--follow` cursor fell behind the ring, a
//! `head=` cursor, then one `event …` line each) then `ok`; `LOG after=<seq>` returns only events
//! past that cursor. The free-text `detail` is emitted **last** on an event line and taken verbatim
//! by the reader; [`sanitize_detail`] strips it of control characters first, so it can never inject
//! a second line.

use std::io;
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::sync::Arc;

/// How many recent broker decisions a session retains. An ssh session asks for one signature per
/// authentication, so this is a deep window in practice — deeper than the egress ring needs to be,
/// because these events are rare and each one matters.
pub(crate) const AGENT_RING_CAP: usize = 500;

/// The longest `detail` an event carries. A key comment comes from the user's own agent and is
/// free-form, so it is capped as well as sanitised.
const DETAIL_MAX: usize = 200;

/// What the broker did. A closed enum with a fixed one-word wire token, so it is a safe field ahead
/// of the verbatim `detail=`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AgentKind {
    /// The cage asked which keys it may use, and was told.
    List,
    /// A signature was produced with a granted key — the event that matters most, because it is the
    /// one that authenticates as the user somewhere.
    Sign,
    /// A request was turned away: a key the grant does not name, a message type the allowlist does
    /// not admit, or a confirmation that was declined.
    Refuse,
}

impl AgentKind {
    /// The one-word wire token — also what the human and `--json` views print.
    pub(crate) fn token(self) -> &'static str {
        match self {
            AgentKind::List => "list",
            AgentKind::Sign => "sign",
            AgentKind::Refuse => "refuse",
        }
    }

    fn from_token(s: &str) -> Option<Self> {
        match s {
            "list" => Some(AgentKind::List),
            "sign" => Some(AgentKind::Sign),
            "refuse" => Some(AgentKind::Refuse),
            _ => None,
        }
    }
}

/// One decision the broker made. `detail` names the key for a signature, or says what was refused
/// and why; it is sanitised and capped by [`AgentRing::push`], so it is safe on the line-based wire
/// and safe to print.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AgentEvent {
    pub(crate) seq: u64,
    /// Wall-clock time in epoch milliseconds — a clean stamp for `--json`; the human view renders it
    /// as a local `hh:mm:ss`.
    pub(crate) at_epoch_ms: u128,
    pub(crate) kind: AgentKind,
    pub(crate) detail: String,
}

impl super::lens::Event for AgentEvent {
    fn seq(&self) -> u64 {
        self.seq
    }

    /// The fixed fields are `key=value` tokens; `detail` is emitted **last** and taken verbatim by
    /// the reader, since it carries spaces. [`sanitize_detail`] has already stripped it of control
    /// characters, so it cannot close the line and forge a second event.
    fn format_line(&self) -> String {
        format!(
            "event seq={} at={} kind={} detail={}\n",
            self.seq,
            self.at_epoch_ms,
            self.kind.token(),
            self.detail
        )
    }

    /// Read one `event seq=… at=… kind=… detail=…` line back, or `None` if malformed.
    fn parse_line(line: &str) -> Option<Self> {
        let (mut seq, mut at, mut kind) = (None, None, None);
        let detail = super::lens::read_event_line(line, "detail=", |key, value| match key {
            "seq" => seq = value.parse().ok(),
            "at" => at = value.parse().ok(),
            "kind" => kind = AgentKind::from_token(value),
            _ => {}
        })?;
        Some(AgentEvent {
            seq: seq?,
            at_epoch_ms: at?,
            kind: kind?,
            detail: detail.to_string(),
        })
    }
}

/// The result of a `LOG` query over this lens. See [`super::lens::Snapshot`].
pub(crate) type AgentSnapshot = super::lens::Snapshot<AgentEvent>;

/// Strip a detail of anything that could forge a second wire line or a terminal escape, and cap its
/// length. A key comment is free-form text from the user's own agent; a refusal reason is one of a
/// closed set of literals. Neither is cage-controlled, but the record of a credential channel is
/// exactly the wrong place to trust that and be wrong: an event line whose `detail` could contain a
/// newline would let one entry write another.
fn sanitize_detail(s: &str) -> String {
    let mut out: String = s
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect();
    if out.chars().count() > DETAIL_MAX {
        out = out.chars().take(DETAIL_MAX - 1).collect::<String>() + "…";
    }
    out
}

/// A bounded ring of recent broker decisions. Shared (via `Arc`) between the broker's per-connection
/// threads (which [`push`](AgentRing::push)) and the control serve thread (which
/// [`snapshot`](super::lens::Ring::snapshot)s for `sbx ssh-agent log`). The sequencing and eviction are
/// [`super::lens::Ring`]'s; what this adds is the shape of a decision — and the announcement a
/// refusal makes on its way in.
pub(crate) struct AgentRing {
    ring: super::lens::Ring<AgentEvent>,
    /// Where a refusal is announced (`[notify] events.ssh_agent`), or `None` when the launch wired
    /// none. Consulted from [`AgentRing::push`] — the one place every outcome passes through — so a
    /// refusal added later cannot forget to announce itself.
    notifier: Option<Arc<crate::sandbox::notify_sink::Notifier>>,
}

impl AgentRing {
    pub(crate) fn new(cap: usize) -> Self {
        AgentRing {
            ring: super::lens::Ring::new(cap),
            notifier: None,
        }
    }

    /// Attach the launch's refusal notifier, so a withheld key is said out loud and not only
    /// recorded for whoever thinks to run `sbx ssh-agent logs`.
    pub(crate) fn with_notifier(
        mut self,
        notifier: Arc<crate::sandbox::notify_sink::Notifier>,
    ) -> Self {
        self.notifier = Some(notifier);
        self
    }

    /// Append one decision, sanitising and capping its detail. Returns the assigned sequence number.
    pub(crate) fn push(&self, kind: AgentKind, detail: &str) -> u64 {
        // Announce a refusal from here, the single point every outcome passes through, and announce
        // it *before* the ring is touched — delivery reaches the desktop bus, and doing that under
        // the ring's lock would stall the reader answering `sbx ssh-agent logs`. A `list` or a
        // `sign` is the channel working as granted — only a refusal is the boundary biting, and it is
        // the one outcome the cage sees as a bare protocol failure it need never mention.
        if kind == AgentKind::Refuse
            && let Some(notifier) = &self.notifier
        {
            notifier.block(crate::notify::Block {
                event: crate::notify::NotifyEvent::SshAgent,
                // The detail is already the whole of what happened — which key, toward which
                // destination — so it is the identity a repeat is measured on. Two refusals of
                // the same key toward the same host read identically and coalesce; a different
                // key, or the same key toward somewhere else, is its own problem.
                subject: detail.to_string(),
                reason: "withheld".to_string(),
                detail: String::new(),
                // Nothing to suggest: widening `[ssh_agent] allow` because the cage reached for a
                // key it was not given is the opposite of the answer.
                fix: String::new(),
            });
        }
        self.ring.push_with(|seq, at_epoch_ms| AgentEvent {
            seq,
            at_epoch_ms,
            kind,
            detail: sanitize_detail(detail),
        })
    }
}

/// The ring underneath, so a snapshot reads the same on this lens as on any other: `snapshot` is
/// [`super::lens::Ring`]'s and is reached through here, while `push` above stays this lens's own.
impl std::ops::Deref for AgentRing {
    type Target = super::lens::Ring<AgentEvent>;

    fn deref(&self) -> &Self::Target {
        &self.ring
    }
}

/// Serve the control socket, answering `LOG` from the ring the broker pushes to. See
/// [`super::lens::serve`].
pub(crate) fn serve(listener: UnixListener, ring: Arc<AgentRing>) -> io::Result<()> {
    super::lens::serve(listener, move |cmd| super::lens::dispatch_log(cmd, &ring))
}

// ── Client side (the `sbx ssh-agent log` process) ──────────────────────────────────────────────

/// The control socket path for a session pid, under the broker's own runtime directory — the same
/// `0700` directory its agent socket is bound in, and never a path inside any cage.
pub(crate) fn agent_control_socket(data_dir: &Path, pid: u32) -> PathBuf {
    super::lens::control_socket(&data_dir.join("ssh-agent"), pid)
}

/// Query one session's control socket for its broker decisions. A session whose socket is absent
/// (no grant, or a dead launch) fails the connect, which the caller distinguishes from an empty log.
/// See [`super::lens::read_log`].
pub(crate) fn read_agent_log(socket: &Path, after: Option<u64>) -> io::Result<AgentSnapshot> {
    super::lens::read_log(socket, after)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sandbox::lens::Event as _;

    /// The ring's own sequencing and eviction are [`super::super::lens`]'s and tested there. What is
    /// this lens's to get right is the mapping: what the broker calls a decision must land on the
    /// fields `sbx ssh-agent logs` reads back.
    #[test]
    fn push_maps_its_arguments_onto_the_event() {
        let ring = AgentRing::new(8);
        assert_eq!(ring.push(AgentKind::Sign, "deploy@example"), 1);
        assert_eq!(ring.push(AgentKind::Refuse, "an unlisted key"), 2);
        let snap = ring.snapshot(None);
        assert_eq!(snap.events[0].kind, AgentKind::Sign);
        assert_eq!(snap.events[0].detail, "deploy@example");
        assert_eq!(snap.events[1].kind, AgentKind::Refuse);
        assert_eq!(snap.events[1].detail, "an unlisted key");
    }

    /// The record of a credential channel is the wrong place for one entry to be able to write
    /// another: a newline in a key comment would close the line and forge a second event.
    #[test]
    fn a_detail_can_never_forge_a_second_event_line() {
        let ring = AgentRing::new(8);
        ring.push(
            AgentKind::Sign,
            "deploy@example\nevent seq=99 at=0 kind=sign detail=forged",
        );
        let wire: String = ring
            .snapshot(None)
            .events
            .iter()
            .map(crate::sandbox::lens::Event::format_line)
            .collect();

        // The forged text survives as *text* — that is fine and even honest. What must not happen is
        // that it becomes a line, because a line is what a reader turns back into an event.
        assert_eq!(wire.lines().count(), 1, "one event, one line: {wire:?}");
        let parsed: Vec<AgentEvent> = wire.lines().filter_map(AgentEvent::parse_line).collect();
        assert_eq!(parsed.len(), 1, "one event read back: {wire:?}");
        assert_eq!(parsed[0].seq, 1, "not the sequence the payload named");
        assert!(parsed[0].detail.starts_with("deploy@example "));
        assert!(
            parsed[0].detail.contains("detail=forged"),
            "the attempt is kept verbatim inside the one field it landed in: {parsed:?}"
        );

        // And a long comment is capped rather than allowed to fill the ring's whole line budget.
        let ring = AgentRing::new(8);
        ring.push(AgentKind::List, &"x".repeat(10_000));
        assert!(ring.snapshot(None).events[0].detail.chars().count() <= DETAIL_MAX);
    }

    #[test]
    fn the_wire_round_trips_a_log_query() {
        let ring = Arc::new(AgentRing::new(8));
        ring.push(AgentKind::List, "offered deploy@example (5 withheld)");
        ring.push(AgentKind::Sign, "deploy@example");
        ring.push(AgentKind::Refuse, "a key the grant does not name");

        let reply = crate::sandbox::lens::dispatch_log("LOG", &ring);
        assert!(reply.ends_with("ok\n"), "{reply}");
        let parsed: Vec<AgentEvent> = reply
            .lines()
            .filter(|l| l.starts_with("event "))
            .filter_map(AgentEvent::parse_line)
            .collect();
        assert_eq!(parsed.len(), 3);
        assert_eq!(parsed[1].kind, AgentKind::Sign);
        assert_eq!(parsed[1].detail, "deploy@example");
        assert_eq!(parsed[2].kind, AgentKind::Refuse);

        // A cursor past the head is a valid, empty answer that still carries the cursor.
        let reply = crate::sandbox::lens::dispatch_log("LOG after=3", &ring);
        assert!(reply.contains("head=3"), "{reply}");
        assert!(!reply.contains("event "), "{reply}");
        assert_eq!(
            crate::sandbox::lens::dispatch_log("NOPE", &ring),
            "err bad-request\n"
        );
    }

    /// The whole point of the socket is that the *host* reads it. A live end-to-end pass over a real
    /// Unix socket, since the serve/read pair is where a protocol mistake would hide.
    #[test]
    fn a_client_reads_the_log_over_a_real_socket() {
        let dir = crate::testutil::TmpDir::new();
        let sock = dir.path().join("control-test.sock");
        let ring = Arc::new(AgentRing::new(8));
        ring.push(AgentKind::Sign, "deploy@example");
        let listener = UnixListener::bind(&sock).expect("bind");
        let served = ring.clone();
        std::thread::spawn(move || {
            let _ = serve(listener, served);
        });

        let snap = read_agent_log(&sock, None).expect("the log reads back");
        assert_eq!(snap.events.len(), 1);
        assert_eq!(snap.events[0].kind, AgentKind::Sign);
        assert_eq!(snap.events[0].detail, "deploy@example");
        assert_eq!(snap.head, 1);

        // A second, later event is picked up past the cursor — the `--follow` path.
        ring.push(AgentKind::Refuse, "an unlisted key");
        let snap = read_agent_log(&sock, Some(snap.head)).expect("the follow read");
        assert_eq!(snap.events.len(), 1);
        assert_eq!(snap.events[0].kind, AgentKind::Refuse);
    }
}

#[cfg(test)]
mod notify_tests {
    use super::*;
    use crate::notify::{NotifyMode, NotifyPolicy};
    use crate::sandbox::notify_sink::{Notifier, Sink};
    use std::sync::Mutex;

    /// Records the summaries a ring's outcomes produced.
    struct Recorder(Arc<Mutex<Vec<String>>>);

    impl Sink for Recorder {
        fn deliver(
            &mut self,
            summary: &str,
            body: &str,
            _replaces: Option<u32>,
        ) -> Result<Option<u32>, ()> {
            self.0.lock().unwrap().push(format!("{summary}|{body}"));
            Ok(None)
        }
    }

    /// Push `events` through a ring wired to a recording notifier, and return what was announced.
    fn announced(events: &[(AgentKind, &str)]) -> Vec<String> {
        let seen = Arc::new(Mutex::new(Vec::new()));
        let notifier = Arc::new(Notifier::recording(
            NotifyPolicy::uniform(NotifyMode::Once),
            Box::new(Recorder(Arc::clone(&seen))),
        ));
        {
            let ring = AgentRing::new(16).with_notifier(Arc::clone(&notifier));
            for (kind, detail) in events {
                ring.push(*kind, detail);
            }
        }
        // Drop the last reference so the delivery thread drains and joins before we read.
        drop(
            Arc::try_unwrap(notifier)
                .map_err(|_| "the notifier is still shared")
                .unwrap(),
        );

        seen.lock().unwrap().clone()
    }

    #[test]
    fn only_a_refusal_is_announced() {
        // A `list` and a `sign` are the channel working exactly as granted — announcing them would
        // turn every authenticated `git push` into a desktop notification. Only the boundary biting
        // is worth saying out loud.
        let out = announced(&[
            (AgentKind::List, "offered id_ed25519 (1 withheld)"),
            (AgentKind::Sign, "id_ed25519 toward git@example.com"),
            (
                AgentKind::Refuse,
                "a signature with a key the grant does not name",
            ),
        ]);
        assert_eq!(out.len(), 1, "only the refusal, got {out:?}");
        // The whole refusal rides the summary here: this event carries its story in the subject,
        // and the body stays empty, so the recorded line ends on the separator.
        assert_eq!(
            out[0],
            "Blocked: a signature with a key the grant does not name|"
        );
    }

    #[test]
    fn a_refusal_toward_a_different_destination_is_its_own_problem() {
        // The identity is the whole recorded detail, which carries the destination. Two reaches for
        // the same withheld key toward *different* hosts are two separate attempts and are each
        // worth hearing; two identical ones coalesce under `once`.
        let out = announced(&[
            (
                AgentKind::Refuse,
                "a signature with a key the grant does not name toward a@x",
            ),
            (
                AgentKind::Refuse,
                "a signature with a key the grant does not name toward b@y",
            ),
            (
                AgentKind::Refuse,
                "a signature with a key the grant does not name toward a@x",
            ),
        ]);
        assert_eq!(
            out.len(),
            2,
            "two destinations, the repeat coalesced: {out:?}"
        );
    }
}
