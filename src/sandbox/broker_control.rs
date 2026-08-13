//! A broker plugin's control plane: the decisions it made on the cage's behalf, and the
//! per-session socket a reader reaches them through.
//!
//! The fourth lens, built on the same substrate as the filesystem, exec and ssh-agent ones
//! ([`super::lens`]), and for the same reason the ssh-agent broker has one: a credential channel
//! that decides and forgets leaves the one question nobody can answer afterwards — *what did the
//! cage ask for, and what was turned away*. A launch note says a broker was stood up; it cannot say
//! whether the cage was refused once or a thousand times.
//!
//! The security posture is the substrate's, and it matters here: the socket is bound under the
//! `0700` data directory and is **never** bound into the cage. In Mode B the in-cage agent is the
//! adversary, so it must not read — or amend — the record of what it asked for.
//!
//! One thing is different from the lenses that watch the cage, and it is why `detail` is treated
//! with more suspicion here: part of it comes from **third-party plugin code**. A verdict
//! carries a `label` the plugin writes, and it is joined to what sbx itself observed. Both halves
//! go through the substrate's sanitiser, so neither can close the wire line and forge a second
//! event; and what sbx observed is written first, so a label can never dress a forward up as a
//! refusal.

use std::io;
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::sync::Arc;

/// How many decisions one session keeps. The same order as the ssh-agent broker's, and for the
/// same reason: these events are rare and each one matters.
pub(crate) const BROKER_RING_CAP: usize = 500;

/// What the broker did with one frame, as **sbx observed it** — never as the plugin described it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BrokerKind {
    /// Passed to the host resource, and its answer returned to the cage.
    Forward,
    /// Answered by the plugin, without the host resource being contacted.
    Answer,
    /// Turned away. The frame never reached the host resource.
    Refuse,
}

impl BrokerKind {
    /// The one-word wire token — also what the human and `--json` views print.
    pub(crate) fn token(self) -> &'static str {
        match self {
            BrokerKind::Forward => "forward",
            BrokerKind::Answer => "answer",
            BrokerKind::Refuse => "refuse",
        }
    }

    fn from_token(s: &str) -> Option<Self> {
        match s {
            "forward" => Some(BrokerKind::Forward),
            "answer" => Some(BrokerKind::Answer),
            "refuse" => Some(BrokerKind::Refuse),
            _ => None,
        }
    }
}

/// One decision. `detail` is sanitised and capped by [`BrokerRing::push`], so it is safe on the
/// line-based wire and safe to print.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct BrokerEvent {
    pub(crate) seq: u64,
    /// Wall-clock time in epoch milliseconds — a clean stamp for `--json`; the human view renders
    /// it as a local `hh:mm:ss`.
    pub(crate) at_epoch_ms: u128,
    pub(crate) kind: BrokerKind,
    pub(crate) detail: String,
}

impl super::lens::Event for BrokerEvent {
    fn seq(&self) -> u64 {
        self.seq
    }

    fn format_line(&self) -> String {
        format!(
            "event seq={} at={} kind={} detail={}\n",
            self.seq,
            self.at_epoch_ms,
            self.kind.token(),
            self.detail
        )
    }

    fn parse_line(line: &str) -> Option<Self> {
        let (mut seq, mut at, mut kind) = (None, None, None);
        let detail = super::lens::read_event_line(line, "detail=", |key, value| match key {
            "seq" => seq = value.parse().ok(),
            "at" => at = value.parse().ok(),
            "kind" => kind = BrokerKind::from_token(value),
            _ => {}
        })?;
        Some(BrokerEvent {
            seq: seq?,
            at_epoch_ms: at?,
            kind: kind?,
            detail: detail.to_string(),
        })
    }
}

/// The result of a `LOG` query over this lens. See [`super::lens::Snapshot`].
pub(crate) type BrokerSnapshot = super::lens::Snapshot<BrokerEvent>;

/// A bounded ring of one **session's** recent broker decisions, shared between every broker's
/// per-connection threads and the control serve thread.
///
/// One ring for the session, not one per broker, with the broker named at each push. A ring per
/// broker would need a socket per broker under one per-session name, and
/// [`super::lens::bind_and_serve`] unlinks before it binds: the second broker to stand up would
/// silently take the first's path, and a reader would see one broker's decisions and have no way to
/// know the others existed.
pub(crate) struct BrokerRing(super::lens::Ring<BrokerEvent>);

impl BrokerRing {
    pub(crate) fn new(cap: usize) -> Self {
        BrokerRing(super::lens::Ring::new(cap))
    }

    /// Append one decision. `broker` names which one made it, `observed` is sbx's own account and is
    /// written first, and `label` is the plugin's, appended only when it said something.
    ///
    /// The order is deliberate. A label is third-party text, and a reader scanning a column of
    /// events reads the front of each line: putting the broker's name and sbx's verdict there means
    /// a plugin cannot make a forward *look* like a refusal by choosing its words.
    pub(crate) fn push(
        &self,
        kind: BrokerKind,
        broker: &str,
        observed: &str,
        label: Option<&str>,
    ) -> u64 {
        let detail = match label {
            Some(l) if !l.is_empty() => format!("{broker}: {observed} — {l}"),
            _ => format!("{broker}: {observed}"),
        };
        self.0.push_with(|seq, at_epoch_ms| BrokerEvent {
            seq,
            at_epoch_ms,
            kind,
            detail: super::lens::sanitize_detail(&detail),
        })
    }
}

/// The ring underneath, so a snapshot reads the same on this lens as on any other.
impl std::ops::Deref for BrokerRing {
    type Target = super::lens::Ring<BrokerEvent>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

/// Serve the control socket, answering `LOG` from the ring the broker pushes to.
pub(crate) fn serve(listener: UnixListener, ring: Arc<BrokerRing>) -> io::Result<()> {
    super::lens::serve(listener, move |cmd| super::lens::dispatch_log(cmd, &ring))
}

/// The control socket path for a session pid, under the broker's own `0700` runtime directory —
/// never a path inside any cage.
pub(crate) fn broker_control_socket(data_dir: &Path, pid: u32) -> PathBuf {
    super::lens::control_socket(&data_dir.join("broker"), pid)
}

/// Query one session's broker decisions. A session whose socket is absent (no broker, or a dead
/// launch) fails the connect, which the caller distinguishes from an empty log.
pub(crate) fn read_broker_log(socket: &Path, after: Option<u64>) -> io::Result<BrokerSnapshot> {
    super::lens::read_log(socket, after)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sandbox::lens::Event as _;

    /// One session's brokers share one ring, so a decision that did not say which of them made it
    /// would be a decision a reader cannot act on. The two-broker case is the point: the record has
    /// to hold both, and each line has to be attributable.
    #[test]
    fn every_decision_names_the_broker_that_made_it() {
        let ring = BrokerRing::new(BROKER_RING_CAP);
        ring.push(
            BrokerKind::Refuse,
            "gpg-agent",
            "a request the policy does not admit",
            None,
        );
        ring.push(BrokerKind::Forward, "vault-agent", "a request", None);
        let events = ring.snapshot(None).events;
        assert_eq!(events[0].kind, BrokerKind::Refuse);
        assert!(
            events[0].detail.starts_with("gpg-agent: "),
            "{:?}",
            events[0]
        );
        assert!(
            events[1].detail.starts_with("vault-agent: "),
            "a second broker's decisions land in the same record, under its own name: {:?}",
            events[1]
        );
    }

    /// sbx's account leads, the plugin's follows. A reader scanning the front of each line sees
    /// what sbx observed, so a plugin cannot dress a forward up as a refusal by choosing words.
    #[test]
    fn what_sbx_observed_is_written_before_what_the_plugin_said() {
        let ring = BrokerRing::new(BROKER_RING_CAP);
        ring.push(
            BrokerKind::Forward,
            "gpg-agent",
            "a request",
            Some("REFUSED EVERYTHING, honest"),
        );
        let detail = &ring.snapshot(None).events[0].detail;
        let observed = detail.find("a request").expect("sbx's account is there");
        let claimed = detail.find("REFUSED").expect("the label is there");
        assert!(observed < claimed, "{detail}");
        assert_eq!(ring.snapshot(None).events[0].kind, BrokerKind::Forward);
    }

    /// A label is third-party text on a line-based wire: one carrying a newline would let one
    /// event write a second. The forged text survives *as text* — `detail=` is taken verbatim to
    /// the end of the line — and that is the point: it is one line, so it parses back as one
    /// event, the real one.
    #[test]
    fn a_label_cannot_forge_a_second_event() {
        let ring = BrokerRing::new(BROKER_RING_CAP);
        ring.push(
            BrokerKind::Forward,
            "gpg-agent",
            "a request",
            Some("ok\nevent seq=99 at=0 kind=refuse detail=forged"),
        );
        let line = ring.snapshot(None).events[0].format_line();
        assert_eq!(
            line.matches('\n').count(),
            1,
            "one line, whatever it says: {line}"
        );
        let parsed = BrokerEvent::parse_line(line.trim_end()).expect("parses back");
        assert_eq!(parsed.seq, 1, "the forged sequence is inert: {line}");
        assert_eq!(parsed.kind, BrokerKind::Forward);
    }

    #[test]
    fn an_event_survives_the_wire_round_trip() {
        let ring = BrokerRing::new(BROKER_RING_CAP);
        ring.push(
            BrokerKind::Answer,
            "gpg-agent",
            "the identities it may see",
            Some("2 of 5"),
        );
        let event = ring.snapshot(None).events[0].clone();
        // Trimmed as the real reader trims: it splits on `lines()`, so a `parse_line` never sees
        // the terminator `format_line` writes.
        let parsed = BrokerEvent::parse_line(event.format_line().trim_end()).expect("parses back");
        assert_eq!(parsed, event);
    }
}
