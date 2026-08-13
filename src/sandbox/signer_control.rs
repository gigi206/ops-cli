//! What a signer plugin formed for the cage's requests, and the per-session socket a reader reaches
//! it through.
//!
//! The fifth lens, built on the same substrate as the filesystem, exec, ssh-agent and broker ones
//! ([`super::lens`]). It answers the question the egress lens cannot: `sbx net logs` says a request
//! was allowed and, on a refusal, that no signature could be formed — it never says *what* was put
//! on the request, or which of several declarations formed it. A credential channel that decides and
//! forgets leaves that unanswerable afterwards.
//!
//! One ring per session, not one per signer. A launch may declare several, and each event names the
//! signer that formed it: a second ring would need a second socket, and two sockets under one
//! per-session name is how a reader ends up seeing one signer and believing it saw them all.
//!
//! The security posture is the substrate's: the socket is bound under the `0700` data directory and
//! is **never** bound into the cage. In Mode B the in-cage agent is the adversary, so it must not
//! read — or amend — the record of what was signed on its behalf.
//!
//! Two things are different from the lenses that watch the cage, and both are about the text an
//! event carries. Part of it comes from **third-party plugin code**: an answer carries a label the
//! plugin writes, and a refusal carries its reason. Both are joined *after* what sbx itself observed,
//! so a plugin cannot dress a refusal up as a signature by choosing its words. And the whole detail
//! is **redacted against the launch's needles before it is capped**, because a signer is the one
//! plugin that may hold a credential in plaintext: a value echoed back in a label would otherwise
//! reach the very record the user reads to audit it.

use std::io;
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use super::proxy::SecretNeedle;

/// How many signatures one session keeps.
///
/// A thousand, like the exec and egress rings rather than the broker's five hundred: this lens ticks
/// once per *request* to a signed host, not once per rare decision, so its rhythm is the traffic's.
pub(crate) const SIGNER_RING_CAP: usize = 1000;

/// What became of one request's credential, as **sbx observed it** — never as the plugin described
/// it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SignerKind {
    /// The plugin formed the headers, and they went on the request.
    Sign,
    /// The plugin could not, so the request was not sent.
    Refuse,
}

impl SignerKind {
    /// The one-word wire token — also what the human and `--json` views print.
    pub(crate) fn token(self) -> &'static str {
        match self {
            SignerKind::Sign => "sign",
            SignerKind::Refuse => "refuse",
        }
    }

    fn from_token(s: &str) -> Option<Self> {
        match s {
            "sign" => Some(SignerKind::Sign),
            "refuse" => Some(SignerKind::Refuse),
            _ => None,
        }
    }
}

/// One request's credential. `detail` is redacted, sanitised and capped by [`SignerRing::push`], so
/// it is safe on the line-based wire and safe to print.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SignerEvent {
    pub(crate) seq: u64,
    /// Wall-clock time in epoch milliseconds — a clean stamp for `--json`; the human view renders
    /// it as a local `hh:mm:ss`.
    pub(crate) at_epoch_ms: u128,
    pub(crate) kind: SignerKind,
    pub(crate) detail: String,
}

impl super::lens::Event for SignerEvent {
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
            "kind" => kind = SignerKind::from_token(value),
            _ => {}
        })?;
        Some(SignerEvent {
            seq: seq?,
            at_epoch_ms: at?,
            kind: kind?,
            detail: detail.to_string(),
        })
    }
}

/// The result of a `LOG` query over this lens. See [`super::lens::Snapshot`].
pub(crate) type SignerSnapshot = super::lens::Snapshot<SignerEvent>;

/// A bounded ring of one session's recent signatures, shared between the proxy's request threads and
/// the control serve thread.
pub(crate) struct SignerRing(super::lens::Ring<SignerEvent>);

impl SignerRing {
    pub(crate) fn new(cap: usize) -> Self {
        SignerRing(super::lens::Ring::new(cap))
    }

    /// Append one signature or refusal. `observed` is sbx's own account and is written first;
    /// `claimed` is the plugin's — its label on an answer, its reason on a refusal — and is appended
    /// only when it said something.
    ///
    /// The order is deliberate, and it is the broker lens's rule for the same reason: a reader
    /// scanning a column of events reads the front of each line, so putting sbx's account there
    /// means a plugin cannot make a refusal *look* like a signature by choosing its words.
    ///
    /// `needles` are the launch's credential needles, and they are applied to the **whole** detail
    /// before it is capped, in that order and not the other way round. A signer is the one plugin
    /// type that may be handed a credential in plaintext, so a value echoed into a label is a real
    /// path to this record; and a cap applied first would cut a value in half, leaving the front of
    /// it in the line and no needle left to match.
    pub(crate) fn push(
        &self,
        kind: SignerKind,
        signer: &str,
        observed: &str,
        claimed: Option<&str>,
        needles: &[SecretNeedle],
    ) -> u64 {
        let detail = match claimed {
            Some(c) if !c.is_empty() => format!("{signer}: {observed} — {c}"),
            _ => format!("{signer}: {observed}"),
        };
        let (detail, _) = crate::sandbox::redact::redact_string(
            &detail,
            needles,
            &crate::sandbox::redact::Placeholder::Plain,
        );
        self.0.push_with(|seq, at_epoch_ms| SignerEvent {
            seq,
            at_epoch_ms,
            kind,
            detail: super::lens::sanitize_detail(&detail),
        })
    }
}

// The events are already redacted and capped by `push`, but a `Debug` that dumped a session's
// whole record would be noise wherever a holder of this ring renders itself. The count is what a
// reader of such a line actually wants.
impl std::fmt::Debug for SignerRing {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "SignerRing({} events)",
            self.0.snapshot(None).events.len()
        )
    }
}

/// The ring underneath, so a snapshot reads the same on this lens as on any other.
impl std::ops::Deref for SignerRing {
    type Target = super::lens::Ring<SignerEvent>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

/// Serve the control socket, answering `LOG` from the ring the proxy pushes to.
pub(crate) fn serve(listener: UnixListener, ring: Arc<SignerRing>) -> io::Result<()> {
    super::lens::serve(listener, move |cmd| super::lens::dispatch_log(cmd, &ring))
}

/// The reader's end of the session's signer record, unlinked when the launch ends. Never bound into
/// any cage — the agent must not read, or amend, the record of what was signed on its behalf.
///
/// A guard of its own, like the brokers' [`super::broker::BrokerFeed`], because the record belongs
/// to the *session*: the proxy that serves the agent and the per-invocation proxies its declared
/// operations stand up all push into one ring, and unlinking its socket when any one of them goes
/// would end a reader's `--follow` while the others were still signing.
pub(crate) struct SignerFeed {
    control_uds: PathBuf,
}

impl Drop for SignerFeed {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.control_uds);
    }
}

/// Stand up the session's signer record: the shared ring, and the socket
/// `sbx logs --feed signer` reads it through.
///
/// Called once per launch that declares a signer anywhere — in a `[[secret]]` or in a
/// `[task.<name>.inject]` — before the proxy that will push into it exists, so the first signature
/// cannot beat a reader to the socket.
///
/// The ring is returned whatever happens to the socket: signing is the point and the record is its
/// witness, so a reader that cannot be stood up degrades to signing with no reader rather than to
/// no signing. The guard is `None` then, and the warning says so.
pub(crate) fn stand_up_feed(
    layout: &crate::store::Layout,
) -> (Arc<SignerRing>, Option<SignerFeed>) {
    let ring = Arc::new(SignerRing::new(SIGNER_RING_CAP));
    let control_uds = signer_control_socket(layout.data_dir(), std::process::id());
    let served = ring.clone();
    let bound = super::lens::ensure_control_dir(&layout.data_dir().join("signer")).and_then(|()| {
        super::lens::bind_and_serve(&control_uds, move |control| serve(control, served))
    });
    match bound {
        Ok(()) => (ring, Some(SignerFeed { control_uds })),
        Err(e) => {
            crate::diag::warn(&format!(
                "credentials will be signed, but what was signed cannot be read (`{}`: {e}) — \
                 `sbx logs --feed signer` will report no signer for this session",
                control_uds.display()
            ));
            (ring, None)
        }
    }
}

/// The control socket path for a session pid, under the lens's own `0700` runtime directory — never
/// a path inside any cage.
pub(crate) fn signer_control_socket(data_dir: &Path, pid: u32) -> PathBuf {
    super::lens::control_socket(&data_dir.join("signer"), pid)
}

/// Query one session's signatures. A session whose socket is absent (no signer declared, or a dead
/// launch) fails the connect, which the caller distinguishes from an empty log.
pub(crate) fn read_signer_log(socket: &Path, after: Option<u64>) -> io::Result<SignerSnapshot> {
    super::lens::read_log(socket, after)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sandbox::lens::Event as _;

    fn ring() -> SignerRing {
        SignerRing::new(SIGNER_RING_CAP)
    }

    /// One ring serves every declaration, so an event that did not say which one formed it would
    /// leave a reader auditing all of them.
    #[test]
    fn every_signature_names_the_signer_that_formed_it() {
        let ring = ring();
        ring.push(
            SignerKind::Sign,
            "demo-sigv4",
            "PUT s3.example.com/bucket/key set Authorization",
            None,
            &[],
        );
        let events = ring.snapshot(None).events;
        assert_eq!(events[0].kind, SignerKind::Sign);
        assert!(events[0].detail.starts_with("demo-sigv4: "), "{events:?}");
    }

    /// sbx's account leads, the plugin's follows. A reader scanning the front of each line sees what
    /// sbx observed, so a plugin cannot dress a refusal up as a signature by choosing words.
    #[test]
    fn what_sbx_observed_is_written_before_what_the_plugin_said() {
        let ring = ring();
        ring.push(
            SignerKind::Refuse,
            "demo-sigv4",
            "GET s3.example.com/bucket",
            Some("SIGNED EVERYTHING, honest"),
            &[],
        );
        let detail = &ring.snapshot(None).events[0].detail;
        let observed = detail.find("GET s3").expect("sbx's account is there");
        let claimed = detail.find("SIGNED").expect("the plugin's words are there");
        assert!(observed < claimed, "{detail}");
        assert_eq!(ring.snapshot(None).events[0].kind, SignerKind::Refuse);
    }

    /// A label is third-party text on a line-based wire: one carrying a newline would let one event
    /// write a second. The forged text survives *as text* — `detail=` is taken verbatim to the end
    /// of the line — and that is the point: it is one line, so it parses back as one event, the real
    /// one.
    #[test]
    fn a_label_cannot_forge_a_second_event() {
        let ring = ring();
        ring.push(
            SignerKind::Sign,
            "demo-sigv4",
            "GET s3.example.com/bucket",
            Some("ok\nevent seq=99 at=0 kind=refuse detail=forged"),
            &[],
        );
        let line = ring.snapshot(None).events[0].format_line();
        assert_eq!(
            line.matches('\n').count(),
            1,
            "one line, whatever it says: {line}"
        );
        let parsed = SignerEvent::parse_line(line.trim_end()).expect("parses back");
        assert_eq!(parsed.seq, 1, "the forged sequence is inert: {line}");
        assert_eq!(parsed.kind, SignerKind::Sign);
    }

    /// The reason this lens redacts where the others do not: a signer may hold the credential in
    /// plaintext, so its own words are a path from the secret back to the record that audits it.
    #[test]
    fn a_credential_echoed_by_the_plugin_is_named_not_printed() {
        let ring = ring();
        let needles = vec![SecretNeedle::named(
            "aws_secret",
            b"wJalrXUtnFEMI-EXAMPLEKEY".to_vec(),
        )];
        ring.push(
            SignerKind::Refuse,
            "demo-sigv4",
            "GET s3.example.com/bucket",
            Some("could not sign with wJalrXUtnFEMI-EXAMPLEKEY"),
            &needles,
        );
        let detail = &ring.snapshot(None).events[0].detail;
        assert!(!detail.contains("wJalrXUtnFEMI"), "{detail}");
        assert!(detail.contains("${aws_secret}"), "{detail}");
    }

    /// Redaction runs before the cap, never after. The filler places the credential *across* the
    /// 200-character cap: capped first, the line would keep its leading bytes and there would be no
    /// whole needle left to match. Redacted first, it becomes a name and the line ends up short
    /// enough that the cap never bites.
    #[test]
    fn a_credential_straddling_the_cap_is_still_named() {
        let ring = ring();
        let needles = vec![SecretNeedle::named(
            "aws_secret",
            b"wJalrXUtnFEMI-EXAMPLEKEY".to_vec(),
        )];
        let filler = "x".repeat(140);
        ring.push(
            SignerKind::Refuse,
            "demo-sigv4",
            "GET s3.example.com/bucket",
            Some(&format!("{filler} wJalrXUtnFEMI-EXAMPLEKEY")),
            &needles,
        );
        let detail = &ring.snapshot(None).events[0].detail;
        assert!(
            !detail.contains("wJalrXUtnFEMI"),
            "not even its leading bytes survive: {detail}"
        );
        assert!(detail.contains("${aws_secret}"), "{detail}");
    }

    #[test]
    fn an_event_survives_the_wire_round_trip() {
        let ring = ring();
        ring.push(
            SignerKind::Sign,
            "demo-sigv4",
            "PUT s3.example.com/bucket/key?x=1 set Authorization, X-Amz-Date",
            Some("us-east-1 s3"),
            &[],
        );
        let event = ring.snapshot(None).events[0].clone();
        // Trimmed as the real reader trims: it splits on `lines()`, so a `parse_line` never sees the
        // terminator `format_line` writes.
        let parsed = SignerEvent::parse_line(event.format_line().trim_end()).expect("parses back");
        assert_eq!(parsed, event);
    }
}
