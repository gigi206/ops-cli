//! Asking a signer plugin what authenticating one request looks like.
//!
//! The counterpart of [`super::broker`] for the third plugin type. A broker stands between the cage
//! and a host resource and rules on a protocol's frames; a signer is asked a question and answers
//! with headers. It holds nothing, listens on nothing, and reaches nothing: it speaks to sbx alone,
//! over a socket pair, from a host-side cage with an empty network namespace.
//!
//! Three properties are what make the answer safe to put on a wire, and all three are enforced
//! here rather than trusted to the plugin:
//!
//! - **Only the headers its manifest declared.** A header outside `sets_headers` refuses the whole
//!   answer, so the manifest is the bound and not a description of one.
//! - **Only values that are header values.** A CR, LF or NUL in a value would end the header and
//!   start whatever the plugin wrote next: the request head is sbx's to frame. This is the same
//!   refusal a statically resolved credential meets.
//! - **Fail-closed.** Every failure here refuses the request. A request that could not be signed is
//!   never sent unsigned: it would reach the destination as an anonymous one, and what comes back
//!   would be an authentication error for a reason that has nothing to do with the credential.
//!
//! The process is **long-lived and shared**, unlike a broker's, which is started per cage
//! connection. A signer is asked once per request, so a cage per request would pay a sandbox spawn
//! on every one; one process per declaration pays it once and is serialized by whoever holds it.

use std::io::{self, Write};

use crate::plugins::signer::SignerPlugin;

/// The wire version this side speaks. Separate from the broker's: the two protocols share a shape
/// and nothing else, so a version bump on one says nothing about the other.
pub(crate) const PROTOCOL_VERSION: u32 = 1;

/// How long sbx waits for one signature before treating the plugin as gone.
///
/// A signature is a computation, not a conversation with a human, and it sits in the path of a
/// request the cage is waiting on. The wait must be bounded at all, because a silent plugin
/// otherwise holds the request thread for as long as the session lives.
const SIGN_DEADLINE: std::time::Duration = std::time::Duration::from_secs(10);

/// The longest header value a plugin may hand back.
///
/// A bound on what a plugin returns, for the reason every other plugin channel has one: the bytes
/// end up on a wire the plugin does not own. How *many* headers it may set needs no bound here,
/// because the manifest's `sets_headers` already is one: an answer is walked against that list and
/// anything outside it refuses the whole answer.
///
/// Generous for a signature, and far under what an upstream accepts as a request head.
const MAX_VALUE_BYTES: usize = 8 * 1024;

/// The longest single line sbx reads from a plugin.
///
/// One answer is one line, and sbx buffers it before it can bound anything inside it — so without a
/// ceiling a plugin that never writes a newline is a plugin that takes the host's memory. Set well
/// above what a well-formed answer reaches: with every value already capped at [`MAX_VALUE_BYTES`],
/// this leaves room for tens of them plus a label.
///
/// The reading itself is [`super::broker::read_bounded_line`], shared with the broker: a signer
/// line carries header values and a broker line carries a hex-encoded frame, so the two ceilings
/// differ, but a bound added to one reader is a bound both protocols get.
pub(super) const MAX_LINE_BYTES: u64 = 256 * 1024;

/// One request put to a signer, in the terms the plugin is allowed to see.
///
/// The method, the host, the port and the target are always shown: a signature over a request that
/// cannot see the request is not a signature. The headers are the subset the manifest named, chosen
/// by the caller — a request carries whatever the cage put on it, and what a plugin has no reason
/// to read it has no reason to be shown.
pub(crate) struct SignRequest<'a> {
    pub(crate) method: &'a str,
    pub(crate) host: &'a str,
    pub(crate) port: u16,
    /// The request target as it appears on the wire: the path with its query.
    pub(crate) target: &'a str,
    /// The declared subset of the request's headers, in the order they were sent.
    pub(crate) headers: Vec<(String, String)>,
    /// What sbx can say about the body, for a plugin whose manifest declared `body_digest`. `None`
    /// for every other plugin, and the key is then absent from the question entirely — so asking
    /// for a digest changes nothing about what any other signer is shown.
    pub(crate) body: Option<&'a BodyFacts>,
}

/// What sbx tells a signer about the body of the request it is signing.
///
/// Two shapes and one discriminant, because the difference is one a signing scheme has to act on:
/// a signature that covers the payload cannot be formed over a body sbx did not hold, and a plugin
/// told nothing would sign as though the request had none. So the absence is *stated*, with the
/// reason, rather than left to be inferred from a missing field.
pub(crate) enum BodyFacts {
    /// sbx holds the whole body: its length, and the digest the manifest asked for.
    Held {
        bytes: u64,
        algorithm: &'static str,
        digest: String,
    },
    /// sbx does not hold it, and this is why.
    Unheld { why: String },
}

impl BodyFacts {
    /// The facts for a body sbx holds in full, digested with the algorithm the manifest named.
    pub(crate) fn held(body: &[u8], algorithm: crate::plugins::signer::BodyDigest) -> Self {
        use crate::plugins::signer::BodyDigest;
        let digest = match algorithm {
            BodyDigest::Sha256 => crate::trust::hash_bytes(body),
        };
        BodyFacts::Held {
            bytes: body.len() as u64,
            algorithm: algorithm.name(),
            digest,
        }
    }

    /// The facts for a body sbx does not hold. `why` is repeated to the plugin verbatim, so it says
    /// what about this request kept sbx from holding it.
    pub(crate) fn unheld(why: impl Into<String>) -> Self {
        BodyFacts::Unheld { why: why.into() }
    }

    fn value(&self) -> serde_json::Value {
        match self {
            // The algorithm names its own key, so a plugin reads the digest under the spelling its
            // manifest asked for rather than under a generic one it would have to interpret.
            BodyFacts::Held {
                bytes,
                algorithm,
                digest,
            } => {
                let mut map = serde_json::Map::new();
                map.insert("held".to_string(), serde_json::Value::from(true));
                map.insert("bytes".to_string(), serde_json::Value::from(*bytes));
                map.insert(
                    (*algorithm).to_string(),
                    serde_json::Value::from(digest.clone()),
                );
                serde_json::Value::Object(map)
            }
            BodyFacts::Unheld { why } => serde_json::json!({ "held": false, "why": why }),
        }
    }
}

impl SignRequest<'_> {
    /// The question line, newline included.
    fn line(&self, seq: u64) -> String {
        let headers: serde_json::Map<String, serde_json::Value> = self
            .headers
            .iter()
            .map(|(k, v)| (k.clone(), serde_json::Value::from(v.clone())))
            .collect();
        let mut v = serde_json::json!({
            "seq": seq,
            "method": self.method,
            "host": self.host,
            "port": self.port,
            "target": self.target,
            "headers": headers,
        });
        if let (Some(body), Some(map)) = (self.body, v.as_object_mut()) {
            map.insert("body".to_string(), body.value());
        }
        format!("{v}\n")
    }
}

/// What sbx tells a signer once, before the first request: what it is signing for, what it may set,
/// and the credential it is forming with.
///
/// The bounds are stated rather than left implicit. A plugin cannot read its own manifest (it is
/// outside its cage), and one that had to guess which headers it may set would discover the answer
/// by having a request refused.
struct Hello<'a> {
    signer: &'a str,
    host: &'a str,
    sets: &'a [String],
    sees: &'a [String],
    /// The credential: the plaintext where the manifest declared `reads_secret`, and otherwise a
    /// marker standing in for it, which sbx substitutes on the way out.
    credential: Credential,
}

/// What the plugin is handed to authenticate with. Held apart from the plaintext's own type so the
/// two spellings cannot be confused at the call site.
#[derive(Clone)]
pub(crate) enum Credential {
    /// The value itself, for a scheme whose credential is *computed* (an HMAC over the canonical
    /// request is a function of the key, so there is nothing to substitute).
    Plaintext(String),
    /// A marker standing in for it, for a scheme whose credential is *carried*: the plugin places
    /// the marker and never learns the value.
    Marker(String),
}

impl Credential {
    /// The token the plugin is given, and how it is labelled on the wire.
    fn parts(&self) -> (&'static str, &str) {
        match self {
            Credential::Plaintext(value) => ("plaintext", value.as_str()),
            Credential::Marker(token) => ("marker", token.as_str()),
        }
    }
}

// The credential is a secret in one arm and stands in for one in the other, so neither reaches a
// log or a panic message.
impl std::fmt::Debug for Credential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Credential::Plaintext(_) => write!(f, "Credential::Plaintext(<redacted>)"),
            Credential::Marker(_) => write!(f, "Credential::Marker(<redacted>)"),
        }
    }
}

impl Hello<'_> {
    fn line(&self) -> String {
        let (kind, value) = self.credential.parts();
        let v = serde_json::json!({
            "v": PROTOCOL_VERSION,
            "signer": self.signer,
            "host": self.host,
            "sets": self.sets.to_vec(),
            "sees": self.sees.to_vec(),
            "credential": { "kind": kind, "value": value },
        });
        format!("{v}\n")
    }
}

/// The plugin's answer to the handshake, before validation.
#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct RawHelloReply {
    ok: Option<bool>,
    error: Option<String>,
}

/// Read the plugin's answer to the handshake. Anything but an explicit acceptance means no signer.
///
/// The handshake exists so an unusable plugin says so at the one moment nothing is at stake yet: a
/// plugin that cannot speak [`PROTOCOL_VERSION`], or that will not sign for this host under these
/// bounds, is one whose first request must never be asked about.
fn parse_hello_reply(line: &str) -> Result<(), String> {
    let raw: RawHelloReply = serde_json::from_str(line.trim_end())
        .map_err(|e| format!("unreadable answer to the handshake: {e}"))?;
    match raw.ok {
        Some(true) => Ok(()),
        Some(false) => Err(match raw.error {
            Some(why) if !why.is_empty() => format!("the plugin declined to sign: {why}"),
            _ => "the plugin declined to sign".to_string(),
        }),
        None => Err("the answer to the handshake carries no `ok`".to_string()),
    }
}

/// The raw answer to one request, before validation. Unknown fields are refused, as everywhere a
/// machine reads a declaration here: a misspelled `headers` silently dropped would turn a signed
/// request into an unsigned one that still looked signed.
#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct RawAnswer {
    seq: Option<u64>,
    headers: Option<std::collections::BTreeMap<String, String>>,
    error: Option<String>,
    label: Option<String>,
}

/// What a plugin decided about one request: the headers to set, and what it says it did.
///
/// The `label` is the plugin's own account — the region and service a SigV4 signature was scoped to,
/// the identity it signed as — and it lands on the signer feed beside what sbx observed. It is
/// optional, and a plugin that sends none simply has sbx's account stand alone. It is third-party
/// text: [`super::signer_control::SignerRing::push`] writes it *after* sbx's own account, redacts it
/// against the launch's credential needles, and caps it. On a **refusal** the plugin's words travel
/// too — they are what the `403` names and what the feed's refusal line carries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Signature {
    /// The headers to put on the request, in the manifest's declared order rather than the
    /// plugin's: what a request carries is sbx's to order, and a stable order keeps two identical
    /// requests identical on the wire.
    pub(crate) headers: Vec<(String, String)>,
    /// The plugin's own account of what it formed, for the feed. Never consulted for anything the
    /// request carries: nothing a plugin says about its answer can change the answer.
    pub(crate) label: Option<String>,
}

/// Why a signer's answer was refused, and whether the two sides have lost each other.
///
/// Both forms refuse the request; what they differ on is what becomes of the *plugin*. A malformed
/// answer is about this exchange, and the next one starts clean. An answer carrying another
/// request's `seq` is not: it says the plugin is reading one question behind, and the channel is a
/// sequence of question-and-answer lines, so it stays behind for every request after this one. That
/// is the same condition [`SignerProcess::sign`] already buries a plugin for when the channel itself
/// fails, arrived at by a different route, and a plugin that has lost its place should say so once
/// rather than refuse every request under a sentence about this one.
pub(crate) struct AnswerRefused {
    /// What to tell the caller.
    pub(crate) why: String,
    /// Whether the answer proves the two sides disagree about which request is being signed.
    pub(crate) desynced: bool,
}

impl From<String> for AnswerRefused {
    fn from(why: String) -> Self {
        AnswerRefused {
            why,
            desynced: false,
        }
    }
}

impl From<&str> for AnswerRefused {
    fn from(why: &str) -> Self {
        AnswerRefused::from(why.to_string())
    }
}

/// Parse and **bound** one answer against the manifest that declared what this plugin may set.
///
/// Every refusal here is a refusal of the request: there is no partial answer, because a request
/// carrying some of a signature is not a less-signed request, it is a malformed one.
pub(crate) fn parse_signature(
    line: &str,
    expect_seq: u64,
    sets: &[String],
) -> Result<Signature, AnswerRefused> {
    let raw: RawAnswer = serde_json::from_str(line.trim_end())
        .map_err(|e| AnswerRefused::from(format!("unreadable answer: {e}")))?;
    match raw.seq {
        Some(seq) if seq == expect_seq => {}
        Some(seq) => {
            return Err(AnswerRefused {
                why: format!("the plugin answered request {seq} while {expect_seq} was asked"),
                desynced: true,
            });
        }
        None => return Err("the answer carries no `seq`".into()),
    }
    // A plugin that cannot sign says so, and that is a refusal like any other: the request does not
    // go out unsigned.
    if let Some(why) = raw.error.filter(|w| !w.is_empty()) {
        return Err(format!("the plugin refused to sign: {why}").into());
    }
    let headers = raw.headers.ok_or(AnswerRefused::from(
        "the answer carries neither `headers` nor `error`",
    ))?;
    if headers.is_empty() {
        return Err("the answer sets no header, so nothing would authenticate it".into());
    }

    let mut out = Vec::with_capacity(headers.len());
    // Walked in the manifest's order, not the answer's: this is also what refuses a header the
    // manifest never declared, since anything left over at the end was not in that list. Which of
    // the answer's own keys the walk took is recorded, because "left over" has two causes and they
    // do not read alike.
    let mut claimed: Vec<&String> = Vec::with_capacity(sets.len());
    for declared in sets {
        let Some((name, value)) = headers
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case(declared))
        else {
            continue;
        };
        claimed.push(name);
        check_value(name, value).map_err(AnswerRefused::from)?;
        // The manifest's spelling wins: it is the one that was reviewed, and it keeps two runs of
        // one plugin from differing by case alone.
        out.push((declared.clone(), value.clone()));
    }
    if claimed.len() != headers.len() {
        // The two causes, separated rather than inferred from the count. A key the manifest never
        // declared is the ordinary overstep. A key it *did* declare, which the walk did not take, is
        // the answer spelling one header two ways — `Authorization` and `authorization` are two JSON
        // keys and one header, and the walk takes the first. Read as the first cause, which is what
        // this did, that answer was refused by a sentence whose list of undeclared headers was
        // empty: a refusal naming no header at all.
        let (duplicated, extra): (Vec<String>, Vec<String>) = headers
            .keys()
            .filter(|name| !claimed.iter().any(|taken| taken == name))
            .cloned()
            .partition(|name| sets.iter().any(|d| d.eq_ignore_ascii_case(name)));
        if !duplicated.is_empty() {
            return Err(format!(
                "the answer sets {} under a second spelling of a header it already sets, so which \
                 value would sign the request is undecided",
                crate::plugins::quoted_list(&duplicated)
            )
            .into());
        }
        return Err(format!(
            "the answer sets {}, which the plugin's manifest does not declare in `sets_headers`",
            crate::plugins::quoted_list(&extra)
        )
        .into());
    }
    Ok(Signature {
        headers: out,
        // Taken as written and bounded where it is recorded, not here: what makes it safe is a
        // property of the sink (one wire line, redacted, capped), and duplicating that check here
        // would leave two spellings of it to drift apart.
        label: raw.label.filter(|l| !l.is_empty()),
    })
}

/// Whether one value may be put on a request head.
///
/// The same refusal a statically resolved credential meets, for the same reason and with more at
/// stake: a CR or LF ends the header and starts whatever follows it, so a plugin that could write
/// one would be writing the rest of the request rather than authenticating it.
fn check_value(name: &str, value: &str) -> Result<(), String> {
    if value.is_empty() {
        return Err(format!("the value for `{name}` is empty"));
    }
    if value.len() > MAX_VALUE_BYTES {
        return Err(format!(
            "the value for `{name}` is {} bytes, above the {MAX_VALUE_BYTES}-byte ceiling for one \
             header",
            value.len()
        ));
    }
    if value.bytes().any(|b| b == b'\r' || b == b'\n' || b == 0) {
        return Err(format!(
            "the value for `{name}` contains a newline or NUL (it cannot be an HTTP header value)"
        ));
    }
    Ok(())
}

/// What a caller needs of a signer, so the callers are testable without a sandbox and a real
/// plugin. [`SignerProcess`] is the one implementation that runs code.
pub(crate) trait Signing: Send {
    /// Sign one request, or say why it cannot be. An `Err` refuses the request.
    fn sign(&mut self, req: &SignRequest<'_>) -> Result<Signature, String>;
}

/// A signer plugin running in its own host-side cage, spoken to over a socket pair.
///
/// A socket rather than a pipe for the reason a broker's is: a socket takes a read deadline and a
/// pipe does not, and that deadline is the only thing between a wedged plugin and a wedged request.
pub(crate) struct SignerProcess {
    child: std::process::Child,
    reader: io::BufReader<std::os::unix::net::UnixStream>,
    writer: std::os::unix::net::UnixStream,
    /// The headers this plugin's manifest declared, kept here so every answer is bounded by the
    /// manifest rather than by what the caller happens to pass.
    sets: Vec<String>,
    /// The next request's sequence number. It exists so an answer can be matched to its question:
    /// a plugin one answer behind would otherwise sign every request with the previous one's
    /// signature.
    seq: u64,
    /// Once a plugin has failed, it stays failed. A broken signer refusing one request per request
    /// is a bounded cost; one restarted per request is a sandbox spawn per request, and one whose
    /// stream desynchronized would answer the wrong question.
    dead: Option<String>,
    /// The descriptor the cage's environment was read from, held open for the child's whole life:
    /// bwrap reads it at startup, and dropping it earlier would race that read.
    _env: Vec<std::fs::File>,
}

impl SignerProcess {
    /// Start `plugin` under `bwrap`, tell it what it is signing for, and require an acceptance.
    ///
    /// An error here means no signer, which the caller turns into a launch that fails rather than
    /// one whose requests silently go out unsigned.
    pub(crate) fn start(
        bwrap: &std::path::Path,
        plugin: &SignerPlugin,
        host: &str,
        credential: Credential,
    ) -> io::Result<Self> {
        let plan = super::resolver::CagePlan {
            kind: crate::plugins::PluginKind::Signer,
            dir: &plugin.dir,
            exec: &plugin.exec,
            grant: &plugin.sandbox,
            host: &plugin.host,
            called: &plugin.name,
            configured_as: &plugin.name,
            // No arguments: everything this plugin is told arrives on the wire, where it can be
            // bounded and where a credential would not be world-readable in `/proc`.
            args: Vec::new(),
            // None, and a signer manifest may not ask for any: it reaches no host resource.
            brokers: &[],
        };
        // Shared with the broker (`spawn_caged_plugin`): the pair, the deadlines, the
        // clone-before-spawn ordering and the stdio handover were written out here as well.
        let super::resolver::CagedPlugin {
            child,
            writer,
            reader_side,
            env,
        } = super::resolver::spawn_caged_plugin(bwrap, &plan, SIGN_DEADLINE)?;

        let mut me = Self {
            child,
            reader: io::BufReader::new(reader_side),
            writer,
            sets: plugin.signer.sets_headers.clone(),
            seq: 0,
            dead: None,
            _env: env,
        };
        me.handshake(plugin, host, credential)?;
        Ok(me)
    }

    fn handshake(
        &mut self,
        plugin: &SignerPlugin,
        host: &str,
        credential: Credential,
    ) -> io::Result<()> {
        let hello = Hello {
            signer: &plugin.name,
            host,
            sets: &plugin.signer.sets_headers,
            sees: &plugin.signer.sees_headers,
            credential,
        };
        self.writer.write_all(hello.line().as_bytes())?;
        self.writer.flush()?;
        let line = self.read_line()?;
        parse_hello_reply(&line).map_err(|why| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("the `{}` signer plugin cannot sign: {why}", plugin.name),
            )
        })
    }

    /// One line from the plugin, or an error when it says nothing in time, closes, or says more than
    /// an answer can be.
    fn read_line(&mut self) -> io::Result<String> {
        super::broker::read_bounded_line(&mut self.reader, MAX_LINE_BYTES)
    }
}

impl Signing for SignerProcess {
    fn sign(&mut self, req: &SignRequest<'_>) -> Result<Signature, String> {
        if let Some(why) = &self.dead {
            return Err(why.clone());
        }
        // Any failure of the channel itself buries the plugin: the stream is a sequence of
        // question-and-answer lines, so a half-written question or an unread answer leaves the two
        // sides disagreeing about which request is being signed.
        let bury = |me: &mut Self, why: String| {
            me.dead = Some(why.clone());
            why
        };
        let seq = self.seq;
        self.seq += 1;
        if let Err(e) = self
            .writer
            .write_all(req.line(seq).as_bytes())
            .and_then(|()| self.writer.flush())
        {
            return Err(bury(self, format!("cannot reach the plugin: {e}")));
        }
        let line = match self.read_line() {
            Ok(line) => line,
            Err(e) => return Err(bury(self, format!("no signature from the plugin: {e}"))),
        };
        // A malformed or out-of-bounds answer refuses this request without burying the plugin: it
        // answered the question asked, and the next request is a fresh one. An answer carrying
        // another request's number is the exception, and belongs with the channel failures above:
        // the two sides have lost each other, and nothing in a sequence of question-and-answer
        // lines brings them back.
        parse_signature(&line, seq, &self.sets).map_err(|refused| {
            if refused.desynced {
                bury(self, refused.why)
            } else {
                refused.why
            }
        })
    }
}

impl Drop for SignerProcess {
    fn drop(&mut self) {
        // The child dies with sbx by construction, but a signer belongs to a launch: it is killed
        // here rather than left holding a slot, and reaped in the same breath so a long session
        // does not accumulate zombies.
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sets() -> Vec<String> {
        vec!["Authorization".to_string(), "X-Amz-Date".to_string()]
    }

    fn answer(json: serde_json::Value) -> Result<Signature, String> {
        parse_signature(&format!("{json}\n"), 7, &sets()).map_err(|refused| refused.why)
    }

    /// An answer carrying another request's number says the plugin has lost its place, and nothing
    /// in a stream of question-and-answer lines gives it back: it is buried, like the channel
    /// failures it belongs with. A malformed answer is not that, and the next request starts clean.
    ///
    /// Teeth: refusing both the same way leaves a desynced plugin answering one question behind
    /// forever, refusing every later request under a sentence about that request rather than about
    /// the plugin, and writing a question down the channel each time to do it.
    #[test]
    fn an_answer_to_another_question_buries_the_plugin_where_a_malformed_one_does_not() {
        let desynced = parse_signature(
            &format!(
                "{}\n",
                serde_json::json!({"seq": 6, "headers": {"Authorization": "x"}})
            ),
            7,
            &sets(),
        )
        .expect_err("another request's number is refused");
        assert!(desynced.desynced, "{}", desynced.why);
        assert!(
            desynced
                .why
                .contains("answered request 6 while 7 was asked"),
            "the refusal names both numbers: {}",
            desynced.why
        );

        for (line, what) in [
            ("not json at all", "an unreadable answer"),
            (
                r#"{"seq": 7, "headers": {"X-Nope": "v"}}"#,
                "a header the manifest does not declare",
            ),
            (
                r#"{"seq": 7, "headers": {}}"#,
                "an answer that sets nothing",
            ),
            (r#"{"headers": {"Authorization": "x"}}"#, "no seq at all"),
        ] {
            let refused =
                parse_signature(&format!("{line}\n"), 7, &sets()).expect_err("still refused");
            assert!(
                !refused.desynced,
                "{what} is about this exchange, not about the plugin's place: {}",
                refused.why
            );
        }
    }

    #[test]
    fn a_well_formed_answer_yields_the_headers_in_the_manifests_order() {
        let sig = answer(serde_json::json!({
            "seq": 7,
            "headers": { "x-amz-date": "20260813T000000Z", "Authorization": "AWS4-HMAC..." }
        }))
        .expect("valid");
        assert_eq!(
            sig.headers,
            vec![
                ("Authorization".to_string(), "AWS4-HMAC...".to_string()),
                ("X-Amz-Date".to_string(), "20260813T000000Z".to_string()),
            ],
            "the manifest's order and spelling win over the answer's"
        );
    }

    /// The bound that makes the manifest a bound. A plugin that could set a header it never
    /// declared would be writing a request rather than authenticating one, and the manifest would
    /// be a description instead of a limit.
    #[test]
    fn a_header_the_manifest_never_declared_refuses_the_whole_answer() {
        let err = answer(serde_json::json!({
            "seq": 7,
            "headers": { "Authorization": "ok", "X-Sneaky": "v" }
        }))
        .expect_err("an undeclared header is refused");
        assert!(
            err.contains("X-Sneaky") && err.contains("sets_headers"),
            "{err}"
        );
    }

    /// One header spelt two ways is refused, and the refusal says which header. The count that
    /// separates "declared" from "left over" cannot tell the two causes apart on its own: the case
    /// duplicate is left over *because* the walk already took its twin, so reading it as an
    /// undeclared header produced a sentence with an empty list — a refusal naming nothing.
    #[test]
    fn one_header_set_under_two_spellings_is_refused_by_name() {
        let err = answer(serde_json::json!({
            "seq": 7,
            "headers": { "Authorization": "one", "authorization": "two" }
        }))
        .expect_err("two spellings of one header are refused");
        assert!(
            err.contains("authorization"),
            "the refusal has to name the header it is about: {err}"
        );
        assert!(
            !err.contains("does not declare in `sets_headers`"),
            "and not blame a manifest that declares this header: {err}"
        );

        // Not satisfiable by refusing every answer: one spelling of each declared header still signs.
        let sig = answer(serde_json::json!({
            "seq": 7,
            "headers": { "authorization": "one", "X-Amz-Date": "20260813T000000Z" }
        }))
        .expect("a single spelling of each declared header is a valid answer");
        assert_eq!(
            sig.headers,
            vec![
                ("Authorization".to_string(), "one".to_string()),
                ("X-Amz-Date".to_string(), "20260813T000000Z".to_string()),
            ]
        );
    }

    /// A value that ends the header ends sbx's framing of the request head: everything after the
    /// CRLF would be headers of the plugin's choosing.
    #[test]
    fn a_value_that_would_split_the_head_is_refused() {
        for bad in ["a\r\nX-Evil: 1", "a\nb", "a\0b"] {
            let err = answer(serde_json::json!({ "seq": 7, "headers": { "Authorization": bad } }))
                .expect_err("a splitting byte is refused");
            assert!(err.contains("newline or NUL"), "{err}");
        }
    }

    #[test]
    fn an_empty_or_oversized_value_is_refused() {
        let err = answer(serde_json::json!({ "seq": 7, "headers": { "Authorization": "" } }))
            .expect_err("empty");
        assert!(err.contains("empty"), "{err}");

        let long = "x".repeat(MAX_VALUE_BYTES + 1);
        let err = answer(serde_json::json!({ "seq": 7, "headers": { "Authorization": long } }))
            .expect_err("oversized");
        assert!(err.contains("ceiling"), "{err}");
    }

    /// A plugin one answer behind would sign every request with the previous one's signature, which
    /// is both wrong and undetectable downstream.
    #[test]
    fn an_answer_to_another_request_is_refused() {
        let err = answer(serde_json::json!({ "seq": 6, "headers": { "Authorization": "v" } }))
            .expect_err("a mismatched seq is refused");
        assert!(err.contains("answered request 6"), "{err}");
    }

    #[test]
    fn a_plugin_that_says_it_cannot_sign_refuses_the_request() {
        let err =
            answer(serde_json::json!({ "seq": 7, "error": "no credentials for that region" }))
                .expect_err("an explicit refusal is a refusal");
        assert!(err.contains("no credentials for that region"), "{err}");
    }

    /// An answer that sets nothing is not a signed request: it would go out anonymous while the
    /// record said a signer had answered.
    #[test]
    fn an_answer_that_sets_no_header_is_refused() {
        let err = answer(serde_json::json!({ "seq": 7, "headers": {} })).expect_err("empty set");
        assert!(err.contains("sets no header"), "{err}");
        let err = answer(serde_json::json!({ "seq": 7 })).expect_err("nothing at all");
        assert!(err.contains("neither `headers` nor `error`"), "{err}");
    }

    /// The plugin's own account of what it formed, which the feed prints after sbx's. Optional: an
    /// answer without one is a complete answer.
    #[test]
    fn an_answer_may_carry_the_plugins_account_of_what_it_formed() {
        let sig = answer(serde_json::json!({
            "seq": 7,
            "headers": { "Authorization": "AWS4-HMAC..." },
            "label": "us-east-1 s3"
        }))
        .expect("valid");
        assert_eq!(sig.label.as_deref(), Some("us-east-1 s3"));

        let bare = answer(serde_json::json!({ "seq": 7, "headers": { "Authorization": "v" } }))
            .expect("valid");
        assert_eq!(bare.label, None);

        // An empty label is no label: it would otherwise render as a trailing separator with
        // nothing after it on the feed.
        let empty = answer(
            serde_json::json!({ "seq": 7, "headers": { "Authorization": "v" }, "label": "" }),
        )
        .expect("valid");
        assert_eq!(empty.label, None);
    }

    /// A line sbx must buffer before it can bound what is inside it. Without a ceiling, a plugin
    /// that never writes a newline takes host memory for as long as the session lives. The reader
    /// is shared with the broker; what this pins is that the *signer* passes its own ceiling to it.
    #[test]
    fn a_line_that_never_ends_is_refused_rather_than_buffered() {
        use super::super::broker::read_bounded_line;
        let flood = vec![b'x'; (MAX_LINE_BYTES + 1) as usize];
        let err = read_bounded_line(&mut io::BufReader::new(flood.as_slice()), MAX_LINE_BYTES)
            .expect_err("an unterminated flood is refused");
        assert_eq!(err.kind(), io::ErrorKind::InvalidData, "{err}");

        // The bound is per line, not per session: an ordinary answer after a long one still reads.
        let mut reader = io::BufReader::new(b"first\nsecond\n".as_slice());
        assert_eq!(
            read_bounded_line(&mut reader, MAX_LINE_BYTES).expect("first"),
            "first\n"
        );
        assert_eq!(
            read_bounded_line(&mut reader, MAX_LINE_BYTES).expect("second"),
            "second\n"
        );
    }

    /// A key nothing reads would leave a plugin author believing they had answered something.
    #[test]
    fn an_unknown_field_in_the_answer_is_refused() {
        let err = answer(serde_json::json!({ "seq": 7, "header": { "Authorization": "v" } }))
            .expect_err("a misspelled field is not a silent no-op");
        assert!(err.contains("unreadable answer"), "{err}");
    }

    #[test]
    fn the_handshake_needs_an_explicit_acceptance() {
        parse_hello_reply("{\"ok\":true}").expect("accepted");
        let err = parse_hello_reply("{\"ok\":false,\"error\":\"unsupported version\"}")
            .expect_err("declined");
        assert!(err.contains("unsupported version"), "{err}");
        let err = parse_hello_reply("{}").expect_err("silence is not acceptance");
        assert!(err.contains("no `ok`"), "{err}");
    }

    /// What the plugin is shown, spelled once: the request facts, and only the headers the caller
    /// selected. A signature over a request it cannot see is not a signature.
    #[test]
    fn the_question_carries_the_request_and_only_the_selected_headers() {
        let req = SignRequest {
            method: "PUT",
            host: "s3.example.com",
            port: 443,
            target: "/bucket/key?x=1",
            headers: vec![("Content-Type".to_string(), "text/plain".to_string())],
            body: None,
        };
        let line = req.line(3);
        let v: serde_json::Value = serde_json::from_str(line.trim_end()).expect("json");
        assert_eq!(v["seq"], 3);
        assert_eq!(v["method"], "PUT");
        assert_eq!(v["host"], "s3.example.com");
        assert_eq!(v["port"], 443);
        assert_eq!(v["target"], "/bucket/key?x=1");
        assert_eq!(v["headers"]["Content-Type"], "text/plain");
        assert_eq!(
            v["headers"].as_object().map(serde_json::Map::len),
            Some(1),
            "nothing the caller did not select"
        );
        assert!(
            v.get("body").is_none(),
            "a plugin that asked for no digest is shown the question it was always shown: {line}"
        );
    }

    /// The digest is stated under the name of the algorithm that produced it, so a plugin reads it
    /// under the spelling its own manifest asked for.
    #[test]
    fn a_held_body_is_stated_by_length_and_digest() {
        let facts = BodyFacts::held(b"hello", crate::plugins::signer::BodyDigest::Sha256);
        let req = SignRequest {
            method: "POST",
            host: "dynamodb.example.com",
            port: 443,
            target: "/",
            headers: Vec::new(),
            body: Some(&facts),
        };
        let v: serde_json::Value = serde_json::from_str(req.line(1).trim_end()).expect("json");
        assert_eq!(v["body"]["held"], true);
        assert_eq!(v["body"]["bytes"], 5);
        assert_eq!(
            v["body"]["sha256"], "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824",
            "the SHA-256 of `hello`, as a literal rather than a second computation of the same thing"
        );
    }

    /// The absence is stated rather than implied by a missing field: a scheme whose signature must
    /// cover the payload has to be able to tell "no body" from "a body sbx does not hold".
    #[test]
    fn a_body_sbx_does_not_hold_says_so_and_says_why() {
        let facts = BodyFacts::unheld("it streams");
        let req = SignRequest {
            method: "POST",
            host: "dynamodb.example.com",
            port: 443,
            target: "/",
            headers: Vec::new(),
            body: Some(&facts),
        };
        let v: serde_json::Value = serde_json::from_str(req.line(1).trim_end()).expect("json");
        assert_eq!(v["body"]["held"], false);
        assert_eq!(v["body"]["why"], "it streams");
        assert!(
            v["body"].get("sha256").is_none(),
            "an unheld body carries no digest to mistake for one"
        );
    }

    /// The credential is stated with which kind it is, so a plugin cannot mistake a marker for a
    /// key and sign with the placeholder.
    #[test]
    fn the_handshake_says_which_kind_of_credential_it_hands_over() {
        let sets = sets();
        let hello = Hello {
            signer: "demo",
            host: "s3.example.com",
            sets: &sets,
            sees: &[],
            credential: Credential::Marker("sbx-marker-1".to_string()),
        };
        let v: serde_json::Value = serde_json::from_str(hello.line().trim_end()).expect("json");
        assert_eq!(v["credential"]["kind"], "marker");
        assert_eq!(v["credential"]["value"], "sbx-marker-1");
        assert_eq!(v["v"], PROTOCOL_VERSION);
        assert_eq!(v["sets"][0], "Authorization");
    }

    /// Neither spelling of the credential may reach a log or a panic message.
    #[test]
    fn a_credential_never_renders_itself() {
        let shown = format!(
            "{:?} {:?}",
            Credential::Plaintext("AKIA-secret".to_string()),
            Credential::Marker("marker".to_string())
        );
        assert!(
            !shown.contains("AKIA-secret") && !shown.contains("marker"),
            "{shown}"
        );
    }
}
