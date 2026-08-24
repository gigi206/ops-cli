//! The wire between sbx and a broker plugin: what sbx asks, what a plugin may answer.
//!
//! [`crate::plugins::broker`] declares what a broker *is*; this is the conversation it holds. The
//! division of labour is the whole security argument, so it is worth restating where the code
//! implementing it begins: **sbx owns the cage-facing socket, the connection to the host resource,
//! the framing and the record; the plugin owns nothing and answers verdicts.**
//!
//! One line of JSON per message, in both directions, because a line is the framing every other
//! control plane here already uses and a plugin can be written in any language without a library.
//! Bytes travel as **hex**, not base64: one canonical spelling, no padding or alphabet variant to
//! disagree about, and a decoder short enough to be read and tested. A protocol frame is opaque to
//! sbx, so it must survive the trip byte for byte.
//!
//! The exchange, per cage connection:
//!
//! 1. sbx writes the [`Hello`]: the protocol version, the broker's name, and the `allow` list the
//!    config declared. sbx does not interpret `allow` — the plugin knows what its own protocol
//!    makes of it.
//! 2. For each frame, sbx writes an [`Ask`] and reads exactly one [`Verdict`], carrying the same
//!    `seq`. A verdict for another `seq` is a plugin that has lost the thread, and is refused. The
//!    `seq` identifies **one frame's exchange**, not one message: a query's reply and a host
//!    reply put back to the plugin carry the `seq` of the frame they belong to, which is what lets
//!    a plugin tie them together. It advances per frame read from the cage, never per line.
//! 3. [`Verdict::Query`] is the one answer that does not end the exchange: sbx sends those bytes to
//!    the host resource and hands the reply back as another [`Ask`], so the plugin can decide on
//!    what the host says. It exists because the first-party ssh-agent broker cannot be expressed
//!    without it: its admission is re-derived from the host agent *inside* each decision, never
//!    cached, so a key removed from the agent stops working at once.
//!
//! `Query` grants the plugin no reach it did not already have: a rewritten [`Verdict::Forward`]
//! could already put arbitrary bytes in front of the host resource. What it adds is *seeing the
//! answer before deciding*, and sbx still holds the connection throughout.
//!
//! Every parse here is fail-closed and every bound is enforced on sbx's side. A plugin that
//! answers nonsense, answers late, or asks to query forever is refused, and the caller turns that
//! refusal into the protocol's own (a declared `deny_frame`, or a closed connection).

use std::io::{self, Read, Write};

use serde::Deserialize;

use crate::plugins::broker::{BrokerSpec, Framing, MAX_FRAME_CEILING};
use crate::plugins::catalogue::to_hex;

/// The protocol version sbx speaks. A plugin that cannot handle it should fail its handshake
/// rather than guess: this number changes only when the meaning of a message changes.
pub(crate) const PROTOCOL_VERSION: u32 = 1;

/// How many [`Verdict::Query`] answers sbx will serve before refusing the frame outright.
///
/// A query is a round trip to the host resource that the *plugin* asked for, so an unbounded chain
/// is a plugin holding the host resource open on the cage's behalf. Deliberately small: the case
/// this exists for (re-deriving admission before deciding) takes one, and a second is slack for a
/// protocol that must ask twice. Reaching the ceiling is a refusal, never a truncation.
pub(crate) const MAX_QUERIES_PER_FRAME: u32 = 4;

/// How many frames one exchange may take from the host resource before sbx gives up on it.
///
/// A protocol like Assuan answers one command with a run of messages ending in a terminator, and
/// the plugin is what says where that run ends. This is the backstop for a host that never says
/// so: without it, a chatty or wedged resource holds the cage's connection while sbx reads on. Set
/// well above any real answer, because reaching it is a refusal and not a truncation.
pub(crate) const MAX_REPLY_FRAMES: u32 = 1024;

/// Which side of the channel a frame came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Direction {
    /// From the cage, on its way to the host resource.
    Up,
    /// From the host resource, on its way back to the cage. Only ever sent to a plugin whose
    /// manifest declares `inspect_replies`.
    Down,
    /// The host's answer to a [`Verdict::Query`] the plugin asked for. Distinct from `Down`
    /// because it is not on its way anywhere: it is owed to the plugin, which asked for it, and a
    /// plugin that does not inspect replies still gets these.
    QueryReply,
}

impl Direction {
    fn token(self) -> &'static str {
        match self {
            Direction::Up => "up",
            Direction::Down => "down",
            Direction::QueryReply => "query-reply",
        }
    }
}

/// What stands in for a secret in the frames a plugin builds.
///
/// The plugin never receives the credential. It receives this marker, places it where the protocol
/// wants the value, and sbx substitutes the real bytes on their way to the host resource — the
/// same shape the egress proxy already uses for HTTP, where an application carries a placeholder
/// and the proxy puts the value on the wire.
///
/// **Random, and drawn per connection.** A fixed marker would be guessable by the cage, which
/// could then place it in a command whose service echoes it back and read the secret in the
/// answer. This one the cage never sees — and sbx refuses to write it toward the cage, which is
/// what keeps that true.
pub(crate) struct SecretMarker {
    /// The bytes a plugin writes to mean "the secret goes here".
    marker: Vec<u8>,
    /// The value they are replaced with, host-side, on the way to the host resource only.
    secret: Vec<u8>,
    /// Whether the way back is watched for this value. Off for a secret shorter than the
    /// `[redact] min_len` floor, where a byte-substring scan would refuse innocent traffic more
    /// often than it would catch a leak — the same trade the egress proxy makes, and the caller
    /// says so out loud when it applies.
    watch: bool,
}

impl SecretMarker {
    /// Draw a marker for one connection. The randomness comes from the same source the rest of
    /// sbx's per-session identifiers do.
    pub(crate) fn new(secret: &str, min_len: usize) -> io::Result<Self> {
        let mut raw = [0u8; 16];
        std::fs::File::open("/dev/urandom")?.read_exact(&mut raw)?;
        Ok(Self {
            marker: format!("SBX-SECRET-{}", to_hex(&raw)).into_bytes(),
            secret: secret.as_bytes().to_vec(),
            watch: secret.len() >= min_len,
        })
    }

    /// What the plugin is told to place.
    pub(crate) fn token(&self) -> String {
        String::from_utf8_lossy(&self.marker).into_owned()
    }

    /// Whether these bytes carry the marker.
    fn present_in(&self, frame: &[u8]) -> bool {
        contains(frame, &self.marker)
    }

    /// Replace every occurrence with the secret. Applied only to bytes on their way to the host
    /// resource, and only to bytes the plugin itself produced.
    fn substitute(&self, frame: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(frame.len());
        let mut at = 0;
        while at < frame.len() {
            if frame[at..].starts_with(&self.marker) {
                out.extend_from_slice(&self.secret);
                at += self.marker.len();
            } else {
                out.push(frame[at]);
                at += 1;
            }
        }
        out
    }

    /// The same substitution on text, for a channel whose messages are strings rather than frames:
    /// a signer answers with header values, not with a byte stream.
    ///
    /// Both sides are valid UTF-8 by construction (the marker is ASCII, and the secret came from a
    /// `String`), so nothing is lost in the round trip.
    pub(crate) fn substitute_str(&self, text: &str) -> String {
        String::from_utf8_lossy(&self.substitute(text.as_bytes())).into_owned()
    }

    /// Whether these bytes carry the secret itself — the tripwire for the way back.
    fn leaks_in(&self, frame: &[u8]) -> bool {
        self.watch && contains(frame, &self.secret)
    }
}

/// Whether `haystack` contains `needle`. The same byte-substring search the egress proxy's
/// outbound scan uses, kept simple on purpose: it runs on frames, not on streams.
fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty()
        && haystack.len() >= needle.len()
        && haystack
            .windows(needle.len())
            .any(|window| window == needle)
}

/// The opening message: what the plugin is being asked to broker, and under which policy.
pub(crate) struct Hello<'a> {
    pub(crate) broker: &'a str,
    pub(crate) allow: &'a [String],
    /// The marker standing in for the secret, when this broker was given one.
    pub(crate) secret_marker: Option<String>,
    /// Whether this plugin will be shown host replies, so it need not infer it from the manifest
    /// it cannot read.
    pub(crate) inspect_replies: bool,
}

impl Hello<'_> {
    /// The handshake line, newline included.
    pub(crate) fn line(&self) -> String {
        let allow = serde_json::Value::from(self.allow.to_vec());
        let mut v = serde_json::json!({
            "v": PROTOCOL_VERSION,
            "broker": self.broker,
            "allow": allow,
            "inspect_replies": self.inspect_replies,
        });
        if let Some(marker) = &self.secret_marker {
            v["secret_marker"] = serde_json::Value::from(marker.clone());
        }
        format!("{v}\n")
    }
}

/// The plugin's answer to the handshake, before validation.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawHelloReply {
    ok: Option<bool>,
    error: Option<String>,
}

/// Read the plugin's answer to [`Hello`]. Anything but an explicit acceptance refuses the
/// connection **before** the host resource is contacted.
///
/// The handshake exists to make an unusable plugin say so at the one moment nothing is at stake
/// yet: a plugin that cannot speak [`PROTOCOL_VERSION`], that will not broker under the `allow` it
/// was given, or that failed to start, is a plugin whose first frame must never be asked about. It
/// also gives the plugin the one place it can explain itself, which a dead pipe cannot.
pub(crate) fn parse_hello_reply(line: &str) -> Result<(), String> {
    let raw: RawHelloReply = serde_json::from_str(line.trim_end())
        .map_err(|e| format!("unreadable answer to the handshake: {e}"))?;
    match raw.ok {
        Some(true) => Ok(()),
        // A refusal carries its reason when the plugin gave one: this is third-party text, so the
        // caller bounds it before it reaches a terminal.
        Some(false) => Err(match raw.error {
            Some(why) if !why.is_empty() => format!("the plugin declined to broker: {why}"),
            _ => "the plugin declined to broker".to_string(),
        }),
        None => Err("the answer to the handshake carries no `ok`".to_string()),
    }
}

/// One frame put to the plugin for a verdict.
pub(crate) struct Ask<'a> {
    pub(crate) seq: u64,
    pub(crate) dir: Direction,
    pub(crate) data: &'a [u8],
}

impl Ask<'_> {
    /// The request line, newline included.
    pub(crate) fn line(&self) -> String {
        let v = serde_json::json!({
            "seq": self.seq,
            "dir": self.dir.token(),
            "data": to_hex(self.data),
        });
        format!("{v}\n")
    }
}

/// What a plugin decided about one frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Verdict {
    /// Send it to the host resource: the frame as it stands, or the rewritten bytes carried here.
    /// Rewriting is how a broker *narrows* a request rather than refusing it whole.
    Forward(Option<Vec<u8>>),
    /// Answer the cage with these bytes and never contact the host resource. What lets a reply be
    /// rebuilt rather than filtered in place, so nothing withheld is ever spelled toward the cage.
    Reply(Vec<u8>),
    /// Refuse. The bytes are the protocol's refusal when the plugin knows one; without them the
    /// caller falls back to the manifest's `deny_frame`, and failing that, closes the connection.
    Deny(Option<Vec<u8>>),
    /// Put these bytes to the host resource and hand the answer back, then ask again.
    Query(Vec<u8>),
}

/// A plugin's answer to one [`Ask`]: its verdict, plus the label the decision record will carry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Answer {
    pub(crate) verdict: Verdict,
    /// On a forwarded frame: whether the host resource will answer at all.
    ///
    /// Most messages get a reply, so this defaults to **true**. Some protocols have messages that
    /// get none — PostgreSQL's `Terminate`, and the close of many others — and waiting for one
    /// would end the connection on a read that can only fail. Worse, it would be *recorded* as a
    /// refusal, which is a record saying something that did not happen.
    pub(crate) expect_reply: bool,
    /// On a reply frame: whether the exchange continues, so sbx should take another frame from the
    /// host and show it too.
    ///
    /// Defaults to **false**, which ends the exchange. A protocol that answers one message with a
    /// run of them needs the plugin to say `more` until it recognises the terminator; a plugin
    /// that says nothing gets the single-message reading, which is the safe one — sbx stops
    /// reading rather than waiting on a resource that may have finished speaking.
    pub(crate) more: bool,
    /// The plugin's own account of what it decided, for the session's record. Free text from
    /// third-party code: bounded and stripped of control characters by the record, never trusted
    /// to be true. sbx logs what it *observed* beside it.
    pub(crate) label: Option<String>,
}

/// The raw answer line, before validation. Every field optional so a missing one yields a precise
/// message; unknown fields are refused, as everywhere a machine reads a declaration here: a
/// misspelled `data` that was silently dropped would turn a refusal into a forward.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawAnswer {
    seq: Option<u64>,
    verdict: Option<String>,
    data: Option<String>,
    label: Option<String>,
    #[serde(default)]
    more: bool,
    #[serde(default = "yes")]
    expect_reply: bool,
}

/// `expect_reply` defaults to true: a message with no answer is the exception, and a plugin that
/// says nothing should get the common case.
fn yes() -> bool {
    true
}

/// Parse one answer line against the frame it should be answering.
///
/// `max_frame` bounds the bytes a plugin may hand back, for the reason it bounds what sbx reads
/// off the socket: the value ends up on a wire the plugin does not own.
pub(crate) fn parse_answer(
    line: &str,
    expect_seq: u64,
    max_frame: usize,
) -> Result<Answer, String> {
    let raw: RawAnswer =
        serde_json::from_str(line.trim_end()).map_err(|e| format!("unreadable answer: {e}"))?;

    match raw.seq {
        Some(seq) if seq == expect_seq => {}
        // A plugin answering another frame has lost track of the conversation. There is no safe
        // way to guess which frame it meant, so the exchange ends.
        Some(seq) => return Err(format!("answer carries seq {seq}, expected {expect_seq}")),
        None => return Err("answer carries no `seq`".to_string()),
    }

    let verdict = raw
        .verdict
        .as_deref()
        .ok_or("answer carries no `verdict`")?;
    let data = match &raw.data {
        None => None,
        Some(hex) => {
            // The bound is read off the *hex*, before decoding it. `from_hex` reserves
            // `hex.len() / 2` up front, so checking the decoded length afterwards would let the
            // plugin choose the very allocation `max_frame` exists to bound. Two hex digits are one
            // byte and an odd length is refused, so this is the same limit one step earlier — not a
            // second, looser one.
            let len = hex.len() / 2;
            if len > max_frame {
                return Err(format!(
                    "`data` is {len} bytes, above this broker's `max_frame` of {max_frame}"
                ));
            }
            let bytes = from_hex(hex).map_err(|e| format!("`data` is not hex: {e}"))?;
            if bytes.is_empty() {
                // An empty frame is not a frame: the framing writes a length, and a zero-length
                // one is what a reader treats as a protocol error. Refused here so it cannot be
                // written toward either side.
                return Err("`data` is empty".to_string());
            }
            Some(bytes)
        }
    };

    let verdict = match (verdict, data) {
        ("forward", data) => Verdict::Forward(data),
        ("reply", Some(data)) => Verdict::Reply(data),
        ("reply", None) => return Err("`reply` carries no `data` to answer with".to_string()),
        ("deny", data) => Verdict::Deny(data),
        ("query", Some(data)) => Verdict::Query(data),
        ("query", None) => return Err("`query` carries no `data` to ask with".to_string()),
        (other, _) => {
            return Err(format!(
                "unknown verdict `{other}` (forward, reply, deny, query)"
            ));
        }
    };

    Ok(Answer {
        verdict,
        more: raw.more,
        expect_reply: raw.expect_reply,
        label: raw.label.filter(|l| !l.is_empty()),
    })
}

// -----------------------------------------------------------------------------------
// Framing: the one part of a protocol sbx must understand.
// -----------------------------------------------------------------------------------

/// Read one frame, or `Ok(None)` at a clean end of stream.
///
/// The declared bound is checked **before** the body is allocated. The cage writes this length, so
/// a reader that trusted it would turn a four-byte prefix into an allocation of the cage's
/// choosing. A zero length is refused for the same reason it is refused in an answer: it is not a
/// frame, and no protocol here has one.
pub(crate) fn read_frame(
    r: &mut impl Read,
    framing: Framing,
    max: usize,
    typed: bool,
) -> io::Result<Option<Vec<u8>>> {
    match framing {
        Framing::LengthU32Be => {
            let mut len = [0u8; 4];
            match r.read_exact(&mut len) {
                Ok(()) => {}
                // Nothing at all is the peer closing between frames, which is ordinary.
                Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
                Err(e) => return Err(e),
            }
            let len = u32::from_be_bytes(len) as usize;
            if len == 0 || len > max {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("frame length {len} out of range (max {max})"),
                ));
            }
            let mut body = vec![0u8; len];
            r.read_exact(&mut body)?;
            Ok(Some(body))
        }
        // PostgreSQL's framing: an optional one-byte type, then a length that counts itself, then
        // the body. What the plugin is handed is the type byte (where there is one) and the body,
        // **without** the length — because a plugin that rewrites a body must not also have to fix
        // a byte count. sbx put the framing on, so sbx recomputes it.
        Framing::PgWire => {
            let mut head = Vec::new();
            if typed {
                let mut ty = [0u8; 1];
                match r.read_exact(&mut ty) {
                    Ok(()) => head.push(ty[0]),
                    Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
                    Err(e) => return Err(e),
                }
            }
            let mut len = [0u8; 4];
            match r.read_exact(&mut len) {
                Ok(()) => {}
                Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => {
                    return if head.is_empty() {
                        Ok(None)
                    } else {
                        Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "the stream ended after a message type",
                        ))
                    };
                }
                Err(e) => return Err(e),
            }
            // The length counts its own four bytes, so anything below that is not a length.
            let len = u32::from_be_bytes(len) as usize;
            let body_len = len.checked_sub(4).ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("pgwire length {len} is below its own four bytes"),
                )
            })?;
            if body_len > max {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("pgwire body of {body_len} bytes, above the {max}-byte bound"),
                ));
            }
            let mut body = vec![0u8; body_len];
            r.read_exact(&mut body)?;
            head.extend_from_slice(&body);
            Ok(Some(head))
        }
        // A line, without its terminator: the frame is what the protocol calls a message, and the
        // newline is the framing. Read byte by byte rather than through a `BufRead`, because the
        // caller hands us a stream it also writes to and a buffered reader would swallow bytes the
        // next read is owed.
        Framing::Line => {
            let mut body = Vec::new();
            let mut byte = [0u8; 1];
            loop {
                match r.read_exact(&mut byte) {
                    Ok(()) => {}
                    // Nothing at all is a clean close between messages; a partial line is not.
                    Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => {
                        return if body.is_empty() {
                            Ok(None)
                        } else {
                            Err(io::Error::new(
                                io::ErrorKind::InvalidData,
                                "the stream ended mid-line",
                            ))
                        };
                    }
                    Err(e) => return Err(e),
                }
                if byte[0] == b'\n' {
                    return Ok(Some(body));
                }
                body.push(byte[0]);
                // Checked as it grows, so an endless line is refused rather than read into memory
                // until something else gives out.
                if body.len() > max {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("line longer than the {max}-byte bound"),
                    ));
                }
            }
        }
    }
}

/// Write one frame, framed as the manifest declared.
pub(crate) fn write_frame(
    w: &mut impl Write,
    framing: Framing,
    body: &[u8],
    typed: bool,
) -> io::Result<()> {
    match framing {
        Framing::LengthU32Be => {
            let len = u32::try_from(body.len()).map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidInput, "frame too large to be framed")
            })?;
            w.write_all(&len.to_be_bytes())?;
            w.write_all(body)?;
            w.flush()
        }
        Framing::PgWire => {
            // The length is recomputed here, from the body as it now stands: a plugin that
            // rewrote it changed its size, and the count on the wire has to say so.
            let (ty, body) = if typed {
                let (first, rest) = body.split_first().ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "a typed pgwire message needs its type byte",
                    )
                })?;
                (Some(*first), rest)
            } else {
                (None, body)
            };
            let len = u32::try_from(body.len() + 4).map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "pgwire message too large to frame",
                )
            })?;
            if let Some(ty) = ty {
                w.write_all(&[ty])?;
            }
            w.write_all(&len.to_be_bytes())?;
            w.write_all(body)?;
            w.flush()
        }
        Framing::Line => {
            // A frame carrying a newline would be read back as two, so it is refused rather than
            // written: one message in, one message out, or an error saying why not.
            if body.contains(&b'\n') {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "a line-framed message cannot contain a newline",
                ));
            }
            w.write_all(body)?;
            w.write_all(b"\n")?;
            w.flush()
        }
    }
}

// -----------------------------------------------------------------------------------
// The relay.
// -----------------------------------------------------------------------------------

/// Whatever answers a frame. The relay is written against this rather than against a child
/// process, so the decisions below are testable without spawning one — the property the
/// first-party ssh-agent broker gets from its own fake agent.
///
/// **An implementation must bound its own wait.** The deadline is not in this signature because a
/// test's decider answers from a script and has nothing to wait on; the one that drives a real
/// plugin sets a read timeout on the socket it holds. A decider that can block forever holds a
/// cage connection, a host connection and a thread with it, and no ceiling elsewhere bounds that:
/// [`MAX_QUERIES_PER_FRAME`] bounds a *talkative* plugin, never a silent one.
pub(crate) trait Decider {
    /// Put one frame to the decider and read back its answer. An error means no verdict was
    /// obtained, which every caller treats as a refusal.
    fn ask(&mut self, ask: &Ask<'_>) -> Result<Answer, String>;
}

/// What the relay did with one frame, for the caller's record. Reports what sbx **observed**,
/// which is not the same thing as what the plugin said it decided.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Outcome {
    /// Sent to the host resource (rewritten or not) and its reply returned to the cage.
    Forwarded { rewritten: bool, queries: u32 },
    /// Answered by the plugin without the host resource being contacted.
    Answered,
    /// Refused. The cage got the refusal frame if there was one to give it.
    Refused { with_frame: bool },
}

/// What one frame's relay produced: what sbx observed, what the cage is owed, and what the plugin
/// said about it. Named rather than a tuple because the second field is the one that matters and a
/// positional reading of three options invites putting the wrong one on the wire.
#[derive(Debug)]
pub(crate) struct Relayed {
    /// What sbx observed happening, which is not the same as what the plugin claims it decided.
    pub(crate) outcome: Outcome,
    /// The frames to write back to the cage, in order. Empty when the refusal is a closed
    /// connection, and more than one where a protocol answers a command with several messages.
    pub(crate) to_cage: Vec<Vec<u8>>,
    /// The plugin's own account of the decision, for the record.
    pub(crate) label: Option<String>,
    /// Whether a credential was placed into what reached the host resource. Recorded because a
    /// frame carrying a credential is not the same event as one that was merely rewritten, and an
    /// audit of a session should be able to tell them apart. Never accompanied by the value.
    pub(crate) secret_placed: bool,
}

/// What one exchange's answer amounted to: the frames owed to the cage, the plugin's account, and
/// whether the plugin refused on the way back — which makes the whole exchange a refusal, however
/// it started.
struct Collected {
    frames: Vec<Vec<u8>>,
    label: Option<String>,
    refused: bool,
}

/// Read one exchange's worth of answer from the host resource.
///
/// A single frame where the protocol answers one message with one message; a run of them where it
/// does not, in which case **the plugin is what says where the run ends** — it sees each frame and
/// answers `more` until the terminator it recognises. That is why a multi-message protocol needs
/// `inspect_replies`: without the plugin seeing the replies, nothing here can know when to stop.
///
/// `first` is a frame already taken from the host (the greeting), or `None` to read one now.
fn collect_reply<H: Read + Write>(
    spec: &BrokerSpec,
    decider: &mut dyn Decider,
    host: &mut H,
    seq: u64,
    first: Option<Vec<u8>>,
    marker: Option<&SecretMarker>,
) -> Result<Collected, String> {
    let mut out = Vec::new();
    let mut label = None;
    let mut taken = 0u32;
    let mut pending = first;
    let done = |frames, label| Collected {
        frames,
        label,
        refused: false,
    };
    loop {
        let frame = match pending.take() {
            Some(f) => f,
            None => read_frame(host, spec.framing, spec.max_frame, true)
                .map_err(|e| format!("cannot read the host resource: {e}"))?
                .ok_or("the host resource closed mid-exchange")?,
        };
        // The tripwire. A host resource that reflects the credential would put it in the cage,
        // which is the one thing this whole design exists to prevent. Block, never strip: a
        // partial strip gives false confidence, and an encoded value defeats it anyway — this is
        // a tripwire, not a wall, exactly as on the egress side.
        if let Some(marker) = marker
            && marker.leaks_in(&frame)
        {
            // The caller appends what was done about it, so this says only what happened.
            return Err("the host resource sent the credential back toward the cage".to_string());
        }
        taken += 1;
        if taken > MAX_REPLY_FRAMES {
            return Err(format!(
                "the host resource sent more than {MAX_REPLY_FRAMES} frames for one exchange \
                 without the broker calling it done"
            ));
        }
        // Without the grant the plugin never sees what the host answered, so one frame is the
        // whole answer — the only reading available when nothing can say otherwise.
        if !spec.inspect_replies {
            out.push(frame);
            return Ok(done(out, label));
        }
        let answer = decider.ask(&Ask {
            seq,
            dir: Direction::Down,
            data: &frame,
        })?;
        if answer.label.is_some() {
            label = answer.label.clone();
        }
        match answer.verdict {
            // Pass it on, as it stands or rebuilt. Rebuilding is what keeps something withheld
            // from ever being spelled toward the cage.
            Verdict::Forward(None) => out.push(frame),
            Verdict::Forward(Some(rewritten)) | Verdict::Reply(rewritten) => {
                // Guard: neither the marker nor the secret may travel toward the cage. The first
                // would teach the cage the marker; the second is the invariant itself.
                if let Some(marker) = marker
                    && marker.present_in(&rewritten)
                {
                    return Err(
                        "the plugin put the secret marker in a frame bound for the cage"
                            .to_string(),
                    );
                }
                out.push(rewritten);
            }
            // Refused on the way back: what the host said is not delivered because the plugin was
            // shown it. The caller turns this into the protocol's refusal.
            // Refused on the way back. The outcome is a refusal, not a forward: what the host
            // said is not delivered, and a record calling it a forward would be false. The
            // manifest's constant stands in when the plugin named no bytes, exactly as on the way
            // up.
            Verdict::Deny(bytes) => {
                let frame = bytes.or_else(|| spec.deny_frame.clone());
                if let (Some(marker), Some(frame)) = (marker, frame.as_deref())
                    && marker.present_in(frame)
                {
                    return Err(
                        "the plugin put the secret marker in the frame it refused with".to_string(),
                    );
                }
                return Ok(Collected {
                    frames: frame.into_iter().collect(),
                    label: answer.label,
                    refused: true,
                });
            }
            Verdict::Query(_) => {
                return Err(
                    "the plugin asked to query the host resource about a reply, which ends no \
                     exchange"
                        .to_string(),
                );
            }
        }
        if !answer.more {
            return Ok(done(out, label));
        }
    }
}

/// One frame's worth of relay: ask, honour the verdict, and say what happened.
///
/// `host` is the connection to the host resource, which sbx opened and holds throughout. A
/// [`Verdict::Query`] round-trips on it and comes back to the plugin; the ceiling on those is
/// [`MAX_QUERIES_PER_FRAME`], and reaching it refuses the frame rather than truncating the
/// exchange.
///
/// **The caller sets the deadline on `host` before calling.** Every path here that writes to the
/// host resource then reads its reply would otherwise wait on it forever, and a host resource that
/// hangs would hang the cage: the socket named in the config is whatever the machine offers, not
/// something sbx vouches for. A read timeout on the stream turns that into an error, which lands
/// on the fail-closed path with every other one.
///
/// Every error path is fail-closed: whatever goes wrong with the plugin, the frame is refused and
/// the caller is told, never forwarded on a guess.
pub(crate) fn relay_one<H: Read + Write>(
    frame: &[u8],
    seq: u64,
    spec: &BrokerSpec,
    decider: &mut dyn Decider,
    host: &mut H,
    marker: Option<&SecretMarker>,
    typed: bool,
) -> Result<Relayed, String> {
    let mut ask_data = frame.to_vec();
    // Always a frame on its way *up*, from the cage: a frame coming back is `collect_reply`'s, and
    // the only thing that changes direction inside one exchange is a query's answer, below.
    let mut ask_dir = Direction::Up;
    let mut queries = 0u32;

    loop {
        let answer = decider.ask(&Ask {
            seq,
            dir: ask_dir,
            data: &ask_data,
        })?;
        match answer.verdict {
            Verdict::Query(bytes) => {
                // Guard: never in a query. The plugin reads what comes back, so a service that
                // echoes would hand it the secret — the one path where placing the value would
                // let the plugin read it.
                if let Some(marker) = marker
                    && marker.present_in(&bytes)
                {
                    return Err(
                        "the plugin put the secret marker in a query, whose answer it reads"
                            .to_string(),
                    );
                }
                queries += 1;
                if queries > MAX_QUERIES_PER_FRAME {
                    return Err(format!(
                        "the plugin asked the host resource {queries} times for one frame \
                         (ceiling {MAX_QUERIES_PER_FRAME})"
                    ));
                }
                write_frame(host, spec.framing, &bytes, true)
                    .map_err(|e| format!("cannot reach the host resource: {e}"))?;
                let reply = read_frame(host, spec.framing, spec.max_frame, true)
                    .map_err(|e| format!("cannot read the host resource: {e}"))?
                    .ok_or("the host resource closed mid-exchange")?;
                // The same tripwire `collect_reply` puts on every frame coming back from the host,
                // on the one other frame that comes back from it. The guard above refuses the
                // *marker* in a query — the plugin arranging for the answer to carry the secret —
                // but a host resource can echo the credential for reasons of its own (an API
                // reflecting the `Authorization` header in an error body is the ordinary one), and
                // this reply becomes `ask_data`: it is handed straight to the plugin, which is
                // precisely what the plugin is promised never to see. Block, never strip, as
                // everywhere else this tripwire is applied.
                if let Some(marker) = marker
                    && marker.leaks_in(&reply)
                {
                    return Err(
                        "the host resource sent the credential back toward the cage".to_string()
                    );
                }
                ask_data = reply;
                ask_dir = Direction::QueryReply;
            }
            Verdict::Forward(rewritten) => {
                // Guard: only in what the plugin produced. A frame passed through untouched is
                // never scanned, so the cage's own bytes can never carry a marker into a
                // substitution. What stops the cage from *choosing* where the secret lands is the
                // marker being random and never shown to it.
                let substituted = match (marker, rewritten.as_deref()) {
                    (Some(marker), Some(written)) if marker.present_in(written) => {
                        Some(marker.substitute(written))
                    }
                    _ => None,
                };
                let out = substituted
                    .as_deref()
                    .or(rewritten.as_deref())
                    .unwrap_or(frame);
                write_frame(host, spec.framing, out, typed)
                    .map_err(|e| format!("cannot reach the host resource: {e}"))?;
                // A message the protocol answers with nothing: sent, and that is the whole
                // exchange. Reading here would fail on a close the client asked for, and the
                // record would call a normal goodbye a refusal.
                if !answer.expect_reply {
                    return Ok(Relayed {
                        outcome: Outcome::Forwarded {
                            rewritten: rewritten.is_some(),
                            queries,
                        },
                        to_cage: Vec::new(),
                        label: answer.label,
                        secret_placed: substituted.is_some(),
                    });
                }
                let reply = collect_reply(spec, decider, host, seq, None, marker)?;
                return Ok(Relayed {
                    secret_placed: substituted.is_some(),
                    outcome: if reply.refused {
                        Outcome::Refused {
                            with_frame: !reply.frames.is_empty(),
                        }
                    } else {
                        Outcome::Forwarded {
                            rewritten: rewritten.is_some(),
                            queries,
                        }
                    },
                    to_cage: reply.frames,
                    label: reply.label.or(answer.label),
                });
            }
            Verdict::Reply(bytes) => {
                // Guard: the marker never goes toward the cage. Letting it through would teach the
                // cage this connection's marker and undo the randomness the other guards rest on.
                // A plugin doing this is broken or hostile, and saying so is the only way to tell
                // them apart.
                if let Some(marker) = marker
                    && marker.present_in(&bytes)
                {
                    return Err(
                        "the plugin tried to answer the cage with the secret marker".to_string()
                    );
                }
                return Ok(Relayed {
                    outcome: Outcome::Answered,
                    to_cage: vec![bytes],
                    label: answer.label,
                    secret_placed: false,
                });
            }
            Verdict::Deny(bytes) => {
                // The plugin's own refusal if it gave one, the manifest's constant if it declared
                // one, and otherwise nothing — which the caller turns into a closed connection.
                let frame = bytes.or_else(|| spec.deny_frame.clone());
                // A refusal reaches the cage like any other answer, so it is held to the same
                // rule: a plugin cannot smuggle the marker out inside the frame it refuses with.
                if let (Some(marker), Some(frame)) = (marker, frame.as_deref())
                    && marker.present_in(frame)
                {
                    return Err(
                        "the plugin put the secret marker in the frame it refused with".to_string(),
                    );
                }
                return Ok(Relayed {
                    outcome: Outcome::Refused {
                        with_frame: frame.is_some(),
                    },
                    to_cage: frame.into_iter().collect(),
                    label: answer.label,
                    secret_placed: false,
                });
            }
        }
    }
}

// -----------------------------------------------------------------------------------
// The decider that is a real plugin.
// -----------------------------------------------------------------------------------

/// How long sbx waits for one verdict before treating the plugin as gone.
///
/// A decision here is a computation, not a conversation with a human: nothing in this exchange
/// asks the user anything, so a plugin that has not answered in this long is stuck rather than
/// slow. The wait must be bounded at all, because a silent plugin otherwise holds a cage
/// connection, a host connection and a thread for as long as the session lives.
const PLUGIN_DEADLINE: std::time::Duration = std::time::Duration::from_secs(10);

/// The largest answer line sbx will buffer from a broker plugin.
///
/// Derived from the protocol rather than chosen: an answer carries its frame **hex-encoded**, so a
/// well-formed one reaches twice [`MAX_FRAME_CEILING`] — the ceiling above every `max_frame` a
/// manifest may declare — plus the JSON envelope around it (`seq`, `verdict`, `more`,
/// `expect_reply`, and a `label` the lens truncates on its way to the ring). The slack covers that
/// envelope; a line past this cannot be a well-formed answer, whatever the manifest asked for.
///
/// The signer's bound is its own ([`super::signer::MAX_LINE_BYTES`]) because its lines carry header
/// values, not frames: one reader, two protocols, each with the ceiling its own wire implies.
const MAX_ANSWER_LINE: u64 = 2 * MAX_FRAME_CEILING as u64 + 4 * 1024;

/// Read one newline-terminated line from a plugin, refusing one that runs past `max`.
///
/// Bounded rather than read to the newline: the peer is a separate process whose line sbx buffers
/// before it can bound anything inside it, so a line that never ends is host memory a plugin can
/// take. The bound is per *line* — a fresh `take` on each call — so a long session of ordinary
/// answers is never cut short by what earlier ones used.
///
/// `max` is a parameter because the protocols that read lines imply different ceilings (see
/// [`MAX_ANSWER_LINE`], [`super::signer::MAX_LINE_BYTES`] and the task plane's request line); the
/// reading itself is one definition, so a bound added on one protocol cannot be forgotten on the
/// others.
///
/// The wording of both refusals says *peer*, not *plugin*: three protocols share this reader, and
/// one of them is the cage. Each caller names its own peer in the error it wraps this one in.
pub(super) fn read_bounded_line(reader: &mut impl io::BufRead, max: u64) -> io::Result<String> {
    use std::io::BufRead as _;
    let mut line = String::new();
    let n = (&mut *reader).take(max).read_line(&mut line)?;
    if n == 0 {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "the peer closed its side",
        ));
    }
    if !line.ends_with('\n') {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("the peer wrote more than {max} bytes without ending its line"),
        ));
    }
    Ok(line)
}

/// A broker plugin running in its own host-side cage, spoken to over a socket pair.
///
/// A socket rather than a pipe for one reason: a socket takes a read deadline, and a pipe does
/// not. That deadline is the only thing standing between a wedged plugin and a wedged session.
pub(crate) struct PluginProcess {
    child: std::process::Child,
    /// The protocol's frame bound, applied to what the plugin *hands back* as well as to what the
    /// cage sends. Those bytes go straight to the host resource or to the cage, so the side that
    /// does not own the wire does not get to set their size.
    max_frame: usize,
    /// Our end of the pair. The plugin has the other as both its stdin and its stdout.
    reader: io::BufReader<std::os::unix::net::UnixStream>,
    writer: std::os::unix::net::UnixStream,
    /// The descriptor the cage's environment was read from, held open for the child's whole life:
    /// bwrap reads it at startup, and dropping it earlier would race that read.
    _env: Vec<std::fs::File>,
}

impl PluginProcess {
    /// Start `plugin` under `bwrap` and complete the handshake. An error here means no broker: the
    /// caller has not yet accepted anything it would have to refuse.
    pub(crate) fn start(
        bwrap: &std::path::Path,
        plugin: &crate::plugins::broker::BrokerPlugin,
        allow: &[String],
        marker: Option<&SecretMarker>,
    ) -> io::Result<Self> {
        use std::os::unix::net::UnixStream;
        use std::process::{Command, Stdio};

        let (ours, theirs) = UnixStream::pair()?;
        ours.set_read_timeout(Some(PLUGIN_DEADLINE))?;
        ours.set_write_timeout(Some(PLUGIN_DEADLINE))?;

        let plan = super::resolver::CagePlan {
            kind: crate::plugins::PluginKind::Broker,
            dir: &plugin.dir,
            exec: &plugin.exec,
            grant: &plugin.sandbox,
            host: &plugin.host,
            called: &plugin.name,
            configured_as: &plugin.name,
            // No arguments: everything this plugin is told arrives on the wire, where it can be
            // bounded and where a secret would not be world-readable in `/proc`.
            args: Vec::new(),
            // None, and a broker manifest may not ask for any: the fence needs no fence.
            brokers: &[],
        };
        let (argv, env) = super::resolver::compose_cage(&plan)?;

        let child = Command::new(bwrap)
            .args(argv)
            // The same socket on both: the plugin reads its asks from stdin and writes verdicts to
            // stdout, and both ends of that are this one connection. Handed over as descriptors,
            // which is the form `Stdio` takes.
            .stdin(Stdio::from(std::os::fd::OwnedFd::from(theirs.try_clone()?)))
            .stdout(Stdio::from(std::os::fd::OwnedFd::from(theirs)))
            // Discarded rather than piped, and the choice is about liveness: nothing here reads a
            // plugin's stderr while it runs, and a pipe nobody drains fills and blocks the very
            // process sbx is waiting on. A plugin's channel for saying what it decided is the
            // `label` on its verdict, which the session's record carries.
            .stderr(Stdio::null())
            .spawn()
            .map_err(|e| {
                io::Error::other(format!(
                    "could not start the `{}` broker plugin: {e}",
                    plugin.name
                ))
            })?;

        let mut me = Self {
            child,
            max_frame: plugin.broker.max_frame,
            reader: io::BufReader::new(ours.try_clone()?),
            writer: ours,
            _env: env,
        };
        me.handshake(plugin, allow, marker)?;
        Ok(me)
    }

    /// Say what is being brokered and under which policy, and require an acceptance.
    fn handshake(
        &mut self,
        plugin: &crate::plugins::broker::BrokerPlugin,
        allow: &[String],
        marker: Option<&SecretMarker>,
    ) -> io::Result<()> {
        let hello = Hello {
            broker: &plugin.name,
            allow,
            secret_marker: marker.map(SecretMarker::token),
            inspect_replies: plugin.broker.inspect_replies,
        };
        self.writer.write_all(hello.line().as_bytes())?;
        self.writer.flush()?;
        let line = self.read_line()?;
        parse_hello_reply(&line).map_err(|why| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("the `{}` broker plugin cannot broker: {why}", plugin.name),
            )
        })
    }

    /// One line from the plugin, or an error when it says nothing in time, closes, or says more
    /// than an answer can be.
    fn read_line(&mut self) -> io::Result<String> {
        read_bounded_line(&mut self.reader, MAX_ANSWER_LINE)
    }
}

impl Decider for PluginProcess {
    fn ask(&mut self, ask: &Ask<'_>) -> Result<Answer, String> {
        self.writer
            .write_all(ask.line().as_bytes())
            .and_then(|()| self.writer.flush())
            .map_err(|e| format!("cannot reach the plugin: {e}"))?;
        let line = self
            .read_line()
            .map_err(|e| format!("no verdict from the plugin: {e}"))?;
        parse_answer(&line, ask.seq, self.max_frame)
    }
}

impl Drop for PluginProcess {
    fn drop(&mut self) {
        // The child dies with sbx by construction (every cage is built that way), but a broker
        // outlives nothing: the cage connection it served is gone, so it is killed here rather
        // than left to hold a slot until the session ends. Reaped in the same breath, so a session
        // that opens many connections does not accumulate zombies.
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

// -----------------------------------------------------------------------------------
// Standing the broker up for a launch.
// -----------------------------------------------------------------------------------

/// The two kinds of stream a broker's host side can be, behind one type so the relay stays written
/// against `Read + Write` and knows nothing of which was named.
trait ReadWrite: Read + Write + Send {}
impl<T: Read + Write + Send> ReadWrite for T {}

/// Cage connections served at once. Each pins a thread, a plugin process and a connection to the
/// host resource, so the ceiling bounds all three. Past it a connection is dropped rather than
/// allowed to take a slot nothing bounds — the rule the ssh-agent broker already applies.
const MAX_CONCURRENT_CONNS: usize = 32;

/// The longest the cage may stay silent on a connection it opened before saying its first word.
///
/// A ceiling of its own rather than `host_deadline` alone, because the two answer different
/// questions. `host_deadline` asks how long the *host resource* may take, and a manifest raises it
/// as far as ten minutes for the one reason that a pinentry waits on a person to type. How long a
/// cage may say nothing after connecting has no such reason behind it: the client connected because
/// it had something to send. Taking that ten minutes as the silence budget too would let a
/// passphrase prompt's allowance become ten minutes of holding a plugin process and a host
/// connection for a caller that never spoke.
///
/// Applied as the *lower* of the two, so a protocol that answers faster than this keeps its own
/// tighter number and none can exceed this one. Fixed rather than configurable because nothing has
/// asked: a protocol whose cage side genuinely pauses before its first frame would be the reason to
/// make it a manifest field, and there is none among those sbx serves.
const CAGE_FIRST_FRAME: std::time::Duration = std::time::Duration::from_secs(30);

/// A running broker's host-side resources. The accept loop is detached and dies with sbx; this
/// guard owns the socket file and unlinks it when the launch ends.
pub(crate) struct Broker {
    host_uds: std::path::PathBuf,
}

impl Drop for Broker {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.host_uds);
    }
}

/// The session's broker feed: the socket a reader takes the decision record from, unlinked when the
/// launch ends. Never bound into the cage — the agent must not read, or amend, the record of what it
/// asked for.
///
/// Held apart from [`Broker`] because it belongs to the *session*, not to any one broker: several
/// brokers share one record, and unlinking it when the first of them goes would end a reader's
/// `--follow` while the rest were still deciding.
pub(crate) struct BrokerFeed {
    /// `None` when the socket could not be bound: the directory below still has to be cleaned up,
    /// and the brokers still run.
    control_uds: Option<std::path::PathBuf>,
    /// This launch's own directory of broker sockets. Emptied by the per-broker guards, which drop
    /// first; removing it here is what keeps `<data>/broker` from growing a directory per launch.
    sockets_dir: std::path::PathBuf,
}

impl Drop for BrokerFeed {
    fn drop(&mut self) {
        if let Some(control) = &self.control_uds {
            let _ = std::fs::remove_file(control);
        }
        // Not recursive, deliberately: an entry still in there is a socket whose guard has not run,
        // and taking it out from under a live broker is the one thing this must never do.
        let _ = std::fs::remove_dir(&self.sockets_dir);
    }
}

/// A standing broker, as a cage reaches it: the host socket to bind, where it lands inside, and the
/// variables that point at it.
///
/// One description for every cage that consumes a broker — the agent's, and a resolver plugin's own
/// — because a broker that stood at one address for one of them and another address for the other
/// would be two fences with one name.
#[derive(Debug, Clone)]
pub(crate) struct Reachable {
    /// The broker's name, which is what a manifest's `brokers` entry and a `[broker.<name>]` table
    /// both spell.
    pub(crate) name: String,
    /// The host-side socket sbx serves, to be bound into a cage.
    pub(crate) src: std::path::PathBuf,
    /// Where it lands inside a cage.
    pub(crate) dest: std::path::PathBuf,
    /// The cage variables the manifest declared, resolved against `dest`.
    pub(crate) env: Vec<(String, String)>,
    /// How long an exchange with this broker's host resource may legitimately take, straight from
    /// the manifest's `host_deadline`.
    ///
    /// Carried on the reachable form because it is not only *this* broker's business: whatever
    /// waits on a broker inherits its wait. A resolver plugin holding this socket is entitled to
    /// take that long, so the runner adds it to the plugin's own deadline rather than killing a
    /// plugin that is doing what the manifest allows.
    pub(crate) host_deadline: std::time::Duration,
}

impl Reachable {
    /// The read-only bind that puts this broker in a cage. Read-only suffices to `connect()` — the
    /// cage runs same-uid — and only the socket file crosses, never the directory holding it.
    pub(crate) fn bind(&self) -> super::binds::ExtraBind {
        super::binds::ExtraBind {
            src: self.src.clone(),
            dest: self.dest.clone(),
            writable: false,
        }
    }
}

/// Where a broker's cage-facing socket lands, and the directory holding it.
///
/// Two placements, and a manifest chooses between them by describing its protocol rather than by
/// naming a path. The default is sbx's own namespace: one directory per broker name, so two brokers
/// in one cage cannot collide, and under `/tmp` (a tmpfs the cage owns) so it can shadow nothing the
/// cage needs. A protocol whose clients compute the socket path themselves (`at_host_path`) is
/// instead stood at the address of the resource it fences, so a client that would have found the
/// raw socket finds the fence — which is the whole of what makes a GnuPG agent fenceable.
fn cage_socket(
    name: &str,
    spec: &crate::plugins::broker::BrokerSpec,
    host: &crate::config::BrokerTarget,
) -> (String, String) {
    if let (true, crate::config::BrokerTarget::Unix(path)) = (spec.at_host_path, host)
        && let Some(dir) = path.parent()
    {
        return (
            dir.to_string_lossy().into_owned(),
            path.to_string_lossy().into_owned(),
        );
    }
    let dir = format!("/tmp/sbx-broker-{name}");
    let path = format!("{dir}/{}", spec.socket_name);
    (dir, path)
}

/// Serve one cage connection: start the plugin, open the host resource, and relay frames until
/// either side is done.
fn serve_conn(
    cage: std::os::unix::net::UnixStream,
    bwrap: &std::path::Path,
    plugin: &crate::plugins::broker::BrokerPlugin,
    allow: &[String],
    host_socket: &crate::config::BrokerTarget,
    ring: &super::broker_control::BrokerRing,
    secret: Option<(&str, usize)>,
) -> Result<(), String> {
    // Drawn per connection: two cages, or two connections of one cage, never share a marker.
    let marker = match secret {
        Some((secret, min_len)) => Some(
            SecretMarker::new(secret, min_len)
                .map_err(|e| format!("cannot draw a secret marker: {e}"))?,
        ),
        None => None,
    };
    let marker = marker.as_ref();
    let mut decider =
        PluginProcess::start(bwrap, plugin, allow, marker).map_err(|e| e.to_string())?;
    let spec = &plugin.broker;
    // One connection, whichever kind of endpoint was named. Both carry the deadline `relay_one`
    // documents as the caller's to set: without it a wedged host resource wedges the cage waiting
    // on it.
    let mut host: Box<dyn ReadWrite> = match host_socket {
        crate::config::BrokerTarget::Unix(path) => {
            let stream = std::os::unix::net::UnixStream::connect(path)
                .map_err(|e| format!("cannot reach {}: {e}", path.display()))?;
            let _ = stream.set_read_timeout(Some(spec.host_deadline));
            let _ = stream.set_write_timeout(Some(spec.host_deadline));
            Box::new(stream)
        }
        crate::config::BrokerTarget::Tcp { host, port } => {
            let stream = std::net::TcpStream::connect((host.as_str(), *port))
                .map_err(|e| format!("cannot reach tcp://{host}:{port}: {e}"))?;
            let _ = stream.set_read_timeout(Some(spec.host_deadline));
            let _ = stream.set_write_timeout(Some(spec.host_deadline));
            // Nagle would hold a small frame back waiting for more, which on a request/response
            // protocol is a delay measured in tens of milliseconds per exchange.
            let _ = stream.set_nodelay(true);
            Box::new(stream)
        }
    };

    serve_exchanges(
        spec,
        &mut decider,
        &mut host,
        cage,
        ring,
        marker,
        &plugin.name,
    )
}

/// Relay one connection's exchanges, from the host's greeting (where the protocol has one) to
/// whichever side ends it.
///
/// Split from [`serve_conn`] so the loop can be driven by a scripted plugin and a stand-in host:
/// what ends a connection and what merely produces no bytes are decided here, and neither is
/// visible from a single exchange.
#[allow(clippy::too_many_arguments)]
fn serve_exchanges(
    spec: &crate::plugins::broker::BrokerSpec,
    decider: &mut impl Decider,
    host: &mut impl ReadWrite,
    cage: std::os::unix::net::UnixStream,
    ring: &super::broker_control::BrokerRing,
    marker: Option<&SecretMarker>,
    name: &str,
) -> Result<(), String> {
    let mut cage_r = io::BufReader::new(cage.try_clone().map_err(|e| e.to_string())?);
    let mut cage_w = cage;
    let mut seq = 0u64;

    // Some protocols have the host speak first. Its greeting belongs to no cage request, so it is
    // exchange 0: read it, let the plugin rule on it, and pass on what the plugin allows — before
    // the cage's first message. Skipping this on a greeting protocol would answer every message
    // with the reply to the one before it.
    if spec.host_greets {
        let greeting = read_frame(host, spec.framing, spec.max_frame, true)
            .map_err(|e| format!("cannot read the host resource's greeting: {e}"))?
            .ok_or("the host resource closed before greeting")?;
        let greeted = collect_reply(spec, decider, host, 0, Some(greeting), marker)?;
        let to_cage = greeted.frames;
        for bytes in &to_cage {
            if write_frame(&mut cage_w, spec.framing, bytes, true).is_err() {
                return Ok(());
            }
        }
        if to_cage.is_empty() {
            // The plugin refused the greeting: there is no exchange to have.
            return Ok(());
        }
    }
    // Only the first refusal of a connection is announced; see below.
    let mut said_refusal = false;
    // Under `pgwire` the connection's first message from the client carries no type byte (the
    // startup packet); every later one does. Ignored by the other framings.
    let mut cage_typed = false;

    // The cage's **first** frame is the one with a deadline on it. Everything a connection stands
    // up — the plugin process, the connection to the host resource, a thread, one of
    // `MAX_CONCURRENT_CONNS` slots — is already standing before the cage has said anything, which is
    // the reason `host_deadline` gives for bounding the other leg: a wedged resource "holds a
    // thread, a plugin process and two connections while it waits". It holds exactly the same when
    // the side saying nothing is the cage, and that side is the one sbx does not trust.
    //
    // Both halves are needed, and neither replaces the other: the socket timeout so a connection
    // that sends nothing at all does not block in `read` for good, the budget so one that trickles a
    // byte per timeout does not extend the wait a frame's length at a time. Both are lifted once the
    // frame is in — a broker connection that sits idle *between* requests is the ordinary case, not
    // a fault.
    let silence = spec.host_deadline.min(CAGE_FIRST_FRAME);
    let mut first_deadline = Some(std::time::Instant::now() + silence);
    let _ = cage_w.set_read_timeout(Some(silence));

    loop {
        let read = match first_deadline {
            Some(deadline) => {
                let mut bounded = super::deadline::Deadlined::new(&mut cage_r, deadline);
                let out = read_frame(&mut bounded, spec.framing, spec.max_frame, cage_typed);
                first_deadline = None;
                let _ = cage_w.set_read_timeout(None);
                // A failed read with the budget spent is a read the budget ended: a fact about the
                // clock rather than a string to match on. Reported, unlike an ordinary close,
                // because a broker quietly losing its slots to connections that never spoke is
                // exactly the thing an operator would otherwise have no way to see.
                if out.is_err() && std::time::Instant::now() >= deadline {
                    return Err(format!(
                        "a connection said nothing for {:?} and was closed; it was holding a plugin \
                         process and a connection to the host resource",
                        silence
                    ));
                }
                out
            }
            None => read_frame(&mut cage_r, spec.framing, spec.max_frame, cage_typed),
        };
        let frame = match read {
            Ok(Some(f)) => f,
            // A clean end, or a frame that is not one: either way the client is done with us.
            Ok(None) | Err(_) => return Ok(()),
        };
        seq += 1;
        let (answer, ends) = match relay_one(&frame, seq, spec, decider, host, marker, cage_typed) {
            Ok(relayed) => {
                // Every decision goes to the record, which is what a reader consults afterwards.
                // What sbx *observed* decides the kind; the plugin's label is only ever a detail
                // appended to it.
                let (kind, observed) = match &relayed.outcome {
                    Outcome::Forwarded { rewritten, queries } => (
                        super::broker_control::BrokerKind::Forward,
                        match (rewritten, queries) {
                            (false, 0) => "a request".to_string(),
                            (true, 0) => "a request, narrowed by the broker".to_string(),
                            (false, n) => format!("a request, after {n} host lookup(s)"),
                            (true, n) => {
                                format!(
                                    "a request, narrowed by the broker, after {n} host lookup(s)"
                                )
                            }
                        },
                    ),
                    Outcome::Answered => (
                        super::broker_control::BrokerKind::Answer,
                        "a request answered without the host resource".to_string(),
                    ),
                    Outcome::Refused { .. } => (
                        super::broker_control::BrokerKind::Refuse,
                        "a request".to_string(),
                    ),
                };
                let observed = if relayed.secret_placed {
                    format!("{observed}, carrying the configured credential")
                } else {
                    observed
                };
                ring.push(kind, name, &observed, relayed.label.as_deref());

                // A refusal is also worth saying out loud, and only the first of a connection: it
                // is rare by nature, and a client that hits one usually reports something
                // unhelpful ("permission denied") with no hint of who decided. A forward is the
                // norm and stays silent on the terminal — the record above has it either way.
                if matches!(relayed.outcome, Outcome::Refused { .. }) && !said_refusal {
                    said_refusal = true;
                    let why = relayed
                        .label
                        .as_deref()
                        .map(super::lens::sanitize_detail)
                        .unwrap_or_default();
                    crate::diag::note(&format!(
                        "broker `{name}` refused a request from the cage{}",
                        if why.is_empty() {
                            String::new()
                        } else {
                            format!(": {why}")
                        }
                    ));
                }
                // Nothing to write is not, by itself, the end of the exchange. A refusal with no
                // frame ends it (closing is the refusal that needs no protocol); a message the
                // protocol answers with nothing is simply followed by the next one, and treating
                // that as an ending cuts the connection under a client that was mid-conversation.
                let ends = matches!(relayed.outcome, Outcome::Refused { .. });
                (relayed.to_cage, ends)
            }
            // No verdict was obtained, so nothing is forwarded. The usual cause is a plugin that
            // died or wedged, and that is not a plugin to keep asking: the refusal goes out (as
            // the protocol's own frame where the manifest declared one) and the connection ends.
            // Looping here would answer every further frame from a broker that no longer exists,
            // in silence, while holding both connections open.
            Err(why) => {
                ring.push(
                    super::broker_control::BrokerKind::Refuse,
                    name,
                    "an exchange that could not be completed",
                    Some(&why),
                );
                // The reason leads, because it is not always the same one: a plugin that died or
                // wedged, and a reply the tripwire stopped, both end the exchange here. Saying
                // "no verdict" for the second would name the wrong cause.
                crate::diag::warn(&format!(
                    "broker `{name}`: {} — the request was refused and the connection ended",
                    super::lens::sanitize_detail(&why)
                ));
                if let Some(deny) = &spec.deny_frame {
                    let _ = write_frame(&mut cage_w, spec.framing, deny, true);
                }
                return Ok(());
            }
        };
        // The cage has now sent a message, which under `pgwire` is what makes every later one
        // carry a type byte. Recorded before the branch below, since it is true of the frame that
        // was read rather than of whatever came back.
        cage_typed = true;
        if answer.is_empty() {
            if ends {
                return Ok(());
            }
            continue;
        }
        for bytes in &answer {
            // The last place bytes can reach the cage, and therefore the right place to hold the
            // rule that they must never carry the marker. The verdict paths refuse it earlier and
            // with a better message; this is the net under them, so a path added later cannot
            // quietly become the one that leaks it.
            if let Some(marker) = marker
                && marker.present_in(bytes)
            {
                ring.push(
                    super::broker_control::BrokerKind::Refuse,
                    name,
                    "a frame that would have taught the cage the credential's marker",
                    None,
                );
                crate::diag::warn(&format!(
                    "broker `{name}`: a frame bound for the cage carried the secret marker — \
                     refused and the connection ended"
                ));
                return Ok(());
            }
            if write_frame(&mut cage_w, spec.framing, bytes, true).is_err() {
                return Ok(());
            }
        }
    }
}

/// The directory one launch's broker sockets live in, keyed by the launcher pid like every other
/// per-launch runtime path — so a crashed predecessor's residue is identifiable, and so
/// [`super::gc::sweep_runtime_dirs`] can take it away once that pid is gone.
///
/// A directory per launch rather than `<name>-<pid>.sock` beside the lens, for two reasons that
/// point the same way. A broker plugin installed as `control` would otherwise name the very file a
/// reader connects to (`control-<pid>.sock`), and `start` unlinks before it binds, so it would take
/// the record's place and answer in it — a plugin name is a name, not a reserved word. And a name
/// carrying its pid in the middle is a name the sweep cannot read: it recognises a prefix followed
/// by a pid, which is what makes an abandoned socket collectable at all.
pub(crate) fn sockets_dir(data_dir: &std::path::Path, pid: u32) -> std::path::PathBuf {
    data_dir.join("broker").join(pid.to_string())
}

/// Where one broker's host socket lives, inside its launch's own directory.
fn host_socket(data_dir: &std::path::Path, name: &str, pid: u32) -> std::path::PathBuf {
    sockets_dir(data_dir, pid).join(format!("{name}.sock"))
}

/// Stand up the session's broker feed: the shared decision ring, and the socket
/// `sbx logs --feed broker` reads it through.
///
/// Called once per launch that declares any `[broker.<name>]`, before the first broker is started,
/// so the first decision cannot beat the reader to it. The ring is returned whatever happens to the
/// socket: the relay is the fence and the record is its witness, so a reader that cannot be stood up
/// degrades to brokers with no reader rather than to no brokers. The guard is `None` then, and the
/// warning says which it was.
///
/// Bound before the loop that starts the brokers, and dropped by the caller when none of them
/// stood up. Both halves matter: binding first means the first decision cannot beat a reader to
/// the socket, and letting it go when nothing started keeps a launch whose brokers all fell away
/// off the supervised path — a bound socket needs a live owner to unlink it, and that owner is a
/// parent process this launch would otherwise not need.
pub(crate) fn stand_up_feed(
    layout: &crate::store::Layout,
) -> (
    std::sync::Arc<super::broker_control::BrokerRing>,
    BrokerFeed,
) {
    let ring = std::sync::Arc::new(super::broker_control::BrokerRing::new(
        super::broker_control::BROKER_RING_CAP,
    ));
    let pid = std::process::id();
    let control_uds = super::broker_control::broker_control_socket(layout.data_dir(), pid);
    let served = ring.clone();
    let bound = super::lens::ensure_control_dir(&layout.data_dir().join("broker")).and_then(|()| {
        super::lens::bind_and_serve(&control_uds, move |control| {
            super::broker_control::serve(control, served)
        })
    });
    let sockets_dir = sockets_dir(layout.data_dir(), pid);
    match bound {
        Ok(()) => (
            ring,
            BrokerFeed {
                control_uds: Some(control_uds),
                sockets_dir,
            },
        ),
        Err(e) => {
            crate::diag::warn(&format!(
                "the brokers this config declares will run, but their decisions cannot be read \
                 (`{}`: {e}) — `sbx logs --feed broker` will report no broker for this session",
                control_uds.display()
            ));
            (
                ring,
                BrokerFeed {
                    control_uds: None,
                    sockets_dir,
                },
            )
        }
    }
}

/// Stand up one broker: bind its socket under the data directory, serve it, and return what the
/// cage needs to reach it.
pub(crate) fn start(
    layout: &crate::store::Layout,
    binding: &crate::config::BrokerBinding,
    plugin: &crate::plugins::broker::BrokerPlugin,
    bwrap: &std::path::Path,
    secret: Option<(String, usize)>,
    // The session's decision record, stood up once by the launch and shared by every broker it
    // starts — see [`super::broker_control`] for why it is one ring and not one per broker.
    ring: std::sync::Arc<super::broker_control::BrokerRing>,
) -> io::Result<(Broker, Reachable)> {
    use std::os::unix::net::UnixListener;

    // The data directory is owner-only, and this socket is a reason it must be: whatever connects
    // to it is brokered through to a host resource.
    crate::store::ensure(layout)?;
    let pid = std::process::id();
    super::lens::ensure_control_dir(&sockets_dir(layout.data_dir(), pid))?;

    // Cleared before the bind, since a stale file from a crashed predecessor would block it.
    let host_uds = host_socket(layout.data_dir(), &binding.name, pid);
    let _ = std::fs::remove_file(&host_uds);
    let listener = UnixListener::bind(&host_uds)?;

    let bwrap = bwrap.to_path_buf();
    let allow = binding.allow.clone();
    let host_socket = binding.socket.clone();
    // The accept loop's own copy: the wiring returned below reads the manifest again, and the
    // launcher's `plugin` outlives neither.
    let serving = plugin.clone();
    let serving_ring = ring.clone();
    std::thread::spawn(move || {
        let plugin = serving;
        let ring = serving_ring;
        let cap = super::conncap::ConnCap::new(MAX_CONCURRENT_CONNS);
        for conn in listener.incoming() {
            let Ok(conn) = conn else { continue };
            let Some(slot) = cap.take() else { continue };
            let (bwrap, plugin, allow, host_socket, ring, secret) = (
                bwrap.clone(),
                plugin.clone(),
                allow.clone(),
                host_socket.clone(),
                ring.clone(),
                secret.clone(),
            );
            std::thread::spawn(move || {
                // Held for the connection's life and given back by its `Drop`, so a handler that
                // panics does not take the slot with it.
                let _slot = slot;
                if let Err(why) = serve_conn(
                    conn,
                    &bwrap,
                    &plugin,
                    &allow,
                    &host_socket,
                    &ring,
                    secret.as_ref().map(|(v, n)| (v.as_str(), *n)),
                ) {
                    // A connection that could not be served at all is a fact about the session,
                    // not about any one frame: without this the client just sees a closed socket.
                    crate::diag::warn(&format!(
                        "broker `{}`: a connection was refused — {why}",
                        plugin.name
                    ));
                }
            });
        }
    });

    let (cage_dir, cage_path) = cage_socket(&binding.name, &plugin.broker, &binding.socket);
    Ok((
        Broker {
            host_uds: host_uds.clone(),
        },
        Reachable {
            name: binding.name.clone(),
            src: host_uds,
            dest: std::path::PathBuf::from(&cage_path),
            host_deadline: plugin.broker.host_deadline,
            // Each name gets the form its client expects: the socket itself, or the directory
            // holding it (libpq derives `.s.PGSQL.<port>` from `PGHOST`).
            env: plugin
                .broker
                .cage_env
                .iter()
                .map(|k| (k.clone(), cage_path.clone()))
                .chain(
                    plugin
                        .broker
                        .cage_env_dir
                        .iter()
                        .map(|k| (k.clone(), cage_dir.clone())),
                )
                .collect(),
        },
    ))
}

/// Decode a `data` field. Strict on purpose: an odd length or a stray character is a plugin
/// mis-encoding a frame, and a lenient decoder would put *almost* the right bytes on the wire.
fn from_hex(s: &str) -> Result<Vec<u8>, String> {
    if !s.len().is_multiple_of(2) {
        return Err(format!("odd length ({})", s.len()));
    }
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(s.len() / 2);
    for pair in bytes.chunks(2) {
        let hi = hex_digit(pair[0])?;
        let lo = hex_digit(pair[1])?;
        out.push(hi << 4 | lo);
    }
    Ok(out)
}

fn hex_digit(c: u8) -> Result<u8, String> {
    match c {
        b'0'..=b'9' => Ok(c - b'0'),
        b'a'..=b'f' => Ok(c - b'a' + 10),
        // Uppercase is refused rather than accepted: one spelling means a test that pins a line
        // pins it exactly, and a plugin author is told at once instead of on the one input whose
        // round trip differs.
        b'A'..=b'F' => Err(format!("uppercase digit `{}`", c as char)),
        _ => Err(format!("`{}` is not a hex digit", c as char)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn answer(verdict: &str, extra: &str) -> String {
        format!("{{\"seq\":7,\"verdict\":\"{verdict}\"{extra}}}")
    }

    /// A stand-in for the host resource: replies are queued, frames are recorded. Lets every
    /// decision below be tested without a socket, a plugin or a protocol.
    struct FakeHost {
        /// Canned answers, one **run** per whole frame received: a protocol may answer one command
        /// with several messages, which is the case this fake exists to reproduce faithfully.
        replies: Vec<Vec<Vec<u8>>>,
        /// Every frame the relay put to the host: the record a test asserts *absence* against.
        seen: Vec<Vec<u8>>,
        /// Bytes written by the relay that do not yet form a whole frame.
        pending: Vec<u8>,
        /// Framed replies waiting to be read back, and how far the relay has read.
        outbox: Vec<u8>,
        read_at: usize,
    }

    impl FakeHost {
        /// One frame answered by one frame, the common case.
        fn with(replies: Vec<Vec<u8>>) -> Self {
            Self::with_runs(replies.into_iter().map(|r| vec![r]).collect())
        }

        /// One frame answered by a run of frames.
        fn with_runs(replies: Vec<Vec<Vec<u8>>>) -> Self {
            Self {
                replies,
                seen: Vec::new(),
                pending: Vec::new(),
                outbox: Vec::new(),
                read_at: 0,
            }
        }
    }

    impl Read for FakeHost {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            let n = (self.outbox.len() - self.read_at).min(buf.len());
            buf[..n].copy_from_slice(&self.outbox[self.read_at..self.read_at + n]);
            self.read_at += n;
            Ok(n)
        }
    }

    impl Write for FakeHost {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.pending.extend_from_slice(buf);
            // Drain every whole frame the write completed, answering each with the next canned
            // reply. Two separate buffers, because one buffer holding both directions cannot say
            // where the relay's writes end and the host's answers begin.
            loop {
                let mut cur = std::io::Cursor::new(&self.pending[..]);
                let Ok(Some(frame)) = read_frame(&mut cur, Framing::LengthU32Be, 4096, false)
                else {
                    break;
                };
                let consumed = cur.position() as usize;
                self.pending.drain(..consumed);
                self.seen.push(frame);
                // A frame with no canned reply is a test that under-specified its host: say so
                // here rather than let the relay block on a read that will never answer.
                if self.replies.is_empty() {
                    // A host that answers nothing: legitimate, for a message the protocol defines
                    // no reply to. A test that meant otherwise sees the relay report a closed
                    // exchange, which is what a real silent host looks like.
                    continue;
                }
                for reply in self.replies.remove(0) {
                    write_frame(&mut self.outbox, Framing::LengthU32Be, &reply, false).unwrap();
                }
            }
            Ok(buf.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    /// A plugin that answers from a script, and records what it was shown.
    struct ScriptedPlugin {
        answers: Vec<Answer>,
        shown: Vec<(Direction, Vec<u8>)>,
    }

    impl ScriptedPlugin {
        fn new(answers: Vec<Answer>) -> Self {
            Self {
                answers,
                shown: Vec::new(),
            }
        }
        fn forward() -> Answer {
            Answer {
                verdict: Verdict::Forward(None),
                expect_reply: true,
                more: false,
                label: None,
            }
        }
    }

    impl Decider for ScriptedPlugin {
        fn ask(&mut self, ask: &Ask<'_>) -> Result<Answer, String> {
            self.shown.push((ask.dir, ask.data.to_vec()));
            if self.answers.is_empty() {
                return Err("the plugin ran out of answers".to_string());
            }
            Ok(self.answers.remove(0))
        }
    }

    fn spec(deny_frame: Option<Vec<u8>>) -> BrokerSpec {
        BrokerSpec {
            at_host_path: false,
            host_deadline: crate::plugins::broker::DEFAULT_HOST_DEADLINE,
            cage_env: vec!["X_SOCK".to_string()],
            cage_env_dir: Vec::new(),
            socket_name: "x.sock".to_string(),
            host_greets: false,
            uses_secret: false,
            framing: Framing::LengthU32Be,
            max_frame: 4096,
            deny_frame,
            inspect_replies: false,
        }
    }

    fn relay(
        frame: &[u8],
        plugin: &mut ScriptedPlugin,
        host: &mut FakeHost,
        spec: &BrokerSpec,
    ) -> Result<Relayed, String> {
        relay_one(frame, 7, spec, plugin, host, None, false)
    }

    #[test]
    fn a_forwarded_frame_reaches_the_host_unchanged_and_its_reply_returns() {
        let mut host = FakeHost::with(vec![vec![0xaa]]);
        let mut plugin = ScriptedPlugin::new(vec![ScriptedPlugin::forward()]);
        let Relayed {
            outcome,
            to_cage: out,
            ..
        } = relay(&[0x0b], &mut plugin, &mut host, &spec(None)).unwrap();
        assert_eq!(
            outcome,
            Outcome::Forwarded {
                rewritten: false,
                queries: 0
            }
        );
        assert_eq!(out, vec![vec![0xaa]]);
        assert_eq!(host.seen, vec![vec![0x0b]]);
    }

    /// Rewriting is how a broker narrows a request instead of refusing it whole, so what reaches
    /// the host must be the plugin's bytes and not the cage's.
    #[test]
    fn a_rewritten_forward_puts_the_plugins_bytes_on_the_wire() {
        let mut host = FakeHost::with(vec![vec![0xaa]]);
        let mut plugin = ScriptedPlugin::new(vec![Answer {
            verdict: Verdict::Forward(Some(vec![0x0c, 0x0d])),
            expect_reply: true,
            more: false,
            label: None,
        }]);
        let Relayed { outcome, .. } = relay(&[0x0b], &mut plugin, &mut host, &spec(None)).unwrap();
        assert_eq!(
            outcome,
            Outcome::Forwarded {
                rewritten: true,
                queries: 0
            }
        );
        assert_eq!(host.seen, vec![vec![0x0c, 0x0d]]);
    }

    /// The property the whole type exists for: a refused frame must leave no trace of having been
    /// attempted at the host resource.
    #[test]
    fn a_refused_frame_never_reaches_the_host() {
        for (declared, plugin_bytes, expect) in [
            (None, None, None),
            (Some(vec![5u8]), None, Some(vec![5u8])),
            (Some(vec![5u8]), Some(vec![9u8]), Some(vec![9u8])),
        ] {
            let mut host = FakeHost::with(Vec::new());
            let mut plugin = ScriptedPlugin::new(vec![Answer {
                verdict: Verdict::Deny(plugin_bytes),
                expect_reply: true,
                more: false,
                label: Some("not allowed".to_string()),
            }]);
            let Relayed {
                outcome,
                to_cage: out,
                label,
                ..
            } = relay(&[0x0b], &mut plugin, &mut host, &spec(declared)).unwrap();
            assert_eq!(
                outcome,
                Outcome::Refused {
                    with_frame: expect.is_some()
                }
            );
            assert_eq!(out, expect.into_iter().collect::<Vec<_>>());
            assert_eq!(label.as_deref(), Some("not allowed"));
            assert!(host.seen.is_empty(), "a refusal must not touch the host");
        }
    }

    /// A plugin's own refusal outranks the manifest's constant: the constant exists for the case
    /// where nothing is there to answer, not to override an answer that is.
    #[test]
    fn a_reply_answers_the_cage_without_the_host() {
        let mut host = FakeHost::with(Vec::new());
        let mut plugin = ScriptedPlugin::new(vec![Answer {
            verdict: Verdict::Reply(vec![0x0c]),
            expect_reply: true,
            more: false,
            label: None,
        }]);
        let Relayed {
            outcome,
            to_cage: out,
            ..
        } = relay(&[0x0b], &mut plugin, &mut host, &spec(None)).unwrap();
        assert_eq!(outcome, Outcome::Answered);
        assert_eq!(out, vec![vec![0x0c]]);
        assert!(host.seen.is_empty());
    }

    /// The verdict the ssh-agent broker cannot be expressed without: ask the host, see the answer,
    /// then decide. The reply comes back to the plugin marked as owed to it, not as a frame on its
    /// way to the cage.
    #[test]
    fn a_query_round_trips_to_the_host_and_the_plugin_decides_after() {
        let mut host = FakeHost::with(vec![vec![0x0e], vec![0xaa]]);
        let mut plugin = ScriptedPlugin::new(vec![
            Answer {
                verdict: Verdict::Query(vec![0x0b]),
                expect_reply: true,
                more: false,
                label: None,
            },
            ScriptedPlugin::forward(),
        ]);
        let Relayed {
            outcome,
            to_cage: out,
            ..
        } = relay(&[0x0d], &mut plugin, &mut host, &spec(None)).unwrap();
        assert_eq!(
            outcome,
            Outcome::Forwarded {
                rewritten: false,
                queries: 1
            }
        );
        assert_eq!(out, vec![vec![0xaa]]);
        // The host saw the query first, then the frame itself.
        assert_eq!(host.seen, vec![vec![0x0b], vec![0x0d]]);
        // And the plugin was shown the host's answer, marked as the query's.
        assert_eq!(
            plugin.shown,
            vec![
                (Direction::Up, vec![0x0d]),
                (Direction::QueryReply, vec![0x0e]),
            ]
        );
    }

    /// An unbounded query chain is a plugin holding the host resource open on the cage's behalf.
    /// Reaching the ceiling refuses the frame; it never truncates the exchange and forwards.
    #[test]
    fn a_query_loop_is_refused_at_the_ceiling() {
        // The bound is written out rather than derived from the constant: a test that recomputes
        // what it is checking goes green again the moment the constant moves.
        assert_eq!(MAX_QUERIES_PER_FRAME, 4, "the ceiling this test pins");
        let mut host = FakeHost::with(vec![vec![0x0e]; 6]);
        let mut plugin = ScriptedPlugin::new(
            (0..6)
                .map(|_| Answer {
                    verdict: Verdict::Query(vec![0x0b]),
                    expect_reply: true,
                    more: false,
                    label: None,
                })
                .collect(),
        );
        let err = relay(&[0x0d], &mut plugin, &mut host, &spec(None)).expect_err("must be refused");
        assert!(err.contains("ceiling"), "{err}");
        assert_eq!(
            host.seen.len(),
            4,
            "the ceiling bounds what actually reached the host"
        );
    }

    /// Whatever goes wrong with the plugin, the frame is refused rather than forwarded on a guess.
    #[test]
    fn a_plugin_that_fails_refuses_the_frame_and_never_forwards() {
        let mut host = FakeHost::with(Vec::new());
        let mut plugin = ScriptedPlugin::new(Vec::new());
        let err = relay(&[0x0b], &mut plugin, &mut host, &spec(None)).expect_err("must fail");
        assert!(err.contains("ran out of answers"), "{err}");
        assert!(host.seen.is_empty(), "nothing may reach the host");
    }

    /// Stage an executable broker plugin whose body is a shell loop over stdin.
    fn staged_broker(
        body: &str,
    ) -> (
        crate::testutil::TmpDir,
        crate::plugins::broker::BrokerPlugin,
    ) {
        use std::os::unix::fs::PermissionsExt;
        let root = crate::testutil::TmpDir::new();
        let dir = root.join("plugins").join("fake-broker");
        std::fs::create_dir_all(&dir).unwrap();
        let exec = dir.join("broker");
        std::fs::write(&exec, format!("#!/bin/sh\n{body}\n")).unwrap();
        std::fs::set_permissions(&exec, std::fs::Permissions::from_mode(0o755)).unwrap();
        let plugin = crate::plugins::broker::BrokerPlugin {
            name: "fake-broker".to_string(),
            dir,
            exec,
            sandbox: crate::plugins::SandboxGrant::default(),
            broker: spec(None),
            version: None,
            description: None,
            host: Default::default(),
        };
        (root, plugin)
    }

    /// The whole chain, for real: a plugin started in its own cage, a handshake it must accept,
    /// and a verdict read back off the socket. Every layer above this is tested against a fake
    /// decider, so this is the one place the spawn, the socket deadline and the line protocol are
    /// exercised as they ship.
    #[test]
    fn a_real_plugin_starts_in_its_cage_and_answers_a_verdict() {
        let Some(bwrap) = crate::pathfind::find_on_path("bwrap")
            .filter(|_| matches!(crate::probe_userns(), crate::Userns::Ok))
        else {
            skip_incapable!("skipping broker plugin run: no bwrap or no capability-bearing userns");
            return;
        };
        // Accept the handshake, then deny every frame with a reason. `read` per line is all a
        // plugin needs of the protocol, which is the point of a line of JSON.
        let (_root, plugin) = staged_broker(
            r#"read -r hello
printf '{"ok":true}\n'
while read -r line; do
  seq=$(printf '%s' "$line" | sed 's/.*"seq":\([0-9]*\).*/\1/')
  printf '{"seq":%s,"verdict":"deny","label":"nothing is allowed"}\n' "$seq"
done"#,
        );
        let mut proc = PluginProcess::start(&bwrap, &plugin, &["a-key".to_string()], None)
            .expect("the plugin starts and accepts the handshake");
        let answer = proc
            .ask(&Ask {
                seq: 1,
                dir: Direction::Up,
                data: &[0x0b],
            })
            .expect("a verdict");
        assert_eq!(answer.verdict, Verdict::Deny(None));
        assert_eq!(answer.label.as_deref(), Some("nothing is allowed"));
    }

    /// The line bound, driven through the real process. A test against the fake decider never
    /// reaches `PluginProcess::read_line`, which is the only place it is applied — the same reason
    /// the frame bound below is exercised here rather than against a fake. A plugin that answers
    /// with a line it never ends takes host memory for as long as the session lives, so the refusal
    /// must name the ceiling instead of arriving later as a socket deadline.
    #[test]
    fn a_plugin_that_never_ends_its_line_is_refused_at_the_ceiling() {
        let Some(bwrap) = crate::pathfind::find_on_path("bwrap")
            .filter(|_| matches!(crate::probe_userns(), crate::Userns::Ok))
        else {
            skip_incapable!("skipping broker plugin run: no bwrap or no capability-bearing userns");
            return;
        };
        // Accepts the handshake, then writes well past the ceiling without ever ending the line.
        // The flood is finite on purpose: an endless one makes a *regression* here take the machine
        // rather than fail the test — measured, the OOM killer ends the run instead of an assertion.
        // Four mebibytes is eight times the ceiling, enough that a reader without the bound is
        // plainly buffering and not merely reading a large answer.
        let (_root, plugin) = staged_broker(
            r#"read -r hello
printf '{"ok":true}\n'
read -r line
i=0
while [ $i -lt 4096 ]; do printf '%01024d' 0; i=$((i+1)); done
sleep 30"#,
        );
        let mut proc = PluginProcess::start(&bwrap, &plugin, &["a-key".to_string()], None)
            .expect("the plugin starts and accepts the handshake");
        let err = proc
            .ask(&Ask {
                seq: 1,
                dir: Direction::Up,
                data: &[0x0b],
            })
            .expect_err("an endless line must be refused");
        assert!(
            err.contains(&format!("more than {MAX_ANSWER_LINE} bytes")),
            "the refusal must name the ceiling, not arrive as a deadline: {err}"
        );
    }

    /// The bound applies to what the plugin *hands back*, not only to what the cage sends. Driven
    /// through the real process, because that is where the parameter was once passed as
    /// `usize::MAX` while a test against the fake decider proved the bound worked.
    #[test]
    fn a_plugins_own_answer_is_bounded_by_its_declared_max_frame() {
        let Some(bwrap) = crate::pathfind::find_on_path("bwrap")
            .filter(|_| matches!(crate::probe_userns(), crate::Userns::Ok))
        else {
            skip_incapable!("skipping broker plugin run: no bwrap or no capability-bearing userns");
            return;
        };
        // Answers with 8 bytes of `data`, under a manifest that declares a 4-byte protocol.
        let (_root, mut plugin) = staged_broker(
            r#"read -r hello
printf '{"ok":true}\n'
while read -r line; do
  seq=$(printf '%s' "$line" | sed 's/.*"seq":\([0-9]*\).*/\1/')
  printf '{"seq":%s,"verdict":"reply","data":"0102030405060708"}\n' "$seq"
done"#,
        );
        plugin.broker.max_frame = 4;
        let mut proc = PluginProcess::start(&bwrap, &plugin, &[], None).expect("the plugin starts");
        let err = proc
            .ask(&Ask {
                seq: 1,
                dir: Direction::Up,
                data: &[0x0b],
            })
            .expect_err("an oversized answer must be refused");
        assert!(err.contains("max_frame"), "{err}");
    }

    /// A plugin that will not broker says so at the one moment nothing is at stake, and sbx never
    /// reaches the point of asking it about a frame.
    #[test]
    fn a_plugin_that_declines_the_handshake_never_becomes_a_broker() {
        let Some(bwrap) = crate::pathfind::find_on_path("bwrap")
            .filter(|_| matches!(crate::probe_userns(), crate::Userns::Ok))
        else {
            skip_incapable!("skipping broker plugin run: no bwrap or no capability-bearing userns");
            return;
        };
        let (_root, plugin) = staged_broker(
            r#"read -r hello
printf '{"ok":false,"error":"this build brokers nothing"}\n'"#,
        );
        match PluginProcess::start(&bwrap, &plugin, &[], None) {
            Ok(_) => panic!("a plugin that declined must not become a broker"),
            Err(err) => assert!(
                err.to_string().contains("this build brokers nothing"),
                "{err}"
            ),
        }
    }

    fn marker_for(secret: &str) -> SecretMarker {
        SecretMarker::new(secret, 4).expect("a marker is drawn")
    }

    fn relay_with(
        frame: &[u8],
        plugin: &mut ScriptedPlugin,
        host: &mut FakeHost,
        spec: &BrokerSpec,
        marker: &SecretMarker,
    ) -> Result<Relayed, String> {
        relay_one(frame, 7, spec, plugin, host, Some(marker), false)
    }

    /// What the capability is for: the plugin places a marker, and the bytes that reach the host
    /// carry the credential the plugin never saw.
    #[test]
    fn the_secret_reaches_the_host_and_the_plugin_only_ever_held_a_marker() {
        let marker = marker_for("hunter2");
        let token = marker.token();
        let mut host = FakeHost::with(vec![b"R".to_vec()]);
        let mut plugin = ScriptedPlugin::new(vec![Answer {
            verdict: Verdict::Forward(Some(format!("PASSWORD {token}").into_bytes())),
            expect_reply: true,
            more: false,
            label: None,
        }]);
        let out = relay_with(b"p", &mut plugin, &mut host, &spec(None), &marker).unwrap();
        assert!(matches!(out.outcome, Outcome::Forwarded { .. }));
        assert_eq!(
            host.seen,
            vec![b"PASSWORD hunter2".to_vec()],
            "the wire carries the credential"
        );
        assert!(
            !host.seen[0]
                .windows(token.len())
                .any(|w| w == token.as_bytes()),
            "and not the marker"
        );
    }

    /// A frame carrying a credential is not the same event as one merely rewritten, and a session
    /// audit has to be able to tell them apart — without the value ever appearing.
    #[test]
    fn the_relay_reports_that_a_credential_was_placed() {
        let marker = marker_for("hunter2");
        let mut host = FakeHost::with(vec![b"R".to_vec()]);
        let mut plugin = ScriptedPlugin::new(vec![Answer {
            verdict: Verdict::Forward(Some(format!("AUTH {}", marker.token()).into_bytes())),
            expect_reply: true,
            more: false,
            label: None,
        }]);
        let out = relay_with(b"p", &mut plugin, &mut host, &spec(None), &marker).unwrap();
        assert!(out.secret_placed, "a placed credential is reported");

        // A rewrite that places nothing is not reported as carrying one.
        let mut host = FakeHost::with(vec![b"R".to_vec()]);
        let mut plugin = ScriptedPlugin::new(vec![Answer {
            verdict: Verdict::Forward(Some(b"PLAIN".to_vec())),
            expect_reply: true,
            more: false,
            label: None,
        }]);
        let out = relay_with(b"p", &mut plugin, &mut host, &spec(None), &marker).unwrap();
        assert!(!out.secret_placed);
    }

    /// Guard: the cage's own bytes are never scanned. A frame passed through untouched carries no
    /// substitution, whatever it contains.
    #[test]
    fn a_pass_through_frame_is_never_substituted() {
        let marker = marker_for("hunter2");
        let cage_frame = format!("ECHO {}", marker.token()).into_bytes();
        let mut host = FakeHost::with(vec![b"R".to_vec()]);
        let mut plugin = ScriptedPlugin::new(vec![ScriptedPlugin::forward()]);
        relay_with(&cage_frame, &mut plugin, &mut host, &spec(None), &marker).unwrap();
        assert_eq!(
            host.seen,
            vec![cage_frame],
            "the cage's bytes reach the host unchanged, marker text and all"
        );
    }

    /// Guard: never in a query. The plugin reads a query's answer, so a service that echoes would
    /// hand it the secret — the one path where placing the value would let it be read.
    #[test]
    fn the_marker_is_refused_in_a_query() {
        let marker = marker_for("hunter2");
        let mut host = FakeHost::with(vec![b"R".to_vec()]);
        let mut plugin = ScriptedPlugin::new(vec![Answer {
            verdict: Verdict::Query(format!("ECHO {}", marker.token()).into_bytes()),
            expect_reply: true,
            more: false,
            label: None,
        }]);
        let err = relay_with(b"p", &mut plugin, &mut host, &spec(None), &marker)
            .expect_err("must be refused");
        assert!(err.contains("query"), "{err}");
        assert!(host.seen.is_empty(), "nothing reaches the host");
    }

    /// The tripwire belongs on a query's answer too, and it was missing there. The guard beside it
    /// refuses the *marker* in a query — the plugin arranging for the answer to carry the secret —
    /// but a host resource can echo the credential for reasons of its own (an API reflecting the
    /// `Authorization` header in an error body is the ordinary one). That reply becomes `ask_data`
    /// and is handed straight to the plugin, which is exactly what the plugin is promised never to
    /// see. `collect_reply` has always checked every frame on the way back; this is the one other
    /// frame that comes back from the host.
    #[test]
    fn a_query_answer_carrying_the_credential_is_refused_before_the_plugin_reads_it() {
        let marker = marker_for("hunter2");
        // The query itself is clean — no marker in it — so only the answer can trip the guard.
        let mut host = FakeHost::with(vec![b"YOU SENT hunter2".to_vec()]);
        let mut plugin = ScriptedPlugin::new(vec![Answer {
            verdict: Verdict::Query(b"WHOAMI".to_vec()),
            expect_reply: true,
            more: false,
            label: None,
        }]);
        let err = relay_with(b"p", &mut plugin, &mut host, &spec(None), &marker)
            .expect_err("an echoed credential must be refused before the plugin sees it");
        assert!(err.contains("back toward the cage"), "{err}");
        assert_eq!(
            host.seen,
            vec![b"WHOAMI".to_vec()],
            "the query still reached the host; it is the answer that was refused"
        );
    }

    /// Guard: the marker never travels toward the cage. Letting it through would teach the cage
    /// this connection's marker, and every other guard rests on the cage not knowing it.
    #[test]
    fn the_marker_is_refused_on_its_way_to_the_cage() {
        let marker = marker_for("hunter2");
        let mut host = FakeHost::with(Vec::new());
        let mut plugin = ScriptedPlugin::new(vec![Answer {
            verdict: Verdict::Reply(format!("HERE {}", marker.token()).into_bytes()),
            expect_reply: true,
            more: false,
            label: None,
        }]);
        let err = relay_with(b"p", &mut plugin, &mut host, &spec(None), &marker)
            .expect_err("must be refused");
        assert!(err.contains("answer the cage"), "{err}");
    }

    /// A refusal reaches the cage like any other answer, so it is held to the same rule. This was
    /// the path the guard first missed: it covered `reply` and not `deny`, and a plugin could have
    /// taught the cage the marker inside the very frame it refused with.
    #[test]
    fn the_marker_is_refused_in_the_frame_a_plugin_denies_with() {
        let marker = marker_for("hunter2");
        let mut host = FakeHost::with(Vec::new());
        let mut plugin = ScriptedPlugin::new(vec![Answer {
            verdict: Verdict::Deny(Some(format!("NO {}", marker.token()).into_bytes())),
            expect_reply: true,
            more: false,
            label: None,
        }]);
        let err = relay_with(b"p", &mut plugin, &mut host, &spec(None), &marker)
            .expect_err("must be refused");
        assert!(err.contains("refused with"), "{err}");
        assert!(host.seen.is_empty(), "nothing reached the host either");
    }

    /// The same guard on the way back, where a plugin that inspects replies could rebuild one.
    #[test]
    fn the_marker_is_refused_in_a_rebuilt_reply() {
        let marker = marker_for("hunter2");
        let inspecting = BrokerSpec {
            inspect_replies: true,
            ..spec(None)
        };
        let mut host = FakeHost::with(vec![b"R".to_vec()]);
        let mut plugin = ScriptedPlugin::new(vec![
            ScriptedPlugin::forward(),
            Answer {
                verdict: Verdict::Forward(Some(format!("R {}", marker.token()).into_bytes())),
                expect_reply: true,
                more: false,
                label: None,
            },
        ]);
        let err = relay_with(b"p", &mut plugin, &mut host, &inspecting, &marker)
            .expect_err("must be refused");
        assert!(err.contains("bound for the cage"), "{err}");
    }

    /// The tripwire on the way back: a host resource that reflects the credential would put it in
    /// the cage, which is the one outcome this design exists to prevent. Blocked, never stripped.
    #[test]
    fn a_reply_carrying_the_credential_back_is_refused() {
        let marker = marker_for("hunter2");
        let inspecting = BrokerSpec {
            inspect_replies: true,
            ..spec(None)
        };
        let mut host = FakeHost::with(vec![b"YOU SENT hunter2".to_vec()]);
        let mut plugin = ScriptedPlugin::new(vec![ScriptedPlugin::forward()]);
        let err = relay_with(b"p", &mut plugin, &mut host, &inspecting, &marker)
            .expect_err("a reflected credential must be refused");
        assert!(err.contains("back toward the cage"), "{err}");
    }

    /// Under the floor the scan is off, and deliberately: a two-byte secret would match innocent
    /// traffic constantly. The launch says so once rather than silently doing nothing.
    #[test]
    fn a_secret_under_the_floor_is_placed_but_not_watched() {
        let short = SecretMarker::new("ab", 8).expect("drawn");
        assert!(!short.leaks_in(b"xx ab xx"), "no scan under the floor");
        let long = SecretMarker::new("hunter2!", 8).expect("drawn");
        assert!(long.leaks_in(b"xx hunter2! xx"), "watched at the floor");
    }

    /// Two connections never share a marker: one drawn per connection is what keeps a cage that
    /// learned one (somehow) from using it on the next.
    #[test]
    fn every_connection_draws_its_own_marker() {
        let a = marker_for("hunter2");
        let b = marker_for("hunter2");
        assert_ne!(a.token(), b.token());
        assert!(a.token().starts_with("SBX-SECRET-"));
    }

    /// The shape a real protocol forced: gpg-agent answers one command with a run of lines
    /// (`D 2.4.8` then `OK`), so one frame out is not one frame back. The plugin says where the run
    /// ends, because only it knows the terminator.
    #[test]
    fn a_multi_frame_answer_is_collected_until_the_plugin_calls_it_done() {
        let inspecting = BrokerSpec {
            inspect_replies: true,
            ..spec(None)
        };
        // One command, two lines back — exactly what `gpg-connect-agent 'GETINFO version'` shows.
        let mut host = FakeHost::with_runs(vec![vec![b"D 2.4.8".to_vec(), b"OK".to_vec()]]);
        let mut plugin = ScriptedPlugin::new(vec![
            ScriptedPlugin::forward(),
            Answer {
                verdict: Verdict::Forward(None),
                expect_reply: true,
                more: true,
                label: None,
            },
            Answer {
                verdict: Verdict::Forward(None),
                expect_reply: true,
                more: false,
                label: Some("done".to_string()),
            },
        ]);
        let Relayed {
            outcome,
            to_cage: out,
            label,
            ..
        } = relay(b"GETINFO version", &mut plugin, &mut host, &inspecting).unwrap();
        assert!(matches!(outcome, Outcome::Forwarded { .. }));
        assert_eq!(
            out,
            vec![b"D 2.4.8".to_vec(), b"OK".to_vec()],
            "both lines reach the cage, in order"
        );
        assert_eq!(label.as_deref(), Some("done"));
    }

    /// Some messages get no answer — PostgreSQL's `Terminate`, and the close of many protocols.
    /// Waiting for one would end the connection on a read that can only fail, and would be
    /// recorded as a refusal: a record saying something that did not happen.
    #[test]
    fn a_message_the_protocol_never_answers_is_not_a_refusal() {
        // The host is given no reply to hand out: reading would fail if the relay tried.
        let mut host = FakeHost::with(Vec::new());
        let mut plugin = ScriptedPlugin::new(vec![Answer {
            verdict: Verdict::Forward(None),
            expect_reply: false,
            more: false,
            label: Some("goodbye".to_string()),
        }]);
        let out = relay(b"X", &mut plugin, &mut host, &spec(None)).expect("not an error");
        assert!(
            matches!(out.outcome, Outcome::Forwarded { .. }),
            "a goodbye is a forward, not a refusal: {:?}",
            out.outcome
        );
        assert!(
            out.to_cage.is_empty(),
            "and there is nothing to answer with"
        );
        assert_eq!(host.seen, vec![b"X".to_vec()], "the message did go out");
    }

    /// A plugin that keeps saying `more` while the host keeps talking would hold the cage's
    /// connection open indefinitely. The ceiling ends the exchange as a refusal, never as a
    /// truncated answer.
    #[test]
    fn an_endless_answer_is_refused_at_the_ceiling() {
        assert_eq!(MAX_REPLY_FRAMES, 1024, "the ceiling this test pins");
        let inspecting = BrokerSpec {
            inspect_replies: true,
            ..spec(None)
        };
        let mut host = FakeHost::with_runs(vec![
            (0..MAX_REPLY_FRAMES + 2)
                .map(|_| b"D chunk".to_vec())
                .collect(),
        ]);
        let answers = std::iter::once(ScriptedPlugin::forward())
            .chain((0..MAX_REPLY_FRAMES + 2).map(|_| Answer {
                verdict: Verdict::Forward(None),
                expect_reply: true,
                more: true,
                label: None,
            }))
            .collect();
        let mut plugin = ScriptedPlugin::new(answers);
        let err = relay(b"GO", &mut plugin, &mut host, &inspecting).expect_err("must be refused");
        assert!(err.contains("without the broker calling it done"), "{err}");
    }

    /// The grant `inspect_replies` buys: what the host answered goes back to the plugin, which may
    /// rebuild it. Rebuilding is how a broker keeps something withheld from ever being spelled
    /// toward the cage, rather than filtering it out of an answer it already sent.
    #[test]
    fn a_reply_is_rebuilt_when_the_manifest_asks_to_inspect_replies() {
        let inspecting = BrokerSpec {
            inspect_replies: true,
            ..spec(None)
        };
        let mut host = FakeHost::with(vec![vec![0xaa, 0xbb]]);
        let mut plugin = ScriptedPlugin::new(vec![
            ScriptedPlugin::forward(),
            Answer {
                verdict: Verdict::Reply(vec![0xaa]),
                expect_reply: true,
                more: false,
                label: Some("second key withheld".to_string()),
            },
        ]);
        let Relayed {
            outcome,
            to_cage: out,
            label,
            ..
        } = relay(&[0x0b], &mut plugin, &mut host, &inspecting).unwrap();
        assert_eq!(
            outcome,
            Outcome::Forwarded {
                rewritten: false,
                queries: 0
            }
        );
        assert_eq!(out, vec![vec![0xaa]], "the cage gets the rebuilt answer");
        assert_eq!(label.as_deref(), Some("second key withheld"));
        assert_eq!(
            plugin.shown,
            vec![
                (Direction::Up, vec![0x0b]),
                (Direction::Down, vec![0xaa, 0xbb]),
            ]
        );
    }

    /// Without the grant the plugin never sees what the host answered, and the answer reaches the
    /// cage untouched.
    #[test]
    fn a_reply_is_not_shown_to_a_plugin_that_did_not_ask_for_it() {
        let mut host = FakeHost::with(vec![vec![0xaa, 0xbb]]);
        let mut plugin = ScriptedPlugin::new(vec![ScriptedPlugin::forward()]);
        let Relayed { to_cage: out, .. } =
            relay(&[0x0b], &mut plugin, &mut host, &spec(None)).unwrap();
        assert_eq!(out, vec![vec![0xaa, 0xbb]]);
        assert_eq!(plugin.shown, vec![(Direction::Up, vec![0x0b])]);
    }

    /// A refusal on the way back still refuses: what the host said is not delivered because the
    /// plugin was shown it.
    #[test]
    fn a_reply_the_plugin_refuses_is_not_delivered() {
        let inspecting = BrokerSpec {
            inspect_replies: true,
            ..spec(Some(vec![5]))
        };
        let mut host = FakeHost::with(vec![vec![0xaa]]);
        let mut plugin = ScriptedPlugin::new(vec![
            ScriptedPlugin::forward(),
            Answer {
                verdict: Verdict::Deny(None),
                expect_reply: true,
                more: false,
                label: None,
            },
        ]);
        let Relayed {
            outcome,
            to_cage: out,
            ..
        } = relay(&[0x0b], &mut plugin, &mut host, &inspecting).unwrap();
        assert_eq!(outcome, Outcome::Refused { with_frame: true });
        assert_eq!(out, vec![vec![5]], "the manifest's refusal, not the answer");
    }

    /// PostgreSQL's framing, on the bytes the protocol actually puts on a wire. The length counts
    /// itself, which is the part a formula gets wrong: a body of 4 bytes is a length of 8.
    #[test]
    fn a_pgwire_message_carries_its_type_and_a_length_that_counts_itself() {
        // `p` (PasswordMessage) with a 6-byte body: 1 + 4 + 6 on the wire, length field = 10.
        let wire = b"p\x00\x00\x00\x0Asecret".to_vec();
        let mut cur = std::io::Cursor::new(wire.clone());
        let frame = read_frame(&mut cur, Framing::PgWire, 4096, true)
            .unwrap()
            .expect("a message");
        assert_eq!(
            frame,
            b"psecret".to_vec(),
            "the plugin sees the type and the body, never the byte count"
        );

        let mut back = Vec::new();
        write_frame(&mut back, Framing::PgWire, &frame, true).unwrap();
        assert_eq!(back, wire, "and it goes back on the wire byte for byte");
    }

    /// The exception no formula covers: the client's first message has no type byte at all.
    #[test]
    fn the_startup_packet_has_no_type_byte() {
        // Length 8, then a 4-byte protocol version. Nothing before the length.
        let wire = b"\x00\x00\x00\x08\x00\x03\x00\x00".to_vec();
        let mut cur = std::io::Cursor::new(wire.clone());
        let frame = read_frame(&mut cur, Framing::PgWire, 4096, false)
            .unwrap()
            .expect("a startup packet");
        assert_eq!(frame, b"\x00\x03\x00\x00".to_vec());

        let mut back = Vec::new();
        write_frame(&mut back, Framing::PgWire, &frame, false).unwrap();
        assert_eq!(back, wire);
    }

    /// The reason sbx owns the framing: a plugin that rewrites a body must not also have to fix a
    /// byte count, and a stale count would corrupt every message after it.
    #[test]
    fn a_rewritten_pgwire_body_is_reframed_with_the_new_length() {
        let mut out = Vec::new();
        write_frame(&mut out, Framing::PgWire, b"pmuch-longer-secret", true).unwrap();
        assert_eq!(&out[..1], b"p");
        assert_eq!(
            u32::from_be_bytes(out[1..5].try_into().unwrap()) as usize,
            "much-longer-secret".len() + 4,
            "the count on the wire follows the body it now describes"
        );
        // And it reads back as one message.
        let mut cur = std::io::Cursor::new(out);
        assert_eq!(
            read_frame(&mut cur, Framing::PgWire, 4096, true).unwrap(),
            Some(b"pmuch-longer-secret".to_vec())
        );
    }

    /// A length below its own four bytes is not a length. The cage writes this field, so it is
    /// checked rather than trusted.
    #[test]
    fn a_pgwire_length_below_its_own_header_is_refused() {
        for len in [0u32, 3] {
            let mut wire = b"p".to_vec();
            wire.extend_from_slice(&len.to_be_bytes());
            let mut cur = std::io::Cursor::new(wire);
            let err = read_frame(&mut cur, Framing::PgWire, 4096, true).expect_err("not a length");
            assert_eq!(err.kind(), io::ErrorKind::InvalidData, "len {len}");
        }
    }

    /// The framing of Assuan and of most text protocols: the newline is the frame boundary, not
    /// part of the message.
    #[test]
    fn a_line_framed_message_travels_without_its_terminator() {
        let mut buf = Vec::new();
        write_frame(&mut buf, Framing::Line, b"OK Pleased to meet you", false).unwrap();
        assert_eq!(buf, b"OK Pleased to meet you\n");
        let mut cur = std::io::Cursor::new(buf);
        assert_eq!(
            read_frame(&mut cur, Framing::Line, 4096, false).unwrap(),
            Some(b"OK Pleased to meet you".to_vec())
        );
        assert_eq!(
            read_frame(&mut cur, Framing::Line, 4096, false).unwrap(),
            None
        );
    }

    /// Two messages in one stream must come back as two, which is the whole of what a framing has
    /// to guarantee.
    #[test]
    fn consecutive_lines_are_two_frames() {
        let mut cur = std::io::Cursor::new(b"D 2.4.8\nOK\n".to_vec());
        assert_eq!(
            read_frame(&mut cur, Framing::Line, 4096, false).unwrap(),
            Some(b"D 2.4.8".to_vec())
        );
        assert_eq!(
            read_frame(&mut cur, Framing::Line, 4096, false).unwrap(),
            Some(b"OK".to_vec())
        );
        assert_eq!(
            read_frame(&mut cur, Framing::Line, 4096, false).unwrap(),
            None
        );
    }

    /// An over-long line is an error, not a truncation: half a message on a wire is worse than
    /// none, and the bound is checked as the line grows rather than after it is all in memory.
    #[test]
    fn an_over_long_line_is_refused_rather_than_cut() {
        let mut cur = std::io::Cursor::new(b"aaaaaaaaaa\n".to_vec());
        let err = read_frame(&mut cur, Framing::Line, 4, false).expect_err("over the bound");
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    /// A stream that stops mid-line is not a clean close: reporting it as one would hand the
    /// caller a truncated message as if the peer had meant it.
    #[test]
    fn a_stream_that_ends_mid_line_is_an_error_not_an_end() {
        let mut cur = std::io::Cursor::new(b"OK no newline".to_vec());
        let err = read_frame(&mut cur, Framing::Line, 4096, false).expect_err("truncated");
        assert!(err.to_string().contains("mid-line"), "{err}");
    }

    /// A message carrying a newline would be read back as two, so writing one is refused.
    #[test]
    fn a_line_framed_message_may_not_contain_a_newline() {
        let mut buf = Vec::new();
        let err =
            write_frame(&mut buf, Framing::Line, b"OK\nERR forged", false).expect_err("refused");
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
        assert!(buf.is_empty(), "nothing may reach the wire: {buf:?}");
    }

    #[test]
    fn a_frame_survives_the_framing_round_trip() {
        let mut buf = Vec::new();
        write_frame(&mut buf, Framing::LengthU32Be, &[0x0b, 0xff], false).unwrap();
        assert_eq!(buf, vec![0, 0, 0, 2, 0x0b, 0xff]);
        let mut cur = std::io::Cursor::new(buf);
        let got = read_frame(&mut cur, Framing::LengthU32Be, 4096, false).unwrap();
        assert_eq!(got, Some(vec![0x0b, 0xff]));
        // And a clean end of stream is not an error.
        assert_eq!(
            read_frame(&mut cur, Framing::LengthU32Be, 4096, false).unwrap(),
            None
        );
    }

    /// The length prefix is written by the cage, so it is checked before it is believed.
    #[test]
    fn an_oversized_or_empty_length_prefix_is_refused_before_allocating() {
        for prefix in [u32::MAX, 5, 0] {
            let mut bytes = prefix.to_be_bytes().to_vec();
            bytes.extend_from_slice(&[0u8; 4]);
            let mut cur = std::io::Cursor::new(bytes);
            let err =
                read_frame(&mut cur, Framing::LengthU32Be, 4, false).expect_err("out of range");
            assert_eq!(err.kind(), io::ErrorKind::InvalidData, "prefix {prefix}");
        }
    }

    #[test]
    fn the_handshake_carries_the_version_the_name_and_the_policy() {
        let allow = vec!["SHA256:abc".to_string()];
        let line = Hello {
            broker: "gpg-agent",
            allow: &allow,
            secret_marker: None,
            inspect_replies: true,
        }
        .line();
        assert!(line.ends_with('\n'));
        let v: serde_json::Value = serde_json::from_str(&line).expect("valid json");
        assert_eq!(v["v"], PROTOCOL_VERSION);
        assert_eq!(v["broker"], "gpg-agent");
        assert_eq!(v["allow"][0], "SHA256:abc");
        assert_eq!(v["inspect_replies"], true);
    }

    #[test]
    fn a_frame_travels_as_lowercase_hex_and_names_its_direction() {
        let line = Ask {
            seq: 3,
            dir: Direction::Up,
            data: &[0x0b, 0xff, 0x00],
        }
        .line();
        let v: serde_json::Value = serde_json::from_str(&line).expect("valid json");
        assert_eq!(v["seq"], 3);
        assert_eq!(v["dir"], "up");
        assert_eq!(v["data"], "0bff00");
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(
                &Ask {
                    seq: 4,
                    dir: Direction::QueryReply,
                    data: &[1]
                }
                .line()
            )
            .unwrap()["dir"],
            "query-reply"
        );
    }

    /// A frame is opaque to sbx, so the one thing the encoding must never do is change it.
    #[test]
    fn every_byte_survives_the_round_trip() {
        let all: Vec<u8> = (0..=255).collect();
        assert_eq!(from_hex(&to_hex(&all)).expect("decodes"), all);
    }

    #[test]
    fn the_four_verdicts_parse() {
        assert_eq!(
            parse_answer(&answer("forward", ""), 7, 64).unwrap().verdict,
            Verdict::Forward(None)
        );
        assert_eq!(
            parse_answer(&answer("forward", ",\"data\":\"0b\""), 7, 64)
                .unwrap()
                .verdict,
            Verdict::Forward(Some(vec![0x0b]))
        );
        assert_eq!(
            parse_answer(&answer("reply", ",\"data\":\"0c\""), 7, 64)
                .unwrap()
                .verdict,
            Verdict::Reply(vec![0x0c])
        );
        assert_eq!(
            parse_answer(&answer("deny", ""), 7, 64).unwrap().verdict,
            Verdict::Deny(None)
        );
        assert_eq!(
            parse_answer(&answer("deny", ",\"data\":\"05\""), 7, 64)
                .unwrap()
                .verdict,
            Verdict::Deny(Some(vec![5]))
        );
        assert_eq!(
            parse_answer(&answer("query", ",\"data\":\"0b\""), 7, 64)
                .unwrap()
                .verdict,
            Verdict::Query(vec![0x0b])
        );
    }

    /// The two verdicts whose whole content is the bytes they carry cannot be spelled without
    /// them: silently treating one as a close would answer a request the plugin meant to answer.
    #[test]
    fn reply_and_query_without_data_are_refused() {
        for verdict in ["reply", "query"] {
            let err = parse_answer(&answer(verdict, ""), 7, 64).expect_err("must be refused");
            assert!(err.contains("carries no `data`"), "{err}");
        }
    }

    /// The exchange is strictly one answer per frame. A mismatched sequence means the plugin and
    /// sbx no longer agree on what is being decided, and no guess about it is safe.
    #[test]
    fn an_answer_to_another_frame_is_refused() {
        let err = parse_answer(&answer("forward", ""), 9, 64).expect_err("seq 7 answers seq 9");
        assert!(err.contains("expected 9"), "{err}");
        let err = parse_answer("{\"verdict\":\"forward\"}", 9, 64).expect_err("no seq");
        assert!(err.contains("no `seq`"), "{err}");
    }

    #[test]
    fn an_unknown_verdict_names_the_four_that_exist() {
        let err = parse_answer(&answer("maybe", ""), 7, 64).expect_err("unknown verdict");
        assert!(
            err.contains("forward") && err.contains("reply") && err.contains("deny"),
            "{err}"
        );
    }

    /// A key nothing reads is never a harmless extra in a declaration a machine acts on: a
    /// misspelled `data` accepted in silence would turn a refusal into a bare forward.
    #[test]
    fn an_unknown_field_is_refused_rather_than_ignored() {
        let err = parse_answer(&answer("deny", ",\"dat\":\"05\""), 7, 64)
            .expect_err("a misspelled field is refused");
        assert!(err.contains("unreadable answer"), "{err}");
    }

    #[test]
    fn data_is_bounded_by_the_brokers_own_max_frame() {
        let err = parse_answer(&answer("reply", ",\"data\":\"0b0c0d\""), 7, 2)
            .expect_err("3 bytes into a 2-byte protocol");
        assert!(err.contains("max_frame"), "{err}");
        parse_answer(&answer("reply", ",\"data\":\"0b0c\""), 7, 2).expect("the bound itself fits");
    }

    /// The size is read off the hex, before `from_hex` reserves anything for it. Proved by a
    /// payload that is oversized **and** not hex: refused for its size means the length was read
    /// first; refused for its digits would mean the decode ran and the bound came too late.
    #[test]
    fn an_oversized_frame_is_refused_before_it_is_decoded() {
        let hex = "zz".repeat(100);
        let err = parse_answer(&answer("reply", &format!(",\"data\":\"{hex}\"")), 7, 2)
            .expect_err("100 bytes into a 2-byte protocol");
        assert!(
            err.contains("max_frame"),
            "the bound must be read off the hex, not after decoding it: {err}"
        );
    }

    /// The line bound is derived from this protocol, not borrowed from the signer's: an answer
    /// carries its frame hex-encoded, so a legitimate one at the top of the ceiling is twice
    /// `MAX_FRAME_CEILING` on the wire. A bound set to the signer's `MAX_LINE_BYTES` would refuse
    /// exactly the answers a manifest is allowed to declare.
    #[test]
    fn an_answer_at_the_top_of_the_frame_ceiling_still_reads() {
        let hex = "ab".repeat(MAX_FRAME_CEILING);
        let line = format!("{{\"seq\":7,\"verdict\":\"reply\",\"data\":\"{hex}\"}}\n");
        assert!(
            line.len() > super::super::signer::MAX_LINE_BYTES as usize,
            "the case only bites if the line is past the signer's ceiling"
        );
        let read = read_bounded_line(&mut io::BufReader::new(line.as_bytes()), MAX_ANSWER_LINE)
            .expect("a maximal well-formed answer must read whole");
        assert_eq!(read.len(), line.len());
        let answer = parse_answer(&read, 7, MAX_FRAME_CEILING).expect("and must parse");
        assert!(matches!(answer.verdict, Verdict::Reply(_)));
    }

    /// A line sbx must buffer before it can bound what is inside it. Without a ceiling, a plugin
    /// that never writes a newline takes host memory for as long as the session lives.
    #[test]
    fn an_answer_line_that_never_ends_is_refused_rather_than_buffered() {
        let flood = vec![b'x'; MAX_ANSWER_LINE as usize + 1];
        let err = read_bounded_line(&mut io::BufReader::new(flood.as_slice()), MAX_ANSWER_LINE)
            .expect_err("an unterminated flood is refused");
        assert_eq!(err.kind(), io::ErrorKind::InvalidData, "{err}");

        // The bound is per line, not per session: an ordinary answer after a long one still reads.
        let mut reader = io::BufReader::new(b"first\nsecond\n".as_slice());
        assert_eq!(
            read_bounded_line(&mut reader, MAX_ANSWER_LINE).expect("first"),
            "first\n"
        );
        assert_eq!(
            read_bounded_line(&mut reader, MAX_ANSWER_LINE).expect("second"),
            "second\n"
        );
    }

    #[test]
    fn an_empty_frame_is_refused() {
        let err = parse_answer(&answer("reply", ",\"data\":\"\""), 7, 64).expect_err("empty");
        assert!(err.contains("empty"), "{err}");
    }

    /// A lenient hex decoder would put almost the right bytes on a wire sbx cannot inspect.
    #[test]
    fn malformed_hex_is_refused_with_the_reason() {
        for (hex, needle) in [
            ("0", "odd length"),
            ("0g", "not a hex digit"),
            ("0B", "uppercase"),
        ] {
            let err = parse_answer(&answer("reply", &format!(",\"data\":\"{hex}\"")), 7, 64)
                .expect_err("malformed hex");
            assert!(err.contains(needle), "{hex}: {err}");
        }
    }

    /// A plugin is written in whatever language its author reached for, and those disagree about
    /// line endings: `print()` and `echo` end a line differently from a writer that adds `\r\n`.
    /// Tolerating the trailing whitespace is deliberate, not incidental — the alternative is a
    /// contract that refuses a correct plugin over an invisible byte.
    #[test]
    fn a_line_is_accepted_however_the_plugins_language_ends_it() {
        for tail in ["", "\n", "\r\n", "  \n", "\t"] {
            let line = format!("{}{tail}", answer("forward", ""));
            assert_eq!(
                parse_answer(&line, 7, 64).expect("accepted").verdict,
                Verdict::Forward(None),
                "tail {tail:?}"
            );
        }
        parse_hello_reply("{\"ok\":true}\r\n").expect("the handshake tolerates it too");
    }

    /// sbx must not speak and then never listen: a plugin that cannot broker has to be able to say
    /// so at the one moment nothing is at stake yet.
    #[test]
    fn the_handshake_is_answered_or_the_connection_is_refused() {
        parse_hello_reply("{\"ok\":true}").expect("an acceptance");
        let err = parse_hello_reply("{\"ok\":false,\"error\":\"unsupported version\"}")
            .expect_err("a refusal");
        assert!(err.contains("unsupported version"), "{err}");
        let err = parse_hello_reply("{\"ok\":false}").expect_err("a bare refusal");
        assert!(err.contains("declined to broker"), "{err}");
        for line in ["", "not json", "{}", "{\"ok\":\"yes\"}"] {
            parse_hello_reply(line).expect_err("anything but an acceptance is a refusal");
        }
    }

    /// The label is the plugin's account of its own decision, and an empty one is no account: it
    /// would otherwise put a blank column in the record where a reader expects a reason.
    #[test]
    fn a_label_is_carried_and_an_empty_one_is_not() {
        let a = parse_answer(&answer("deny", ",\"label\":\"no such key\""), 7, 64).unwrap();
        assert_eq!(a.label.as_deref(), Some("no such key"));
        let a = parse_answer(&answer("deny", ",\"label\":\"\""), 7, 64).unwrap();
        assert_eq!(a.label, None);
    }

    /// A connection that opens and says nothing is closed, and a trickle does not buy it time.
    ///
    /// By the time the cage's first frame is waited on, the connection is already holding a plugin
    /// process, a connection to the host resource, a thread and one of the broker's connection
    /// slots. `host_deadline`'s own documentation gives the reason for bounding the other leg in
    /// exactly those terms; the side that says nothing here is the one sbx does not trust.
    ///
    /// Two halves, and the second is the one a socket timeout alone would miss: a timeout bounds
    /// one `read`, so a sender that produces a byte just inside it resets the bound on every byte
    /// and the wait becomes as long as the frame it declared is allowed to be. The trickle below
    /// declares a body it feeds at one byte per interval, which without the budget would hold this
    /// connection for minutes; what it must cost is the deadline.
    #[test]
    fn a_connection_that_says_nothing_is_closed_rather_than_held() {
        let mut spec = spec(None);
        spec.host_deadline = std::time::Duration::from_millis(200);

        for trickle in [false, true] {
            let (cage, theirs) = std::os::unix::net::UnixStream::pair().expect("socketpair");
            // Held for the length of the test in the silent case: a peer that is *dropped* has
            // closed the connection, which is an ordinary ending and not the case under test.
            let mut idle = Some(theirs);
            // The feeder is asked to stop rather than waited out: on a failing run the relay is
            // still holding the connection, so a feeder that only stops when its write fails would
            // never be joinable and the failure would read as a hang.
            let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
            let feeder_stop = std::sync::Arc::clone(&stop);
            let feeding = trickle.then(|| {
                let mut client = idle.take().expect("the peer, handed to the trickle");
                std::thread::spawn(move || {
                    use std::io::Write as _;
                    // A header declaring a body, then the body one byte at a time. Each byte lands
                    // inside the socket timeout, and there are two thousand of them: on a per-read
                    // bound alone this connection would be held for minutes.
                    let _ = client.write_all(&2000u32.to_be_bytes());
                    for _ in 0..2000 {
                        if feeder_stop.load(std::sync::atomic::Ordering::Relaxed)
                            || client.write_all(b"x").is_err()
                        {
                            return;
                        }
                        std::thread::sleep(std::time::Duration::from_millis(150));
                    }
                })
            });

            // Served on a thread so the test asserts on the *bound* rather than inheriting it: a
            // relay that never returns would otherwise hang the suite with nothing to read, where
            // this says which half was lost and moves on.
            let served = spec.clone();
            let (tx, rx) = std::sync::mpsc::channel();
            let relaying = std::thread::spawn(move || {
                let mut plugin = ScriptedPlugin::new(Vec::new());
                let mut host = FakeHost::with(Vec::new());
                let ring = super::super::broker_control::BrokerRing::new(8);
                let out = serve_exchanges(&served, &mut plugin, &mut host, cage, &ring, None, "x");
                let _ = tx.send((out, host.seen));
            });

            let outcome = rx.recv_timeout(std::time::Duration::from_secs(5));
            // Let go of the peer either way, so a relay still parked on it ends and the thread
            // below is joinable rather than leaked into the rest of the suite.
            drop(idle);
            stop.store(true, std::sync::atomic::Ordering::Relaxed);
            if let Some(h) = feeding {
                let _ = h.join();
            }
            let (out, seen) = outcome.unwrap_or_else(|_| {
                panic!("the wait must end on the deadline, not on the sender's schedule (trickle={trickle})")
            });
            let _ = relaying.join();

            let why = out.expect_err("a connection that never speaks must not be served");
            assert!(
                why.contains("said nothing"),
                "the refusal must name what was actually wrong: {why}"
            );
            assert!(seen.is_empty(), "nothing was ever put to the host resource");
        }
    }

    /// A message the protocol answers with nothing does not end the conversation.
    ///
    /// Measured on GnuPG: `PKDECRYPT` makes the agent inquire, and the client then sends its
    /// ciphertext as data lines the agent answers only at the end. Reading the empty verdict as a
    /// closed exchange cut the connection in the middle of every decryption, and the client
    /// reported an end of file where a fence had simply stopped relaying.
    #[test]
    fn a_message_the_protocol_answers_with_nothing_is_followed_by_the_next_one() {
        let spec = spec(None);
        let (cage, theirs) = std::os::unix::net::UnixStream::pair().expect("socketpair");
        // Two frames from the cage: one the host answers with nothing, then one it answers.
        let mut client = theirs;
        write_frame(&mut client, spec.framing, b"data", false).expect("first frame");
        write_frame(&mut client, spec.framing, b"end", false).expect("second frame");
        // Half-closed, so the relay reaches the end of the client's messages rather than blocking
        // on a third that is not coming. The read half stays open to receive what comes back.
        client
            .shutdown(std::net::Shutdown::Write)
            .expect("half-close");

        let mut plugin = ScriptedPlugin::new(vec![
            Answer {
                expect_reply: false,
                ..ScriptedPlugin::forward()
            },
            ScriptedPlugin::forward(),
        ]);
        let mut host = FakeHost::with_runs(vec![vec![], vec![b"answered".to_vec()]]);
        let ring = super::super::broker_control::BrokerRing::new(8);
        serve_exchanges(&spec, &mut plugin, &mut host, cage, &ring, None, "x").expect("served");

        assert_eq!(
            host.seen,
            vec![b"data".to_vec(), b"end".to_vec()],
            "both frames must reach the host: the first one's silence is not an ending"
        );
        let mut back = Vec::new();
        client.read_to_end(&mut back).expect("read what came back");
        let mut cur = std::io::Cursor::new(&back[..]);
        assert_eq!(
            read_frame(&mut cur, spec.framing, 4096, false).unwrap(),
            Some(b"answered".to_vec()),
            "the answer to the second frame must reach the cage"
        );
    }

    /// A broker's socket and the session's record share one `0700` directory, and a plugin name is
    /// whatever a plugin was installed as. Without a namespace of its own, a broker named `control`
    /// would bind the very path `sbx logs --feed broker` connects to — and `start` unlinks before
    /// it binds, so it would take the record's place and answer a reader in it.
    #[test]
    fn a_brokers_socket_can_never_be_the_one_a_reader_connects_to() {
        let data = std::path::Path::new("/data");
        let lens = super::super::broker_control::broker_control_socket(data, 4242);
        assert_eq!(
            lens,
            data.join("broker/control-4242.sock"),
            "the reader's end"
        );
        for name in ["gpg-agent", "control", "control-4242.sock"] {
            let socket = host_socket(data, name, 4242);
            assert_ne!(
                socket, lens,
                "a broker named `{name}` must not name the record's socket"
            );
            assert_eq!(
                socket.parent(),
                Some(sockets_dir(data, 4242).as_path()),
                "and it lives in the launch's own directory, which the sweep can read: {socket:?}"
            );
        }
    }

    /// A protocol whose clients compute the socket path is stood at the address of the resource it
    /// fences — the only placement a GnuPG client can find, since it derives the path from the uid
    /// and the home rather than reading any variable.
    #[test]
    fn a_broker_stands_where_its_protocols_clients_look_for_it() {
        let mut spec = crate::plugins::broker::BrokerSpec {
            host_deadline: crate::plugins::broker::DEFAULT_HOST_DEADLINE,
            cage_env: Vec::new(),
            cage_env_dir: Vec::new(),
            socket_name: "gpg-agent.sock".to_string(),
            framing: crate::plugins::broker::Framing::Line,
            max_frame: 2048,
            deny_frame: None,
            uses_secret: false,
            host_greets: true,
            inspect_replies: true,
            at_host_path: true,
        };
        let unix = crate::config::BrokerTarget::Unix(std::path::PathBuf::from(
            "/run/user/1000/gnupg/S.gpg-agent",
        ));
        assert_eq!(
            cage_socket("gpg-agent", &spec, &unix),
            (
                "/run/user/1000/gnupg".to_string(),
                "/run/user/1000/gnupg/S.gpg-agent".to_string()
            )
        );

        // Without the declaration, sbx's own namespace — which is where every broker stood before
        // this existed, and where one whose clients are told the path still stands.
        spec.at_host_path = false;
        assert_eq!(
            cage_socket("gpg-agent", &spec, &unix),
            (
                "/tmp/sbx-broker-gpg-agent".to_string(),
                "/tmp/sbx-broker-gpg-agent/gpg-agent.sock".to_string()
            )
        );
    }
}
