//! The WebSocket frame decoder the relay drives: framing, `permessage-deflate` inflation, the
//! capture tee and the outbound-secret tripwire.
//!
//! [`super::websocket`] relays an established upgrade as an opaque byte stream and never has to
//! understand a frame to forward one. Two things do. The `--with-body` transcript must store what
//! the sender actually sent rather than the masked — and possibly compressed — bytes that cross,
//! and the leak tripwire must see a declared secret whichever frame carries it. Both read the same
//! decode, so the decode is done once, here, and the relay drives it through [`FrameTee`] without
//! parsing anything itself.

use std::sync::Arc;

use miniz_oxide::inflate::TINFLStatus;
use miniz_oxide::inflate::core::inflate_flags::{
    TINFL_FLAG_HAS_MORE_INPUT, TINFL_FLAG_IGNORE_ADLER32,
};
use miniz_oxide::inflate::core::{DecompressorOxide, TINFL_LZ_DICT_SIZE, decompress};

use super::capture::CapBuf;
use super::inject::SecretNeedle;

/// The traffic capture's decoder for one direction of an established WebSocket: it follows the frame
/// framing as the bytes are relayed and copies each data frame's payload into a capped sink.
///
/// Decoding is forced by the protocol, not a presentation choice. A payload is preceded by a
/// variable-length header, and a frame the client sends is XOR-masked with a per-frame key, so the
/// bytes as they cross are not readable as themselves; unmasking recovers exactly what the sender
/// sent, nothing more. (RFC 6455 masking exists to stop intermediaries being tricked into cache
/// poisoning; it carries no confidentiality, so undoing it reveals nothing that was protected.)
///
/// When `permessage-deflate` is negotiated the payloads are DEFLATE-compressed per *message*, one
/// stream across the message's frames, which is inflated as each frame's bytes arrive; see
/// [`Inflater`]. Control frames (close, ping, pong) are not part of the message transcript, so
/// nothing they carry is captured, and they may interleave a fragmented message without disturbing
/// its decoding. They are still **scanned**, though: RFC 6455 §5.5.2 and §5.5.3 both allow a ping
/// and a pong to carry "Application data" and close carries a reason, so up to 125 bytes a frame
/// are whatever the cage put there — skipping them outright, as this once did, left a channel past
/// the outbound-secret tripwire that needed no reassembly and no compression to use.
pub(super) struct FrameTee {
    /// The capture's sink, when the launch captures bodies.
    sink: Option<Arc<CapBuf>>,
    /// Whether the sink has already reported itself full. It is asked once: a filled sink keeps
    /// answering "full", and re-reporting it would re-emit the tunnel's transcript on every later
    /// read instead of the one time that fact is news.
    sink_full: bool,
    /// The leak tripwire, when the launch has any secret configured. It never fills, so a tunnel
    /// that scans keeps following the framing after the capture stops.
    scan: Option<LeakScan>,
    /// Whether this direction is followed for a scan it does not have yet — the posture the caller
    /// passed to [`Self::new`]. It outlives construction because the two questions asked of a
    /// stopped decoder both turn on it: a direction kept alive for a needle the cage has not
    /// acquired must not end when the capture fills ([`Self::spent`]), and if it does stop the
    /// relay has to be told ([`Self::newly_blinded`]) even though no scan was ever attached.
    follow_anyway: bool,
    /// The header of the frame being decoded. It can arrive split across reads, and is bounded: a
    /// WebSocket frame header is at most 14 bytes.
    header: Vec<u8>,
    /// What is left of the current frame's payload, and how this frame is to be treated.
    payload_left: u64,
    keeps: bool,
    /// Whether the frame being decoded is a control frame, whose payload is scanned but never
    /// captured — see [`Self::control_payload`].
    control: bool,
    /// The current control frame's payload, gathered so it can be scanned whole.
    ///
    /// Gathered rather than scanned piecewise because a frame can arrive split across reads and a
    /// value straddling the split would otherwise be missed, and kept apart from [`Self::plain`]
    /// because a control frame may interleave a fragmented message that is using that buffer. It is
    /// bounded by [`CONTROL_MAX`], so nothing here grows on a length the cage picked — a second line
    /// behind [`scan_frame_header`], which refuses an over-125 control frame outright.
    control_payload: Vec<u8>,
    mask: Option<[u8; 4]>,
    /// Where in the 4-byte mask key the next payload byte lands, carried across reads.
    mask_at: u8,
    /// Set once the sink is full or the framing stopped making sense; from then on this direction
    /// costs nothing at all.
    done: bool,
    /// Whether [`Self::newly_blinded`] has already told the relay that the scan stopped. Asked once,
    /// like a sighting: the fact is news the first time and noise on every read after it.
    blind_reported: bool,
    /// This direction's decompressor, present only when `permessage-deflate` was negotiated.
    inflater: Option<Inflater>,
    /// What the capture keeps of the compressed message in flight, filed when the message ends: up
    /// to one byte past the capture's cap, so a message that overflows it is seen to, and nothing
    /// without a capture. Held rather than filed as it is inflated, so that a message that turns
    /// out not to decode leaves nothing of itself in the transcript.
    plain: Vec<u8>,
    /// Whether the message currently being decoded is compressed (`RSV1` on its first frame). A
    /// continuation frame inherits it, so it is tracked per message rather than per frame.
    compressed: bool,
    /// Whether the data frame being decoded ends its message.
    fin: bool,
}

/// The most payload one control frame can carry, from RFC 6455 §5.5: "All control frames MUST have
/// a payload length of 125 bytes or less".
///
/// It is read twice, on the two questions a declared length raises. [`scan_frame_header`] refuses a
/// control frame that declares more: the framing is then not what it claims, and following the
/// declared length would let a fourteen-byte header swallow the rest of the tunnel. And it bounds
/// [`FrameTee::control_payload`], so what is *gathered* follows the protocol's limit rather than the
/// length the sender wrote, whatever else changes above it.
const CONTROL_MAX: usize = 125;

/// The leak tripwire for one direction of an established WebSocket.
///
/// Unlike the two HTTP tripwires this one **never mutates**. An open tunnel is a byte-exact pipe
/// between two peers that agreed their own framing, masking and compression; rewriting a payload in
/// flight would mean re-framing and re-masking the stream around it, on the one path that has to
/// stay exact. So a sighting produces a note on the tunnel's own log event: the bytes still cross
/// as they were sent, and the user is told that they did.
///
/// Scanning is per **message**, not per stream. A message is one application payload, so a value
/// split across two of them is two payloads — which a byte-exact scan does not claim to catch, no
/// more than it catches a re-encoded one. Within a message the pieces are contiguous, so a carry of
/// `max_len - 1` bytes spans the frame and read boundaries inside it.
///
/// Each needle is reported once per direction: a credential that keeps crossing says nothing new
/// after the first time, and repeating it would turn an alarm into noise.
struct LeakScan {
    needles: Vec<SecretNeedle>,
    /// The tail of the message being scanned, so a value straddling two pieces is still matched.
    carry: Vec<u8>,
    /// How much tail to keep: one byte short of the longest needle, the most that can be the start
    /// of a match completed by the next piece.
    keep: usize,
    /// Which needles have already been reported for this direction.
    reported: Vec<bool>,
    /// Names seen since the caller last drained them. A name is a label, never the value.
    fresh: Vec<String>,
}

impl LeakScan {
    /// A scanner for `needles`, or `None` when there is nothing to look for. The needles are the
    /// already-screened set (a value below the redaction floor never becomes one), so the false
    /// positives that floor exists to prevent cannot reach here either.
    fn new(needles: &[SecretNeedle]) -> Option<Self> {
        if needles.is_empty() {
            return None;
        }
        let keep = needles
            .iter()
            .map(|n| n.as_bytes().len())
            .max()
            .unwrap_or(0)
            .saturating_sub(1);
        Some(LeakScan {
            needles: needles.to_vec(),
            carry: Vec::with_capacity(keep),
            keep,
            reported: vec![false; needles.len()],
            fresh: Vec::new(),
        })
    }

    /// Take on needles the launch learned after this scanner was built.
    ///
    /// Additive, and that is the property rather than a simplification. A tunnel outlives the
    /// request that opened it, so the shared set both grows (the cage signs in somewhere and the
    /// value is remembered) and turns over (the learned population evicts its oldest). Dropping a
    /// needle here on the second would take back a value this direction was already watching for,
    /// on a stream where the watching is the whole control; keeping it costs one finder over
    /// bytes that are being scanned anyway.
    ///
    /// What it cannot do is see backwards. A value that had already begun crossing when this ran
    /// is matched only from the piece the scan is handed next, which is the same limit any needle
    /// has: the scan is per message and starts where it starts.
    fn extend(&mut self, needles: &[SecretNeedle]) {
        for needle in needles {
            if self
                .needles
                .iter()
                .any(|held| held.as_bytes() == needle.as_bytes())
            {
                continue;
            }
            self.keep = self.keep.max(needle.as_bytes().len().saturating_sub(1));
            self.needles.push(needle.clone());
            self.reported.push(false);
        }
    }

    /// A new application message begins: nothing carries across it.
    fn start_message(&mut self) {
        self.carry.clear();
    }

    /// Scan a payload that stands on its own — a control frame's, which RFC 6455 §5.4 forbids
    /// fragmenting — without disturbing the carry of the message it may be sitting between.
    ///
    /// The carry is set aside and put back rather than cleared, because a control frame is allowed
    /// to interleave a fragmented message: clearing it would let a ping sent between two halves of a
    /// secret hide the secret, which is the hole this exists to close wearing a different hat.
    fn take_standalone(&mut self, piece: &[u8]) {
        let held = std::mem::take(&mut self.carry);
        self.take(piece);
        self.carry = held;
    }

    /// Scan one decoded piece of the current message.
    fn take(&mut self, piece: &[u8]) {
        if self.reported.iter().all(|seen| *seen) {
            // Every configured value has already been reported for this direction; there is nothing
            // left this scan could learn, so it stops costing anything.
            return;
        }
        self.carry.extend_from_slice(piece);
        let hits: Vec<usize> = (0..self.needles.len())
            .filter(|&i| !self.reported[i] && self.needles[i].find_in(&self.carry, 0).is_some())
            .collect();
        for i in hits {
            self.reported[i] = true;
            self.fresh.push(self.needles[i].name().to_string());
        }
        let drop = self.carry.len().saturating_sub(self.keep);
        self.carry.drain(..drop);
    }

    /// Take the names seen since the last call, for the caller to report.
    fn drain(&mut self) -> Vec<String> {
        std::mem::take(&mut self.fresh)
    }
}

/// One direction's `permessage-deflate` decompressor.
///
/// Two details of RFC 7692 matter and are easy to get wrong. A message's payload is a raw DEFLATE
/// stream whose final empty block is elided, so the four bytes `00 00 FF FF` are fed in after its
/// last frame ([`Self::finish`]). And unless the peer announced `*_no_context_takeover`, the
/// compression window carries across messages: the state must persist, or every message after the
/// first inflates to garbage.
///
/// A message is inflated as its bytes arrive ([`Self::feed`]), not once it is whole. A frame is a
/// stretch of the message's one stream, which the decoder takes up where the frame before it
/// stopped, mid-symbol if that is where it stopped, so what a frame carries is read before the
/// relay writes the frame on, as an uncompressed frame's payload is. Inflated only once whole, a
/// message had every frame but its last relayed before any of it was read.
struct Inflater {
    /// The DEFLATE decoder's state between one stretch and the next.
    decoder: Box<DecompressorOxide>,
    /// The decoder's window: the last 32 KiB it produced, which a back-reference reads, and where
    /// it writes what it decodes next. It is the whole of what a message costs in memory, however
    /// far it inflates.
    window: Box<[u8]>,
    /// Where in [`Self::window`] the next decoded byte lands.
    at: usize,
    /// Whether the peer resets its window per message, in which case so must this.
    no_context_takeover: bool,
    /// The most plaintext one message may inflate to, from [`MESSAGE_PLAINTEXT_CAP`].
    ///
    /// A field rather than the constant read straight from the function, so a test can reach the
    /// limit without inflating sixty-four megabytes to get there. Production has exactly one value
    /// for it.
    message_cap: usize,
    /// What the message in flight has inflated to so far.
    inflated: usize,
}

/// Why a compressed message's inflate stopped before its end. Either way the decoder is out of
/// step with the peer's compressor, and the direction stops rather than decode the rest wrongly.
enum Stop {
    /// Its bytes are not a DEFLATE stream this decoder can follow.
    Undecodable,
    /// It inflated past [`MESSAGE_PLAINTEXT_CAP`].
    TooLong,
}

impl Inflater {
    fn new(no_context_takeover: bool) -> Self {
        Inflater {
            decoder: Box::default(),
            window: vec![0u8; TINFL_LZ_DICT_SIZE].into_boxed_slice(),
            at: 0,
            no_context_takeover,
            message_cap: MESSAGE_PLAINTEXT_CAP,
            inflated: 0,
        }
    }

    /// A message begins: what it inflates to is counted from nothing.
    fn start(&mut self) {
        self.inflated = 0;
    }

    /// Inflate `rest`, the next stretch of the message in flight, handing every byte it yields to
    /// `plaintext` in stream order, the order the scan's carry across pieces relies on.
    ///
    /// Driven through the decoder itself rather than `miniz_oxide`'s stream wrapper, whose window
    /// is the same one, for what the wrapper did with it. It copied what a call decoded into the
    /// caller's buffer only as far as that buffer held, kept the rest back, and answered every call
    /// after a fault with the fault, so the rest never came out. A stretch that decoded more than
    /// the buffer before a corrupt byte lost the end of what it decoded, a secret included, while
    /// the same bytes cut finer handed all of it on. Here the window is the output: whatever a call
    /// decoded is handed on before its status is read, so what the scan reads up to a fault
    /// depends on the stream and not on how it was cut.
    fn feed(&mut self, mut rest: &[u8], plaintext: &mut impl FnMut(&[u8])) -> Result<(), Stop> {
        loop {
            let (status, consumed, written) = decompress(
                &mut self.decoder,
                rest,
                &mut self.window,
                self.at,
                TINFL_FLAG_HAS_MORE_INPUT | TINFL_FLAG_IGNORE_ADLER32,
            );
            rest = &rest[consumed..];
            plaintext(&self.window[self.at..self.at + written]);
            self.at = (self.at + written) & (TINFL_LZ_DICT_SIZE - 1);
            self.inflated = self.inflated.saturating_add(written);
            let ends = match status {
                // The window's end was reached with output still to come, a back-reference going
                // on unrolling after the few bits naming it were read: on from the window's start.
                TINFLStatus::HasMoreOutput => false,
                // The stretch is spent and everything it decodes to is out.
                TINFLStatus::NeedsMoreInput => true,
                // A final block, as a peer may send one, ends the stream: with nothing behind it in
                // the stretch, that is where it ends.
                TINFLStatus::Done | TINFLStatus::FailedCannotMakeProgress if rest.is_empty() => {
                    true
                }
                // Bytes that do not decode, or bytes behind the stream's end: what came before them
                // is already handed on.
                _ => return Err(Stop::Undecodable),
            };
            if self.inflated > self.message_cap {
                return Err(Stop::TooLong);
            }
            if ends {
                return Ok(());
            }
            if consumed == 0 && written == 0 {
                return Err(Stop::Undecodable);
            }
        }
    }

    /// The message's last frame is in: feed the empty block its sender elided, which brings out
    /// what the decoder still held back, and start the window afresh where the peer does, as
    /// `miniz_oxide`'s full reset does: the decoder new, the window zeroed, writing from its start.
    fn finish(&mut self, plaintext: &mut impl FnMut(&[u8])) -> Result<(), Stop> {
        let ended = self.feed(&[0x00, 0x00, 0xff, 0xff], plaintext);
        if self.no_context_takeover {
            *self.decoder = DecompressorOxide::new();
            self.window.fill(0);
            self.at = 0;
        }
        ended
    }
}

/// The most plaintext one compressed message is inflated to.
///
/// Inflating is the only way to read a message, and the only way to keep this direction's window
/// level with the peer's: under context takeover, the default, since `no_context_takeover` has to
/// be announced, one window carries across a direction's messages, and a message left partly
/// inflated leaves every later one decoding to rubbish, which is a scan the cage switches off at
/// will. There is no shortcut past a message's bytes, so the bound is on work rather than memory
/// ([`Inflater::window`] is the one buffer, reused). It is set far above any message a real peer sends
/// and far below what one could be made to cost: DEFLATE's ratio tops out near 1000:1, so a few
/// megabytes on the wire could otherwise ask for gigabytes of inflate. A message past it stops the
/// direction, the answer a message that does not decode gets too.
const MESSAGE_PLAINTEXT_CAP: usize = 64 * 1024 * 1024;

/// What the peers agreed for `permessage-deflate`, read off the upgrade response. Absent means the
/// extension was not negotiated and payloads cross uncompressed.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(super) struct Deflate {
    pub(super) negotiated: bool,
    /// Whether the *client* resets its window per message — governs the cage → upstream direction.
    pub(super) client_no_context_takeover: bool,
    /// Whether the *server* does — governs the upstream → cage direction.
    pub(super) server_no_context_takeover: bool,
}

/// Read the negotiated `permessage-deflate` parameters off an upgrade response head.
///
/// Only the response decides: the client may offer the extension and the server decline it, in which
/// case nothing is compressed. A response naming any other extension — first, last, or beside
/// `permessage-deflate` — is not something this decoder can follow, so it reports nothing negotiated
/// and the payloads are captured as they cross.
///
/// That is a whole-list rule, not a search for the deflate entry: extensions negotiated on one
/// stream compose, each transforming what the next one sees (RFC 6455 §9.1), so an unknown entry
/// sits between the framing and the DEFLATE stream this would otherwise inflate. Picking the deflate
/// entry out of the list and inflating past the unknown one — which this did — decodes whatever that
/// other extension left behind, and files it as the message's text. Reporting nothing negotiated
/// keeps the payload as it crossed: honest about not knowing, where a wrong inflate is not.
///
/// The list is the whole list, and a response may split it over several `Sec-WebSocket-Extensions`
/// fields: every one of them is read, so an entry named in a later field is not a way past the rule.
/// An empty element is no entry at all, as RFC 9110 §5.6.1 has a recipient read one: a client
/// that reads the list that way compresses under `permessage-deflate,`, and taking the empty
/// element for an extension this cannot follow left the scan reading DEFLATE bytes for text.
///
/// Where this and a peer could read the list apart, the reading leans towards "negotiated", which
/// is why an element loses every blank around it rather than only the spaces and tabs a peer takes
/// off. A decoder that expects compression where the peers agreed none costs nothing, since an
/// honest peer then sets no `RSV1`; one that misses it scans compressed bytes and finds nothing.
pub(super) fn negotiated_deflate(resp_head: &[u8]) -> Deflate {
    let head = String::from_utf8_lossy(resp_head);
    let values: Vec<&str> = head
        .lines()
        .filter_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.trim()
                .eq_ignore_ascii_case("sec-websocket-extensions")
                .then(|| value.trim())
        })
        .collect();
    if values.is_empty() {
        return Deflate::default();
    }
    // One negotiated extension per comma-separated entry, and every one of them has to be the
    // deflate entry — see the doc above for why an entry beside it is not skipped past.
    let mut negotiated: Option<Deflate> = None;
    for entry in values.iter().flat_map(|value| value.split(',')) {
        if entry.trim().is_empty() {
            continue;
        }
        let mut params = entry.split(';').map(str::trim);
        if !params
            .next()
            .is_some_and(|n| n.eq_ignore_ascii_case("permessage-deflate"))
        {
            return Deflate::default();
        }
        if negotiated.is_some() {
            // The same extension negotiated twice is no more followable: there is one window per
            // direction and this response asks for two sets of parameters over it.
            return Deflate::default();
        }
        let mut out = Deflate {
            negotiated: true,
            ..Default::default()
        };
        for param in params {
            let key = param.split('=').next().unwrap_or_default().trim();
            if key.eq_ignore_ascii_case("client_no_context_takeover") {
                out.client_no_context_takeover = true;
            } else if key.eq_ignore_ascii_case("server_no_context_takeover") {
                out.server_no_context_takeover = true;
            }
        }
        negotiated = Some(out);
    }
    negotiated.unwrap_or_default()
}

/// What one pass over the header bytes so far concluded.
enum HeaderScan {
    /// Not enough bytes yet to know the header's length.
    Need,
    /// Not a frame header this decoder can follow. The direction stops being captured rather than
    /// being reported as something it is not.
    Bad,
    Done {
        payload_len: u64,
        /// Whether this frame carries application data (so its payload is captured).
        keeps: bool,
        /// Whether this is a control frame (close, ping, pong). Its payload is not part of the
        /// message transcript, so it is never captured — but it is still bytes the cage chose, so
        /// it is still scanned. See [`FrameTee::control_payload`].
        control: bool,
        mask: Option<[u8; 4]>,
        /// Whether this frame ends its message.
        fin: bool,
        /// `RSV1`, which on a message's first frame means its payload is compressed.
        rsv1: bool,
        /// Whether this frame opens a message (a text or binary opcode) rather than continuing one.
        starts_message: bool,
    },
}

impl FrameTee {
    /// A decoder feeding whichever consumers this launch has: the capture's `sink`, the leak scan
    /// over `needles`, or both. `deflate` carries the negotiated compression for this direction:
    /// `None` when the extension was not agreed, so nothing is inflated.
    ///
    /// Returns `None` when neither consumer is present, so a tunnel that neither captures nor scans
    /// is relayed without the framing being followed at all.
    ///
    /// `follow_anyway` overrides that, and it exists because a decoder cannot join a stream it did
    /// not start with: a chunk boundary is not a frame boundary, so a direction relayed as a plain
    /// pipe stays one for the life of the tunnel however the launch's needle set later grows. On a
    /// tunnel that will never have a needle that costs nothing and buys nothing; under
    /// [`crate::allowlist::WebsocketSecret::Block`], where the scan is what the posture promises,
    /// it is the difference between the promise holding for a credential the cage acquires after
    /// the `101` and not holding at all. The caller passes the posture, so the default one keeps
    /// its plain pipe.
    pub(super) fn new(
        sink: Option<Arc<CapBuf>>,
        needles: &[SecretNeedle],
        deflate: Option<bool>,
        follow_anyway: bool,
    ) -> Option<Self> {
        let scan = LeakScan::new(needles);
        if sink.is_none() && scan.is_none() && !follow_anyway {
            return None;
        }
        Some(FrameTee {
            sink,
            sink_full: false,
            scan,
            follow_anyway,
            header: Vec::with_capacity(14),
            payload_left: 0,
            keeps: false,
            control: false,
            control_payload: Vec::new(),
            mask: None,
            mask_at: 0,
            done: false,
            blind_reported: false,
            inflater: deflate.map(Inflater::new),
            plain: Vec::new(),
            compressed: false,
            fin: false,
        })
    }

    /// Take on the needle set as it stands now, for a direction that is already running.
    ///
    /// The request planes read the shared set once per request, so each request is watched with
    /// what the launch knows by then. A tunnel has one read for its whole life, which on the one
    /// transport built to stay open for hours means it watches for the values that existed at the
    /// `101` and for nothing learned since: exactly the credential an agent acquires and then
    /// exfiltrates. This is that read, repeated.
    ///
    /// A direction that had nothing to look for gains a scan here. One whose decoder has already
    /// stopped ([`Self::done`]) gains nothing, because there is no longer a stream to scan.
    pub(super) fn refresh_needles(&mut self, needles: &[SecretNeedle]) {
        if self.done {
            return;
        }
        match self.scan.as_mut() {
            Some(scan) => scan.extend(needles),
            None => self.scan = LeakScan::new(needles),
        }
    }

    /// Hand one decoded piece to whichever consumers are present, and report whether the capture
    /// sink filled **on this piece** — asked once, so a full sink cannot re-trigger on every later
    /// read. The scan sees the same piece whether or not the capture is still taking bytes: what is
    /// retained for a human to read and what is watched for a leak are different questions.
    fn consume(&mut self, piece: &[u8]) -> bool {
        if let Some(scan) = self.scan.as_mut() {
            scan.take(piece);
        }
        self.capture(piece)
    }

    /// Push one decoded piece to the capture sink alone, for a path that has already scanned it.
    ///
    /// The compressed path is that caller: its scan is fed as the inflater yields, piece by piece,
    /// and what the capture keeps is filed when the message ends. Scanning here as well would hand
    /// the scan the kept prefix twice, out of order with what it already saw, and the carry that
    /// matches a value straddling two pieces is exactly what that would corrupt.
    fn capture(&mut self, piece: &[u8]) -> bool {
        if self.sink_full {
            return false;
        }
        match self.sink.as_ref() {
            Some(sink) if sink.push(piece) => {
                self.sink_full = true;
                true
            }
            _ => false,
        }
    }

    /// Names this direction has newly seen crossing it, for the caller to report. Empty on all but
    /// the few passes where a configured value is first spotted.
    pub(super) fn sightings(&mut self) -> Vec<String> {
        self.scan.as_mut().map(LeakScan::drain).unwrap_or_default()
    }

    /// Whether nothing further can be learned from this direction, so the decoder may stop: the
    /// capture is full, there is no scan to keep going for, and none is expected — a direction the
    /// caller asked to follow anyway is being held open for a needle the launch does not have yet
    /// ([`Self::new`]), and ending it at the capture's cap would put the framing out of reach
    /// before [`Self::refresh_needles`] could ever attach that scan.
    fn spent(&self) -> bool {
        self.sink_full && self.scan.is_none() && !self.follow_anyway
    }

    /// Whether this direction's leak tripwire has *just* gone blind: the decoder gave up on the
    /// framing while a scan was configured — or while one was still expected, on a direction the
    /// caller asked to follow anyway — so nothing crossing from here on is watched.
    ///
    /// Reported once, like a sighting.
    ///
    /// [`Self::done`] is the right answer for the capture, whose transcript honestly ends at the last
    /// message it decoded — but it is not an answer for the scan. A decoder that stops mid-tunnel
    /// leaves every later byte unwatched, a control the cage switches off at will with one message
    /// the decoder cannot follow: one past [`MESSAGE_PLAINTEXT_CAP`], or one that does not decode.
    /// `done` is invisible outside the tee, so without this `follow` reports no sighting, the relay
    /// keeps forwarding, and `websocket_secret = block` never fires again on that tunnel. Reporting
    /// it lets the relay treat a blinded direction as what it is.
    ///
    /// An empty needle set is not the same as no tripwire. Under [`crate::allowlist::WebsocketSecret::Block`]
    /// the caller follows a direction that has nothing to look for yet precisely so it can look
    /// later, so a decoder that stops there loses a tripwire just as surely as one that was already
    /// scanning — and loses it for good, since [`Self::refresh_needles`] cannot attach a scan to a
    /// stopped decoder. Only a capture-only tee, which has no tripwire to lose, stays silent.
    pub(super) fn newly_blinded(&mut self) -> bool {
        if !self.done || (self.scan.is_none() && !self.follow_anyway) || self.blind_reported {
            return false;
        }
        self.blind_reported = true;
        true
    }

    /// Follow `chunk` through the framing, capturing what it carries. Returns whether the sink filled
    /// on this pass — the moment worth showing a long-lived tunnel's transcript, since nothing more
    /// will be captured for this direction.
    pub(super) fn push(&mut self, chunk: &[u8]) -> bool {
        if self.done {
            return false;
        }
        // Accumulated rather than returned on the spot: a filled capture sink no longer ends the
        // decode, because a scan may still want the rest of this chunk.
        let mut filled = false;
        // Scratch for the masked direction, reused across every frame of this read — see the
        // payload branch below for why only one direction needs it.
        let mut unmasked: Vec<u8> = Vec::new();
        let mut at = 0;
        while at < chunk.len() {
            if self.payload_left == 0 {
                self.header.push(chunk[at]);
                at += 1;
                match scan_frame_header(&self.header) {
                    HeaderScan::Need => continue,
                    HeaderScan::Bad => {
                        self.done = true;
                        break;
                    }
                    HeaderScan::Done {
                        payload_len,
                        keeps,
                        control,
                        mask,
                        fin,
                        rsv1,
                        starts_message,
                    } => {
                        // A new message begun in the midst of a compressed one (RFC 6455 §5.4
                        // forbids it) leaves the decoder partway through a DEFLATE stream the peer
                        // has walked away from, and what the new message's bytes mean to a decoder
                        // in that state is anyone's guess. The direction stops there, which
                        // [`Self::newly_blinded`] reports. The frames of the message were read as
                        // they came, and a control frame may sit between two of them, a close
                        // included.
                        if self.compressed && !self.fin && starts_message {
                            self.done = true;
                            break;
                        }
                        self.payload_left = payload_len;
                        self.keeps = keeps;
                        self.control = control;
                        self.control_payload.clear();
                        self.mask = mask;
                        self.mask_at = 0;
                        self.header.clear();
                        if keeps {
                            self.fin = fin;
                            if starts_message {
                                if rsv1 && self.inflater.is_none() {
                                    // A compressed message where this decoder has no compression
                                    // to follow: the peers agreed on an encoding the upgrade
                                    // response did not show it (RFC 6455 §5.2 has a peer fail the
                                    // connection otherwise). Its payload is not the text it
                                    // carries, so capturing it files noise and scanning it finds
                                    // nothing. Stopping says so ([`Self::newly_blinded`]), where
                                    // reading on would say nothing.
                                    self.done = true;
                                    break;
                                }
                                // A new message: whether it is compressed is decided here and
                                // inherited by its continuation frames, and nothing carries across
                                // the boundary for the scan.
                                self.compressed = rsv1;
                                self.plain.clear();
                                if let Some(inflater) = self.inflater.as_mut() {
                                    inflater.start();
                                }
                                if let Some(scan) = self.scan.as_mut() {
                                    scan.start_message();
                                }
                            }
                        }
                    }
                }
                // A zero-length frame carries no payload to consume, so its end is here.
                if self.payload_left == 0 {
                    filled |= self.end_of_frame();
                }
                if self.done {
                    break;
                }
                continue;
            }
            let take = self.payload_left.min((chunk.len() - at) as u64) as usize;
            if self.keeps || (self.control && self.scan.is_some()) {
                // The payload as its sender wrote it. The copy this made of every piece existed
                // only to give the unmask loop somewhere to write, and a frame carrying no mask key
                // has nothing to undo — RFC 6455 §5.3 masks one direction of a tunnel, so the
                // direction carrying a streamed response was copying every byte for nothing. A frame
                // that does carry a key is unmasked into a buffer reused for the whole read, which
                // is one allocation where there was one per frame. The key is read off the frame
                // header either way, so a peer that masks when it should not is still handled.
                let piece: &[u8] = match self.mask {
                    None => &chunk[at..at + take],
                    Some(key) => {
                        unmasked.clear();
                        unmasked.extend_from_slice(&chunk[at..at + take]);
                        for (n, byte) in unmasked.iter_mut().enumerate() {
                            *byte ^= key[(self.mask_at as usize + n) % 4];
                        }
                        &unmasked
                    }
                };
                if self.control {
                    // A control frame's payload is application data the cage chose (RFC 6455 §5.5.2
                    // and §5.5.3 both allow one), so the scan reads it — but it is not part of the
                    // message transcript, so the capture never sees it. Gathered to the frame's end
                    // rather than scanned as it arrives, so a value split across two reads is still
                    // matched. The bound is redundant with the header check that refuses an over-125
                    // control frame, and kept: the buffer must not grow on a length the cage picked,
                    // whatever else changes above it.
                    let room = CONTROL_MAX.saturating_sub(self.control_payload.len());
                    let fits = piece.len().min(room);
                    self.control_payload.extend_from_slice(&piece[..fits]);
                } else if self.compressed {
                    // Inflated as it arrives, so the scan reads this piece before the relay writes
                    // it on, as it reads an uncompressed one.
                    if let Err(stop) = self.inflate(Some(piece)) {
                        filled |= self.give_up(stop);
                        break;
                    }
                } else {
                    filled |= self.consume(piece);
                    if self.spent() {
                        self.done = true;
                    }
                }
            }
            self.mask_at = ((self.mask_at as usize + take) % 4) as u8;
            self.payload_left -= take as u64;
            at += take;
            if self.payload_left == 0 {
                filled |= self.end_of_frame();
            }
            if self.done {
                break;
            }
        }
        filled
    }

    /// Inflate `piece`, the next stretch of the compressed message in flight, or, given none, the
    /// end its sender elided ([`Inflater::finish`]). The scan reads every byte it yields, whatever
    /// the capture keeps of them, and [`Self::plain`] keeps what the capture can use.
    fn inflate(&mut self, piece: Option<&[u8]>) -> Result<(), Stop> {
        let keep = match &self.sink {
            Some(sink) if !self.sink_full => sink.cap().saturating_add(1),
            _ => 0,
        };
        // `push` stops a direction whose message opens compressed with no compression to follow.
        let Some(inflater) = self.inflater.as_mut() else {
            return Err(Stop::Undecodable);
        };
        let (scan, plain) = (&mut self.scan, &mut self.plain);
        let mut yielded = |block: &[u8]| {
            if let Some(scan) = scan.as_mut() {
                scan.take(block);
            }
            let room = keep.saturating_sub(plain.len());
            plain.extend_from_slice(&block[..block.len().min(room)]);
        };
        match piece {
            Some(piece) => inflater.feed(piece, &mut yielded),
            None => inflater.finish(&mut yielded),
        }
    }

    /// Stop this direction on a compressed message whose inflate stopped short, and file what the
    /// capture kept of it where that is the message's text. Returns whether the sink filled.
    fn give_up(&mut self, stop: Stop) -> bool {
        self.done = true;
        let plain = std::mem::take(&mut self.plain);
        match stop {
            // Every byte kept decoded before the bound was reached, so it is the message's own.
            Stop::TooLong => self.capture(&plain),
            // Bytes that do not decode can yield some before they fail, and those are a guess: the
            // transcript ends at the last message that decoded.
            Stop::Undecodable => false,
        }
    }

    /// Settle a frame that has just ended. A compressed message's capture is filed only now, on its
    /// final frame. Returns whether the sink filled.
    fn end_of_frame(&mut self) -> bool {
        if self.control {
            // The frame is whole, so its payload can be scanned as the self-contained thing it is
            // (§5.4 forbids fragmenting a control frame) — and without clearing the carry of the
            // message it may be interleaving, which is what `take_standalone` is for.
            let payload = std::mem::take(&mut self.control_payload);
            if let Some(scan) = self.scan.as_mut() {
                scan.take_standalone(&payload);
            }
            return false;
        }
        if !self.keeps || !self.compressed || !self.fin {
            return false;
        }
        if let Err(stop) = self.inflate(None) {
            return self.give_up(stop);
        }
        let plain = std::mem::take(&mut self.plain);
        let filled = self.capture(&plain);
        if self.spent() {
            self.done = true;
        }
        filled
    }
}

/// Read a WebSocket frame header out of the bytes gathered so far.
fn scan_frame_header(buf: &[u8]) -> HeaderScan {
    if buf.len() < 2 {
        return HeaderScan::Need;
    }
    let opcode = buf[0] & 0x0f;
    // Data frames: a continuation of the previous message (`0x0`), text (`0x1`), binary (`0x2`).
    // Control frames: close (`0x8`), ping (`0x9`), pong (`0xA`). Anything else is reserved, and a
    // reserved opcode means this stream is not what it claims — stop rather than guess.
    if !matches!(opcode, 0x0 | 0x1 | 0x2 | 0x8 | 0x9 | 0xa) {
        return HeaderScan::Bad;
    }
    let masked = buf[1] & 0x80 != 0;
    let len7 = buf[1] & 0x7f;
    let extended = match len7 {
        126 => 2,
        127 => 8,
        _ => 0,
    };
    let total = 2 + extended + if masked { 4 } else { 0 };
    if buf.len() < total {
        return HeaderScan::Need;
    }
    let payload_len = match extended {
        2 => u64::from(u16::from_be_bytes([buf[2], buf[3]])),
        8 => {
            #[expect(
                clippy::expect_used,
                reason = "the length check above returned `Need` unless the buffer holds `total` \
                          bytes, which for this arm is at least ten"
            )]
            let n = u64::from_be_bytes(buf[2..10].try_into().expect("8 bytes checked above"));
            // The most significant bit of a 64-bit length must be 0 (RFC 6455 §5.2); a stream that
            // sets it is not framing this decoder should keep following.
            if n >> 63 != 0 {
                return HeaderScan::Bad;
            }
            n
        }
        _ => u64::from(len7),
    };
    // RFC 6455 §5.5: "All control frames MUST have a payload length of 125 bytes or less and MUST
    // NOT be fragmented." A frame claiming more, or claiming to continue, is not a control frame and
    // this stream is not what it says it is. [`CONTROL_MAX`] bounds only the gather buffer, so
    // without this the decoder went on *following* the declared length: fourteen bytes — a masked
    // ping declaring 2^63-1 — made every byte behind them that frame's payload for the life of the
    // tunnel, so the leak scan never saw another one and the `--with-body` transcript ended there,
    // while the relay forwarded the ordinary frames behind it verbatim.
    if matches!(opcode, 0x8..=0xa) && (payload_len > CONTROL_MAX as u64 || buf[0] & 0x80 == 0) {
        return HeaderScan::Bad;
    }
    let mask = masked.then(|| {
        let at = 2 + extended;
        [buf[at], buf[at + 1], buf[at + 2], buf[at + 3]]
    });
    HeaderScan::Done {
        payload_len,
        keeps: matches!(opcode, 0x0..=0x2),
        control: matches!(opcode, 0x8..=0xa),
        mask,
        fin: buf[0] & 0x80 != 0,
        rsv1: buf[0] & 0x40 != 0,
        starts_message: matches!(opcode, 0x1 | 0x2),
    }
}

// Frame fixtures for both test modules: the relay's tests build real frames and a real needle too,
// and one definition beside the framing it encodes cannot drift from the decoder that reads it.
/// Build one WebSocket frame: `opcode`, the payload, and whether to mask it the way a client
/// must. Extended lengths are chosen the way a real peer would, so a test exercises the same
/// header shapes the decoder meets on the wire.
#[cfg(test)]
pub(super) fn frame(opcode: u8, payload: &[u8], mask: Option<[u8; 4]>) -> Vec<u8> {
    frame_with_fin(opcode, payload, mask, true)
}

/// The same, with `fin` chosen: a fragmented message is a first frame with `fin` clear followed
/// by continuations (opcode `0x0`), the last of which sets it.
#[cfg(test)]
fn frame_with_fin(opcode: u8, payload: &[u8], mask: Option<[u8; 4]>, fin: bool) -> Vec<u8> {
    let mut out = vec![if fin { 0x80 | opcode } else { opcode }];
    let flag = if mask.is_some() { 0x80u8 } else { 0 };
    match payload.len() {
        n if n < 126 => out.push(flag | n as u8),
        n if n <= u16::MAX as usize => {
            out.push(flag | 126);
            out.extend_from_slice(&(n as u16).to_be_bytes());
        }
        n => {
            out.push(flag | 127);
            out.extend_from_slice(&(n as u64).to_be_bytes());
        }
    }
    match mask {
        Some(key) => {
            out.extend_from_slice(&key);
            out.extend(payload.iter().enumerate().map(|(i, b)| b ^ key[i % 4]));
        }
        None => out.extend_from_slice(payload),
    }
    out
}

/// The value [`needle`] looks for, so a test can send exactly what the scan is watching for.
#[cfg(test)]
pub(super) const NEEDLE_VALUE: &[u8] = b"SECRET-VALUE-0123456789";

/// A needle for the leak-scan tests. The value is long enough to clear the redaction floor, and
/// distinctive enough that a match cannot be a coincidence.
#[cfg(test)]
pub(super) fn needle() -> SecretNeedle {
    SecretNeedle::named("demo-token", NEEDLE_VALUE.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sandbox::control::CaptureBytes;

    /// A tee over a sink of `cap` bytes, plus the sink so a test can read what it captured.
    fn tee(cap: usize) -> (FrameTee, Arc<CapBuf>) {
        let sink = Arc::new(CapBuf::new(cap));
        (
            FrameTee::new(Some(sink.clone()), &[], None, false).expect("a sink is a consumer"),
            sink,
        )
    }

    /// The same over a `permessage-deflate` direction; `no_takeover` mirrors what the peer announced.
    fn deflating_tee(cap: usize, no_takeover: bool) -> (FrameTee, Arc<CapBuf>) {
        let sink = Arc::new(CapBuf::new(cap));
        (
            FrameTee::new(Some(sink.clone()), &[], Some(no_takeover), false)
                .expect("a sink is a consumer"),
            sink,
        )
    }

    /// A tee that only SCANS: no capture sink at all, which is the shape a launch has when it
    /// configures a secret and does not capture. Nothing about the leak scan may depend on the
    /// capture being on — that would make a security check follow a debugging setting.
    fn scanning_tee(needles: &[SecretNeedle], deflate: Option<bool>) -> FrameTee {
        FrameTee::new(None, needles, deflate, false).expect("needles are a consumer")
    }

    /// A tee for a direction followed with nothing to look for yet, which is the shape
    /// `websocket_secret = block` gives a tunnel whose destination has no declared secret at the
    /// `101`. `cap` mirrors whether the launch also captures bodies.
    fn blocking_tee(cap: Option<usize>) -> (FrameTee, Option<Arc<CapBuf>>) {
        let sink = cap.map(|c| Arc::new(CapBuf::new(c)));
        (
            FrameTee::new(sink.clone(), &[], None, true).expect("the posture follows anyway"),
            sink,
        )
    }

    /// The payload a `permessage-deflate` sender puts on the wire for `text`: raw DEFLATE against
    /// `c`'s running window, with the trailing empty block elided.
    fn deflated(text: &[u8], c: &mut miniz_oxide::deflate::core::CompressorOxide) -> Vec<u8> {
        use miniz_oxide::deflate::core::{TDEFLFlush, compress};
        let mut body = vec![0u8; text.len() * 2 + 4096];
        let (status, consumed, n) = compress(c, text, &mut body, TDEFLFlush::Sync);
        // Asserted, not assumed: a short write would silently compress a *prefix* of the payload,
        // and a test whose big message turned out not to be big proves nothing.
        assert_eq!(
            consumed,
            text.len(),
            "the whole payload must compress in one call (status {status:?})"
        );
        body.truncate(n);
        if body.ends_with(&[0x00, 0x00, 0xff, 0xff]) {
            body.truncate(body.len() - 4);
        }
        body
    }

    /// One `permessage-deflate` message, compressed against `c`'s running window and framed with
    /// whichever of the three length forms fits — the two-byte and eight-byte forms included, since
    /// the message this exists for is far past the 125 bytes the short form carries.
    fn deflated_message(
        payload: &[u8],
        c: &mut miniz_oxide::deflate::core::CompressorOxide,
    ) -> Vec<u8> {
        let mut framed = frame(0x1, &deflated(payload, c), None);
        framed[0] |= 0x40; // RSV1: the message is compressed
        framed
    }

    /// A plaintext far past what any capture here keeps, which compresses to a few hundred bytes.
    const PAD: usize = 256 * 1024;

    /// What a compressed message decoded before a byte that does not decode is scanned, however much
    /// came before it in the read. The stream wrapper this decoder went through handed a call's
    /// output on only as far as the caller's sixteen-kilobyte buffer held, kept the rest back, and
    /// answered every call after the fault with the fault, so a secret decoded past that point of
    /// one read, ahead of a corrupt byte, was never named, while the same bytes read in smaller
    /// pieces named it. Each case is one read: the secret past the first sixteen kilobytes, and the
    /// secret straddling the end of the decoder's 32 KiB window, where its output wraps.
    #[test]
    fn a_secret_decoded_before_a_corrupt_byte_is_named_however_much_came_before_it() {
        use miniz_oxide::deflate::core::CompressorOxide;
        const SECRET: &[u8] = b"SUPERSECRETVALUE0000";
        let needle = SecretNeedle::named("test-secret", SECRET.to_vec());
        for (lead, case) in [
            (20 * 1024, "past the first sixteen kilobytes"),
            (32 * 1024 - SECRET.len() / 2, "straddling the window's wrap"),
        ] {
            let mut text: Vec<u8> = (0..lead).map(|i| b'a' + (i % 23) as u8).collect();
            text.extend_from_slice(SECRET);
            text.extend_from_slice(&[b'z'; 64]);
            let mut body = deflated(&text, &mut CompressorOxide::new(raw_deflate_flags()));
            // The empty stored block the sync flush ends with, sent rather than elided, leaves the
            // stream on a block boundary, where `0xff` opens a final block of the reserved type,
            // which no decoder follows.
            body.extend_from_slice(&[0x00, 0x00, 0xff, 0xff, 0xff]);
            let mut message = frame(0x1, &body, None);
            message[0] |= 0x40; // RSV1: the message is compressed

            let mut t = scanning_tee(std::slice::from_ref(&needle), Some(false));
            t.push(&message);
            assert_eq!(
                t.sightings(),
                vec!["test-secret".to_string()],
                "{case}: the secret decoded ahead of the fault must be named"
            );
            assert!(
                t.newly_blinded(),
                "{case}: and the direction stops at the fault"
            );
        }
    }

    /// A secret sitting behind a compressible pad, in the same message, must still be seen.
    ///
    /// The sibling test below covers the message *behind* a large one. This is the other half,
    /// and it is the cheaper attack: one message whose plaintext is a compressible pad followed by
    /// the credential. The pad costs a few hundred bytes on the wire, and a scan fed only what the
    /// capture keeps of a message sees a quarter of a megabyte of `a` and reports nothing.
    ///
    /// Both takeover modes, because the cage negotiates that. With context takeover the whole
    /// message has to be inflated anyway to keep the window level; with `no_context_takeover`
    /// nothing forces its end out at all, and a decoder that inflated only what the capture keeps
    /// would leave the hole open to any client that announces it.
    #[test]
    fn a_secret_behind_a_compressible_pad_in_its_own_message_is_still_seen() {
        use miniz_oxide::deflate::core::CompressorOxide;
        const SECRET: &[u8] = b"SUPERSECRETVALUE0000";
        let needle = SecretNeedle::named("test-secret", SECRET.to_vec());

        for no_takeover in [false, true] {
            // The control: the same secret alone, on a tee in the same mode. Without it a green
            // arm could mean the scan is off rather than thorough.
            let mut c = CompressorOxide::new(raw_deflate_flags());
            let mut control = scanning_tee(std::slice::from_ref(&needle), Some(no_takeover));
            control.push(&deflated_message(SECRET, &mut c));
            assert_eq!(
                control.sightings(),
                vec!["test-secret".to_string()],
                "no_takeover={no_takeover}: the scan must see the secret sent alone"
            );

            // One message: the pad, then the credential.
            let mut payload = vec![b'a'; PAD + 1];
            payload.extend_from_slice(SECRET);
            let mut c = CompressorOxide::new(raw_deflate_flags());
            let framed = deflated_message(&payload, &mut c);
            assert!(
                framed.len() < 64 * 1024,
                "no_takeover={no_takeover}: the pad must be cheap on the wire ({} bytes)",
                framed.len()
            );

            let mut t = scanning_tee(std::slice::from_ref(&needle), Some(no_takeover));
            t.push(&framed);
            assert_eq!(
                t.sightings(),
                vec!["test-secret".to_string()],
                "no_takeover={no_takeover}: a compressible pad ahead of the secret carried it past \
                 the scan"
            );
        }
    }

    /// A message that inflates far past what the capture keeps must not blind the messages behind
    /// it.
    ///
    /// With context takeover — the default, since `no_context_takeover` has to be announced — one
    /// DEFLATE window carries across a direction's messages. Stopping the inflate where the capture
    /// stops keeping would leave the decoder holding a window the peer does not share, and every
    /// later message would inflate to rubbish. That is not a truncated scan, it is a scan the cage
    /// switches **off**: send one large compressible message, then exfiltrate freely down the same
    /// tunnel. So what the capture keeps bounds nothing that is *decoded*, and the secret in the
    /// message behind it is still seen.
    #[test]
    fn a_large_message_does_not_blind_the_scan_behind_it() {
        use miniz_oxide::deflate::core::CompressorOxide;
        const SECRET: &[u8] = b"SUPERSECRETVALUE0000";
        let needle = SecretNeedle::named("test-secret", SECRET.to_vec());

        // The control. Without it a green test could mean the scan never sees anything at all.
        let mut c = CompressorOxide::new(raw_deflate_flags());
        let mut control = scanning_tee(std::slice::from_ref(&needle), Some(false));
        control.push(&deflated_message(SECRET, &mut c));
        assert_eq!(
            control.sightings(),
            vec!["test-secret".to_string()],
            "the scan must see a secret sent on its own, else this test proves nothing"
        );

        // The real thing. Message 1 is the pad and ends with a distinctive stretch, so that stretch
        // lands in the peer's window but in the part a capped inflate would never produce.
        // Message 2 repeats it and then carries the secret, so the compressor back-references into
        // exactly that part: message 2 is decodable only if message 1 was inflated *whole*. Both are
        // compressed against one window (`Some(false)` — the peer keeps context across messages).
        let tail: Vec<u8> = (0..8192u32).flat_map(|i| i.to_le_bytes()).collect();
        let mut first = vec![b'a'; PAD + 1024];
        first.extend_from_slice(&tail);
        let mut second = tail.clone();
        second.extend_from_slice(SECRET);

        let mut c = CompressorOxide::new(raw_deflate_flags());
        let overflowing = deflated_message(&first, &mut c);
        let carrying = deflated_message(&second, &mut c);
        // The whole point of the attack shape: it is cheap. A cage would buy a blinded tunnel for a
        // few kilobytes.
        assert!(
            overflowing.len() < 64 * 1024,
            "the large message must be cheap on the wire ({} bytes)",
            overflowing.len()
        );

        let mut t = scanning_tee(std::slice::from_ref(&needle), Some(false));
        t.push(&overflowing);
        t.push(&carrying);
        assert_eq!(
            t.sightings(),
            vec!["test-secret".to_string()],
            "a large message blinded the scan behind it — the leak tripwire on this direction is \
             off for the rest of the tunnel"
        );
    }

    /// The companion to the test above, on the axis it cannot cover: a message too large to inflate
    /// whole leaves the window out of step, and that must be *reported*, so the direction stops
    /// rather than carrying on handing the scan whatever a desynced decoder produces. It is reported
    /// whether or not the peer resets its window per message: the part never inflated is a part the
    /// scan never saw either.
    ///
    /// The bound is lowered for the test rather than the message being grown to sixty-four
    /// megabytes, and a message under it is inflated whole beside it, so the refusal is the bound's.
    #[test]
    fn a_message_past_its_plaintext_bound_is_refused_in_either_window_mode() {
        use miniz_oxide::deflate::core::CompressorOxide;
        for no_takeover in [false, true] {
            for (len, fits) in [(1024, true), (1025, false)] {
                let mut c = CompressorOxide::new(raw_deflate_flags());
                let framed = deflated_message(&vec![b'a'; len], &mut c);
                assert!(framed[1] < 126, "expected the one-byte length form");
                let mut inflater = Inflater::new(no_takeover);
                inflater.message_cap = 1024;
                inflater.start();
                let mut got = 0;
                let mut count = |b: &[u8]| got += b.len();
                let ended = inflater
                    .feed(&framed[2..], &mut count)
                    .and_then(|()| inflater.finish(&mut count));
                match (fits, ended) {
                    (true, Ok(())) => assert_eq!(got, len),
                    (false, Err(Stop::TooLong)) => {}
                    (_, Err(Stop::Undecodable)) => panic!("{len} bytes: the message decodes"),
                    (fits, _) => panic!("{len} bytes, no_takeover {no_takeover}: fits {fits}"),
                }
            }
        }
    }

    /// And the tee acts on that report: the direction stops, says it went blind, and files what the
    /// capture kept of the message, which decoded as far as it went.
    #[test]
    fn a_direction_whose_message_passes_its_plaintext_bound_stops() {
        use miniz_oxide::deflate::core::CompressorOxide;
        let mut c = CompressorOxide::new(raw_deflate_flags());
        let large = deflated_message(&vec![b'a'; 64 * 1024], &mut c);

        let sink = Arc::new(CapBuf::new(8));
        let mut t = FrameTee::new(Some(sink.clone()), &[needle()], Some(false), false)
            .expect("two consumers");
        t.inflater
            .as_mut()
            .expect("a deflate direction has an inflater")
            .message_cap = 1024;
        t.push(&large);
        assert!(
            t.done,
            "a direction holding a window it could not square must stop, not keep scanning"
        );
        assert!(t.newly_blinded(), "and the relay is told");
        assert_eq!(captured(&sink).bytes, b"aaaaaaaa");
    }

    /// Compressor flags for RAW deflate (negative window bits) at a level that genuinely compresses.
    /// A low level emits *stored* blocks, which would leave the payload readable on the wire and make
    /// a compression test vacuous.
    fn raw_deflate_flags() -> u32 {
        miniz_oxide::deflate::core::create_comp_flags_from_zip_params(9, -15, 0)
    }

    /// One compressed frame, built the way a `permessage-deflate` peer builds it: raw DEFLATE with
    /// the trailing empty block stripped, and `RSV1` set on the message's first frame.
    fn deflated_frame(
        payload: &[u8],
        compressor: &mut miniz_oxide::deflate::core::CompressorOxide,
    ) -> Vec<u8> {
        use miniz_oxide::deflate::core::{TDEFLFlush, compress};
        let mut out = vec![0u8; payload.len() * 2 + 128];
        let (_, _, written) = compress(compressor, payload, &mut out, TDEFLFlush::Sync);
        out.truncate(written);
        // The sync flush ends with the empty block `00 00 FF FF`, which the wire format elides.
        if out.ends_with(&[0x00, 0x00, 0xff, 0xff]) {
            out.truncate(out.len() - 4);
        }
        let mut framed = vec![0xc1]; // FIN | RSV1 | text
        framed.push(out.len() as u8);
        framed.extend_from_slice(&out);
        framed
    }

    fn captured(sink: &CapBuf) -> CaptureBytes {
        sink.snapshot()
    }

    /// The core of the whole thing: a client frame is XOR-masked on the wire, so capturing the bytes
    /// as they cross would store noise. Unmasking recovers exactly what the sender sent.
    #[test]
    fn a_masked_client_frame_is_captured_as_what_the_sender_actually_sent() {
        let (mut t, sink) = tee(1024);
        let wire = frame(0x1, br#"{"from":"cage"}"#, Some([0x37, 0xfa, 0x21, 0x3d]));
        assert!(
            !wire.windows(15).any(|w| w == br#"{"from":"cage"}"#),
            "the payload must not appear verbatim on the wire, else this test proves nothing"
        );
        t.push(&wire);
        assert_eq!(captured(&sink).bytes, br#"{"from":"cage"}"#);
    }

    #[test]
    fn an_unmasked_server_frame_is_captured_verbatim() {
        let (mut t, sink) = tee(1024);
        t.push(&frame(0x2, b"\x00\x01binary", None));
        assert_eq!(captured(&sink).bytes, b"\x00\x01binary");
    }

    /// Control frames carry no application data. Capturing a ping's payload would put protocol
    /// housekeeping in the middle of the transcript.
    #[test]
    fn control_frames_are_skipped_and_do_not_break_the_frames_around_them() {
        let (mut t, sink) = tee(1024);
        let mut wire = frame(0x1, b"before", None);
        wire.extend(frame(0x9, b"ping-payload", None)); // ping
        wire.extend(frame(0xa, b"pong-payload", None)); // pong
        wire.extend(frame(0x1, b"after", None));
        t.push(&wire);
        assert_eq!(
            captured(&sink).bytes,
            b"beforeafter",
            "the data frames concatenate and the control frames vanish"
        );
    }

    /// A continuation frame is the rest of the message before it, so its payload belongs to the
    /// transcript exactly like the frame it continues.
    #[test]
    fn a_continued_message_is_captured_whole() {
        let (mut t, sink) = tee(1024);
        let mut wire = frame(0x1, b"first-half ", None);
        wire.extend(frame(0x0, b"second-half", None));
        t.push(&wire);
        assert_eq!(captured(&sink).bytes, b"first-half second-half");
    }

    /// The decoder reads a byte stream, not messages: a header can arrive split across two reads,
    /// and so can a payload. Feeding a whole conversation ONE BYTE AT A TIME must give the same
    /// answer as feeding it in one go.
    #[test]
    fn framing_split_across_reads_decodes_the_same_as_in_one_piece() {
        let mut wire = frame(0x1, b"alpha", Some([1, 2, 3, 4]));
        wire.extend(frame(0x2, &vec![b'z'; 300], None)); // a 2-byte extended length
        wire.extend(frame(0x1, b"omega", Some([9, 8, 7, 6])));

        let (mut whole, whole_sink) = tee(4096);
        whole.push(&wire);

        let (mut split, split_sink) = tee(4096);
        for byte in &wire {
            split.push(std::slice::from_ref(byte));
        }
        assert_eq!(captured(&split_sink).bytes, captured(&whole_sink).bytes);
        assert_eq!(
            captured(&whole_sink).bytes.len(),
            5 + 300 + 5,
            "every data payload is captured once"
        );
    }

    /// A 64-bit length is the third header shape; a peer sending a large binary message uses it.
    #[test]
    fn a_sixty_four_bit_length_header_is_decoded() {
        let (mut t, sink) = tee(1024);
        // Force the 8-byte form by hand: a real peer would only use it past 64 KiB, but the header
        // shape is what is under test, not the size.
        let payload = b"large-message";
        let mut wire = vec![0x81, 127];
        wire.extend_from_slice(&(payload.len() as u64).to_be_bytes());
        wire.extend_from_slice(payload);
        t.push(&wire);
        assert_eq!(captured(&sink).bytes, payload);
    }

    /// A stream whose framing does not parse stops being captured rather than being reported as
    /// something it is not. The relay itself is untouched — it never parsed the frames to begin with.
    #[test]
    fn a_reserved_opcode_stops_the_capture_instead_of_inventing_a_transcript() {
        let (mut t, sink) = tee(1024);
        let mut wire = frame(0x1, b"real", None);
        wire.extend(frame(0x5, b"reserved", None)); // 0x5 is reserved
        wire.extend(frame(0x1, b"never-seen", None));
        t.push(&wire);
        assert_eq!(
            captured(&sink).bytes,
            b"real",
            "what was decoded stands; nothing past the break is guessed"
        );
    }

    /// The point of the whole decompression path: with `permessage-deflate` negotiated, a payload is
    /// DEFLATE on the wire, so capturing it raw stores binary noise for exactly the JSON-per-message
    /// protocols this feature exists for. Teeth: the test asserts the plaintext is ABSENT from the
    /// bytes that crossed and PRESENT in the capture.
    #[test]
    fn a_compressed_message_is_captured_as_the_text_it_carries() {
        use miniz_oxide::deflate::core::{CompressorOxide, TDEFLFlush};
        let _ = TDEFLFlush::Sync;
        let mut comp = CompressorOxide::new(raw_deflate_flags());
        let payload =
            br#"{"type":"session.update","session":{"voice":"alloy","session":"session"}}"#;
        let wire = deflated_frame(payload, &mut comp);
        assert!(
            !wire.windows(payload.len()).any(|w| w == payload),
            "the payload must be compressed on the wire, else this test proves nothing"
        );
        let (mut t, sink) = deflating_tee(4096, false);
        t.push(&wire);
        assert_eq!(captured(&sink).bytes, payload);
    }

    /// The context-takeover trap: without `no_context_takeover` the DEFLATE window carries across
    /// messages, so a decoder that resets between them inflates everything after the first to
    /// garbage. A second message compressed against the first is the only way to catch that.
    #[test]
    fn a_second_message_sharing_the_compression_window_still_decodes() {
        use miniz_oxide::deflate::core::CompressorOxide;
        let mut comp = CompressorOxide::new(raw_deflate_flags());
        let first = br#"{"type":"response.delta","text":"hello"}"#;
        let second = br#"{"type":"response.delta","text":"world"}"#;
        let mut wire = deflated_frame(first, &mut comp);
        wire.extend(deflated_frame(second, &mut comp));

        let (mut t, sink) = deflating_tee(4096, false);
        t.push(&wire);
        let got = captured(&sink).bytes;
        assert_eq!(
            String::from_utf8(got).unwrap(),
            format!(
                "{}{}",
                String::from_utf8_lossy(first),
                String::from_utf8_lossy(second)
            ),
            "the second message must decode against the window the first left behind"
        );
    }

    /// A compressed message split across a continuation frame is one DEFLATE stream, which the
    /// decoder takes up in the second frame where the first left it, here in the middle of a
    /// symbol. A decoder that inflated each frame as a stream of its own would fail on the second.
    #[test]
    fn a_compressed_message_fragmented_across_frames_is_inflated_as_one_stream() {
        use miniz_oxide::deflate::core::{CompressorOxide, TDEFLFlush, compress};
        let mut comp = CompressorOxide::new(raw_deflate_flags());
        let payload = br#"{"a":"first-half","b":"second-half","a2":"first-half"}"#;
        let mut body = vec![0u8; payload.len() * 2 + 128];
        let (_, _, n) = compress(&mut comp, payload, &mut body, TDEFLFlush::Sync);
        body.truncate(n);
        if body.ends_with(&[0x00, 0x00, 0xff, 0xff]) {
            body.truncate(body.len() - 4);
        }
        let (head, tail) = body.split_at(body.len() / 2);
        // First frame: RSV1 + text, not final. Second: continuation, final.
        let mut wire = vec![0x41, head.len() as u8];
        wire.extend_from_slice(head);
        wire.extend_from_slice(&[0x80, tail.len() as u8]);
        wire.extend_from_slice(tail);

        let (mut t, sink) = deflating_tee(4096, false);
        t.push(&wire);
        assert_eq!(captured(&sink).bytes, payload);
    }

    /// A secret carried whole by a compressed message's first frame is seen as that frame is read,
    /// before the frames after it: the relay writes each chunk on only once the scan has read it,
    /// and a message read only at its final frame has had every frame before it relayed by then.
    /// The frame ends where the sender's compressor flushed, so its bytes decode to the secret on
    /// their own; the next frame carries the rest of the message.
    #[test]
    fn a_secret_in_a_compressed_messages_first_frame_is_seen_before_its_last() {
        use miniz_oxide::deflate::core::CompressorOxide;
        const KEY: Option<[u8; 4]> = Some([9, 8, 7, 6]);
        for no_takeover in [false, true] {
            let mut c = CompressorOxide::new(raw_deflate_flags());
            let mut text = b"token=".to_vec();
            text.extend_from_slice(NEEDLE_VALUE);
            // The flush's empty block stays within a message: only the message's end elides it.
            let mut flushed = deflated(&text, &mut c);
            flushed.extend_from_slice(&[0x00, 0x00, 0xff, 0xff]);
            let mut opening = frame_with_fin(0x1, &flushed, KEY, false);
            opening[0] |= 0x40; // RSV1: the message is compressed
            let closing = frame_with_fin(0x0, &deflated(b" and the rest", &mut c), KEY, true);

            let mut t = scanning_tee(&[needle()], Some(no_takeover));
            t.push(&opening);
            assert_eq!(
                t.sightings(),
                ["demo-token"],
                "no_takeover {no_takeover}: seen before the message's last frame"
            );
            t.push(&closing);
            assert!(!t.newly_blinded(), "no_takeover {no_takeover}");
            assert!(t.sightings().is_empty(), "and reported once");
        }
    }

    /// A new message begun in the midst of a compressed one, which RFC 6455 §5.4 forbids, leaves the
    /// decoder partway through a stream the peer walked away from, and the direction says it has
    /// gone blind rather than decoding the rest as a guess. A control frame between two of the
    /// message's frames is legal, a close included, and needs nothing of the kind: every frame was
    /// read as it came.
    #[test]
    fn a_compressed_message_another_begins_in_the_midst_of_blinds_its_direction() {
        use miniz_oxide::deflate::core::CompressorOxide;
        const KEY: Option<[u8; 4]> = Some([1, 2, 3, 4]);
        let first = |c: &mut CompressorOxide| {
            let mut text = b"hello ".to_vec();
            text.extend_from_slice(NEEDLE_VALUE);
            text.extend_from_slice(b" bye");
            let mut framed = frame_with_fin(0x1, &deflated(&text, c), KEY, false);
            framed[0] |= 0x40; // RSV1: the message is compressed
            framed
        };
        let mut c = CompressorOxide::new(raw_deflate_flags());
        let mut t = scanning_tee(&[needle()], Some(false));
        t.push(&first(&mut c));
        assert!(!t.newly_blinded(), "the message is still open");
        t.push(&frame(0x1, b"next", KEY));
        assert!(t.newly_blinded(), "a new message in its midst");

        for (between, what) in [
            (frame(0x9, b"ping", KEY), "a ping"),
            (frame(0x8, b"", KEY), "a close"),
        ] {
            let mut c = CompressorOxide::new(raw_deflate_flags());
            let mut t = scanning_tee(&[needle()], Some(false));
            t.push(&first(&mut c));
            assert_eq!(t.sightings(), ["demo-token"], "{what}: read as it came");
            t.push(&between);
            assert!(!t.newly_blinded(), "{what} may sit between two frames");
            t.push(&frame_with_fin(0x0, b"", KEY, true));
            assert!(!t.newly_blinded(), "{what}");
            assert!(!t.done, "{what}: the message ended as it should");
        }
    }

    /// A message the peer chose NOT to compress rides the same connection with `RSV1` clear, and must
    /// be captured verbatim rather than pushed through the decompressor.
    #[test]
    fn an_uncompressed_message_on_a_deflate_connection_is_captured_verbatim() {
        let (mut t, sink) = deflating_tee(4096, false);
        t.push(&frame(0x1, b"plain text", None));
        assert_eq!(captured(&sink).bytes, b"plain text");
    }

    /// A compressed message that does not decode leaves the transcript at the last message that
    /// was actually decoded: neither its bytes, which are not the text it claims to carry, nor what
    /// a decoder made of them before it failed, which is a guess.
    ///
    /// The direction has to stop there, since every later message shares the window.
    #[test]
    fn a_message_that_does_not_decode_files_none_of_its_bytes() {
        use miniz_oxide::deflate::core::CompressorOxide;
        let (mut t, sink) = deflating_tee(4096, false);

        // A real compressed message first, so the assertion below cannot be satisfied by a tee that
        // captures nothing at all.
        let mut c = CompressorOxide::new(raw_deflate_flags());
        t.push(&deflated_frame(b"decoded-and-kept", &mut c));
        assert_eq!(
            captured(&sink).bytes,
            b"decoded-and-kept",
            "the ordinary compressed message must be captured, else this test proves nothing"
        );

        // Then one claiming RSV1 whose payload is not DEFLATE at all, so its bytes are exactly what
        // a consumer would file if this path consumed them.
        let marker = b"NOT-PLAINTEXT-";
        let payload: Vec<u8> = marker.iter().copied().cycle().take(80 * 1024).collect();
        let mut wire = vec![0xc1u8, 127];
        wire.extend_from_slice(&(payload.len() as u64).to_be_bytes());
        wire.extend_from_slice(&payload);
        t.push(&wire);

        assert!(
            t.done,
            "a direction that gave up on a message holds a window it cannot square, so it stops"
        );
        let got = captured(&sink).bytes;
        assert!(
            !got.windows(marker.len()).any(|w| w == marker),
            "DEFLATE bytes were filed as a message's text — nothing any peer sent looks like this"
        );
        assert_eq!(
            got, b"decoded-and-kept",
            "the transcript must end at the last message actually decoded"
        );

        // And one whose stream decodes a while and then breaks: what came out before the break is
        // not filed either.
        let mut c = CompressorOxide::new(raw_deflate_flags());
        let mut broken = deflated(b"decoded-then-broken", &mut c);
        broken.extend_from_slice(&[0x00, 0x00, 0xff, 0xff, 0xff, 0xff]);
        let mut wire = frame(0x1, &broken, None);
        wire[0] |= 0x40; // RSV1
        let (mut t, sink) = deflating_tee(4096, false);
        t.push(&wire);
        assert!(t.done, "a stream that breaks stops the direction");
        assert!(captured(&sink).bytes.is_empty(), "and files nothing of it");
    }

    /// A compressed message whose text fills the decoder's block exactly as its input runs out is
    /// read whole: the text is 16 KiB or one of its doublings, or one of those and a byte, or that
    /// and one more block. The value at its end is seen, the capture holds it, and the message
    /// behind it decodes, so the window was left level, whether it carries across messages or not.
    #[test]
    fn a_compressed_message_that_fills_the_output_exactly_is_read_whole() {
        use miniz_oxide::deflate::core::CompressorOxide;
        for len in [
            16 * 1024,
            32 * 1024,
            64 * 1024,
            128 * 1024,
            PAD,
            PAD + 1,
            PAD + 1 + 16 * 1024,
        ] {
            for no_takeover in [false, true] {
                let mut text = vec![b'a'; len - NEEDLE_VALUE.len()];
                text.extend_from_slice(NEEDLE_VALUE);
                let mut c = CompressorOxide::new(raw_deflate_flags());
                let first = deflated_message(&text, &mut c);
                if no_takeover {
                    c = CompressorOxide::new(raw_deflate_flags());
                }
                let second = deflated_message(b"after", &mut c);

                let mut scan = scanning_tee(&[needle()], Some(no_takeover));
                scan.push(&first);
                scan.push(&second);
                assert!(
                    !scan.done,
                    "{len} bytes, no_takeover {no_takeover}: still read"
                );
                assert_eq!(scan.sightings(), vec!["demo-token".to_string()]);

                let (mut capture, sink) = deflating_tee(1 << 20, no_takeover);
                capture.push(&first);
                capture.push(&second);
                assert!(
                    captured(&sink).bytes == [&text[..], b"after"].concat(),
                    "{len} bytes, no_takeover {no_takeover}: captured whole, then the next"
                );
            }
        }
    }

    /// A capture filled exactly by one message, then an empty compressed message, then more text:
    /// the empty message carries no byte, so it says nothing about whether the transcript was cut,
    /// and the text behind it is what does. Such a message goes out as a payload of nothing, which
    /// is what a compressor flushing no text leaves once the trailer is elided, or as the single
    /// `00` byte RFC 7692 §7.2.3.6 gives; each is sent, to a capture alone and to one beside a scan.
    #[test]
    fn an_empty_compressed_message_at_a_full_capture_leaves_the_cut_to_what_follows() {
        use miniz_oxide::deflate::core::CompressorOxide;
        let flushed = deflated_message(b"", &mut CompressorOxide::new(raw_deflate_flags()));
        let single_zero = vec![0xc1u8, 0x01, 0x00];
        for empty in [flushed, single_zero] {
            for needles in [Vec::new(), vec![needle()]] {
                let sink = Arc::new(CapBuf::new(4));
                let mut t = FrameTee::new(Some(sink.clone()), &needles, Some(false), false)
                    .expect("a sink is a consumer");
                t.push(&frame(0x1, b"abcd", None));
                t.push(&empty);
                assert!(
                    !t.done,
                    "a capture filled exactly still waits for the next byte"
                );
                assert!(
                    !captured(&sink).truncated,
                    "nothing has followed yet, so nothing was cut"
                );
                t.push(&frame(0x1, b"e", None));
                let got = captured(&sink);
                assert_eq!(got.bytes, b"abcd");
                assert!(
                    got.truncated,
                    "text followed the empty message, so the transcript was cut ({} needles)",
                    needles.len()
                );
            }
        }
    }

    /// A stream that claims compression but does not decode stops the direction rather than storing
    /// rubbish — and it must stop, since every later message shares the same window.
    #[test]
    fn a_compressed_message_that_does_not_decode_stops_the_direction() {
        let (mut t, sink) = deflating_tee(4096, false);
        let mut wire = vec![0xc1, 6];
        wire.extend_from_slice(b"\xff\xff\xff\xff\xff\xff");
        t.push(&wire);
        t.push(&frame(0x1, b"never-seen", None));
        assert!(
            !captured(&sink)
                .bytes
                .windows(10)
                .any(|w| w == b"never-seen"),
            "nothing past an undecodable message is guessed at"
        );
    }

    /// A message that opens compressed on a direction with no compression to follow stops the
    /// direction, and a scan says it went blind, rather than scanning DEFLATE bytes that no needle
    /// can match and filing them as the message's text. The peers compressed under an agreement the
    /// upgrade response did not show this decoder, so nothing it reads past that point is text.
    #[test]
    fn a_compressed_message_where_none_was_negotiated_stops_the_direction() {
        use miniz_oxide::deflate::core::CompressorOxide;
        let mut payload = b"token=".to_vec();
        payload.extend_from_slice(NEEDLE_VALUE);
        let compressed = deflated_frame(&payload, &mut CompressorOxide::new(raw_deflate_flags()));

        let mut scan = scanning_tee(&[needle()], None);
        scan.push(&frame(0x1, b"plain", Some([1, 2, 3, 4])));
        assert!(
            !scan.newly_blinded(),
            "a plain message is followed as before"
        );
        scan.push(&compressed);
        assert!(scan.newly_blinded(), "the scan says it can no longer see");
        assert!(!scan.newly_blinded(), "and says it once");

        let (mut capture, sink) = tee(4096);
        capture.push(&frame(0x1, b"kept", None));
        capture.push(&compressed);
        capture.push(&frame(0x1, b"after", None));
        assert_eq!(
            captured(&sink).bytes,
            b"kept",
            "the transcript ends at the last message it could read"
        );
        assert!(
            !capture.newly_blinded(),
            "a capture alone has no tripwire to lose"
        );
    }

    #[test]
    fn the_negotiated_extension_is_read_off_the_upgrade_response() {
        let none =
            negotiated_deflate(b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\r\n");
        assert!(!none.negotiated, "no extension header means no compression");

        let both = negotiated_deflate(
            b"HTTP/1.1 101 Switching Protocols\r\n\
              Sec-WebSocket-Extensions: permessage-deflate; server_no_context_takeover; \
              client_max_window_bits=15\r\n\r\n",
        );
        assert!(both.negotiated);
        assert!(
            both.server_no_context_takeover,
            "the server resets its window"
        );
        assert!(
            !both.client_no_context_takeover,
            "the client was not asked to, so its window carries"
        );

        let other = negotiated_deflate(
            b"HTTP/1.1 101 Switching Protocols\r\nSec-WebSocket-Extensions: x-custom\r\n\r\n",
        );
        assert!(
            !other.negotiated,
            "an extension this decoder cannot follow is not claimed"
        );

        // Co-negotiated, in both orders. Extensions on one stream compose, so an unknown entry sits
        // between the framing and the DEFLATE stream — picking the deflate entry out of the list
        // and inflating past the unknown one decodes whatever that other extension left behind and
        // files it as the message's text. Neither order may report a followable stream.
        for head in [
            b"HTTP/1.1 101 Switching Protocols\r\n              Sec-WebSocket-Extensions: x-custom, permessage-deflate\r\n\r\n"
                .as_slice(),
            b"HTTP/1.1 101 Switching Protocols\r\n              Sec-WebSocket-Extensions: permessage-deflate, x-custom\r\n\r\n"
                .as_slice(),
        ] {
            let got = negotiated_deflate(head);
            assert!(
                !got.negotiated,
                "deflate co-negotiated with an extension this decoder cannot follow must report \
                 nothing negotiated, so the payload is captured as it crosses: {}",
                String::from_utf8_lossy(head)
            );
        }
        // The same list, split over two header fields, which RFC 6455 §9.1 allows. Reading only the
        // first field never examined the second, so an entry the decoder cannot follow was skipped
        // past and the tee inflated a stream that other extension had already transformed.
        for head in [
            b"HTTP/1.1 101 Switching Protocols\r\n\
              Sec-WebSocket-Extensions: permessage-deflate\r\n\
              Sec-WebSocket-Extensions: x-custom\r\n\r\n"
                .as_slice(),
            b"HTTP/1.1 101 Switching Protocols\r\n\
              Sec-WebSocket-Extensions: x-custom\r\n\
              Sec-WebSocket-Extensions: permessage-deflate\r\n\r\n"
                .as_slice(),
        ] {
            assert!(
                !negotiated_deflate(head).negotiated,
                "an entry named in a second extensions field belongs to the same list: {}",
                String::from_utf8_lossy(head)
            );
        }
        // And the guard still admits the plain case, so it cannot be satisfied by refusing every
        // response that carries an extension header at all.
        assert!(
            negotiated_deflate(
                b"HTTP/1.1 101 Switching Protocols\r\n                  Sec-WebSocket-Extensions: permessage-deflate\r\n\r\n",
            )
            .negotiated,
            "a response naming only permessage-deflate is exactly what this follows"
        );
    }

    /// An empty element of the extension list is no extension, as a client reading RFC 9110's list
    /// rule takes it: Python's `websockets` compresses under `permessage-deflate,` and
    /// `, permessage-deflate`, so the decoder has to inflate there too. The reading only widens:
    /// every head read as negotiated before is still read so, the ones naming an extension beside
    /// the deflate entry are still refused, and a list of empty elements names nothing.
    #[test]
    fn an_empty_element_of_the_extension_list_is_no_extension() {
        let read = |fields: &[&str]| {
            let mut head = String::from("HTTP/1.1 101 Switching Protocols\r\n");
            for value in fields {
                head.push_str(&format!("Sec-WebSocket-Extensions:{value}\r\n"));
            }
            head.push_str("\r\n");
            negotiated_deflate(head.as_bytes()).negotiated
        };
        for fields in [
            &[" permessage-deflate,"][..],
            &[" , permessage-deflate"],
            &[" permessage-deflate,,"],
            &[" permessage-deflate", ""],
            &["", " permessage-deflate"],
            &[" permessage-deflate; server_no_context_takeover,"],
            &[" ,\u{a0}permessage-deflate"],
        ] {
            assert!(read(fields), "{fields:?} negotiates permessage-deflate");
        }
        // What was read as negotiated still is: the reading leans that way on purpose.
        for fields in [
            &[" permessage-deflate"][..],
            &["\tpermessage-deflate\t"],
            &[" \u{a0}permessage-deflate"],
            &[" permessage-deflate;"],
            &[" permessage-deflate\u{a0}; server_no_context_takeover"],
            &[" PerMessage-Deflate"],
        ] {
            assert!(read(fields), "{fields:?} is still read as negotiated");
        }
        for fields in [
            &[" permessage-deflate, , x-custom"][..],
            &[" ,x-custom,"],
            &[" ,"],
            &[""],
        ] {
            assert!(
                !read(fields),
                "{fields:?} negotiates nothing this can follow"
            );
        }
    }

    /// The sink's cap bounds a chatty tunnel, and filling it is the signal the relay uses to show a
    /// long-lived tunnel's transcript before it closes.
    #[test]
    fn filling_the_cap_is_reported_once_so_the_relay_can_file_the_transcript() {
        let (mut t, sink) = tee(8);
        assert!(!t.push(&frame(0x1, b"1234", None)), "not full yet");
        assert!(
            t.push(&frame(0x1, b"5678ABCD", None)),
            "the cap is reached, and the relay is told exactly once"
        );
        assert!(
            !t.push(&frame(0x1, b"more", None)),
            "and never told again afterwards"
        );
        let got = captured(&sink);
        assert_eq!(got.bytes, b"12345678");
        assert!(got.truncated, "the cut is reported, never silent");
    }

    /// The scan reports a configured secret it sees crossing, and reports it by NAME. Teeth: the
    /// tee has NO capture sink, so this proves the enforcement path does not ride on the capture
    /// being enabled — a security check that followed a debugging setting would be worthless.
    #[test]
    fn a_secret_crossing_a_frame_is_seen_with_no_capture_configured() {
        let mut t = scanning_tee(&[needle()], None);
        t.push(&frame(0x1, b"{\"auth\":\"SECRET-VALUE-0123456789\"}", None));
        assert_eq!(
            t.sightings(),
            vec!["demo-token".to_string()],
            "the credential is named, and nothing else is"
        );
    }

    /// The same value crossing again says nothing new, so it is reported once. Without this an
    /// alarm on a chatty tunnel would amend its event on every message and drown the log it is
    /// meant to stand out in.
    #[test]
    fn a_secret_seen_twice_is_reported_once() {
        let mut t = scanning_tee(&[needle()], None);
        t.push(&frame(0x1, b"first SECRET-VALUE-0123456789", None));
        assert_eq!(t.sightings().len(), 1);
        t.push(&frame(0x1, b"again SECRET-VALUE-0123456789", None));
        assert!(
            t.sightings().is_empty(),
            "a repeat carries no new information and must not re-alarm"
        );
    }

    /// A value split across two frames of ONE message is still seen: the pieces of a message are
    /// contiguous, so the scan carries the tail across them. A frame boundary is not a place a
    /// secret gets to hide.
    #[test]
    fn a_secret_split_across_two_frames_of_one_message_is_still_seen() {
        let mut t = scanning_tee(&[needle()], None);
        // A fragmented text message: first frame not final, then a continuation that ends it.
        let mut wire = frame_with_fin(0x1, b"prefix SECRET-VALUE-", None, false);
        wire.extend_from_slice(&frame_with_fin(0x0, b"0123456789 suffix", None, true));
        t.push(&wire);
        assert_eq!(t.sightings(), vec!["demo-token".to_string()]);
    }

    /// A value split across two SEPARATE messages is NOT reported. Two messages are two application
    /// payloads, so a match spanning them would be an artefact of concatenation, not a secret that
    /// crossed — and a false alarm in a security tool costs more than a missed byte-exact split,
    /// which the documented scope already excludes (as it excludes a re-encoded value).
    #[test]
    fn a_value_split_across_two_messages_is_not_reported() {
        let mut t = scanning_tee(&[needle()], None);
        t.push(&frame(0x1, b"prefix SECRET-VALUE-", None));
        t.push(&frame(0x1, b"0123456789 suffix", None));
        assert!(
            t.sightings().is_empty(),
            "a match across a message boundary is a concatenation artefact, not a sighting"
        );
    }

    /// A masked frame — every frame the cage sends is masked — is unmasked before it is scanned.
    /// Without that the outbound direction would never match anything at all.
    #[test]
    fn a_masked_outbound_frame_is_unmasked_before_it_is_scanned() {
        let mut t = scanning_tee(&[needle()], None);
        t.push(&frame(
            0x1,
            b"take SECRET-VALUE-0123456789",
            Some([0x37, 0xfa, 0x21, 0x3d]),
        ));
        assert_eq!(t.sightings(), vec!["demo-token".to_string()]);
    }

    /// A secret inside a `permessage-deflate` message is seen: the message is inflated before it is
    /// scanned. Teeth: the payload is asserted absent from the wire bytes first, so a decoder that
    /// silently stopped compressing would fail here rather than pass vacuously.
    #[test]
    fn a_secret_inside_a_compressed_message_is_seen() {
        use miniz_oxide::deflate::core::CompressorOxide;
        let mut comp = CompressorOxide::new(raw_deflate_flags());
        // Padded into genuinely compressible shape: a short, high-entropy payload is emitted as a
        // STORED block, which would leave the secret readable on the wire and make the guard below
        // pass for the wrong reason.
        let mut payload = b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".repeat(20);
        payload.extend_from_slice(br#"{"authorization":"Bearer SECRET-VALUE-0123456789"}"#);
        let wire = deflated_frame(&payload, &mut comp);
        assert!(
            !wire
                .windows(b"SECRET-VALUE-0123456789".len())
                .any(|w| w == b"SECRET-VALUE-0123456789"),
            "the secret must be compressed on the wire, else this test proves nothing"
        );
        let mut t = scanning_tee(&[needle()], Some(false));
        t.push(&wire);
        assert_eq!(t.sightings(), vec!["demo-token".to_string()]);
    }

    /// Ordinary traffic raises nothing. The obvious property, asserted because a scan that reported
    /// on everything would be indistinguishable from one that worked.
    #[test]
    fn traffic_carrying_no_secret_raises_nothing() {
        let mut t = scanning_tee(&[needle()], None);
        t.push(&frame(0x1, b"{\"type\":\"ping\",\"n\":1}", None));
        assert!(t.sightings().is_empty());
    }

    /// A control frame carries application data, so the scan has to read it.
    ///
    /// RFC 6455 §5.5.2 and §5.5.3 both say a ping and a pong "MAY include 'Application data'", and
    /// close carries a reason — up to 125 bytes the cage chooses, on a frame the tee used to skip
    /// whole. That is a clean exfiltration channel past the outbound-secret tripwire: no reassembly,
    /// no compression, 125 bytes a frame and as many frames as it likes.
    #[test]
    fn a_secret_in_a_control_frame_payload_is_seen() {
        for opcode in [0x9u8, 0xa, 0x8] {
            let mut t = scanning_tee(&[needle()], None);
            t.push(&frame(opcode, NEEDLE_VALUE, Some([0x11, 0x22, 0x33, 0x44])));
            assert_eq!(
                t.sightings(),
                vec!["demo-token".to_string()],
                "a secret sent as the payload of control frame {opcode:#x} crossed unseen"
            );
        }
    }

    /// A control frame may interleave a fragmented message, and scanning its payload must not
    /// disturb the carry that message's own scan depends on — otherwise sending a ping between two
    /// halves of a secret would hide it, which is the same hole wearing a different hat.
    #[test]
    fn a_control_frame_between_two_halves_of_a_secret_does_not_hide_it() {
        let (first, second) = NEEDLE_VALUE.split_at(5);
        let mut t = scanning_tee(&[needle()], None);
        t.push(&frame_with_fin(0x1, first, None, false));
        t.push(&frame(0x9, b"keepalive", None));
        t.push(&frame_with_fin(0x0, second, None, true));
        assert_eq!(
            t.sightings(),
            vec!["demo-token".to_string()],
            "a ping between the halves of a secret hid it from the scan"
        );
    }

    /// With neither a capture sink nor a needle there is no consumer, so no decoder is built at all
    /// and the tunnel is relayed without its framing being followed. The cost of both features is
    /// exactly zero for a launch that uses neither.
    #[test]
    fn a_tunnel_with_nothing_to_do_builds_no_decoder() {
        assert!(FrameTee::new(None, &[], None, false).is_none());
    }

    /// A control frame that declares more than RFC 6455 §5.5 allows is refused, not followed.
    ///
    /// [`CONTROL_MAX`] bounded only the gather buffer, so the decoder went on counting the declared
    /// length down: fourteen bytes — a masked ping claiming 2^63-1 — made every byte behind them
    /// that frame's payload for the life of the tunnel. `payload_left` never reached zero, so no
    /// further header was ever parsed; `done` was never set, so nothing could report it; and the
    /// relay went on forwarding the ordinary frames behind it verbatim with the leak tripwire and
    /// the `--with-body` transcript both off.
    #[test]
    fn a_control_frame_declaring_more_than_the_protocol_allows_stops_the_direction() {
        // The whole of it: FIN|ping, masked, an 8-byte length of 2^63-1, and a mask key.
        let mut wire = vec![0x89u8, 0xff];
        wire.extend_from_slice(&0x7fff_ffff_ffff_ffffu64.to_be_bytes());
        wire.extend_from_slice(&[0x11, 0x22, 0x33, 0x44]);
        assert_eq!(wire.len(), 14, "the whole attack is fourteen bytes");

        let mut t = scanning_tee(&[needle()], None);
        t.push(&wire);
        assert!(
            t.done,
            "a frame claiming to be a control frame and not being one must stop the decoder rather \
             than have it follow the length"
        );
        assert!(
            t.newly_blinded(),
            "and the relay must be told the tripwire stopped"
        );
        assert!(!t.newly_blinded(), "once, not on every later read");

        // §5.5 forbids fragmenting a control frame too, and the gather buffer assumes it: a
        // continuation would be scanned as a self-contained payload it is not.
        let mut fragmented = scanning_tee(&[needle()], None);
        fragmented.push(&frame_with_fin(0x9, b"ping", None, false));
        assert!(fragmented.done, "a fragmented control frame is not one");

        // ...and a conforming ping is still read whole, so this cannot be satisfied by refusing
        // every control frame — reading their payload is why they are followed at all.
        let mut ok = scanning_tee(&[needle()], None);
        ok.push(&frame(0x9, NEEDLE_VALUE, Some([0x11, 0x22, 0x33, 0x44])));
        assert!(
            !ok.done,
            "a control frame inside the protocol's limit is ordinary traffic"
        );
        assert_eq!(ok.sightings(), vec!["demo-token".to_string()]);
    }

    /// A direction that gives up on the framing while a leak scan is configured says so — once.
    ///
    /// `done` is the right answer for the *capture*, whose transcript honestly ends at the last
    /// message it decoded. It is not an answer for the *scan*: a decoder going blind mid-tunnel is
    /// a security control the cage switches off at will, and `done` is private, so without the
    /// report `follow` says nothing, the relay keeps forwarding, and `websocket_secret = block`
    /// never fires again on that tunnel. One compressed message the decoder cannot follow is
    /// enough, here one whose bytes are not DEFLATE.
    #[test]
    fn a_direction_that_goes_blind_while_scanning_reports_it_once() {
        // A capture-only tee that stops is NOT a tripwire that stopped: its transcript ending is the
        // documented answer and there is no scan to lose. Asserted first, so the report cannot be
        // satisfied by firing on every `done`.
        let (mut capture_only, _sink) = tee(1024);
        capture_only.push(&frame(0x5, b"reserved", None));
        assert!(capture_only.done, "a reserved opcode stops the capture");
        assert!(
            !capture_only.newly_blinded(),
            "a capture that ends is not a tripwire that was switched off"
        );

        let mut t = scanning_tee(&[needle()], Some(false));
        let payload: Vec<u8> = b"NOT-PLAINTEXT-"
            .iter()
            .copied()
            .cycle()
            .take(64 * 1024)
            .collect();
        let mut wire = vec![0xc1u8, 127]; // FIN | RSV1 | text, 8-byte length
        wire.extend_from_slice(&(payload.len() as u64).to_be_bytes());
        wire.extend_from_slice(&payload);
        t.push(&wire);
        assert!(t.done, "a message that does not decode stops the direction");
        assert!(
            t.newly_blinded(),
            "and the relay must be told, because from here nothing outbound is watched"
        );
        assert!(!t.newly_blinded(), "once, not on every later read");

        // The report is the whole point: the secret behind that message really is unseen.
        t.push(&frame(0x1, NEEDLE_VALUE, None));
        assert!(
            t.sightings().is_empty(),
            "a blinded direction sees nothing — which is why it has to be reported"
        );
    }

    /// A capture that has filled does not stop the scan: the decoder keeps following the framing for
    /// as long as a consumer still wants bytes. Teeth: the secret is sent AFTER the sink's cap is
    /// exhausted, so a decoder that quit when the capture filled would miss it.
    #[test]
    fn a_full_capture_does_not_blind_the_scan() {
        let sink = Arc::new(CapBuf::new(4));
        let mut t =
            FrameTee::new(Some(sink.clone()), &[needle()], None, false).expect("two consumers");
        t.push(&frame(0x1, b"aaaaaaaaaaaa", None));
        assert!(captured(&sink).truncated, "the capture is full by now");
        t.push(&frame(0x1, b"late SECRET-VALUE-0123456789", None));
        assert_eq!(
            t.sightings(),
            vec!["demo-token".to_string()],
            "the scan outlives the capture it shares a decoder with"
        );
    }

    /// A direction followed for a needle the launch does not have yet is a tripwire like any other:
    /// it may not end at the capture's cap, and if the framing stops it says so.
    ///
    /// This is the shape `websocket_secret = block` gives a tunnel whose destination has no declared
    /// secret at the `101` — the decoder is kept alive purely so `refresh_needles` can arm it when
    /// the cage acquires a credential. Ending it quietly leaves the posture promising a scan that
    /// can never be attached, on a tunnel that keeps relaying.
    #[test]
    fn a_direction_followed_for_a_later_needle_is_kept_and_reports_going_blind() {
        // The capture fills first. The decoder must keep following the framing, because the scan it
        // is being held open for has not arrived yet.
        let (mut t, sink) = blocking_tee(Some(4));
        t.push(&frame(0x1, b"aaaaaaaaaaaa", None));
        assert!(
            captured(&sink.expect("this arm captures")).truncated,
            "the capture is full by now"
        );
        assert!(
            !t.done,
            "a full capture does not end a direction the posture follows anyway"
        );
        t.refresh_needles(&[needle()]);
        t.push(&frame(0x1, b"late SECRET-VALUE-0123456789", None));
        assert_eq!(
            t.sightings(),
            vec!["demo-token".to_string()],
            "the credential the cage acquired after the `101` is watched for"
        );

        // And when the framing does stop before any needle arrives, the relay is told: the scan can
        // never be attached afterwards, so this is the tripwire going off the air for good.
        let (mut blind, _) = blocking_tee(None);
        blind.push(&frame(0x5, b"reserved", None));
        assert!(blind.done, "a reserved opcode stops the decoder");
        assert!(
            blind.newly_blinded(),
            "a direction the posture was holding open for a scan cannot stop in silence"
        );
        assert!(!blind.newly_blinded(), "once, not on every later read");
    }

    // Generated conversations, against the messages as they were written.

    /// A second declared value, shorter than [`NEEDLE_VALUE`], so the carry the scan keeps is sized
    /// by the longer of two needles and each is looked for on its own.
    const SHORT_VALUE: &[u8] = b"TOKEN-abcdef0123";

    fn two_needles() -> Vec<SecretNeedle> {
        vec![
            needle(),
            SecretNeedle::named("short-token", SHORT_VALUE.to_vec()),
        ]
    }

    /// One message of a generated conversation, as its sender wrote it.
    #[derive(Debug, Clone)]
    struct Sent {
        binary: bool,
        text: Vec<u8>,
        /// Sent compressed, which only a direction that negotiated compression does.
        compressed: bool,
        /// Where the payload on the wire is cut into frames.
        cuts: Vec<proptest::sample::Index>,
        /// Each frame's mask key, in turn.
        masks: Vec<Option<[u8; 4]>>,
        /// Control frames sent after one of its frames: after which, the opcode, the payload.
        controls: Vec<(proptest::sample::Index, u8, Vec<u8>)>,
    }

    /// A direction's negotiated compression as the tee is told it (`Some(no_context_takeover)`),
    /// the messages sent down it, and the payload of the close that ends it, if one does.
    #[derive(Debug, Clone)]
    struct Conversation {
        deflate: Option<bool>,
        sent: Vec<Sent>,
        /// Last when sent at all: RFC 6455 §5.5.1 has nothing sent after a close.
        close: Option<Vec<u8>>,
    }

    /// Text made of pieces: arbitrary bytes, the two declared values, and the halves of one, so a
    /// value may be whole, cut by a frame boundary, or absent.
    fn texts() -> impl proptest::strategy::Strategy<Value = Vec<u8>> {
        use proptest::prelude::{Just, any, prop_oneof};
        use proptest::strategy::Strategy;
        proptest::collection::vec(
            prop_oneof![
                3 => proptest::collection::vec(any::<u8>(), 0..24),
                1 => Just(NEEDLE_VALUE.to_vec()),
                1 => Just(SHORT_VALUE.to_vec()),
                1 => Just(NEEDLE_VALUE[..9].to_vec()),
                1 => Just(NEEDLE_VALUE[9..].to_vec()),
            ],
            0..5,
        )
        .prop_map(|pieces| pieces.concat())
    }

    /// Conversations of up to four messages, each in one to three frames, masked or not, with
    /// pings and pongs between or after them, and now and then a close to end them. A compressed
    /// message is now and then preceded by [`PAD`] bytes of padding, far past what any capture here
    /// keeps.
    fn conversations() -> impl proptest::strategy::Strategy<Value = Conversation> {
        use proptest::prelude::{Just, any, prop_oneof};
        use proptest::sample::Index;
        use proptest::strategy::Strategy;
        let control =
            (prop_oneof![Just(0x9u8), Just(0xa)], texts()).prop_map(|(opcode, mut payload)| {
                payload.truncate(CONTROL_MAX);
                (opcode, payload)
            });
        let sent = (
            (
                any::<bool>(),
                texts(),
                any::<bool>(),
                proptest::bool::weighted(0.05),
            ),
            proptest::collection::vec(any::<Index>(), 0..3),
            proptest::collection::vec(proptest::option::of(any::<[u8; 4]>()), 1..3),
            proptest::collection::vec((any::<Index>(), control), 0..3),
        )
            .prop_map(
                |((binary, text, compressed, padded), cuts, masks, controls)| {
                    let controls = controls
                        .into_iter()
                        .map(|(after, (opcode, payload))| (after, opcode, payload))
                        .collect();
                    (
                        padded,
                        Sent {
                            binary,
                            text,
                            compressed,
                            cuts,
                            masks,
                            controls,
                        },
                    )
                },
            );
        (
            proptest::option::of(any::<bool>()),
            proptest::collection::vec(sent, 0..5),
            proptest::option::of(texts()),
        )
            .prop_map(|(deflate, sent, close)| Conversation {
                deflate,
                close: close.map(|mut payload| {
                    payload.truncate(CONTROL_MAX);
                    payload
                }),
                sent: sent
                    .into_iter()
                    .map(|(padded, mut sent)| {
                        sent.compressed &= deflate.is_some();
                        if padded && sent.compressed {
                            let mut text = vec![b'a'; PAD];
                            text.append(&mut sent.text);
                            sent.text = text;
                        }
                        sent
                    })
                    .collect(),
            })
    }

    /// The bytes a conversation puts on the wire.
    fn wire(talk: &Conversation) -> Vec<u8> {
        use miniz_oxide::deflate::core::CompressorOxide;
        let mut window = CompressorOxide::new(raw_deflate_flags());
        let mut out = Vec::new();
        for sent in &talk.sent {
            let payload = match (sent.compressed, talk.deflate) {
                (true, Some(true)) => {
                    deflated(&sent.text, &mut CompressorOxide::new(raw_deflate_flags()))
                }
                (true, _) => deflated(&sent.text, &mut window),
                (false, _) => sent.text.clone(),
            };
            let mut bounds: Vec<usize> = sent
                .cuts
                .iter()
                .map(|at| at.index(payload.len() + 1))
                .collect();
            bounds.extend([0, payload.len()]);
            bounds.sort_unstable();
            bounds.dedup();
            if bounds.len() == 1 {
                bounds.push(0);
            }
            let frames = bounds.len() - 1;
            for (i, span) in bounds.windows(2).enumerate() {
                let opcode = match (i, sent.binary) {
                    (0, true) => 0x2,
                    (0, false) => 0x1,
                    _ => 0x0,
                };
                let mask = sent.masks[i % sent.masks.len()];
                let mut bytes =
                    frame_with_fin(opcode, &payload[span[0]..span[1]], mask, i + 1 == frames);
                if sent.compressed && i == 0 {
                    bytes[0] |= 0x40;
                }
                out.extend(bytes);
                for (after, opcode, control) in &sent.controls {
                    if after.index(frames) == i {
                        out.extend(frame(*opcode, control, mask));
                    }
                }
            }
        }
        if let Some(close) = &talk.close {
            out.extend(frame(0x8, close, None));
        }
        out
    }

    /// Push `wire` through `tee` in pieces of `sizes`, taken in turn, and gather what it names.
    fn fed(tee: &mut FrameTee, wire: &[u8], sizes: &[usize]) -> Vec<String> {
        let mut named = Vec::new();
        let (mut at, mut turn) = (0, 0);
        while at < wire.len() {
            let n = sizes[turn % sizes.len()].min(wire.len() - at);
            tee.push(&wire[at..at + n]);
            named.extend(tee.sightings());
            at += n;
            turn += 1;
        }
        named.sort();
        named
    }

    /// The consumers a direction may have: a capture of one of a few sizes, the scan, or both.
    fn consumers() -> impl proptest::strategy::Strategy<Value = (Option<usize>, bool)> {
        use proptest::prelude::any;
        use proptest::strategy::Strategy;
        (
            proptest::option::of(proptest::sample::select(vec![1usize, 7, 40, 4096])),
            any::<bool>(),
        )
            .prop_map(|(cap, scan)| (cap, scan || cap.is_none()))
    }

    fn tee_for(
        cap: Option<usize>,
        scan: bool,
        deflate: Option<bool>,
    ) -> (FrameTee, Option<Arc<CapBuf>>) {
        let sink = cap.map(|cap| Arc::new(CapBuf::new(cap)));
        let needles = if scan { two_needles() } else { Vec::new() };
        let tee = FrameTee::new(sink.clone(), &needles, deflate, false).expect("a consumer");
        (tee, sink)
    }

    proptest::proptest! {
        #![proptest_config(proptest::prelude::ProptestConfig::with_cases(4096))]

        /// Whatever pieces a conversation arrives in, the capture holds its messages' text, cut at
        /// the capture's size and marked cut when it was, and the scan names every declared value
        /// that one message or one control frame carried, reading on to the end. The expectation
        /// is read off the messages as they were written, not off the bytes.
        #[test]
        fn a_conversation_is_captured_and_scanned_as_it_was_written_in_any_pieces(
            talk in conversations(),
            (cap, scan) in consumers(),
            sizes in proptest::collection::vec(1usize..40, 1..6),
        ) {
            let (mut tee, sink) = tee_for(cap, scan, talk.deflate);
            let named = fed(&mut tee, &wire(&talk), &sizes);
            let carried = |value: &[u8]| {
                let within = |text: &[u8]| text.windows(value.len()).any(|w| w == value);
                talk.sent.iter().any(|sent| {
                    within(&sent.text) || sent.controls.iter().any(|(_, _, c)| within(c))
                }) || talk.close.as_deref().is_some_and(within)
            };
            if scan {
                let mut expected: Vec<String> = two_needles()
                    .iter()
                    .filter(|n| carried(n.as_bytes()))
                    .map(|n| n.name().to_string())
                    .collect();
                expected.sort();
                proptest::prop_assert_eq!(named, expected);
                proptest::prop_assert!(!tee.done, "a scan reads a well-formed conversation to its end");
            }
            if let (Some(cap), Some(sink)) = (cap, sink) {
                let text: Vec<u8> = talk.sent.iter().flat_map(|s| s.text.iter().copied()).collect();
                let got = captured(&sink);
                proptest::prop_assert_eq!(&got.bytes[..], &text[..text.len().min(cap)]);
                proptest::prop_assert_eq!(got.truncated, text.len() > cap);
            }
        }

        /// Any bytes, a conversation's with bytes replaced, put in or taken out and more bytes
        /// behind it, are decoded alike whole and in pieces: the same capture, the same names,
        /// the same stop and the same report of going blind, and no panic.
        #[test]
        fn any_bytes_are_decoded_alike_whole_and_in_pieces(
            talk in conversations(),
            (cap, scan) in consumers(),
            edits in proptest::collection::vec(
                (proptest::prelude::any::<proptest::sample::Index>(), proptest::prelude::any::<u8>(), 0u8..3),
                0..4,
            ),
            tail in proptest::collection::vec(proptest::prelude::any::<u8>(), 0..64),
            sizes in proptest::collection::vec(1usize..40, 1..6),
        ) {
            let mut bytes = wire(&talk);
            bytes.extend(tail);
            for (at, byte, edit) in edits {
                if bytes.is_empty() {
                    break;
                }
                let at = at.index(bytes.len());
                match edit {
                    0 => bytes[at] = byte,
                    1 => bytes.insert(at, byte),
                    _ => {
                        bytes.remove(at);
                    }
                }
            }
            let (mut whole, whole_sink) = tee_for(cap, scan, talk.deflate);
            let (mut split, split_sink) = tee_for(cap, scan, talk.deflate);
            let whole_named = fed(&mut whole, &bytes, &[bytes.len().max(1)]);
            proptest::prop_assert_eq!(fed(&mut split, &bytes, &sizes), whole_named);
            proptest::prop_assert_eq!(split.done, whole.done);
            proptest::prop_assert_eq!(split.newly_blinded(), whole.newly_blinded());
            if let (Some(split), Some(whole)) = (split_sink, whole_sink) {
                proptest::prop_assert_eq!(captured(&split), captured(&whole));
            }
        }
    }
}
