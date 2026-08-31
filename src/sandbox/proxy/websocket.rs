//! WebSocket proxying for the inspected (MITM) TLS path.
//!
//! Once a decrypted request is permitted and turns out to be a `Upgrade: websocket`
//! handshake, the proxy stops parsing HTTP and relays the raw bidirectional byte stream
//! between the in-cage client and the validated upstream. These helpers detect the
//! upgrade, reserialize the upgrade request/response, and pump the two directions.

use super::capture::{CapBuf, CaptureGuard};
use super::*;
use crate::sandbox::control::SecretWay;
use miniz_oxide::inflate::stream::{InflateState, inflate};
use miniz_oxide::{DataFormat, MZFlush, MZStatus};

/// The traffic capture's decoder for one direction of an established WebSocket: it follows the frame
/// framing as the bytes are relayed and copies each data frame's payload into a capped sink.
///
/// Decoding is forced by the protocol, not a presentation choice. A payload is preceded by a
/// variable-length header, and a frame the client sends is XOR-masked with a per-frame key, so the
/// bytes as they cross are not readable as themselves; unmasking recovers exactly what the sender
/// sent, nothing more. (RFC 6455 masking exists to stop intermediaries being tricked into cache
/// poisoning; it carries no confidentiality, so undoing it reveals nothing that was protected.)
///
/// When `permessage-deflate` is negotiated the payloads are DEFLATE-compressed per *message*, so
/// they are reassembled across the message's frames and inflated before being captured; see
/// [`Inflater`]. Control frames (close, ping, pong) are not part of the message transcript, so
/// nothing they carry is captured, and they may interleave a fragmented message without disturbing
/// its reassembly. They are still **scanned**, though: RFC 6455 §5.5.2 and §5.5.3 both allow a ping
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
    /// value straddling the split would otherwise be missed, and kept apart from [`Self::pending`]
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
    /// The compressed payload of the message being reassembled. Non-empty only while a compressed
    /// message is in flight; a compressed message can only be inflated once it is whole, since
    /// DEFLATE is per-message here.
    pending: Vec<u8>,
    /// Whether the message currently being reassembled is compressed (`RSV1` on its first frame).
    /// A continuation frame inherits it, so it is tracked per message rather than per frame.
    compressed: bool,
    /// Whether the data frame being decoded ends its message.
    fin: bool,
}

/// The most plaintext the leak scan asks the decoder to produce out of one compressed message.
///
/// A bound is needed because a compressed message can inflate to far more than it cost to send. It
/// is generous next to anything that would plausibly carry a leaked credential, and a message that
/// inflates past it is scanned up to it — never silently claimed to have been scanned whole.
const SCAN_MESSAGE_CAP: usize = 256 * 1024;

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
/// stream whose final empty block is elided, so the four bytes `00 00 FF FF` are appended before
/// inflating. And unless the peer announced `*_no_context_takeover`, the compression window carries
/// across messages: the state must persist, or every message after the first inflates to garbage.
struct Inflater {
    state: Box<InflateState>,
    /// Whether the peer resets its window per message, in which case so must this.
    no_context_takeover: bool,
    /// The budget [`Self::drain`] works to, from [`RESYNC_PLAINTEXT_CAP`].
    ///
    /// A field rather than the constant read straight from the function, so a test can reach the
    /// give-up path — the one that reports a window it could not square — without inflating
    /// sixty-four megabytes to get there. Production has exactly one value for it.
    resync_cap: usize,
}

impl Inflater {
    fn new(no_context_takeover: bool) -> Self {
        Inflater {
            state: InflateState::new_boxed(DataFormat::Raw),
            no_context_takeover,
            resync_cap: RESYNC_PLAINTEXT_CAP,
        }
    }

    /// Inflate one whole message, keeping at most `cap + 1` bytes — one past the sink's capacity, so
    /// a message that overflows is seen as an overflow rather than as one that happened to fit.
    /// `None` means the stream did not decode, and the caller stops capturing this direction rather
    /// than storing rubbish.
    ///
    /// The cap bounds what is **kept**, never what is **decoded**: see [`Inflated::in_step`] for why
    /// the difference is the whole of this direction's leak scan.
    fn message(&mut self, compressed: &[u8], cap: usize) -> Option<Inflated> {
        let mut input: Vec<u8> = Vec::with_capacity(compressed.len() + 4);
        input.extend_from_slice(compressed);
        input.extend_from_slice(&[0x00, 0x00, 0xff, 0xff]);

        let limit = cap.saturating_add(1);
        let mut out = vec![0u8; limit.clamp(1, 16 * 1024)];
        let mut written = 0usize;
        let mut read = 0usize;
        loop {
            let res = inflate(
                &mut self.state,
                &input[read..],
                &mut out[written..],
                MZFlush::None,
            );
            read += res.bytes_consumed;
            written += res.bytes_written;
            match res.status {
                Ok(MZStatus::Ok | MZStatus::StreamEnd) => {}
                // A truncated or corrupt stream: refuse it rather than store a partial guess.
                Err(_) => return None,
                _ => {}
            }
            if written >= limit {
                break;
            }
            if written == out.len() {
                // The output buffer filled: grow it, still bounded by `limit`, and go round again.
                // Whether or not the input is spent — a back-reference goes on unrolling into the
                // output long after the few bytes naming it were read, so "the input is consumed"
                // does not mean "the message is out". Stopping here on a spent input would drop
                // whatever was still coming, which for a message whose length lands on one of these
                // doublings is its tail: a truncated transcript, and a secret in those bytes
                // unseen by a scan that reported nothing.
                let grown = (out.len() * 2).min(limit);
                if grown == out.len() {
                    break;
                }
                out.resize(grown, 0);
                continue;
            }
            // Room was left over, so the decoder emitted everything it had: with the input spent
            // too, the message is whole.
            if read >= input.len() {
                break;
            }
            if res.bytes_consumed == 0 && res.bytes_written == 0 {
                // No progress and no room needed: the decoder wants more input than this message
                // has, which for a whole message means the stream is not what it claimed.
                return None;
            }
        }
        out.truncate(written);
        // A peer that resets its window per message shares nothing across them, so a message the cap
        // cut short costs the next one nothing: reset, and the decoder is in step by construction.
        if self.no_context_takeover {
            self.state.reset(DataFormat::Raw);
            return Some(Inflated {
                plain: out,
                in_step: true,
            });
        }
        // Otherwise the window carries across messages, and the bytes past the cap are part of it.
        // Inflate the rest and throw it away, so the window this message leaves behind is the one
        // the peer has. The loop above exits with input pending *only* on the cap — its other exits
        // both require the input consumed — so this is exactly the overflow path.
        let in_step = read >= input.len() || self.drain(&input[read..]);
        Some(Inflated {
            plain: out,
            in_step,
        })
    }

    /// Inflate the rest of a message the plaintext cap cut short, discarding every byte it yields,
    /// so this direction's window ends the message holding what the peer's does.
    ///
    /// Bounded like everything else here that inflates hostile input, but on a different axis from
    /// the cap it is recovering from: the discard buffer is one fixed block reused to the end, so the
    /// *memory* cost is constant however far the message inflates, and [`RESYNC_PLAINTEXT_CAP`]
    /// bounds the *work*. Returns whether the input was consumed — `false` leaves the decoder out of
    /// step, and is the caller's signal to stop this direction rather than decode the rest wrongly.
    fn drain(&mut self, mut rest: &[u8]) -> bool {
        let mut scratch = vec![0u8; 16 * 1024];
        let mut inflated = 0usize;
        loop {
            let res = inflate(&mut self.state, rest, &mut scratch, MZFlush::None);
            match res.status {
                Ok(MZStatus::Ok | MZStatus::StreamEnd) => {}
                Err(_) => return false,
                _ => {}
            }
            rest = &rest[res.bytes_consumed..];
            inflated = inflated.saturating_add(res.bytes_written);
            if inflated > self.resync_cap {
                return false;
            }
            // Square only when the input is spent *and* the decoder stopped short of filling the
            // block — the same distinction the capped loop above draws, and for the same reason: a
            // back-reference keeps unrolling after its token is read, and those bytes are precisely
            // the window this is here to rebuild.
            if rest.is_empty() && res.bytes_written < scratch.len() {
                return true;
            }
            // No progress with a whole empty block to write into: the stream is not what it claimed,
            // or it has ended with input still behind it. Either way the window cannot be squared.
            if res.bytes_consumed == 0 && res.bytes_written == 0 {
                return false;
            }
        }
    }
}

/// What inflating one message yielded, and whether the decoder can still be trusted after it.
struct Inflated {
    /// The plaintext, capped at one byte past what this direction's consumers could use.
    plain: Vec<u8>,
    /// Whether this direction's decoder is still level with the peer's compressor.
    ///
    /// Under `permessage-deflate` with context takeover — the default, since `no_context_takeover`
    /// has to be announced — one window carries across a direction's messages. A message stopped at
    /// the plaintext cap therefore leaves the decoder holding a window the peer does not share, and
    /// **every later message on this direction decodes to rubbish or not at all**: the capture stores
    /// noise and the leak scan sees none of the values it exists to catch. That is a security control
    /// the cage switches off at will — one large compressible message, then exfiltrate freely down
    /// the same tunnel — so the overflow path inflates the remainder rather than abandoning it, and
    /// this reports the case where even that could not square the window.
    in_step: bool,
}

/// The most plaintext [`Inflater::drain`] will inflate and discard to bring one direction's window
/// back level with the peer's.
///
/// Squaring the window means inflating every byte the peer put in it — there is no shortcut, so the
/// bound is on work rather than on memory (the discard buffer is a single reused block). It is set
/// far above any message a real peer sends and far below what one message could be made to cost: the
/// compressed input is already held to [`FrameTee::compressed_budget`], and DEFLATE's ratio tops out
/// near 1000:1, so without a bound here one crafted message could ask for a gigabyte of inflate.
/// A message past this is not decoded further; the direction stops instead, which is the same answer
/// the compressed budget and a failed decode already give.
const RESYNC_PLAINTEXT_CAP: usize = 64 * 1024 * 1024;

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
pub(super) fn negotiated_deflate(resp_head: &[u8]) -> Deflate {
    let head = String::from_utf8_lossy(resp_head);
    let Some(value) = head.lines().find_map(|line| {
        let (name, value) = line.split_once(':')?;
        name.trim()
            .eq_ignore_ascii_case("sec-websocket-extensions")
            .then(|| value.trim())
    }) else {
        return Deflate::default();
    };
    // One negotiated extension per comma-separated entry, and every one of them has to be the
    // deflate entry — see the doc above for why an entry beside it is not skipped past.
    let mut negotiated: Option<Deflate> = None;
    for entry in value.split(',') {
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
    /// `None` when the extension was not agreed, so nothing is reassembled or inflated.
    ///
    /// Returns `None` when neither consumer is present, so a tunnel that neither captures nor scans
    /// is relayed without the framing being followed at all.
    pub(super) fn new(
        sink: Option<Arc<CapBuf>>,
        needles: &[SecretNeedle],
        deflate: Option<bool>,
    ) -> Option<Self> {
        let scan = LeakScan::new(needles);
        if sink.is_none() && scan.is_none() {
            return None;
        }
        Some(FrameTee {
            sink,
            sink_full: false,
            scan,
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
            pending: Vec::new(),
            compressed: false,
            fin: false,
        })
    }

    /// Hand one decoded piece to whichever consumers are present, and report whether the capture
    /// sink filled **on this piece** — asked once, so a full sink cannot re-trigger on every later
    /// read. The scan sees the same piece whether or not the capture is still taking bytes: what is
    /// retained for a human to read and what is watched for a leak are different questions.
    fn consume(&mut self, piece: &[u8]) -> bool {
        if let Some(scan) = self.scan.as_mut() {
            scan.take(piece);
        }
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
    /// capture is full and there is no scan to keep going for.
    fn spent(&self) -> bool {
        self.sink_full && self.scan.is_none()
    }

    /// Whether this direction's leak tripwire has *just* gone blind: the decoder gave up on the
    /// framing while a scan was still configured, so nothing crossing from here on is watched.
    ///
    /// Reported once, like a sighting.
    ///
    /// [`Self::done`] is the right answer for the capture, whose transcript honestly ends at the last
    /// message it decoded — but it is not an answer for the scan. This file already states the rule
    /// ([`Inflated::in_step`]): a decoder that goes blind mid-tunnel is "a security control the cage
    /// switches off at will", which is the whole reason the resync machinery exists. That machinery
    /// closed one door; the compressed budget above closes on another, for a single protocol-legal
    /// message, and `done` was invisible outside the tee — so `follow` reported no sighting, the
    /// relay kept forwarding, and `websocket_secret = block` could never fire again on that tunnel.
    /// Reporting it lets the relay treat a blinded direction as what it is.
    fn newly_blinded(&mut self) -> bool {
        if !self.done || self.scan.is_none() || self.blind_reported {
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
                                // A new message: whether it is compressed is decided here and
                                // inherited by its continuation frames, and nothing carries across
                                // the boundary for the scan.
                                self.compressed = rsv1 && self.inflater.is_some();
                                self.pending.clear();
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
                let mut piece = chunk[at..at + take].to_vec();
                if let Some(key) = self.mask {
                    for (n, byte) in piece.iter_mut().enumerate() {
                        *byte ^= key[(self.mask_at as usize + n) % 4];
                    }
                }
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
                    // A compressed message is only decodable whole, so it is held until its last
                    // frame. Bounded by what its consumers could ever use: past that, inflating more
                    // would yield bytes nobody reads, and stopping mid-message leaves the shared
                    // window out of step, so this direction stops here rather than decoding the rest
                    // wrongly.
                    if self.pending.len() + piece.len() > self.compressed_budget() {
                        // Nothing is consumed on the way out. `piece` is raw DEFLATE — consuming it
                        // filed the compressor's output in the transcript as if it were the
                        // message's text, and handed the scan bytes no needle can ever match. The
                        // transcript ends at the last message actually decoded, which is the answer
                        // the failed-decode path in `end_of_frame` already gives. With a scan
                        // configured the relay is told as well ([`Self::newly_blinded`]): one
                        // protocol-legal message the cage chooses the size of would otherwise switch
                        // the tripwire off for the rest of the tunnel with nothing said.
                        self.done = true;
                        break;
                    }
                    self.pending.extend_from_slice(&piece);
                } else {
                    filled |= self.consume(&piece);
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

    /// The most plaintext one compressed message is decoded into, which is whatever its consumers
    /// could actually use: the capture keeps up to its own cap, while the leak scan wants the whole
    /// message, since a value past the capture's cap is exactly the one worth reporting.
    fn plaintext_cap(&self) -> usize {
        let capture = self.sink.as_ref().map_or(0, |s| s.cap());
        let scan = if self.scan.is_some() {
            SCAN_MESSAGE_CAP
        } else {
            0
        };
        capture.max(scan)
    }

    /// The most compressed bytes held for one message. Generous against what that message could
    /// yield, since compression is the point: a message that inflates to far more than this is cut
    /// by its consumers, not here.
    fn compressed_budget(&self) -> usize {
        self.plaintext_cap().saturating_mul(4).max(64 * 1024)
    }

    /// Settle a frame that has just ended. A compressed message becomes capturable only now, on its
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
        let compressed = std::mem::take(&mut self.pending);
        let cap = self.plaintext_cap();
        let Some(inflater) = self.inflater.as_mut() else {
            return false;
        };
        match inflater.message(&compressed, cap) {
            Some(inflated) => {
                // The message arrives whole here, so the scan needs no carry on this path — it is
                // handed the one payload it was going to reassemble anyway.
                if let Some(scan) = self.scan.as_mut() {
                    scan.start_message();
                }
                let filled = self.consume(&inflated.plain);
                if !inflated.in_step {
                    // The window could not be brought back level with the peer's, so every later
                    // message on this direction would decode to rubbish. Stop, rather than scan
                    // noise and report nothing — the same answer the compressed budget above and a
                    // failed decode below already give.
                    self.done = true;
                }
                if self.spent() {
                    self.done = true;
                }
                if filled {
                    return true;
                }
            }
            None => {
                // The stream did not decode. Every later message shares its window, so nothing
                // further can be trusted for this direction.
                self.done = true;
            }
        }
        false
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

/// Whether a decrypted request head is a WebSocket upgrade: `Upgrade: websocket` together with a
/// `Connection` header listing the `upgrade` token (both case-insensitive; `Connection` is a
/// comma-separated token list). Both are required — an `Upgrade` header without `Connection:
/// upgrade` is not an upgrade a client will complete, so it stays on the normal request path.
pub(super) fn is_websocket_upgrade(head: &Head) -> bool {
    let names_token = |header: &str, token: &str| {
        head.header(header)
            .map(|v| v.split(',').any(|t| t.trim().eq_ignore_ascii_case(token)))
            .unwrap_or(false)
    };
    names_token("upgrade", "websocket") && names_token("connection", "upgrade")
}

/// Reserialize a WebSocket upgrade handshake for forwarding upstream. Like [`reserialize_request`]
/// it injects any matching credential and strips the client's copy of an injected header, but it
/// PRESERVES the hop-by-hop `Connection`/`Upgrade` headers (and the `Sec-WebSocket-*` set) so the
/// upstream actually performs the upgrade — the opposite of the normal path, which forces
/// `Connection: close`. `Proxy-Connection` and `Expect` are still stripped (proxy-local hop headers).
pub(super) fn reserialize_upgrade(head: &Head, injections: &[(String, String)]) -> Vec<u8> {
    let mut out = String::with_capacity(head.request_line.len() + 64);
    out.push_str(&head.request_line);
    out.push_str("\r\n");
    for (k, v) in &head.headers {
        if k.eq_ignore_ascii_case("proxy-connection")
            || k.eq_ignore_ascii_case("expect")
            // A credential the client addressed to the proxy hop, never to the origin server —
            // the same rule `reserialize_request` states for every other request, and it was
            // missing only here and on the h2 rebuild. `Connection` is deliberately *not* stripped
            // alongside it: an upgrade needs its `Connection: Upgrade` to survive.
            || k.eq_ignore_ascii_case("proxy-authorization")
        {
            continue;
        }
        if injections.iter().any(|(name, _)| header_name_eq(k, name)) {
            continue;
        }
        out.push_str(k);
        out.push_str(": ");
        out.push_str(v);
        out.push_str("\r\n");
    }
    for (name, value) in injections {
        out.push_str(name);
        out.push_str(": ");
        out.push_str(value);
        out.push_str("\r\n");
    }
    out.push_str("\r\n");
    out.into_bytes()
}

/// Forward an allowed WebSocket upgrade and, on a `101`, relay the two TLS streams bidirectionally.
/// The handshake was already inspected by the same verdict as any request (host / path / method /
/// anti-fronting / SSRF / upstream-cert), so the allowlist still governs which host and path may open
/// a WebSocket; from the `101` on, the framed bytes are opaque and relayed verbatim. If the upstream
/// declines the upgrade (any non-`101`), its response is relayed as a normal one and the tunnel closes.
///
/// Takes `br` and `upstream` by value: the response phase owns both streams, and on the `101` path the
/// buffered bytes each `BufReader` read past its head are handed to [`relay_websocket`] to flush first.
///
/// `capture` is the traffic capture of the handshake, already carrying the client's request head. A
/// declined upgrade is captured like any other response (head and body); an accepted one is captured
/// up to and including the `101` and filed there — see the `101` branch for why it cannot wait.
#[allow(clippy::too_many_arguments)]
pub(super) fn relay_upgrade(
    mut br: BufReader<StreamOwned<ServerConnection, UnixStream>>,
    mut upstream: StreamOwned<ClientConnection, TcpStream>,
    inner: &Head,
    injected: &[(String, String)],
    ctx: &ProxyCtx,
    allow_seq: Option<u64>,
    capture: Option<&CaptureGuard>,
    up: Arc<AtomicU64>,
    down: Arc<AtomicU64>,
) -> io::Result<()> {
    // Forward the handshake with its upgrade headers preserved (a handshake carries no body).
    let handshake = reserialize_upgrade(inner, injected);
    upstream.write_all(&handshake)?;
    up.fetch_add(handshake.len() as u64, Ordering::Relaxed);
    upstream.flush().ok();

    // Read the upstream's response head. A BufReader may read past it into the server's first frames;
    // those buffered bytes are drained below so none is lost.
    let mut up_br = BufReader::new(upstream);
    let resp_head = read_head_buffered(&mut up_br, HEAD_MAX, head_deadline(ctx))?;

    if parse_status_code(&resp_head) != Some(101) {
        // The upstream declined the upgrade — relay its response as a normal one, then close. The
        // upstream keeps the read timeout it was given (the handshake did not force `Connection:
        // close`), so a keep-alive response without an EOF is bounded by that timeout, not hung.
        if let Some(code) = parse_status_code(&resp_head)
            && code >= 200
        {
            ctx.set_status(allow_seq, code);
        }
        br.get_mut().write_all(&resp_head)?;
        down.fetch_add(resp_head.len() as u64, Ordering::Relaxed);
        // A declined upgrade is an ordinary response — capture its head, then tee its body like any
        // other. The guard files when this handler returns.
        if let Some(c) = capture {
            c.push_response(&resp_head);
        }
        // Framed like any ordinary response, so the relay ends at the end of the message. The
        // handshake was a `GET`, so no bodiless-method rule applies here.
        let framing = response_framing(&resp_head, "GET");
        // Count the declined response body (`down`) as it streams back to the client.
        let counted = CountingReader::new(FramedBody::new(up_br, framing), down.clone());
        let mut body: Box<dyn Read + '_> = match capture {
            Some(c) => Box::new(CaptureReader::new(counted, c.response_sink())),
            None => Box::new(counted),
        };
        pump_to_eof(&mut body, br.get_mut())?;
        finish_tls(br.get_mut());
        return Ok(());
    }

    // What the peers agreed for payload compression, decided by this response alone.
    let deflate = negotiated_deflate(&resp_head);
    ctx.set_status(allow_seq, 101);
    // Relay the `101` to the client so it completes the WebSocket handshake.
    br.get_mut().write_all(&resp_head)?;
    br.get_mut().flush()?;
    down.fetch_add(resp_head.len() as u64, Ordering::Relaxed);
    // Capture the handshake and file it here rather than letting the guard file on return: a
    // WebSocket tunnel can stay open for hours and the log event carries exactly one amendment, so a
    // capture held open would keep the `101` out of `sbx net logs` until the tunnel closed. What is
    // captured is the handshake, both heads; the frames past it are opaque (masked, framed binary)
    // and are not captured.
    if let Some(c) = capture {
        c.push_response(&resp_head);
        c.file_now();
    }
    // Drain what each BufReader already read past its head, then relay the raw TLS streams.
    let upstream_pending = up_br.buffer().to_vec();
    let upstream = up_br.into_inner();
    let client_pending = br.buffer().to_vec();
    let client = br.into_inner();
    // The host this tunnel is bound for, which decides which learned credential the leak tripwire
    // scans for. Read off the handshake's own `Host` rather than threaded down from the CONNECT:
    // `serve_tunneled_request` refuses the request outright unless the CONNECT target, the SNI and
    // this header all canonicalize to the same name, so there is one host here and not two.
    let dest = inner.header("host").map(strip_port).unwrap_or_default();
    relay_websocket(
        client,
        &client_pending,
        upstream,
        &upstream_pending,
        deflate,
        &dest,
        TunnelObservers {
            up,
            down,
            capture,
            ctx,
            seq: allow_seq,
        },
    )
}

/// Flush a rustls connection's pending TLS output to its (non-blocking) socket, stopping when the
/// buffer is drained or the socket would block (the rest goes out on the next `POLLOUT`).
pub(super) fn flush_tls<D: rustls::SideData>(
    conn: &mut rustls::ConnectionCommon<D>,
    sock: &mut impl Write,
) -> io::Result<()> {
    while conn.wants_write() {
        match conn.write_tls(sock) {
            Ok(0) => break,
            Ok(_) => {}
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

/// Read available plaintext from a rustls connection over its (non-blocking) socket: `Some(n>0)` for
/// plaintext, `Some(0)` for end of stream (clean `close_notify` or a socket EOF), `None` when the
/// socket would block (no more data right now — wait for the next `POLLIN`). A partial TLS record
/// yields `None` rather than blocking.
pub(super) fn read_plaintext<D: rustls::SideData>(
    conn: &mut rustls::ConnectionCommon<D>,
    sock: &mut impl Read,
    buf: &mut [u8],
) -> io::Result<Option<usize>> {
    loop {
        match conn.reader().read(buf) {
            Ok(n) => return Ok(Some(n)),
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
            // An unclean peer close (a TCP FIN with no TLS `close_notify`) surfaces here as
            // `UnexpectedEof`; for a byte relay that is simply end-of-stream, the same as a clean
            // close, so treat it as EOF and half-close this direction rather than failing the relay.
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(Some(0)),
            Err(e) => return Err(e),
        }
        match conn.read_tls(sock) {
            Ok(0) => return Ok(Some(0)),
            Ok(_) => {
                conn.process_new_packets().map_err(io::Error::other)?;
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => return Ok(None),
            Err(e) => return Err(e),
        }
    }
}

/// Everything an established tunnel reports its activity to, gathered so the relay and its decoders
/// pass one value rather than five. They travel together because they answer one question between
/// them — what crossed this tunnel — for three different readers: `sbx net live` (the byte
/// counters), `sbx net logs --with-body` (the transcript), and a secret sighting on the event.
pub(super) struct TunnelObservers<'a> {
    /// Bytes cage → upstream, for the live flow view.
    pub(super) up: Arc<AtomicU64>,
    /// Bytes upstream → cage.
    pub(super) down: Arc<AtomicU64>,
    /// The capture the transcript is filed into, when this launch captures bodies.
    pub(super) capture: Option<&'a CaptureGuard>,
    /// The context a secret sighting is recorded through.
    pub(super) ctx: &'a ProxyCtx,
    /// The log event a sighting amends, or `None` when nothing was logged (tests).
    pub(super) seq: Option<u64>,
}

/// Push one direction's bytes through its decoder and act on both things that can come of it: file
/// the transcript when the capture has just filled, and report a configured secret newly seen
/// crossing. One place, so a call site cannot follow the framing and then forget half of it.
///
/// The transcript is filed whenever a direction reaches its cap, and once more when the tunnel ends
/// (in the capture guard's teardown). Each direction has its own trigger, and each fires at most
/// once: one side of a live stream can fill in seconds while the other trickles for hours, so a
/// single shared trigger would strand whichever filled second. The guard drops a filing that would
/// show what it already showed, which is what keeps the count bounded.
fn follow(
    tee: &mut Option<FrameTee>,
    chunk: &[u8],
    way: SecretWay,
    obs: &TunnelObservers,
) -> Followed {
    let Some(tee) = tee.as_mut() else {
        return Followed::default();
    };
    if tee.push(chunk)
        && let Some(c) = obs.capture
    {
        c.file_frames_snapshot();
    }
    let mut out = Followed {
        seen: false,
        blinded: tee.newly_blinded(),
    };
    for name in tee.sightings() {
        obs.ctx.websocket_secret_seen(obs.seq, &name, way);
        out.seen = true;
    }
    out
}

/// What one pass of a direction's decoder concluded, beyond the bytes it moved.
///
/// Two facts rather than one, because the relay owes each a different answer: a sighting is what
/// `websocket_secret` decides on, and a decoder that stopped is the tunnel losing the control that
/// would make that decision at all.
#[derive(Default)]
struct Followed {
    /// A configured secret was newly seen crossing this direction.
    seen: bool,
    /// The decoder just gave up on the framing while a leak scan was configured — see
    /// [`FrameTee::newly_blinded`].
    blinded: bool,
}

/// The needles a tunnel bound for `dest` scans for, on the same rule the request planes use
/// ([`SecretNeedle::scanned_for`]): every declared secret, and every credential the cage *learned*
/// except on the host it was learned from.
///
/// Scanning the whole set here contradicted that rule on the one path where it costs the most. A
/// tunnel to `chat.example` carries the session token the app obtained from `chat.example` in its
/// very first frame; the tripwire read it as a leak, and under `[network] websocket_secret = block`
/// closed the socket the app had just opened — the app cutting its own session off, reported as an
/// exfiltration attempt. The way back is filtered on the same set, so the credential's own service
/// echoing it is not filed as a secret that "came back" either.
fn tunnel_needles(needles: &[SecretNeedle], dest: &str) -> Vec<SecretNeedle> {
    needles
        .iter()
        .filter(|n| n.scanned_for(dest))
        .cloned()
        .collect()
}

/// Hand the cage's pending bytes — the frames it sent behind its handshake, before the `101` — to
/// the outbound tripwire, and then, only if they are allowed to cross, to the upstream.
///
/// One function because the **order** is the property rather than an ordering detail.
///
/// [`crate::allowlist::WebsocketSecret::Block`] states its guarantee in those terms — "the scan runs
/// on each chunk read from the cage, before that chunk is written on, so a secret whole inside one
/// chunk never crosses" — and the relay loop keeps it for every chunk it reads. On this one chunk it
/// was inverted: the frames were written into the upstream's rustls send buffer first, and what
/// follows a sighting is `send_close_notify` + [`flush_tls`], which drains the already-encrypted
/// application data ahead of the close_notify. The secret was delivered and the tunnel was closed
/// behind it — available exactly once per tunnel, on the ~8 KiB a cage that does not wait for the
/// `101` gets to choose.
///
/// A direction whose decoder has *stopped* is refused on the same terms as a sighting: under `block`
/// a tunnel this posture can no longer police must end rather than relay bytes nothing is watching.
fn seed_outbound_pending(
    to_upstream: &mut impl Write,
    pending: &[u8],
    tee: &mut Option<FrameTee>,
    obs: &TunnelObservers,
    blocking: bool,
) -> io::Result<SeededPending> {
    let followed = follow(tee, pending, SecretWay::Out, obs);
    if blocking && (followed.seen || followed.blinded) {
        return Ok(SeededPending {
            followed,
            crossed: false,
        });
    }
    to_upstream.write_all(pending)?;
    Ok(SeededPending {
        followed,
        crossed: true,
    })
}

/// What became of the bytes the cage sent behind its handshake.
struct SeededPending {
    /// What the decoder concluded about them.
    followed: Followed,
    /// Whether they were written into the upstream. `false` means the outbound gate refused them —
    /// nothing was written, and the caller must close the tunnel without relaying anything.
    crossed: bool,
}

/// Relay an established bidirectional connection (a WebSocket) between the cage `client` and the
/// `upstream`, both TLS-terminated, until each direction closes. The handshake was inspected and
/// allowed; from here every byte is opaque (masked frames), relayed verbatim both ways.
///
/// Single-threaded and **non-blocking**: the two rustls `Connection`s cannot be read and written from
/// two threads without aliasing UB, so one thread multiplexes both directions with `poll`. Each
/// direction reads plaintext from its source and buffers it into the destination's rustls send buffer,
/// which is then drained to the socket; a source is not read while its destination still has unflushed
/// output (`wants_write()`), so the buffering is bounded and neither direction couples head-of-line
/// onto the other — a stalled reader on one side cannot block the other. Idle time is parked in `poll`
/// (never in a read), so a live-but-idle channel is never cut; a dead peer that neither sends nor
/// closes is bounded by the connection cap, as for the L4 splice. Each read-side EOF half-closes only
/// that direction (a `close_notify` to the peer), so the reverse direction drains fully before teardown.
/// The bytes each side already read past its head (`*_pending`) are the tunnel's first frames, not a
/// preamble: they go through the outbound gate before anything is written on, and are seeded into the
/// send buffers only once that gate has let them by.
pub(super) fn relay_websocket(
    mut client: StreamOwned<ServerConnection, UnixStream>,
    client_pending: &[u8],
    mut upstream: StreamOwned<ClientConnection, TcpStream>,
    upstream_pending: &[u8],
    deflate: Deflate,
    dest: &str,
    obs: TunnelObservers,
) -> io::Result<()> {
    // Only a body-keeping capture has anything to file for a tunnel, so it is narrowed once, here,
    // rather than re-tested at each use — which would leave two spellings of "the capture" in scope
    // and invite a later reader to reach for the wrong one.
    let obs = TunnelObservers {
        capture: obs.capture.filter(|c| c.keeps_body()),
        ..obs
    };
    let TunnelObservers { up, down, ctx, .. } = &obs;

    // One frame decoder per direction, present when this launch has something to do with the frames:
    // a traffic capture to fill, a configured secret to watch for, or both. They see exactly the
    // bytes the relay moves — starting with the ones each side already read past its handshake head,
    // which are frames like any other and would otherwise be missed. With neither consumer the
    // framing is not followed at all and the tunnel is a plain pipe.
    let capture = obs.capture;
    let (to_upstream, to_client) = match capture {
        Some(c) => {
            let (u, d) = c.ws_sinks();
            (Some(u), Some(d))
        }
        None => (None, None),
    };
    // Each direction is decompressed under the peer that COMPRESSES it: the cage's frames by the
    // client parameters, the upstream's by the server ones.
    let (up_deflate, down_deflate) = match deflate.negotiated {
        true => (
            Some(deflate.client_no_context_takeover),
            Some(deflate.server_no_context_takeover),
        ),
        false => (None, None),
    };
    let creds = ctx.credentials.snapshot();
    let needles = tunnel_needles(&creds.needles, dest);
    let mut tee_up = FrameTee::new(to_upstream, &needles, up_deflate);
    let mut tee_down = FrameTee::new(to_client, &needles, down_deflate);
    // The transcript is filed whenever a direction reaches its cap, and once more when the tunnel
    // ends (in the capture guard's teardown). Each direction has its own trigger, and each fires at
    // most once: one side of a live stream can fill in seconds while the other trickles for hours,
    // so a single shared trigger would strand whichever filled second. The guard drops a filing that
    // would show what it already showed, which is what keeps the count bounded.
    // Whether a secret leaving through this tunnel closes it, from `[network] websocket_secret`.
    // Read from the config policy rather than the effective one: a `--session` overlay amends the
    // rules and carries every setting through untouched, so the two answer the same and this one
    // costs no clone.
    let blocking = obs.ctx.policy.websocket_secret() == crate::allowlist::WebsocketSecret::Block;
    // Said on the supervisor's stderr, once per direction: the tunnel's own log event carries secret
    // *sightings*, and "the decoder stopped" is not one — filing it as a sighting would name a
    // credential that was never seen. What the reader needs to know is that from here the transcript
    // and the tripwire cover nothing, on a tunnel that may stay open for hours.
    let report_blind = |way: SecretWay| {
        let direction = match way {
            SecretWay::Out => "cage → upstream",
            SecretWay::Back => "upstream → cage",
        };
        crate::diag::warn(&format!(
            "the WebSocket frame decoder for `{dest}` lost the framing on the {direction} \
             direction: the outbound-secret tripwire and the traffic capture cover nothing further \
             on this tunnel"
        ));
    };
    // The bytes the cage already sent behind its handshake are the tunnel's first frames, not a
    // preamble, so they go through the outbound gate before they are written on — see
    // [`seed_outbound_pending`] for why that order is the property and not an ordering detail.
    let pending_up = {
        let mut upstream_writer = upstream.conn.writer();
        seed_outbound_pending(
            &mut upstream_writer,
            client_pending,
            &mut tee_up,
            &obs,
            blocking,
        )?
    };
    if pending_up.followed.blinded {
        report_blind(SecretWay::Out);
    }
    if !pending_up.crossed {
        client.conn.send_close_notify();
        upstream.conn.send_close_notify();
        let _ = flush_tls(&mut client.conn, &mut client.sock);
        let _ = flush_tls(&mut upstream.conn, &mut upstream.sock);
        return Ok(());
    }
    up.fetch_add(client_pending.len() as u64, Ordering::Relaxed);
    // The way back is recorded and never refused, whatever `websocket_secret` says — the same rule
    // the loop below applies to every later inbound chunk — so these are seeded without a gate.
    client.conn.writer().write_all(upstream_pending)?;
    down.fetch_add(upstream_pending.len() as u64, Ordering::Relaxed);
    if follow(&mut tee_down, upstream_pending, SecretWay::Back, &obs).blinded {
        report_blind(SecretWay::Back);
    }

    client.sock.set_nonblocking(true)?;
    upstream.sock.set_nonblocking(true)?;

    let cfd = client.sock.as_raw_fd();
    let ufd = upstream.sock.as_raw_fd();
    let mut c_read_done = false; // client → upstream: client's read side reached EOF
    let mut u_read_done = false; // upstream → client: upstream's read side reached EOF
    let mut buf = [0u8; 16 * 1024];

    loop {
        // Drain pending TLS output on both sides.
        flush_tls(&mut client.conn, &mut client.sock)?;
        flush_tls(&mut upstream.conn, &mut upstream.sock)?;

        // `progressed` tracks whether a read delivered plaintext this pass. One `read_tls` can decrypt
        // several TLS records into rustls's plaintext buffer at once, but a single `reader().read`
        // returns at most `buf`; the rest sits in rustls, invisible to `poll` (which sees only the
        // socket). So while a read makes progress we loop again instead of parking in `poll` — else a
        // burst larger than `buf` on an otherwise-idle stream would strand its tail until the next
        // socket event (which, on a live long-lived WebSocket, may never come).
        let mut progressed = false;

        // client → upstream: read only while the destination can still accept (is not backpressured).
        if !c_read_done && !upstream.conn.wants_write() {
            match read_plaintext(&mut client.conn, &mut client.sock, &mut buf)? {
                Some(0) => {
                    c_read_done = true;
                    upstream.conn.send_close_notify();
                }
                Some(n) => {
                    // Scanned before it is written on, which is the whole of what `block` can
                    // promise: a secret whole inside this chunk does not reach the upstream at all.
                    // One split across chunks had its first part relayed a turn ago, and closing
                    // now stops the rest — the bound is the read size, not the tunnel.
                    let followed = follow(&mut tee_up, &buf[..n], SecretWay::Out, &obs);
                    if followed.blinded {
                        report_blind(SecretWay::Out);
                    }
                    if (followed.seen || followed.blinded) && blocking {
                        // Closed on both legs rather than dropped: a peer told the tunnel ended
                        // stops, where one left waiting on a socket that answers nothing retries.
                        // The sighting is already on the tunnel's own event, which is where a
                        // reader finds out why it ended.
                        client.conn.send_close_notify();
                        upstream.conn.send_close_notify();
                        let _ = flush_tls(&mut client.conn, &mut client.sock);
                        let _ = flush_tls(&mut upstream.conn, &mut upstream.sock);
                        return Ok(());
                    }
                    upstream.conn.writer().write_all(&buf[..n])?;
                    up.fetch_add(n as u64, Ordering::Relaxed);
                    progressed = true;
                }
                None => {}
            }
        }
        // upstream → client: symmetric.
        if !u_read_done && !client.conn.wants_write() {
            match read_plaintext(&mut upstream.conn, &mut upstream.sock, &mut buf)? {
                Some(0) => {
                    u_read_done = true;
                    client.conn.send_close_notify();
                }
                Some(n) => {
                    // The way back is recorded and never refused, whatever `websocket_secret` says.
                    // A secret arriving *into* the cage is not an exfiltration, and the answer the
                    // request planes give it is redaction rather than refusal — which a relay two
                    // peers agreed the framing of cannot do without rewriting their stream.
                    client.conn.writer().write_all(&buf[..n])?;
                    down.fetch_add(n as u64, Ordering::Relaxed);
                    if follow(&mut tee_down, &buf[..n], SecretWay::Back, &obs).blinded {
                        report_blind(SecretWay::Back);
                    }
                    progressed = true;
                }
                None => {}
            }
        }

        // Push out anything just buffered (a close_notify or relayed plaintext) before parking.
        flush_tls(&mut client.conn, &mut client.sock)?;
        flush_tls(&mut upstream.conn, &mut upstream.sock)?;

        // Done when both directions have closed and no TLS output remains to be written.
        if c_read_done && u_read_done && !client.conn.wants_write() && !upstream.conn.wants_write()
        {
            break;
        }

        // A read delivered data — more may be buffered in rustls; drain it before ever blocking. (When
        // both sources are backpressured/closed, nothing progresses and we fall through to `poll` on
        // `POLLOUT`, so this never spins.)
        if progressed {
            continue;
        }

        let mut fds = [
            libc::pollfd {
                fd: cfd,
                events: 0,
                revents: 0,
            },
            libc::pollfd {
                fd: ufd,
                events: 0,
                revents: 0,
            },
        ];
        if !c_read_done && !upstream.conn.wants_write() {
            fds[0].events |= libc::POLLIN;
        }
        if !u_read_done && !client.conn.wants_write() {
            fds[1].events |= libc::POLLIN;
        }
        if client.conn.wants_write() {
            fds[0].events |= libc::POLLOUT;
        }
        if upstream.conn.wants_write() {
            fds[1].events |= libc::POLLOUT;
        }
        // Nothing to wait for (each source is backpressured and neither has pending output) — a state
        // the done-check above normally covers; break rather than spin on a poll with no interest.
        if fds[0].events == 0 && fds[1].events == 0 {
            break;
        }
        // Indefinite: an idle live channel parks here, not in a read, so it is never cut.
        let rc = unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, -1) };
        if rc < 0 {
            if io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
                continue;
            }
            break;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sandbox::control::CaptureBytes;

    /// Build one WebSocket frame: `opcode`, the payload, and whether to mask it the way a client
    /// must. Extended lengths are chosen the way a real peer would, so a test exercises the same
    /// header shapes the decoder meets on the wire.
    fn frame(opcode: u8, payload: &[u8], mask: Option<[u8; 4]>) -> Vec<u8> {
        frame_with_fin(opcode, payload, mask, true)
    }

    /// The same, with `fin` chosen: a fragmented message is a first frame with `fin` clear followed
    /// by continuations (opcode `0x0`), the last of which sets it.
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

    /// A tee over a sink of `cap` bytes, plus the sink so a test can read what it captured.
    fn tee(cap: usize) -> (FrameTee, Arc<CapBuf>) {
        let sink = Arc::new(CapBuf::new(cap));
        (
            FrameTee::new(Some(sink.clone()), &[], None).expect("a sink is a consumer"),
            sink,
        )
    }

    /// The same over a `permessage-deflate` direction; `no_takeover` mirrors what the peer announced.
    fn deflating_tee(cap: usize, no_takeover: bool) -> (FrameTee, Arc<CapBuf>) {
        let sink = Arc::new(CapBuf::new(cap));
        (
            FrameTee::new(Some(sink.clone()), &[], Some(no_takeover))
                .expect("a sink is a consumer"),
            sink,
        )
    }

    /// A tee that only SCANS: no capture sink at all, which is the shape a launch has when it
    /// configures a secret and does not capture. Nothing about the leak scan may depend on the
    /// capture being on — that would make a security check follow a debugging setting.
    fn scanning_tee(needles: &[SecretNeedle], deflate: Option<bool>) -> FrameTee {
        FrameTee::new(None, needles, deflate).expect("needles are a consumer")
    }

    /// One `permessage-deflate` message, compressed against `c`'s running window and framed with
    /// whichever of the three length forms fits — the two-byte and eight-byte forms included, since
    /// the message this exists for is far past the 125 bytes the short form carries.
    fn deflated_message(
        payload: &[u8],
        c: &mut miniz_oxide::deflate::core::CompressorOxide,
    ) -> Vec<u8> {
        use miniz_oxide::deflate::core::{TDEFLFlush, compress};
        let mut body = vec![0u8; payload.len() * 2 + 4096];
        let (status, consumed, n) = compress(c, payload, &mut body, TDEFLFlush::Sync);
        // Asserted, not assumed: a short write would silently compress a *prefix* of the payload,
        // and a test whose big message turned out not to be big proves nothing.
        assert_eq!(
            consumed,
            payload.len(),
            "the whole payload must compress in one call (status {status:?})"
        );
        body.truncate(n);
        if body.ends_with(&[0x00, 0x00, 0xff, 0xff]) {
            body.truncate(body.len() - 4);
        }
        let mut framed = vec![0xc1u8]; // FIN | RSV1 | text
        let n = body.len();
        if n < 126 {
            framed.push(n as u8);
        } else if n <= u16::MAX as usize {
            framed.push(126);
            framed.extend_from_slice(&(n as u16).to_be_bytes());
        } else {
            framed.push(127);
            framed.extend_from_slice(&(n as u64).to_be_bytes());
        }
        framed.extend_from_slice(&body);
        framed
    }

    /// A message that inflates past [`SCAN_MESSAGE_CAP`] must not blind the messages behind it.
    ///
    /// With context takeover — the default, since `no_context_takeover` has to be announced — one
    /// DEFLATE window carries across a direction's messages. Stopping the inflate at the cap with
    /// input still pending would leave the decoder holding a window the peer does not share, and
    /// every later message would inflate to rubbish. That is not a truncated scan, it is a scan the
    /// cage switches **off**: send one large compressible message, then exfiltrate freely down the
    /// same tunnel. So the cap bounds what is *kept*, never what is *decoded* — the remainder is
    /// inflated and discarded, and the secret in the message behind it is still seen.
    #[test]
    fn an_overflowing_message_does_not_blind_the_scan_behind_it() {
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

        // The real thing. Message 1 runs past the cap and ends with a distinctive stretch, so that
        // stretch lands in the peer's window but in the part a capped inflate never produces.
        // Message 2 repeats it and then carries the secret, so the compressor back-references into
        // exactly that part: message 2 is decodable only if message 1 was inflated *whole*. Both are
        // compressed against one window (`Some(false)` — the peer keeps context across messages).
        let tail: Vec<u8> = (0..8192u32).flat_map(|i| i.to_le_bytes()).collect();
        let mut first = vec![b'a'; SCAN_MESSAGE_CAP + 1024];
        first.extend_from_slice(&tail);
        let mut second = tail.clone();
        second.extend_from_slice(SECRET);

        let mut c = CompressorOxide::new(raw_deflate_flags());
        let overflowing = deflated_message(&first, &mut c);
        let carrying = deflated_message(&second, &mut c);
        // The whole point of the attack shape: it is cheap. A cage buys a blinded tunnel for a few
        // kilobytes, and the message stays well inside the compressed budget, so what is under test
        // is the plaintext cap and not that other bound.
        assert!(
            overflowing.len() < 64 * 1024,
            "the overflowing message must be cheap on the wire ({} bytes) — otherwise the \
             compressed budget stops it first and this tests the wrong bound",
            overflowing.len()
        );

        let mut t = scanning_tee(std::slice::from_ref(&needle), Some(false));
        t.push(&overflowing);
        t.push(&carrying);
        assert_eq!(
            t.sightings(),
            vec!["test-secret".to_string()],
            "a message past the scan cap blinded the scan behind it — the leak tripwire on this \
             direction is off for the rest of the tunnel"
        );
    }

    /// The companion to the test above, on the axis it cannot cover: when the remainder is too big
    /// to inflate away, the window stays out of step — and that must be *reported*, so the direction
    /// stops rather than carrying on handing the scan whatever a desynced decoder produces.
    ///
    /// The resync budget is lowered for the test rather than the message being grown to sixty-four
    /// megabytes, and the assertion is on `in_step` itself: a decode that merely failed would leave
    /// this path unobserved while still looking green.
    #[test]
    fn a_window_that_cannot_be_squared_is_reported_as_out_of_step() {
        use miniz_oxide::deflate::core::CompressorOxide;
        let mut c = CompressorOxide::new(raw_deflate_flags());
        let framed = deflated_message(&vec![b'a'; SCAN_MESSAGE_CAP + 64 * 1024], &mut c);
        // Past the header, whichever length form it used — asserted rather than assumed, so a
        // change in how well this payload compresses cannot quietly slice off the wrong bytes.
        assert_eq!(framed[1], 126, "expected the two-byte length form");
        let body = &framed[4..];

        let mut inflater = Inflater::new(false);
        inflater.resync_cap = 1024; // far below the ~64 KiB left after the cap
        let got = inflater
            .message(body, SCAN_MESSAGE_CAP)
            .expect("the message decodes as far as the cap");
        assert_eq!(
            got.plain.len(),
            SCAN_MESSAGE_CAP + 1,
            "the overflow path is the one under test, so the cap must be what stopped it"
        );
        assert!(
            !got.in_step,
            "a window the drain gave up on must be reported out of step, or the direction carries \
             on scanning rubbish and reporting nothing"
        );
    }

    /// And the tee acts on that report: the direction stops, which is what the compressed budget and
    /// a failed decode already do. Without this the flag could be set and ignored.
    #[test]
    fn a_direction_whose_window_cannot_be_squared_stops() {
        use miniz_oxide::deflate::core::CompressorOxide;
        let mut c = CompressorOxide::new(raw_deflate_flags());
        let overflowing = deflated_message(&vec![b'a'; SCAN_MESSAGE_CAP + 64 * 1024], &mut c);

        let mut t = scanning_tee(&[needle()], Some(false));
        t.inflater
            .as_mut()
            .expect("a deflate direction has an inflater")
            .resync_cap = 1024;
        t.push(&overflowing);
        assert!(
            t.done,
            "a direction holding a window it could not square must stop, not keep scanning"
        );
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

    /// A compressed message split across a continuation frame is one DEFLATE stream, so it can only
    /// be inflated once whole. A decoder that inflated per frame would fail on the second half.
    #[test]
    fn a_compressed_message_fragmented_across_frames_is_inflated_once_whole() {
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

    /// A message the peer chose NOT to compress rides the same connection with `RSV1` clear, and must
    /// be captured verbatim rather than pushed through the decompressor.
    #[test]
    fn an_uncompressed_message_on_a_deflate_connection_is_captured_verbatim() {
        let (mut t, sink) = deflating_tee(4096, false);
        t.push(&frame(0x1, b"plain text", None));
        assert_eq!(captured(&sink).bytes, b"plain text");
    }

    /// A message whose compressed bytes run past [`FrameTee::compressed_budget`] leaves the
    /// transcript at the last message that was actually decoded.
    ///
    /// The direction has to stop there — the peer's window is now ahead of this decoder's, so every
    /// later message would inflate to rubbish. What it must not do is *file* the bytes it gave up
    /// on: they are raw DEFLATE, and consuming them (which this did) stored the compressor's output
    /// in the capture as if it were the message's text, and handed the leak scan bytes no needle
    /// could ever match.
    #[test]
    fn a_message_past_the_compressed_budget_files_none_of_its_deflate_bytes() {
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

        // Then one claiming RSV1 whose payload alone exceeds the budget (`plaintext_cap * 4`, floored
        // at 64 KiB). It is never inflated — the budget is checked before the message is assembled —
        // so its bytes are exactly what a consumer would file if this path consumed them.
        let marker = b"NOT-PLAINTEXT-";
        let payload: Vec<u8> = marker.iter().copied().cycle().take(80 * 1024).collect();
        assert!(
            payload.len() > t.compressed_budget(),
            "the payload must exceed the budget under test"
        );
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

    /// A tunnel must not scan for a credential the cage learned on the very host the tunnel goes to.
    ///
    /// `carries_secret` already waves that case through on the request planes ([`SecretNeedle::scanned_for`]):
    /// re-sending a session token to the service that issued it is the app using its own sign-in.
    /// The tunnel scanned the whole set instead, so under `[network] websocket_secret = block` the
    /// first frame carrying the app's own token closed the socket it had just opened — the app
    /// cutting off its own session, reported as an exfiltration attempt.
    ///
    /// The declared needle and the needle learned on *another* host are asserted kept in the same
    /// breath, so the filter cannot be satisfied by scanning for nothing.
    #[test]
    fn a_tunnel_does_not_scan_for_a_credential_learned_on_its_own_host() {
        const OWN: &str = "SESSION-TOKEN-OWN-HOST-01";
        const OTHER: &str = "SESSION-TOKEN-OTHER-HOST-1";
        let creds = Credentials::new(
            Vec::new(),
            vec![SecretNeedle::named("declared", NEEDLE_VALUE.to_vec())],
            crate::sandbox::redact::MIN_LEN_DEFAULT,
        );
        assert!(
            creds.observe("Authorization", &format!("Bearer {OWN}"), "chat.example"),
            "the needle learned on the tunnel's own host is the premise of this test"
        );
        assert!(
            creds.observe("Authorization", &format!("Bearer {OTHER}"), "other.example"),
            "the needle learned elsewhere is the premise of this test"
        );

        let all = creds.snapshot();
        let kept = tunnel_needles(&all.needles, "chat.example");
        let has =
            |needles: &[SecretNeedle], value: &[u8]| needles.iter().any(|n| n.as_bytes() == value);
        assert!(
            !has(&kept, OWN.as_bytes()),
            "a credential learned on chat.example must not be scanned for on a tunnel to \
             chat.example — the app's own authenticated stream is not a leak"
        );
        assert!(
            has(&kept, OTHER.as_bytes()),
            "a credential learned on another host is exactly what this tripwire exists to catch"
        );
        assert!(
            has(&kept, NEEDLE_VALUE),
            "a declared secret is scanned for everywhere, destination included"
        );
        // The exemption is scoped to the one host: the same tunnel to anywhere else still scans it.
        assert!(
            has(
                &tunnel_needles(&all.needles, "elsewhere.example"),
                OWN.as_bytes()
            ),
            "the exemption must be the host it was learned on and no other"
        );
    }

    /// The value [`needle`] looks for, so a test can send exactly what the scan is watching for.
    const NEEDLE_VALUE: &[u8] = b"SECRET-VALUE-0123456789";

    /// The credential the client addressed to the **proxy hop** must not reach the origin server.
    ///
    /// `reserialize_request` drops `Proxy-Authorization` on both HTTP/1.1 planes, saying why in as
    /// many words; the upgrade reserializer did not, so a `ws://`/`wss://` handshake handed the
    /// far end a secret that was meant for sbx. `Connection` is asserted to survive in the same
    /// breath, because an upgrade needs it and a blanket hop-by-hop strip would break the feature
    /// this function exists for.
    #[test]
    fn a_websocket_upgrade_does_not_hand_the_proxy_credential_to_the_origin() {
        let head = Head {
            request_line: "GET /chat HTTP/1.1".to_string(),
            headers: vec![
                ("Host".to_string(), "example.com".to_string()),
                ("Upgrade".to_string(), "websocket".to_string()),
                ("Connection".to_string(), "Upgrade".to_string()),
                (
                    "Proxy-Authorization".to_string(),
                    "Basic c2J4OnNlY3JldA==".to_string(),
                ),
            ],
        };
        let wire = String::from_utf8(reserialize_upgrade(&head, &[])).expect("ascii");
        assert!(
            !wire.to_ascii_lowercase().contains("proxy-authorization"),
            "the proxy-hop credential was forwarded to the origin:\n{wire}"
        );
        assert!(
            !wire.contains("c2J4OnNlY3JldA=="),
            "the credential value survived under some other spelling:\n{wire}"
        );
        assert!(
            wire.contains("Connection: Upgrade"),
            "the upgrade's own Connection header must survive:\n{wire}"
        );
    }

    /// A needle for the leak-scan tests. The value is long enough to clear the redaction floor, and
    /// distinctive enough that a match cannot be a coincidence.
    fn needle() -> SecretNeedle {
        SecretNeedle::named("demo-token", NEEDLE_VALUE.to_vec())
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
        assert!(FrameTee::new(None, &[], None).is_none());
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
    /// message it decoded. It is not an answer for the *scan*: this file states that a decoder going
    /// blind mid-tunnel is a security control the cage switches off at will, which is the whole
    /// reason the resync machinery exists — and `done` was private, so `follow` reported nothing, the
    /// relay kept forwarding, and `websocket_secret = block` could never fire again on that tunnel.
    /// The cheapest protocol-legal way in is one compressed message past `compressed_budget()`,
    /// whose size the cage chooses.
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
            .take(t.compressed_budget() + 1)
            .collect();
        let mut wire = vec![0xc1u8, 127]; // FIN | RSV1 | text, 8-byte length
        wire.extend_from_slice(&(payload.len() as u64).to_be_bytes());
        wire.extend_from_slice(&payload);
        t.push(&wire);
        assert!(
            t.done,
            "a message past the compressed budget stops the direction"
        );
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

    /// The frames a cage pipelines behind its handshake are gated BEFORE they are written upstream.
    ///
    /// `WebsocketSecret::Block` states its guarantee as an order — "the scan runs on each chunk read
    /// from the cage, before that chunk is written on, so a secret whole inside one chunk never
    /// crosses" — and the relay loop keeps it for every chunk it reads. On this one chunk the write
    /// came first: the frames were already in the upstream's rustls send buffer, and the `flush_tls`
    /// that follows the close drains encrypted application data ahead of the close_notify, so the
    /// secret was delivered and the tunnel was closed behind it. A cage that does not wait for the
    /// `101` chooses those bytes, so the bypass was available exactly once per tunnel, on the frames
    /// the attacker picks.
    #[test]
    fn frames_pipelined_behind_the_handshake_are_gated_before_they_are_written_upstream() {
        let ctx = ProxyCtx::new(
            Arc::new(Ca::ephemeral().unwrap()),
            crate::allowlist::EgressPolicy::default(),
        )
        .unwrap();
        let obs = TunnelObservers {
            up: Arc::new(AtomicU64::new(0)),
            down: Arc::new(AtomicU64::new(0)),
            capture: None,
            ctx: &ctx,
            seq: None,
        };
        // Exactly what a cage writes in the same `write_all` as its upgrade request head: a masked
        // text frame carrying a declared secret.
        let carrying = frame(0x1, NEEDLE_VALUE, Some([0x37, 0xfa, 0x21, 0x3d]));
        let ordinary = frame(0x1, br#"{"hello":"world"}"#, Some([1, 2, 3, 4]));

        let mut tee = FrameTee::new(None, &[needle()], None);
        let mut upstream = Vec::new();
        let seeded = seed_outbound_pending(&mut upstream, &carrying, &mut tee, &obs, true).unwrap();
        assert!(
            seeded.followed.seen,
            "the pipelined frame carries the value the tripwire exists for"
        );
        assert!(!seeded.crossed, "so under `block` it must not cross");
        assert!(
            upstream.is_empty(),
            "not one byte may reach the upstream's send buffer: {upstream:?}"
        );

        // Under `warn` the tunnel stays byte-exact, sighting or not — so this cannot be satisfied by
        // a gate that never writes.
        let mut tee = FrameTee::new(None, &[needle()], None);
        let mut upstream = Vec::new();
        let seeded =
            seed_outbound_pending(&mut upstream, &carrying, &mut tee, &obs, false).unwrap();
        assert!(seeded.followed.seen && seeded.crossed);
        assert_eq!(upstream, carrying, "`warn` records and relays");

        // And ordinary pipelined frames cross under `block` too: what closes the tunnel is the
        // sighting, never the pipelining.
        let mut tee = FrameTee::new(None, &[needle()], None);
        let mut upstream = Vec::new();
        let seeded = seed_outbound_pending(&mut upstream, &ordinary, &mut tee, &obs, true).unwrap();
        assert!(!seeded.followed.seen && seeded.crossed);
        assert_eq!(upstream, ordinary);
    }

    /// A capture that has filled does not stop the scan: the decoder keeps following the framing for
    /// as long as a consumer still wants bytes. Teeth: the secret is sent AFTER the sink's cap is
    /// exhausted, so a decoder that quit when the capture filled would miss it.
    #[test]
    fn a_full_capture_does_not_blind_the_scan() {
        let sink = Arc::new(CapBuf::new(4));
        let mut t = FrameTee::new(Some(sink.clone()), &[needle()], None).expect("two consumers");
        t.push(&frame(0x1, b"aaaaaaaaaaaa", None));
        assert!(captured(&sink).truncated, "the capture is full by now");
        t.push(&frame(0x1, b"late SECRET-VALUE-0123456789", None));
        assert_eq!(
            t.sightings(),
            vec!["demo-token".to_string()],
            "the scan outlives the capture it shares a decoder with"
        );
    }
}
