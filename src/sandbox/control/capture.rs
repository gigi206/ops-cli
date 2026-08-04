//! The egress **traffic capture**: the bounded store of request/response bytes `sbx net logs
//! --with-headers/--with-body` reads back, so a launch can be watched at the level of what it
//! actually sent and received rather than only which host it reached.
//!
//! Off unless a **trusted** layer asks for it (`[network] capture`), because a capture is by
//! definition the most sensitive thing the proxy holds: the plaintext of an inspected exchange.
//! Three properties make it safe to hold at all:
//!
//! - **Redacted once, at the door.** [`CaptureRing::insert`] is the only way bytes enter the ring
//!   and it masks every configured secret before storing them, so the ring never holds a credential
//!   and no reader can forget to mask. Masking a *complete* buffer (rather than each streamed
//!   chunk) is what makes it exact — a secret split across two reads is still one contiguous run by
//!   the time it is masked.
//! - **Bounded three ways.** Each part is capped on its own ([`CaptureCaps`]), the number of
//!   captured exchanges is capped, and the ring holds a total byte budget past which the *oldest*
//!   captures are dropped. An in-cage agent streaming gigabytes therefore costs a fixed amount of
//!   host memory, however long the session runs.
//!
//!   The budget covers what is *retained*. An exchange still in flight also holds its own buffers
//!   (a head plus at most two bodies) until it is filed, so the peak adds roughly
//!   `concurrent exchanges × (head cap + 2 × body cap)` on top. At the default 8 KiB body cap that
//!   is small; raising `capture_max_kb` to the ceiling raises it in proportion, which is why the
//!   ceiling exists and why the whole feature is trusted-only.
//! - **Never silent about what it dropped.** A part cut at its cap is stored with its `truncated`
//!   flag, and a capture evicted for the byte budget leaves its log event behind (the exchange is
//!   still listed, it simply carries no body).
//!
//! The capture lives beside the event ring rather than inside it: an event is a small, cheap,
//! always-on record, and a capture is a large, optional one keyed to it by sequence number. Keeping
//! them apart is what lets the byte budget evict a capture without touching the decision record.

use std::collections::VecDeque;
use std::sync::Mutex;

use crate::sandbox::proxy::{redact_in_place, SecretNeedle};

/// How much of each exchange a launch captures. `Off` is the default and costs nothing — no buffer
/// is ever allocated on the forwarding path.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) enum CaptureLevel {
    /// No capture at all.
    #[default]
    Off,
    /// The request and response **heads** only (request line, status line, headers).
    Headers,
    /// The heads plus the leading bytes of each body, up to the configured per-body cap.
    Bodies,
}

impl CaptureLevel {
    /// The config token for this level, as `sbx config show` prints it.
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            CaptureLevel::Off => "off",
            CaptureLevel::Headers => "headers",
            CaptureLevel::Bodies => "bodies",
        }
    }

    /// Parse a config token, returning `None` for anything else so the caller can reject it by name
    /// rather than silently falling back to a level the user did not ask for.
    pub(crate) fn parse(s: &str) -> Option<Self> {
        match s {
            "off" => Some(CaptureLevel::Off),
            "headers" => Some(CaptureLevel::Headers),
            "bodies" => Some(CaptureLevel::Bodies),
            _ => None,
        }
    }

    /// Whether anything at all is captured — the single predicate the forwarding paths branch on, so
    /// an `off` launch pays no allocation and takes no lock.
    pub(crate) fn captures(self) -> bool {
        !matches!(self, CaptureLevel::Off)
    }

    /// Whether bodies are captured on top of the heads.
    pub(crate) fn captures_bodies(self) -> bool {
        matches!(self, CaptureLevel::Bodies)
    }
}

/// The default per-body cap, in KiB. A prompt/response body is the thing worth reading and its
/// interesting part is the front (the JSON envelope, the first SSE events), so a small default
/// keeps a whole session's capture in a few MiB.
pub(crate) const CAPTURE_BODY_KB_DEFAULT: u64 = 8;

/// The largest per-body cap a config may ask for, in KiB (1 MiB). Past this the byte budget below
/// would be spent by a handful of exchanges, which is worse than a shorter capture of many — and
/// the in-flight buffers of concurrent exchanges scale with it (see the module doc), so it also
/// bounds the peak, not only what is retained.
pub(crate) const CAPTURE_BODY_KB_MAX: u64 = 1024;

/// The most head bytes captured per direction. Generous for real headers, and it bounds the head
/// side independently of the body cap so a header flood cannot eat the body budget.
pub(crate) const CAPTURE_HEAD_MAX: usize = 32 * 1024;

/// The most exchanges the ring retains, oldest evicted first — the capture analogue of the event
/// ring's cap, an order of magnitude smaller because each entry is an order of magnitude larger.
pub(crate) const CAPTURE_RING_CAP: usize = 200;

/// The total captured bytes the ring holds across every entry. Reaching it evicts the oldest
/// captures until the newest fits, so memory is flat regardless of how long a session runs or how
/// large the per-body cap is.
pub(crate) const CAPTURE_TOTAL_BUDGET: usize = 16 * 1024 * 1024;

/// The per-part byte caps a launch captures with, derived once from the policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct CaptureCaps {
    /// The most head bytes kept per direction.
    pub(crate) head: usize,
    /// The most body bytes kept per direction — `0` under [`CaptureLevel::Headers`], which is what
    /// makes that level cost nothing beyond the heads.
    pub(crate) body: usize,
}

impl CaptureCaps {
    /// The caps for `level` with a per-body cap of `body_kb` KiB (clamped to
    /// [`CAPTURE_BODY_KB_MAX`], so a config value can only ever shrink the budget's reach).
    pub(crate) fn new(level: CaptureLevel, body_kb: u64) -> Self {
        CaptureCaps {
            head: CAPTURE_HEAD_MAX,
            body: if level.captures_bodies() {
                (body_kb.min(CAPTURE_BODY_KB_MAX) as usize) * 1024
            } else {
                0
            },
        }
    }
}

/// One captured part of an exchange. The four parts are stored and transported separately so a
/// reader can ask for the heads alone, and so a truncated body is flagged as its own fact rather
/// than as a truncation of "the exchange".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CapturePart {
    /// The client's request head, exactly as it arrived — **before** any sbx credential injection,
    /// so an injected secret cannot reach the capture even in principle.
    ReqHead,
    /// The names (never the values) of the headers sbx injected into this request, one per line.
    /// Recorded so the capture does not read as if sbx forwarded the client's head verbatim.
    Injected,
    /// The leading bytes of the request body.
    ReqBody,
    /// The upstream response head (status line + headers).
    ResHead,
    /// The leading bytes of the response body.
    ResBody,
    /// The leading payload bytes the cage sent over an established WebSocket, data frames only,
    /// concatenated in order and unmasked.
    WsUp,
    /// The same for what the upstream sent back over that WebSocket.
    WsDown,
}

impl CapturePart {
    /// The wire token for this part.
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            CapturePart::ReqHead => "req-head",
            CapturePart::Injected => "injected",
            CapturePart::ReqBody => "req-body",
            CapturePart::ResHead => "res-head",
            CapturePart::ResBody => "res-body",
            CapturePart::WsUp => "ws-up",
            CapturePart::WsDown => "ws-down",
        }
    }

    /// Parse a wire token back, returning `None` for an unknown one so a reader from a newer sbx
    /// simply ignores a part it does not understand.
    pub(crate) fn parse(s: &str) -> Option<Self> {
        match s {
            "req-head" => Some(CapturePart::ReqHead),
            "injected" => Some(CapturePart::Injected),
            "req-body" => Some(CapturePart::ReqBody),
            "res-head" => Some(CapturePart::ResHead),
            "res-body" => Some(CapturePart::ResBody),
            "ws-up" => Some(CapturePart::WsUp),
            "ws-down" => Some(CapturePart::WsDown),
            _ => None,
        }
    }
}

/// One part's captured bytes plus whether they were cut at the cap.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct CaptureBytes {
    pub(crate) bytes: Vec<u8>,
    /// Whether more followed than the cap allowed — rendered as an explicit marker, never dropped
    /// silently.
    pub(crate) truncated: bool,
}

impl CaptureBytes {
    /// Whether this part holds nothing at all (never captured, or captured empty).
    pub(crate) fn is_empty(&self) -> bool {
        self.bytes.is_empty() && !self.truncated
    }

    /// The bytes' weight against the ring's budget.
    fn weight(&self) -> usize {
        self.bytes.len()
    }
}

/// One exchange's capture, keyed to the log event of the same sequence number.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Capture {
    pub(crate) seq: u64,
    pub(crate) req_head: CaptureBytes,
    /// The names of the headers sbx injected, one per line. Values never appear.
    pub(crate) injected: CaptureBytes,
    pub(crate) req_body: CaptureBytes,
    pub(crate) res_head: CaptureBytes,
    pub(crate) res_body: CaptureBytes,
    /// An established WebSocket's data-frame payloads, per direction. Filed separately from the
    /// handshake above (which lands as `req_head`/`res_head` at the `101`), because a tunnel outlives
    /// its handshake by definition.
    pub(crate) ws_up: CaptureBytes,
    pub(crate) ws_down: CaptureBytes,
}

impl Capture {
    /// A capture for `seq` with every part empty.
    pub(crate) fn new(seq: u64) -> Self {
        Capture {
            seq,
            ..Default::default()
        }
    }

    /// Every non-empty part, in exchange order (request first) — the order the wire emits and the
    /// renderer prints.
    pub(crate) fn parts(&self) -> Vec<(CapturePart, &CaptureBytes)> {
        [
            (CapturePart::ReqHead, &self.req_head),
            (CapturePart::Injected, &self.injected),
            (CapturePart::ReqBody, &self.req_body),
            (CapturePart::ResHead, &self.res_head),
            (CapturePart::ResBody, &self.res_body),
            (CapturePart::WsUp, &self.ws_up),
            (CapturePart::WsDown, &self.ws_down),
        ]
        .into_iter()
        .filter(|(_, b)| !b.is_empty())
        .collect()
    }

    /// The part this capture stores under `part`, for a reader assembling one from the wire.
    pub(crate) fn part_mut(&mut self, part: CapturePart) -> &mut CaptureBytes {
        match part {
            CapturePart::ReqHead => &mut self.req_head,
            CapturePart::Injected => &mut self.injected,
            CapturePart::ReqBody => &mut self.req_body,
            CapturePart::ResHead => &mut self.res_head,
            CapturePart::ResBody => &mut self.res_body,
            CapturePart::WsUp => &mut self.ws_up,
            CapturePart::WsDown => &mut self.ws_down,
        }
    }

    /// Fold a later filing of the same exchange into this one: every part the newer capture actually
    /// carries replaces this one's, and the rest stay.
    ///
    /// A WebSocket is filed twice — the handshake when the `101` lands, the frames once the tunnel
    /// has something worth showing — and a frame filing is always a **superset** of any earlier one
    /// (the sink is snapshotted, not drained, until the tunnel ends), so replacing never loses bytes.
    fn merge(&mut self, other: Capture) {
        for (part, bytes) in [
            (CapturePart::ReqHead, other.req_head),
            (CapturePart::Injected, other.injected),
            (CapturePart::ReqBody, other.req_body),
            (CapturePart::ResHead, other.res_head),
            (CapturePart::ResBody, other.res_body),
            (CapturePart::WsUp, other.ws_up),
            (CapturePart::WsDown, other.ws_down),
        ] {
            if !bytes.is_empty() {
                *self.part_mut(part) = bytes;
            }
        }
    }

    /// Whether nothing at all was captured for this exchange.
    pub(crate) fn is_empty(&self) -> bool {
        self.parts().is_empty()
    }

    /// This capture's weight against the ring's byte budget.
    fn weight(&self) -> usize {
        self.req_head.weight()
            + self.injected.weight()
            + self.req_body.weight()
            + self.res_head.weight()
            + self.res_body.weight()
            + self.ws_up.weight()
            + self.ws_down.weight()
    }
}

/// The bounded store of captured exchanges, shared (via `Arc`) between the proxy threads that
/// [`insert`](CaptureRing::insert) a finished exchange and the control thread that reads captures
/// back for `sbx net logs`.
pub(crate) struct CaptureRing {
    inner: Mutex<CaptureInner>,
    caps: CaptureCaps,
    /// The secret values masked out of every capture on the way in. Held here rather than passed per
    /// call so masking cannot be skipped at a call site.
    redactions: Vec<SecretNeedle>,
}

struct CaptureInner {
    /// Captures in ascending sequence order (the order they are inserted, since a sequence number is
    /// assigned when the exchange is decided and exchanges finish in no particular order — see
    /// [`CaptureRing::insert`], which keeps the invariant by inserting in place).
    entries: VecDeque<Capture>,
    bytes: usize,
    /// How many captures were dropped to stay inside the budget or the ring cap, so a reader can be
    /// told its view is partial instead of inferring completeness.
    evicted: u64,
}

impl CaptureRing {
    /// A ring capturing at `caps`, masking `redactions` out of everything it stores.
    pub(crate) fn new(caps: CaptureCaps, redactions: Vec<SecretNeedle>) -> Self {
        CaptureRing {
            inner: Mutex::new(CaptureInner {
                entries: VecDeque::new(),
                bytes: 0,
                evicted: 0,
            }),
            caps,
            redactions,
        }
    }

    /// The per-part caps this ring was built with, so the forwarding path sizes its buffers from the
    /// same source of truth the ring enforces.
    pub(crate) fn caps(&self) -> CaptureCaps {
        self.caps
    }

    /// Store one finished exchange, masking every configured secret out of every part first.
    ///
    /// This is the **only** door into the ring, which is what makes the masking unmissable. It runs
    /// on whole parts rather than on streamed chunks, so a secret that arrived split across two
    /// reads is a contiguous run here and is masked exactly.
    ///
    /// An entry over the ring cap or the byte budget evicts the oldest captures (counted, not
    /// silently forgotten) until the newest fits; a capture larger than the whole budget on its own
    /// is stored anyway — it is already bounded by the per-part caps, and refusing it would silently
    /// lose the one exchange the user is most likely watching.
    pub(crate) fn insert(&self, mut capture: Capture) {
        if capture.is_empty() {
            return;
        }
        for part in [
            &mut capture.req_head,
            &mut capture.injected,
            &mut capture.req_body,
            &mut capture.res_head,
            &mut capture.res_body,
            &mut capture.ws_up,
            &mut capture.ws_down,
        ] {
            redact_in_place(&mut part.bytes, &self.redactions);
        }
        let weight = capture.weight();
        let mut g = self.inner.lock().unwrap();
        // An exchange filed more than once (a WebSocket: its handshake, then its frames) folds into
        // the entry already there rather than appearing twice.
        if let Some(at) = g.entries.iter().position(|e| e.seq == capture.seq) {
            let before = g.entries[at].weight();
            g.entries[at].merge(capture);
            let after = g.entries[at].weight();
            // Subtract first and saturate: a fold is expected to grow an entry, but the budget must
            // not depend on that holding — an underflow here would panic the control plane.
            g.bytes = g.bytes.saturating_sub(before) + after;
        } else {
            // Keep the ascending-sequence invariant without assuming completion order: the common
            // case is an append (the newest exchange finishing last), so scan from the back.
            let at = g
                .entries
                .iter()
                .rposition(|e| e.seq < capture.seq)
                .map(|i| i + 1)
                .unwrap_or(0);
            g.entries.insert(at, capture);
            g.bytes += weight;
        }
        while g.entries.len() > CAPTURE_RING_CAP
            || (g.bytes > CAPTURE_TOTAL_BUDGET && g.entries.len() > 1)
        {
            let Some(dropped) = g.entries.pop_front() else {
                break;
            };
            g.bytes = g.bytes.saturating_sub(dropped.weight());
            g.evicted += 1;
        }
    }

    /// The captures for `seqs` (those still retained), plus how many captures have been evicted over
    /// this ring's life. Cloned out under the lock so the caller renders without holding it.
    pub(crate) fn get(&self, seqs: &[u64]) -> (Vec<Capture>, u64) {
        let g = self.inner.lock().unwrap();
        let found = g
            .entries
            .iter()
            .filter(|e| seqs.contains(&e.seq))
            .cloned()
            .collect();
        (found, g.evicted)
    }
}

/// Encode `bytes` as standard base64 (RFC 4648, padded). The capture wire is line-based and a body
/// is arbitrary binary, so it travels encoded — base64 has no byte that can end a line or be
/// mistaken for a field separator.
pub(crate) fn base64_encode(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b = [
            chunk[0],
            chunk.get(1).copied().unwrap_or(0),
            chunk.get(2).copied().unwrap_or(0),
        ];
        let n = u32::from(b[0]) << 16 | u32::from(b[1]) << 8 | u32::from(b[2]);
        out.push(ALPHABET[(n >> 18) as usize & 63] as char);
        out.push(ALPHABET[(n >> 12) as usize & 63] as char);
        out.push(if chunk.len() > 1 {
            ALPHABET[(n >> 6) as usize & 63] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            ALPHABET[n as usize & 63] as char
        } else {
            '='
        });
    }
    out
}

/// Decode standard base64, returning `None` on any malformed input (a bad character, a bad length,
/// misplaced padding) — a capture that does not decode is dropped rather than rendered as garbage.
pub(crate) fn base64_decode(s: &str) -> Option<Vec<u8>> {
    let s = s.trim_end_matches('=');
    let mut out = Vec::with_capacity(s.len() / 4 * 3);
    let mut acc: u32 = 0;
    let mut bits = 0u32;
    for c in s.bytes() {
        let v = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            _ => return None,
        };
        acc = acc << 6 | u32::from(v);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    // Leftover bits must be zero padding, never a dropped partial byte.
    if bits >= 6 || (acc & ((1 << bits) - 1)) != 0 {
        return None;
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bytes(b: &[u8]) -> CaptureBytes {
        CaptureBytes {
            bytes: b.to_vec(),
            truncated: false,
        }
    }

    fn needle(value: &str) -> SecretNeedle {
        SecretNeedle::named("TOKEN", value.as_bytes().to_vec())
    }

    #[test]
    fn base64_round_trips_every_length_and_binary_bytes() {
        for len in 0..=32usize {
            let raw: Vec<u8> = (0..len).map(|i| (i * 7 + 3) as u8).collect();
            let encoded = base64_encode(&raw);
            assert_eq!(
                base64_decode(&encoded).as_deref(),
                Some(raw.as_slice()),
                "length {len} must round-trip"
            );
        }
        // Known vectors, so an encoder bug cannot hide behind a symmetric decoder bug.
        assert_eq!(base64_encode(b"f"), "Zg==");
        assert_eq!(base64_encode(b"foobar"), "Zm9vYmFy");
        assert_eq!(base64_decode("Zm9vYmFy").as_deref(), Some(&b"foobar"[..]));
        // A body is arbitrary binary — every byte value survives.
        let all: Vec<u8> = (0..=255u8).collect();
        assert_eq!(
            base64_decode(&base64_encode(&all)).as_deref(),
            Some(&all[..])
        );
    }

    #[test]
    fn base64_refuses_malformed_input_rather_than_guessing() {
        assert_eq!(base64_decode("Zm9v YmFy"), None, "a space is not base64");
        assert_eq!(base64_decode("Zm9vYmF*"), None, "an out-of-alphabet byte");
        assert_eq!(
            base64_decode("Z"),
            None,
            "a lone 6-bit group cannot be a byte"
        );
    }

    #[test]
    fn a_capture_is_masked_on_the_way_in_so_the_ring_never_holds_a_secret() {
        let ring = CaptureRing::new(
            CaptureCaps::new(CaptureLevel::Bodies, 8),
            vec![needle("s3cr3t-value")],
        );
        let mut cap = Capture::new(1);
        cap.req_head = bytes(b"POST /v1 HTTP/1.1\r\nhost: api.example.com\r\n\r\n");
        cap.req_body = bytes(br#"{"key":"s3cr3t-value"}"#);
        cap.res_body = bytes(b"echoed s3cr3t-value back");
        ring.insert(cap);

        let (found, _) = ring.get(&[1]);
        let stored = &found[0];
        let body = String::from_utf8(stored.req_body.bytes.clone()).unwrap();
        assert_eq!(
            body, r#"{"key":"************"}"#,
            "the secret is masked in place, at equal length"
        );
        assert!(
            !stored
                .res_body
                .bytes
                .windows(12)
                .any(|w| w == b"s3cr3t-value"),
            "a reflected secret is masked on the response side too"
        );
    }

    #[test]
    fn the_byte_budget_evicts_the_oldest_captures_and_counts_them() {
        let ring = CaptureRing::new(CaptureCaps::new(CaptureLevel::Bodies, 8), vec![]);
        // Each capture is a third of the budget, so the fifth leaves room for only the last three.
        let chunk = vec![b'x'; CAPTURE_TOTAL_BUDGET / 3];
        for seq in 1..=5u64 {
            let mut cap = Capture::new(seq);
            cap.res_body = bytes(&chunk);
            ring.insert(cap);
        }
        let (found, evicted) = ring.get(&[1, 2, 3, 4, 5]);
        let kept: Vec<u64> = found.iter().map(|c| c.seq).collect();
        assert_eq!(
            kept,
            vec![3, 4, 5],
            "the oldest captures are the ones dropped"
        );
        assert_eq!(evicted, 2, "and the drop is counted, not silent");
    }

    /// An exchange filed twice is one entry, not two: a WebSocket's handshake lands at the `101` and
    /// its transcript later, and a reader must see one line with both. The byte budget has to follow
    /// the fold, or a long session's accounting drifts until it evicts captures it should have kept.
    #[test]
    fn a_second_filing_of_the_same_exchange_folds_into_the_first() {
        let ring = CaptureRing::new(CaptureCaps::new(CaptureLevel::Bodies, 8), vec![]);
        let mut handshake = Capture::new(4);
        handshake.req_head = bytes(b"GET /chat HTTP/1.1\r\n\r\n");
        handshake.res_head = bytes(b"HTTP/1.1 101 Switching Protocols\r\n\r\n");
        ring.insert(handshake);

        let mut frames = Capture::new(4);
        frames.ws_up = bytes(br#"{"from":"cage"}"#);
        frames.ws_down = bytes(br#"{"from":"server"}"#);
        ring.insert(frames);

        let (found, _) = ring.get(&[4]);
        assert_eq!(found.len(), 1, "one entry per exchange");
        let cap = &found[0];
        assert!(
            String::from_utf8_lossy(&cap.req_head.bytes).contains("GET /chat"),
            "the handshake survives the fold"
        );
        assert_eq!(cap.ws_up.bytes, br#"{"from":"cage"}"#);
        assert_eq!(cap.ws_down.bytes, br#"{"from":"server"}"#);

        // The budget tracks the folded entry's real size, not the sum of the two filings.
        let expected: usize = cap.parts().iter().map(|(_, b)| b.bytes.len()).sum();
        assert_eq!(ring.inner.lock().unwrap().bytes, expected);
    }

    /// A later filing of a part that already had bytes REPLACES it. That is only safe because a
    /// transcript filing is always a superset of the last (the sink is snapshotted, not drained,
    /// while the tunnel is open) — pinned here so the fold's contract is explicit.
    #[test]
    fn a_later_filing_replaces_a_part_it_carries_and_leaves_the_others_alone() {
        let ring = CaptureRing::new(CaptureCaps::new(CaptureLevel::Bodies, 8), vec![]);
        let mut first = Capture::new(1);
        first.res_head = bytes(b"HTTP/1.1 101 Switching Protocols\r\n\r\n");
        first.ws_down = CaptureBytes {
            bytes: b"partial".to_vec(),
            truncated: true,
        };
        ring.insert(first);

        let mut second = Capture::new(1);
        second.ws_down = bytes(b"partial-and-the-rest");
        ring.insert(second);

        let (found, _) = ring.get(&[1]);
        assert_eq!(found[0].ws_down.bytes, b"partial-and-the-rest");
        assert!(
            !found[0].ws_down.truncated,
            "the superseding filing brings its own truncation state"
        );
        assert!(
            !found[0].res_head.is_empty(),
            "a part the later filing did not carry is untouched"
        );
    }

    #[test]
    fn entries_stay_in_sequence_order_even_when_exchanges_finish_out_of_order() {
        let ring = CaptureRing::new(CaptureCaps::new(CaptureLevel::Headers, 8), vec![]);
        // A long-running exchange (seq 1) finishes after two later ones.
        for seq in [3u64, 2, 1] {
            let mut cap = Capture::new(seq);
            cap.req_head = bytes(b"GET / HTTP/1.1\r\n\r\n");
            ring.insert(cap);
        }
        let (found, _) = ring.get(&[1, 2, 3]);
        let order: Vec<u64> = found.iter().map(|c| c.seq).collect();
        assert_eq!(order, vec![1, 2, 3]);
    }

    #[test]
    fn an_empty_capture_is_not_stored_at_all() {
        let ring = CaptureRing::new(CaptureCaps::new(CaptureLevel::Bodies, 8), vec![]);
        ring.insert(Capture::new(7));
        assert!(ring.get(&[7]).0.is_empty());
    }

    #[test]
    fn headers_level_caps_bodies_at_zero_and_bodies_level_clamps_to_the_ceiling() {
        let heads = CaptureCaps::new(CaptureLevel::Headers, 64);
        assert_eq!(heads.body, 0, "the headers level never buffers a body");
        assert_eq!(heads.head, CAPTURE_HEAD_MAX);
        let big = CaptureCaps::new(CaptureLevel::Bodies, CAPTURE_BODY_KB_MAX * 8);
        assert_eq!(
            big.body,
            CAPTURE_BODY_KB_MAX as usize * 1024,
            "a config cannot ask for more than the ceiling"
        );
    }

    #[test]
    fn levels_round_trip_through_their_config_tokens() {
        for level in [
            CaptureLevel::Off,
            CaptureLevel::Headers,
            CaptureLevel::Bodies,
        ] {
            assert_eq!(CaptureLevel::parse(level.as_str()), Some(level));
        }
        assert_eq!(CaptureLevel::parse("bodys"), None);
        assert!(!CaptureLevel::Off.captures());
        assert!(CaptureLevel::Headers.captures());
        assert!(!CaptureLevel::Headers.captures_bodies());
        assert!(CaptureLevel::Bodies.captures_bodies());
    }

    #[test]
    fn parts_round_trip_through_their_wire_tokens_and_list_in_exchange_order() {
        for part in [
            CapturePart::ReqHead,
            CapturePart::Injected,
            CapturePart::ReqBody,
            CapturePart::ResHead,
            CapturePart::ResBody,
        ] {
            assert_eq!(CapturePart::parse(part.as_str()), Some(part));
        }
        assert_eq!(CapturePart::parse("res-trailer"), None);

        let mut cap = Capture::new(1);
        cap.req_head = bytes(b"GET / HTTP/1.1\r\n\r\n");
        cap.res_body = bytes(b"hi");
        let listed: Vec<CapturePart> = cap.parts().into_iter().map(|(p, _)| p).collect();
        assert_eq!(
            listed,
            vec![CapturePart::ReqHead, CapturePart::ResBody],
            "empty parts are skipped and the rest stay in exchange order"
        );
    }

    #[test]
    fn a_part_truncated_at_its_cap_is_kept_even_with_no_bytes_to_show() {
        let mut cap = Capture::new(1);
        cap.res_body = CaptureBytes {
            bytes: Vec::new(),
            truncated: true,
        };
        assert!(
            !cap.is_empty(),
            "a truncation is itself a fact worth reporting"
        );
    }
}
