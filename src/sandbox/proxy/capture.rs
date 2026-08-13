//! The forwarding side of the traffic capture: the tee that copies a bounded prefix of each
//! inspected stream aside while it is relayed, and the guard that files the finished exchange.
//!
//! Two properties matter here, both about not disturbing what is being watched:
//!
//! - **The stream stays a stream.** [`CaptureReader`] is a pass-through that copies what it yields
//!   into a capped buffer; it never buffers ahead, never delays a byte, and stops copying entirely
//!   once its cap is reached. A streamed completion or an SSE feed reaches the cage exactly as it
//!   would with the capture off — which is the whole point of watching it.
//! - **The exchange is filed however it ends.** [`CaptureGuard`] files on drop, so a relay that
//!   fails mid-response still leaves what it saw behind. That also makes the capture arrive as a
//!   *single* amendment to its log event, rather than growing across several: the reader shows the
//!   exchange once, complete, instead of reprinting it as more bytes trickle in.
//!
//!   A WebSocket is the one exchange that cannot be shown once, because a tunnel outlives its
//!   handshake by design. It is filed in phases instead — the handshake when the `101` lands, each
//!   direction's transcript when that direction's capture fills, and once more when the tunnel ends
//!   — and the ring folds the filings into one entry. Three things keep that bounded and honest:
//!   each transcript filing is a **superset** of the last (the sinks are snapshotted, not drained,
//!   while the tunnel lives), so folding never loses a byte; a filing taken while the tunnel is open
//!   reports its bytes **cut**, because more frames may still cross; and a filing that would show
//!   exactly what was shown last time is **dropped**, so the tunnel's end costs a line only when it
//!   changed something. Four re-emissions over a tunnel's whole life is the ceiling.

use std::io::{self, Read};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use crate::sandbox::control::{Capture, CaptureBytes, CaptureRing, LogRing};

/// A byte sink with a hard cap, shared between the relay thread that fills it and the guard that
/// files it. Past the cap it records that more followed and stops copying.
pub(super) struct CapBuf {
    inner: Mutex<CaptureBytes>,
    cap: usize,
    /// Set while a feeder that may still be running when the exchange is filed has not reported its
    /// source exhausted — see [`CapBuf::expect_source_end`].
    source_open: AtomicBool,
}

impl CapBuf {
    /// A sink holding at most `cap` bytes. A cap of `0` means this part was not asked for at all —
    /// it captures nothing and reports no truncation, so a body the capture level excludes reads as
    /// absent rather than as one that was cut short.
    pub(super) fn new(cap: usize) -> Self {
        CapBuf {
            inner: Mutex::new(CaptureBytes::default()),
            cap,
            source_open: AtomicBool::new(false),
        }
    }

    /// Declare that this sink is fed by a pump that may still be running when the exchange is filed,
    /// and will call [`CapBuf::mark_source_ended`] once its source is exhausted. Until then the
    /// captured bytes are reported as cut short, because they are: what has arrived so far is a
    /// prefix of what the pump would eventually deliver, and a capture must never present a prefix
    /// as if it were whole.
    ///
    /// Only a concurrently-pumped part needs this. A part fed inline (an HTTP/1.1 request body,
    /// relayed before the response is read) is always finished by filing time, so its truncation is
    /// decided by the cap alone.
    pub(super) fn expect_source_end(&self) {
        self.source_open.store(true, Ordering::SeqCst);
    }

    /// Report the feeder's source exhausted: everything it will ever deliver has been pushed, so the
    /// cap is once again the only thing that can cut this part.
    pub(super) fn mark_source_ended(&self) {
        self.source_open.store(false, Ordering::SeqCst);
    }

    /// Copy as much of `chunk` as still fits, flagging the truncation when it does not.
    ///
    /// Returns whether this sink is **settled**: full *and* certain about whether anything was cut.
    /// Filling the buffer exactly is not settled — the stream may end there (nothing was cut) or
    /// continue (something was), and only the next chunk says which. The caller keeps feeding until
    /// this returns `true`, which is at most one extra call and is what keeps a body cut exactly at
    /// a read boundary from being stored as if it were whole.
    pub(super) fn push(&self, chunk: &[u8]) -> bool {
        if self.cap == 0 {
            return true;
        }
        let mut g = self.inner.lock().unwrap();
        let room = self.cap.saturating_sub(g.bytes.len());
        if room == 0 {
            // The buffer was already full and more arrived: that is the truncation.
            g.truncated = g.truncated || !chunk.is_empty();
            return true;
        }
        let take = room.min(chunk.len());
        g.bytes.extend_from_slice(&chunk[..take]);
        if take < chunk.len() {
            g.truncated = true;
            return true;
        }
        false
    }

    /// Read the captured bytes WITHOUT draining the sink, so a later read still carries them. Used
    /// for a capture filed more than once (a WebSocket's frames, shown while the tunnel is still
    /// open): each filing is then a superset of the last, and folding one into the other never loses
    /// a byte.
    pub(super) fn snapshot(&self) -> CaptureBytes {
        let mut out = self.inner.lock().unwrap().clone();
        if self.source_open.load(Ordering::SeqCst) && !out.bytes.is_empty() {
            out.truncated = true;
        }
        out
    }

    /// Take the captured bytes out, leaving the sink empty (the guard files once).
    ///
    /// A sink whose feeder never reported its source exhausted yields its bytes marked cut short:
    /// more was still coming when the exchange was filed. Empty stays empty — a part that never
    /// received a byte is absent, not a phantom truncation.
    fn take(&self) -> CaptureBytes {
        let mut out = std::mem::take(&mut *self.inner.lock().unwrap());
        if self.source_open.load(Ordering::SeqCst) && !out.bytes.is_empty() {
            out.truncated = true;
        }
        out
    }

    /// Whether this sink is settled before it has seen a byte: true only for a zero cap (a part the
    /// capture level excludes), which never stores and never reports a truncation.
    fn settled_empty(&self) -> bool {
        self.cap == 0
    }

    /// The most bytes this sink will ever keep, for a feeder that has to size its own work against
    /// it (a WebSocket decompressor deciding how much compressed input is worth holding).
    pub(super) fn cap(&self) -> usize {
        self.cap
    }
}

/// A `Read` adapter that copies a bounded prefix of what it yields into a [`CapBuf`], then gets out
/// of the way. Wrapping the reader (rather than splitting the copy) is what keeps the relay a
/// single pass: the bytes are teed as they are already being moved.
pub(super) struct CaptureReader<R> {
    inner: R,
    buf: Arc<CapBuf>,
    /// Set once the sink is settled (full, and certain whether anything was cut), so every later
    /// read is a plain pass-through that takes no lock at all.
    done: bool,
}

impl<R: Read> CaptureReader<R> {
    /// Tee `inner` into `buf`.
    pub(super) fn new(inner: R, buf: Arc<CapBuf>) -> Self {
        let done = buf.settled_empty();
        CaptureReader { inner, buf, done }
    }
}

impl<R: Read> Read for CaptureReader<R> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        let n = self.inner.read(out)?;
        if !self.done && n > 0 {
            // Keep feeding until the sink says it is settled: a chunk that fills it exactly leaves
            // open whether more follows, and the answer only arrives with the next chunk.
            self.done = self.buf.push(&out[..n]);
        }
        Ok(n)
    }
}

/// The in-flight capture of one exchange: the sinks the relay tees into, and the filing that
/// happens when the exchange ends however it ends.
///
/// The request head is set outright (it is already in memory when the request is decided); the two
/// bodies stream. The response sink takes the raw response prefix — head and the start of the body
/// in one buffer, since they arrive as one stream — and the split happens at filing time.
pub(super) struct CaptureGuard {
    ring: Arc<CaptureRing>,
    log: Arc<LogRing>,
    seq: u64,
    req_head: Mutex<CaptureBytes>,
    injected: Mutex<CaptureBytes>,
    req_body: Arc<CapBuf>,
    response: Arc<CapBuf>,
    /// Whether the response sink is allowed to yield a body part. Under the headers-only level the
    /// raw prefix is still read (a head cannot be recognized without reading past it) but the body
    /// is dropped at filing rather than stored.
    keeps_body: bool,
    filed: AtomicBool,
    /// The two directions of an established WebSocket, fed by the frame decoders in the relay. Empty
    /// for every other exchange, and filed on their own schedule: a tunnel outlives its handshake, so
    /// they cannot ride the handshake's filing.
    ws_up: Arc<CapBuf>,
    ws_down: Arc<CapBuf>,
    /// What the last transcript filing showed — byte count and cut flag, per direction. A filing that
    /// would show exactly the same thing again is dropped, so a tunnel is re-emitted only when there
    /// is genuinely something new to read. This is what bounds a WebSocket's line count: each
    /// direction can trigger one filing by reaching its cap, and the tunnel's end triggers one more
    /// only if it changed anything.
    last_frames: Mutex<FramesShape>,
}

/// The shape of a filed transcript: `(bytes, cut)` for the cage's direction, then the upstream's.
type FramesShape = ((usize, bool), (usize, bool));

impl CaptureGuard {
    /// Start capturing the exchange logged as `seq`.
    pub(super) fn new(ring: Arc<CaptureRing>, log: Arc<LogRing>, seq: u64) -> Self {
        let caps = ring.caps();
        CaptureGuard {
            ring,
            log,
            seq,
            req_head: Mutex::new(CaptureBytes::default()),
            injected: Mutex::new(CaptureBytes::default()),
            req_body: Arc::new(CapBuf::new(caps.body)),
            // The response arrives as one stream, so one sink holds the head and the body's start.
            response: Arc::new(CapBuf::new(caps.head + caps.body)),
            keeps_body: caps.body > 0,
            filed: AtomicBool::new(false),
            ws_up: Arc::new(CapBuf::new(caps.body)),
            ws_down: Arc::new(CapBuf::new(caps.body)),
            last_frames: Mutex::new(((0, false), (0, false))),
        }
    }

    /// The two frame sinks for an established WebSocket, one per direction, marked as fed by a source
    /// whose end only the tunnel's close announces — so any filing before then reports its bytes as
    /// cut short, which they are: the tunnel is still carrying frames.
    pub(super) fn ws_sinks(&self) -> (Arc<CapBuf>, Arc<CapBuf>) {
        self.ws_up.expect_source_end();
        self.ws_down.expect_source_end();
        (self.ws_up.clone(), self.ws_down.clone())
    }

    /// File what the WebSocket has carried so far and amend its event, WITHOUT draining the sinks —
    /// so the tunnel keeps capturing and a later filing simply supersedes this one.
    ///
    /// Called when a direction reaches its cap, once per direction: nothing more will be captured
    /// for that direction, so that is exactly when it is worth showing. A tunnel that showed nothing
    /// until it closed would be a blank line for as long as a live agent stream stays open, which is
    /// hours. Each direction gets its own trigger because one can fill in seconds while the other
    /// trickles, and waiting for the quiet one would strand the busy one's transcript.
    pub(super) fn file_frames_snapshot(&self) {
        self.file_frames(self.ws_up.snapshot(), self.ws_down.snapshot());
    }

    /// File the WebSocket's frames one last time, the tunnel having ended: the sinks are drained and
    /// their sources declared exhausted, so what is stored is cut only if a cap cut it.
    fn file_frames_final(&self) {
        self.ws_up.mark_source_ended();
        self.ws_down.mark_source_ended();
        self.file_frames(self.ws_up.take(), self.ws_down.take());
    }

    /// Store one frame filing and re-emit the event for it. Nothing captured means nothing filed and
    /// no amendment, so a WebSocket that carried no data frame is not re-emitted at all — and neither
    /// is one whose transcript has not changed since it was last shown.
    fn file_frames(&self, up: CaptureBytes, down: CaptureBytes) {
        if up.is_empty() && down.is_empty() {
            return;
        }
        let shape = (
            (up.bytes.len(), up.truncated),
            (down.bytes.len(), down.truncated),
        );
        {
            let mut last = self.last_frames.lock().unwrap();
            if *last == shape {
                return;
            }
            *last = shape;
        }
        let mut capture = Capture::new(self.seq);
        capture.ws_up = up;
        capture.ws_down = down;
        self.ring.insert(capture);
        self.log.capture_grew(self.seq);
    }

    /// Record the client's request head — the bytes exactly as they arrived, **before** any sbx
    /// credential injection, and the names (never the values) of the headers sbx injected.
    pub(super) fn set_request(&self, head: &[u8], injected: &[(String, String)]) {
        let caps = self.ring.caps();
        let take = caps.head.min(head.len());
        *self.req_head.lock().unwrap() = CaptureBytes {
            bytes: head[..take].to_vec(),
            truncated: take < head.len(),
        };
        if !injected.is_empty() {
            let names: Vec<&str> = injected.iter().map(|(name, _)| name.as_str()).collect();
            *self.injected.lock().unwrap() = CaptureBytes {
                bytes: names.join("\n").into_bytes(),
                truncated: false,
            };
        }
    }

    /// Record a piece of request body already held in memory, capped like a streamed one. Called
    /// once for a de-chunked HTTP/1.1 body, or once per DATA frame on the HTTP/2 path.
    pub(super) fn set_request_body(&self, body: &[u8]) {
        self.req_body.push(body);
    }

    /// Append to the response sink directly, for a path that does not hand the proxy a byte stream
    /// to wrap: an HTTP/2 response, whose head is framed rather than serialized and whose body
    /// arrives as DATA frames. The caller pushes a synthesized head terminated by a blank line and
    /// then the body, so what the sink holds has the same shape as a relayed HTTP/1.1 response and
    /// [`split_response`] separates the two identically.
    pub(super) fn push_response(&self, chunk: &[u8]) {
        self.response.push(chunk);
    }

    /// Whether this capture keeps bodies at all (the `bodies` level). A framed protocol can consult
    /// it and never buffer a body byte in the first place, where a byte-stream protocol has to read
    /// past the head to find where it ends.
    pub(super) fn keeps_body(&self) -> bool {
        self.keeps_body
    }

    /// File the exchange now rather than at drop, for a relay that hands the connection off and will
    /// not return for a long time (a WebSocket tunnel). Filing early releases the log event's single
    /// amendment, so the handshake's `101` shows up live instead of at teardown; the frames past it
    /// are never captured either way.
    pub(super) fn file_now(&self) {
        self.file();
    }

    /// The sink for a streamed request body — wrap the client reader with it.
    pub(super) fn request_body_sink(&self) -> Arc<CapBuf> {
        self.req_body.clone()
    }

    /// The sink for the response — wrap the upstream reader with it.
    pub(super) fn response_sink(&self) -> Arc<CapBuf> {
        self.response.clone()
    }

    /// File the exchange into the ring and amend its log event once, so a `--follow` reader shows
    /// the capture in a single pass. Idempotent; called by [`Drop`], so a relay that fails partway
    /// still files what it saw.
    fn file(&self) {
        if self.filed.swap(true, Ordering::SeqCst) {
            return;
        }
        let mut capture = Capture::new(self.seq);
        capture.req_head = std::mem::take(&mut *self.req_head.lock().unwrap());
        capture.injected = std::mem::take(&mut *self.injected.lock().unwrap());
        capture.req_body = self.req_body.take();
        let (head, body) = split_response(
            self.response.take(),
            self.keeps_body.then(|| self.ring.caps().body),
        );
        capture.res_head = head;
        capture.res_body = body;
        // Nothing captured (an exchange that failed before any head was recorded) still settles the
        // event: a status that arrived while the capture was pending is held back from re-emission
        // until now, and would otherwise never be shown.
        let filed = !capture.is_empty();
        if filed {
            self.ring.insert(capture);
        }
        self.log.capture_settled(self.seq, filed);
    }
}

impl Drop for CaptureGuard {
    fn drop(&mut self) {
        self.file();
        // However the tunnel ended — cleanly, on an error, or because it was never a tunnel at all —
        // this is where its frames are settled. A no-op when none were captured.
        self.file_frames_final();
    }
}

/// Split a captured response prefix into its head and the start of its body. The head ends at the
/// first blank line (`CRLF CRLF`, or `LF LF` from a lax upstream); with no blank line in the
/// captured prefix the whole of it is the head, cut short.
///
/// `body_cap` is the per-body cap, or `None` under the headers-only level (which drops the body
/// part entirely — the bytes past the head were read only because a head cannot be recognized
/// without passing it). The cap is applied HERE rather than by the sink: the response arrives as one
/// stream, so the sink is sized for a head *plus* a body and only this split knows where the body
/// actually starts. Without it a short head would let a body run to the sink's whole size.
fn split_response(raw: CaptureBytes, body_cap: Option<usize>) -> (CaptureBytes, CaptureBytes) {
    let CaptureBytes { bytes, truncated } = raw;
    if bytes.is_empty() && !truncated {
        // Nothing came back at all (a relay that failed before the first byte) — that is an absent
        // capture, not a head cut short.
        return (CaptureBytes::default(), CaptureBytes::default());
    }
    let Some((end, sep)) = find_head_end(&bytes) else {
        // No blank line in what was captured: it is all head, and it is incomplete either because
        // the cap cut it or because the upstream never finished it.
        return (
            CaptureBytes {
                bytes,
                truncated: true,
            },
            CaptureBytes::default(),
        );
    };
    let head = CaptureBytes {
        bytes: bytes[..end].to_vec(),
        truncated: false,
    };
    let Some(cap) = body_cap else {
        return (head, CaptureBytes::default());
    };
    let rest = &bytes[end + sep..];
    let take = cap.min(rest.len());
    let body = CaptureBytes {
        bytes: rest[..take].to_vec(),
        // More followed either because the cap cut it here, or because the sink stopped short of the
        // whole response. Either way the head is whole, so it is the body that continues.
        truncated: truncated || take < rest.len(),
    };
    (head, body)
}

/// The offset of the end of an HTTP head in `bytes` and the length of the blank-line separator,
/// looking for `CRLF CRLF` first and tolerating a bare `LF LF`.
fn find_head_end(bytes: &[u8]) -> Option<(usize, usize)> {
    let crlf = bytes
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|i| (i, 4));
    let lf = bytes.windows(2).position(|w| w == b"\n\n").map(|i| (i, 2));
    match (crlf, lf) {
        (Some(c), Some(l)) => Some(if c.0 <= l.0 { c } else { l }),
        (Some(c), None) => Some(c),
        (None, Some(l)) => Some(l),
        (None, None) => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sandbox::control::{CaptureCaps, CaptureLevel, LOG_RING_CAP};

    fn ring(level: CaptureLevel, kb: u64) -> Arc<CaptureRing> {
        Arc::new(CaptureRing::with_needles(
            CaptureCaps::new(level, kb),
            vec![],
        ))
    }

    /// A guard over a real log ring, with an event already pushed at seq 1 so the amendment has a
    /// target.
    fn guard(level: CaptureLevel, kb: u64) -> (CaptureGuard, Arc<CaptureRing>, Arc<LogRing>) {
        let ring = ring(level, kb);
        let log = Arc::new(LogRing::new(LOG_RING_CAP));
        let seq = log.push(
            false,
            "api.example.com",
            443,
            Some("POST"),
            Some("/v1/messages"),
            crate::sandbox::control::LogVerdict::Allow,
            "allowed",
            crate::sandbox::control::Proto::Https,
            crate::sandbox::control::HttpVer::H1,
            crate::sandbox::control::RpcKind::None,
        );
        log.expect_capture(seq);
        (CaptureGuard::new(ring.clone(), log.clone(), seq), ring, log)
    }

    #[test]
    fn the_tee_yields_every_byte_it_captures_and_stops_at_the_cap() {
        let buf = Arc::new(CapBuf::new(4));
        let source: Vec<u8> = b"abcdefghij".to_vec();
        let mut reader = CaptureReader::new(&source[..], buf.clone());
        let mut relayed = Vec::new();
        io::copy(&mut reader, &mut relayed).unwrap();
        assert_eq!(relayed, source, "the relay is byte-for-byte unaffected");
        let got = buf.take();
        assert_eq!(got.bytes, b"abcd", "the capture stops at its cap");
        assert!(got.truncated, "and says that it did");
    }

    /// A `Read` that hands out its data in fixed-size chunks, so a test can put the cap exactly on a
    /// read boundary the way an 8 KiB `io::copy` buffer does against an 8 KiB sink.
    struct ChunkedReader {
        data: Vec<u8>,
        chunk: usize,
        at: usize,
    }

    impl Read for ChunkedReader {
        fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
            let n = self.chunk.min(out.len()).min(self.data.len() - self.at);
            out[..n].copy_from_slice(&self.data[self.at..self.at + n]);
            self.at += n;
            Ok(n)
        }
    }

    /// The dangerous shape: a body whose first read fills the sink EXACTLY, with more to follow. The
    /// truncation is only knowable from the next chunk, so a tee that stopped looking at the moment
    /// the buffer filled would store a cut body as if it were whole.
    #[test]
    fn a_body_cut_exactly_on_a_read_boundary_is_still_reported_truncated() {
        let buf = Arc::new(CapBuf::new(8));
        let source = ChunkedReader {
            data: b"AAAAAAAABBBBBBBB".to_vec(),
            chunk: 8,
            at: 0,
        };
        let mut reader = CaptureReader::new(source, buf.clone());
        let mut relayed = Vec::new();
        io::copy(&mut reader, &mut relayed).unwrap();
        assert_eq!(relayed, b"AAAAAAAABBBBBBBB", "the relay is unaffected");
        let got = buf.take();
        assert_eq!(got.bytes, b"AAAAAAAA");
        assert!(
            got.truncated,
            "the second chunk is what proves the body was cut"
        );
    }

    /// The mirror case: a body that ends exactly at the cap is NOT truncated. Without this, the fix
    /// above could just mark everything and be vacuously "safe".
    #[test]
    fn a_body_ending_exactly_at_the_cap_is_not_reported_truncated() {
        let buf = Arc::new(CapBuf::new(8));
        let source = ChunkedReader {
            data: b"AAAAAAAA".to_vec(),
            chunk: 8,
            at: 0,
        };
        let mut reader = CaptureReader::new(source, buf.clone());
        io::copy(&mut reader, &mut io::sink()).unwrap();
        let got = buf.take();
        assert_eq!(got.bytes, b"AAAAAAAA");
        assert!(!got.truncated, "nothing followed, so nothing was cut");
    }

    /// A sink whose feeder is still running when the exchange is filed holds a PREFIX, and must say
    /// so. This is the HTTP/2 request-body shape: the pump runs concurrently and can outlive the
    /// filing (a server that answers without draining the request), so a body captured mid-pump
    /// would otherwise be stored as if it were the whole thing.
    #[test]
    fn a_sink_still_being_pumped_reports_its_bytes_cut_short() {
        let buf = Arc::new(CapBuf::new(64));
        buf.expect_source_end();
        buf.push(b"the first frame");
        let got = buf.take();
        assert_eq!(got.bytes, b"the first frame", "what arrived is kept");
        assert!(
            got.truncated,
            "more was still coming, so the prefix is marked as cut"
        );
    }

    #[test]
    fn a_sink_whose_pump_reported_its_source_ended_is_not_reported_cut() {
        let buf = Arc::new(CapBuf::new(64));
        buf.expect_source_end();
        buf.push(b"the whole body");
        buf.mark_source_ended();
        let got = buf.take();
        assert_eq!(got.bytes, b"the whole body");
        assert!(!got.truncated, "the source ended, so nothing was cut");
    }

    /// The guard on the rule above: a part that never received a byte stays ABSENT rather than
    /// becoming a phantom truncation. A request with no body at all opens its sink, ends without
    /// pushing, and must not read as a body that was cut.
    #[test]
    fn an_open_sink_that_never_received_a_byte_is_absent_not_truncated() {
        let buf = Arc::new(CapBuf::new(64));
        buf.expect_source_end();
        let got = buf.take();
        assert!(got.is_empty(), "no bytes and no truncation: {got:?}");
    }

    #[test]
    fn a_zero_cap_sink_captures_nothing_but_relays_everything() {
        let buf = Arc::new(CapBuf::new(0));
        let source = b"payload".to_vec();
        let mut reader = CaptureReader::new(&source[..], buf.clone());
        let mut relayed = Vec::new();
        io::copy(&mut reader, &mut relayed).unwrap();
        assert_eq!(relayed, source);
        assert!(buf.take().bytes.is_empty());
    }

    #[test]
    fn a_secret_split_across_two_reads_is_still_masked_because_masking_sees_the_whole_buffer() {
        use crate::sandbox::proxy::SecretNeedle;
        let ring = Arc::new(CaptureRing::with_needles(
            CaptureCaps::new(CaptureLevel::Bodies, 8),
            vec![SecretNeedle::named("TOKEN", b"abcdef".to_vec())],
        ));
        let log = Arc::new(LogRing::new(LOG_RING_CAP));
        let seq = log.push(
            false,
            "api.example.com",
            443,
            Some("POST"),
            Some("/"),
            crate::sandbox::control::LogVerdict::Allow,
            "allowed",
            crate::sandbox::control::Proto::Https,
            crate::sandbox::control::HttpVer::H1,
            crate::sandbox::control::RpcKind::None,
        );
        log.expect_capture(seq);
        let g = CaptureGuard::new(ring.clone(), log, seq);
        // Two pushes that split the needle down the middle — as two socket reads would.
        g.set_request_body(b"xx abc");
        g.set_request_body(b"def yy");
        drop(g);
        let (found, _) = ring.get(&[seq]);
        assert_eq!(
            String::from_utf8(found[0].req_body.bytes.clone()).unwrap(),
            "xx ****** yy",
            "the needle is masked across the read boundary"
        );
    }

    #[test]
    fn the_response_prefix_splits_into_head_and_body() {
        let (g, ring, _log) = guard(CaptureLevel::Bodies, 8);
        let seq = g.seq;
        let sink = g.response_sink();
        let raw = b"HTTP/1.1 200 OK\r\ncontent-type: application/json\r\n\r\n{\"ok\":true}";
        let mut reader = CaptureReader::new(&raw[..], sink);
        io::copy(&mut reader, &mut io::sink()).unwrap();
        drop(g);

        let (found, _) = ring.get(&[seq]);
        let cap = &found[0];
        assert_eq!(
            String::from_utf8(cap.res_head.bytes.clone()).unwrap(),
            "HTTP/1.1 200 OK\r\ncontent-type: application/json"
        );
        assert_eq!(
            String::from_utf8(cap.res_body.bytes.clone()).unwrap(),
            "{\"ok\":true}"
        );
        assert!(!cap.res_body.truncated);
    }

    /// The framed shape (HTTP/2): the head is pushed as a synthesized blob terminated by a blank
    /// line and the DATA frames follow into the same sink, so one code path splits both protocols.
    #[test]
    fn a_framed_response_pushed_head_then_frames_splits_like_a_relayed_one() {
        let (g, ring, _log) = guard(CaptureLevel::Bodies, 8);
        let seq = g.seq;
        g.push_response(b"HTTP/2 200\r\ncontent-type: application/grpc\r\n\r\n");
        g.push_response(b"\x00\x00\x00\x00\x05hello");
        g.push_response(b" again");
        drop(g);

        let (found, _) = ring.get(&[seq]);
        let cap = &found[0];
        assert_eq!(
            String::from_utf8(cap.res_head.bytes.clone()).unwrap(),
            "HTTP/2 200\r\ncontent-type: application/grpc",
            "the synthesized head is recognized as one"
        );
        assert_eq!(
            cap.res_body.bytes, b"\x00\x00\x00\x00\x05hello again",
            "the frames concatenate into the body"
        );
        assert!(!cap.res_body.truncated);
    }

    #[test]
    fn the_headers_level_keeps_the_head_and_drops_the_body_it_had_to_read_past() {
        let (g, ring, _log) = guard(CaptureLevel::Headers, 8);
        let seq = g.seq;
        let sink = g.response_sink();
        let raw = b"HTTP/1.1 200 OK\r\n\r\nsecret-ish payload";
        let mut reader = CaptureReader::new(&raw[..], sink);
        io::copy(&mut reader, &mut io::sink()).unwrap();
        g.set_request_body(b"a request body");
        drop(g);

        let (found, _) = ring.get(&[seq]);
        let cap = &found[0];
        assert_eq!(
            String::from_utf8(cap.res_head.bytes.clone()).unwrap(),
            "HTTP/1.1 200 OK"
        );
        assert!(cap.res_body.is_empty(), "no response body at this level");
        assert!(cap.req_body.is_empty(), "and no request body either");
    }

    #[test]
    fn a_head_cut_before_its_blank_line_is_reported_as_truncated_with_no_body() {
        let raw = CaptureBytes {
            bytes: b"HTTP/1.1 200 OK\r\nx-long: aaa".to_vec(),
            truncated: true,
        };
        let (head, body) = split_response(raw, Some(8 * 1024));
        assert!(head.truncated, "an unterminated head is incomplete");
        assert!(body.is_empty(), "and nothing can be claimed as its body");
    }

    #[test]
    fn the_request_head_is_captured_verbatim_with_the_injected_names_but_never_their_values() {
        let (g, ring, _log) = guard(CaptureLevel::Bodies, 8);
        let seq = g.seq;
        g.set_request(
            b"POST /v1/messages HTTP/1.1\r\nhost: api.example.com\r\n\r\n",
            &[
                ("x-api-key".to_string(), "s3cr3t".to_string()),
                ("authorization".to_string(), "Bearer t".to_string()),
            ],
        );
        drop(g);

        let (found, _) = ring.get(&[seq]);
        let cap = &found[0];
        assert!(
            String::from_utf8(cap.req_head.bytes.clone())
                .unwrap()
                .starts_with("POST /v1/messages HTTP/1.1")
        );
        assert_eq!(
            String::from_utf8(cap.injected.bytes.clone()).unwrap(),
            "x-api-key\nauthorization",
            "the header names are listed"
        );
        assert!(
            !cap.injected.bytes.windows(6).any(|w| w == b"s3cr3t"),
            "the injected values never enter the capture"
        );
    }

    #[test]
    fn the_guard_files_once_and_amends_its_event_once() {
        let (g, ring, log) = guard(CaptureLevel::Bodies, 8);
        let seq = g.seq;
        g.set_request(b"GET / HTTP/1.1\r\n\r\n", &[]);
        // A status arriving before the capture is filed must not amend on its own — the capture is
        // what completes the record, and one amendment is what keeps `--follow` from reprinting.
        log.set_status(seq, 200);
        let snap = log.snapshot(Some(seq), Some(0), false);
        assert!(
            snap.events.is_empty(),
            "the status alone does not re-emit an event whose capture is still pending"
        );
        drop(g);
        let snap = log.snapshot(Some(seq), Some(0), false);
        assert_eq!(snap.events.len(), 1, "exactly one re-emission, at filing");
        assert_eq!(snap.events[0].status, Some(200), "carrying the status too");
        assert_eq!(ring.get(&[seq]).0.len(), 1);
    }

    #[test]
    fn an_exchange_that_captured_nothing_still_releases_its_held_back_status() {
        let (g, ring, log) = guard(CaptureLevel::Bodies, 8);
        let seq = g.seq;
        log.set_status(seq, 502);
        drop(g);
        assert!(ring.get(&[seq]).0.is_empty(), "nothing to store");
        let snap = log.snapshot(Some(seq), Some(0), false);
        assert_eq!(
            snap.events.len(),
            1,
            "the status held back for the pending capture is released, never lost"
        );
        assert_eq!(snap.events[0].status, Some(502));
    }

    /// A WebSocket's transcript is filed twice: once while the tunnel is open (so a tunnel that lives
    /// for hours is not a blank line until it closes), and once when it ends. The first filing must
    /// say its bytes are cut — more frames may follow — and the second must SUPERSEDE it with the
    /// whole thing, never replace it with only what arrived after.
    #[test]
    fn a_transcript_filed_while_the_tunnel_is_open_is_marked_cut_then_superseded_whole() {
        let (g, ring, log) = guard(CaptureLevel::Bodies, 8);
        let seq = g.seq;
        let (up, down) = g.ws_sinks();
        up.push(b"first");
        down.push(b"reply");
        g.file_frames_snapshot();

        let (found, _) = ring.get(&[seq]);
        assert_eq!(found[0].ws_up.bytes, b"first");
        assert!(
            found[0].ws_up.truncated,
            "the tunnel is still open, so what is shown is a prefix and says so"
        );
        let after_first = log.snapshot(Some(seq), Some(0), false);
        assert_eq!(
            after_first.events.len(),
            1,
            "the open tunnel was re-emitted"
        );

        // More frames cross before the tunnel ends.
        up.push(b"-more");
        drop(g);

        let (found, _) = ring.get(&[seq]);
        assert_eq!(
            String::from_utf8(found[0].ws_up.bytes.clone()).unwrap(),
            "first-more",
            "the second filing carries everything, not only what arrived after the first"
        );
        assert!(
            !found[0].ws_up.truncated,
            "the tunnel ended, so nothing more was coming"
        );
        assert_eq!(found.len(), 1, "one entry for the exchange, not two");
        let after_second = log.snapshot(Some(seq), Some(after_first.amend_head), false);
        assert_eq!(
            after_second.events.len(),
            1,
            "the tunnel's end re-emits the exchange a second and final time"
        );
    }

    /// How many times a WebSocket is re-emitted over its whole life, counted rather than reasoned
    /// about. A tunnel is the one exchange shown more than once, so the number is a promise the docs
    /// make and it has to be pinned: the handshake, then each direction as its capture fills, then
    /// the tunnel's end **only if that changed anything**. Four lines at the very most.
    ///
    /// Teeth: a shared "already filed" flag across the two directions would strand whichever filled
    /// second (a live agent stream fills one side in seconds and trickles on the other for hours),
    /// and filing unconditionally at the end would add a line showing exactly what was already shown.
    #[test]
    fn a_tunnels_whole_life_is_re_emitted_at_most_four_times_and_never_with_nothing_new() {
        let (g, _ring, log) = guard(CaptureLevel::Bodies, 1); // 1 KiB per direction
        let seq = g.seq;
        g.set_request(b"GET /chat HTTP/1.1\r\n\r\n", &[]);
        let (up, down) = g.ws_sinks();

        // The bare line every exchange gets when it is decided.
        let mut cursor = 0;
        let mut lines = 1;

        // 1. The handshake, at the `101`.
        log.set_status(seq, 101);
        g.file_now();
        let s = log.snapshot(Some(seq), Some(cursor), false);
        assert_eq!(s.events.len(), 1, "the handshake is shown");
        cursor = s.amend_head;
        lines += 1;

        // 2. The upstream direction fills first — a server-push-heavy stream.
        down.push(&vec![b'd'; 4096]);
        g.file_frames_snapshot();
        let s = log.snapshot(Some(seq), Some(cursor), false);
        assert_eq!(s.events.len(), 1, "the filled direction is shown");
        cursor = s.amend_head;
        lines += 1;

        // 3. Much later the cage's own direction fills too. It must get its own line: this is the
        //    case a single shared trigger would have swallowed.
        up.push(&vec![b'u'; 4096]);
        g.file_frames_snapshot();
        let s = log.snapshot(Some(seq), Some(cursor), false);
        assert_eq!(
            s.events.len(),
            1,
            "the second direction to fill is shown too, not stranded until teardown"
        );
        cursor = s.amend_head;
        lines += 1;

        // 4. A filing with nothing new must not cost a line.
        g.file_frames_snapshot();
        assert!(
            log.snapshot(Some(seq), Some(cursor), false)
                .events
                .is_empty(),
            "a transcript that has not changed is not shown again"
        );

        // 5. The tunnel closes. Both directions were already cut at their cap, so nothing changed.
        drop(g);
        assert!(
            log.snapshot(Some(seq), Some(cursor), false)
                .events
                .is_empty(),
            "the tunnel's end adds nothing when it changed nothing"
        );
        assert_eq!(lines, 4, "four lines over the tunnel's whole life");
    }

    /// The other half of the bound: when a direction never fills, its transcript is incomplete until
    /// the tunnel ends — so the end IS worth a line, and it is the one that drops the cut marker.
    #[test]
    fn a_tunnel_that_ends_before_filling_is_shown_once_more_with_its_transcript_complete() {
        let (g, ring, log) = guard(CaptureLevel::Bodies, 1);
        let seq = g.seq;
        let (up, _down) = g.ws_sinks();
        up.push(b"a few frames");
        g.file_frames_snapshot();
        let s = log.snapshot(Some(seq), Some(0), false);
        assert_eq!(s.events.len(), 1);
        assert!(
            ring.get(&[seq]).0[0].ws_up.truncated,
            "shown while the tunnel is open, so it is a prefix"
        );

        drop(g);
        assert_eq!(
            log.snapshot(Some(seq), Some(s.amend_head), false)
                .events
                .len(),
            1,
            "the end re-emits it, because the transcript is complete only now"
        );
        assert!(
            !ring.get(&[seq]).0[0].ws_up.truncated,
            "and the cut marker is gone"
        );
    }

    /// A tunnel that carried no data frame at all is not re-emitted for its frames: there is nothing
    /// to show, and a reader following the log should not see the same line twice for nothing.
    #[test]
    fn a_tunnel_that_carried_nothing_is_not_re_emitted_for_its_frames() {
        let (g, ring, log) = guard(CaptureLevel::Bodies, 8);
        let seq = g.seq;
        g.set_request(b"GET /chat HTTP/1.1\r\n\r\n", &[]);
        let _ = g.ws_sinks();
        g.file_now(); // the handshake, at the `101`
        let after_handshake = log.snapshot(Some(seq), Some(0), false);
        assert_eq!(after_handshake.events.len(), 1);
        drop(g);
        assert!(
            ring.get(&[seq]).0[0].ws_up.is_empty(),
            "no frame, no transcript"
        );
        assert!(
            log.snapshot(Some(seq), Some(after_handshake.amend_head), false)
                .events
                .is_empty(),
            "and no second re-emission"
        );
    }

    #[test]
    fn an_exchange_with_neither_capture_nor_status_is_not_re_emitted_at_all() {
        let (g, _ring, log) = guard(CaptureLevel::Bodies, 8);
        let seq = g.seq;
        drop(g);
        let snap = log.snapshot(Some(seq), Some(0), false);
        assert!(
            snap.events.is_empty(),
            "nothing to show means nothing to re-emit"
        );
    }
}
