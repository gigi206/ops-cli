//! WebSocket proxying for the inspected (MITM) TLS path.
//!
//! Once a decrypted request is permitted and turns out to be a `Upgrade: websocket`
//! handshake, the proxy stops parsing HTTP and relays the raw bidirectional byte stream
//! between the in-cage client and the validated upstream. These helpers detect the
//! upgrade, reserialize the upgrade request/response, and pump the two directions.

use super::capture::{CapBuf, CaptureGuard};
use super::*;
use miniz_oxide::inflate::stream::{inflate, InflateState};
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
/// [`Inflater`]. Control frames (close, ping, pong) carry no application data and are skipped, and
/// they may interleave a fragmented message without disturbing its reassembly.
pub(super) struct FrameTee {
    sink: Arc<CapBuf>,
    /// The header of the frame being decoded. It can arrive split across reads, and is bounded: a
    /// WebSocket frame header is at most 14 bytes.
    header: Vec<u8>,
    /// What is left of the current frame's payload, and how this frame is to be treated.
    payload_left: u64,
    keeps: bool,
    mask: Option<[u8; 4]>,
    /// Where in the 4-byte mask key the next payload byte lands, carried across reads.
    mask_at: u8,
    /// Set once the sink is full or the framing stopped making sense; from then on this direction
    /// costs nothing at all.
    done: bool,
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
}

impl Inflater {
    fn new(no_context_takeover: bool) -> Self {
        Inflater {
            state: InflateState::new_boxed(DataFormat::Raw),
            no_context_takeover,
        }
    }

    /// Inflate one whole message, yielding at most `cap + 1` bytes — one past the sink's capacity, so
    /// a message that overflows is seen as an overflow rather than as one that happened to fit.
    /// `None` means the stream did not decode, and the caller stops capturing this direction rather
    /// than storing rubbish.
    fn message(&mut self, compressed: &[u8], cap: usize) -> Option<Vec<u8>> {
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
            if read >= input.len() || written >= limit {
                break;
            }
            if written == out.len() {
                // The output buffer filled while input remained: grow it, still bounded by `limit`.
                let grown = (out.len() * 2).min(limit);
                if grown == out.len() {
                    break;
                }
                out.resize(grown, 0);
            } else if res.bytes_consumed == 0 && res.bytes_written == 0 {
                // No progress and no room needed: the decoder wants more input than this message
                // has, which for a whole message means the stream is not what it claimed.
                return None;
            }
        }
        out.truncate(written);
        if self.no_context_takeover {
            self.state.reset(DataFormat::Raw);
        }
        Some(out)
    }
}

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
/// case nothing is compressed. A response naming any other extension first is not something this
/// decoder can follow, so it reports nothing negotiated and the payloads are captured as they cross.
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
    // One negotiated extension per comma-separated entry; only the deflate one concerns this.
    for entry in value.split(',') {
        let mut params = entry.split(';').map(str::trim);
        if !params
            .next()
            .is_some_and(|n| n.eq_ignore_ascii_case("permessage-deflate"))
        {
            continue;
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
        return out;
    }
    Deflate::default()
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
    /// A decoder feeding `sink`. `deflate` carries the negotiated compression for this direction:
    /// `None` when the extension was not agreed, so nothing is reassembled or inflated.
    pub(super) fn new(sink: Arc<CapBuf>, deflate: Option<bool>) -> Self {
        FrameTee {
            sink,
            header: Vec::with_capacity(14),
            payload_left: 0,
            keeps: false,
            mask: None,
            mask_at: 0,
            done: false,
            inflater: deflate.map(Inflater::new),
            pending: Vec::new(),
            compressed: false,
            fin: false,
        }
    }

    /// Follow `chunk` through the framing, capturing what it carries. Returns whether the sink filled
    /// on this pass — the moment worth showing a long-lived tunnel's transcript, since nothing more
    /// will be captured for this direction.
    pub(super) fn push(&mut self, chunk: &[u8]) -> bool {
        if self.done {
            return false;
        }
        let mut at = 0;
        while at < chunk.len() {
            if self.payload_left == 0 {
                self.header.push(chunk[at]);
                at += 1;
                match scan_frame_header(&self.header) {
                    HeaderScan::Need => continue,
                    HeaderScan::Bad => {
                        self.done = true;
                        return false;
                    }
                    HeaderScan::Done {
                        payload_len,
                        keeps,
                        mask,
                        fin,
                        rsv1,
                        starts_message,
                    } => {
                        self.payload_left = payload_len;
                        self.keeps = keeps;
                        self.mask = mask;
                        self.mask_at = 0;
                        self.header.clear();
                        if keeps {
                            self.fin = fin;
                            if starts_message {
                                // A new message: whether it is compressed is decided here and
                                // inherited by its continuation frames.
                                self.compressed = rsv1 && self.inflater.is_some();
                                self.pending.clear();
                            }
                        }
                    }
                }
                // A zero-length frame carries no payload to consume, so its end is here.
                if self.payload_left == 0 && self.end_of_frame() {
                    return true;
                }
                continue;
            }
            let take = self.payload_left.min((chunk.len() - at) as u64) as usize;
            if self.keeps {
                let mut piece = chunk[at..at + take].to_vec();
                if let Some(key) = self.mask {
                    for (n, byte) in piece.iter_mut().enumerate() {
                        *byte ^= key[(self.mask_at as usize + n) % 4];
                    }
                }
                if self.compressed {
                    // A compressed message is only decodable whole, so it is held until its last
                    // frame. Bounded by what the sink could ever keep: past that, inflating more
                    // would yield bytes that are discarded anyway, and stopping mid-message leaves
                    // the shared window out of step, so this direction stops here rather than
                    // decoding the rest wrongly.
                    if self.pending.len() + piece.len() > self.compressed_budget() {
                        self.sink.push(&piece);
                        self.done = true;
                        return true;
                    }
                    self.pending.extend_from_slice(&piece);
                } else if self.sink.push(&piece) {
                    self.done = true;
                    return true;
                }
            }
            self.mask_at = ((self.mask_at as usize + take) % 4) as u8;
            self.payload_left -= take as u64;
            at += take;
            if self.payload_left == 0 && self.end_of_frame() {
                return true;
            }
        }
        false
    }

    /// The most compressed bytes held for one message. Generous against the sink's own capacity,
    /// since compression is the point: a message that inflates to far more than this is cut by the
    /// sink, not here.
    fn compressed_budget(&self) -> usize {
        self.sink.cap().saturating_mul(4).max(64 * 1024)
    }

    /// Settle a frame that has just ended. A compressed message becomes capturable only now, on its
    /// final frame. Returns whether the sink filled.
    fn end_of_frame(&mut self) -> bool {
        if !self.keeps || !self.compressed || !self.fin {
            return false;
        }
        let compressed = std::mem::take(&mut self.pending);
        let cap = self.sink.cap();
        let Some(inflater) = self.inflater.as_mut() else {
            return false;
        };
        match inflater.message(&compressed, cap) {
            Some(plain) => {
                if self.sink.push(&plain) {
                    self.done = true;
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
    let mask = masked.then(|| {
        let at = 2 + extended;
        [buf[at], buf[at + 1], buf[at + 2], buf[at + 3]]
    });
    HeaderScan::Done {
        payload_len,
        keeps: matches!(opcode, 0x0..=0x2),
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
pub(super) fn reserialize_upgrade(head: &Head, injections: &[(&str, &str)]) -> Vec<u8> {
    let mut out = String::with_capacity(head.request_line.len() + 64);
    out.push_str(&head.request_line);
    out.push_str("\r\n");
    for (k, v) in &head.headers {
        if k.eq_ignore_ascii_case("proxy-connection") || k.eq_ignore_ascii_case("expect") {
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
    injected: &[(&str, &str)],
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
    let resp_head = read_head_buffered(&mut up_br, HEAD_MAX)?;

    if parse_status_code(&resp_head) != Some(101) {
        // The upstream declined the upgrade — relay its response as a normal one, then close. The
        // upstream keeps the read timeout it was given (the handshake did not force `Connection:
        // close`), so a keep-alive response without an EOF is bounded by that timeout, not hung.
        if let Some(code) = parse_status_code(&resp_head) {
            if code >= 200 {
                ctx.set_status(allow_seq, code);
            }
        }
        br.get_mut().write_all(&resp_head)?;
        down.fetch_add(resp_head.len() as u64, Ordering::Relaxed);
        // A declined upgrade is an ordinary response — capture its head, then tee its body like any
        // other. The guard files when this handler returns.
        if let Some(c) = capture {
            c.push_response(&resp_head);
        }
        // Count the declined response body (`down`) as it streams back to the client.
        let counted = CountingReader::new(&mut up_br, down.clone());
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
    relay_websocket(
        client,
        &client_pending,
        upstream,
        &upstream_pending,
        capture,
        deflate,
        up,
        down,
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
/// The bytes each side already read past its head (`*_pending`) are seeded into the send buffers first.
#[allow(clippy::too_many_arguments)]
pub(super) fn relay_websocket(
    mut client: StreamOwned<ServerConnection, UnixStream>,
    client_pending: &[u8],
    mut upstream: StreamOwned<ClientConnection, TcpStream>,
    upstream_pending: &[u8],
    capture: Option<&CaptureGuard>,
    deflate: Deflate,
    up: Arc<AtomicU64>,
    down: Arc<AtomicU64>,
) -> io::Result<()> {
    // Seed the already-read bytes into the destination send buffers (the loop flushes them out), and
    // count them (`up` = client→upstream, `down` = upstream→client) toward the live flow view.
    upstream.conn.writer().write_all(client_pending)?;
    client.conn.writer().write_all(upstream_pending)?;
    up.fetch_add(client_pending.len() as u64, Ordering::Relaxed);
    down.fetch_add(upstream_pending.len() as u64, Ordering::Relaxed);

    // The traffic capture's frame decoders, one per direction, when the launch captures bodies. They
    // see exactly the bytes the relay moves — starting with the ones each side already read past its
    // handshake head, which are frames like any other and would otherwise be missed.
    let capture = capture.filter(|c| c.keeps_body());
    let (mut tee_up, mut tee_down) = match capture {
        Some(c) => {
            let (to_upstream, to_client) = c.ws_sinks();
            // Each direction is decompressed under the peer that COMPRESSES it: the cage's frames
            // by the client parameters, the upstream's by the server ones.
            let (up_deflate, down_deflate) = match deflate.negotiated {
                true => (
                    Some(deflate.client_no_context_takeover),
                    Some(deflate.server_no_context_takeover),
                ),
                false => (None, None),
            };
            (
                Some(FrameTee::new(to_upstream, up_deflate)),
                Some(FrameTee::new(to_client, down_deflate)),
            )
        }
        None => (None, None),
    };
    // The transcript is filed whenever a direction reaches its cap, and once more when the tunnel
    // ends (in the capture guard's teardown). Each direction has its own trigger, and each fires at
    // most once: one side of a live stream can fill in seconds while the other trickles for hours,
    // so a single shared trigger would strand whichever filled second. The guard drops a filing that
    // would show what it already showed, which is what keeps the count bounded.
    let mut filled = false;
    if let Some(tee) = &mut tee_up {
        filled |= tee.push(client_pending);
    }
    if let Some(tee) = &mut tee_down {
        filled |= tee.push(upstream_pending);
    }
    if filled {
        if let Some(c) = capture {
            c.file_frames_snapshot();
        }
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
                    upstream.conn.writer().write_all(&buf[..n])?;
                    up.fetch_add(n as u64, Ordering::Relaxed);
                    if let Some(tee) = &mut tee_up {
                        if tee.push(&buf[..n]) {
                            if let Some(c) = capture {
                                c.file_frames_snapshot();
                            }
                        }
                    }
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
                    client.conn.writer().write_all(&buf[..n])?;
                    down.fetch_add(n as u64, Ordering::Relaxed);
                    if let Some(tee) = &mut tee_down {
                        if tee.push(&buf[..n]) {
                            if let Some(c) = capture {
                                c.file_frames_snapshot();
                            }
                        }
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
        let mut out = vec![0x80 | opcode];
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
        (FrameTee::new(sink.clone(), None), sink)
    }

    /// The same over a `permessage-deflate` direction; `no_takeover` mirrors what the peer announced.
    fn deflating_tee(cap: usize, no_takeover: bool) -> (FrameTee, Arc<CapBuf>) {
        let sink = Arc::new(CapBuf::new(cap));
        (FrameTee::new(sink.clone(), Some(no_takeover)), sink)
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
        use miniz_oxide::deflate::core::{compress, TDEFLFlush};
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
        use miniz_oxide::deflate::core::{compress, CompressorOxide, TDEFLFlush};
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
}
