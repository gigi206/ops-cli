//! Low-level HTTP/1.1 wire parsing and byte plumbing for the proxy.
//!
//! Pure, self-contained helpers the CONNECT/MITM and cleartext paths share: request-head
//! parsing, request-line/authority splitting, byte-counting stream wrappers, and
//! chunked-transfer decoding. None of these touch the proxy's policy or connection state.

use super::*;

/// Whether the request head carries `Expect: 100-continue` (case-insensitive) — the client will
/// withhold its body until it sees a `100 Continue`, so the proxy answers one on the upstream's behalf.
pub(super) fn head_expects_continue(head: &Head) -> bool {
    head.headers
        .iter()
        .any(|(k, v)| k.eq_ignore_ascii_case("expect") && v.eq_ignore_ascii_case("100-continue"))
}

/// Whether two header names denote the same header for stripping: case-insensitive, and
/// treating `_` and `-` as equivalent (some servers fold `X_API_KEY` onto `X-Api-Key`). So a
/// client cannot dodge the strip-and-replace with an alternate spelling of a header sbx injects.
pub(super) fn header_name_eq(a: &str, b: &str) -> bool {
    let norm = |s: &str| -> Vec<u8> {
        s.bytes()
            .map(|c| {
                if c == b'_' {
                    b'-'
                } else {
                    c.to_ascii_lowercase()
                }
            })
            .collect()
    };
    norm(a) == norm(b)
}

/// Parse a request head's bytes into its request line and headers. A non-UTF-8 or empty head is an
/// error.
pub(super) fn parse_head(bytes: &[u8]) -> io::Result<Head> {
    let text = std::str::from_utf8(bytes).map_err(|_| invalid("non-UTF-8 request head"))?;
    let mut lines = text.split("\r\n").flat_map(|l| l.split('\n'));
    let request_line = lines.next().unwrap_or("").to_string();
    if request_line.is_empty() {
        return Err(invalid("empty request line"));
    }
    let mut headers = Vec::new();
    for line in lines {
        if line.is_empty() {
            break;
        }
        if let Some((k, v)) = line.split_once(':') {
            headers.push((k.trim().to_string(), v.trim().to_string()));
        }
    }
    Ok(Head {
        request_line,
        headers,
    })
}

/// Whether a parsed request head carries a byte another parser could frame the message by.
///
/// [`parse_head`] splits on CRLF *and* on a bare LF, so no LF survives into a name or a value. A lone
/// CR does — the trim only reaches the ends — and so does a NUL. Every inspected request is then
/// written out again by [`reserialize_request`], which emits each name
/// and value verbatim.
///
/// That re-serialization is what makes sbx's own reading of a request authoritative, and it is what
/// closes the ordinary smuggling desync: the upstream sees what sbx parsed, never what the client
/// framed. A byte the upstream's parser reads as a line break reopens it from inside a header sbx
/// wrote itself. The reach is not theoretical — it is how a process in the cage puts a second
/// `Authorization` in front of the one sbx strips and replaces, having never held the credential.
///
/// The rule is the one the HTTP/2 plane already gets for free, HPACK decoding into
/// `http::HeaderValue`: a byte must be HTAB, visible ASCII, or `obs-text`. Adopting it here is what
/// makes the same request refused on every plane rather than on one of the three.
pub(super) fn head_carries_control_byte(head: &Head) -> bool {
    let bad = |s: &str| s.bytes().any(|b| b != b'\t' && (b < 0x20 || b == 0x7f));
    bad(&head.request_line) || head.headers.iter().any(|(k, v)| bad(k) || bad(v))
}

/// What a request's framing says, once every ambiguity a downstream parser could desync on has been
/// refused. See [`inspect_framing`].
pub(super) struct Framing {
    /// Whether the body arrives `Transfer-Encoding: chunked`, so its length is discovered by
    /// de-chunking rather than declared.
    pub(super) chunked: bool,
    /// The declared body length. Zero for a chunked request, which declares none, and zero for one
    /// that carries no body.
    pub(super) body_len: u64,
}

/// Why a request's framing was refused: the reason token that goes in the log and the
/// `X-Sbx-Egress-Reason` header, and the sentence that goes in the body. Both static, because both
/// are about the *shape* of the request rather than about anything in it.
pub(super) struct FramingRefusal {
    pub(super) reason: &'static str,
    pub(super) detail: &'static str,
}

/// Read a request's framing, refusing every ambiguity that could desync a downstream parser.
///
/// **One function for every inspected plane**, and that is the point rather than a tidiness. This
/// check was written out three times, once per plane, and the copies drifted: a bare CR reached two
/// planes after being refused on the third, and the reason tokens diverged for years — each divergence
/// found later, by someone looking, rather than by the code refusing to hold two answers.
///
/// What legitimately differs is `forwards_chunked`. The two inspected planes de-chunk a `chunked`
/// body and re-frame it with a synthesized `Content-Length`, so no CL/TE ambiguity reaches the
/// upstream; the cleartext plane forwards no chunked framing at all and refuses the coding outright.
/// The refusal is the same token either way, since the caller's question is the same one, and only
/// the sentence changes.
pub(super) fn inspect_framing(
    head: &Head,
    forwards_chunked: bool,
) -> Result<Framing, FramingRefusal> {
    if head_carries_control_byte(head) {
        return Err(FramingRefusal {
            reason: "bad-request:control-char",
            detail: super::CONTROL_BYTE_DETAIL,
        });
    }
    let chunked = match head.header("transfer-encoding").map(str::trim) {
        Some(v) if forwards_chunked && v.eq_ignore_ascii_case("chunked") => true,
        Some(_) => {
            return Err(FramingRefusal {
                reason: "bad-request:transfer-encoding",
                detail: if forwards_chunked {
                    "the request carries a Transfer-Encoding coding other than `chunked`, which \
                     this egress proxy does not forward"
                } else {
                    "the request carries a Transfer-Encoding, which this cleartext path does not \
                     forward"
                },
            });
        }
        None => false,
    };
    if head.count("content-length") > 1 {
        return Err(FramingRefusal {
            reason: "bad-request:dup-content-length",
            detail: "the request carries a duplicated Content-Length header",
        });
    }
    if head.count("host") > 1 {
        return Err(FramingRefusal {
            reason: "bad-request:dup-host",
            detail: "the request carries a duplicated Host header",
        });
    }
    // Known up front only for a Content-Length-framed request; a chunked one's length is discovered
    // by the de-chunker, so nothing is parsed for it here.
    let body_len = match head.header("content-length").filter(|_| !chunked) {
        Some(v) => v.trim().parse().map_err(|_| FramingRefusal {
            reason: "bad-request:invalid-content-length",
            detail: "the Content-Length header is not a valid number",
        })?,
        None => 0,
    };
    Ok(Framing { chunked, body_len })
}

/// The method and target of a request line, requiring all three space-separated tokens
/// (`METHOD target HTTP/x`).
pub(super) fn request_line_parts(line: &str) -> Option<(String, String)> {
    let mut it = line.split_whitespace();
    let method = it.next()?.to_string();
    let target = it.next()?.to_string();
    it.next()?; // the HTTP-version token must be present
    Some((method, target))
}

/// Split a CONNECT authority `host:port` (port required) into its parts, handling a bracketed
/// IPv6 literal.
pub(super) fn split_authority(authority: &str) -> Option<(String, u16)> {
    if let Some(rest) = authority.strip_prefix('[') {
        let (addr, tail) = rest.split_once(']')?;
        let port = tail.strip_prefix(':')?.parse().ok()?;
        return Some((addr.to_string(), port));
    }
    let (h, p) = authority.rsplit_once(':')?;
    Some((h.to_string(), p.parse().ok()?))
}

/// A `Host` header value with any `:port` removed (handling a bracketed IPv6 literal).
pub(super) fn strip_port(authority: &str) -> String {
    if let Some(rest) = authority.strip_prefix('[')
        && let Some((addr, _)) = rest.split_once(']')
    {
        return addr.to_string();
    }
    match authority.rsplit_once(':') {
        Some((h, p)) if !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()) => h.to_string(),
        _ => authority.to_string(),
    }
}

/// A `Read` adapter that adds every byte it yields to a shared counter — the live byte total the flow
/// registry exposes for `sbx net live`. Wrapping the *reader* (not the fd) is what lets one counter
/// cover the inspected L7/cleartext plaintext streams and the raw L4 splice uniformly. On the splice
/// path this means `io::copy` no longer sees two bare fds, so it cannot take the kernel `splice(2)`
/// fast-path std uses for socket→socket copies (falling back to a userspace loop). This is a deliberate
/// trade: continuous byte accounting is the whole point of the live view for exactly the durable
/// `tcp://` tunnels — a count only at close would read zero for a whole active SSH/download. The
/// inspected L7/cleartext/WebSocket pumps are already userspace, so they pay nothing extra.
pub(super) struct CountingReader<R> {
    inner: R,
    counter: Arc<AtomicU64>,
}

impl<R> CountingReader<R> {
    pub(super) fn new(inner: R, counter: Arc<AtomicU64>) -> Self {
        CountingReader { inner, counter }
    }
}

impl<R: Read> Read for CountingReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.inner.read(buf)?;
        self.counter.fetch_add(n as u64, Ordering::Relaxed);
        Ok(n)
    }
}

/// A `Write` adapter that adds every byte it accepts to a shared counter (the write-side twin of
/// [`CountingReader`]).
pub(super) struct CountingWriter<W> {
    inner: W,
    counter: Arc<AtomicU64>,
}

impl<W> CountingWriter<W> {
    pub(super) fn new(inner: W, counter: Arc<AtomicU64>) -> Self {
        CountingWriter { inner, counter }
    }
}

impl<W: Write> Write for CountingWriter<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let n = self.inner.write(buf)?;
        self.counter.fetch_add(n as u64, Ordering::Relaxed);
        Ok(n)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

/// How much the relay moves per read/write on the inspected path.
///
/// Sized by measurement rather than by habit. On a loopback upstream the inspected relay moved
/// ~1300 MiB/s at 8 KiB and ~1490 MiB/s at 64 KiB, while the raw L4 splice — which does not use this
/// buffer — stayed flat across both, so the gain is the syscall count falling and not the machine
/// drifting. Going larger buys little: what remains is the TLS record work either side of the copy,
/// which no chunk size removes. Heap-held rather than a stack array, so a connection thread's frame
/// does not grow with it.
pub(super) const RELAY_CHUNK: usize = 64 * 1024;

/// Copy exactly `n` bytes from `r` to `w`; a short read is an error (a truncated body).
pub(super) fn copy_exact<R: Read, W: Write>(r: &mut R, w: &mut W, mut n: u64) -> io::Result<()> {
    let mut buf = vec![0u8; RELAY_CHUNK];
    while n > 0 {
        let want = n.min(buf.len() as u64) as usize;
        let got = r.read(&mut buf[..want])?;
        if got == 0 {
            return Err(invalid("request body shorter than Content-Length"));
        }
        w.write_all(&buf[..got])?;
        n -= got as u64;
    }
    Ok(())
}

/// The most one chunk-size line (or one trailer line) may be before it is refused. A chunk-size
/// line is a hex count plus optional `;extensions`; a trailer is one header — both are short, so 8
/// KiB is generous. Without this bound a bare `read_until` would buffer an arbitrarily long
/// no-newline flood *before* any size check, letting an in-cage client force unbounded host-side
/// allocation (this proxy runs outside the cage's cgroup) — the same footgun `read_head_buffered`
/// caps.
pub(super) const CHUNK_LINE_MAX: u64 = 8 * 1024;

/// De-chunk a `Transfer-Encoding: chunked` request body into one buffer, fail-closed on malformed
/// framing (a non-hex chunk size, a short data read, a missing trailing CRLF) or a body over
/// the caller's ceiling. The caller re-frames the result with a synthesized `Content-Length`
/// (stripping `Transfer-Encoding`), so the upstream receives one unambiguous Content-Length and no
/// TE — no CL/TE request-smuggling ambiguity can reach it. Trailers after the zero chunk are read
/// and discarded (the proxy does not forward them; they are not part of any secret-tripwire path).
pub(super) fn read_chunked_body<R: BufRead>(r: &mut R, cap: u64) -> io::Result<Vec<u8>> {
    let mut buf = Vec::new();
    loop {
        let size = read_chunk_size_line(r)?;
        if size == 0 {
            // trailers (if any) end at a blank line; read until it, each trailer line bounded.
            loop {
                let t = read_line_bounded(r, CHUNK_LINE_MAX)?;
                if t.is_empty() || strip_eol(&t).is_empty() {
                    break;
                }
            }
            return Ok(buf);
        }
        // `checked_add` so a crafted `ffffffffffffffff` (u64::MAX) size cannot overflow the running
        // total and slip past the cap (which would then panic in `resize`/the slice below).
        let start = buf.len();
        if (start as u64)
            .checked_add(size)
            .is_none_or(|total| total > cap)
        {
            return Err(invalid("chunked request body exceeds the proxy cap"));
        }
        buf.resize(start + size as usize, 0);
        r.read_exact(&mut buf[start..])?;
        let mut crlf = [0u8; 2];
        r.read_exact(&mut crlf)?;
        if crlf != *b"\r\n" {
            return Err(invalid("chunk data not followed by CRLF"));
        }
    }
}

/// Read one `\n`-terminated line, bounded to `max` bytes (a no-newline flood over the bound is a
/// hard error, not unbounded buffering — mirrors `read_head_buffered`). Returns the line including
/// its terminator; an empty return means EOF before any byte.
pub(super) fn read_line_bounded<R: BufRead>(r: &mut R, max: u64) -> io::Result<Vec<u8>> {
    let mut line = Vec::new();
    // +1 so a line of exactly `max` bytes plus its terminator is distinguishable from an overflow.
    let n = r.take(max + 1).read_until(b'\n', &mut line)?;
    if n == 0 {
        return Ok(line);
    }
    if line.len() as u64 > max {
        return Err(invalid("chunked framing line too long"));
    }
    Ok(line)
}

/// Read one chunk-size line (hex, optionally followed by `;extensions`), parse the size, and
/// require a CRLF/LF terminator so an EOF mid-line is a malformed-body error, not a silent short
/// read. The line is length-bounded (see [`read_line_bounded`]).
pub(super) fn read_chunk_size_line<R: BufRead>(r: &mut R) -> io::Result<u64> {
    let line = read_line_bounded(r, CHUNK_LINE_MAX)?;
    if line.is_empty() {
        return Err(invalid("chunked body ended before a chunk size"));
    }
    parse_chunk_size(&line)
}

/// Parse the size out of one already-read chunk-size line (hex, optionally followed by
/// `;extensions`), requiring a CRLF/LF terminator so a line cut short by an EOF is a malformed-body
/// error rather than a silent short read. Split out from [`read_chunk_size_line`] so a relay that
/// must forward the line verbatim can parse the copy it already holds.
pub(super) fn parse_chunk_size(line: &[u8]) -> io::Result<u64> {
    if !line.ends_with(b"\n") {
        return Err(invalid("chunk size line has no line terminator"));
    }
    let s = strip_eol(line);
    let size_field = match s.iter().position(|&b| b == b';') {
        Some(i) => &s[..i],
        None => s,
    };
    let size_str =
        std::str::from_utf8(size_field).map_err(|_| invalid("chunk size is not ASCII"))?;
    u64::from_str_radix(size_str.trim(), 16).map_err(|_| invalid("chunk size is not hexadecimal"))
}

/// Read a response head from a buffered reader, **tolerantly**: like [`read_head_buffered`], but an
/// upstream that closes, errors, or floods past `max` before the blank-line terminator yields what
/// was read with `complete = false` instead of failing. The response path relays whatever the
/// upstream managed to send and lets the relay end on the EOF that follows, so a truncated head must
/// stay a truncated relay here and not become a hard error the client never sees the reason for.
/// Bytes past the head stay in the reader.
pub(super) fn read_response_head<R: BufRead>(r: &mut R, max: usize) -> (Vec<u8>, bool) {
    let mut buf = Vec::new();
    loop {
        let start = buf.len();
        // Cap each line at the remaining budget (+1 to detect overflow), for the reason
        // `read_head_buffered` does: a bare `read_until` would buffer an arbitrarily long
        // no-newline flood before any size check could run.
        let budget = (max - start + 1) as u64;
        match (&mut *r).take(budget).read_until(b'\n', &mut buf) {
            // EOF, or a read error/timeout: hand back what arrived and let the caller relay it.
            Ok(0) | Err(_) => return (buf, false),
            Ok(_) => {}
        }
        if buf.len() > max {
            return (buf, false);
        }
        if matches!(&buf[start..], b"\r\n" | b"\n") {
            return (buf, true);
        }
    }
}

/// Where an HTTP/1.1 response body ends, decided from the response head (RFC 9112 §6.3).
pub(super) enum BodyFraming {
    /// The message has no body at all, whatever its head declares: a `1xx`, a `204` or a `304`, or
    /// any response to a `HEAD`. Such a head routinely carries a `Content-Length` describing the
    /// entity that *would* have been sent — reading that many bytes would block forever on a body
    /// the server never sends, so the status wins over the length.
    Empty,
    /// Exactly this many bytes follow the head.
    Length(u64),
    /// The body is a chain of sized chunks ending at the terminal zero-size chunk and its trailers.
    Chunked,
    /// The end of the message cannot be determined from the head, so relay until the upstream
    /// closes. Either the head genuinely delimits by close (no length, no coding), or it is
    /// ambiguous: a duplicated or unparsable `Content-Length`, a final coding other than `chunked`,
    /// or both framings at once. Ambiguity **degrades to this rather than failing** — the forced
    /// `Connection: close` makes a close-delimited relay correct, and it is exactly what this path
    /// did before it framed anything, so framing can shorten the wait but never truncate a response
    /// it merely failed to understand.
    ToEof,
}

/// Decide where a response body ends, from its head bytes and the method that asked for it.
///
/// The order is the specification's and the first match wins: a bodiless status, then
/// `Transfer-Encoding`, then `Content-Length`, then close-delimited. Anything unparsable or
/// ambiguous yields [`BodyFraming::ToEof`] — this decides how long to *read*, never what to
/// forward, so an undecidable head costs a close-delimited relay and not a refusal.
pub(super) fn response_framing(head: &[u8], request_method: &str) -> BodyFraming {
    let status = parse_status_code(head);
    if request_method.eq_ignore_ascii_case("head")
        || matches!(status, Some(204) | Some(304))
        || matches!(status, Some(c) if (100..200).contains(&c))
    {
        return BodyFraming::Empty;
    }
    let Ok(parsed) = parse_head(head) else {
        return BodyFraming::ToEof;
    };
    let te = parsed.count("transfer-encoding");
    let cl = parsed.count("content-length");
    if te > 0 {
        // Both framings at once is the classic desync ambiguity, and more than one coding field
        // leaves which one is final undetermined. Neither is decidable here.
        if te > 1 || cl > 0 {
            return BodyFraming::ToEof;
        }
        let final_coding = parsed
            .header("transfer-encoding")
            .unwrap_or("")
            .rsplit(',')
            .next()
            .unwrap_or("")
            .trim()
            .to_string();
        return if final_coding.eq_ignore_ascii_case("chunked") {
            BodyFraming::Chunked
        } else {
            BodyFraming::ToEof
        };
    }
    if cl > 1 {
        return BodyFraming::ToEof;
    }
    match parsed.header("content-length") {
        Some(v) => match v.trim().parse::<u64>() {
            Ok(n) => BodyFraming::Length(n),
            Err(_) => BodyFraming::ToEof,
        },
        None => BodyFraming::ToEof,
    }
}

/// Whether a relayed response leaves its connection able to carry a further request. Read entirely
/// off the head the upstream sent, and false unless every one of three conditions holds:
///
///   - the protocol version persists: HTTP/1.1 does by default, HTTP/1.0 only when it asks to;
///   - no `close` token in `Connection` — that token is the upstream announcing this is the last
///     response it will serve on the connection;
///   - no `WWW-Authenticate` naming a **connection-bound** scheme (`NTLM`, `Negotiate`). Those bind
///     an authenticated identity to the TCP connection rather than to the request, so handing the
///     connection to a later request would hand it an authentication state it never asked for and
///     cannot see. A proxy that injects credentials of its own has no business blurring that line.
///
/// A head that will not parse is not reusable either: an unreadable head is exactly the case where
/// nothing about the connection's state is known.
pub(super) fn response_keeps_alive(head: &[u8]) -> bool {
    let Ok(parsed) = parse_head(head) else {
        return false;
    };
    // A repeated `Connection` is legal (each carries its own token list), so every one is read.
    let connection_token = |tok: &str| {
        parsed
            .headers
            .iter()
            .filter(|(k, _)| k.eq_ignore_ascii_case("connection"))
            .flat_map(|(_, v)| v.split(','))
            .any(|t| t.trim().eq_ignore_ascii_case(tok))
    };
    if connection_token("close") {
        return false;
    }
    let connection_bound_auth = parsed
        .headers
        .iter()
        .filter(|(k, _)| k.eq_ignore_ascii_case("www-authenticate"))
        .flat_map(|(_, v)| v.split(','))
        .any(|challenge| {
            let scheme = challenge.split_whitespace().next().unwrap_or("");
            scheme.eq_ignore_ascii_case("ntlm") || scheme.eq_ignore_ascii_case("negotiate")
        });
    if connection_bound_auth {
        return false;
    }
    match parsed.request_line.split(' ').next().unwrap_or("") {
        "HTTP/1.1" => true,
        "HTTP/1.0" => connection_token("keep-alive"),
        _ => false,
    }
}

/// A response head rewritten as the **client** should see it: every `Connection` and `Keep-Alive`
/// header dropped, and a single `Connection: close` put back before the terminator.
///
/// The two legs of a forwarded request have independent connection lifetimes, and this is what keeps
/// them from being mistaken for one. Whether the upstream leg is held open for a later request and
/// whether the client's is are separate decisions, and passing the upstream's answer through as if
/// it were the client's would invite the client to send a second request into a socket already
/// closing: an idempotent one is silently retried, doubling the very traffic the reuse was meant to
/// save, and a `POST` simply fails. `Connection` is hop-by-hop, so setting it is the proxy's to do —
/// exactly as it already is on the request side. This is the writing half of that: the reading half
/// is [`response_keeps_alive`], and a plane that keeps its client leg calls neither.
///
/// A head with no blank-line terminator comes back untouched: there is nothing well-formed to
/// rewrite, and synthesizing a terminator would fabricate a head the upstream never sent.
pub(super) fn force_close_in_head(head: &[u8]) -> Vec<u8> {
    rewrite_client_connection(head, b"Connection: close\r\n")
}

/// The twin of [`force_close_in_head`] for a client leg that will carry another request: the same
/// drop of every `Connection` and `Keep-Alive` the upstream sent, with sbx's own answer put back.
///
/// Replacing rather than passing through is what keeps the two legs' hop parameters from being
/// mistaken for one. An upstream's `Keep-Alive: timeout=60` describes the upstream's socket; relayed
/// unchanged it would tell the client it has a minute on a tunnel sbx holds for `idle`, and a client
/// that believed it would send its next request into a connection already gone. `idle` is the
/// launch's own bound (`[network] idle_timeout`), so what is announced is what will be honored.
pub(super) fn offer_reuse_in_head(head: &[u8], idle: Duration) -> Vec<u8> {
    let replacement = format!(
        "Connection: keep-alive\r\nKeep-Alive: timeout={}\r\n",
        idle.as_secs()
    );
    rewrite_client_connection(head, replacement.as_bytes())
}

/// Drop every `Connection` and `Keep-Alive` header from a response head and put `replacement` back
/// in their place, just before the terminator — the shared body of the two rewrites above.
fn rewrite_client_connection(head: &[u8], replacement: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(head.len() + replacement.len());
    let mut lines = head.split_inclusive(|&b| b == b'\n');
    match lines.next() {
        // The status line is not a header; it is copied through verbatim.
        Some(status) => out.extend_from_slice(status),
        None => return head.to_vec(),
    }
    // Dropping a header written over several lines (the obsolete line folding) means dropping its
    // continuations too, or the fold would silently re-attach to whichever header now precedes it.
    let mut dropping = false;
    let mut terminated = false;
    for line in lines {
        let bare = strip_eol(line);
        if bare.is_empty() {
            out.extend_from_slice(replacement);
            out.extend_from_slice(line);
            terminated = true;
            break;
        }
        if matches!(bare.first(), Some(b' ' | b'\t')) {
            if dropping {
                continue;
            }
        } else {
            let name = bare
                .split(|&b| b == b':')
                .next()
                .unwrap_or(&[])
                .trim_ascii();
            dropping = name.eq_ignore_ascii_case(b"connection")
                || name.eq_ignore_ascii_case(b"keep-alive");
            if dropping {
                continue;
            }
        }
        out.extend_from_slice(line);
    }
    if terminated { out } else { head.to_vec() }
}

/// The framing state machine's position inside a response body.
enum BodyState {
    /// Nothing left to read. `as_framed` separates the two ways a body arrives here: `true` when it
    /// ended exactly where the head said it would (a bodiless status, the declared length consumed,
    /// the blank line closing a chunked body's trailers), `false` when the upstream stopped
    /// mid-message. Both end the relay identically — the cage gets the bytes that did arrive — but
    /// only the first leaves the connection positioned at the start of whatever comes next.
    Done { as_framed: bool },
    /// This many declared bytes are still outstanding.
    Length(u64),
    /// At the start of a chunk-size line.
    ChunkSize,
    /// Inside a chunk's data, this many bytes from its end.
    ChunkData(u64),
    /// At the CRLF that closes a chunk's data.
    ChunkCrlf,
    /// Past the terminal zero chunk, reading trailer lines until the blank one.
    ChunkTrailers,
    /// Relay whatever comes until the upstream closes.
    ToEof,
}

/// A reader over one response body that **ends where the message ends**.
///
/// It yields the upstream's bytes verbatim — chunk-size lines and trailers included — and simply
/// reports EOF at the end of the framed message instead of waiting for the socket to close. So every
/// consumer stacked on top of it (the byte counter, the capture tee, the reflection masking) is
/// unchanged, and so is what the cage receives; only the moment the proxy stops reading moves.
///
/// Malformed framing discovered mid-body **degrades to [`BodyState::ToEof`]** rather than erroring:
/// by then some bytes are already relayed, and cutting the response would turn an upstream's framing
/// bug into a truncation the cage blames on sbx. The bytes that revealed the problem are relayed too,
/// so the degraded path is byte-for-byte the close-delimited relay this code did before it framed.
pub(super) struct FramedBody<R> {
    inner: R,
    state: BodyState,
    /// Framing bytes read ahead of the caller's request that still have to be relayed verbatim: one
    /// chunk-size line, one data-closing CRLF, or one trailer. Bounded by [`CHUNK_LINE_MAX`]; chunk
    /// *data* never passes through here, so a large body costs nothing extra.
    pending: Vec<u8>,
    at: usize,
}

impl<R: BufRead> FramedBody<R> {
    pub(super) fn new(inner: R, framing: BodyFraming) -> Self {
        let state = match framing {
            BodyFraming::Empty => BodyState::Done { as_framed: true },
            BodyFraming::Length(n) => BodyState::Length(n),
            BodyFraming::Chunked => BodyState::ChunkSize,
            BodyFraming::ToEof => BodyState::ToEof,
        };
        Self {
            inner,
            state,
            pending: Vec::new(),
            at: 0,
        }
    }

    /// Whether the body ended **exactly where its framing said it would**, leaving the reader
    /// positioned at the start of whatever the connection carries next.
    ///
    /// This is a check of the terminal state, not a flag raised along the way, and that is what
    /// makes it safe to build on: a relay abandoned part-way — a client that went away mid-body, a
    /// read that errored — leaves the machine inside `Length`/`ChunkData`, so it answers `false`
    /// without any caller having to remember to say so. Reaching [`BodyState::Done`] is not the
    /// answer either: the machine also lands there when the upstream stops mid-message, which ends
    /// the relay the same way but leaves the connection at an unknown position. A body delimited by
    /// the close is never framed, so it never qualifies.
    pub(super) fn ended_as_framed(&self) -> bool {
        matches!(self.state, BodyState::Done { as_framed: true })
    }

    /// Read one framing line, returning its bytes whether or not it was terminated. An untermined
    /// or over-long line is a malformed body, and the caller degrades — but it must still relay what
    /// was consumed, so the bytes come back either way.
    fn framing_line(&mut self) -> (Vec<u8>, bool) {
        let mut line = Vec::new();
        let complete = match (&mut self.inner)
            .take(CHUNK_LINE_MAX + 1)
            .read_until(b'\n', &mut line)
        {
            Ok(0) | Err(_) => false,
            Ok(_) => line.len() as u64 <= CHUNK_LINE_MAX && line.ends_with(b"\n"),
        };
        (line, complete)
    }
}

impl<R: BufRead> Read for FramedBody<R> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        loop {
            // Framing bytes always leave first, so the relay stays in wire order.
            if self.at < self.pending.len() {
                let n = (self.pending.len() - self.at).min(out.len());
                out[..n].copy_from_slice(&self.pending[self.at..self.at + n]);
                self.at += n;
                if self.at == self.pending.len() {
                    self.pending.clear();
                    self.at = 0;
                }
                return Ok(n);
            }
            if out.is_empty() {
                return Ok(0);
            }
            match self.state {
                BodyState::Done { .. } => return Ok(0),
                BodyState::ToEof => return self.inner.read(out),
                BodyState::Length(0) => {
                    self.state = BodyState::Done { as_framed: true };
                    return Ok(0);
                }
                BodyState::Length(n) => {
                    let want = n.min(out.len() as u64) as usize;
                    let got = self.inner.read(&mut out[..want])?;
                    if got == 0 {
                        // The upstream closed before its declared length. Ending here hands the cage
                        // the bytes that did arrive followed by a clean close, which is what a
                        // close-delimited relay did with the same truncation.
                        self.state = BodyState::Done { as_framed: false };
                        return Ok(0);
                    }
                    self.state = BodyState::Length(n - got as u64);
                    return Ok(got);
                }
                BodyState::ChunkSize => {
                    let (line, complete) = self.framing_line();
                    let size = complete.then(|| parse_chunk_size(&line).ok()).flatten();
                    self.state = match size {
                        Some(0) => BodyState::ChunkTrailers,
                        Some(n) => BodyState::ChunkData(n),
                        None if line.is_empty() => BodyState::Done { as_framed: false },
                        None => BodyState::ToEof,
                    };
                    self.pending = line;
                }
                BodyState::ChunkData(0) => self.state = BodyState::ChunkCrlf,
                BodyState::ChunkData(n) => {
                    let want = n.min(out.len() as u64) as usize;
                    let got = self.inner.read(&mut out[..want])?;
                    if got == 0 {
                        self.state = BodyState::Done { as_framed: false };
                        return Ok(0);
                    }
                    self.state = BodyState::ChunkData(n - got as u64);
                    return Ok(got);
                }
                BodyState::ChunkCrlf => {
                    let mut crlf = [0u8; 2];
                    let n = read_full(&mut self.inner, &mut crlf)?;
                    self.state = if n == 2 && crlf == *b"\r\n" {
                        BodyState::ChunkSize
                    } else if n == 0 {
                        BodyState::Done { as_framed: false }
                    } else {
                        BodyState::ToEof
                    };
                    self.pending = crlf[..n].to_vec();
                }
                BodyState::ChunkTrailers => {
                    let (line, complete) = self.framing_line();
                    if !complete {
                        self.state = if line.is_empty() {
                            BodyState::Done { as_framed: false }
                        } else {
                            BodyState::ToEof
                        };
                    } else if strip_eol(&line).is_empty() {
                        self.state = BodyState::Done { as_framed: true };
                    }
                    self.pending = line;
                }
            }
        }
    }
}

/// Fill `buf` as far as the reader allows, returning how many bytes arrived — a short count means
/// the stream ended there. Unlike `read_exact`, a truncation is a fact to relay, not an error.
fn read_full<R: Read>(r: &mut R, buf: &mut [u8]) -> io::Result<usize> {
    let mut got = 0;
    while got < buf.len() {
        match r.read(&mut buf[got..])? {
            0 => break,
            n => got += n,
        }
    }
    Ok(got)
}

/// Drop a trailing `\r\n` (or a lone `\n`) from a line read with `read_until(b'\n')`.
pub(super) fn strip_eol(line: &[u8]) -> &[u8] {
    let mut end = line.len();
    if end > 0 && line[end - 1] == b'\n' {
        end -= 1;
    }
    if end > 0 && line[end - 1] == b'\r' {
        end -= 1;
    }
    &line[..end]
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Read a whole framed body, returning the bytes the relay would forward.
    fn framed(head: &[u8], method: &str, wire: &[u8]) -> Vec<u8> {
        let framing = response_framing(head, method);
        let mut body = FramedBody::new(io::BufReader::new(io::Cursor::new(wire.to_vec())), framing);
        let mut out = Vec::new();
        body.read_to_end(&mut out).unwrap();
        out
    }

    /// Read a whole framed body and report whether it ended where its framing said it would.
    fn framed_verdict(head: &[u8], method: &str, wire: &[u8]) -> bool {
        let framing = response_framing(head, method);
        let mut body = FramedBody::new(io::BufReader::new(io::Cursor::new(wire.to_vec())), framing);
        body.read_to_end(&mut Vec::new()).unwrap();
        body.ended_as_framed()
    }

    #[test]
    fn a_body_that_ends_where_its_framing_said_reports_so() {
        // The three ways a message can legitimately end. Each is followed on the wire by bytes that
        // do not belong to it, which is the situation the verdict exists for: they are exactly what a
        // reused connection would go on to read.
        for (head, method, wire) in [
            (
                &b"HTTP/1.1 204 No Content\r\n\r\n"[..],
                "GET",
                &b"HTTP/1.1 200 OK\r\n\r\n"[..],
            ),
            (
                &b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n"[..],
                "GET",
                &b"helloHTTP/1.1 200 OK\r\n\r\n"[..],
            ),
            (
                &b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"[..],
                "GET",
                &b"5\r\nhello\r\n0\r\n\r\nHTTP/1.1 200 OK\r\n\r\n"[..],
            ),
        ] {
            assert!(
                framed_verdict(head, method, wire),
                "a complete message must report itself framed: {:?}",
                String::from_utf8_lossy(head)
            );
        }
    }

    #[test]
    fn a_message_the_upstream_cut_short_is_not_reported_as_framed() {
        // Every one of these ends the relay at the same place a complete message would — the cage
        // gets the bytes that arrived and a clean close. What separates them is where the connection
        // is left, and that is the whole point of asking: a truncated message leaves it nowhere
        // knowable, so it must never be handed to another request.
        for (head, wire, what) in [
            (
                &b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\n"[..],
                &b"hello"[..],
                "a body shorter than its declared length",
            ),
            (
                &b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"[..],
                &b"5\r\nhel"[..],
                "a chunk cut inside its data",
            ),
            (
                &b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"[..],
                &b"5\r\nhello\r\n"[..],
                "a chunked body with no terminal chunk",
            ),
            (
                &b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"[..],
                &b"5\r\nhello\r\n0\r\n"[..],
                "a terminal chunk whose trailers never end",
            ),
        ] {
            assert!(
                !framed_verdict(head, "GET", wire),
                "{what} must not report itself framed"
            );
        }
    }

    #[test]
    fn a_close_delimited_body_is_never_reported_as_framed() {
        // Nothing in the head says where this ends, so the relay reads to the close. There is no
        // "after" on such a connection to be positioned at.
        assert!(!framed_verdict(b"HTTP/1.1 200 OK\r\n\r\n", "GET", b"hello"));
    }

    #[test]
    fn a_body_abandoned_part_way_is_not_reported_as_framed() {
        // The verdict is read off the terminal state rather than raised along the way, so a relay
        // that stops early — a client that went away mid-body — answers `false` on its own, with no
        // caller having to notice and say so.
        let mut body = FramedBody::new(
            io::BufReader::new(io::Cursor::new(b"hello world".to_vec())),
            BodyFraming::Length(11),
        );
        let mut some = [0u8; 5];
        body.read_exact(&mut some).unwrap();
        assert!(
            !body.ended_as_framed(),
            "a body still mid-message is not framed-complete"
        );
    }

    #[test]
    fn a_head_rewritten_for_the_client_carries_exactly_one_connection_close() {
        let out = force_close_in_head(
            b"HTTP/1.1 200 OK\r\nConnection: keep-alive\r\nKeep-Alive: timeout=5\r\n\
              Content-Length: 5\r\n\r\n",
        );
        assert_eq!(
            String::from_utf8(out).unwrap(),
            "HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\n",
            "the upstream's persistence headers give way to a single close"
        );
    }

    #[test]
    fn rewriting_a_head_drops_a_folded_headers_continuation_lines_too() {
        // Obsolete line folding: dropping only a folded header's first line would leave its
        // continuation attached to whatever header now precedes it, silently corrupting that one.
        let out = force_close_in_head(
            b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: keep-alive,\r\n te\r\nEtag: x\r\n\r\n",
        );
        assert_eq!(
            String::from_utf8(out).unwrap(),
            "HTTP/1.1 200 OK\r\nContent-Length: 5\r\nEtag: x\r\nConnection: close\r\n\r\n"
        );
    }

    #[test]
    fn an_unterminated_head_is_returned_untouched_rather_than_completed() {
        // Synthesizing the terminator would fabricate a head the upstream never sent.
        let cut = &b"HTTP/1.1 200 OK\r\nConnection: keep-alive\r\n"[..];
        assert_eq!(force_close_in_head(cut), cut);
    }

    #[test]
    fn a_response_states_whether_its_connection_survives_it() {
        for (head, reusable, what) in [
            (
                &b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"[..],
                true,
                "HTTP/1.1 persists by default",
            ),
            (
                &b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n"[..],
                false,
                "an explicit close ends the connection",
            ),
            (
                &b"HTTP/1.1 200 OK\r\nConnection: keep-alive, close\r\n\r\n"[..],
                false,
                "a close among several tokens still ends it",
            ),
            (
                &b"HTTP/1.0 200 OK\r\n\r\n"[..],
                false,
                "HTTP/1.0 does not persist unless it asks to",
            ),
            (
                &b"HTTP/1.0 200 OK\r\nConnection: keep-alive\r\n\r\n"[..],
                true,
                "HTTP/1.0 asking to persist",
            ),
            (
                &b"HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: NTLM\r\n\r\n"[..],
                false,
                "NTLM binds the identity to the connection",
            ),
            (
                &b"HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Negotiate, Basic realm=\"x\"\r\n\r\n"[..],
                false,
                "so does Negotiate, wherever it sits in the challenge list",
            ),
            (
                &b"HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Basic realm=\"x\"\r\n\r\n"[..],
                true,
                "a request-scoped scheme leaves the connection alone",
            ),
            (&b"not a response at all\r\n\r\n"[..], false, "an unparsable head knows nothing"),
        ] {
            assert_eq!(
                response_keeps_alive(head),
                reusable,
                "{what}: {:?}",
                String::from_utf8_lossy(head)
            );
        }
    }

    #[test]
    fn a_bodiless_status_ends_at_the_head_whatever_length_it_declares() {
        // The trap this exists for: `204`, `304` and a response to `HEAD` routinely carry a
        // `Content-Length` describing the entity that *would* have been sent. Reading that many
        // bytes waits forever on a body no server will send, so the status has to win. The wire
        // below holds the NEXT message's bytes — if any of them are consumed, the rule did not hold.
        for (head, method) in [
            (
                &b"HTTP/1.1 204 No Content\r\nContent-Length: 100\r\n\r\n"[..],
                "GET",
            ),
            (
                &b"HTTP/1.1 304 Not Modified\r\nContent-Length: 4096\r\n\r\n"[..],
                "GET",
            ),
            (
                &b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n"[..],
                "HEAD",
            ),
            (
                &b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n"[..],
                "head",
            ),
            (
                &b"HTTP/1.1 304 Not Modified\r\nTransfer-Encoding: chunked\r\n\r\n"[..],
                "GET",
            ),
        ] {
            assert!(
                matches!(response_framing(head, method), BodyFraming::Empty),
                "{method} {}",
                String::from_utf8_lossy(head)
            );
            assert_eq!(
                framed(head, method, b"NOT-THE-BODY"),
                b"",
                "{method}: a bodiless response must consume nothing"
            );
        }
    }

    #[test]
    fn a_content_length_body_ends_at_the_declared_length() {
        let head = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n";
        assert!(matches!(
            response_framing(head, "GET"),
            BodyFraming::Length(5)
        ));
        // Exactly the declared count is relayed and the trailing bytes — a smuggled second response
        // on a socket the proxy would otherwise keep draining — are left untouched.
        assert_eq!(framed(head, "GET", b"hello"), b"hello");
        assert_eq!(
            framed(head, "GET", b"helloHTTP/1.1 200 OK\r\n\r\nsmuggled"),
            b"hello"
        );
        // An upstream that closes before its declared length hands over what did arrive, as a
        // close-delimited relay did with the same truncation — not an error the cage cannot read.
        assert_eq!(framed(head, "GET", b"hel"), b"hel");
    }

    #[test]
    fn a_chunked_body_is_relayed_verbatim_and_ends_at_the_terminal_chunk() {
        let head = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n";
        assert!(matches!(
            response_framing(head, "GET"),
            BodyFraming::Chunked
        ));
        // Verbatim: the size lines, the CRLFs and the trailers all reach the client unchanged — the
        // proxy learns where the body ends without re-writing a byte of it.
        let wire = b"5\r\nhello\r\n3\r\n mo\r\n0\r\nX-T: v\r\n\r\nAFTER";
        assert_eq!(
            framed(head, "GET", wire),
            b"5\r\nhello\r\n3\r\n mo\r\n0\r\nX-T: v\r\n\r\n"
        );
        // No trailers is the common shape, and the terminal chunk still ends it.
        assert_eq!(
            framed(head, "GET", b"2\r\nhi\r\n0\r\n\r\nAFTER"),
            b"2\r\nhi\r\n0\r\n\r\n"
        );
        // A chunk extension is part of the size line and rides along untouched.
        assert_eq!(
            framed(head, "GET", b"2;a=b\r\nhi\r\n0\r\n\r\n"),
            b"2;a=b\r\nhi\r\n0\r\n\r\n"
        );
    }

    #[test]
    fn malformed_chunked_framing_degrades_to_the_close_rather_than_truncating() {
        // The rule the increment turns on: framing decides how long to READ, never what to forward.
        // A body that stops being decodable mid-stream falls back to relaying until the upstream
        // closes — which is what this path did before it framed anything — so an upstream's framing
        // bug can never become a truncation the cage blames on sbx.
        let head = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n";
        let wire = b"5\r\nhello\r\nNOTHEX\r\nrest of it";
        assert_eq!(framed(head, "GET", wire), wire);
        // Same for a chunk whose data is not followed by the CRLF the framing requires.
        let wire = b"5\r\nhelloXXtail";
        assert_eq!(framed(head, "GET", wire), wire);
    }

    #[test]
    fn an_undecidable_head_relays_until_the_upstream_closes() {
        // Every shape here leaves the end of the message undetermined, so each must relay to EOF —
        // the pre-framing behaviour — instead of guessing a length.
        for head in [
            // Nothing declared at all: genuinely close-delimited.
            &b"HTTP/1.1 200 OK\r\n\r\n"[..],
            // Both framings at once is the classic desync ambiguity.
            &b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\n"[..],
            // Two codings: which one is final is undetermined.
            &b"HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip\r\nTransfer-Encoding: chunked\r\n\r\n"[..],
            // A final coding other than `chunked` delimits nothing.
            &b"HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip\r\n\r\n"[..],
            // A duplicated or unparsable length is not a length.
            &b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nContent-Length: 9\r\n\r\n"[..],
            &b"HTTP/1.1 200 OK\r\nContent-Length: not-a-number\r\n\r\n"[..],
            &b"HTTP/1.1 200 OK\r\nContent-Length: -1\r\n\r\n"[..],
        ] {
            assert!(
                matches!(response_framing(head, "GET"), BodyFraming::ToEof),
                "{}",
                String::from_utf8_lossy(head)
            );
            assert_eq!(
                framed(head, "GET", b"everything until the close"),
                b"everything until the close",
                "{}",
                String::from_utf8_lossy(head)
            );
        }
        // `chunked` as the final coding of a list still frames.
        assert!(matches!(
            response_framing(
                b"HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip, chunked\r\n\r\n",
                "GET"
            ),
            BodyFraming::Chunked
        ));
    }

    #[test]
    fn a_head_this_proxy_cannot_parse_frames_nothing() {
        // Non-UTF-8 header bytes relay fine today; deciding they are unframeable keeps them relaying.
        let head = b"HTTP/1.1 200 OK\r\nX: \xff\xfe\r\n\r\n";
        assert!(matches!(response_framing(head, "GET"), BodyFraming::ToEof));
        assert_eq!(framed(head, "GET", b"body bytes"), b"body bytes");
    }

    #[test]
    fn read_response_head_leaves_a_body_that_shared_the_head_s_read() {
        // The wiring hazard of the whole change: the buffered reader pulls body bytes off the socket
        // while reading the head, so the body must be read from IT. One `Cursor` hands the head and
        // the body over in a single read, exactly as one TCP segment carrying both would.
        let mut src = io::BufReader::new(io::Cursor::new(
            b"HTTP/1.1 200 OK\r\nContent-Length: 11\r\n\r\nhello world".to_vec(),
        ));
        let (head, complete) = read_response_head(&mut src, 16 * 1024);
        assert!(complete);
        let framing = response_framing(&head, "GET");
        let mut out = Vec::new();
        FramedBody::new(src, framing).read_to_end(&mut out).unwrap();
        assert_eq!(
            out, b"hello world",
            "the body buffered alongside the head must not be lost"
        );
    }

    #[test]
    fn framing_survives_a_reader_that_dribbles_one_byte_at_a_time() {
        // A socket splits where it likes: every state of the machine must survive being fed one byte
        // per read, including mid-size-line and mid-trailer.
        struct Dribble(io::Cursor<Vec<u8>>);
        impl Read for Dribble {
            fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
                if out.is_empty() {
                    return Ok(0);
                }
                self.0.read(&mut out[..1])
            }
        }
        let wire = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n";
        let mut src = io::BufReader::with_capacity(1, Dribble(io::Cursor::new(wire.to_vec())));
        let (head, complete) = read_response_head(&mut src, 16 * 1024);
        assert!(complete);
        assert_eq!(
            head,
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
        );
        let mut out = Vec::new();
        FramedBody::new(src, response_framing(&head, "GET"))
            .read_to_end(&mut out)
            .unwrap();
        assert_eq!(out, b"5\r\nhello\r\n0\r\n\r\n");
    }

    #[test]
    fn parse_head_rejects_a_non_utf8_or_empty_head() {
        assert!(
            parse_head(&[0xff, 0xfe]).is_err(),
            "a non-UTF-8 head is refused"
        );
        assert!(parse_head(b"").is_err());
        assert!(
            parse_head(b"\r\n").is_err(),
            "an empty request line is refused"
        );
    }

    /// The exact rule, and where it comes from.
    ///
    /// First the vector, because the check only makes sense next to it: a bare CR is *not* a line
    /// break to [`parse_head`], so it lands whole inside a header value and is written back out
    /// verbatim. Then the rule, pinned side by side against `http::HeaderValue` — the validation the
    /// HTTP/2 plane performs for free when HPACK decodes a header. Every byte this refuses is a byte
    /// that plane already refuses, and every byte it allows is one that plane allows, so the same
    /// request is turned down whichever way into the cage it came.
    #[test]
    fn a_head_carrying_a_byte_another_parser_could_break_a_line_on_is_recognized() {
        let parsed =
            parse_head(b"GET / HTTP/1.1\r\nX-Note: a\rAuthorization: Bearer smuggled\r\n\r\n")
                .unwrap();
        assert_eq!(
            parsed.headers,
            vec![(
                "X-Note".to_string(),
                "a\rAuthorization: Bearer smuggled".to_string()
            )],
            "a bare CR is one header value here and two headers to a lenient upstream: the whole \
             reason this check exists"
        );
        assert!(head_carries_control_byte(&parsed));

        let with = |name: &str, value: &str| Head {
            request_line: "GET / HTTP/1.1".to_string(),
            headers: vec![(name.to_string(), value.to_string())],
        };
        for (case, byte) in [
            ("a carriage return", "\r"),
            ("a NUL", "\0"),
            ("a DEL", "\x7f"),
            ("a form feed", "\x0c"),
            ("a vertical tab", "\x0b"),
        ] {
            let value = format!("a{byte}b");
            assert!(head_carries_control_byte(&with("X-Note", &value)), "{case}");
            assert!(
                head_carries_control_byte(&with(&value, "v")),
                "{case}, in a header name"
            );
            assert!(
                http::HeaderValue::from_str(&value).is_err(),
                "{case} is no more acceptable on the HTTP/2 plane, which is where this rule is from"
            );
        }
        for (case, value) in [
            ("a tab", "a\tb"),
            ("ordinary text", "Bearer abc.def"),
            ("obs-text above ASCII", "café"),
        ] {
            assert!(!head_carries_control_byte(&with("X-Note", value)), "{case}");
            assert!(
                http::HeaderValue::from_str(value).is_ok(),
                "{case} is carried on the HTTP/2 plane, so it must be carried here"
            );
        }
        assert!(
            head_carries_control_byte(&Head {
                request_line: "GET /a\rHost: elsewhere HTTP/1.1".to_string(),
                headers: Vec::new(),
            }),
            "the request line is written out verbatim too"
        );
    }

    #[test]
    fn parse_head_reads_the_request_line_and_headers_over_crlf_or_lf() {
        let head = parse_head(b"GET / HTTP/1.1\r\nHost: h\r\nX: y\r\n\r\n").unwrap();
        assert_eq!(head.request_line, "GET / HTTP/1.1");
        assert!(head.headers.iter().any(|(k, v)| k == "Host" && v == "h"));
        // a header line without a colon is skipped (not fatal), and LF-only endings parse too.
        let head = parse_head(b"POST /x HTTP/1.1\nHost: h\nnonsense\n\n").unwrap();
        assert_eq!(head.request_line, "POST /x HTTP/1.1");
        assert!(head.headers.iter().any(|(k, _)| k == "Host"));
        assert!(!head.headers.iter().any(|(k, _)| k == "nonsense"));
    }

    #[test]
    fn request_line_parts_requires_all_three_tokens() {
        assert_eq!(
            request_line_parts("GET / HTTP/1.1"),
            Some(("GET".to_string(), "/".to_string()))
        );
        assert_eq!(
            request_line_parts("GET /"),
            None,
            "a missing HTTP-version token is refused"
        );
        assert_eq!(request_line_parts(""), None);
    }

    #[test]
    fn split_authority_handles_ports_and_a_bracketed_ipv6_literal() {
        assert_eq!(split_authority("h:443"), Some(("h".to_string(), 443)));
        assert_eq!(
            split_authority("[::1]:8080"),
            Some(("::1".to_string(), 8080))
        );
        assert_eq!(
            split_authority("hostonly"),
            None,
            "a missing port is refused (CONNECT requires one)"
        );
        assert_eq!(split_authority("h:notaport"), None);
    }

    #[test]
    fn strip_port_removes_a_numeric_port_but_keeps_a_non_numeric_suffix() {
        assert_eq!(strip_port("h:443"), "h");
        assert_eq!(strip_port("[::1]:8080"), "::1");
        assert_eq!(strip_port("[::1]"), "::1");
        assert_eq!(strip_port("h"), "h");
        // a colon suffix that is not all-digits is not a port, so the value is kept verbatim.
        assert_eq!(strip_port("h:notaport"), "h:notaport");
    }

    #[test]
    fn header_name_eq_is_case_and_underscore_insensitive() {
        // so a client cannot dodge the strip-and-replace with an alternate spelling of a header sbx
        // injects (`X_API_KEY` folded onto `X-Api-Key`).
        assert!(header_name_eq("X_API_KEY", "x-api-key"));
        assert!(header_name_eq("Authorization", "authorization"));
        assert!(!header_name_eq("x-api-key", "x-api-token"));
    }

    /// The proxy compares header names by two different rules, and the boundary between them is a
    /// decision rather than an oversight. This pins both sides of it.
    ///
    /// [`header_name_eq`] folds `_` onto `-` because the collision it defends against is **at the
    /// application**: a CGI-style server maps `X-Api-Key` and `X_Api_Key` onto the same
    /// `HTTP_X_API_KEY`, so the caller's spelling would contend with sbx's for one key. That is the
    /// rule the injection strip needs.
    ///
    /// [`Head::count`] and [`Head::header`] fold case only, because the collision they defend
    /// against is **at the framing**, and framing is read by the HTTP parser, which matches field
    /// names as exact tokens. `_` is a valid token character, so `Content_Length` is a different
    /// header, not a spelling of that one; nginx's `underscores_in_headers` drops or forwards such a
    /// header, it does not rename it. Widening these to fold as well would add a refusal for a
    /// collision no reachable parser performs, which is the one thing the guards in this proxy do
    /// not do.
    ///
    /// What would overturn it: a demonstrated hop between sbx and an origin that resolves
    /// `Content_Length` or `Transfer_Encoding` as its framing. This test is where to start.
    #[test]
    fn the_framing_lookups_fold_case_only_while_the_injection_strip_also_folds_underscores() {
        let head = parse_head(
            b"POST / HTTP/1.1\r\nHost: h\r\nContent-Length: 5\r\nContent_Length: 999\r\n\
              X_API_KEY: caller\r\n\r\n",
        )
        .unwrap();

        assert_eq!(
            head.count("content-length"),
            1,
            "the underscored spelling is a different header to the framing lookups, so the \
             duplicate check sees one Content-Length and reads its length from that one"
        );
        assert_eq!(head.header("content-length"), Some("5"));
        assert_eq!(
            head.count("host"),
            1,
            "the same holds for the header the anti-fronting check reads"
        );

        // ...and the injection strip, over the very same head, does fold: a credential sbx injects
        // as `x-api-key` takes the caller's `X_API_KEY` copy with it.
        assert!(
            head.headers
                .iter()
                .any(|(k, _)| header_name_eq(k, "x-api-key")),
            "the caller's alternate spelling is what the strip has to recognize"
        );
    }

    #[test]
    fn head_expects_continue_detects_the_case_insensitive_expectation() {
        let with = parse_head(b"POST / HTTP/1.1\r\nExpect: 100-Continue\r\n\r\n").unwrap();
        assert!(head_expects_continue(&with));
        let without = parse_head(b"POST / HTTP/1.1\r\nHost: h\r\n\r\n").unwrap();
        assert!(!head_expects_continue(&without));
    }

    #[test]
    fn strip_eol_drops_a_crlf_a_lone_lf_or_nothing() {
        assert_eq!(strip_eol(b"line\r\n"), b"line");
        assert_eq!(strip_eol(b"line\n"), b"line");
        assert_eq!(strip_eol(b"line"), b"line");
    }

    #[test]
    fn read_chunk_size_line_parses_hex_and_extensions_but_fails_closed_on_junk() {
        let mut r: &[u8] = b"1a\r\n";
        assert_eq!(read_chunk_size_line(&mut r).unwrap(), 0x1a);
        // a `;extension` after the size is ignored (only the hex count is read).
        let mut r: &[u8] = b"5;ext=1\r\n";
        assert_eq!(read_chunk_size_line(&mut r).unwrap(), 5);
        // a non-hex size is refused rather than mis-parsed.
        let mut r: &[u8] = b"zz\r\n";
        assert!(read_chunk_size_line(&mut r).is_err());
        // an EOF mid-line (no terminator) is a malformed-body error, not a silent short read.
        let mut r: &[u8] = b"5";
        assert!(read_chunk_size_line(&mut r).is_err());
    }

    #[test]
    fn read_line_bounded_refuses_a_no_newline_flood_over_the_bound() {
        let flood = vec![b'a'; 16]; // no newline, longer than the tiny bound below
        let mut r: &[u8] = &flood;
        assert!(
            read_line_bounded(&mut r, 8).is_err(),
            "a no-newline flood over the bound is a hard error, not unbounded buffering"
        );
        let mut empty: &[u8] = b"";
        assert!(
            read_line_bounded(&mut empty, 8).unwrap().is_empty(),
            "EOF before any byte returns an empty line"
        );
    }

    #[test]
    fn read_chunked_body_reassembles_and_fails_closed_on_bad_framing() {
        // two chunks then the zero terminator (with a trailer) reassemble to the payload.
        let mut r: &[u8] = b"3\r\nabc\r\n2\r\nde\r\n0\r\nTrailer: x\r\n\r\n";
        assert_eq!(
            read_chunked_body(&mut r, crate::allowlist::DEFAULT_BODY_MAX).unwrap(),
            b"abcde"
        );
        // chunk data not followed by CRLF is a malformed body.
        let mut r: &[u8] = b"3\r\nabcXX";
        assert!(read_chunked_body(&mut r, crate::allowlist::DEFAULT_BODY_MAX).is_err());
        // a body over the cap fails closed rather than buffering unboundedly.
        let mut r: &[u8] = b"4\r\ndata\r\n0\r\n\r\n";
        assert!(
            read_chunked_body(&mut r, 2).is_err(),
            "a chunk past the cap is refused"
        );
    }

    #[test]
    fn copy_exact_errors_on_a_read_shorter_than_the_content_length() {
        let mut src: &[u8] = b"abc";
        let mut dst = Vec::new();
        copy_exact(&mut src, &mut dst, 3).unwrap();
        assert_eq!(dst, b"abc");
        let mut src: &[u8] = b"ab";
        let mut dst = Vec::new();
        assert!(
            copy_exact(&mut src, &mut dst, 5).is_err(),
            "fewer bytes than the declared length is a truncated-body error"
        );
    }
}
