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
    if let Some(rest) = authority.strip_prefix('[') {
        if let Some((addr, _)) = rest.split_once(']') {
            return addr.to_string();
        }
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

/// Copy exactly `n` bytes from `r` to `w`; a short read is an error (a truncated body).
pub(super) fn copy_exact<R: Read, W: Write>(r: &mut R, w: &mut W, mut n: u64) -> io::Result<()> {
    let mut buf = [0u8; 8192];
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

/// The most request body the proxy will buffer to de-chunk a `Transfer-Encoding: chunked` request
/// before re-framing it with a synthesized Content-Length. Agent prompt bodies are KB–MB, so 64 MiB
/// is generous; a larger chunked upload fails closed (the proxy does not stream chunked through).
pub(super) const CHUNKED_REQUEST_CAP: u64 = 64 * 1024 * 1024;

/// The most one chunk-size line (or one trailer line) may be before it is refused. A chunk-size
/// line is a hex count plus optional `;extensions`; a trailer is one header — both are short, so 8
/// KiB is generous. Without this bound a bare `read_until` would buffer an arbitrarily long
/// no-newline flood *before* any size check, letting an in-cage client force unbounded host-side
/// allocation (this proxy runs outside the cage's cgroup) — the same footgun `read_head_buffered`
/// caps.
pub(super) const CHUNK_LINE_MAX: u64 = 8 * 1024;

/// De-chunk a `Transfer-Encoding: chunked` request body into one buffer, fail-closed on malformed
/// framing (a non-hex chunk size, a short data read, a missing trailing CRLF) or a body over
/// [`CHUNKED_REQUEST_CAP`]. The caller re-frames the result with a synthesized `Content-Length`
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
    if !line.ends_with(b"\n") {
        return Err(invalid("chunk size line has no line terminator"));
    }
    let s = strip_eol(&line);
    let size_field = match s.iter().position(|&b| b == b';') {
        Some(i) => &s[..i],
        None => s,
    };
    let size_str =
        std::str::from_utf8(size_field).map_err(|_| invalid("chunk size is not ASCII"))?;
    u64::from_str_radix(size_str.trim(), 16).map_err(|_| invalid("chunk size is not hexadecimal"))
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
