//! The one thing a registry needs that sbx's other host-side fetches do not: a request with
//! headers on it.
//!
//! Everything else sbx fetches host-side rides nix's `fetchurl` (see
//! [`crate::sandbox::nixhub`]), which deliberately keeps an HTTP client out of the dependency
//! graph. A registry cannot be reached that way: the manifest request carries an
//! `Authorization: Bearer` and an `Accept` that selects which of five media types comes back, and
//! `fetchurl` sets neither.
//!
//! So this is a small HTTPS client built from what the proxy already owns: its validated upstream
//! configuration ([`crate::sandbox::proxy::ca::upstream_config`], anchored on the bundled root
//! certificates), its synchronous `rustls` stream, and its HTTP/1.1 response reader
//! ([`crate::sandbox::proxy::wire`]). No parser is written twice, and no async runtime is involved:
//! provisioning is a blocking host-side step like every other one.
//!
//! **Every hop is checked, not just the first.** A scheme gate that admits `https://` and then
//! follows a redirect wherever it points is not a gate: it is a check on the string the user wrote.
//! [`get`] re-checks the scheme of each redirect target, and refuses a downgrade rather than
//! following it, because a blob URL is chosen by the registry and not by the config.
//!
//! **A redirect drops the credential.** Registries answer a blob request with a redirect to object
//! storage, which is a different origin; sending the bearer token there would hand a third party a
//! credential scoped to the repository. Only the first request carries the caller's headers.

use super::super::proxy::ca;
use super::super::proxy::wire;
use std::io::{self, BufReader, Read, Write};
use std::net::TcpStream;
use std::time::Duration;

/// How many redirects a request follows before giving up. Registries use one for the blob
/// hand-off to object storage; a chain longer than this is a loop or a misconfiguration, and
/// following it forever is how a fetch becomes a hang.
const MAX_REDIRECTS: usize = 5;

/// The cap on a response read into memory. Manifests and token documents are kilobytes; anything
/// claiming to be larger is not the document we asked for, and buffering it would let a registry
/// answer decide how much memory sbx spends.
pub(super) const MAX_DOCUMENT: u64 = 4 * 1024 * 1024;

/// The cap on a **streamed** body when the caller has no size of its own to hold it to.
///
/// The same argument as [`MAX_DOCUMENT`] one layer down: that one keeps a registry answer from
/// deciding how much *memory* sbx spends, this one keeps it from deciding how much *disk*. A blob
/// is written before its digest can be checked, because the digest is computed from the bytes as
/// they land, so a mismatch is found only once the whole body has arrived. The digest therefore
/// bounds what is *kept*, never what is *written*, and something else has to bound the writing.
///
/// Generous on purpose, like the block-group ceiling in [`crate::storage`]: no real layer
/// approaches it, and what it is for is refusing an implausible length rather than serving one.
pub(super) const MAX_STREAMED_BODY: u64 = 8 * 1024 * 1024 * 1024;

/// How long to wait for the connection and for each read. A provisioning step that hangs is worse
/// than one that fails: the failure names the host, and the caller can try again.
const TIMEOUT: Duration = Duration::from_secs(60);

/// A response worth acting on: its status, the headers a caller reads, and the body when one was
/// buffered.
pub(super) struct Response {
    pub(super) status: u16,
    pub(super) headers: Vec<(String, String)>,
    pub(super) body: Vec<u8>,
}

impl Response {
    /// The first value of `name`, compared case-insensitively as HTTP requires.
    pub(super) fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| wire::header_name_eq(k, name))
            .map(|(_, v)| v.as_str())
    }
}

/// A parsed `https://` URL: what a connection and a request line need.
struct Url {
    host: String,
    port: u16,
    /// Path and query together, as they appear on the request line.
    target: String,
}

/// Parse an absolute `https://` URL. Anything else, `http://` included, is refused here: this
/// client exists to fetch what a registry names, and a registry that names a plaintext hop is
/// answering a question nobody asked.
fn parse_url(url: &str) -> io::Result<Url> {
    let rest = url.strip_prefix("https://").ok_or_else(|| {
        io::Error::other(format!(
            "refusing a non-https URL: {url} (a registry hop that is not TLS is not followed)"
        ))
    })?;
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    if authority.is_empty() {
        return Err(io::Error::other(format!("no host in URL: {url}")));
    }
    let (host, port) = match authority.rsplit_once(':') {
        Some((h, p)) => (
            h,
            p.parse::<u16>()
                .map_err(|_| io::Error::other(format!("bad port in URL: {url}")))?,
        ),
        None => (authority, 443),
    };
    Ok(Url {
        host: host.to_string(),
        port,
        target: path.to_string(),
    })
}

/// Open a validated TLS connection to `url`'s host, using the proxy's own upstream trust anchors so
/// this fetch is held to exactly the transport the cage's own traffic is.
fn connect(url: &Url) -> io::Result<rustls::StreamOwned<rustls::ClientConnection, TcpStream>> {
    let addr = (url.host.as_str(), url.port);
    let sock = TcpStream::connect(addr)
        .map_err(|e| io::Error::other(format!("connecting to {}:{}: {e}", url.host, url.port)))?;
    sock.set_read_timeout(Some(TIMEOUT))?;
    sock.set_write_timeout(Some(TIMEOUT))?;
    let name = ca::upstream_server_name(&url.host)?;
    let conn = rustls::ClientConnection::new(ca::upstream_config(), name)
        .map_err(|e| io::Error::other(format!("TLS to {}: {e}", url.host)))?;
    Ok(rustls::StreamOwned::new(conn, sock))
}

/// A response head and the reader positioned at the body: the status, the headers, whatever of the
/// body the head-reader already consumed, and the stream the rest comes from.
type Head<S> = (u16, Vec<(String, String)>, Vec<u8>, BufReader<S>);

/// Write a `GET` request, then read the response head and hand back the reader positioned at the
/// body. Split from [`get`] so the streaming caller ([`get_to_writer`]) reads the body itself
/// rather than through a buffer sized for a document.
fn send<S: Read + Write>(stream: S, url: &Url, headers: &[(&str, &str)]) -> io::Result<Head<S>> {
    let mut request = format!(
        "GET {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: sbx\r\nAccept-Encoding: identity\r\n\
         Connection: close\r\n",
        url.target, url.host
    );
    for (name, value) in headers {
        request.push_str(name);
        request.push_str(": ");
        request.push_str(value);
        request.push_str("\r\n");
    }
    request.push_str("\r\n");

    let mut reader = BufReader::new(stream);
    reader.get_mut().write_all(request.as_bytes())?;
    reader.get_mut().flush()?;

    let (head, complete) = wire::read_response_head(&mut reader, 64 * 1024);
    if !complete {
        return Err(io::Error::other(format!(
            "no complete response head from {}",
            url.host
        )));
    }
    let text = String::from_utf8_lossy(&head).into_owned();
    let mut lines = text.split("\r\n");
    let status_line = lines.next().unwrap_or_default();
    let status = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse::<u16>().ok())
        .ok_or_else(|| io::Error::other(format!("unreadable status line from {}", url.host)))?;
    let headers = lines
        .filter(|l| !l.is_empty())
        .filter_map(|l| l.split_once(':'))
        .map(|(k, v)| (k.trim().to_string(), v.trim().to_string()))
        .collect();
    Ok((status, headers, head, reader))
}

/// Fetch `url`, following redirects, and buffer the body up to [`MAX_DOCUMENT`].
///
/// `headers` are sent on the first request only; see the module note on why a redirect drops them.
pub(super) fn get(url: &str, headers: &[(&str, &str)]) -> io::Result<Response> {
    let mut current = url.to_string();
    let mut carry = headers;
    for _ in 0..=MAX_REDIRECTS {
        let parsed = parse_url(&current)?;
        let stream = connect(&parsed)?;
        let (status, headers, head, mut reader) = send(stream, &parsed, carry)?;
        if let Some(location) = redirect_target(status, &headers, &current)? {
            current = location;
            // Past the first hop the request is to somewhere the registry chose, so the caller's
            // credential does not travel with it.
            carry = &[];
            continue;
        }
        let body = read_body(&mut reader, &head, MAX_DOCUMENT)?;
        return Ok(Response {
            status,
            headers,
            body,
        });
    }
    Err(io::Error::other(format!(
        "more than {MAX_REDIRECTS} redirects starting at {url}"
    )))
}

/// Fetch `url` and stream the body into `sink`, returning how many bytes were written.
///
/// For blobs, which are megabytes and must not be buffered. The caller verifies the digest as the
/// bytes pass, so nothing here decides whether the content was the right *content* — but the digest
/// is only known once the whole body has been written, so `cap` is what decides how much may be
/// written before that answer exists. Pass the length the caller expects when it knows one, and
/// [`MAX_STREAMED_BODY`] when it does not.
pub(super) fn get_to_writer<W: Write>(
    url: &str,
    headers: &[(&str, &str)],
    sink: &mut W,
    cap: u64,
) -> io::Result<u64> {
    let mut current = url.to_string();
    let mut carry = headers;
    for _ in 0..=MAX_REDIRECTS {
        let parsed = parse_url(&current)?;
        let stream = connect(&parsed)?;
        let (status, headers, head, mut reader) = send(stream, &parsed, carry)?;
        if let Some(location) = redirect_target(status, &headers, &current)? {
            current = location;
            carry = &[];
            continue;
        }
        if status != 200 {
            return Err(io::Error::other(format!("{current} answered {status}")));
        }
        return stream_body(&mut reader, &head, sink, cap);
    }
    Err(io::Error::other(format!(
        "more than {MAX_REDIRECTS} redirects starting at {url}"
    )))
}

/// Where a redirect points, absolute and checked, or `None` when the status is not one.
///
/// A relative `Location` is resolved against the current URL's origin, which is what a registry
/// sends for an in-registry hand-off. The result goes back through [`parse_url`] at the next
/// iteration, so a redirect into `http://` is refused there rather than followed.
fn redirect_target(
    status: u16,
    headers: &[(String, String)],
    current: &str,
) -> io::Result<Option<String>> {
    if !matches!(status, 301 | 302 | 303 | 307 | 308) {
        return Ok(None);
    }
    let location = headers
        .iter()
        .find(|(k, _)| wire::header_name_eq(k, "location"))
        .map(|(_, v)| v.as_str())
        .ok_or_else(|| io::Error::other(format!("{current} answered {status} with no Location")))?;
    if location.starts_with("https://") {
        return Ok(Some(location.to_string()));
    }
    if location.contains("://") {
        return Err(io::Error::other(format!(
            "refusing a redirect from {current} to {location}: only https is followed"
        )));
    }
    let origin = parse_url(current)?;
    let base = if origin.port == 443 {
        format!("https://{}", origin.host)
    } else {
        format!("https://{}:{}", origin.host, origin.port)
    };
    if location.starts_with('/') {
        Ok(Some(format!("{base}{location}")))
    } else {
        Err(io::Error::other(format!(
            "refusing a relative redirect from {current} to {location}"
        )))
    }
}

/// Read a framed body into memory, refusing one that claims more than `cap`.
fn read_body<R: Read + std::io::BufRead>(
    reader: &mut R,
    head: &[u8],
    cap: u64,
) -> io::Result<Vec<u8>> {
    match wire::response_framing(head, "GET") {
        wire::BodyFraming::Empty => Ok(Vec::new()),
        wire::BodyFraming::Length(n) if n > cap => Err(io::Error::other(format!(
            "response body of {n} bytes exceeds the {cap}-byte cap"
        ))),
        wire::BodyFraming::Length(n) => {
            let mut buf = vec![0u8; usize::try_from(n).map_err(io::Error::other)?];
            reader.read_exact(&mut buf)?;
            Ok(buf)
        }
        wire::BodyFraming::Chunked => wire::read_chunked_body(reader, cap),
        wire::BodyFraming::ToEof => {
            let mut buf = Vec::new();
            reader.take(cap + 1).read_to_end(&mut buf)?;
            if buf.len() as u64 > cap {
                return Err(io::Error::other(format!(
                    "response body exceeds the {cap}-byte cap"
                )));
            }
            Ok(buf)
        }
    }
}

/// Copy a framed body to `sink` without buffering it, returning the byte count.
///
/// `cap` bounds every framing, including the one that announces its own length: a `Content-Length`
/// is the registry's claim, not a fact, so a body that overruns what the caller will accept is
/// refused here rather than after it has been written. The server chooses the framing, so leaving
/// either of the other two unbounded would leave the bound to the server as well.
fn stream_body<R: Read + std::io::BufRead, W: Write>(
    reader: &mut R,
    head: &[u8],
    sink: &mut W,
    cap: u64,
) -> io::Result<u64> {
    let too_large = || {
        io::Error::other(format!(
            "the response body is larger than the {cap} bytes this fetch accepts"
        ))
    };
    match wire::response_framing(head, "GET") {
        wire::BodyFraming::Empty => Ok(0),
        wire::BodyFraming::Length(n) => {
            if n > cap {
                return Err(too_large());
            }
            wire::copy_exact(reader, sink, n)?;
            Ok(n)
        }
        wire::BodyFraming::Chunked | wire::BodyFraming::ToEof => {
            // Neither announces a length, so the bound is the caller's. Read one byte past the cap
            // to tell "exactly at the cap" from "over it": a body that reaches `cap + 1` is refused
            // whole rather than silently truncated into something whose digest would then be
            // reported as a mismatch.
            let n = io::copy(&mut reader.take(cap.saturating_add(1)), sink)?;
            if n > cap {
                return Err(too_large());
            }
            Ok(n)
        }
    }
}

#[cfg(test)]
mod tests;
