//! The HTTP/2 (gRPC) man-in-the-middle path, for a CONNECT to a designated `[network] http2` host.
//!
//! It is a sibling of the synchronous HTTP/1.1 tail of [`handle_client`], not a rewrite of it: the
//! sync path is untouched. Because the `h2` crate is async (tokio-based), the whole branch runs on a
//! **per-connection current-thread tokio runtime** built and dropped inside [`handle`], so tokio
//! never leaks into sbx's std-thread world.
//!
//! Security parity with the HTTP/1.1 path is the invariant: every stream is checked against the same
//! [`effective_policy`]/[`EgressPolicy::explain`] chokepoint (host/`:path`/method), the `:authority`
//! is re-verified against the CONNECT host **per stream** (h2 lets a client vary it), the SSRF guard
//! resolves and validates the address exactly as [`connect_upstream`] does (connect the checked IP,
//! no re-resolve, validate the upstream cert), and gRPC is HTTP/2 end-to-end (no downgrade). The
//! secret machinery is replicated too: the outbound tripwire ([`carries_secret`]) refuses a request
//! whose head carries a configured secret verbatim, matching host-scoped credentials are injected
//! (strip-and-replace) onto the upstream request, and a reflected secret is masked out of the
//! response DATA/headers/trailers for an injection-target host ([`relay_body_redacting`]).

use super::capture::CapBuf;
use super::{
    carries_secret, effective_policy, ip_permitted, matching_injections, redact_in_place,
    upstream_server_name, ProxyCtx, SecretNeedle, StatKind,
};
use crate::allowlist::{self, Decision, Rule};
use crate::sandbox::control::{HttpVer, LogVerdict, Proto, RpcKind};
use bytes::Bytes;
use futures_util::stream::{FuturesUnordered, StreamExt};
use http::{Method, Request, Response, StatusCode};
use std::io;
use std::net::IpAddr;
use std::sync::Arc;
use tokio::io::AsyncWriteExt;

/// The most concurrent h2 streams the proxy carries on one tunnel — h2 multiplexes, so the
/// per-connection thread cap no longer bounds request count; this does. Advertised to the client
/// (SETTINGS) and enforced as a backstop when accepting.
const MAX_STREAMS: u32 = 256;
/// The largest decoded header list the proxy accepts on an h2 connection — bounds an HPACK
/// decompression bomb. 64 KiB is ample for gRPC.
const MAX_HEADER_LIST: u32 = 64 * 1024;

/// Entry from the sync [`super::handle_client`]: run the whole HTTP/2 MITM for one CONNECT on a
/// per-connection current-thread runtime, confined here.
pub(super) fn handle(
    client: std::os::unix::net::UnixStream,
    connect_host: String,
    port: u16,
    ctx: &ProxyCtx,
) -> io::Result<()> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(io::Error::other)?;
    rt.block_on(serve(client, &connect_host, port, ctx))
}

/// Accept the tunnel, terminate TLS as h2, then drive stream acceptance and every in-flight
/// stream concurrently. The per-stream futures borrow `ctx`, so they are driven in a
/// [`FuturesUnordered`] here (not spawned) — no `'static` bound, no `Arc<ProxyCtx>` threading.
async fn serve(
    client: std::os::unix::net::UnixStream,
    connect_host: &str,
    port: u16,
    ctx: &ProxyCtx,
) -> io::Result<()> {
    client.set_nonblocking(true)?;
    let mut client = tokio::net::UnixStream::from_std(client)?;
    client
        .write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
        .await?;

    let acceptor = tokio_rustls::TlsAcceptor::from(ctx.server_config_h2.clone());
    // Bound the handshake so a client that connects but stalls mid-handshake cannot pin this
    // connection's thread + runtime (the per-socket read/write timeouts the sync path relies on
    // do not apply once the stream is in nonblocking/tokio mode). Established streams are then
    // driven with no overall deadline — a gRPC stream may legitimately be long-lived.
    let tls = match tokio::time::timeout(ctx.timeout, acceptor.accept(client)).await {
        Ok(Ok(t)) => t,
        _ => {
            // No common ALPN (an HTTP/1.1-only client reached a designated h2 host) or a
            // handshake failure — nothing to inspect. Pre-stream, so no method/path to log.
            ctx.push_log(
                Proto::Https,
                connect_host,
                port,
                None,
                None,
                LogVerdict::Blocked,
                "http2-handshake",
            );
            return Ok(());
        }
    };
    // rustls fails the handshake only when the client OFFERS an ALPN that does not match; a
    // client that offers no ALPN connects with none negotiated. This branch speaks h2 only, so
    // refuse anything that did not land on h2 (fail-closed — never fall through to HTTP/1.1).
    if tls.get_ref().1.alpn_protocol() != Some(b"h2".as_slice()) {
        ctx.push_log(
            Proto::Https,
            connect_host,
            port,
            None,
            None,
            LogVerdict::Blocked,
            "http2-required",
        );
        return Ok(());
    }
    // Domain-fronting: the SNI (which minted the leaf) must match the CONNECT authority. The
    // per-stream `:authority` is re-checked against the same host below.
    let sni_ok = tls
        .get_ref()
        .1
        .server_name()
        .map(|s| allowlist::canonical_host(s) == *connect_host)
        .unwrap_or(false);
    if !sni_ok {
        ctx.outcome(
            Proto::Https,
            connect_host,
            port,
            None,
            None,
            StatKind::Blocked,
            "host-mismatch",
        );
        return Ok(());
    }

    let handshake = h2::server::Builder::new()
        .max_concurrent_streams(MAX_STREAMS)
        .max_header_list_size(MAX_HEADER_LIST)
        .handshake::<_, Bytes>(tls);
    let mut conn = match tokio::time::timeout(ctx.timeout, handshake).await {
        Ok(Ok(c)) => c,
        _ => return Ok(()),
    };

    let mut inflight = FuturesUnordered::new();
    loop {
        tokio::select! {
            accepted = conn.accept() => match accepted {
                Some(Ok((req, respond))) => {
                    if inflight.len() >= MAX_STREAMS as usize {
                        // Backstop the advertised SETTINGS limit: refuse the excess stream
                        // rather than letting an in-cage client open unbounded work per tunnel.
                        let _ = refuse(respond, StatusCode::TOO_MANY_REQUESTS, "http2-stream-cap");
                        continue;
                    }
                    inflight.push(stream(req, respond, connect_host, port, ctx));
                }
                // Accept error, or the client sent GOAWAY / closed the connection: stop taking
                // new streams, then drain the ones already in flight below.
                Some(Err(_)) | None => break,
            },
            Some(()) = inflight.next(), if !inflight.is_empty() => {}
        }
    }
    // Drain the in-flight streams, but bounded: once `accept()` has returned (the connection is
    // winding down) the loop above no longer polls `conn`, so a stream still flushing a response
    // larger than the flow-control window would never receive the peer's WINDOW_UPDATE and would
    // hang. Cap the drain by the per-socket timeout, then drop `inflight` (resetting any straggler
    // stream), so a wound-down connection can never pin its thread. (A stream that completes in the
    // main loop leaves nothing to drain — the common case.)
    let _ = tokio::time::timeout(ctx.timeout, async {
        while inflight.next().await.is_some() {}
    })
    .await;
    Ok(())
}

/// Handle one h2 stream: decode it, enforce the verdict + SSRF exactly like the HTTP/1.1 path,
/// then relay it to the validated upstream. Every early return has already answered the client
/// with a refusal carrying an `x-sbx-egress-reason`.
async fn stream(
    req: Request<h2::RecvStream>,
    respond: h2::server::SendResponse<Bytes>,
    connect_host: &str,
    port: u16,
    ctx: &ProxyCtx,
) {
    let method = req.method().clone();
    let path = req
        .uri()
        .path_and_query()
        .map(|p| p.as_str().to_string())
        .unwrap_or_else(|| "/".into());
    let authority = req
        .uri()
        .authority()
        .map(|a| allowlist::canonical_host(a.host()));

    // Extended CONNECT (h2 tunneling / WebSocket-over-h2) is a distinct, unredactable capability
    // — refuse it fail-closed in v1 (gRPC is POST).
    if method == Method::CONNECT {
        ctx.push_log(
            Proto::Https,
            connect_host,
            port,
            Some(method.as_str()),
            Some(&path),
            LogVerdict::Blocked,
            "method-not-allowed",
        );
        let _ = refuse(
            respond,
            StatusCode::METHOD_NOT_ALLOWED,
            "method-not-allowed",
        );
        return;
    }
    // Per-stream domain-fronting re-check: a client may send a different `:authority` per stream
    // over one h2 tunnel, so bind every stream to the CONNECT host (== the SNI checked above).
    if authority.as_deref() != Some(connect_host) {
        ctx.outcome(
            Proto::Https,
            connect_host,
            port,
            Some(method.as_str()),
            Some(&path),
            StatKind::Blocked,
            "host-mismatch",
        );
        let _ = refuse(respond, StatusCode::MISDIRECTED_REQUEST, "host-mismatch");
        return;
    }
    // Outbound secret tripwire (GLOBAL): if the client's decoded request head carries any
    // configured secret value verbatim, refuse it — a secret must not leave the cage, whatever
    // the verdict. Scanned on the client's head *before* sbx's own injection is added, so it can
    // never self-trip on an injected credential (parity with the HTTP/1.1 `carries_secret`).
    if !ctx.redactions.is_empty() && head_carries_secret(&req, &ctx.redactions) {
        ctx.outcome(
            Proto::Https,
            connect_host,
            port,
            Some(method.as_str()),
            Some(&path),
            StatKind::Blocked,
            "outbound-secret",
        );
        let _ = refuse(respond, StatusCode::FORBIDDEN, "outbound-secret");
        return;
    }

    // The verdict — the same chokepoint as the HTTP/1.1 path (config policy ∪ any `--session`
    // overlay), deny-wins, method/path aware.
    let policy = effective_policy(ctx);
    let deciding: Option<Rule> = match policy.explain(connect_host, port, &path, method.as_str()) {
        Decision::AllowedBy(rule) => Some(rule.clone()),
        Decision::AllowedDefault => None,
        Decision::DeniedBy(_) => {
            ctx.outcome(
                Proto::Https,
                connect_host,
                port,
                Some(method.as_str()),
                Some(&path),
                StatKind::Deny,
                "denied-by-rule",
            );
            let _ = refuse(respond, StatusCode::FORBIDDEN, "denied-by-rule");
            return;
        }
        Decision::DeniedDefault => {
            let reason = if policy.method_denied(connect_host, port, &path, method.as_str()) {
                "denied-method"
            } else {
                "denied-default"
            };
            ctx.outcome(
                Proto::Https,
                connect_host,
                port,
                Some(method.as_str()),
                Some(&path),
                StatKind::Deny,
                reason,
            );
            let _ = refuse(respond, StatusCode::FORBIDDEN, reason);
            return;
        }
        Decision::Ask => {
            // `ask`-mode parking (a blocking live per-request decision) is not supported on the
            // async h2 path yet — an unmatched stream to a designated http2 host under `ask` mode
            // is denied, not parked (fail-closed). An explicit `allow` rule for the gRPC endpoint
            // is the intended posture; parking on h2 is a later increment.
            ctx.outcome(
                Proto::Https,
                connect_host,
                port,
                Some(method.as_str()),
                Some(&path),
                StatKind::Deny,
                "http2-ask-unsupported",
            );
            let _ = refuse(respond, StatusCode::FORBIDDEN, "http2-ask-unsupported");
            return;
        }
    };
    // The allow is recorded only after the upstream connects (in `relay`), matching the
    // HTTP/1.1 path: a request that passes the verdict but then fails SSRF/DNS/upstream is
    // logged (an `Error`/`Blocked` line) but never counted as an allow in `sbx net stats`.

    // Resolve host-side, then the SSRF guard against the deciding rule (a private/metadata
    // address is refused unless the rule names the exact host) — then connect the checked IP with
    // no re-resolution, exactly like the HTTP/1.1 path.
    let ips = match (ctx.resolve)(connect_host) {
        Ok(ips) => ips,
        Err(_) => {
            ctx.push_log(
                Proto::Https,
                connect_host,
                port,
                Some(method.as_str()),
                Some(&path),
                LogVerdict::Error,
                "dns-failure",
            );
            let _ = refuse(respond, StatusCode::BAD_GATEWAY, "dns-failure");
            return;
        }
    };
    let ip = match ips
        .into_iter()
        .find(|ip| ip_permitted(*ip, connect_host, deciding.as_ref()))
    {
        Some(ip) => ip,
        None => {
            ctx.push_log(
                Proto::Https,
                connect_host,
                port,
                Some(method.as_str()),
                Some(&path),
                LogVerdict::Blocked,
                "ssrf-blocked",
            );
            let _ = refuse(respond, StatusCode::FORBIDDEN, "ssrf-blocked");
            return;
        }
    };

    relay(
        req,
        respond,
        ip,
        port,
        connect_host,
        method.as_str(),
        &path,
        ctx,
    )
    .await;
}

/// Connect the checked upstream over HTTP/2 (validate cert, require ALPN `h2`) and relay the RPC —
/// request headers + body, then the response headers + body + trailers (`grpc-status`). A
/// pre-forward failure answers the client with a `502`; a mid-stream error just ends the stream.
#[allow(clippy::too_many_arguments)]
async fn relay(
    req: Request<h2::RecvStream>,
    mut respond: h2::server::SendResponse<Bytes>,
    ip: IpAddr,
    port: u16,
    host: &str,
    method: &str,
    path: &str,
    ctx: &ProxyCtx,
) {
    let tcp =
        match tokio::time::timeout(ctx.timeout, tokio::net::TcpStream::connect((ip, port))).await {
            Ok(Ok(t)) => t,
            _ => {
                let _ = refuse(respond, StatusCode::BAD_GATEWAY, "upstream-unreachable");
                return;
            }
        };
    let name = match upstream_server_name(host) {
        Ok(n) => n,
        Err(_) => {
            let _ = refuse(respond, StatusCode::BAD_GATEWAY, "upstream-cert-rejected");
            return;
        }
    };
    let connector = tokio_rustls::TlsConnector::from(ctx.upstream_h2.clone());
    let upstream_tls = match tokio::time::timeout(ctx.timeout, connector.connect(name, tcp)).await {
        Ok(Ok(t)) => t,
        // A forged / self-signed / otherwise-untrusted upstream fails validation here — never
        // downgraded, exactly like the HTTP/1.1 `connect_upstream`.
        _ => {
            let _ = refuse(respond, StatusCode::BAD_GATEWAY, "upstream-cert-rejected");
            return;
        }
    };
    if upstream_tls.get_ref().1.alpn_protocol() != Some(b"h2".as_slice()) {
        // gRPC is HTTP/2 end-to-end; the proxy does not translate to HTTP/1.1. Fail closed.
        let _ = refuse(
            respond,
            StatusCode::BAD_GATEWAY,
            "upstream-http2-unsupported",
        );
        return;
    }
    let (send_req, connection) = match h2::client::handshake(upstream_tls).await {
        Ok(x) => x,
        Err(_) => {
            let _ = refuse(
                respond,
                StatusCode::BAD_GATEWAY,
                "upstream-http2-unsupported",
            );
            return;
        }
    };
    // The upstream connection driver owns only the TLS stream + h2 state (it does not borrow
    // `ctx`), so it is `'static` and can be spawned on this connection's runtime; it is cancelled
    // when the runtime is dropped.
    tokio::spawn(async move {
        let _ = connection.await;
    });

    // The upstream is connected and validated (this is the HTTP/1.1 path's `connect_upstream`
    // success point), so record the allow now — a verdict-passing request that failed to reach
    // here was logged but not counted as an allow. `seq` then carries the response status.
    let seq = ctx.outcome_l7(
        Proto::Https,
        HttpVer::H2,
        // A designated `[network] http2` host is MITM'd as HTTP/2 for gRPC; tag the framing from
        // the request's `Content-Type` (`application/grpc` and friends).
        RpcKind::from_content_type(
            req.headers()
                .get("content-type")
                .and_then(|v| v.to_str().ok())
                .unwrap_or_default(),
        ),
        host,
        port,
        Some(method),
        Some(path),
        StatKind::Allow,
        "allowed",
    );

    // Any host-scoped credential to inject — keyed on the already-verified host and the decrypted
    // path, so it reaches exactly its scoped destination. Runs after the verdict (a denied request
    // never got here). Each is **strip-and-replace**: the client's own copy of that header is
    // dropped and sbx's value is the only one forwarded.
    let injected = matching_injections(ctx, host, port, path);

    // Open the traffic capture for this stream, when the launch captures. The head recorded is the
    // client's own, rendered from the decoded request *before* the rebuild below adds any injected
    // credential, so a secret cannot reach the capture even in principle. The guard files on drop,
    // so every early return below files what it saw exactly once.
    let capture = ctx.begin_capture(seq);
    if let Some(c) = &capture {
        c.set_request(&capture_request_head(&req), &injected);
    }

    // Rebuild the request for the upstream: reuse the decoded method/URI (h2 re-derives the
    // pseudo-headers), copying regular headers minus the connection-specific ones h2 forbids and
    // minus any header sbx is injecting (stripped so its value is the only one upstream).
    let (parts, client_body) = req.into_parts();
    let mut builder = Request::builder()
        .method(parts.method)
        .uri(parts.uri)
        .version(http::Version::HTTP_2);
    for (name, value) in parts.headers.iter() {
        let n = name.as_str();
        if forbidden_request_header(n) || injected.iter().any(|(h, _)| h.eq_ignore_ascii_case(n)) {
            continue;
        }
        builder = builder.header(name, value);
    }
    for (h, v) in &injected {
        builder = builder.header(*h, *v);
    }
    let up_req = match builder.body(()) {
        Ok(r) => r,
        Err(_) => {
            let _ = refuse(respond, StatusCode::BAD_GATEWAY, "bad-request");
            return;
        }
    };
    let mut send_req = match send_req.ready().await {
        Ok(s) => s,
        Err(_) => {
            let _ = refuse(respond, StatusCode::BAD_GATEWAY, "upstream-unreachable");
            return;
        }
    };
    let (resp_fut, up_send_body) = match send_req.send_request(up_req, false) {
        Ok(x) => x,
        Err(_) => {
            let _ = refuse(respond, StatusCode::BAD_GATEWAY, "upstream-unreachable");
            return;
        }
    };
    // Pump the request body (client → upstream) concurrently; it owns only h2 stream state (plus an
    // `Arc` sink), so it is `'static` and spawnable.
    //
    // That concurrency is why the sink is told to expect a source end. The pump can still be running
    // when this exchange is filed — a server that answers and closes without draining the request, a
    // bidi-streaming RPC whose client half stays open — and a body captured mid-pump is a prefix.
    // Marking the source open until the pump reports it exhausted is what keeps that prefix from
    // being stored as if it were the whole body. (Waiting for the pump instead would let a
    // never-draining client hold the response status out of `sbx net logs` indefinitely.)
    let req_sink = capture.as_ref().filter(|c| c.keeps_body()).map(|c| {
        let sink = c.request_body_sink();
        sink.expect_source_end();
        sink
    });
    tokio::spawn(async move {
        let _ = relay_body(client_body, up_send_body, req_sink).await;
    });

    let resp = match resp_fut.await {
        Ok(r) => r,
        Err(_) => {
            let _ = refuse(respond, StatusCode::BAD_GATEWAY, "upstream-unreachable");
            return;
        }
    };
    let (mut rparts, up_body) = resp.into_parts();
    ctx.set_status(seq, rparts.status.as_u16());

    // Capture the response head, rendered from the framed status + headers. Teed ahead of the
    // reflection masking below, like the HTTP/1.1 path: the capture masks its own buffers at filing
    // time, so what is stored is masked either way, and what the cage receives is decided by
    // `masks_reflection` alone.
    if let Some(c) = &capture {
        c.push_response(&capture_response_head(rparts.status, &rparts.headers));
    }

    // Response-side leak backstop: a configured secret can only re-enter the cage by being
    // *reflected* by a host an injection targets (an echo/debug endpoint, or one that stores and
    // later returns the credential). So mask the reflected value out — but only for a response
    // from such a host (parity with the HTTP/1.1 `masks_reflection`); every other response
    // streams untouched (no scan cost, and the mutate-on-match is confined to the one host the
    // reflection threat lives on).
    let masks_reflection = !ctx.redactions.is_empty()
        && ctx
            .injections
            .iter()
            .any(|inj| super::names_exact_host(host, Some(&inj.rule)));
    if masks_reflection {
        redact_header_map(&mut rparts.headers, &ctx.redactions);
    }

    let mut out = Response::builder().status(rparts.status);
    for (name, value) in rparts.headers.iter() {
        if forbidden_response_header(name.as_str()) {
            continue;
        }
        out = out.header(name, value);
    }
    let head = match out.body(()) {
        Ok(h) => h,
        Err(_) => return,
    };
    // From here the response head is committed; a mid-stream failure just ends the stream (no
    // second response can be sent). Relay the response body + trailers (gRPC status), masking a
    // reflected secret out of the DATA and trailers when the host is an injection target.
    let client_send_body = match respond.send_response(head, false) {
        Ok(s) => s,
        Err(_) => return,
    };
    // The response body is relayed inline (awaited here), so its sink is finished by the time the
    // guard files and needs no source-end tracking. Under the headers-only level no sink is handed
    // over at all: an HTTP/2 head is its own frame, so unlike a byte stream there is nothing to read
    // past, and not one body byte is ever buffered.
    let res_sink = capture
        .as_ref()
        .filter(|c| c.keeps_body())
        .map(|c| c.response_sink());
    if masks_reflection {
        let _ = relay_body_redacting(up_body, client_send_body, &ctx.redactions, res_sink).await;
    } else {
        let _ = relay_body(up_body, client_send_body, res_sink).await;
    }
}

/// Render a client HTTP/2 request head as text for the traffic capture.
///
/// HTTP/2 carries a head as HPACK-compressed pseudo-headers, so there is no wire form to copy the
/// way the HTTP/1.1 path copies the client's own bytes — it is rendered here instead. The
/// pseudo-headers keep their real names (`:authority`, never a synthesized `Host:`), so a reader is
/// never shown a fiction of an HTTP/1.1 request that was not sent.
fn capture_request_head<B>(req: &Request<B>) -> Vec<u8> {
    let mut out = format!(
        "{} {} HTTP/2\r\n",
        req.method(),
        req.uri()
            .path_and_query()
            .map(|p| p.as_str())
            .unwrap_or("/")
    );
    if let Some(authority) = req.uri().authority() {
        out.push_str(":authority: ");
        out.push_str(authority.as_str());
        out.push_str("\r\n");
    }
    append_headers(&mut out, req.headers());
    out.into_bytes()
}

/// Render an HTTP/2 response head as text for the traffic capture, terminated by the blank line the
/// capture's response split looks for. HTTP/2 has no reason phrase, so the status line carries the
/// code alone rather than a plausible-looking phrase nothing sent.
fn capture_response_head(status: StatusCode, headers: &http::HeaderMap) -> Vec<u8> {
    let mut out = format!("HTTP/2 {}\r\n", status.as_u16());
    append_headers(&mut out, headers);
    out.into_bytes()
}

/// Append `name: value` lines plus the terminating blank line. A header value is bytes, not text, so
/// a non-UTF-8 one is rendered lossily rather than dropping the header from the capture.
fn append_headers(out: &mut String, headers: &http::HeaderMap) {
    for (name, value) in headers.iter() {
        out.push_str(name.as_str());
        out.push_str(": ");
        out.push_str(&String::from_utf8_lossy(value.as_bytes()));
        out.push_str("\r\n");
    }
    out.push_str("\r\n");
}

/// Relay one h2 body (DATA frames + trailers) from `src` to `dst`, honoring flow control. Used
/// for both the request (client → upstream) and the response (upstream → client). The trailers
/// carry the gRPC status, so they are forwarded when present, else the stream is ended with an
/// empty final DATA frame.
///
/// `cap` is the traffic capture's sink for this direction, when the launch captures bodies: each
/// frame is copied into it as it is relayed (bounded by the sink's own cap, so a large body costs a
/// fixed amount). The source is reported exhausted only when the DATA loop ends of its own accord —
/// never on the error or downstream-reset exits, where what was captured really is a prefix.
async fn relay_body(
    mut src: h2::RecvStream,
    mut dst: h2::SendStream<Bytes>,
    cap: Option<Arc<CapBuf>>,
) -> Result<(), h2::Error> {
    while let Some(chunk) = src.data().await {
        let chunk = chunk?;
        let len = chunk.len();
        if let Some(cap) = &cap {
            cap.push(&chunk);
        }
        if len > 0 {
            dst.reserve_capacity(len);
            loop {
                if dst.capacity() >= len {
                    break;
                }
                match std::future::poll_fn(|cx| dst.poll_capacity(cx)).await {
                    Some(Ok(_)) => continue,
                    Some(Err(e)) => return Err(e),
                    // The downstream reset/closed: stop relaying (dropping `dst` sends a reset).
                    None => return Ok(()),
                }
            }
            dst.send_data(chunk, false)?;
        }
        // Return the consumed window to the sender so it can keep sending.
        let _ = src.flow_control().release_capacity(len);
    }
    // The DATA stream ended on its own: everything this direction will ever carry has been captured.
    if let Some(cap) = &cap {
        cap.mark_source_ended();
    }
    match src.trailers().await? {
        Some(trailers) => dst.send_trailers(trailers)?,
        None => dst.send_data(Bytes::new(), true)?,
    }
    Ok(())
}

/// Relay a response body like [`relay_body`], but mask every configured secret value out of each
/// DATA frame (and the trailers) with an equal-length run of `*` — the streaming response-side
/// leak backstop, used only for a response from an injection-target host.
///
/// Each frame is redacted **independently and emitted whole** — deliberately NOT carrying bytes
/// across frames. Holding bytes back would deadlock an interactive stream (e.g. gRPC reflection or
/// any client-streaming RPC): the client must receive a complete response message before it sends
/// its next request, so a relay that withholds the frame's tail until the stream ends stalls
/// forever. The residual is a secret split across two DATA frames (a 16 KiB boundary), which is
/// then not masked — rare, and the same best-effort class as the gzip-compressed-body limit; the
/// real controls are the empty netns, the allowlist, the per-host `to` scoping, and the outbound
/// tripwire. Equal-length masking keeps every byte count intact.
async fn relay_body_redacting(
    mut src: h2::RecvStream,
    mut dst: h2::SendStream<Bytes>,
    needles: &[SecretNeedle],
    cap: Option<Arc<CapBuf>>,
) -> Result<(), h2::Error> {
    while let Some(chunk) = src.data().await {
        let chunk = chunk?;
        let len = chunk.len();
        // Captured before the masking, like the HTTP/1.1 path: the capture ring masks whatever it
        // stores at filing time, over whole buffers rather than per frame.
        if let Some(cap) = &cap {
            cap.push(&chunk);
        }
        let mut buf = chunk.to_vec();
        redact_in_place(&mut buf, needles);
        let sent = send_masked(&mut dst, buf).await?;
        // Return the consumed receive-window for the original chunk so the sender keeps sending.
        let _ = src.flow_control().release_capacity(len);
        if !sent {
            return Ok(());
        }
    }
    if let Some(cap) = &cap {
        cap.mark_source_ended();
    }
    match src.trailers().await? {
        Some(mut trailers) => {
            redact_header_map(&mut trailers, needles);
            dst.send_trailers(trailers)?;
        }
        None => dst.send_data(Bytes::new(), true)?,
    }
    Ok(())
}

/// Send one masked DATA frame under flow control (never end-of-stream). Returns `Ok(false)` when
/// the downstream reset/closed (stop relaying), `Ok(true)` when sent (or the frame was empty).
async fn send_masked(dst: &mut h2::SendStream<Bytes>, data: Vec<u8>) -> Result<bool, h2::Error> {
    if data.is_empty() {
        return Ok(true);
    }
    let len = data.len();
    dst.reserve_capacity(len);
    loop {
        if dst.capacity() >= len {
            break;
        }
        match std::future::poll_fn(|cx| dst.poll_capacity(cx)).await {
            Some(Ok(_)) => continue,
            Some(Err(e)) => return Err(e),
            None => return Ok(false),
        }
    }
    dst.send_data(Bytes::from(data), false)?;
    Ok(true)
}

/// Whether the client's decoded request head carries any configured secret value verbatim — the
/// outbound leak tripwire, HTTP/2 form. Reconstructs a byte blob of the `:path` plus each
/// `name: value` header line and reuses the HTTP/1.1 [`carries_secret`] scan. Scanned before sbx's
/// own injection is added, so an injected credential can never self-trip it.
fn head_carries_secret(req: &Request<h2::RecvStream>, needles: &[SecretNeedle]) -> bool {
    let mut blob = Vec::new();
    if let Some(pq) = req.uri().path_and_query() {
        blob.extend_from_slice(pq.as_str().as_bytes());
        blob.push(b'\n');
    }
    for (name, value) in req.headers().iter() {
        blob.extend_from_slice(name.as_str().as_bytes());
        blob.extend_from_slice(b": ");
        blob.extend_from_slice(value.as_bytes());
        blob.push(b'\n');
    }
    carries_secret(&blob, needles)
}

/// Mask every configured secret value out of each header value in `headers` (an equal-length run
/// of `*`, so it stays a valid header value) — for a reflected secret in a response header or
/// trailer of an injection-target host.
fn redact_header_map(headers: &mut http::HeaderMap, needles: &[SecretNeedle]) {
    for value in headers.values_mut() {
        let mut bytes = value.as_bytes().to_vec();
        redact_in_place(&mut bytes, needles);
        if let Ok(v) = http::HeaderValue::from_bytes(&bytes) {
            *value = v;
        }
    }
}

/// Answer the client on this stream with a header-only refusal carrying the reason category (as
/// `x-sbx-egress-reason`), ending the stream. A gRPC client maps the non-`200` status to an RPC
/// error; the header names the exact category for a raw-HTTP client.
fn refuse(
    mut respond: h2::server::SendResponse<Bytes>,
    status: StatusCode,
    reason: &str,
) -> Result<(), h2::Error> {
    let resp = Response::builder()
        .status(status)
        .header("x-sbx-egress-reason", reason)
        .body(())
        .expect("a static status + ASCII reason is always a valid response");
    respond.send_response(resp, true)?;
    Ok(())
}

/// Connection-specific request headers HTTP/2 forbids (RFC 9113 §8.2.2), plus `host` (h2 carries
/// the authority as the `:authority` pseudo-header). `te` is deliberately kept — gRPC requires
/// `te: trailers`, which h2 permits.
fn forbidden_request_header(name: &str) -> bool {
    matches!(
        name,
        "host" | "connection" | "keep-alive" | "proxy-connection" | "transfer-encoding" | "upgrade"
    )
}

/// Connection-specific response headers HTTP/2 forbids.
fn forbidden_response_header(name: &str) -> bool {
    matches!(
        name,
        "connection" | "keep-alive" | "proxy-connection" | "transfer-encoding" | "upgrade"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redact_header_map_masks_a_reflected_secret_in_a_header_value() {
        // The response-header redaction path (a secret reflected in an h2 response header/trailer)
        // — exercised by neither the live nor the committed e2e (grpcb.in echoes into the body),
        // so pin it here: a masked value keeps its length (equal-length `*`) and a header with no
        // secret is untouched.
        let needles = vec![SecretNeedle::named("test-secret", b"topsecret".to_vec())];
        let mut headers = http::HeaderMap::new();
        headers.insert("x-echo", "before-topsecret-after".parse().unwrap());
        headers.insert("x-clean", "nothing to see".parse().unwrap());
        redact_header_map(&mut headers, &needles);
        assert_eq!(headers["x-echo"], "before-*********-after");
        assert_eq!(headers["x-clean"], "nothing to see");
    }

    /// An HTTP/2 head has no wire form to copy, so the capture renders it. The rendering must show
    /// the pseudo-headers under their real names: presenting `:authority` as an HTTP/1.1 `Host:`
    /// would be a fiction the reader cannot detect, and the point of a capture is that what it shows
    /// is what crossed.
    #[test]
    fn a_captured_h2_request_head_shows_the_pseudo_headers_as_themselves() {
        let req = Request::builder()
            .method(Method::POST)
            .uri("https://api.example.com/pkg.Svc/Method?x=1")
            .header("content-type", "application/grpc")
            .header("te", "trailers")
            .body(())
            .unwrap();
        let rendered = String::from_utf8(capture_request_head(&req)).unwrap();
        assert_eq!(
            rendered,
            "POST /pkg.Svc/Method?x=1 HTTP/2\r\n\
             :authority: api.example.com\r\n\
             content-type: application/grpc\r\n\
             te: trailers\r\n\r\n"
        );
        assert!(
            !rendered.to_ascii_lowercase().contains("host:"),
            "no synthesized Host: header may appear: {rendered:?}"
        );
    }

    /// The response head carries the status code with no reason phrase, because HTTP/2 has none —
    /// and it ends on the blank line the capture's head/body split looks for.
    #[test]
    fn a_captured_h2_response_head_has_no_invented_reason_phrase() {
        let mut headers = http::HeaderMap::new();
        headers.insert("content-type", "application/grpc".parse().unwrap());
        let rendered = String::from_utf8(capture_response_head(StatusCode::OK, &headers)).unwrap();
        assert_eq!(
            rendered,
            "HTTP/2 200\r\ncontent-type: application/grpc\r\n\r\n"
        );
        assert!(
            !rendered.contains("OK\r\n"),
            "HTTP/2 sends no reason phrase, so none is shown: {rendered:?}"
        );
    }
}
