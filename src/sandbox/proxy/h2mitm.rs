//! The HTTP/2 (gRPC) man-in-the-middle path, for a CONNECT to a designated `[network] http2` host.
//!
//! It is a sibling of the synchronous HTTP/1.1 tail of [`handle_client`](super::handle_client), not a rewrite of it: the
//! sync path is untouched. Because the `h2` crate is async (tokio-based), the whole branch runs on a
//! **per-connection current-thread tokio runtime** built and dropped inside [`handle`], so tokio
//! never leaks into sbx's std-thread world.
//!
//! Security parity with the HTTP/1.1 path is the invariant, and since the verdict was folded it is
//! no longer a parity that has to be maintained by hand: every stream goes through
//! [`decide_https`], the same function the tunnel and the absolute-form forward
//! call, so there is one policy decision rather than three that must be kept in step. This path
//! passes [`AskPosture::RefuseUnsupported`](super::AskPosture), which is the single way it diverges —
//! see the call site for why it cannot park. The `:authority`
//! is re-verified against the CONNECT host **per stream** (h2 lets a client vary it), the SSRF guard
//! resolves and validates the address exactly as [`connect_upstream`](super::connect_upstream) does (connect the checked IP,
//! no re-resolve, validate the upstream cert), and gRPC is HTTP/2 end-to-end (no downgrade). The
//! secret machinery is replicated too: the outbound tripwire ([`carries_secret`]) refuses a request
//! whose head carries a configured secret verbatim, matching host-scoped credentials are injected
//! (strip-and-replace) onto the upstream request, and a reflected secret is masked out of the
//! response DATA/headers/trailers for an injection-target host ([`relay_body_redacting`]).

use super::capture::CapBuf;
use super::inject::{HeaderLookup, RequestFacts, pairs_for as injection_values};
use super::{
    AskPosture, ProxyCtx, SIGNER_REFUSED, SecretNeedle, StatKind, carries_secret, decide_https,
    header_name_eq, is_connection_bound_challenge, matching_injection_ids, note_final_status,
    redact_in_place, resolve_checked, signer_refusal_message, upstream_server_name,
};
use crate::allowlist::{self, Rule};
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
///
/// Applied on **both** legs. The cage-facing one is the obvious half, but the proxy is a MITM: it
/// decodes the upstream's response headers too, and a remote server is untrusted here by the same
/// rule that makes its certificate worth validating. `h2::client::handshake` uses h2's own default
/// of `16 << 20` — 16 MiB per connection, kept alive by the tunnel's pool — so leaving the upstream
/// leg unbounded left the larger of the two doors open.
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
    // driven with no overall deadline — a gRPC stream may legitimately be long-lived — while the
    // *connection* carrying none is let go on `ctx.idle`, as [`accept_streams`] explains.
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

    // One pool per tunnel, living exactly as long as the runtime that drives its connections.
    let pool = UpstreamPool::default();
    accept_streams(&mut conn, connect_host, port, ctx, &pool).await;
    Ok(())
}

/// Drive one established h2 tunnel: accept its streams and run them concurrently until the client
/// stops, then drain what is still in flight.
///
/// Split out of [`serve`] so it can be driven over an in-memory duplex by a test — everything above
/// it is the TLS the tunnel already terminated.
///
/// A connection carrying **no stream** has an idle bound, exactly as the HTTP/1.1 tunnel bounds the
/// gap between two requests with `ctx.idle`. The no-overall-deadline choice this path documents is
/// about a *stream* that may legitimately be long-lived (a server-streaming RPC), and that argument
/// says nothing about a connection with nothing on it: without the bound a cage could complete
/// `max_connections` tunnels, send nothing further, and pin every host handler thread for the life of
/// the launch — with `ctx.conns` at its cap, so every later connection, to every other allowed host,
/// was answered `503 connection-cap` with no timeout that could ever recover it. The timer is rebuilt
/// each pass, so any activity resets it, and it is inert while a stream is in flight.
///
/// It covers the gap before the *first* stream as well, where the HTTP/1.1 tunnel gives its first
/// head the longer per-request timeout. The two windows are not the same question: there, a head is
/// already being read and the bound is how long that read may take; here the handshake is done and
/// the only question left is whether anything is using the tunnel at all, which is precisely what
/// `[network] idle_timeout` answers.
async fn accept_streams<T>(
    conn: &mut h2::server::Connection<T, Bytes>,
    connect_host: &str,
    port: u16,
    ctx: &ProxyCtx,
    pool: &UpstreamPool,
) where
    T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let bound = ctx.idle;
    let mut inflight = FuturesUnordered::new();
    loop {
        // Read before the timer is built rather than inside it: the future is pinned across the
        // `select!`, so a borrow of `inflight` taken here would still be live while the accept arm
        // pushes onto it.
        let quiet = inflight.is_empty();
        let idle = async {
            match quiet {
                true => tokio::time::sleep(bound).await,
                false => std::future::pending::<()>().await,
            }
        };
        tokio::pin!(idle);
        tokio::select! {
            accepted = conn.accept() => match accepted {
                Some(Ok((req, respond))) => {
                    if inflight.len() >= MAX_STREAMS as usize {
                        // Backstop the advertised SETTINGS limit: refuse the excess stream
                        // rather than letting an in-cage client open unbounded work per tunnel.
                        //
                        // Recorded before it is answered. `refuse` only writes the response; the
                        // log is `refuse_upstream`'s doing, and this site took the bare form, so
                        // the one cap an in-cage client can reach on this plane left no trace
                        // anywhere — no stat, no log line, no notice. `Blocked` rather than
                        // `Error`: its own documentation files the splice cap there, and this is
                        // that cap's h2 twin, not a downstream failure.
                        ctx.push_log(
                            Proto::Https,
                            connect_host,
                            port,
                            Some(req.method().as_str()),
                            Some(req.uri().path()),
                            LogVerdict::Blocked,
                            "http2-stream-cap",
                        );
                        let _ = refuse(respond, StatusCode::TOO_MANY_REQUESTS, "http2-stream-cap");
                        continue;
                    }
                    inflight.push(stream(req, respond, connect_host, port, ctx, pool));
                }
                // Accept error, or the client sent GOAWAY / closed the connection: stop taking
                // new streams, then drain the ones already in flight below.
                Some(Err(_)) | None => break,
            },
            Some(()) = inflight.next(), if !inflight.is_empty() => {}
            // An established tunnel carrying nothing, for longer than the launch's idle bound.
            () = &mut idle => break,
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
}

/// Handle one h2 stream: decode it, enforce the verdict + SSRF exactly like the HTTP/1.1 path,
/// then relay it to the validated upstream. Every early return has already answered the client
/// with a refusal carrying an `x-sbx-egress-reason`.
#[allow(clippy::too_many_arguments)]
async fn stream(
    req: Request<h2::RecvStream>,
    respond: h2::server::SendResponse<Bytes>,
    connect_host: &str,
    port: u16,
    ctx: &ProxyCtx,
    pool: &UpstreamPool,
) {
    let method = req.method().clone();
    let path = req
        .uri()
        .path_and_query()
        .map(|p| p.as_str().to_string())
        .unwrap_or_else(|| "/".into());
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
    if !authority_bound_to(req.uri().authority(), connect_host, port) {
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
    let creds = ctx.credentials.snapshot();
    if !creds.needles.is_empty() && head_carries_secret(&req, &creds.needles, connect_host) {
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

    // The verdict — literally the same decision the HTTP/1.1 paths reach, through the shared
    // [`decide_https`]: config policy ∪ any `--session` overlay, deny-wins, method/path aware. Only
    // the answer differs, framed here as a status plus the reason token rather than written — the
    // token *is* the answer for a policy refusal, and the prose the other planes add says the same
    // thing about a host the caller named. A signer refusal is the one exception, and carries the
    // plugin's own sentence as a body: see [`refuse_with_detail`].
    //
    // [`AskPosture::RefuseUnsupported`] is where this path genuinely diverges. Parking blocks the
    // caller until a person answers, and every stream of this connection shares one current-thread
    // runtime, so parking one would stall its siblings. An undecided host fails closed under its own
    // reason instead; an explicit `allow` rule for the gRPC endpoint is the intended posture.
    let deciding: Option<Rule> = match decide_https(
        ctx,
        connect_host,
        port,
        &path,
        method.as_str(),
        AskPosture::RefuseUnsupported,
    ) {
        Ok(rule) => rule,
        Err(refusal) => {
            let _ = refuse(respond, refusal.status(), refusal.tag());
            return;
        }
    };
    // The allow is recorded only after the upstream connects (in `relay`), matching the
    // HTTP/1.1 path: a request that passes the verdict but then fails SSRF/DNS/upstream is
    // logged (an `Error`/`Blocked` line) but never counted as an allow in `sbx net stats`.

    // Resolve host-side, then the SSRF guard against the deciding rule (a private/metadata
    // address is refused unless the rule names the exact host) — then connect the checked IP with
    // no re-resolution, exactly like the HTTP/1.1 path.
    let ip = match resolve_checked(
        ctx,
        Proto::Https,
        connect_host,
        port,
        Some(method.as_str()),
        Some(&path),
        deciding.as_ref(),
    ) {
        Ok(ip) => ip,
        Err(refusal) => {
            // The refusal is already recorded — the shared guard counts an SSRF block and logs a
            // resolution failure, so this path answers the client and nothing else.
            let _ = refuse(respond, refusal.status(), refusal.tag());
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
        pool,
    )
    .await;
}

/// Whether a stream's `:authority` is bound to the tunnel it arrived on: the same host, the same
/// port, and no userinfo.
///
/// The host comparison alone is not the check, because the string sbx *authorizes* has to be the
/// string sbx *forwards*. The upstream request is rebuilt from the decoded `parts.uri` and h2
/// re-emits the authority verbatim (`Pseudo::request` writes `authority.as_str()`), while
/// `Authority::host()` drops both the userinfo and the port — so an authority of
/// `victim.example@grpc.vendor.example` passed a host-only gate and then crossed to the origin
/// whole, for any edge that keys on the raw bytes or reads the segment before the `@`. RFC 9113
/// §8.3.1 settles it independently: `:authority` MUST NOT carry the deprecated userinfo, and an
/// intermediary receiving one must treat the request as malformed. sbx is that intermediary.
///
/// The HTTP/1.1 twin never had the gap — `serve_tunneled_request` compares the whole `Host` value
/// minus an all-digit `:`-suffix, so both spellings mismatch there — and the module header claims
/// parity with it, which this restores. A port is optional in an `:authority` (a client on the
/// scheme's default port omits it), so it is checked only when present.
fn authority_bound_to(
    authority: Option<&http::uri::Authority>,
    connect_host: &str,
    port: u16,
) -> bool {
    authority.is_some_and(|a| {
        !a.as_str().contains('@')
            && a.port_u16().is_none_or(|p| p == port)
            && allowlist::canonical_host(a.host()) == connect_host
    })
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
    pool: &UpstreamPool,
) {
    // One credential state for the whole stream's relay: the injection applied below and the reflection
    // masking decided further down must come from the same resolution.
    let creds = ctx.credentials.snapshot();
    // Any host-scoped credential to inject — keyed on the already-verified host and the decrypted
    // path, so it reaches exactly its scoped destination. Runs after the verdict (a denied request
    // never got here). Each is **strip-and-replace**: the client's own copy of that header is
    // dropped and sbx's value is the only one forwarded.
    //
    // Forming the values goes through the same door the other two plans use, so a signer refusal
    // cannot be invisible on this one: it is counted at the same chokepoint and answered with the
    // same status, framed rather than written.
    //
    // Settled here, *before* the upstream is opened and before the allow is recorded, which is
    // where the HTTP/1.1 paths settle it too. Left where the injection used to sit — after the
    // allow — a refused stream would have been counted twice, once allowed and once blocked, which
    // is the same asymmetry between the plans that once made an h2 refusal invisible, inverted.
    let injected_ids = matching_injection_ids(&creds, host, port, path);
    // What a signer asking for a body digest is told here. A stream that ended with its headers has
    // no body, and the digest of nothing is exact and free. Anything else is **stated as unheld**:
    // this plan relays DATA frames as they arrive, and an h2 request half may legitimately never end
    // (a bidi-streaming RPC), so a digest over it is not a cost sbx declines to pay — it is a fact
    // that does not exist yet at the moment the request must be signed. Saying so lets a scheme that
    // requires the body covered refuse, instead of signing as though there were none.
    let body_facts = creds.wants_body_digest(&injected_ids).map(|algorithm| {
        match req.body().is_end_stream() {
            true => crate::sandbox::signer::BodyFacts::held(&[], algorithm),
            false => crate::sandbox::signer::BodyFacts::unheld(
                "this request's body arrives as HTTP/2 DATA frames, which sbx relays as they come \
                 rather than holding — an HTTP/2 request half may legitimately never end",
            ),
        }
    });
    let injected = match injection_values(
        &creds,
        &injected_ids,
        &RequestFacts {
            method,
            host,
            port,
            target: path,
            headers: &H2Headers(req.headers()),
            body: body_facts.as_ref(),
        },
        ctx.signer_log(),
    ) {
        Ok(pairs) => pairs,
        Err(refusal) => {
            ctx.outcome(
                Proto::Https,
                host,
                port,
                Some(method),
                Some(path),
                StatKind::Blocked,
                SIGNER_REFUSED,
            );
            // Answered with the plugin's own sentence, as both HTTP/1.1 planes answer it, and
            // scrubbed by the same function they share: what reaches the sandbox here is what
            // reaches it there.
            let _ = refuse_with_detail(
                respond,
                StatusCode::FORBIDDEN,
                SIGNER_REFUSED,
                &signer_refusal_message(&refusal, &creds.needles),
            );
            return;
        }
    };

    // Remember any credential the cage sent for itself, on the same terms and in the same place as
    // both HTTP/1.1 planes: after the verdict, after the outbound tripwire, after the injection
    // match. The scan set is shared across every plane, so a token a gRPC client acquired here is
    // one the tripwires cover everywhere afterwards — and one this plane never observed would be a
    // hole in all three.
    let injected_names = super::injected_names(&injected);
    ctx.credentials
        .observe_head(&H2Headers(req.headers()), &injected_names, host);

    // The upstream this stream will ride: one this tunnel already opened for the same credential
    // set, or a new one. HTTP/2 multiplexes, so a connection here is **shared** rather than taken
    // and returned: several streams use it at once and none of them gives it back.
    //
    // Nothing about the decision is reused. The `:authority` re-check, the outbound tripwire, the
    // verdict, the resolution and the address guard all ran above, per stream, and a stream that any
    // of them refuses never reaches this line. What is reused is the handshake.
    let send_req = match ready_upstream(pool, &injected_ids, ip, port, host, ctx).await {
        Ok(send) => send,
        Err(reason) => {
            refuse_upstream(respond, ctx, host, port, method, path, reason);
            return;
        }
    };

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

    // Register this stream in the live flow registry for as long as it is relayed, exactly where the
    // other three planes register theirs (tunnel.rs, forward.rs, cleartext.rs all take the guard
    // beside their allow) and on the contract [`ProxyCtx::register_flow`] states: after the request
    // is permitted and the upstream is connected. Per stream rather than per tunnel, following the
    // tunneled path — that is what keeps the byte totals attributable to the exchange that moved
    // them, on a transport where one connection carries many.
    //
    // Without it `sbx net live` — the whole point of which is seeing what is moving right now — was
    // empty for every gRPC tunnel, and its `↑`/`↓` totals zero, while the same transfer to the same
    // host over HTTP/1.1 showed a row with running counts. A long-lived bidirectional stream is the
    // canonical durable row, and it was the one kind that never appeared. This path stays `https`:
    // an h2 stream over the MITM is inspected TLS like any other.
    let flow = ctx.register_flow(host, port, Proto::Https);

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
        // The strip compares names the way the other three serializers do, through
        // [`header_name_eq`]: case-insensitively **and** treating `_` as `-`. An HTTP/2 name is
        // lowercase already, so case is not what this is for — `_` is. A server that folds
        // `x_api_key` onto `x-api-key` would otherwise receive the caller's spelling beside sbx's,
        // which is the dodge the HTTP/1.1 planes close and this one has to close identically.
        if forbidden_request_header(n) || injected.iter().any(|(h, _)| header_name_eq(h, n)) {
            continue;
        }
        builder = builder.header(name, value);
    }
    for (h, v) in &injected {
        builder = builder.header(h.as_str(), v.as_str());
    }
    // The client's own headers were decoded by `h2` and cannot fail to be re-added, so the only way
    // this builder refuses is a header **sbx** is adding whose value cannot be one. It is a backstop
    // rather than a live path — a signer's value is already refused at the plugin boundary if it
    // carries a newline or a NUL — and it is named for its cause: reporting it as a malformed
    // request would blame the caller for a header the caller never sent.
    let up_req = match builder.body(()) {
        Ok(r) => r,
        Err(_) => {
            refuse_upstream(
                respond,
                ctx,
                host,
                port,
                method,
                path,
                "injected-header-invalid",
            );
            return;
        }
    };
    // From here the upstream connection is open, so a failure is one that CLOSED — never
    // `upstream-unreachable`, which on every plane means the connection was not made at all. Each
    // leaves its own `error` line beside the allow already recorded, which is the shape the HTTP/1.1
    // path leaves for the same event (an allow whose status never arrives, and an `upstream-closed`
    // naming why).
    let mut send_req = send_req;
    let (resp_fut, up_send_body) = match send_req.send_request(up_req, false) {
        Ok(x) => x,
        Err(_) => {
            refuse_upstream(respond, ctx, host, port, method, path, "upstream-closed");
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
    // The names sbx injected into the head, carried into the pump so the trailers of the same
    // request are held to the same strip — see [`relay_body`].
    let trailer_strip: Vec<String> = injected.iter().map(|(h, _)| h.clone()).collect();
    // The `up` half of the flow's byte totals. Cloned rather than borrowed because the pump outlives
    // this function on a request half that never ends; a counter the registry has already dropped is
    // simply an atomic nobody reads any more.
    let up_bytes = Arc::clone(&flow.up);
    tokio::spawn(async move {
        let _ = relay_body(
            client_body,
            up_send_body,
            req_sink,
            Some(trailer_strip),
            up_bytes,
        )
        .await;
    });

    let resp = match resp_fut.await {
        Ok(r) => r,
        Err(_) => {
            refuse_upstream(respond, ctx, host, port, method, path, "upstream-closed");
            return;
        }
    };
    let (mut rparts, up_body) = resp.into_parts();
    // The h2 response's `:status` is already final, so it goes straight to the decision the two
    // HTTP/1.1 planes reach through their own status-line parse.
    note_final_status(ctx, seq, &creds, &injected_ids, rparts.status.as_u16());
    // Stop sharing a connection the upstream has just bound an identity to — see
    // [`binds_identity_to_the_connection`].
    if binds_identity_to_the_connection(&rparts.headers) {
        pool.open.borrow_mut().retain(|(k, _)| *k != injected_ids);
    }

    // Capture the response head, rendered from the framed status + headers. Teed ahead of the
    // reflection masking below, like the HTTP/1.1 path: the capture masks its own buffers at filing
    // time, so what is stored is masked either way, and what the cage receives is decided by
    // `masks_reflection` alone.
    if let Some(c) = &capture {
        c.push_response(&capture_response_head(rparts.status, &rparts.headers));
    }

    // Response-side leak backstop, scoped to a host an injection targets. It is the HTTP/1.1
    // planes' question asked of the same function (`CredentialSet::masks_reflection_for`), so
    // parity here is structural rather than maintained by hand.
    let masks_reflection = creds.masks_reflection_for(host);
    if masks_reflection {
        redact_header_map(&mut rparts.headers, &creds.needles);
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
        let _ = relay_body_redacting(
            up_body,
            client_send_body,
            &creds.needles,
            res_sink,
            Arc::clone(&flow.down),
        )
        .await;
    } else {
        let _ = relay_body(
            up_body,
            client_send_body,
            res_sink,
            None,
            Arc::clone(&flow.down),
        )
        .await;
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

/// Send `chunk` downstream under HTTP/2 flow control, in as many DATA frames as the peer's window
/// grants, and report how many bytes actually left.
///
/// **What was granted, not what was asked for** — and that is the difference between relaying and
/// deadlocking. h2 assigns at most the peer's stream window (`try_assign_capacity` bounds the
/// assignment by `window_size - available`), so a peer whose `SETTINGS_INITIAL_WINDOW_SIZE` is below
/// the size of one relayed chunk makes `capacity()` plateau there. Waiting for
/// `capacity() >= chunk.len()` then waits forever: the proxy will not send until it can send the
/// whole chunk, and the peer will not enlarge the window until it has read something — which it
/// cannot, because nothing was sent. Both directions used that spelling, and a cage picks its own
/// initial window, so an in-cage client advertising a small one wedged the stream and held the
/// tunnel's thread and its upstream connection with it.
///
/// `Ok(0)` with a non-empty chunk means the downstream reset or closed and relaying should stop —
/// the same signal the `None` arm of `poll_capacity` carried before.
async fn send_granted(
    dst: &mut h2::SendStream<Bytes>,
    mut chunk: Bytes,
) -> Result<usize, h2::Error> {
    let mut sent = 0;
    while !chunk.is_empty() {
        dst.reserve_capacity(chunk.len());
        let granted = match dst.capacity() {
            0 => match std::future::poll_fn(|cx| dst.poll_capacity(cx)).await {
                Some(Ok(n)) if n > 0 => n,
                Some(Ok(_)) => continue,
                Some(Err(e)) => return Err(e),
                // The downstream reset/closed: stop relaying (dropping `dst` sends a reset).
                None => return Ok(sent),
            },
            n => n,
        };
        let take = granted.min(chunk.len());
        let piece = chunk.split_to(take);
        dst.send_data(piece, false)?;
        sent += take;
    }
    Ok(sent)
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
///
/// `bytes` is this direction's half of the live flow's totals, the row `sbx net live` renders.
///
/// Counted as each frame is *read*, which is what the HTTP/1.1 planes' `CountingReader` counts, so
/// the two transports answer the same question the same way.
async fn relay_body(
    mut src: h2::RecvStream,
    mut dst: h2::SendStream<Bytes>,
    cap: Option<Arc<CapBuf>>,
    strip: Option<Vec<String>>,
    bytes: Arc<std::sync::atomic::AtomicU64>,
) -> Result<(), h2::Error> {
    while let Some(chunk) = src.data().await {
        let chunk = chunk?;
        let len = chunk.len();
        bytes.fetch_add(len as u64, std::sync::atomic::Ordering::Relaxed);
        if let Some(cap) = &cap {
            cap.push(&chunk);
        }
        if len > 0 && send_granted(&mut dst, chunk).await? < len {
            // The downstream reset/closed part-way: stop relaying.
            return Ok(());
        }
        // Return the consumed window to the sender so it can keep sending.
        let _ = src.flow_control().release_capacity(len);
    }
    // The DATA stream ended on its own: everything this direction will ever carry has been captured.
    if let Some(cap) = &cap {
        cap.mark_source_ended();
    }
    match src.trailers().await? {
        Some(mut trailers) => {
            // The request head's strip, applied to the trailers of the same request. `Some` marks
            // the **request** direction and carries the names sbx injected.
            //
            // The head rebuild drops a connection-specific header and every name sbx is about to
            // inject, "so the injected value is the only one the upstream sees". Trailers went
            // through untouched, so a cage could put its own `authorization` after the body instead
            // of before it and have it reach the upstream beside sbx's — and this plane exists for
            // gRPC, where trailers are ordinary traffic rather than an exotic corner. The HTTP/1.1
            // planes never had the hole: they de-chunk and re-frame, so no trailer is forwarded at
            // all.
            //
            // The response direction passes `None`: nothing is injected that way, and a reflected
            // secret in a response trailer is `relay_body_redacting`'s to mask.
            if let Some(strip) = &strip {
                trailers = strip_request_trailers(trailers, strip);
            }
            dst.send_trailers(trailers)?;
        }
        None => dst.send_data(Bytes::new(), true)?,
    }
    Ok(())
}

/// Hold a request's trailers to the same strip the request head passed: no connection-specific
/// header, and none of the names sbx injected.
///
/// Split out of [`relay_body`] because it is the decision rather than the plumbing, and because the
/// pump around it needs a live h2 stream pair while this needs nothing.
///
/// `HeaderMap` has no `retain`, so the kept set is rebuilt. Its `into_iter` reports the name only
/// once per run of repeats, yielding `None` for the rest — `last` carries it, so a repeated header
/// is judged by the name it belongs to instead of being dropped for having none.
fn strip_request_trailers(trailers: http::HeaderMap, injected: &[String]) -> http::HeaderMap {
    let mut kept = http::HeaderMap::with_capacity(trailers.len());
    let mut last: Option<http::header::HeaderName> = None;
    for (name, value) in trailers {
        let Some(name) = name.or_else(|| last.clone()) else {
            continue;
        };
        let n = name.as_str();
        if !forbidden_request_header(n) && !injected.iter().any(|h| header_name_eq(h, n)) {
            kept.append(name.clone(), value);
        }
        last = Some(name);
    }
    kept
}

/// Relay a response body like [`relay_body`], but mask every configured secret value out of each
/// DATA frame (and the trailers) with an equal-length run of `*` — the streaming response-side
/// leak backstop, used only for a response from an injection-target host.
///
/// Each frame is redacted **independently and emitted whole** — deliberately NOT carrying bytes
/// across frames, where the HTTP/1.1 twin ([`super::pump_redacting`]) does carry a tail across reads. The
/// two planes answer differently because what a withheld byte costs is not the same on them.
///
/// On HTTP/1.1 a response is one message the client reads to its end, so holding a tail costs
/// latency and the tail is always released by the next read or by the end of the body. On HTTP/2 the
/// client may have to act on a complete response message before it sends its next request (gRPC
/// reflection, any client-streaming or bidirectional RPC), and there the tail is released by a next
/// frame that will never be sent: a stall with no end. Holding only what *begins* a needle, as the
/// other plane does, does not make that safe either — a frame ends on some needle's first byte often
/// enough that the stall would be a live risk rather than a corner.
///
/// The residual is therefore a secret split across two DATA frames (a 16 KiB boundary), which is
/// then not masked — rare, and the same best-effort class as the gzip-compressed-body limit; the
/// real controls are the empty netns, the allowlist, the per-host `to` scoping, and the outbound
/// tripwire. Equal-length masking keeps every byte count intact.
async fn relay_body_redacting(
    mut src: h2::RecvStream,
    mut dst: h2::SendStream<Bytes>,
    needles: &[SecretNeedle],
    cap: Option<Arc<CapBuf>>,
    bytes: Arc<std::sync::atomic::AtomicU64>,
) -> Result<(), h2::Error> {
    while let Some(chunk) = src.data().await {
        let chunk = chunk?;
        let len = chunk.len();
        bytes.fetch_add(len as u64, std::sync::atomic::Ordering::Relaxed);
        // Captured before the masking, like the HTTP/1.1 path: the capture ring masks whatever it
        // stores at filing time, over whole buffers rather than per frame.
        if let Some(cap) = &cap {
            cap.push(&chunk);
        }
        // Copy only a frame that has something to change. `redact_in_place` writes into an owned
        // buffer, so a frame with no occurrence in it was copied whole — a 16 KiB memcpy per DATA
        // frame — only to be handed back unaltered. The scan that decides is one pass of the same
        // prebuilt finders the masking would have run anyway, and the no-match frame, which is
        // nearly every frame (the premise of a reflection backstop is that reflection is rare), now
        // relays exactly as the unmasked path relays it: the `Bytes` split under flow control, no
        // copy at all.
        let sent = if needles.iter().any(|n| n.find_in(&chunk, 0).is_some()) {
            let mut buf = chunk.to_vec();
            redact_in_place(&mut buf, needles);
            send_masked(&mut dst, buf).await?
        } else {
            send_granted(&mut dst, chunk).await? == len
        };
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
    Ok(send_granted(dst, Bytes::from(data)).await? == len)
}

/// Whether the client's decoded request head carries any configured secret value verbatim — the
/// outbound leak tripwire, HTTP/2 form. Reconstructs a byte blob of the `:path` plus each
/// `name: value` header line and reuses the HTTP/1.1 [`carries_secret`] scan. Scanned before sbx's
/// own injection is added, so an injected credential can never self-trip it.
fn head_carries_secret(
    req: &Request<h2::RecvStream>,
    needles: &[SecretNeedle],
    dest: &str,
) -> bool {
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
    carries_secret(&blob, needles, dest)
}

/// Mask every configured secret value out of each header value in `headers` (an equal-length run
/// of `*`, so it stays a valid header value) — for a reflected secret in a response header or
/// trailer of an injection-target host.
fn redact_header_map(headers: &mut http::HeaderMap, needles: &[SecretNeedle]) {
    for value in headers.values_mut() {
        // A value carrying nothing to mask is left exactly as it arrived: the copy and the
        // `HeaderValue` round trip below are the price of changing a value, and almost no value of
        // almost any response has to change.
        if !needles
            .iter()
            .any(|n| n.find_in(value.as_bytes(), 0).is_some())
        {
            continue;
        }
        let mut bytes = value.as_bytes().to_vec();
        redact_in_place(&mut bytes, needles);
        if let Ok(v) = http::HeaderValue::from_bytes(&bytes) {
            *value = v;
        }
    }
}

/// The most connections one tunnel keeps. The key is the injected credential set, which follows
/// from the **path**, and the path is the caller's to choose: with several path-scoped credentials a
/// stream can ask for a combination no earlier one used, and each combination is a live connection.
/// Far above any real policy's distinct sets, and past it a stream still gets its connection, the
/// tunnel simply stops keeping it — the same stance the leaf cache takes.
const MAX_POOLED: usize = 8;

/// The upstream connections one tunnel has opened, shared by the streams riding it.
///
/// HTTP/2 multiplexes, so this is not the HTTP/1.1 pool's take-and-return: a connection is handed to
/// every stream that may use it, all at once, and none of them gives it back. It lives exactly as
/// long as the tunnel, because the runtime driving it is the tunnel's own.
///
/// **Keyed by the injected credential set**, which is the whole of the HTTP/1.1 pool's key that is
/// left once the host and port are fixed by the CONNECT. It is also the half that matters: a
/// connection that carried a credential is never offered to a stream that does not receive the same
/// one.
#[derive(Default)]
struct UpstreamPool {
    // A `RefCell` rather than a lock: every stream of a tunnel runs on that tunnel's single
    // current-thread runtime. No borrow is ever held across an await.
    open: std::cell::RefCell<Vec<(Vec<usize>, h2::client::SendRequest<Bytes>)>>,
}

/// A connection ready to carry this stream: the tunnel's, if it has one for this credential set,
/// else a new one. `Err` carries the reason token the client is refused with.
///
/// A pooled connection the far side closed while it sat idle only reveals that here — and here is
/// **before** the request is handed over, because `ready` resolves on the connection and
/// `send_request` is a separate step. So a stale one costs this stream nothing but the handshake it
/// was trying to avoid, and there is no re-sendability to establish first. That is the whole of why
/// this pool is simpler than the HTTP/1.1 one, where a body already streamed away cannot be replayed
/// and the request must therefore qualify before it may take a parked connection at all.
async fn ready_upstream(
    pool: &UpstreamPool,
    ids: &[usize],
    ip: IpAddr,
    port: u16,
    host: &str,
    ctx: &ProxyCtx,
) -> Result<h2::client::SendRequest<Bytes>, &'static str> {
    // `[network] pool = false` means what it says on this plane too: a launch that asked for no
    // upstream reuse gets a connection per stream, as it did before this pool existed.
    if ctx.pool.is_none() {
        return open_upstream(ip, port, host, ctx)
            .await?
            .ready()
            .await
            .map_err(|_| "upstream-closed");
    }
    // Cloned out, and the borrow dropped, before anything is awaited.
    let pooled = pool
        .open
        .borrow()
        .iter()
        .find(|(k, _)| k == ids)
        .map(|(_, send)| send.clone());
    if let Some(send) = pooled {
        match send.ready().await {
            Ok(ready) => return Ok(ready),
            Err(_) => pool.open.borrow_mut().retain(|(k, _)| k != ids),
        }
    }
    let send = open_upstream(ip, port, host, ctx).await?;
    {
        let mut open = pool.open.borrow_mut();
        if open.len() < MAX_POOLED {
            open.push((ids.to_vec(), send.clone()));
        }
    }
    send.ready().await.map_err(|_| "upstream-closed")
}

/// Open one validated HTTP/2 connection to the checked address: connect, terminate TLS with the
/// certificate validated and ALPN `h2` required, then run the client handshake. `Err` carries the
/// reason token, so a caller answers the same refusal whether the connection was opened for this
/// stream or for the one before it.
async fn open_upstream(
    ip: IpAddr,
    port: u16,
    host: &str,
    ctx: &ProxyCtx,
) -> Result<h2::client::SendRequest<Bytes>, &'static str> {
    let tcp =
        match tokio::time::timeout(ctx.timeout, tokio::net::TcpStream::connect((ip, port))).await {
            Ok(Ok(t)) => {
                // Nagle off, as on the HTTP/1.1 paths: h2 writes headers and DATA as separate
                // frames, so the coalescing Nagle waits for is latency this plane adds per stream.
                let _ = t.set_nodelay(true);
                t
            }
            _ => return Err("upstream-unreachable"),
        };
    let name = upstream_server_name(host).map_err(|_| "upstream-cert-rejected")?;
    let connector = tokio_rustls::TlsConnector::from(ctx.upstream_h2.clone());
    let upstream_tls = match tokio::time::timeout(ctx.timeout, connector.connect(name, tcp)).await {
        Ok(Ok(t)) => t,
        // A forged / self-signed / otherwise-untrusted upstream fails validation here — never
        // downgraded, exactly like the HTTP/1.1 `connect_upstream`. One failure among these is not
        // about the certificate at all, so it is not reported as one: see [`handshake_reason`].
        Ok(Err(e)) => return Err(handshake_reason(&e)),
        Err(_) => return Err("upstream-cert-rejected"),
    };
    if upstream_tls.get_ref().1.alpn_protocol() != Some(b"h2".as_slice()) {
        // gRPC is HTTP/2 end-to-end; the proxy does not translate to HTTP/1.1. Fail closed.
        return Err("upstream-http2-unsupported");
    }
    let (send_req, connection) = h2::client::Builder::new()
        .max_header_list_size(MAX_HEADER_LIST)
        // The same both-legs rule `MAX_HEADER_LIST` states, applied to the two settings that bound
        // how much *state* a remote server can make the host hold. The proxy is a MITM and a remote
        // server is untrusted here by the same rule that makes its certificate worth validating.
        //
        // Server push is the one that matters. h2 sends no `SETTINGS_ENABLE_PUSH` of its own and the
        // default is on, so an allowlisted upstream could emit PUSH_PROMISE frames on a stream that
        // never ends — which is the shape this plane exists for, a server-streaming RPC. Nothing
        // here ever drains `ResponseFuture::push_promises`, and a reserved stream is explicitly
        // outside the concurrency budget, so each promise's decoded head — up to the full
        // `MAX_HEADER_LIST`, from a couple of HPACK indexed bytes on the wire — was retained for the
        // life of the tunnel. That growth lands in the supervisor, which is deliberately outside the
        // cage's cgroup, so the cage's `MemoryMax` does not contain it. Refused, the upstream's own
        // stack will not send one at all, and h2 answers a PUSH_PROMISE that arrives anyway with a
        // connection PROTOCOL_ERROR.
        //
        // The stream budget is the ordinary half: the cage-facing server advertises `MAX_STREAMS`,
        // and a leg that advertised nothing let the peer open as many as it liked.
        .enable_push(false)
        .max_concurrent_streams(MAX_STREAMS)
        .handshake::<_, Bytes>(upstream_tls)
        .await
        .map_err(|_| "upstream-http2-unsupported")?;
    // The connection driver owns only the TLS stream + h2 state (it does not borrow `ctx`), so it is
    // `'static` and can be spawned on this tunnel's runtime; it is cancelled when the runtime is
    // dropped, which is what bounds a pooled connection's life to its tunnel.
    tokio::spawn(async move {
        let _ = connection.await;
    });
    Ok(send_req)
}

/// Whether a response binds an authenticated identity to the **connection** rather than to the
/// request: an `NTLM` or `Negotiate` challenge. The HTTP/1.1 pool refuses to park such a connection
/// for the same reason this one stops sharing it — handing it to a later stream would hand that
/// stream an identity it never asked for and cannot see.
///
/// Which schemes those are is [`is_connection_bound_challenge`]'s to say, so the two pools cannot
/// come to disagree about it; what is decided here is only that an HTTP/2 challenge is read out of
/// an HPACK header map rather than off a parsed head.
///
/// The streams already riding it are not recalled, which is inherent to multiplexing and true of any
/// HTTP/2 client. What this stops is every stream after.
fn binds_identity_to_the_connection(headers: &http::HeaderMap) -> bool {
    headers
        .get_all("www-authenticate")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .any(is_connection_bound_challenge)
}

/// Refuse a stream over its upstream: the client gets the `502` and its reason, and the exchange
/// leaves an `error` line behind.
///
/// The line is the point. Its HTTP/1.1 twin ([`refuse_upstream`](super::refuse_upstream)) writes one
/// at the same place in its own sequence, and without it a stream that policy allowed but that never
/// reached its host was reported nowhere at all — neither counted (the allow is recorded only once
/// the upstream is up) nor logged.
///
/// What a reader ends up with therefore depends on where the failure fell, and both shapes match the
/// HTTP/1.1 path. Before the allow: one `error` line and nothing else, the stream never having been
/// an allow. After it: the allow stands, its status never arrives, and the `error` beside it says
/// why — an upstream that was reached and then closed is a different event from one that was never
/// reached, and the reasons keep them apart.
fn refuse_upstream(
    respond: h2::server::SendResponse<Bytes>,
    ctx: &ProxyCtx,
    host: &str,
    port: u16,
    method: &str,
    path: &str,
    reason: &str,
) {
    ctx.push_log(
        Proto::Https,
        host,
        port,
        Some(method),
        Some(path),
        LogVerdict::Error,
        reason,
    );
    let _ = refuse(respond, StatusCode::BAD_GATEWAY, reason);
}

/// Which reason a failed upstream TLS handshake carries.
///
/// Nearly all of them are what they look like: an untrusted, expired or misnamed certificate. One is
/// not. This plane offers only `h2`, so a peer that will not speak HTTP/2 has no protocol in common
/// and ends the handshake with a `no_application_protocol` alert — a working, correctly certified
/// server that simply does not do gRPC. Reporting that as a rejected certificate points the reader
/// at the one thing that is not wrong, so it is named for what it is.
fn handshake_reason(e: &io::Error) -> &'static str {
    match e.get_ref().and_then(|e| e.downcast_ref::<rustls::Error>()) {
        Some(rustls::Error::AlertReceived(rustls::AlertDescription::NoApplicationProtocol)) => {
            "upstream-http2-unsupported"
        }
        _ => "upstream-cert-rejected",
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

/// Refuse a stream **with prose**, in the body shape the HTTP/1.1 planes write.
///
/// The exception to this path's framing, and the exception is the point. Every other refusal here
/// answers with a status and a reason token because the token *is* the answer: `denied`, `ssrf`,
/// `not-upgradable` say the whole of what happened, and the prose the HTTP/1.1 planes add is
/// derived from that token plus a host the caller already named.
///
/// A signer refusal is not like that. Its content is the plugin's own sentence about why it would
/// not form this credential, which no token encodes and nothing else carries to the caller: the
/// `signer` feed is the operator's, not the sandbox's. Framed without it, an h2 caller is told a
/// request was refused and given no way to learn what to change, where an HTTP/1.1 caller is told
/// exactly. That is the asymmetry this closes, and it closes it without overturning the framing
/// choice for the refusals whose answer really is one word.
fn refuse_with_detail(
    mut respond: h2::server::SendResponse<Bytes>,
    status: StatusCode,
    reason: &str,
    detail: &str,
) -> Result<(), h2::Error> {
    let body = Bytes::from(super::refusal_body(detail));
    let resp = Response::builder()
        .status(status)
        .header("x-sbx-egress-reason", reason)
        .header("content-type", "text/plain")
        .header("content-length", body.len())
        .body(())
        .expect("a static status + ASCII reason is always a valid response");
    let mut stream = respond.send_response(resp, false)?;
    stream.send_data(body, true)?;
    Ok(())
}

/// This path's header representation, offered to a signer under the shape every path offers.
///
/// A wrapper rather than an `impl` on `HeaderMap` itself, because the trait belongs to the
/// injection layer and the map to `http`: neither is ours to give the other.
struct H2Headers<'a>(&'a http::HeaderMap);

impl HeaderLookup for H2Headers<'_> {
    fn get(&self, name: &str) -> Option<&str> {
        // A header whose bytes are not text is not one a signer can be shown: it would have to be
        // spelled to reach a JSON line, and a spelling sbx invented is not what the cage sent.
        self.0.get(name).and_then(|v| v.to_str().ok())
    }

    fn for_each(&self, name: &str, f: &mut dyn FnMut(&str)) {
        for value in self.0.get_all(name) {
            // Same rule as `get`: bytes that are not text are not a value sbx can hand on.
            if let Ok(text) = value.to_str() {
                f(text);
            }
        }
    }
}

/// Request headers this plane does not forward: the connection-specific ones HTTP/2 forbids
/// (RFC 9113 §8.2.2), plus `host` (h2 carries the authority as the `:authority` pseudo-header), plus
/// `proxy-authorization`. `te` is deliberately kept — gRPC requires `te: trailers`, which h2 permits.
///
/// `proxy-authorization` is the odd one out and is here on its own reasoning, not the RFC's: it is a
/// credential the client addressed to the **proxy hop**, so handing it to the origin server gives
/// that server a secret meant for sbx. `reserialize_request` says exactly this and drops it on both
/// HTTP/1.1 planes; this plane and the WebSocket upgrade were forwarding it.
fn forbidden_request_header(name: &str) -> bool {
    matches!(
        name,
        "host"
            | "connection"
            | "keep-alive"
            | "proxy-connection"
            | "proxy-authorization"
            | "transfer-encoding"
            | "upgrade"
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
    // Named here rather than per-test because the shared verdict harness carries them in its
    // signature; the tests below still spell their own policy imports where they build one.
    use crate::allowlist::EgressPolicy;
    use crate::sandbox::egress_stats::Counts;

    /// The h2 plane drops the proxy-hop credential too, and keeps what gRPC needs.
    ///
    /// `forbidden_request_header` is the h2 rebuild's only filter, so a header absent from it is
    /// forwarded to the origin. `proxy-authorization` was, handing the far end a secret the client
    /// addressed to sbx — while both HTTP/1.1 planes have always dropped it. `te` is asserted in the
    /// same test because gRPC requires `te: trailers` and a careless widening of this list would
    /// take it out.
    #[test]
    fn the_proxy_credential_is_not_forwarded_and_grpc_keeps_its_te() {
        assert!(forbidden_request_header("proxy-authorization"));
        assert!(
            !forbidden_request_header("te"),
            "gRPC requires `te: trailers`, which h2 permits"
        );
        assert!(
            !forbidden_request_header("authorization"),
            "the origin's own credential is not the proxy hop's and must still be forwarded"
        );
    }

    /// A peer whose stream window is smaller than one relayed chunk must still be relayed to.
    ///
    /// h2 assigns at most the peer's window, so `capacity()` plateaus there. Both relay directions
    /// used to wait for `capacity() >= chunk.len()` before sending anything — which never arrives:
    /// the proxy will not send until it can send the whole chunk, and the peer will not enlarge the
    /// window until it has read something, which it cannot because nothing was sent. A cage picks
    /// its own `SETTINGS_INITIAL_WINDOW_SIZE`, so an in-cage client advertising a small one wedged
    /// the stream and held the tunnel's thread and its upstream connection with it.
    ///
    /// Driven over an in-memory duplex against a real h2 client, so what is exercised is h2's own
    /// capacity assignment rather than a model of it. The old spelling stalls rather than answering
    /// wrongly, so the timeout is the assertion.
    #[test]
    fn a_body_larger_than_the_peers_window_is_relayed_in_pieces_rather_than_deadlocking() {
        // A window well under the payload, and under h2's 16 KiB default frame size.
        const WINDOW: u32 = 1024;
        const PAYLOAD: usize = 8 * 1024;

        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let (sent, received) = rt.block_on(async {
            let (client_io, server_io) = tokio::io::duplex(64 * 1024);

            // The cage's leg: a client that advertises a small window and drains what arrives.
            // Reading is what returns window to the sender, so without it nothing can progress
            // however the send side is written — which is the point.
            let client = async {
                let (mut send, conn) = h2::client::Builder::new()
                    .initial_window_size(WINDOW)
                    .handshake::<_, Bytes>(client_io)
                    .await
                    .unwrap();
                let driver = tokio::spawn(async move {
                    let _ = conn.await;
                });
                let (response, _) = send
                    .send_request(Request::builder().body(()).unwrap(), true)
                    .unwrap();
                let mut body = response.await.unwrap().into_body();
                let mut total = 0;
                while let Some(chunk) = body.data().await {
                    let chunk = chunk.unwrap();
                    total += chunk.len();
                    let _ = body.flow_control().release_capacity(chunk.len());
                }
                driver.abort();
                total
            };

            // The proxy's leg: the function under test, handed a chunk far larger than that window.
            // The connection has to be polled *while* the send awaits capacity, or nothing is
            // written and the stall would be the harness's rather than the code's.
            let proxy = async {
                let mut conn = h2::server::handshake(server_io).await.unwrap();
                let (_req, mut respond) = conn.accept().await.unwrap().unwrap();
                let mut stream = respond
                    .send_response(http::Response::new(()), false)
                    .unwrap();
                let sent = {
                    let driver = async { while conn.accept().await.is_some() {} };
                    tokio::pin!(driver);
                    tokio::select! {
                        r = send_granted(&mut stream, Bytes::from(vec![b'x'; PAYLOAD])) => r.unwrap(),
                        () = &mut driver => panic!("the connection ended before the body was sent"),
                    }
                };
                let _ = stream.send_data(Bytes::new(), true);
                while conn.accept().await.is_some() {}
                sent
            };

            tokio::time::timeout(std::time::Duration::from_secs(30), async {
                tokio::join!(proxy, client)
            })
            .await
            .expect("the relay stalled: the send is waiting for a window the peer cannot grant")
        });

        assert_eq!(sent, PAYLOAD, "every byte of the chunk must leave");
        assert_eq!(
            received, PAYLOAD,
            "and arrive, in as many frames as the window takes"
        );
    }

    /// An SSRF refusal on the HTTP/2 path must be *accounted for* the way the HTTP/1.1 one is, not
    /// merely written into the log: the `blocked` bucket `sbx net stats` reports, and — because
    /// [`ProxyCtx::outcome`] is the one chokepoint that announces a refusal — the desktop notice
    /// too. A guard that turns a request down without counting it is the single refusal no reader
    /// of sbx can see, which is the opposite of what a guard is for.
    ///
    /// [`stream`] is driven over an in-memory duplex, so this is the real request path
    /// (`:authority` re-check → verdict → resolve → guard); only the TLS the tunnel already
    /// terminated is absent.
    #[test]
    fn an_h2_stream_the_ssrf_guard_refuses_is_counted_like_the_http1_one() {
        use crate::allowlist::{EgressPolicy, classify};
        use crate::sandbox::control::{LOG_RING_CAP, LogRing};
        use crate::sandbox::egress_stats::{Counts, EgressStats};
        use crate::testutil::TmpDir;
        use std::time::Duration;

        let dir = TmpDir::new();
        let stats = Arc::new(EgressStats::new(dir.join("stats"), "/t".into(), None));
        let log = Arc::new(LogRing::new(LOG_RING_CAP));
        let ctx = ProxyCtx::new(
            Arc::new(super::super::Ca::ephemeral().unwrap()),
            EgressPolicy::new(vec![classify("grpc.test:*").unwrap()], vec![]),
        )
        .unwrap()
        .with_stats(Arc::clone(&stats))
        .with_log(Arc::clone(&log))
        // the cloud-metadata address: refused whatever the rule, this exact-host one included
        .with_resolver(Box::new(|_| Ok(vec![IpAddr::from([169, 254, 169, 254])])));

        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let status = rt.block_on(async {
            let (client_io, server_io) = tokio::io::duplex(16 * 1024);
            // The client leg: handshake, one POST, read back whatever the proxy answers.
            let client = async {
                let (mut send, conn) = h2::client::handshake(client_io).await.unwrap();
                let driver = tokio::spawn(async move {
                    let _ = conn.await;
                });
                let req = Request::builder()
                    .method(Method::POST)
                    .uri("https://grpc.test/pkg.Svc/Method")
                    .header("content-type", "application/grpc")
                    .body(())
                    .unwrap();
                let (resp, _body) = send.send_request(req, true).unwrap();
                let status = resp.await.unwrap().status();
                driver.abort();
                status
            };
            // The proxy leg: accept the one stream, run it through the real handler, then keep
            // polling the connection so the queued refusal is actually written back. It never ends
            // on its own — the client's answer is what ends the exchange, so it is simply dropped.
            let proxy = async {
                let mut conn = h2::server::handshake(server_io).await.unwrap();
                let (req, respond) = conn.accept().await.unwrap().unwrap();
                stream(
                    req,
                    respond,
                    "grpc.test",
                    443,
                    &ctx,
                    &UpstreamPool::default(),
                )
                .await;
                while conn.accept().await.is_some() {}
            };
            // A bound so a regression that stalls the exchange fails the test instead of hanging
            // the whole suite; the real exchange is in-memory and takes microseconds.
            tokio::time::timeout(Duration::from_secs(30), async {
                tokio::select! {
                    status = client => status,
                    () = proxy => panic!("the proxy leg ended before the client had its answer"),
                }
            })
            .await
            .expect("the in-memory h2 exchange must not stall")
        });

        assert_eq!(status, StatusCode::FORBIDDEN, "the stream is refused");
        assert_eq!(
            stats
                .snapshot()
                .get("grpc.test")
                .copied()
                .unwrap_or_default(),
            Counts {
                blocked: 1,
                ..Default::default()
            },
            "an SSRF block counts in the `blocked` bucket, exactly as it does on HTTP/1.1"
        );
        let events = log.snapshot(None, None, false).events;
        assert_eq!(events.len(), 1, "one event for one decision: {events:?}");
        assert_eq!(
            (
                events[0].host.as_str(),
                events[0].verdict,
                events[0].reason.as_str()
            ),
            ("grpc.test", LogVerdict::Blocked, "ssrf-blocked")
        );
    }

    /// Drive ONE h2 stream through the real handler over an in-memory duplex and read back BOTH
    /// halves of the decision: what the client was told (the status and the `x-sbx-egress-reason`
    /// token) and what the proxy recorded (the host's stats bucket, and the log events). The
    /// resolver PANICS on purpose — a verdict is settled from the policy alone, so a refusal that
    /// reaches a name lookup is a refusal that ran too late.
    fn h2_verdict(
        policy: EgressPolicy,
        method: Method,
        uri: &str,
    ) -> (
        StatusCode,
        String,
        Counts,
        Vec<(String, LogVerdict, String)>,
    ) {
        use crate::sandbox::control::{LOG_RING_CAP, LogRing};
        use crate::sandbox::egress_stats::EgressStats;
        use crate::testutil::TmpDir;
        use std::time::Duration;

        let dir = TmpDir::new();
        let stats = Arc::new(EgressStats::new(dir.join("stats"), "/t".into(), None));
        let log = Arc::new(LogRing::new(LOG_RING_CAP));
        let ctx = ProxyCtx::new(Arc::new(super::super::Ca::ephemeral().unwrap()), policy)
            .unwrap()
            .with_stats(Arc::clone(&stats))
            .with_log(Arc::clone(&log))
            .with_resolver(Box::new(|_| {
                panic!("a verdict refusal must be decided before any name is resolved")
            }));

        let (status, reason) = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async {
                let (client_io, server_io) = tokio::io::duplex(16 * 1024);
                let client = async {
                    let (mut send, conn) = h2::client::handshake(client_io).await.unwrap();
                    let driver = tokio::spawn(async move {
                        let _ = conn.await;
                    });
                    let req = Request::builder()
                        .method(method)
                        .uri(uri)
                        .header("content-type", "application/grpc")
                        .body(())
                        .unwrap();
                    let (resp, _body) = send.send_request(req, true).unwrap();
                    let resp = resp.await.unwrap();
                    let reason = resp
                        .headers()
                        .get("x-sbx-egress-reason")
                        .and_then(|v| v.to_str().ok())
                        .unwrap_or_default()
                        .to_string();
                    let status = resp.status();
                    driver.abort();
                    (status, reason)
                };
                let proxy = async {
                    let mut conn = h2::server::handshake(server_io).await.unwrap();
                    let (req, respond) = conn.accept().await.unwrap().unwrap();
                    stream(req, respond, "grpc.test", 443, &ctx, &UpstreamPool::default()).await;
                    while conn.accept().await.is_some() {}
                };
                // The bound is also the assertion for the `ask` case: a verdict that parked would
                // block this leg forever, so a regression that starts parking fails here instead of
                // hanging the suite. The real exchange is in-memory and takes microseconds.
                tokio::time::timeout(Duration::from_secs(30), async {
                    tokio::select! {
                        answer = client => answer,
                        () = proxy => panic!("the proxy leg ended before the client had its answer"),
                    }
                })
                .await
                .expect("the in-memory h2 exchange must not stall")
            });

        let counts = stats
            .snapshot()
            .get("grpc.test")
            .copied()
            .unwrap_or_default();
        let events = log
            .snapshot(None, None, false)
            .events
            .into_iter()
            .map(|e| (e.host, e.verdict, e.reason))
            .collect();
        (status, reason, counts, events)
    }

    /// The `deny` bucket every verdict refusal on this path must land in, and the one log event it
    /// must emit. Shared by the three denial shapes below, which differ only in their reason.
    fn one_denial(reason: &str) -> (Counts, Vec<(String, LogVerdict, String)>) {
        (
            Counts {
                deny: 1,
                ..Default::default()
            },
            vec![(
                "grpc.test".to_string(),
                LogVerdict::Deny,
                reason.to_string(),
            )],
        )
    }

    /// A deny rule refuses an h2 stream as `denied-by-rule`. The policy allows by default, so
    /// nothing but the rule itself can produce this — which is what makes it the arm rather than
    /// the fallback below.
    #[test]
    fn an_h2_stream_a_deny_rule_blocks_is_told_denied_by_rule() {
        use crate::allowlist::{DefaultAction, EgressPolicy, classify};

        let (status, reason, counts, events) = h2_verdict(
            EgressPolicy::new(vec![], vec![classify("grpc.test:*").unwrap()])
                .with_default(DefaultAction::Allow),
            Method::POST,
            "https://grpc.test/pkg.Svc/Method",
        );
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(reason, "denied-by-rule");
        assert_eq!((counts, events), one_denial("denied-by-rule"));
    }

    /// A host the policy opens for reading only refuses a gRPC call — which is always a `POST` — as
    /// `denied-method`, not as a closed host. The distinction is the whole point: the agent can tell
    /// "this host, but not this verb" from "not this host at all", whichever protocol it spoke.
    #[test]
    fn an_h2_stream_outside_the_allow_set_is_told_denied_method() {
        use crate::allowlist::{EgressPolicy, classify};

        let (status, reason, counts, events) = h2_verdict(
            EgressPolicy::new(vec![classify("{GET} grpc.test:*").unwrap()], vec![]),
            Method::POST,
            "https://grpc.test/pkg.Svc/Method",
        );
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(reason, "denied-method");
        assert_eq!((counts, events), one_denial("denied-method"));
    }

    /// No rule names the host: `denied-default`, the shape `sbx net learn` reads back to synthesize
    /// a rule.
    #[test]
    fn an_h2_stream_to_an_unnamed_host_is_told_denied_default() {
        use crate::allowlist::{EgressPolicy, classify};

        let (status, reason, counts, events) = h2_verdict(
            EgressPolicy::new(vec![classify("other.test:*").unwrap()], vec![]),
            Method::POST,
            "https://grpc.test/pkg.Svc/Method",
        );
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(reason, "denied-default");
        assert_eq!((counts, events), one_denial("denied-default"));
    }

    /// The one arm this path does NOT share with the HTTP/1.1 verdict: under an `ask` posture an
    /// undecided host is refused, never parked. Every stream of an h2 connection is multiplexed on
    /// one current-thread runtime, so blocking this one for a live decision would stall its
    /// siblings. It fails closed under its own reason, so the refusal reads as the documented
    /// limitation it is rather than as an ordinary deny — and the exchange still completes, which
    /// the harness's timeout is what proves.
    #[test]
    fn an_h2_stream_under_an_ask_posture_is_refused_rather_than_parked() {
        use crate::allowlist::{DefaultAction, EgressPolicy};

        let (status, reason, counts, events) = h2_verdict(
            EgressPolicy::default().with_default(DefaultAction::Ask),
            Method::POST,
            "https://grpc.test/pkg.Svc/Method",
        );
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(reason, "http2-ask-unsupported");
        assert_eq!((counts, events), one_denial("http2-ask-unsupported"));
    }

    /// A request's trailers are held to the same strip its head passed.
    ///
    /// The head rebuild drops a connection-specific header and every name sbx injects, "so the
    /// injected value is the only one the upstream sees". Trailers were forwarded untouched, so a
    /// cage could send its own `authorization` *after* the body instead of before it and have it
    /// reach the upstream beside sbx's — and this plane exists for gRPC, where trailers are ordinary
    /// traffic. The HTTP/1.1 planes never had the hole: they de-chunk and re-frame, forwarding no
    /// trailer at all.
    #[test]
    fn a_requests_trailers_are_stripped_like_its_head() {
        let injected = vec!["Authorization".to_string(), "X-Api-Key".to_string()];
        let mut trailers = http::HeaderMap::new();
        trailers.append("grpc-status", "0".parse().unwrap());
        // The cage's own copy of a header sbx injects — the whole point of the strip.
        trailers.append("authorization", "Bearer attacker".parse().unwrap());
        // The `_`-for-`-` dodge the head closes through `header_name_eq`, closed identically here.
        trailers.append("x_api_key", "attacker".parse().unwrap());
        // A connection-specific header, which HTTP/2 forbids in a trailer as in a head.
        trailers.append("transfer-encoding", "chunked".parse().unwrap());
        // An ordinary repeated trailer: `HeaderMap`'s iterator names it once for the run, so this
        // is what a naive rebuild drops.
        trailers.append("grpc-message", "a".parse().unwrap());
        trailers.append("grpc-message", "b".parse().unwrap());

        let kept = strip_request_trailers(trailers, &injected);

        assert_eq!(kept.get("grpc-status").unwrap(), "0");
        assert!(
            kept.get("authorization").is_none(),
            "the cage's own copy of an injected header must not reach the upstream"
        );
        assert!(kept.get("x_api_key").is_none(), "nor its `_` spelling");
        assert!(kept.get("transfer-encoding").is_none());
        assert_eq!(
            kept.get_all("grpc-message")
                .iter()
                .map(|v| v.to_str().unwrap())
                .collect::<Vec<_>>(),
            vec!["a", "b"],
            "a repeated trailer keeps every value, name-once iteration notwithstanding"
        );
    }

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

    // ------------------------------------------------------------------------------------------
    // A real upstream on this plane.
    //
    // Every test above refuses *before* the upstream is opened, so none of them ever reached the
    // relay itself: the connect, the upstream TLS negotiating ALPN `h2`, the client handshake, the
    // request rebuilt from the decoded head, and the response head + DATA + trailers coming back.
    // The harness below is the first thing here to drive an h2 stream to a real HTTP/2 server, and
    // it is assembled from the same pieces the HTTP/1.1 tests use (an ephemeral CA minting a leaf
    // per SNI, a loopback listener, a resolver pinned to 127.0.0.1 — allowed only because the
    // deciding rule names the exact host).
    // ------------------------------------------------------------------------------------------

    /// Where an exchange got to, recorded from both ends.
    ///
    /// An in-memory h2 exchange either completes in microseconds or does not complete at all, and
    /// from the client leg alone "the handler was never entered", "it is stuck inside" and "the
    /// upstream never answered" are the same silence. Each milestone is bumped where it happens, so
    /// one run localizes a stall instead of leaving it to be guessed at.
    #[derive(Default)]
    struct H2Trace {
        /// the test upstream accepted a TCP connection
        upstream_tcp: std::sync::atomic::AtomicUsize,
        /// ...and finished TLS, negotiating this ALPN protocol (empty string = none) — one per connection
        upstream_alpn: std::sync::Mutex<Vec<String>>,
        /// ...and every request head it received, with the body that followed
        seen: std::sync::Mutex<Vec<SeenRequest>>,
        /// the proxy's per-stream handler started
        entered: std::sync::atomic::AtomicUsize,
        /// ...and returned
        returned: std::sync::atomic::AtomicUsize,
        /// how many PUSH_PROMISEs the test upstream got to send...
        pushes_accepted: std::sync::atomic::AtomicUsize,
        /// ...and how many its own h2 stack refused because the proxy disabled server push
        pushes_refused: std::sync::atomic::AtomicUsize,
        /// The live flow registry a test attached, and the rows it held the moment each request
        /// head reached the upstream.
        ///
        /// A flow is deregistered when its stream ends, so a row that existed only while the stream
        /// was open cannot be read after the exchange returns. The upstream receiving a head is
        /// proof the proxy had already registered — the registration sits between the allow and the
        /// forward — so this is the one deterministic window onto the live view.
        flows: std::sync::Mutex<Option<Arc<crate::sandbox::control::FlowRegistry>>>,
        flows_when_forwarded: std::sync::Mutex<Vec<crate::sandbox::control::FlowSnapshot>>,
    }

    impl H2Trace {
        /// The five-point trace, for the panic message of an exchange that did not finish.
        fn render(&self) -> String {
            use std::sync::atomic::Ordering;
            format!(
                "upstream: tcp={} alpn={:?} heads={} | proxy handler: entered={} returned={}",
                self.upstream_tcp.load(Ordering::Relaxed),
                self.upstream_alpn.lock().unwrap(),
                self.seen.lock().unwrap().len(),
                self.entered.load(Ordering::Relaxed),
                self.returned.load(Ordering::Relaxed),
            )
        }

        fn seen_one(&self) -> SeenRequest {
            let seen = self.seen.lock().unwrap();
            assert_eq!(seen.len(), 1, "one request reached the upstream: {seen:?}");
            seen[0].clone()
        }
    }

    /// One request as the test upstream received it — what the proxy actually put on the wire,
    /// which is the only trustworthy account of what it forwarded.
    #[derive(Debug, Default, Clone)]
    struct SeenRequest {
        method: String,
        /// the `:authority` pseudo-header, which `http` carries on the URI rather than in the map
        authority: String,
        path: String,
        headers: Vec<(String, String)>,
        body: Vec<u8>,
    }

    impl SeenRequest {
        fn header(&self, name: &str) -> Option<&str> {
            self.headers
                .iter()
                .find(|(n, _)| n == name)
                .map(|(_, v)| v.as_str())
        }
    }

    /// What the test upstream answers on every stream it accepts.
    #[derive(Clone)]
    struct UpstreamReply {
        /// Whether to answer at all: `false` takes the request and then drops the stream, which is
        /// how a server that dies mid-call looks from here.
        answers: bool,
        status: StatusCode,
        headers: Vec<(String, String)>,
        body: Vec<u8>,
        trailers: Vec<(String, String)>,
        /// How many PUSH_PROMISEs to offer on the stream before answering — the shape a hostile
        /// allowlisted upstream uses to make the host hold state it never asked for.
        pushes: usize,
    }

    impl UpstreamReply {
        /// The gRPC shape: a `200`, one message, and the `grpc-status` trailer that carries the
        /// call's real outcome — the response half this plane exists to relay intact.
        fn grpc(body: &str) -> Self {
            UpstreamReply {
                answers: true,
                status: StatusCode::OK,
                headers: vec![("content-type".into(), "application/grpc".into())],
                body: body.as_bytes().to_vec(),
                trailers: vec![("grpc-status".into(), "0".into())],
                pushes: 0,
            }
        }

        /// A server that takes the request and then goes away without answering.
        fn silence() -> Self {
            UpstreamReply {
                answers: false,
                ..UpstreamReply::grpc("")
            }
        }
    }

    /// What the client received back through the proxy.
    #[derive(Debug)]
    struct H2Answer {
        status: StatusCode,
        headers: Vec<(String, String)>,
        body: Vec<u8>,
        trailers: Vec<(String, String)>,
    }

    impl H2Answer {
        fn header(&self, name: &str) -> Option<&str> {
            self.headers
                .iter()
                .find(|(n, _)| n == name)
                .map(|(_, v)| v.as_str())
        }

        fn trailer(&self, name: &str) -> Option<&str> {
            self.trailers
                .iter()
                .find(|(n, _)| n == name)
                .map(|(_, v)| v.as_str())
        }

        fn text(&self) -> String {
            String::from_utf8_lossy(&self.body).into_owned()
        }
    }

    fn header_pairs(map: &http::HeaderMap) -> Vec<(String, String)> {
        map.iter()
            .map(|(n, v)| {
                (
                    n.as_str().to_string(),
                    String::from_utf8_lossy(v.as_bytes()).into_owned(),
                )
            })
            .collect()
    }

    /// The proxy's upstream config, trusting only the test upstream's CA and offering ALPN `h2`
    /// (without it the proxy fails closed on `upstream-http2-unsupported`, which is the intent).
    fn trusting_h2(
        upstream_ca: rustls::pki_types::CertificateDer<'static>,
    ) -> Arc<rustls::ClientConfig> {
        let mut roots = rustls::RootCertStore::empty();
        roots.add(upstream_ca).unwrap();
        let mut cfg = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        cfg.alpn_protocols = vec![b"h2".to_vec()];
        Arc::new(cfg)
    }

    /// A context that allows `grpc.test` on any port and trusts only the test upstream's CA.
    ///
    /// The stats and log handles come back with it because on this plane what was *recorded* is
    /// half of what a relay has to get right — a forward nothing counted is the refusal's mirror
    /// image. The [`TmpDir`](crate::testutil::TmpDir) is returned so the stats file outlives it.
    fn relaying_ctx(
        upstream_ca: rustls::pki_types::CertificateDer<'static>,
    ) -> (
        ProxyCtx,
        Arc<crate::sandbox::egress_stats::EgressStats>,
        Arc<crate::sandbox::control::LogRing>,
        crate::testutil::TmpDir,
    ) {
        use crate::allowlist::classify;
        use crate::sandbox::control::{LOG_RING_CAP, LogRing};
        use crate::sandbox::egress_stats::EgressStats;
        use crate::testutil::TmpDir;

        let dir = TmpDir::new();
        let stats = Arc::new(EgressStats::new(dir.join("stats"), "/t".into(), None));
        let log = Arc::new(LogRing::new(LOG_RING_CAP));
        let mut ctx = ProxyCtx::new(
            Arc::new(super::super::Ca::ephemeral().unwrap()),
            EgressPolicy::new(vec![classify("grpc.test:*").unwrap()], vec![]),
        )
        .unwrap()
        .with_stats(Arc::clone(&stats))
        .with_log(Arc::clone(&log))
        // loopback, permitted only because the deciding rule names this exact host
        .with_resolver(Box::new(|_| Ok(vec![IpAddr::from([127, 0, 0, 1])])));
        ctx.upstream_h2 = trusting_h2(upstream_ca);
        (ctx, stats, log, dir)
    }

    /// A gRPC request to the harness's host, carrying whatever extra headers a test needs.
    fn grpc_request(extra: &[(&str, &str)]) -> Request<()> {
        let mut req = Request::builder()
            .method(Method::POST)
            .uri("https://grpc.test/pkg.Svc/Method")
            .header("content-type", "application/grpc")
            .header("te", "trailers");
        for (name, value) in extra {
            req = req.header(*name, *value);
        }
        req.body(()).unwrap()
    }

    /// Send a body under h2 flow control, ending the stream if asked.
    ///
    /// `reserve_capacity` is a request and `poll_capacity` is the answer: what may be written is
    /// what was **granted**, never what was asked for, and writing past the grant overruns the
    /// peer's window.
    async fn send_under_flow_control(send: &mut h2::SendStream<Bytes>, mut data: Bytes, end: bool) {
        while !data.is_empty() {
            send.reserve_capacity(data.len());
            let granted = match std::future::poll_fn(|cx| send.poll_capacity(cx)).await {
                Some(Ok(n)) if n > 0 => n,
                Some(Ok(_)) => continue,
                _ => return,
            };
            let chunk = data.split_to(granted.min(data.len()));
            if send.send_data(chunk, data.is_empty() && end).is_err() {
                return;
            }
        }
    }

    /// One stream on the test upstream: record what arrived, then answer.
    async fn upstream_stream(
        req: Request<h2::RecvStream>,
        mut respond: h2::server::SendResponse<Bytes>,
        reply: UpstreamReply,
        trace: Arc<H2Trace>,
    ) {
        let (parts, mut src) = req.into_parts();
        let mut seen = SeenRequest {
            method: parts.method.to_string(),
            authority: parts
                .uri
                .authority()
                .map(|a| a.as_str().to_string())
                .unwrap_or_default(),
            path: parts
                .uri
                .path_and_query()
                .map(|p| p.as_str().to_string())
                .unwrap_or_default(),
            headers: header_pairs(&parts.headers),
            body: Vec::new(),
        };
        while let Some(chunk) = src.data().await {
            let Ok(chunk) = chunk else { break };
            seen.body.extend_from_slice(&chunk);
            let _ = src.flow_control().release_capacity(chunk.len());
        }
        trace.seen.lock().unwrap().push(seen);
        // Read the live view here and nowhere else: the proxy registers the stream's flow between
        // the allow and the forward, so a head that has arrived is a row that is up right now.
        if let Some(registry) = trace.flows.lock().unwrap().as_ref() {
            trace
                .flows_when_forwarded
                .lock()
                .unwrap()
                .extend(registry.snapshot());
        }
        // Offered before the response, as RFC 9113 §8.4 requires. A peer that disabled server push
        // makes h2 refuse this locally, which is exactly what is being asserted.
        for _ in 0..reply.pushes {
            let promised = Request::builder()
                .method(Method::GET)
                .uri("https://grpc.test/pushed")
                .body(())
                .expect("a static pushed request");
            match respond.push_request(promised) {
                Ok(_) => &trace.pushes_accepted,
                Err(_) => &trace.pushes_refused,
            }
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }

        if !reply.answers {
            // Dropping the responder resets the stream, which is what the proxy sees when a server
            // takes a call and then dies.
            return;
        }
        let mut head = Response::builder().status(reply.status);
        for (n, v) in &reply.headers {
            head = head.header(n.as_str(), v.as_str());
        }
        let ends_with_the_head = reply.body.is_empty() && reply.trailers.is_empty();
        let Ok(head) = head.body(()) else { return };
        let Ok(mut send) = respond.send_response(head, ends_with_the_head) else {
            return;
        };
        if !reply.body.is_empty() {
            let end = reply.trailers.is_empty();
            send_under_flow_control(&mut send, Bytes::from(reply.body.clone()), end).await;
        }
        if !reply.trailers.is_empty() {
            let mut trailers = http::HeaderMap::new();
            for (n, v) in &reply.trailers {
                if let (Ok(n), Ok(v)) = (
                    n.parse::<http::HeaderName>(),
                    v.parse::<http::HeaderValue>(),
                ) {
                    trailers.insert(n, v);
                }
            }
            let _ = send.send_trailers(trailers);
        }
    }

    /// One connection on the test upstream: TLS, then h2, then its streams — driven with the same
    /// select-and-drive shape [`serve`] uses, since a response is only written while the connection
    /// itself is being polled.
    async fn upstream_conn(
        sock: tokio::net::TcpStream,
        acceptor: tokio_rustls::TlsAcceptor,
        reply: UpstreamReply,
        trace: Arc<H2Trace>,
    ) {
        let Ok(tls) = acceptor.accept(sock).await else {
            return;
        };
        trace.upstream_alpn.lock().unwrap().push(
            tls.get_ref()
                .1
                .alpn_protocol()
                .map(|p| String::from_utf8_lossy(p).into_owned())
                .unwrap_or_default(),
        );
        let Ok(mut conn) = h2::server::handshake(tls).await else {
            return;
        };
        let mut inflight = FuturesUnordered::new();
        loop {
            tokio::select! {
                accepted = conn.accept() => match accepted {
                    Some(Ok((req, respond))) => inflight.push(upstream_stream(
                        req,
                        respond,
                        reply.clone(),
                        Arc::clone(&trace),
                    )),
                    _ => break,
                },
                Some(()) = inflight.next(), if !inflight.is_empty() => {}
            }
        }
        while inflight.next().await.is_some() {}
    }

    /// A loopback HTTP/2 TLS upstream serving `conns` connections — one per stream, since this
    /// plane opens a fresh upstream connection for every stream it relays.
    ///
    /// It runs on **its own OS thread with its own runtime**: the proxy's leg is a current-thread
    /// runtime, and an upstream sharing it would be one blocking call away from starving the very
    /// timers meant to bound the exchange. The thread ends on its own once the proxy's runtime is
    /// dropped and the connections close.
    fn spawn_h2_upstream(
        conns: usize,
        alpn: Vec<Vec<u8>>,
        reply: UpstreamReply,
        trace: Arc<H2Trace>,
    ) -> (
        std::net::SocketAddr,
        rustls::pki_types::CertificateDer<'static>,
    ) {
        use std::sync::atomic::Ordering;

        let ca = Arc::new(super::super::Ca::ephemeral().unwrap());
        let ca_der = ca.ca_cert_der();
        let mut cfg = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_cert_resolver(Arc::new(super::super::ca::CertResolver::new(ca)));
        cfg.alpn_protocols = alpn;
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(cfg));
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        listener.set_nonblocking(true).unwrap();
        std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            rt.block_on(async move {
                let listener = tokio::net::TcpListener::from_std(listener).unwrap();
                let mut live = Vec::new();
                for _ in 0..conns {
                    let Ok((sock, _)) = listener.accept().await else {
                        return;
                    };
                    trace.upstream_tcp.fetch_add(1, Ordering::Relaxed);
                    live.push(tokio::spawn(upstream_conn(
                        sock,
                        acceptor.clone(),
                        reply.clone(),
                        Arc::clone(&trace),
                    )));
                }
                for task in live {
                    let _ = task.await;
                }
            });
        });
        (addr, ca_der)
    }

    /// One exchange, for the tests that send a single stream.
    fn through_h2_proxy(
        ctx: &ProxyCtx,
        connect_host: &str,
        port: u16,
        request: Request<()>,
        body: Option<Vec<u8>>,
        trace: &H2Trace,
    ) -> H2Answer {
        let mut answers =
            through_h2_proxy_streams(ctx, connect_host, port, vec![(request, body)], trace);
        answers.remove(0)
    }

    /// Several streams over **one** tunnel, answered in order — the shape a multiplexing client
    /// actually has, and the only way to see what the tunnel's upstream pool does.
    ///
    /// Both legs run through the real handler and on to whatever upstream `ctx` points at: the
    /// client leg over an in-memory duplex, the proxy leg driven exactly as [`serve`] drives it.
    ///
    /// Awaiting a stream without polling the connection is the deadlock this shape exists to avoid:
    /// a queued response is only written while the connection is being polled, so the accept loop
    /// and the in-flight streams have to advance together.
    fn through_h2_proxy_streams(
        ctx: &ProxyCtx,
        connect_host: &str,
        port: u16,
        requests: Vec<(Request<()>, Option<Vec<u8>>)>,
        trace: &H2Trace,
    ) -> Vec<H2Answer> {
        use std::sync::atomic::Ordering;
        use std::time::Duration;

        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            // Wide enough that the duplex is never the bottleneck: what is being exercised is the
            // proxy, not a buffer between two halves of the same test.
            let (client_io, server_io) = tokio::io::duplex(1024 * 1024);
            let client = async {
                let (mut send, conn) = h2::client::handshake(client_io).await.unwrap();
                let driver = tokio::spawn(async move {
                    let _ = conn.await;
                });
                let mut answers = Vec::new();
                for (request, body) in requests {
                    let (resp_fut, mut send_body) =
                        send.send_request(request, body.is_none()).unwrap();
                    if let Some(b) = body {
                        send_under_flow_control(&mut send_body, Bytes::from(b), true).await;
                    }
                    let (parts, mut recv) = resp_fut.await.unwrap().into_parts();
                    let mut data = Vec::new();
                    while let Some(chunk) = recv.data().await {
                        let chunk = chunk.unwrap();
                        data.extend_from_slice(&chunk);
                        // Return the window as it is consumed, or a response larger than the
                        // initial one stalls halfway through.
                        let _ = recv.flow_control().release_capacity(chunk.len());
                    }
                    let trailers = recv.trailers().await.unwrap();
                    answers.push(H2Answer {
                        status: parts.status,
                        headers: header_pairs(&parts.headers),
                        body: data,
                        trailers: trailers.as_ref().map(header_pairs).unwrap_or_default(),
                    });
                }
                driver.abort();
                answers
            };
            let proxy = async {
                let mut conn = h2::server::handshake(server_io).await.unwrap();
                // One pool per tunnel, exactly as `serve` holds it.
                let pool = UpstreamPool::default();
                let mut inflight = FuturesUnordered::new();
                loop {
                    tokio::select! {
                        accepted = conn.accept() => match accepted {
                            Some(Ok((req, respond))) => inflight.push(async {
                                trace.entered.fetch_add(1, Ordering::Relaxed);
                                stream(req, respond, connect_host, port, ctx, &pool).await;
                                trace.returned.fetch_add(1, Ordering::Relaxed);
                            }),
                            _ => break,
                        },
                        Some(()) = inflight.next(), if !inflight.is_empty() => {}
                    }
                }
                while inflight.next().await.is_some() {}
            };
            // A bound so a regression that stalls the exchange fails here instead of hanging the
            // suite; the trace says where it got to.
            tokio::time::timeout(Duration::from_secs(20), async {
                tokio::select! {
                    answer = client => answer,
                    () = proxy => panic!(
                        "the proxy leg ended before the client had its answer — {}",
                        trace.render()
                    ),
                }
            })
            .await
            .unwrap_or_else(|_| panic!("the h2 exchange stalled — {}", trace.render()))
        })
    }

    /// The third plane's share of the observed-credential scan set. A gRPC client that authenticates
    /// with a token of its own teaches sbx that token here, exactly as the two HTTP/1.1 planes do,
    /// and the set is shared — so a plane that never observed would be a hole in all three rather
    /// than in one.
    #[test]
    fn a_grpc_client_s_own_credential_joins_the_shared_scan_set() {
        let trace = Arc::new(H2Trace::default());
        let (addr, upstream_ca) = spawn_h2_upstream(
            2,
            vec![b"h2".to_vec()],
            UpstreamReply::grpc("PONG"),
            Arc::clone(&trace),
        );
        let (ctx, _stats, _log, _dir) = relaying_ctx(upstream_ca);
        let credentials = ctx.credentials.clone();
        let answers = through_h2_proxy_streams(
            &ctx,
            "grpc.test",
            addr.port(),
            vec![(
                grpc_request(&[("authorization", "Bearer grpc-acquired-by-the-client")]),
                None,
            )],
            &trace,
        );
        assert!(
            answers.iter().all(|a| a.status == StatusCode::OK),
            "the request that teaches the value is not itself refused: {}",
            trace.render()
        );
        let set = credentials.snapshot();
        assert!(
            set.needles
                .iter()
                .any(|n| n.as_bytes() == b"grpc-acquired-by-the-client"),
            "the credential the cage sent must join the scan set"
        );
    }

    /// Two streams of one tunnel that receive the same credential share one upstream connection;
    /// two that receive different ones do not.
    ///
    /// The first half is the point of the pool: HTTP/2 multiplexes, so a client that opens one
    /// tunnel and many streams was paying a TCP connection, a TLS handshake and an h2 handshake for
    /// every one of them.
    ///
    /// **The second half is the reason the pool is keyed the way it is**, and it is the half worth
    /// breaking the test over: a connection that carried a credential must never be offered to a
    /// stream that does not receive the same one. Everything else a stream is checked for happens
    /// before the pool is consulted at all, per stream, so reuse cannot skip it: the `:authority`
    /// re-check, the outbound tripwire, the verdict, the resolution and the address guard.
    #[test]
    fn streams_share_an_upstream_only_with_the_credential_set_they_share() {
        use crate::allowlist::classify;
        use crate::sandbox::proxy::HeaderInjection;
        use std::sync::atomic::Ordering;

        let plain = || {
            Request::builder()
                .method(Method::POST)
                .uri("https://grpc.test/pkg.Svc/Method")
                .header("content-type", "application/grpc")
                .body(())
                .unwrap()
        };
        let scoped = || {
            Request::builder()
                .method(Method::POST)
                .uri("https://grpc.test/pkg.Svc/Secret")
                .header("content-type", "application/grpc")
                .body(())
                .unwrap()
        };

        // Same credential set (neither stream matches the injection): one connection for both.
        let trace = Arc::new(H2Trace::default());
        let (addr, upstream_ca) = spawn_h2_upstream(
            4,
            vec![b"h2".to_vec()],
            UpstreamReply::grpc("PONG"),
            Arc::clone(&trace),
        );
        let (ctx, _stats, _log, _dir) = relaying_ctx(upstream_ca);
        let ctx = ctx.with_injections(vec![HeaderInjection::fixed(
            classify("grpc.test:*/pkg.Svc/Secret").unwrap(),
            "authorization".to_string(),
            "Bearer sbx-issued".to_string(),
        )]);
        let answers = through_h2_proxy_streams(
            &ctx,
            "grpc.test",
            addr.port(),
            vec![(plain(), None), (plain(), None)],
            &trace,
        );
        assert!(answers.iter().all(|a| a.status == StatusCode::OK));
        assert_eq!(
            trace.upstream_tcp.load(Ordering::Relaxed),
            1,
            "two streams receiving the same credentials ride one connection: {}",
            trace.render()
        );

        // Different credential sets: the injected stream must not ride the other's connection.
        let trace = Arc::new(H2Trace::default());
        let (addr, upstream_ca) = spawn_h2_upstream(
            4,
            vec![b"h2".to_vec()],
            UpstreamReply::grpc("PONG"),
            Arc::clone(&trace),
        );
        let (ctx, _stats, _log, _dir) = relaying_ctx(upstream_ca);
        let ctx = ctx.with_injections(vec![HeaderInjection::fixed(
            classify("grpc.test:*/pkg.Svc/Secret").unwrap(),
            "authorization".to_string(),
            "Bearer sbx-issued".to_string(),
        )]);
        let answers = through_h2_proxy_streams(
            &ctx,
            "grpc.test",
            addr.port(),
            vec![(plain(), None), (scoped(), None)],
            &trace,
        );
        assert!(answers.iter().all(|a| a.status == StatusCode::OK));
        assert_eq!(
            trace.upstream_tcp.load(Ordering::Relaxed),
            2,
            "a stream carrying a credential opens its own: {}",
            trace.render()
        );
        let seen = trace.seen.lock().unwrap();
        assert_eq!(seen.len(), 2);
        let credentialed: Vec<&SeenRequest> = seen
            .iter()
            .filter(|r| r.header("authorization").is_some())
            .collect();
        assert_eq!(
            credentialed.len(),
            1,
            "exactly one of the two carried the credential: {seen:?}"
        );
        assert_eq!(credentialed[0].path, "/pkg.Svc/Secret");
        drop(seen);

        // ...and `[network] pool = false` means what it says here too: no reuse, one connection per
        // stream, exactly as before the pool existed.
        let trace = Arc::new(H2Trace::default());
        let (addr, upstream_ca) = spawn_h2_upstream(
            4,
            vec![b"h2".to_vec()],
            UpstreamReply::grpc("PONG"),
            Arc::clone(&trace),
        );
        let dir = crate::testutil::TmpDir::new();
        let mut ctx = ProxyCtx::new(
            Arc::new(super::super::Ca::ephemeral().unwrap()),
            EgressPolicy::new(vec![classify("grpc.test:*").unwrap()], vec![]).with_pool(false),
        )
        .unwrap()
        .with_resolver(Box::new(|_| Ok(vec![IpAddr::from([127, 0, 0, 1])])));
        ctx.upstream_h2 = trusting_h2(upstream_ca);
        let _keep = dir;
        let answers = through_h2_proxy_streams(
            &ctx,
            "grpc.test",
            addr.port(),
            vec![(plain(), None), (plain(), None)],
            &trace,
        );
        assert!(answers.iter().all(|a| a.status == StatusCode::OK));
        assert_eq!(
            trace.upstream_tcp.load(Ordering::Relaxed),
            2,
            "a launch that asked for no reuse gets none: {}",
            trace.render()
        );
    }

    /// A connection the upstream binds an identity to stops being shared.
    ///
    /// `NTLM` and `Negotiate` authenticate the *connection*, not the request, so a later stream
    /// riding it would inherit an identity it never asked for and cannot see. The HTTP/1.1 pool
    /// refuses to park such a connection; this one stops offering it. The streams already on it are
    /// not recalled, which is inherent to multiplexing.
    #[test]
    fn a_connection_the_upstream_binds_an_identity_to_stops_being_shared() {
        use std::sync::atomic::Ordering;

        let trace = Arc::new(H2Trace::default());
        let (addr, upstream_ca) = spawn_h2_upstream(
            4,
            vec![b"h2".to_vec()],
            UpstreamReply {
                answers: true,
                status: StatusCode::UNAUTHORIZED,
                headers: vec![("www-authenticate".into(), "Negotiate".into())],
                body: Vec::new(),
                trailers: Vec::new(),
                pushes: 0,
            },
            Arc::clone(&trace),
        );
        let (ctx, _stats, _log, _dir) = relaying_ctx(upstream_ca);
        let answers = through_h2_proxy_streams(
            &ctx,
            "grpc.test",
            addr.port(),
            vec![(grpc_request(&[]), None), (grpc_request(&[]), None)],
            &trace,
        );
        assert!(answers.iter().all(|a| a.status == StatusCode::UNAUTHORIZED));
        assert_eq!(
            trace.upstream_tcp.load(Ordering::Relaxed),
            2,
            "the second stream must not ride the connection the challenge was bound to: {}",
            trace.render()
        );
    }

    /// The happy path this plane never had: an allowed gRPC stream is relayed to a real HTTP/2
    /// upstream and its whole answer comes back — head, message, and the `grpc-status` trailer that
    /// carries the call's actual result. Everything else here refuses before the connect, so this
    /// is the only test that exercises the relay: the upstream TLS with ALPN `h2`, the request
    /// rebuilt from the decoded head, and both body directions under flow control.
    #[test]
    fn an_allowed_h2_stream_is_relayed_to_a_real_upstream_and_the_whole_answer_returns() {
        use crate::sandbox::control::{HttpVer, LogVerdict, RpcKind};
        use std::sync::atomic::Ordering;

        let trace = Arc::new(H2Trace::default());
        let (addr, upstream_ca) = spawn_h2_upstream(
            1,
            vec![b"h2".to_vec()],
            UpstreamReply::grpc("PONG"),
            Arc::clone(&trace),
        );
        let (ctx, stats, log, _dir) = relaying_ctx(upstream_ca);

        let answer = through_h2_proxy(
            &ctx,
            "grpc.test",
            addr.port(),
            grpc_request(&[]),
            Some(b"PING".to_vec()),
            &trace,
        );

        assert_eq!(answer.status, StatusCode::OK);
        assert_eq!(answer.header("content-type"), Some("application/grpc"));
        assert_eq!(answer.text(), "PONG", "the response message crossed back");
        assert_eq!(
            answer.trailer("grpc-status"),
            Some("0"),
            "the trailer carrying the RPC's outcome crossed back: {answer:?}"
        );

        // What the upstream actually received, which is the only trustworthy account of what was
        // forwarded: the request half, rebuilt from the decoded head and still bound to its host.
        let seen = trace.seen_one();
        assert_eq!(seen.method, "POST");
        assert_eq!(seen.path, "/pkg.Svc/Method");
        assert_eq!(seen.authority, "grpc.test");
        assert_eq!(seen.header("content-type"), Some("application/grpc"));
        assert_eq!(seen.header("te"), Some("trailers"));
        assert_eq!(seen.body, b"PING", "the request body crossed too");

        assert_eq!(
            *trace.upstream_alpn.lock().unwrap(),
            vec!["h2".to_string()],
            "the upstream leg is HTTP/2 end to end, never downgraded"
        );
        assert_eq!(
            (
                trace.entered.load(Ordering::Relaxed),
                trace.returned.load(Ordering::Relaxed)
            ),
            (1, 1),
            "one stream, entered and returned"
        );

        // The allow is recorded only once the upstream is connected, and the response status is
        // amended onto that same event when the head returns.
        assert_eq!(stats.snapshot()["grpc.test"].allow, 1);
        let events = log.snapshot(None, None, false).events;
        assert_eq!(
            events.len(),
            1,
            "one event for one relayed stream: {events:?}"
        );
        assert_eq!(events[0].verdict, LogVerdict::Allow);
        assert_eq!(events[0].reason, "allowed");
        assert_eq!(events[0].method.as_deref(), Some("POST"));
        assert_eq!(events[0].path.as_deref(), Some("/pkg.Svc/Method"));
        assert_eq!(events[0].http_ver, HttpVer::H2);
        assert_eq!(events[0].rpc, RpcKind::Grpc);
        assert_eq!(events[0].status, Some(200));
    }

    /// Credential injection is **strip-and-replace** here too, and now proved from the upstream's
    /// own account of what arrived rather than from the proxy's account of what it sent. The client
    /// carries its own `authorization`; exactly one reaches the upstream and it is sbx's, so a
    /// process in the cage cannot smuggle a header of its own past the credential it never held.
    #[test]
    fn an_injected_credential_replaces_the_clients_own_copy_on_the_h2_plane() {
        use crate::allowlist::classify;
        use crate::sandbox::proxy::HeaderInjection;

        let trace = Arc::new(H2Trace::default());
        let (addr, upstream_ca) = spawn_h2_upstream(
            1,
            vec![b"h2".to_vec()],
            UpstreamReply::grpc("PONG"),
            Arc::clone(&trace),
        );
        let (ctx, _stats, _log, _dir) = relaying_ctx(upstream_ca);
        let ctx = ctx.with_injections(vec![HeaderInjection::fixed(
            classify("grpc.test:*").unwrap(),
            "authorization".to_string(),
            "Bearer sbx-issued".to_string(),
        )]);

        let answer = through_h2_proxy(
            &ctx,
            "grpc.test",
            addr.port(),
            grpc_request(&[("authorization", "Bearer client-own")]),
            None,
            &trace,
        );
        assert_eq!(answer.status, StatusCode::OK, "the stream was relayed");

        let seen = trace.seen_one();
        let authorizations: Vec<&(String, String)> = seen
            .headers
            .iter()
            .filter(|(n, _)| n == "authorization")
            .collect();
        assert_eq!(
            authorizations.len(),
            1,
            "exactly one authorization reaches the upstream: {seen:?}"
        );
        assert_eq!(
            authorizations[0].1, "Bearer sbx-issued",
            "sbx's value is the one that crossed"
        );
        assert!(
            !seen.headers.iter().any(|(_, v)| v.contains("client-own")),
            "no copy of the client's value survives anywhere: {seen:?}"
        );
        assert_eq!(
            seen.header("content-type"),
            Some("application/grpc"),
            "the client's other headers are carried through untouched"
        );
    }

    /// A `401` from an injection target re-resolves the credential on this plane too.
    ///
    /// Both HTTP/1.1 planes have done this since the refresher existed, beside their own
    /// `set_status`. This one recorded the status and stopped there, so a token that went stale
    /// mid-session stayed stale for every later h2 stream while the very same credential refreshed
    /// on the other two. The refused stream itself is already lost — its head reached the cage
    /// before the status was read — so what is asserted is the credential state, which is what the
    /// *next* stream would carry.
    ///
    /// The two negative arms are what keep the gate from being satisfied by refreshing on
    /// everything: a `200` says nothing about the credential, and a `401` from a host sbx injects
    /// nothing into must never let an in-cage agent spend a resolver run.
    #[test]
    fn a_401_from_an_injection_target_re_resolves_the_credential_on_the_h2_plane() {
        use crate::allowlist::classify;
        use crate::sandbox::proxy::{CredentialRefresh, Credentials, HeaderInjection};
        use std::sync::atomic::{AtomicUsize, Ordering};

        // One exchange against an upstream answering `status`, with a refresher wired and a fixed
        // `authorization` injection scoped to `inject_host`. Reports how often the resolver ran and
        // what the credential holds afterwards.
        fn run(status: StatusCode, inject_host: &str) -> (usize, String) {
            let trace = Arc::new(H2Trace::default());
            let (addr, upstream_ca) = spawn_h2_upstream(
                1,
                vec![b"h2".to_vec()],
                UpstreamReply {
                    status,
                    ..UpstreamReply::grpc("")
                },
                Arc::clone(&trace),
            );
            let credentials = Arc::new(Credentials::new(
                vec![HeaderInjection::fixed(
                    classify(inject_host).unwrap(),
                    "authorization".to_string(),
                    "Bearer stale".to_string(),
                )],
                Vec::new(),
                crate::sandbox::redact::MIN_LEN_DEFAULT,
            ));
            let calls = Arc::new(AtomicUsize::new(0));
            let seen = Arc::clone(&calls);
            let scope = inject_host.to_string();
            let refresh = Arc::new(CredentialRefresh::new(
                Arc::clone(&credentials),
                Box::new(move |_| {
                    seen.fetch_add(1, Ordering::SeqCst);
                    Ok((
                        vec![HeaderInjection::fixed(
                            classify(&scope).unwrap(),
                            "authorization".to_string(),
                            "Bearer refreshed".to_string(),
                        )],
                        Vec::new(),
                    ))
                }),
            ));
            let (ctx, _stats, _log, _dir) = relaying_ctx(upstream_ca);
            let ctx = ctx
                .with_shared_credentials(Arc::clone(&credentials))
                .with_refresh(refresh);

            let answer = through_h2_proxy(
                &ctx,
                "grpc.test",
                addr.port(),
                grpc_request(&[]),
                None,
                &trace,
            );
            assert_eq!(
                answer.status, status,
                "the upstream's own status reached the cage"
            );
            let value = credentials.snapshot().injections[0].value().to_string();
            (calls.load(Ordering::SeqCst), value)
        }

        assert_eq!(
            run(StatusCode::UNAUTHORIZED, "grpc.test:*"),
            (1, "Bearer refreshed".to_string()),
            "a 401 from the injection target must re-resolve exactly once"
        );
        assert_eq!(
            run(StatusCode::OK, "grpc.test:*"),
            (0, "Bearer stale".to_string()),
            "a successful response is not a signal about the credential"
        );
        assert_eq!(
            run(StatusCode::UNAUTHORIZED, "other.test:*"),
            (0, "Bearer stale".to_string()),
            "a 401 from a host sbx injects nothing into must not reach the resolver"
        );
    }

    /// The strip has to cover the *spellings* of the injected header, not just its name, and this
    /// plane did not: it compared names case-insensitively where the other three fold `_` onto `-`
    /// as well. HTTP/2 names are lowercase already, so case was never what that rule was for —
    /// `_` was. A server that folds `x_api_key` onto `x-api-key`, which is why the rule exists at
    /// all, received the caller's spelling sitting beside sbx's.
    ///
    /// Read from what the upstream got: two headers arrived, one of them the caller's.
    #[test]
    fn an_alternate_spelling_of_the_injected_header_is_stripped_like_the_plain_one() {
        use crate::allowlist::classify;
        use crate::sandbox::proxy::HeaderInjection;

        let trace = Arc::new(H2Trace::default());
        let (addr, upstream_ca) = spawn_h2_upstream(
            1,
            vec![b"h2".to_vec()],
            UpstreamReply::grpc("PONG"),
            Arc::clone(&trace),
        );
        let (ctx, _stats, _log, _dir) = relaying_ctx(upstream_ca);
        let ctx = ctx.with_injections(vec![HeaderInjection::fixed(
            classify("grpc.test:*").unwrap(),
            "x-api-key".to_string(),
            "sbx-issued".to_string(),
        )]);

        let answer = through_h2_proxy(
            &ctx,
            "grpc.test",
            addr.port(),
            grpc_request(&[
                ("x-api-key", "client-plain"),
                ("x_api_key", "client-underscored"),
            ]),
            None,
            &trace,
        );
        assert_eq!(answer.status, StatusCode::OK, "the stream was relayed");

        let seen = trace.seen_one();
        let credentials: Vec<&(String, String)> = seen
            .headers
            .iter()
            .filter(|(n, _)| n == "x-api-key" || n == "x_api_key")
            .collect();
        assert_eq!(
            credentials.len(),
            1,
            "one credential header reaches the upstream, whatever the caller spelled: {seen:?}"
        );
        assert_eq!(
            (credentials[0].0.as_str(), credentials[0].1.as_str()),
            ("x-api-key", "sbx-issued")
        );
        assert!(
            !seen.headers.iter().any(|(_, v)| v.starts_with("client-")),
            "neither spelling's value survives: {seen:?}"
        );
    }

    /// The response-side leak backstop, end to end at last: a host an injection targets reflects the
    /// credential back in a header, in the DATA, and in a trailer, and all three reach the cage
    /// masked. Until this harness existed only the header-masking helper could be exercised, in
    /// isolation; the three sinks are separate code paths, and a response body is masked frame by
    /// frame as it streams.
    #[test]
    fn a_secret_reflected_in_a_header_body_or_trailer_is_masked_before_it_re_enters_the_cage() {
        use crate::allowlist::classify;
        use crate::sandbox::proxy::HeaderInjection;

        let trace = Arc::new(H2Trace::default());
        let (addr, upstream_ca) = spawn_h2_upstream(
            1,
            vec![b"h2".to_vec()],
            UpstreamReply {
                answers: true,
                status: StatusCode::OK,
                headers: vec![
                    ("content-type".into(), "application/grpc".into()),
                    ("x-echo".into(), "before-topsecret-after".into()),
                    ("x-clean".into(), "nothing to see".into()),
                ],
                body: b"msg:topsecret;".to_vec(),
                trailers: vec![
                    ("grpc-status".into(), "0".into()),
                    ("x-echoed".into(), "topsecret".into()),
                ],
                pushes: 0,
            },
            Arc::clone(&trace),
        );
        let (ctx, _stats, _log, _dir) = relaying_ctx(upstream_ca);
        let ctx = ctx
            .with_injections(vec![HeaderInjection::fixed(
                classify("grpc.test:*").unwrap(),
                "authorization".to_string(),
                "Bearer topsecret".to_string(),
            )])
            .with_redactions(vec![SecretNeedle::named(
                "test-secret",
                b"topsecret".to_vec(),
            )]);

        let answer = through_h2_proxy(
            &ctx,
            "grpc.test",
            addr.port(),
            grpc_request(&[]),
            None,
            &trace,
        );

        assert_eq!(answer.status, StatusCode::OK);
        // Masked in place and at equal length, so every byte count the caller sees stays true.
        assert_eq!(answer.header("x-echo"), Some("before-*********-after"));
        assert_eq!(answer.text(), "msg:*********;");
        assert_eq!(answer.trailer("x-echoed"), Some("*********"));
        // ...and only the secret: the rest of the response is untouched.
        assert_eq!(answer.header("x-clean"), Some("nothing to see"));
        assert_eq!(answer.trailer("grpc-status"), Some("0"));
        // The upstream did receive the real credential — the masking is on the way back, not a
        // failure to inject.
        assert_eq!(
            trace.seen_one().header("authorization"),
            Some("Bearer topsecret")
        );
    }

    /// One stream whose upstream cannot be opened, driven for real: what the client was told (status
    /// and reason token) and what was recorded (the log events, and the allow count). `alpn` is what
    /// the test upstream offers, `trusted` whether the proxy trusts the CA that signed it, and
    /// `listening` whether anything is behind the port at all.
    fn refused_upstream(
        alpn: Vec<Vec<u8>>,
        trusted: bool,
        listening: bool,
    ) -> (
        StatusCode,
        String,
        Vec<(crate::sandbox::control::LogVerdict, String)>,
        u64,
        Arc<H2Trace>,
    ) {
        let trace = Arc::new(H2Trace::default());
        let (port, upstream_ca) = match listening {
            true => {
                let (addr, ca) =
                    spawn_h2_upstream(1, alpn, UpstreamReply::grpc("PONG"), Arc::clone(&trace));
                (addr.port(), ca)
            }
            // A port held only long enough to be sure nothing is behind it once released.
            false => {
                let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
                let port = listener.local_addr().unwrap().port();
                (port, super::super::Ca::ephemeral().unwrap().ca_cert_der())
            }
        };
        let trusted_ca = match trusted {
            true => upstream_ca,
            // A different CA entirely: the upstream's certificate is real, just not one this
            // proxy has any reason to accept.
            false => super::super::Ca::ephemeral().unwrap().ca_cert_der(),
        };
        let (ctx, stats, log, _dir) = relaying_ctx(trusted_ca);

        let answer = through_h2_proxy(&ctx, "grpc.test", port, grpc_request(&[]), None, &trace);
        let events = log
            .snapshot(None, None, false)
            .events
            .into_iter()
            .map(|e| (e.verdict, e.reason))
            .collect();
        let allow = stats
            .snapshot()
            .get("grpc.test")
            .copied()
            .unwrap_or_default()
            .allow;
        (
            answer.status,
            answer
                .header("x-sbx-egress-reason")
                .unwrap_or_default()
                .to_string(),
            events,
            allow,
            trace,
        )
    }

    /// A stream that policy allowed but that never reached its host must leave a trace. It used to
    /// leave none: the allow is recorded only once the upstream is up, and these refusals answered
    /// the client without logging, so the one thing a reader could look for was absent. Each of the
    /// four failures now surfaces exactly once, as an `error` carrying its own reason.
    ///
    /// The two HTTP/2 ones are the reason this matters beyond bookkeeping. A peer that will not
    /// speak `h2` is a working, correctly certified server that simply does not do gRPC, and it can
    /// say so in two places — by refusing the ALPN outright (a `no_application_protocol` alert
    /// during the handshake) or by ignoring ALPN and negotiating nothing. Both are the same fact
    /// about the upstream, and both now say so; reporting the first as a rejected certificate, as it
    /// once did, pointed the reader at the one thing that was not wrong.
    #[test]
    fn each_way_an_h2_upstream_can_fail_to_open_is_answered_and_recorded_as_itself() {
        use crate::sandbox::control::LogVerdict;
        use std::sync::atomic::Ordering;

        for (case, alpn, trusted, listening, expected, reached_tcp) in [
            (
                "nothing is listening",
                vec![b"h2".to_vec()],
                true,
                false,
                "upstream-unreachable",
                0,
            ),
            (
                "the certificate is not one this proxy trusts",
                vec![b"h2".to_vec()],
                false,
                true,
                "upstream-cert-rejected",
                1,
            ),
            (
                "the upstream refuses the ALPN offer",
                vec![b"http/1.1".to_vec()],
                true,
                true,
                "upstream-http2-unsupported",
                1,
            ),
            (
                "the upstream ignores ALPN and negotiates nothing",
                vec![],
                true,
                true,
                "upstream-http2-unsupported",
                1,
            ),
        ] {
            let (status, reason, events, allow, trace) = refused_upstream(alpn, trusted, listening);
            assert_eq!(status, StatusCode::BAD_GATEWAY, "{case}");
            assert_eq!(reason, expected, "what the client is told when {case}");
            assert_eq!(
                events,
                vec![(LogVerdict::Error, expected.to_string())],
                "one error line, carrying the same reason, when {case}"
            );
            assert_eq!(
                allow, 0,
                "a stream that never reached its host is not an allow ({case})"
            );
            // The reason token alone would still read right if the failure happened somewhere else
            // entirely, so pin where each case actually got to.
            assert_eq!(
                (
                    trace.upstream_tcp.load(Ordering::Relaxed),
                    trace.entered.load(Ordering::Relaxed),
                    trace.returned.load(Ordering::Relaxed),
                ),
                (reached_tcp, 1, 1),
                "where the exchange reached when {case} — {}",
                trace.render()
            );
        }
    }

    /// The other side of the same coin: an upstream that is reached, takes the call, and then goes
    /// away without answering. The allow is already recorded by then, so this stream reads as an
    /// allow whose status never arrived with an `upstream-closed` beside it — the shape the HTTP/1.1
    /// path leaves for the same event, and the reason that keeps "reached and then lost" apart from
    /// "never reached". It answered `upstream-unreachable` until now, which said the connection was
    /// never made when it plainly had been.
    #[test]
    fn an_upstream_that_takes_the_call_and_goes_away_is_reported_as_closed_not_unreachable() {
        use crate::sandbox::control::LogVerdict;

        let trace = Arc::new(H2Trace::default());
        let (addr, upstream_ca) = spawn_h2_upstream(
            1,
            vec![b"h2".to_vec()],
            UpstreamReply::silence(),
            Arc::clone(&trace),
        );
        let (ctx, stats, log, _dir) = relaying_ctx(upstream_ca);

        let answer = through_h2_proxy(
            &ctx,
            "grpc.test",
            addr.port(),
            grpc_request(&[]),
            None,
            &trace,
        );
        assert_eq!(answer.status, StatusCode::BAD_GATEWAY);
        assert_eq!(
            answer.header("x-sbx-egress-reason"),
            Some("upstream-closed")
        );
        assert_eq!(
            trace.seen.lock().unwrap().len(),
            1,
            "the request did reach the upstream: {}",
            trace.render()
        );

        // The allow stands, because the request was forwarded; what never came is its status.
        assert_eq!(stats.snapshot()["grpc.test"].allow, 1);
        let events: Vec<(LogVerdict, String, Option<u16>)> = log
            .snapshot(None, None, false)
            .events
            .into_iter()
            .map(|e| (e.verdict, e.reason, e.status))
            .collect();
        assert_eq!(
            events,
            vec![
                (LogVerdict::Allow, "allowed".to_string(), None),
                (LogVerdict::Error, "upstream-closed".to_string(), None),
            ]
        );
    }

    /// The upstream leg refuses server push, so an allowlisted host cannot make the supervisor hold
    /// state it never asked for.
    ///
    /// h2 sends no `SETTINGS_ENABLE_PUSH` of its own and its default is on, so this leg advertised
    /// push enabled with no concurrency budget beside it. Nothing here drains
    /// `ResponseFuture::push_promises`, so every PUSH_PROMISE a compromised (or attacker-owned,
    /// wildcard-matched) gRPC host emitted on a long-lived server-streaming call reserved a stream
    /// and retained its decoded head — up to the whole 64 KiB `MAX_HEADER_LIST`, from a handful of
    /// HPACK indexed bytes on the wire — for the life of the tunnel. It grows in the sbx supervisor,
    /// which holds the CA key and every other connection's state and sits outside the cage's cgroup.
    ///
    /// Asserted from the upstream's own h2 stack: it is the peer's SETTINGS that decides whether a
    /// push may be sent at all, so a refusal there is proof the proxy advertised the setting.
    #[test]
    fn the_upstream_leg_refuses_a_server_push_it_would_otherwise_have_to_hold() {
        use std::sync::atomic::Ordering;

        let trace = Arc::new(H2Trace::default());
        let (addr, upstream_ca) = spawn_h2_upstream(
            1,
            vec![b"h2".to_vec()],
            UpstreamReply {
                pushes: 3,
                ..UpstreamReply::grpc("PONG")
            },
            Arc::clone(&trace),
        );
        let (ctx, _stats, _log, _dir) = relaying_ctx(upstream_ca);

        let answer = through_h2_proxy(
            &ctx,
            "grpc.test",
            addr.port(),
            grpc_request(&[]),
            None,
            &trace,
        );

        assert_eq!(
            answer.status,
            StatusCode::OK,
            "the ordinary answer still crosses: {}",
            trace.render()
        );
        assert_eq!(
            (
                trace.pushes_accepted.load(Ordering::Relaxed),
                trace.pushes_refused.load(Ordering::Relaxed),
            ),
            (0, 3),
            "every push the upstream offered must be refused before it reaches the host"
        );
    }

    /// An established h2 tunnel carrying **no stream** is let go on the launch's idle bound.
    ///
    /// `serve` retires the per-socket timeouts when it hands the stream to tokio, and bounds only
    /// the TLS accept and the h2 handshake after that. The no-overall-deadline choice documented
    /// beside them is about a *stream* that may legitimately be long-lived; it says nothing about a
    /// connection with nothing on it, and that state had no bound at all where the HTTP/1.1 tunnel
    /// bounds the gap between two requests with the same `ctx.idle`. A cage could complete
    /// `max_connections` tunnels, send nothing further, and pin every host handler thread — with
    /// `ctx.conns` stuck at its ceiling, so ordinary egress to every other allowed host was answered
    /// `503 connection-cap` with no timeout that could ever recover it.
    ///
    /// The bound is the assertion: with none, the accept loop never returns and the join below
    /// elapses.
    #[test]
    fn an_h2_tunnel_carrying_no_stream_is_let_go_on_the_idle_bound() {
        use crate::allowlist::classify;
        use std::time::Duration;

        let ctx = ProxyCtx::new(
            Arc::new(super::super::Ca::ephemeral().unwrap()),
            EgressPolicy::new(vec![classify("grpc.test:*").unwrap()], vec![])
                .with_idle_timeout(Some(Duration::from_millis(200))),
        )
        .unwrap();

        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async {
                let (client_io, server_io) = tokio::io::duplex(16 * 1024);
                // The cage's leg: complete the preface, then send nothing ever again. The request
                // handle is held for the whole exchange, so nothing closes this side — which is the
                // whole point: the connection is alive, idle, and abandoned.
                let client = async {
                    let (keep_open, conn) = h2::client::handshake(client_io).await.unwrap();
                    let _ = conn.await;
                    drop(keep_open);
                };
                let proxy = async {
                    let mut conn = h2::server::handshake(server_io).await.unwrap();
                    accept_streams(&mut conn, "grpc.test", 443, &ctx, &UpstreamPool::default())
                        .await;
                };
                tokio::time::timeout(Duration::from_secs(10), async {
                    tokio::join!(proxy, client)
                })
                .await
                .expect(
                    "an h2 tunnel carrying no stream must be let go on the idle bound; held, it \
                     pins its host thread and its connection slot for the life of the launch",
                );
            });
    }

    /// The `:authority` sbx authorizes has to be the `:authority` sbx forwards.
    ///
    /// The gate reduced it to `Authority::host()`, which drops the userinfo and the port both, while
    /// the upstream request is rebuilt from the decoded URI and h2 re-emits the authority whole. So
    /// `victim.example@grpc.test` passed a host-only comparison and then crossed to the origin with
    /// the userinfo still on it, for any edge that keys on the raw bytes or reads the segment before
    /// the `@` — and RFC 9113 §8.3.1 makes a `:authority` carrying userinfo malformed for an
    /// intermediary to relay at all. The HTTP/1.1 twin compares the whole `Host` value minus an
    /// all-digit port suffix and refuses both spellings; this is the parity the module header claims.
    ///
    /// Teeth: the resolver answers the cloud-metadata address, which the SSRF guard always refuses.
    /// A stream that slips past the authority gate therefore comes back `403 ssrf-blocked` — a
    /// different answer from the `421 host-mismatch` under test, so neither failure can be mistaken
    /// for the other, and the last case proves the gate still admits the tunnel's own authority.
    #[test]
    fn a_stream_authority_carrying_userinfo_or_another_port_is_refused_as_host_mismatch() {
        use crate::allowlist::classify;
        use crate::sandbox::control::{LOG_RING_CAP, LogRing};
        use std::time::Duration;

        fn answered(uri: &str) -> (StatusCode, String) {
            let ctx = ProxyCtx::new(
                Arc::new(super::super::Ca::ephemeral().unwrap()),
                EgressPolicy::new(vec![classify("grpc.test:*").unwrap()], vec![]),
            )
            .unwrap()
            .with_log(Arc::new(LogRing::new(LOG_RING_CAP)))
            // the cloud-metadata address: refused by the address guard whatever the rule says
            .with_resolver(Box::new(|_| Ok(vec![IpAddr::from([169, 254, 169, 254])])));

            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(async {
                    let (client_io, server_io) = tokio::io::duplex(16 * 1024);
                    let client = async {
                        let (mut send, conn) = h2::client::handshake(client_io).await.unwrap();
                        let driver = tokio::spawn(async move {
                            let _ = conn.await;
                        });
                        let req = Request::builder()
                            .method(Method::POST)
                            .uri(uri)
                            .header("content-type", "application/grpc")
                            .body(())
                            .unwrap();
                        let (resp, _body) = send.send_request(req, true).unwrap();
                        let resp = resp.await.unwrap();
                        let reason = resp
                            .headers()
                            .get("x-sbx-egress-reason")
                            .and_then(|v| v.to_str().ok())
                            .unwrap_or_default()
                            .to_string();
                        let status = resp.status();
                        driver.abort();
                        (status, reason)
                    };
                    let proxy = async {
                        let mut conn = h2::server::handshake(server_io).await.unwrap();
                        let (req, respond) = conn.accept().await.unwrap().unwrap();
                        stream(req, respond, "grpc.test", 443, &ctx, &UpstreamPool::default())
                            .await;
                        while conn.accept().await.is_some() {}
                    };
                    tokio::time::timeout(Duration::from_secs(30), async {
                        tokio::select! {
                            answer = client => answer,
                            () = proxy => panic!("the proxy leg ended before the client had its answer"),
                        }
                    })
                    .await
                    .expect("the in-memory h2 exchange must not stall")
                })
        }

        for uri in [
            // The userinfo dodge: everything before the `@` is what `host()` throws away and what
            // the rebuilt request still carries.
            "https://internal-admin.corp.example@grpc.test/pkg.Svc/Method",
            // ...and a port that is not the one the tunnel was opened to, dropped by the same call
            // and forwarded to any `host:port`-matching router on the far side.
            "https://grpc.test:8080/pkg.Svc/Method",
        ] {
            assert_eq!(
                answered(uri),
                (StatusCode::MISDIRECTED_REQUEST, "host-mismatch".to_string()),
                "`{uri}` is not the authority this tunnel was opened for"
            );
        }

        assert_eq!(
            answered("https://grpc.test/pkg.Svc/Method"),
            (StatusCode::FORBIDDEN, "ssrf-blocked".to_string()),
            "the tunnel's own authority must still pass the gate and reach the address guard"
        );
    }

    /// A relayed gRPC stream appears in the live flow view while it is open, with its byte totals.
    ///
    /// Every other plane takes the guard beside its allow (tunnel.rs, forward.rs, cleartext.rs);
    /// this one never did, so `sbx net live` — whose whole purpose is showing what is moving right
    /// now — was empty for every gRPC tunnel and its `↑`/`↓` totals zero, while the identical
    /// transfer to the same host over HTTP/1.1 showed a row with running counts. A long-lived
    /// bidirectional stream is the canonical durable row and was the one kind that never appeared.
    ///
    /// The row is read at the only deterministic moment it exists: a flow is deregistered when its
    /// stream ends, and the registration sits between the allow and the forward, so the upstream
    /// receiving the request head is proof the row was up.
    #[test]
    fn a_relayed_h2_stream_registers_a_live_flow_with_its_byte_totals() {
        use crate::sandbox::control::FlowRegistry;

        let trace = Arc::new(H2Trace::default());
        let (addr, upstream_ca) = spawn_h2_upstream(
            1,
            vec![b"h2".to_vec()],
            UpstreamReply::grpc("PONG"),
            Arc::clone(&trace),
        );
        let (ctx, _stats, _log, _dir) = relaying_ctx(upstream_ca);
        let flows = Arc::new(FlowRegistry::new());
        let ctx = ctx.with_flows(Arc::clone(&flows));
        *trace.flows.lock().unwrap() = Some(Arc::clone(&flows));

        let answer = through_h2_proxy(
            &ctx,
            "grpc.test",
            addr.port(),
            grpc_request(&[]),
            Some(b"PING".to_vec()),
            &trace,
        );
        assert_eq!(answer.status, StatusCode::OK, "{}", trace.render());

        let rows = trace.flows_when_forwarded.lock().unwrap().clone();
        assert_eq!(rows.len(), 1, "one open stream, one live row: {rows:?}");
        assert_eq!(
            (rows[0].host.as_str(), rows[0].port, rows[0].proto),
            ("grpc.test", addr.port(), Proto::Https),
            "the row names the destination and the inspected-TLS transport it rides"
        );
        assert!(
            rows[0].up >= 4,
            "the request body is counted into the flow as it is relayed: {rows:?}"
        );
        assert!(
            flows.snapshot().is_empty(),
            "and the row is gone once the stream closes"
        );
    }
}
