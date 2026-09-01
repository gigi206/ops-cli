//! Serving requests off one intercepted CONNECT tunnel.
//!
//! The client's leg is terminated TLS and may carry request after request, so this is where the
//! rule that every one of them is decided on its own lives — see [`Turn`] for the shape that makes
//! it structural rather than remembered. The decisions themselves are the parent module's, shared
//! with every other plane; what is here is one plane's sequencing of them.

use super::*;

/// Whether the client's tunnel may carry a further request after the turn that just ended.
///
/// A turn returns [`Turn::Continue`] from exactly one place — the last line of
/// [`serve_tunneled_request`] — and every other exit is a [`Turn::Close`]. That is the rule in
/// structural form: a request is followed by another on the same connection only when the one
/// before it ran the whole pipeline and left the connection's position known on both legs. A
/// refusal closes because its request body was never drained, so where the client's stream sits is
/// unknown; an error closes because it is an error.
///
/// The tunnel travels in the variant rather than beside it: a turn that closes has already disposed
/// of the stream its own way — shut down cleanly, handed to the WebSocket relay, or dropped after a
/// refusal — so there is no way for the caller to keep reading one that said `Close`.
pub(super) enum Turn {
    /// Read another request off this tunnel, which comes back to be read from. Boxed because the
    /// interception state is a kilobyte or so and this is a value returned once per request: one
    /// allocation when the tunnel opens buys a pointer-sized move per turn thereafter.
    Continue(Box<ClientTls>),
    /// This tunnel is finished.
    Close,
}

impl Turn {
    /// A helper that finished with the tunnel and reports only whether it worked: whatever it did,
    /// the connection is over.
    fn closing(done: io::Result<()>) -> io::Result<Turn> {
        done.map(|()| Turn::Close)
    }
}

/// The client-facing TLS stream of one intercepted CONNECT tunnel, buffered.
type ClientTls = BufReader<StreamOwned<ServerConnection, UnixStream>>;

/// Serve ONE request off an established tunnel: read its head, decide it against the policy (with
/// the host/SNI/Host triple agreeing and the SSRF guard applied to the resolved address), and — when
/// permitted — forward it to the validated upstream and stream the response back. Every failure path
/// is fail-closed, and each returns a [`write_refusal`] reason (an `X-Sbx-Egress-Reason` category
/// plus a text body) so the agent can tell an explicit policy refusal from an unreachable host or a
/// name that did not resolve, instead of an opaque status or a dropped connection.
///
/// Everything a request is judged on is read here, per request, with nothing carried in from the
/// turn before: the credential snapshot, the anti-fronting checks, the verdict, the resolution, the
/// injection match and the capture all start again. The tunnel's host and port are the only facts
/// that come from outside, and the CONNECT the client sent fixed those before the first request.
pub(super) fn serve_tunneled_request(
    mut br: Box<ClientTls>,
    ctx: &ProxyCtx,
    connect_host: &str,
    port: u16,
) -> io::Result<Turn> {
    // A tunnel the client has finished with ends here rather than inside the head reader: nothing
    // arriving before the first byte of a head is the client closing, or falling silent past the
    // idle bound, which is how a persistent connection is meant to end — not a truncated request,
    // and not something to log. All three shapes are that one event (rustls reports a peer that went
    // away without a `close_notify` as an unexpected EOF), so all three end the same way, with the
    // TLS shut down cleanly so a client still watching reads an end-of-stream and not a dropped
    // socket.
    if !matches!(br.fill_buf(), Ok([_, ..])) {
        finish_tls(br.get_mut());
        return Ok(Turn::Close);
    }
    // The idle bound the caller may have set covered the wait for that first byte; the request it
    // begins gets the launch's own timeout back.
    let _ = br.get_ref().sock.set_read_timeout(Some(ctx.timeout));
    // One credential state for the whole request: taken once here so the value injected and the
    // needle scanned for can never come from two different resolutions, even if a refresh lands
    // mid-request. The next request on this tunnel takes its own, as a later connection would.
    let creds = ctx.credentials.snapshot();

    // 4. Read this request's head (on the first turn that also drives the handshake to completion,
    //    so the SNI is known afterwards); keep the SAME buffered reader for the body.
    let inner_bytes = match read_head_buffered(&mut br, HEAD_MAX, head_deadline(ctx)) {
        Ok(bytes) => bytes,
        Err(e) => return refuse_unreadable_inner_head(&mut br, ctx, connect_host, port, &e),
    };
    let sni = br.get_ref().conn.server_name().map(|s| s.to_string());

    // CONNECT-host == SNI: the leaf was minted for the SNI, so a CONNECT to a different host is a
    // domain-fronting attempt. Re-asked on every turn rather than once per tunnel: it costs a string
    // compare, and a check that runs per request cannot be the one a later request skipped.
    if sni
        .as_deref()
        .map(|s| allowlist::canonical_host(s) != connect_host)
        .unwrap_or(true)
    {
        // Pre-parse: the inner request is not decoded yet, so there is no method/path to log.
        ctx.outcome(
            crate::sandbox::control::Proto::Https,
            connect_host,
            port,
            None,
            None,
            StatKind::Blocked,
            "host-mismatch",
        );
        return respond_refusal_tls(
            &mut br,
            "421 Misdirected Request",
            "host-mismatch",
            "the TLS SNI does not match the CONNECT target (possible domain-fronting)",
        );
    }

    let inner = match parse_head(&inner_bytes) {
        Ok(inner) => inner,
        Err(e) => return refuse_unreadable_inner_head(&mut br, ctx, connect_host, port, &e),
    };
    let Some((imethod, itarget)) = request_line_parts(&inner.request_line) else {
        ctx.push_log(
            crate::sandbox::control::Proto::Https,
            connect_host,
            port,
            None,
            None,
            crate::sandbox::control::LogVerdict::Blocked,
            "bad-request",
        );
        return respond_refusal_tls(
            &mut br,
            "400 Bad Request",
            "bad-request",
            "the tunneled request line is malformed",
        );
    };
    // A WebSocket upgrade is gated on an explicit opt-in: it is evaluated (and logged) under the `WS`
    // pseudo-verb, not the handshake's literal `GET`. Only a rule that names `WS` (`{WS}` or
    // `{…,WS}`) admits it — NOT an unrestricted `{*}` and NOT the read-by-default `{GET,HEAD}`, since
    // a WebSocket is a distinct unredactable bidirectional capability, not just another HTTP method,
    // and must be granted deliberately. Refused, a WS reads `denied-method` for `WS`; the log names it.
    let ws_upgrade = is_websocket_upgrade(&inner);
    let imethod = if ws_upgrade {
        "WS".to_string()
    } else {
        imethod
    };
    // The tunneled request must be origin-form (`/path`); an absolute-form target or `*` is
    // refused. The check is on the start, not a substring, so a URL inside the query
    // (`/login?next=https://…`) is not mistaken for absolute-form.
    if !itarget.starts_with('/') {
        ctx.push_log(
            crate::sandbox::control::Proto::Https,
            connect_host,
            port,
            Some(&imethod),
            Some(&itarget),
            crate::sandbox::control::LogVerdict::Blocked,
            "bad-request",
        );
        return respond_refusal_tls(
            &mut br,
            "400 Bad Request",
            "bad-request",
            "the tunneled request target must be origin-form (a path)",
        );
    }
    // Anti request-smuggling, fail-closed, through the check every inspected plane shares: a byte
    // another parser could frame by, a coding this proxy does not forward, a duplicated
    // Content-Length or Host, a length that is not a number. What it answers with is a reason and a
    // sentence; where that answer is written is this plane's own.
    let Framing { chunked, body_len } = match inspect_framing(&inner, true) {
        Ok(framing) => framing,
        Err(refusal) => {
            ctx.push_log(
                crate::sandbox::control::Proto::Https,
                connect_host,
                port,
                Some(&imethod),
                Some(&itarget),
                crate::sandbox::control::LogVerdict::Blocked,
                refusal.reason,
            );
            return respond_refusal_tls(&mut br, "400 Bad Request", refusal.reason, refusal.detail);
        }
    };

    // CONNECT-host == Host header (== SNI, already checked): the decrypted Host must agree too.
    if inner
        .header("host")
        .map(|h| allowlist::canonical_host(&strip_port(h)) != connect_host)
        .unwrap_or(true)
    {
        ctx.outcome(
            crate::sandbox::control::Proto::Https,
            connect_host,
            port,
            Some(&imethod),
            Some(&itarget),
            StatKind::Blocked,
            "host-mismatch",
        );
        return respond_refusal_tls(
            &mut br,
            "421 Misdirected Request",
            "host-mismatch",
            "the Host header does not match the CONNECT target (possible domain-fronting)",
        );
    }

    // 4c. Outbound leak tripwire: if the decrypted client head carries a configured secret value
    //     verbatim, refuse the whole request — block, never strip (a partial strip gives false
    //     confidence). Scanned on the pre-injection client bytes, so sbx's own injected credential
    //     can never trip it, and reached before the verdict so an exfil attempt never resolves a
    //     name or opens an upstream. A backstop against naive re-exfil only: it sees the head, not
    //     the streamed body, and matches the value byte-for-byte (any encoding evades it).
    if carries_secret(&inner_bytes, &creds.needles, connect_host) {
        ctx.outcome(
            crate::sandbox::control::Proto::Https,
            connect_host,
            port,
            Some(&imethod),
            Some(&itarget),
            StatKind::Blocked,
            "outbound-secret",
        );
        return respond_refusal_tls(
            &mut br,
            "403 Forbidden",
            "outbound-secret",
            "the request carries a configured secret value (outbound credential leak refused)",
        );
    }

    // 5. The verdict — the shared `https` decision ([`decide_https`]), which an absolute-form forward
    //    to the same host reaches identically. A refusal is answered *inside* the terminated TLS, so
    //    the client reads a real HTTP response rather than a tunnel that dies without explanation.
    let deciding: Option<Rule> = match decide_https(
        ctx,
        connect_host,
        port,
        &itarget,
        &imethod,
        AskPosture::Park,
    ) {
        Ok(rule) => rule,
        Err(refusal) => {
            return respond_refusal_tls(
                &mut br,
                refusal.status_line(),
                refusal.tag(),
                &refusal.message(ctx, connect_host, port, &imethod),
            );
        }
    };

    // 5b. A credential-injected host cannot also host a WebSocket: the reason, the `Blocked` outcome
    //     and the `403` are `refuse_ws_into_injected_host`'s, shared with the forward plane, and the
    //     refusal comes before any egress so no `allow` is recorded. Reached only when a `{WS}` rule
    //     already permitted the upgrade to this host; a WS to a non-`{WS}` host was denied by method
    //     above.
    if ws_upgrade
        && refuse_ws_into_injected_host(
            br.get_mut(),
            ctx,
            &creds,
            connect_host,
            port,
            &imethod,
            &itarget,
        )?
    {
        return Ok(Turn::Close);
    }

    // 6. Resolve host-side, then the SSRF guard — one call, which records the refusal whichever way
    //    it goes. A resolution failure for an allowed host is a clean 502 (not a dropped
    //    connection), so the agent sees "the name did not resolve" rather than an ambiguous
    //    transport error.
    let ip = match resolve_checked(
        ctx,
        crate::sandbox::control::Proto::Https,
        connect_host,
        port,
        Some(&imethod),
        Some(&itarget),
        deciding.as_ref(),
    ) {
        Ok(ip) => ip,
        Err(refusal) => {
            return respond_refusal_tls(
                &mut br,
                refusal.status_line(),
                refusal.tag(),
                &refusal.message(connect_host),
            );
        }
    };

    // 7. Match this request's host-scoped credential injections. This runs *after* the verdict, so a
    //    denied request never receives a secret, and is keyed on the already-verified `connect_host`
    //    plus the decrypted path — so the credential reaches exactly the destination it was scoped
    //    to. A redirect to another host opens a new tunnel and re-runs this match, so the secret
    //    cannot ride along to an unintended host. It is settled before any connection is taken,
    //    because which credentials a request carries is half of what partitions the pool below.
    let injected_ids = matching_injection_ids(&creds, connect_host, port, &itarget);
    // 7'. A signer whose manifest asks for a digest over the body is told one, which means the body
    //     has to exist before the question is put: hold it here rather than stream it at step 9. The
    //     `100-continue` a client may be waiting on is answered first — it withholds the body until
    //     it sees one — so this reads a body the request may still be refused over, which is the
    //     price of a signature that covers it.
    let digest_wanted = creds.wants_body_digest(&injected_ids);
    // A body already larger than the proxy will hold is refused here, before the reservation below
    // and before the client is invited to send. The order carries the meaning: this refusal is
    // **permanent** and the budget's is **transient**, so a request turned away by the budget for a
    // length no budget could ever admit would be told to retry something that will never succeed.
    if digest_wanted.is_some() && body_exceeds_hold(chunked, body_len, ctx.body) {
        ctx.outcome(
            crate::sandbox::control::Proto::Https,
            connect_host,
            port,
            Some(&imethod),
            Some(&itarget),
            StatKind::Blocked,
            SIGNER_BODY_TOO_LARGE,
        );
        return respond_refusal_tls(
            &mut br,
            "413 Payload Too Large",
            SIGNER_BODY_TOO_LARGE,
            &body_too_large_message(body_len, ctx.body),
        );
    }
    // Whether the proxy will read this request's body into memory rather than stream it: a chunked
    // request, which it de-chunks and re-frames whatever any signer wanted, or one a signer will be
    // told a digest of. One reservation covers both, taken here — before the allow is recorded and
    // before any upstream is opened, so a request refused for want of buffer is counted once and
    // costs no connection. Released with the buffer it covers, once the forwarded bytes are on the
    // wire: holding it through the response relay would turn a ceiling on what is *held* into a
    // limit on how many responses may be in flight.
    // Whether a `Content-Length` body is read into memory although nothing asked for its digest.
    // A performance decision, not a policy one: a held body is a re-sendable one, and re-sendable is
    // exactly what makes a request eligible for a pooled upstream connection. Streamed, it opened
    // its own connection and paid a handshake for it every time. See [`POOL_HOLD_MAX`].
    //
    // `!ws_upgrade` for the same reason the `keep_alive` binding below carries it: an upgrade takes
    // the connection over entirely, so there is no reuse for a held body to buy. Without it the
    // bytes were pulled off the client's TLS stream into `held` and then dropped on the floor — the
    // `if ws_upgrade` branch returns into `relay_upgrade` and never looks at `held` — while the
    // handshake forwarded to the upstream still declared the `Content-Length` those bytes belonged
    // to. The relay that follows is a byte-exact pipe, so the upstream sat waiting for a body that
    // had already been consumed, and the frames the cage then sent were read as the tail of it.
    let hold_for_reuse = ctx.pool.is_some()
        && !ws_upgrade
        && digest_wanted.is_none()
        && !chunked
        && (1..=POOL_HOLD_MAX).contains(&body_len);
    let mut budget: Option<BodyBudget> = None;
    if chunked || digest_wanted.is_some() {
        budget = match reserve_body_buffer(&ctx.held_bodies, chunked, body_len, ctx.body) {
            Some(reserved) => Some(reserved),
            None => {
                ctx.outcome(
                    crate::sandbox::control::Proto::Https,
                    connect_host,
                    port,
                    Some(&imethod),
                    Some(&itarget),
                    StatKind::Blocked,
                    BODY_BUFFER_CAP,
                );
                return respond_refusal_tls(
                    &mut br,
                    "503 Service Unavailable",
                    BODY_BUFFER_CAP,
                    &body_budget_message(),
                );
            }
        };
    } else if hold_for_reuse {
        // Best-effort, unlike the two above: the ceiling exists to bound host memory, and a request
        // that cannot have a buffer right now simply streams as it always did. There is nothing to
        // refuse it over — nothing asked for this body, the proxy only preferred it.
        budget = reserve_body_buffer(&ctx.held_bodies, false, body_len, ctx.body);
    }
    let hold_for_reuse = hold_for_reuse && budget.is_some();
    let held: Option<Vec<u8>> = if digest_wanted.is_none() && !hold_for_reuse {
        None
    } else {
        {
            // Only where there is a body to invite. A request that declares none is answered by the
            // response itself, and an interim `100` for a body that will never come is noise.
            if (chunked || body_len > 0) && head_expects_continue(&inner) {
                let client = br.get_mut();
                let _ = client.write_all(b"HTTP/1.1 100 Continue\r\n\r\n");
                let _ = client.flush();
            }
            match hold_request_body(&mut br, chunked, body_len, ctx.body) {
                Ok(body) => Some(body),
                // A malformed chunked body is the same refusal it is when the de-chunk happens on
                // the way out, under the same reason. A `Content-Length` body that ends early is a
                // transport failure rather than a malformed request, and stays the dropped
                // connection it is when the body streams.
                Err(e) if chunked => {
                    ctx.push_log(
                        crate::sandbox::control::Proto::Https,
                        connect_host,
                        port,
                        Some(&imethod),
                        Some(&itarget),
                        crate::sandbox::control::LogVerdict::Blocked,
                        "bad-request:chunked",
                    );
                    return respond_refusal_tls(
                        &mut br,
                        "400 Bad Request",
                        "bad-request:chunked",
                        &format!("the chunked request body could not be read: {e}"),
                    );
                }
                Err(e) => return Err(e),
            }
        }
    };
    let body_facts = held
        .as_deref()
        .zip(digest_wanted)
        .map(|(body, algorithm)| crate::sandbox::signer::BodyFacts::held(body, algorithm));
    // Forming the values may take a plugin round trip, and a plugin that cannot sign refuses the
    // request: a request that could not be given its credential is never sent without it.
    let injected = match injection_values(
        &creds,
        &injected_ids,
        &inject::RequestFacts {
            method: &imethod,
            host: connect_host,
            port,
            target: &itarget,
            headers: &inner.headers,
            body: body_facts.as_ref(),
        },
        ctx.signer_log(),
    ) {
        Ok(pairs) => pairs,
        Err(refusal) => {
            ctx.outcome(
                crate::sandbox::control::Proto::Https,
                connect_host,
                port,
                Some(&imethod),
                Some(&itarget),
                StatKind::Blocked,
                SIGNER_REFUSED,
            );
            return respond_refusal_tls(
                &mut br,
                "403 Forbidden",
                SIGNER_REFUSED,
                &signer_refusal_message(&refusal, &creds.needles),
            );
        }
    };

    // 7b. Remember any credential the cage sent for itself (an OAuth token an app obtained by its
    //     own sign-in), so the tripwires cover it as they cover a declared secret. Placed here for
    //     three reasons: after the verdict, so a refused request cannot seed the scan set; after the
    //     outbound scan, so a request is never refused by the credential it just taught sbx about;
    //     and after the injection match, so a header sbx is about to replace is skipped — its value
    //     never reaches the wire, and remembering it would tripwire the client's own placeholder,
    //     refusing every later request that carries it.
    let injected_names = injected_names(&injected);
    ctx.credentials
        .observe_head(&inner.headers, &injected_names, connect_host);

    // 7a. Whether this request may share its upstream leg with others. It takes a launch that asked
    //     for reuse, an HTTP/1.1 request (the version whose connections persist by default), and no
    //     protocol upgrade — an upgrade takes the connection over entirely. The key pairs the
    //     verified host and port with the exact credential set above, so a connection that carried a
    //     secret is only ever offered to a request that receives the same secret.
    let keep_alive =
        ctx.pool.is_some() && !ws_upgrade && request_line_is_http11(&inner.request_line);
    let pool_key = keep_alive.then(|| PoolKey::new(connect_host, port, &injected_ids));
    // Taking a parked connection is limited to a request the proxy can send a second time, because a
    // connection the upstream closed while it was parked only shows up after the write. That means a
    // request with no body, a chunked one whose body the de-chunker buffers before forwarding, or one
    // whose body was held to be digested above; a body streaming straight from the client is gone
    // once written. Such a request opens its own connection and still leaves it behind for the next
    // one.
    let replayable = chunked || body_len == 0 || held.is_some();

    // 7b. Take the upstream connection: a parked one, or a new one to the address just checked (not
    //     a re-resolve, which would reopen the rebinding window) with its certificate validated up
    //     front — a forged or self-signed upstream is refused, never passed through.
    let (mut upstream, mut from_pool) = match acquire_upstream(
        ctx,
        pool_key.as_ref().filter(|_| replayable),
        ip,
        port,
        connect_host,
    ) {
        Ok(pair) => pair,
        Err(e) => {
            return Turn::closing(refuse_upstream(
                br.get_mut(),
                ctx,
                connect_host,
                port,
                &imethod,
                &itarget,
                e,
            ));
        }
    };

    // The request is permitted and the upstream is up — it will now egress. Record the one `allow`
    // outcome here (a single count per request: a refusal above already returned, and the steps
    // below are I/O, not policy verdicts, so this is the sole place a forwarded request is counted).
    let allow_seq = ctx.outcome_l7(
        crate::sandbox::control::Proto::Https,
        crate::sandbox::control::HttpVer::H1,
        // The RPC framing from the inspected inner request's `Content-Type` (gRPC/gRPC-web/Connect
        // streaming); a plain or Connect-*unary* request classifies to `None`.
        crate::sandbox::control::RpcKind::from_content_type(
            inner.header("content-type").unwrap_or_default(),
        ),
        connect_host,
        port,
        Some(&imethod),
        Some(&itarget),
        StatKind::Allow,
        "allowed",
    );

    // The tunnel is now carrying traffic — register it for `sbx net live` until this turn returns.
    // One guard covers both the request/response below and a WebSocket upgrade: a WS over TLS is
    // still inspected TLS, so its proto stays `https`. The relay increments the guard's byte counters
    // as data flows (application-plaintext bytes on this inspected path). A tunnel serving several
    // requests registers one flow per request rather than one for its whole life, which is what
    // keeps the byte counts attributable to the request that moved them.
    let flow = ctx.register_flow(connect_host, port, crate::sandbox::control::Proto::Https);

    // 8a. Open the traffic capture for this exchange, when the launch captures. The request head
    //     recorded is the client's own (`inner_bytes`), taken before the reserialization below adds
    //     any injected credential — so a secret cannot reach the capture even in principle; only the
    //     injected header *names* are noted. The guard files on drop, so however this relay ends,
    //     what it saw is filed exactly once.
    let capture = ctx.begin_capture(allow_seq);
    if let Some(c) = &capture {
        c.set_request(&inner_bytes, &injected);
    }

    // 8b. A WebSocket upgrade cannot ride the request/response path below, which relays a single
    //     direction and hands the tunnel back. The handshake was inspected by the same
    //     verdict as any request — host, path, method, anti-fronting, SSRF, upstream-cert — and the
    //     outbound-secret tripwire already ran on it above, so the allowlist governs which host/path
    //     may open a WebSocket. Hand it to the upgrade relay, which forwards it with its
    //     `Upgrade`/`Connection` headers preserved and, on a `101`, relays both TLS streams verbatim.
    //
    //     Two known properties of an opened WebSocket, deliberate and bounded to a low-volume agent
    //     stream (documented, not silent):
    //       - Posture: the upgrade is judged under the `WS` pseudo-verb, not under the handshake's
    //         literal `GET` — step 4 rewrites `imethod` to `WS` the moment the handshake is
    //         recognised, so the verdict, the log and the stats all name it. Only a rule naming
    //         `WS` (`{WS}` or `{…,WS}`) admits it: a bare rule does not, `{GET,HEAD}` does not,
    //         `{*}` does not, and a `WS` never reaches the default action either (see
    //         `EgressPolicy::explain`), so a denylist posture does not hand one out. Refused, it
    //         reads `denied-method` for `WS`, and the log names it that way. A bidirectional,
    //         unredactable channel is its own capability and is granted deliberately — this is no
    //         longer the earlier posture, where a read-only `{GET}` allow opened one.
    //       - Once opened, the framed bytes are relayed VERBATIM: they are NOT scanned by the
    //         response-side redaction ([`pump_redacting`]), so a secret a peer reflects inside a
    //         frame reaches the cage as it was sent. The boundary stays the empty netns + the
    //         allowlist + the inspected handshake. Masking a frame would mean rewriting the relayed
    //         stream (decode, mask, re-frame, re-mask), which is a far larger change to the one path
    //         that must stay a byte-exact pipe; the traffic capture decodes frames only to copy them
    //         aside, and masks its own buffers, without touching what is relayed. The two handshake
    //         *heads* are not frames and are not covered by that: they are relayed under the same
    //         reflection mask any other head gets.
    if ws_upgrade {
        // The heads of this exchange are masked by the same rule an ordinary response's head is —
        // the upgrade is the one exchange whose bytes cannot be masked once it is open, so the
        // handshake is where the question has to be asked rather than after it.
        let head_masking: &[SecretNeedle] = if creds.masks_reflection_for(connect_host) {
            &creds.needles
        } else {
            &[]
        };
        // The capture follows the handshake into the upgrade relay, which files it at the `101` (it
        // cannot wait for a tunnel that may stay open for hours — see [`relay_upgrade`]).
        return Turn::closing(relay_upgrade(
            *br,
            upstream,
            &inner,
            &injected,
            head_masking,
            ctx,
            allow_seq,
            capture.as_ref(),
            flow.up.clone(),
            flow.down.clone(),
        ));
    }

    // 9. Forward this one request and stream the response back. A second request the client sent
    //    ahead of this response is still sitting in the buffered reader; it is not forwarded here but
    //    read as its own turn, which runs this whole function again — so pipelining costs a round of
    //    latency and skips no check.
    //
    //    The forwarded bytes are materialized whenever the proxy still holds all of them, which is
    //    exactly what `replayable` above decided: that is what lets a connection the upstream closed
    //    while it was parked cost a second attempt instead of an empty response. Branching on the
    //    same binding is what keeps the two in step — a request that took a parked connection and
    //    then could not be sent again would drop the client's connection instead of retrying.
    let forwarded: Option<Vec<u8>> = if !replayable {
        // A body streaming straight from the client: gone once written, which is why such a request
        // never took a parked connection.
        None
        // A held body that is empty is a request with no body, and reserializes as one below:
        // nothing about a bodyless request changes because a signer asked to be told a digest. A
        // chunked request takes this arm whatever it carried, since its framing must be replaced.
    } else if let Some(body) = held.filter(|held| chunked || !held.is_empty()) {
        // The body was read above so a signer could be told its digest. It is framed exactly as a
        // de-chunked one: a forced `Content-Length`, and the client's own framing headers dropped by
        // `reserialize_request`. The capture tee lives on the streaming path, so a held body is
        // handed to the capture here instead.
        if let Some(c) = &capture {
            c.set_request_body(&body);
        }
        let mut req = reserialize_request(&inner, &injected, Some(body.len() as u64), keep_alive);
        req.extend_from_slice(&body);
        Some(req)
    } else if chunked {
        // A `Transfer-Encoding: chunked` request: de-chunk the body into a bounded buffer and
        // forward a clean `Content-Length`-framed request (the `Transfer-Encoding` header is
        // stripped by `reserialize_request` when a length is forced), so no chunked framing — and
        // no CL/TE request-smuggling ambiguity — reaches the upstream. The cap bounds memory for
        // an agent prompt body (KB–MB); a larger chunked upload fails closed. Its room in the
        // shared ceiling was reserved at step 7', before the allow was recorded.
        // Answer a client `Expect: 100-continue` before reading, else it withholds the body. A
        // de-chunk failure (malformed framing, or over the cap) is fail-closed: log + refuse 400
        // (the interim 100 already sent is harmless — a final 4xx may follow it on one connection).
        if head_expects_continue(&inner) {
            let client = br.get_mut();
            let _ = client.write_all(b"HTTP/1.1 100 Continue\r\n\r\n");
            let _ = client.flush();
        }
        let body = match read_chunked_body(&mut br, ctx.body.per_request) {
            Ok(b) => b,
            Err(e) => {
                ctx.push_log(
                    crate::sandbox::control::Proto::Https,
                    connect_host,
                    port,
                    Some(&imethod),
                    Some(&itarget),
                    crate::sandbox::control::LogVerdict::Blocked,
                    "bad-request:chunked",
                );
                return respond_refusal_tls(
                    &mut br,
                    "400 Bad Request",
                    "bad-request:chunked",
                    &format!("the chunked request body could not be read: {e}"),
                );
            }
        };
        if let Some(c) = &capture {
            c.set_request_body(&body);
        }
        let mut req = reserialize_request(&inner, &injected, Some(body.len() as u64), keep_alive);
        req.extend_from_slice(&body);
        Some(req)
    } else {
        // Replayable, neither held nor chunked: a request with no body at all.
        Some(reserialize_request(&inner, &injected, None, keep_alive))
    };

    if let Some(req) = &forwarded {
        // Exactly one retry, and only for a connection that came from the pool: after it, the
        // connection is fresh and the loop condition ends it. The check is a peek, so an upstream
        // that is simply slow to answer — a completion that thinks before its first token — is
        // waited for rather than retried (the read bound is lifted first, or that wait would look
        // like a dead connection), and a healthy connection reaches the relay untouched. Only the
        // attempt that survives is counted on the flow.
        loop {
            match upstream.write_all(req) {
                Ok(()) => {
                    upstream.flush().ok();
                    begin_response_stream(&upstream.sock);
                    if !from_pool || upstream_spoke(&upstream.sock) {
                        break;
                    }
                }
                // A fresh connection that will not take the request is a real error and stays one.
                Err(e) if !from_pool => return Err(e),
                // A parked one that will not is the same event as one that takes the request and
                // then answers nothing: the far side is gone. It surfaces here rather than at the
                // peek when the close arrived as a reset instead of a clean shutdown, and letting
                // it out would drop the client's connection without even the `502` the other shape
                // produces. Fall through to the retry below — the request is replayable by
                // construction, which is what let it take a parked connection at all.
                Err(_) => {}
            }
            // The parked connection is gone. Sending the request again is safe for a method whose
            // effect does not depend on how many times it lands; for one that does, the honest reply
            // is the refusal, and the client keeps the decision it alone can make.
            if !idempotent_method(&imethod) {
                ctx.push_log(
                    crate::sandbox::control::Proto::Https,
                    connect_host,
                    port,
                    Some(&imethod),
                    Some(&itarget),
                    crate::sandbox::control::LogVerdict::Error,
                    "upstream-closed",
                );
                return respond_refusal_tls(
                    &mut br,
                    "502 Bad Gateway",
                    "upstream-closed",
                    &format!(
                        "`{connect_host}` closed the reused connection before answering, and \
                         `{imethod}` is not safe to send a second time"
                    ),
                );
            }
            let (fresh, _) = match acquire_upstream(ctx, None, ip, port, connect_host) {
                Ok(pair) => pair,
                Err(e) => {
                    return Turn::closing(refuse_upstream(
                        br.get_mut(),
                        ctx,
                        connect_host,
                        port,
                        &imethod,
                        &itarget,
                        e,
                    ));
                }
            };
            upstream = fresh;
            from_pool = false;
        }
        // Count client→upstream (`up`) — the forwarded head plus any body that rode with it.
        flow.up.fetch_add(req.len() as u64, Ordering::Relaxed);
    } else {
        // A body the proxy does not hold: forwarded straight from the client, on its own connection.
        let reserialized = reserialize_request(&inner, &injected, None, keep_alive);
        upstream.write_all(&reserialized)?;
        flow.up
            .fetch_add(reserialized.len() as u64, Ordering::Relaxed);
        // If the client announced `Expect: 100-continue` it withholds the body until it sees a 100.
        // The request is already permitted and the upstream is up, so answer the continue now — else
        // `copy_exact` below would block reading a body the client will not send, until the timeout.
        // `Expect` is stripped from the forwarded head (see `reserialize_request`), so the upstream
        // does not run the handshake a second time.
        if head_expects_continue(&inner) {
            let client = br.get_mut();
            let _ = client.write_all(b"HTTP/1.1 100 Continue\r\n\r\n");
            let _ = client.flush();
        }
        // The body is teed as it is relayed — a pass-through, so the forwarded stream is unchanged.
        copy_exact(
            &mut tee_request_body(&mut br, capture.as_ref()),
            &mut upstream,
            body_len,
        )?;
        // Count the forwarded body (`copy_exact` moved exactly `body_len` bytes upstream).
        flow.up.fetch_add(body_len, Ordering::Relaxed);
        upstream.flush().ok();
        // The request is permitted and fully forwarded; the response may now idle between bursts (a
        // streamed completion), so lift the upstream read timeout for the relay below.
        begin_response_stream(&upstream.sock);
    }

    // The forwarded bytes are on the wire, retries included: the buffer and its reservation are
    // done. Released here rather than at the end of the function, or a ceiling on what the proxy
    // *holds* would silently become a limit on how many responses may be relayed at once — a
    // streaming completion would hold its 64 MiB of budget for as long as it streams.
    drop(forwarded);
    drop(budget);

    // 9b. Response-side leak backstop, scoped to a host an injection targets — the threat it
    //     answers and why the scoping is what it is belong to `CredentialSet::masks_reflection_for`,
    //     which every inspected plane asks. What is this plane's is the placement: decided here
    //     because the mask covers the head as much as the body, and the head is relayed first.
    let masks_reflection = creds.masks_reflection_for(connect_host);
    let head_masking: &[SecretNeedle] = if masks_reflection {
        &creds.needles
    } else {
        &[]
    };

    // 9c. Read the response head, relay it, and decide from it where the body ends, so the relay
    //     stops at the end of the message instead of waiting for the upstream to close. Buffering is
    //     what makes that possible and is also the hazard: the reader below already holds body bytes
    //     pulled off the socket, so the body must be read from IT and never from the socket again.
    //     `set_status` amends the `allow` event pushed above; on an L4 splice, a refusal, or an
    //     error there is no such amend (no response).
    let mut up_br = BufReader::new(&mut upstream);
    let RelayedHead {
        head: resp_head,
        framing,
        persistent,
        ..
    } = relay_response_head(
        &mut up_br,
        br.get_mut(),
        &flow.down,
        capture.as_ref(),
        head_masking,
        &imethod,
        // The client's leg is offered a further request only when the client's own request left it
        // open to one. Everything else about reuse is decided from the response, but this half of it
        // belongs to the client and answering keep-alive over a `Connection: close` would be sbx
        // telling the client something the client did not ask for.
        if inner.keeps_alive() {
            ClientLeg::MayReuse { idle: ctx.idle }
        } else {
            ClientLeg::Close
        },
    )?;
    // An upstream that closed without answering leaves nothing to relay, and saying so is the honest
    // reply: an empty success is indistinguishable from a genuine zero-byte response, and it would
    // hide the one failure reuse can produce — a connection the far side closed in the window
    // between the pool's probe and the write.
    if resp_head.is_empty() {
        ctx.push_log(
            crate::sandbox::control::Proto::Https,
            connect_host,
            port,
            Some(&imethod),
            Some(&itarget),
            crate::sandbox::control::LogVerdict::Error,
            "upstream-closed",
        );
        return respond_refusal_tls(
            &mut br,
            "502 Bad Gateway",
            "upstream-closed",
            &format!("`{connect_host}` closed the connection without sending a response"),
        );
    }
    // Record only a FINAL status (>= 200). Any interim 1xx was relayed and read past above, so what
    // is left is the request's real outcome; a head cut short parses to nothing and simply leaves
    // the event without a status.
    if let Some(code) = parse_status_code(&resp_head)
        && code >= 200
    {
        note_final_status(ctx, allow_seq, &creds, &injected_ids, code);
    }

    // 10. The body is teed on the way through, ahead of the reflection masking: the capture does its
    //     own masking at filing time (over whole buffers), so what is stored is masked either way,
    //     and what the cage receives is decided by `masks_reflection` alone (the head above was
    //     masked under the same decision). Counted upstream→client (`down`) through the body; the
    //     head was counted as it was relayed.
    let mut framed = FramedBody::new(&mut up_br, framing);
    {
        let counted = CountingReader::new(&mut framed, flow.down.clone());
        let mut response = tee_response(counted, capture.as_ref());
        if masks_reflection {
            pump_redacting(&mut response, br.get_mut(), &creds.needles)?;
        } else {
            pump_to_eof(&mut response, br.get_mut())?;
        }
    }

    // 11. The response is over, and both legs now ask whether they may carry another request. Two
    //     answers are shared between them: the body ended exactly where its framing said (a
    //     truncated one leaves the exchange at an unknown position on both sides), and nothing the
    //     head read pulled ahead is still buffered. Together they are the one thing reuse cannot do
    //     without — knowing where the message ended. The upstream adds that the response left *its*
    //     connection reusable, and the pool settles the last question, whether anything is pending on
    //     the socket. This sits after the relay's `?`, so a relay that ended early reuses nothing.
    let ended_as_framed = framed.ended_as_framed();
    drop(framed);
    let no_residual = up_br.buffer().is_empty();
    drop(up_br);
    let position_known = ended_as_framed && no_residual;
    if position_known
        && response_keeps_alive(&resp_head)
        && let (Some(pool), Some(key)) = (ctx.pool.as_ref(), pool_key)
    {
        pool.park(key, upstream, ctx.timeout);
    }

    // The client's leg may carry another request only when the head it was sent already said so and
    // the body then ended exactly where that head promised. The announcement is made before the body
    // is relayed and cannot wait for it, so it is a necessary condition and never a sufficient one:
    // announcing a persistent connection and then closing is legal at any point, while announcing it
    // and reading on with the stream at an unknown position is the desync this guards against.
    if persistent && position_known {
        return Ok(Turn::Continue(br));
    }
    // The response is fully relayed and this tunnel carries nothing more — close the intercepted TLS
    // cleanly so the client sees a proper end-of-stream, not a bare socket drop (the reported
    // `without sending TLS close_notify`).
    finish_tls(br.get_mut());
    Ok(Turn::Close)
}

/// A request head inside a tunnel that never became a request: log the attempt against the tunnel's
/// own host, tell the caller why, and close the tunnel.
///
/// The reason and the sentence are the entrance's ([`refuse_unreadable_head`]), because this is the
/// same event: a head that arrived truncated, over [`HEAD_MAX`], past its deadline or not as UTF-8.
/// What differs is that the CONNECT has already fixed a host and a port here, so the line names them
/// where the entrance's line cannot.
///
/// A client simply finished with the tunnel never reaches this. [`serve_tunneled_request`]
/// establishes that a byte is waiting before it reads a head at all, and answers a tunnel with
/// nothing on it with [`Turn::Close`] and no line, which is how a persistent connection is meant to
/// end.
fn refuse_unreadable_inner_head(
    br: &mut ClientTls,
    ctx: &ProxyCtx,
    connect_host: &str,
    port: u16,
    err: &io::Error,
) -> io::Result<Turn> {
    ctx.push_log(
        crate::sandbox::control::Proto::Https,
        connect_host,
        port,
        None,
        None,
        crate::sandbox::control::LogVerdict::Blocked,
        UNREADABLE_HEAD,
    );
    respond_refusal_tls(
        br,
        "400 Bad Request",
        UNREADABLE_HEAD,
        &unreadable_head_detail(err),
    )
}

/// Write a refusal to the client through the buffered TLS stream (the in-tunnel error paths,
/// after the CONNECT tunnel is established and TLS is terminated).
///
/// It answers with the tunnel's [`Turn`], and that answer is always [`Turn::Close`]: a refused
/// request's body was never read, so the client's stream is left somewhere inside a message rather
/// than at the start of the next one. The refusal says so on the wire too ([`write_refusal`] sends
/// `Connection: close`). Returning the turn rather than `()` is what makes that a property of the
/// type instead of a rule each of the ~18 refusal sites has to remember.
fn respond_refusal_tls<S: Read + Write>(
    br: &mut BufReader<StreamOwned<ServerConnection, S>>,
    status: &str,
    category: &str,
    detail: &str,
) -> io::Result<Turn> {
    write_refusal(br.get_mut(), status, category, detail)?;
    Ok(Turn::Close)
}
