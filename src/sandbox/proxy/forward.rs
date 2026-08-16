//! The absolute-form `https://` plane: a forward proxy without a CONNECT.
//!
//! A client that treats sbx as a TLS-terminating forward proxy sends `POST https://host/path`
//! straight to the proxy port. Plaintext on the client's leg, a validated TLS upstream on the
//! other, and the same `https` verdict a CONNECT to the same host reaches.

use super::*;

/// Handle a top-level **absolute-form `https://`** request that arrives WITHOUT a CONNECT tunnel: a
/// client (typically a bundled proxy library that treats the proxy as a TLS-terminating forward
/// proxy — the "secure web proxy" form) sends `POST https://host/path HTTP/1.1` straight to the proxy
/// port instead of `CONNECT host:443`. Without this path the request is refused `405
/// method-not-allowed`, which strands a tool whose only egress transport is this form (observed live:
/// the Kiro IDE's OAuth token exchange to `auth.desktop.kiro.dev/oauth/token`).
///
/// This is the plaintext-client sibling of the CONNECT MITM path. The client→proxy leg is cleartext
/// (an `http://` proxy connection), but policy is terminated the SAME way and the proxy makes a
/// **validated TLS** connection to the real upstream. Differences from [`handle_cleartext`] (the
/// opt-in `http://` scheme):
///   - the verdict uses [`EgressPolicy::explain`](crate::allowlist::EgressPolicy::explain) — a normal `https` allow rule permits it, so this
///     is NOT a separate opt-in (it is exactly the egress an equivalent `CONNECT` would have gotten,
///     down to parking an `ask`-undecided host for `sbx net pending`);
///   - the upstream leg is TLS with certificate validation (never downgraded — a forged upstream is a
///     `502`, as on the MITM path);
///   - a host-scoped credential IS injected: it rides the encrypted upstream leg (unlike a cleartext
///     request, which never carries a header secret), and the response is masked if the host is an
///     injection target.
///
/// One `host` value — the one [`allowlist::parse_url_target`] read from the request line — feeds the
/// policy verdict, the upstream certificate validation, and the name resolution, so those three
/// cannot disagree without the `Host` header. The `Host` comparison below adds the fourth party: the
/// *upstream's* own routing. Without it a request could name an allowed host in its line (winning the
/// verdict, the validated certificate, and any host-scoped credential) while its `Host` header sends
/// the upstream to vhost-route it elsewhere — so the check is what keeps an injected credential on
/// the request the policy actually approved.
///
/// Conscious, bounded property: request and response travel cleartext on the client→proxy leg — but
/// that leg is a loopback socket inside the cage, unreadable by any cage process (no `CAP_NET_RAW`
/// for a packet socket, `ptrace` on the seccomp denylist), and the injected credential is added for
/// the upstream leg only, so it never appears on the client leg at all. What this path shares with
/// the tunneled one is that it does not authenticate its client: any in-cage process can drive the
/// injected credential to the allowlisted host — the accepted property of host-side injection.
pub(super) fn handle_https_forward(
    mut client: UnixStream,
    head: &Head,
    head_bytes: &[u8],
    method: &str,
    target: &str,
    ctx: &ProxyCtx,
) -> io::Result<()> {
    // One credential state for the whole exchange: taken once here so the value injected and
    // the needle scanned for can never come from two different resolutions, even if a refresh
    // lands mid-request. A later exchange picks up the newer state.
    let creds = ctx.credentials.snapshot();
    // 1. Parse the absolute-form `https://host[:port]/path` target into (host, port=443 default, path).
    //    The host is canonicalized by the parser; the path is canonicalized inside `explain`.
    let (host, port, path) = match allowlist::parse_url_target(target) {
        Ok(t) => t,
        Err(_) => {
            ctx.push_log(
                crate::sandbox::control::Proto::Https,
                "",
                0,
                Some(method),
                Some(target),
                crate::sandbox::control::LogVerdict::Blocked,
                "bad-request",
            );
            return write_refusal(
                &mut client,
                "400 Bad Request",
                "bad-request",
                "the absolute-form request target is not a valid `https://` URL",
            );
        }
    };

    // 2. Anti request-smuggling, fail-closed, through the check every inspected plane shares. Like
    //    the tunneled path this one de-chunks and re-frames, so `chunked` is forwardable here.
    let Framing { chunked, body_len } = match inspect_framing(head, true) {
        Ok(framing) => framing,
        Err(refusal) => {
            ctx.push_log(
                crate::sandbox::control::Proto::Https,
                &host,
                port,
                Some(method),
                Some(&path),
                crate::sandbox::control::LogVerdict::Blocked,
                refusal.reason,
            );
            return write_refusal(
                &mut client,
                "400 Bad Request",
                refusal.reason,
                refusal.detail,
            );
        }
    };

    // 3. Anti-fronting: the absolute-form URL host must equal the `Host` header, so a request cannot
    //    claim one host in the line and another in the header (the URL host is what the policy checks).
    if head
        .header("host")
        .map(|h| allowlist::canonical_host(&strip_port(h)) != host)
        .unwrap_or(true)
    {
        ctx.outcome(
            crate::sandbox::control::Proto::Https,
            &host,
            port,
            Some(method),
            Some(&path),
            StatKind::Blocked,
            "host-mismatch",
        );
        return write_refusal(
            &mut client,
            "421 Misdirected Request",
            "host-mismatch",
            "the Host header does not match the request-line host",
        );
    }

    // 4. Outbound leak tripwire on the raw head — refuse (block, never strip) a request re-sending a
    //    configured secret verbatim, scanned before sbx's own injection so it cannot self-trip.
    if carries_secret(head_bytes, &creds.needles, &host) {
        ctx.outcome(
            crate::sandbox::control::Proto::Https,
            &host,
            port,
            Some(method),
            Some(&path),
            StatKind::Blocked,
            "outbound-secret",
        );
        return write_refusal(
            &mut client,
            "403 Forbidden",
            "outbound-secret",
            "the request carries a configured secret value (outbound credential leak refused)",
        );
    }

    // 5. The verdict — the SAME `https` decision a `CONNECT` to this host gets ([`decide_https`]):
    //    same rules, same denial shapes, same parking for an undecided host. Only the answer differs,
    //    written on the plaintext client socket this form arrived on.
    let deciding: Option<Rule> =
        match decide_https(ctx, &host, port, &path, method, AskPosture::Park) {
            Ok(rule) => rule,
            Err(refusal) => {
                return write_refusal(
                    &mut client,
                    refusal.status_line(),
                    refusal.tag(),
                    &refusal.message(ctx, &host, port, method),
                );
            }
        };

    // 6. Resolve host-side, then the SSRF guard against the deciding rule. A resolution failure for an
    //    allowed host is a clean 502, distinct from a refusal.
    let ip = match resolve_checked(
        ctx,
        crate::sandbox::control::Proto::Https,
        &host,
        port,
        Some(method),
        Some(&path),
        deciding.as_ref(),
    ) {
        Ok(ip) => ip,
        Err(refusal) => {
            return write_refusal(
                &mut client,
                refusal.status_line(),
                refusal.tag(),
                &refusal.message(&host),
            );
        }
    };

    // 7. Match this request's host-scoped credential injection — after the verdict (a denied request
    //    never gets a secret) and keyed on the verified host + decrypted path, so it reaches only its
    //    scoped destination. Unlike the `http://` path, the upstream is TLS, so a header secret rides
    //    it encrypted, never in the clear. Settled before a connection is taken, because which
    //    credentials a request carries is half of what partitions the pool.
    let injected_ids = matching_injection_ids(&creds, &host, port, &path);
    // 7'. As on the tunneled path: a signer that asks for a digest over the body needs the body held
    //     before the question is put, so it is read here rather than streamed at step 9.
    let digest_wanted = creds.wants_body_digest(&injected_ids);
    // Ahead of the reservation, for the reason the tunneled path states: a permanent refusal must
    // not be delivered as the budget's transient one.
    if digest_wanted.is_some() && body_exceeds_hold(chunked, body_len, ctx.body) {
        ctx.outcome(
            crate::sandbox::control::Proto::Https,
            &host,
            port,
            Some(method),
            Some(&path),
            StatKind::Blocked,
            SIGNER_BODY_TOO_LARGE,
        );
        return write_refusal(
            &mut client,
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
    let hold_for_reuse = ctx.pool.is_some()
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
                    &host,
                    port,
                    Some(method),
                    Some(&path),
                    StatKind::Blocked,
                    BODY_BUFFER_CAP,
                );
                return write_refusal(
                    &mut client,
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
            if (chunked || body_len > 0) && head_expects_continue(head) {
                let _ = client.write_all(b"HTTP/1.1 100 Continue\r\n\r\n");
                let _ = client.flush();
            }
            // The buffered reader is scoped to the read, as it is for the de-chunk below: it may
            // read past the body's terminator, and this path forwards no pipelined second request.
            let read = {
                let mut reader = BufReader::new(&client);
                hold_request_body(&mut reader, chunked, body_len, ctx.body)
            };
            match read {
                Ok(body) => Some(body),
                Err(e) if chunked => {
                    ctx.push_log(
                        crate::sandbox::control::Proto::Https,
                        &host,
                        port,
                        Some(method),
                        Some(&path),
                        crate::sandbox::control::LogVerdict::Blocked,
                        "bad-request:chunked",
                    );
                    return write_refusal(
                        &mut client,
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
    let injected = match injection_values(
        &creds,
        &injected_ids,
        &inject::RequestFacts {
            method,
            host: &host,
            port,
            target: &path,
            headers: &head.headers,
            body: body_facts.as_ref(),
        },
        ctx.signer_log(),
    ) {
        Ok(pairs) => pairs,
        Err(refusal) => {
            ctx.outcome(
                crate::sandbox::control::Proto::Https,
                &host,
                port,
                Some(method),
                Some(&path),
                StatKind::Blocked,
                SIGNER_REFUSED,
            );
            return write_refusal(
                &mut client,
                "403 Forbidden",
                SIGNER_REFUSED,
                &signer_refusal_message(&refusal, &creds.needles),
            );
        }
    };

    // 7b. Remember any credential the cage sent for itself, on the same terms and in the same place
    //     as the tunneled path — after the verdict, after the outbound scan, after the injection
    //     match. This plane is where it matters most: it exists for a client whose only egress
    //     transport is the absolute form, and the traffic that brought it here was an OAuth token
    //     exchange. A credential acquired that way and never observed is one the tripwires do not
    //     cover afterwards, on any plane.
    let injected_names = injected_names(&creds, &injected_ids);
    ctx.credentials
        .observe_head(&head.headers, &injected_names, &host);

    // 7a. Whether this request may share its upstream leg with others, on the same terms as the
    //     tunneled path: the launch has to have asked for reuse, and the request has to be HTTP/1.1.
    //     Only a request the proxy can send again takes a parked connection.
    let keep_alive =
        ctx.pool.is_some() && head.request_line.split_whitespace().nth(2) == Some("HTTP/1.1");
    let pool_key = keep_alive.then(|| PoolKey::new(&host, port, &injected_ids));
    let replayable = chunked || body_len == 0 || held.is_some();

    // 7b. Take the upstream connection: a parked one, or a new validated TLS connection to the
    //     checked address (not a re-resolve, which would reopen the rebinding window). A
    //     forged/self-signed upstream is refused, never downgraded.
    let (mut upstream, mut from_pool) = match acquire_upstream(
        ctx,
        pool_key.as_ref().filter(|_| replayable),
        ip,
        port,
        &host,
    ) {
        Ok(pair) => pair,
        Err(e) => return refuse_upstream(&mut client, ctx, &host, port, method, &path, e),
    };

    // The request is permitted and the upstream TLS handshake is validated — record the one `allow`.
    let allow_seq = ctx.outcome_l7(
        crate::sandbox::control::Proto::Https,
        crate::sandbox::control::HttpVer::H1,
        crate::sandbox::control::RpcKind::from_content_type(
            head.header("content-type").unwrap_or_default(),
        ),
        &host,
        port,
        Some(method),
        Some(&path),
        StatKind::Allow,
        "allowed",
    );
    let flow = ctx.register_flow(&host, port, crate::sandbox::control::Proto::Https);

    // 8a. Open the traffic capture, recording the client's own head (before the reserialization
    //     below adds any injected credential) plus the injected header names, never their values.
    let capture = ctx.begin_capture(allow_seq);
    if let Some(c) = &capture {
        c.set_request(head_bytes, &injected);
    }

    // 9. Forward the one request in **origin-form** (`POST /path`) with the injected credential (the
    //    reserializer strips hop-by-hop headers and the client's copy of any injected header). A
    //    pipelined second request is never forwarded, so it cannot skip the per-request check. The
    //    forwarded bytes are materialized when the proxy still holds all of them — the same binding
    //    that decided whether this request could take a parked connection, so the two cannot drift.
    let version = head
        .request_line
        .split_whitespace()
        .nth(2)
        .unwrap_or("HTTP/1.1");
    let origin = Head {
        request_line: format!("{method} {path} {version}"),
        headers: head.headers.clone(),
    };
    let forwarded: Option<Vec<u8>> = if !replayable {
        // A body streaming straight from the client: gone once written, which is why such a request
        // never took a parked connection.
        None
        // A held body that is empty is a request with no body, and reserializes as one below:
        // nothing about a bodyless request changes because a signer asked to be told a digest. A
        // chunked request takes this arm whatever it carried, since its framing must be replaced.
    } else if let Some(body) = held.filter(|held| chunked || !held.is_empty()) {
        // The body was read above so a signer could be told its digest, and is framed exactly as a
        // de-chunked one. The capture tee lives on the streaming path, so a held body is handed to
        // the capture here instead.
        if let Some(c) = &capture {
            c.set_request_body(&body);
        }
        let mut req = reserialize_request(&origin, &injected, Some(body.len() as u64), keep_alive);
        req.extend_from_slice(&body);
        Some(req)
    } else if chunked {
        // A `Transfer-Encoding: chunked` request: de-chunk the body into a bounded buffer and forward
        // a clean `Content-Length`-framed request (the reserializer strips the client's
        // Transfer-Encoding when a length is forced), so no chunked framing — and no CL/TE
        // request-smuggling ambiguity — reaches the upstream. Answer a client `Expect: 100-continue`
        // before reading, else it withholds the body. A de-chunk failure (malformed framing, or over
        // the cap) is fail-closed: log + refuse 400. The shared buffer ceiling is taken here as the
        // held path takes it, for the same host-side memory it bounds.
        if head_expects_continue(head) {
            let _ = client.write_all(b"HTTP/1.1 100 Continue\r\n\r\n");
            let _ = client.flush();
        }
        // The buffered reader is scoped to the de-chunk: it may read past the body's terminator (a
        // pipelined second request), which this path never forwards anyway.
        let read = {
            let mut reader = BufReader::new(&client);
            read_chunked_body(&mut reader, ctx.body.per_request)
        };
        let body = match read {
            Ok(b) => b,
            Err(e) => {
                ctx.push_log(
                    crate::sandbox::control::Proto::Https,
                    &host,
                    port,
                    Some(method),
                    Some(&path),
                    crate::sandbox::control::LogVerdict::Blocked,
                    "bad-request:chunked",
                );
                return write_refusal(
                    &mut client,
                    "400 Bad Request",
                    "bad-request:chunked",
                    &format!("the chunked request body could not be read: {e}"),
                );
            }
        };
        if let Some(c) = &capture {
            c.set_request_body(&body);
        }
        let mut req = reserialize_request(&origin, &injected, Some(body.len() as u64), keep_alive);
        req.extend_from_slice(&body);
        Some(req)
    } else {
        // Replayable, neither held nor chunked: a request with no body at all.
        Some(reserialize_request(&origin, &injected, None, keep_alive))
    };

    if let Some(req) = &forwarded {
        // Exactly one retry, and only for a connection that came from the pool — see the tunneled
        // path for why the peek, and why the read bound is lifted before it.
        loop {
            match upstream.write_all(req) {
                Ok(()) => {
                    upstream.flush().ok();
                    begin_response_stream(&upstream.sock);
                    if !from_pool || upstream_spoke(&upstream.sock) {
                        break;
                    }
                }
                // The same two cases as the tunneled path, for the same reasons: a fresh connection
                // that refuses the write is a real error, a parked one is a far side that is gone
                // and reached us as a reset rather than at the peek.
                Err(e) if !from_pool => return Err(e),
                Err(_) => {}
            }
            // Same rule as the tunneled path: replay what may be replayed, refuse the rest plainly.
            if !idempotent_method(method) {
                ctx.push_log(
                    crate::sandbox::control::Proto::Https,
                    &host,
                    port,
                    Some(method),
                    Some(&path),
                    crate::sandbox::control::LogVerdict::Error,
                    "upstream-closed",
                );
                return write_refusal(
                    &mut client,
                    "502 Bad Gateway",
                    "upstream-closed",
                    &format!(
                        "`{host}` closed the reused connection before answering, and `{method}` \
                         is not safe to send a second time"
                    ),
                );
            }
            let (fresh, _) = match acquire_upstream(ctx, None, ip, port, &host) {
                Ok(pair) => pair,
                Err(e) => return refuse_upstream(&mut client, ctx, &host, port, method, &path, e),
            };
            upstream = fresh;
            from_pool = false;
        }
        flow.up.fetch_add(req.len() as u64, Ordering::Relaxed);
    } else {
        // A body the proxy does not hold: forwarded straight from the client, on its own connection.
        let reserialized = reserialize_request(&origin, &injected, None, keep_alive);
        upstream.write_all(&reserialized)?;
        flow.up
            .fetch_add(reserialized.len() as u64, Ordering::Relaxed);
        // Answer a client `Expect: 100-continue` now (the request is permitted and the upstream is
        // up), else `copy_exact` would block reading a body the client withholds. `Expect` is
        // stripped from the forwarded head, so the upstream does not re-run the handshake.
        if head_expects_continue(head) {
            let _ = client.write_all(b"HTTP/1.1 100 Continue\r\n\r\n");
            let _ = client.flush();
        }
        // Teed as it is relayed — a pass-through, so the forwarded stream is unchanged.
        match &capture {
            Some(c) => copy_exact(
                &mut CaptureReader::new(&mut client, c.request_body_sink()),
                &mut upstream,
                body_len,
            )?,
            None => copy_exact(&mut client, &mut upstream, body_len)?,
        }
        flow.up.fetch_add(body_len, Ordering::Relaxed);
        upstream.flush().ok();
        // The request is fully forwarded; the response may idle between bursts, so lift the timeout.
        begin_response_stream(&upstream.sock);
    }

    // The forwarded bytes are on the wire, retries included: the buffer and its reservation are
    // done. Released here rather than at the end of the function, or a ceiling on what the proxy
    // *holds* would silently become a limit on how many responses may be relayed at once — a
    // streaming completion would hold its 64 MiB of budget for as long as it streams.
    drop(forwarded);
    drop(budget);

    // 10. Relay the response head, then stream its framed body to the plaintext client and close.
    //     Mask a reflected secret only for a response from an injection-target host (every other
    //     response streams untouched) — decided before the head is read, because the masking covers
    //     the head as much as the body and the head is relayed first.
    let masks_reflection = !creds.needles.is_empty()
        && creds
            .injections
            .iter()
            .any(|inj| names_exact_host(&host, Some(&inj.rule)));
    let head_masking: &[SecretNeedle] = if masks_reflection {
        &creds.needles
    } else {
        &[]
    };
    let mut up_br = BufReader::new(&mut upstream);
    let RelayedHead {
        head: resp_head,
        framing,
        ..
    } = relay_response_head(
        &mut up_br,
        &mut client,
        &flow.down,
        capture.as_ref(),
        head_masking,
        method,
        // This plane's client leg is the proxy's own listening socket, spoken in cleartext and
        // served one request at a time — there is nothing on it to keep alive, whatever the
        // upstream leg does.
        if keep_alive {
            ClientLeg::Close
        } else {
            ClientLeg::Verbatim
        },
    )?;
    // An upstream that closed without answering leaves nothing to relay, and an empty success would
    // be indistinguishable from a genuine zero-byte response — see the tunneled path.
    if resp_head.is_empty() {
        ctx.push_log(
            crate::sandbox::control::Proto::Https,
            &host,
            port,
            Some(method),
            Some(&path),
            crate::sandbox::control::LogVerdict::Error,
            "upstream-closed",
        );
        return write_refusal(
            &mut client,
            "502 Bad Gateway",
            "upstream-closed",
            &format!("`{host}` closed the connection without sending a response"),
        );
    }
    if let Some(code) = parse_status_code(&resp_head)
        && code >= 200
    {
        ctx.set_status(allow_seq, code);
        // A `401` from a host this request carried a credential to is the destination itself saying
        // the value is no longer accepted — the one signal worth re-resolving on, and a truer one
        // than any declared expiry. Gated on a *refreshable* injection, so a refusal from a host we
        // inject nothing into can never make an in-cage agent drive sbx's resolver, and a host whose
        // credential is signed per request never spends a resolver run on a value that cannot be
        // stale.
        if code == 401 && any_refreshable(&creds, &injected_ids) {
            ctx.credential_refused();
        }
    }
    // Count upstream→client (`down`) through the body; the head was counted as it was relayed.
    // Teed ahead of the reflection masking — the capture masks its own buffers at filing time.
    let mut framed = FramedBody::new(&mut up_br, framing);
    {
        let response = CountingReader::new(&mut framed, flow.down.clone());
        let mut response: Box<dyn Read + '_> = match &capture {
            Some(c) => Box::new(CaptureReader::new(response, c.response_sink())),
            None => Box::new(response),
        };
        if masks_reflection {
            pump_redacting(&mut response, &mut client, &creds.needles)?;
        } else {
            pump_to_eof(&mut response, &mut client)?;
        }
    }
    // 11. Whether this connection may carry another request — the same three answers as the tunneled
    //     path, and after the relay's `?` for the same reason.
    let ended_as_framed = framed.ended_as_framed();
    drop(framed);
    let no_residual = up_br.buffer().is_empty();
    drop(up_br);
    if ended_as_framed
        && no_residual
        && response_keeps_alive(&resp_head)
        && let (Some(pool), Some(key)) = (ctx.pool.as_ref(), pool_key)
    {
        pool.park(key, upstream, ctx.timeout);
    }
    Ok(())
}
