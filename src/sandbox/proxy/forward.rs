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
///     down to parking an `ask`-undecided host for `sbx net pending`, and down to deciding a
///     WebSocket handshake under the `WS` pseudo-verb rather than its literal `GET`);
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
/// The equivalence is one of **verdict**, not of transport: this plane relays one request and one
/// response and cannot switch protocols, so a `101` from the upstream is relayed as the interim
/// response [`relay_response_head`] reads it as, and an upgrade the policy permits does not complete
/// here the way it does through a CONNECT. What it does share with the tunneled path is every gate
/// the upgrade passes through first — the `WS` opt-in and the credential-injection refusal below.
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
    let Some(AbsoluteForm {
        host,
        port,
        path,
        framing: Framing { chunked, body_len },
    }) = admit_absolute_form(
        &mut client,
        ctx,
        Plane::HttpsForward,
        RawRequest {
            head,
            head_bytes,
            method,
            target,
        },
        &creds.needles,
    )?
    else {
        return Ok(());
    };

    // 4d. A WebSocket handshake is decided under the `WS` pseudo-verb, as `serve_tunneled_request`
    //     decides one inside a tunnel: only a rule that names `WS` admits it — NOT an unrestricted
    //     `{*}` and NOT the read-by-default `{GET,HEAD}`. Deciding it as the literal `GET` it
    //     arrives as, which is what this plane did, handed the absolute form an upgrade the same
    //     launch's `CONNECT` would have refused `denied-method`: the opt-in is a property of the
    //     request, not of the transport that carried it here.
    //
    //     `verb` is what every *record* this plane leaves names — the verdict, the allow, the
    //     refusals, the stats and the `[notify] events.network` feed — which is the invariant
    //     `serve_tunneled_request` states in as many words ("the verdict, the log and the stats all
    //     name it"). It reached only the refusing paths here, so a WebSocket *denial* read `WS` and a
    //     WebSocket *allow* read `GET`, on a plane the agent chooses by sending its handshake in the
    //     absolute form. `method` stays the literal verb for the three things that are about the
    //     request on the wire rather than about the decision: the origin-form request line, the
    //     signer's `RequestFacts`, the response framing, and whether a lost connection may be
    //     retried. That split is why rebinding `method` outright, as the tunneled path does, is not
    //     available here.
    let ws_upgrade = is_websocket_upgrade(head);
    let verb = if ws_upgrade { "WS" } else { method };

    // 5. The verdict — the SAME `https` decision a `CONNECT` to this host gets ([`decide_https`]):
    //    same rules, same denial shapes, same parking for an undecided host. Only the answer differs,
    //    written on the plaintext client socket this form arrived on.
    let deciding: Option<Rule> = match decide_https(ctx, &host, port, &path, verb, AskPosture::Park)
    {
        Ok(rule) => rule,
        Err(refusal) => {
            return write_refusal(
                &mut client,
                refusal.status_line(),
                refusal.tag(),
                &refusal.message(ctx, &host, port, verb),
            );
        }
    };

    // 5b. The same refusal the tunneled plane makes, from the same `refuse_ws_into_injected_host`:
    //     a credential-injected host cannot also host a WebSocket, and the refusal comes before any
    //     egress so no `allow` is recorded. Reached only when a `{WS}` rule already permitted the
    //     upgrade — an upgrade to a non-`{WS}` host was denied by method above.
    if ws_upgrade
        && refuse_ws_into_injected_host(&mut client, ctx, &creds, &host, port, verb, &path)?
    {
        return Ok(());
    }

    // 6. Resolve host-side, then the SSRF guard against the deciding rule. A resolution failure for an
    //    allowed host is a clean 502, distinct from a refusal.
    let ip = match resolve_checked(
        ctx,
        crate::sandbox::control::Proto::Https,
        &host,
        port,
        Some(verb),
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
            Some(verb),
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
                    Some(verb),
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
                        Some(verb),
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
                Some(verb),
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
    let injected_names = injected_names(&injected);
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
        Err(e) => return refuse_upstream(&mut client, ctx, &host, port, verb, &path, e),
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
        Some(verb),
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
                    Some(verb),
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
                    Some(verb),
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
                Err(e) => return refuse_upstream(&mut client, ctx, &host, port, verb, &path, e),
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
        copy_exact(
            &mut tee_request_body(&mut client, capture.as_ref()),
            &mut upstream,
            body_len,
        )?;
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
    //     A reflected secret is masked only for a response from an injection-target host, by the
    //     same question the tunneled plane asks (`CredentialSet::masks_reflection_for`); it is
    //     decided before the head is read, because the masking covers the head as much as the body.
    let masks_reflection = creds.masks_reflection_for(&host);
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
        // upstream leg does or says it does.
        ClientLeg::Close,
    )?;
    // An upstream that closed without answering leaves nothing to relay, and an empty success would
    // be indistinguishable from a genuine zero-byte response — see the tunneled path.
    if resp_head.is_empty() {
        ctx.push_log(
            crate::sandbox::control::Proto::Https,
            &host,
            port,
            Some(verb),
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
        note_final_status(ctx, allow_seq, &creds, &injected_ids, code);
    }
    // Count upstream→client (`down`) through the body; the head was counted as it was relayed.
    // Teed ahead of the reflection masking — the capture masks its own buffers at filing time.
    let mut framed = FramedBody::new(&mut up_br, framing);
    {
        let counted = CountingReader::new(&mut framed, flow.down.clone());
        let mut response = tee_response(counted, capture.as_ref());
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

/// Tests for what this plane decides *before* it opens anything upstream — the gates an absolute-form
/// request passes on its way to a verdict, driven through [`handle_https_forward`] itself over a
/// socket pair.
#[cfg(test)]
mod tests {
    use super::*;
    use crate::allowlist::{EgressPolicy, classify};
    use std::io::Read;

    /// Serve one absolute-form request under `rules` and `injections`, and return what the client
    /// read back. The resolver answers loopback, so a request the policy *permits* ends at its own
    /// connection rather than at a name lookup — no listener, and no test that passes by refusing
    /// everything.
    fn served(rules: &[&str], injections: Vec<HeaderInjection>, request: &str) -> String {
        let ctx = ProxyCtx::new(
            Arc::new(Ca::ephemeral().unwrap()),
            EgressPolicy::new(rules.iter().map(|r| classify(r).unwrap()).collect(), vec![]),
        )
        .unwrap()
        .with_injections(injections)
        .with_resolver(Box::new(|_| {
            Ok(vec![std::net::IpAddr::from([127, 0, 0, 1])])
        }));
        let (client, mut peer) = UnixStream::pair().unwrap();
        let bytes = request.as_bytes().to_vec();
        let head = parse_head(&bytes).unwrap();
        let (method, target) = request_line_parts(&head.request_line).unwrap();
        handle_https_forward(client, &head, &bytes, &method, &target, &ctx).unwrap();
        let mut transcript = String::new();
        peer.read_to_string(&mut transcript).unwrap();
        transcript
    }

    /// An absolute-form WebSocket handshake to `host` on port 9 (discard: a permitted request ends
    /// at a refused connection, immediately and without a listener).
    fn upgrade_to(host: &str) -> String {
        format!(
            "GET https://{host}:9/socket HTTP/1.1\r\nHost: {host}:9\r\nUpgrade: websocket\r\n\
             Connection: Upgrade\r\nSec-WebSocket-Version: 13\r\n\r\n"
        )
    }

    #[test]
    fn an_absolute_form_upgrade_is_decided_under_the_ws_pseudo_verb() {
        // `{GET}` is not `{WS}`: the same handshake through a CONNECT reads `denied-method`, and this
        // plane claims that verdict. Decided as its literal `GET`, which is what it did, an
        // unrestricted-method or read-by-default rule admitted an upgrade nobody opted into.
        let transcript = served(
            &["{GET} ws-host.test:*"],
            vec![],
            &upgrade_to("ws-host.test"),
        );
        assert!(
            transcript.contains("403") && transcript.contains("denied-method"),
            "an upgrade to a host with no `WS` rule must be refused by method: {transcript:?}"
        );

        // The guard is not "refuse everything": the same rule still admits the plain `GET` it names,
        // which then gets as far as its own connection.
        let transcript = served(
            &["{GET} ws-host.test:*"],
            vec![],
            "GET https://ws-host.test:9/socket HTTP/1.1\r\nHost: ws-host.test:9\r\n\r\n",
        );
        assert!(
            !transcript.contains("denied-method"),
            "a plain GET the rule names is not a WebSocket: {transcript:?}"
        );

        // And a `WS` rule admits the upgrade the launch opted into.
        let transcript = served(
            &["{WS} ws-host.test:*"],
            vec![],
            &upgrade_to("ws-host.test"),
        );
        assert!(
            !transcript.contains("denied-method"),
            "a `{{WS}}` rule is what admits an upgrade: {transcript:?}"
        );
    }

    /// A one-shot loopback TLS upstream: its own ephemeral CA mints a leaf for whatever SNI is
    /// asked for, it reads the request head and replies with `response`. Returns the port it is on
    /// and the CA the proxy must trust to validate it.
    fn spawn_https_upstream(
        response: &'static [u8],
    ) -> (u16, rustls::pki_types::CertificateDer<'static>) {
        let ca = Arc::new(Ca::ephemeral().unwrap());
        let ca_der = ca.ca_cert_der();
        let server_config = Arc::new(
            rustls::ServerConfig::builder()
                .with_no_client_auth()
                .with_cert_resolver(Arc::new(super::super::ca::CertResolver::new(ca))),
        );
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        std::thread::spawn(move || {
            let Ok((sock, _)) = listener.accept() else {
                return;
            };
            let Ok(conn) = ServerConnection::new(server_config) else {
                return;
            };
            let mut tls = StreamOwned::new(conn, sock);
            {
                let mut br = BufReader::new(&mut tls);
                let mut line = String::new();
                loop {
                    line.clear();
                    match br.read_line(&mut line) {
                        Ok(0) | Err(_) => return,
                        Ok(_) if line == "\r\n" || line == "\n" => break,
                        Ok(_) => {}
                    }
                }
            }
            let _ = tls.write_all(response);
            let _ = tls.flush();
            // Read to the client's close before letting the socket go: closing one that still holds
            // unread received data makes Linux send an RST, which discards the response just
            // written.
            let _ = tls.sock.set_read_timeout(Some(Duration::from_secs(30)));
            let mut rest = Vec::new();
            let _ = tls.read_to_end(&mut rest);
        });
        (port, ca_der)
    }

    /// A WebSocket handshake this plane *allows* is recorded under `WS`, exactly as one it refuses.
    ///
    /// `verb` reached the verdict and every refusing path, and the literal `method` reached
    /// everything else — so a `{WS}`-admitted upgrade was logged, counted and announced as a plain
    /// `GET`, while the identical handshake through a `CONNECT` was attributed. The agent chooses
    /// which transport carries its handshake, so this was a reporting channel it picked. The
    /// tunneled path states the invariant in as many words: the verdict, the log and the stats all
    /// name it.
    ///
    /// Driven to a real TLS upstream because the one `allow` record is written *after* the upstream
    /// handshake succeeds — every refusal-only harness above stops short of it.
    #[test]
    fn an_absolute_form_upgrade_that_is_allowed_is_recorded_under_the_ws_pseudo_verb() {
        use crate::sandbox::control::{LOG_RING_CAP, LogRing, LogVerdict};
        use crate::sandbox::egress_stats::EgressStats;
        use crate::testutil::TmpDir;

        let (port, upstream_ca) = spawn_https_upstream(
            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
        );
        let mut roots = rustls::RootCertStore::empty();
        roots.add(upstream_ca).unwrap();
        let upstream_cfg = Arc::new(
            rustls::ClientConfig::builder()
                .with_root_certificates(roots)
                .with_no_client_auth(),
        );
        let dir = TmpDir::new();
        let stats = Arc::new(EgressStats::new(dir.join("stats"), "/t".into(), None));
        let log = Arc::new(LogRing::new(LOG_RING_CAP));
        let ctx = ProxyCtx::new(
            Arc::new(Ca::ephemeral().unwrap()),
            EgressPolicy::new(vec![classify("{WS} ws-host.test:*").unwrap()], vec![]),
        )
        .unwrap()
        .with_upstream(upstream_cfg)
        .with_stats(Arc::clone(&stats))
        .with_log(Arc::clone(&log))
        // loopback, permitted only because the deciding rule names this exact host
        .with_resolver(Box::new(|_| Ok(vec![IpAddr::from([127, 0, 0, 1])])));

        let request = format!(
            "GET https://ws-host.test:{port}/socket HTTP/1.1\r\nHost: ws-host.test:{port}\r\n\
             Upgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 13\r\n\r\n"
        );
        let bytes = request.into_bytes();
        let head = parse_head(&bytes).unwrap();
        let (method, target) = request_line_parts(&head.request_line).unwrap();
        let (client, mut peer) = UnixStream::pair().unwrap();
        handle_https_forward(client, &head, &bytes, &method, &target, &ctx).unwrap();
        let mut transcript = String::new();
        peer.read_to_string(&mut transcript).unwrap();
        assert!(
            transcript.contains("200 OK"),
            "the upgrade had to be admitted and forwarded for there to be an allow: {transcript:?}"
        );

        let events = log.snapshot(None, None, false).events;
        assert_eq!(events.len(), 1, "one exchange, one event: {events:?}");
        assert_eq!(events[0].verdict, LogVerdict::Allow);
        assert_eq!(
            events[0].method.as_deref(),
            Some("WS"),
            "the one `allow` record must name the verb the verdict was reached under"
        );
        assert_eq!(stats.snapshot()["ws-host.test"].allow, 1);
    }

    #[test]
    fn an_absolute_form_upgrade_to_a_credential_injected_host_is_refused() {
        // The tunneled path's rule, which this plane states it shares: the injected secret rides the
        // handshake, and the frames that follow it cannot be redacted.
        let transcript = served(
            &["{WS} secret-host.test:*"],
            vec![HeaderInjection::fixed(
                classify("secret-host.test:*").unwrap(),
                "Authorization".to_string(),
                "Bearer s3cr3t".to_string(),
            )],
            &upgrade_to("secret-host.test"),
        );
        assert!(
            transcript.contains("403") && transcript.contains("ws-injection-refused"),
            "a credential-injected WebSocket must be refused: {transcript:?}"
        );
        assert!(
            !transcript.contains("s3cr3t"),
            "and the refusal carries no part of the credential: {transcript:?}"
        );
    }
}
