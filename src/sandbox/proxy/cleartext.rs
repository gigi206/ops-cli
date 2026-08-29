//! The inspected-cleartext (`http://`) plane.
//!
//! A client whose `http_proxy` points here sends an absolute-form request with no CONNECT, and an
//! `http://` allow rule may permit it. The same HTTP policy as the tunneled plane, on a connection
//! that was never encrypted.

use super::*;

/// Handle an **inspected-cleartext** (`http://`) request: the client sent an absolute-form request
/// (`GET http://host/path HTTP/1.1`) because its `http_proxy` points here, and an `http://` allow
/// rule may permit it. This is the plaintext sibling of the MITM path — the *same* HTTP policy (host
/// / port / path / method / the outbound-secret tripwire / the SSRF guard), but on a connection with
/// **no TLS**: no CONNECT tunnel, no leaf minted, no upstream certificate to validate, and — because
/// a bearer must never travel in the clear — **no credential injection** (a secret host can only be
/// an inspected-over-TLS `to`, so `egress::resolve_injections` is skipped entirely, not merely
/// trusted to return empty). Injection and *observation* part company here: this plane injects
/// nothing and still calls [`Credentials::observe_head`], because what it learns is what scopes that
/// value on every other plane. The request is forwarded to the origin server in **origin-form** with
/// the client's own `Host`, and the one response is streamed back. Every failure path is fail-closed
/// with the same [`write_refusal`] reason categories the MITM path uses, so the agent tells a policy
/// refusal from an unreachable host. `head_bytes` is the raw head (for the byte-exact secret
/// tripwire); `head` is its parse.
pub(super) fn handle_cleartext(
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
        framing: Framing { body_len, .. },
    }) = admit_absolute_form(
        &mut client,
        ctx,
        Plane::Cleartext,
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

    // 5. The verdict — cleartext is strictly opt-in, so only an explicit `http://` allow rule permits
    //    it (`explain_clear` never consults the default action or parks; deny wins layer-agnostically).
    //    Evaluated against the effective policy, so an `http://` rule loaded live with `sbx net allow
    //    http://host --session` opens it too. The two denial shapes get distinct reasons, and the
    //    `denied-default` suggestion names the `http://` scheme and, past port 80, the port too
    //    (a bare `sbx net allow host` would add an https/443 rule that does not open the clear, and
    //    a scheme with no port would open 80 rather than the port that was refused) — spelled by the
    //    one shared [`rule_destination`], which the notification for this same refusal also reads.
    let policy = effective_policy(ctx);
    let deciding: Rule = match policy.explain_clear(&host, port, &path, method) {
        Decision::AllowedBy(rule) => rule.clone(),
        Decision::DeniedBy(_) => {
            ctx.outcome(
                crate::sandbox::control::Proto::Http,
                &host,
                port,
                Some(method),
                Some(&path),
                StatKind::Deny,
                "denied-by-rule",
            );
            return write_refusal(
                &mut client,
                "403 Forbidden",
                "denied-by-rule",
                "this request matches a deny rule in the network policy",
            );
        }
        // `DeniedDefault` (nothing opened it) — and, defensively, any verdict `explain_clear` does not
        // return (it never yields an allow-default or ask): all fail closed as a deny-default refusal.
        _ => {
            let method_denied = policy.method_denied_clear(&host, port, &path, method);
            let reason = if method_denied {
                "denied-method"
            } else {
                "denied-default"
            };
            ctx.outcome(
                crate::sandbox::control::Proto::Http,
                &host,
                port,
                Some(method),
                Some(&path),
                StatKind::Deny,
                reason,
            );
            if method_denied {
                return write_refusal(
                    &mut client,
                    "403 Forbidden",
                    "denied-method",
                    &format!(
                        "the `{method}` method is not permitted to `http://{host}:{port}` by the \
                         network policy"
                    ),
                );
            }
            return write_refusal(
                &mut client,
                "403 Forbidden",
                "denied-default",
                &format!(
                    "cleartext `http://{host}:{port}` is not allowed by the network policy. \
                     Allow it: {}",
                    ctx.allow_suggestion(&rule_destination(
                        crate::sandbox::control::Proto::Http,
                        &host,
                        port
                    ))
                ),
            );
        }
    };

    // 6. Resolve host-side, then the SSRF guard against the deciding rule (a private/metadata address
    //    is refused unless the `http://` rule names this exact host). A resolution failure for an
    //    allowed host is a clean 502, distinct from a refusal.
    let ip = match resolve_checked(
        ctx,
        crate::sandbox::control::Proto::Http,
        &host,
        port,
        Some(method),
        Some(&path),
        Some(&deciding),
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

    // 6b. Remember any credential the cage sent for itself, in the same place the other inspected
    //     planes put it: after the verdict (a refused request must not seed the scan set), after the
    //     outbound scan (a request is never refused by the value it just taught sbx), and after the
    //     SSRF guard, which is the last refusal before the wire. The names to exclude are empty here,
    //     and that is a property of this plane rather than a shortcut: it skips `matching_injection_ids`
    //     entirely because a bearer must not travel in the clear, so no header is being replaced and
    //     none has to be held back from observation.
    //
    //     This plane has to observe for the same reason it has to tripwire: what it learns protects
    //     the *other* planes. A token the cage sends here is already exposed on this hop, but until it
    //     is a needle, re-sending it over TLS to a different host is not refused. Learning it is what
    //     scopes it to the destination it was acquired on.
    ctx.credentials.observe_head(&head.headers, &[], &host);

    // 7. Open the plaintext upstream to the checked address (no TLS, no certificate — an `http://`
    //    connection is cleartext by definition; the empty netns + the allowlist are the boundary).
    let mut upstream = match TcpStream::connect((ip, port)) {
        Ok(s) => {
            let _ = s.set_read_timeout(Some(ctx.timeout));
            let _ = s.set_write_timeout(Some(ctx.timeout));
            // Nagle off, for the reason `connect_upstream` states: this path writes a head and
            // then streams a body, and the second write would wait on a delayed ACK.
            let _ = s.set_nodelay(true);
            s
        }
        Err(_) => {
            ctx.push_log(
                crate::sandbox::control::Proto::Http,
                &host,
                port,
                Some(method),
                Some(&path),
                crate::sandbox::control::LogVerdict::Error,
                "upstream-unreachable",
            );
            return write_refusal(
                &mut client,
                "502 Bad Gateway",
                "upstream-unreachable",
                &format!("`{host}:{port}` is allowed but could not be reached"),
            );
        }
    };

    // The request is permitted and the upstream is up — record the one `allow` outcome here.
    let allow_seq = ctx.outcome_l7(
        crate::sandbox::control::Proto::Http,
        crate::sandbox::control::HttpVer::H1,
        // Cleartext is always HTTP/1.1; a gRPC/Connect-streaming content-type still tags (rare over
        // cleartext, but honest if it occurs).
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

    // Register the open cleartext tunnel for `sbx net live` until this function returns (the tunnel
    // closes). This is inspected cleartext, so the byte counters reflect application data.
    let flow = ctx.register_flow(&host, port, crate::sandbox::control::Proto::Http);

    // Open the traffic capture, recording the client's own head. No credential is ever injected on
    // a cleartext request, so no injected names accompany it. What is forwarded is not this byte for
    // byte: `reserialize_request` writes out what sbx parsed, which drops the hop-by-hop headers
    // (`Connection`, `Proxy-Connection`, `Proxy-Authorization`, `Expect`) and states its own
    // `Connection: close`. What the capture answers is what the client sent.
    let capture = ctx.begin_capture(allow_seq);
    if let Some(c) = &capture {
        c.set_request(head_bytes, &[]);
    }

    // 8. Forward the request in **origin-form** (`GET /path HTTP/1.1`) with the client's `Host` — an
    //    origin server, unlike a proxy, expects the path, not the absolute-form URL. No credential is
    //    injected (a header secret never rides a cleartext request). `Connection: close` is forced so
    //    the upstream closes after the one response (the reserializer strips hop-by-hop headers).
    let version = head
        .request_line
        .split_whitespace()
        .nth(2)
        .unwrap_or("HTTP/1.1");
    let origin = Head {
        request_line: format!("{method} {path} {version}"),
        headers: head.headers.clone(),
    };
    // Never reused: reuse exists to amortize a TLS handshake, and a cleartext leg has none to save.
    let reserialized = reserialize_request(&origin, &[], None, false);
    upstream.write_all(&reserialized)?;
    flow.up
        .fetch_add(reserialized.len() as u64, Ordering::Relaxed);
    if body_len > 0 && head_expects_continue(head) {
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

    // The request is permitted and fully forwarded; the response may now idle between bursts, so
    // lift the upstream read timeout for the relay below (same rationale as the tunneled path).
    begin_response_stream(&upstream);

    // 9. Relay the response head, then stream its framed body to the client and close. Inbound
    //    masking is scoped to the responses of an injection-target host, and a cleartext host is
    //    never one, so this response is relayed unredacted by the *same* rule the other planes apply
    //    rather than a weaker one (`masks_reflection`, on the inspected-TLS path, asks exactly this
    //    question). What that leaves open is narrow and deliberate: a value observed at step 6b can
    //    name a cleartext host, so that host reflecting it back is not masked. Masking every host's
    //    response instead would scan every body of every allowed request, which is the cost the
    //    scoping decision exists to avoid.
    let mut up_br = BufReader::new(upstream);
    let RelayedHead {
        head: resp_head,
        framing,
        ..
    } = relay_response_head(
        &mut up_br,
        &mut client,
        &flow.down,
        capture.as_ref(),
        &[],
        method,
        // One request per connection on this plane, so the client is told `close` in sbx's own
        // words rather than in whatever the upstream chose to answer.
        ClientLeg::Close,
    )?;
    if let Some(code) = parse_status_code(&resp_head)
        && code >= 200
    {
        ctx.set_status(allow_seq, code);
    }
    // Count upstream→client (`down`) through the body; the head was counted as it was relayed.
    let response = CountingReader::new(FramedBody::new(up_br, framing), flow.down.clone());
    let mut response: Box<dyn Read + '_> = match &capture {
        Some(c) => Box::new(CaptureReader::new(response, c.response_sink())),
        None => Box::new(response),
    };
    pump_to_eof(&mut response, &mut client)
}
