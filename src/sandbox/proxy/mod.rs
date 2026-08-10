//! The host-side egress proxy: a TLS-terminating filtering proxy that is the cage's only
//! path to the network under a filtered-egress posture (`[network] mode = "deny"`, `"allow"`, or
//! `"ask"`).
//!
//! The cage runs in an empty network namespace, so its sole egress is a Unix socket bound
//! into it; an in-cage forwarder bridges the tool's `http_proxy`/`https_proxy` to this host
//! process, which is the only one with real network access — and the only place the allowlist
//! is enforced (deny-by-construction). To filter by path (not just host), the proxy must see
//! inside the TLS tunnel, so it man-in-the-middles every CONNECT: it presents a leaf certificate
//! it mints on the fly for the requested host, signed by an **ephemeral, per-session CA** whose
//! certificate is trusted **only inside the cage** (never the host's trust store). It then reads
//! the real request, decides it against the [`crate::allowlist`] policy, and — when permitted —
//! opens its own TLS connection to the true upstream, validating that upstream against the
//! bundled root store so the interception never downgrades transport security.
//!
//! ## L4 (`tcp://`) raw splice
//!
//! A `tcp://` allow rule selects a **raw L4 splice** instead of inspection: at CONNECT time (on
//! host:port alone, [`crate::allowlist::EgressPolicy::l4_decision`]) the proxy accepts the tunnel
//! and copies the TCP byte stream verbatim to the upstream, without terminating TLS or parsing
//! anything ([`splice_l4`]). This carries a non-HTTP protocol (SSH, a database wire protocol) that
//! cannot be man-in-the-middled. A spliced flow keeps the controls a raw stream can bear — the empty
//! netns, host-side DNS, the host:port allowlist, the SSRF guard, and a concurrent-splice cap — but
//! **loses** path/method matching, Host/SNI anti-fronting, and the secret tripwires (there is no HTTP
//! to inspect). It is strictly opt-in: a host with no `tcp://` rule is always inspected (the MITM
//! path below). The split is decided pre-decrypt, so the splice and the MITM never both run for one
//! connection.
//!
//! ## L7 cleartext (`http://`)
//!
//! An `http://` allow rule permits **inspected cleartext**: a tool with `http_proxy` set sends an
//! absolute-form request (`GET http://host/path HTTP/1.1`, no CONNECT) for an `http://` URL, and
//! [`handle_cleartext`] applies the *same* HTTP policy as the MITM path — host / port / path / method
//! matching, the anti-fronting `Host` check, the outbound-secret tripwire, and the SSRF guard — on a
//! plaintext connection. There is no TLS to terminate, so nothing is decrypted, no leaf is minted, and
//! the upstream is reached over plain TCP with no certificate to validate; the request is forwarded in
//! origin-form and the one response streamed back. It is **strictly opt-in** exactly like the splice
//! (only an explicit `http://` allow enables it; the default action never opens it), and it forgoes
//! **credential injection** — a header secret is never sent in the clear (a secret `to` must be an
//! inspected-over-TLS host). Its one cost versus the default path is transport confidentiality (the
//! bytes travel unencrypted); the empty netns + allowlist boundary is unchanged.
//!
//! ## L7 forward (absolute-form `https://`)
//!
//! Some clients (a bundled proxy library, or a "secure web proxy" configuration) reach an `https://`
//! URL by sending an **absolute-form request straight to the proxy** — `POST https://host/path
//! HTTP/1.1`, no CONNECT — expecting the proxy to make the outbound TLS connection. Without a home
//! this is refused `405`, stranding such a tool (observed: the Kiro IDE's OAuth token exchange).
//! [`handle_https_forward`] serves it as the plaintext-client sibling of the MITM path: the
//! client→proxy leg is cleartext (the cage loopback), but the verdict is the *ordinary* `https` policy
//! ([`EgressPolicy::explain`](crate::allowlist::EgressPolicy::explain), NOT the opt-in `http://` scheme — so a normal allow rule covers it,
//! exactly as an equivalent `CONNECT` would, `ask` park included), the upstream leg is a **validated
//! TLS** connection (a forged upstream is a `502`, never downgraded), and — unlike the cleartext path
//! — a host-scoped **credential IS injected** (it rides only the encrypted upstream leg, and a
//! reflected value is masked out of the response).
//!
//! The residual is *not* confidentiality on the client leg: that leg is a loopback socket inside the
//! cage, which no cage process can read (no `CAP_NET_RAW` for a packet socket, and `ptrace` is on the
//! seccomp denylist). It is that this transport, like the tunneled one, **does not authenticate its
//! client** — any process in the cage can drive the injected credential to the allowlisted host. That
//! is the already-accepted property of host-side injection, not something this path adds: the bound
//! is the empty netns plus the allowlist plus the `to`-scoping of the credential.
//!
//! This module is the serve loop; the surrounding pieces live in focused submodules — the cert
//! machinery in [`ca`], the running context and policy in [`ctx`], name resolution in [`dns`], the
//! SSRF guard in [`ssrf`], the credential/needle types in [`inject`], and the HTTP/2 (gRPC) branch
//! in [`h2mitm`]. [`super::egress`] wires it into a launch (binding the socket into the cage,
//! injecting the CA into the cage trust store, supervising its lifetime under the
//! network-allowlist posture).
//!
//! ## Refusal reasons
//!
//! Every refusal the proxy *itself* issues (as opposed to a genuine upstream response it relays
//! verbatim) carries an `X-Sbx-Egress-Reason` header with a stable category token, plus a short
//! `text/plain` body repeating it — so the agent can tell an explicit policy refusal from an
//! unreachable host or a name that did not resolve, instead of an opaque status or a dropped
//! connection. The categories:
//!
//! | Status | `X-Sbx-Egress-Reason` | Meaning |
//! |---|---|---|
//! | `403` | `denied-default`         | no allow rule matched the host / port / path |
//! | `403` | `denied-by-rule`         | a deny rule matched (the rule text is not disclosed) |
//! | `403` | `denied-method`          | an allow rule matched the host but not the request's HTTP method (a `{VERB}`-scoped rule) |
//! | `403` | `asked-denied`           | the `ask` posture parked the request and it was not allowed — deliberately conflating an explicit `sbx net pending deny`, the ask timeout, and the pending-queue cap (all three mean "no egress" in Mode B) |
//! | `403` | `ssrf-blocked`           | the host resolved only to private / metadata addresses |
//! | `403` | `ip-literal`             | the CONNECT target was an IP literal on the inspected path (allow it raw with a `tcp://` rule) |
//! | `403` | `outbound-secret`        | the request head carried a configured secret value verbatim (leak refused) |
//! | `503` | `splice-cap`             | the concurrent raw (`tcp://`) tunnel cap was reached (retry when one closes) |
//! | `421` | `host-mismatch`          | the TLS SNI or `Host` header disagreed with the CONNECT target (or, on an absolute-form request, with the request-line host) |
//! | `400` | `bad-request`            | the request was malformed or used ambiguous framing. The reason is sub-categorized: `bad-request:transfer-encoding` (a coding other than `chunked`), `bad-request:dup-content-length`, `bad-request:dup-host`, `bad-request:invalid-content-length`, or `bad-request:chunked` (a `Transfer-Encoding: chunked` body that was malformed or over the proxy cap). A well-formed `chunked` request is de-chunked and re-framed with a synthesized `Content-Length` (not refused) |
//! | `405` | `method-not-allowed`     | a non-CONNECT request that is neither a routable `http://` nor `https://` absolute-form (a bare origin-form has no destination) |
//! | `502` | `dns-failure`            | DNS resolution failed for an allowed host |
//! | `502` | `upstream-unreachable`   | the host is allowed but the TCP connection failed |
//! | `502` | `upstream-cert-rejected` | the upstream TLS certificate failed validation (never downgraded) |
//!
//! A genuine upstream status (e.g. a `404`) is streamed back unchanged and carries no such
//! header — save that a reflected secret is masked out of it on the way back (see *Credential
//! injection* below), which never changes the status or the framing. Raw transport breakage — a
//! peer that closed early, an unparseable CONNECT, or a failure mid-response — closes the
//! connection with no status, there being no well-formed HTTP peer to answer. The category and body echo only what the agent already sent (its own host /
//! port) or a fixed token; they never disclose the injected credential, a host-side secret, or
//! the policy's internal rule text (for the deciding rule, `sbx test net` is the host-side tool).
//!
//! Whether the agent *surfaces* the reason depends on its tool: a raw-HTTP client or `curl -i`
//! shows the header and body, while a tool like `nix` reports the status code — but the coarse
//! class is already informative (an explicit `403` refusal vs a `502` unreachable vs a relayed
//! `404`), which is the distinction the reasons sharpen.
//!
//! ## Credential injection
//!
//! Under a configured `[secret]` entry, the proxy injects a host-scoped HTTP header into an allowed
//! request ([`HeaderInjection`]): the plaintext is read host-side at launch and never enters the
//! cage, and the injection fires only *after* the verdict and only for the concrete host (and
//! path) the secret was scoped to, replacing any client-supplied copy of the header. The
//! guarantee is precise: **no plaintext secret ever lives in the cage at rest, and the credential
//! can only egress to the one declared host**. It is *not* "the agent can never obtain the value"
//! — if that host *reflects* the header back (an echo/debug endpoint, or a compromised-but-
//! allowlisted host), the response carries it into the cage. Bounding egress to a single concrete
//! `to` host is what keeps that the agent's own narrow blast radius rather than arbitrary
//! exfiltration; the two tripwires below — one outbound, one inbound — are the backstops around it.
//!
//! An **outbound** tripwire complements the host scoping: the proxy scans each decrypted request
//! *head* for any configured secret's value ([`SecretNeedle`]) and **refuses** the request
//! (`outbound-secret`) — block, never strip — when it carries one verbatim, so a secret the agent
//! *did* obtain (a reflection, an out-of-band leak) cannot be re-sent in the clear to any allowed
//! host. It is deliberately a *tripwire, not a wall*: it inspects the head only (not the streamed
//! body) and matches the value byte-for-byte (any encoding evades it), so the load-bearing boundary
//! stays the empty netns plus the egress allowlist — this only catches naive verbatim re-exfil. Two
//! named residuals: the distinct `outbound-secret` reason is a weak *confirmation oracle* (it tells
//! a prober that an exact byte string is a configured secret), defanged by a high-entropy value plus
//! the resolution-side minimum length — kept distinct deliberately so a legitimately-confused agent
//! is not blinded; and a secret value that happens to be a substring of legitimate traffic on the
//! always-on built-in lane would refuse that request (low-probability, length-mitigated, nonzero).
//!
//! An **inbound** tripwire closes the reflection itself: when the response comes from a host an
//! injection targets — the only place a configured secret can re-enter the cage by reflection — the
//! proxy masks every verbatim occurrence of the value out of the relayed response, replacing it with
//! an equal-length run of `*` ([`pump_redacting`]). So the agent receives the legitimate response
//! content with the credential struck out, never the plaintext. It is scoped to injection-target
//! responses precisely so the always-on built-in downloads are streamed untouched and the
//! mutate-on-match cannot corrupt unrelated traffic. The action differs from the outbound tripwire's
//! — mask here, refuse there — not from a different security claim but because the response also
//! carries content the agent legitimately needs, so refusing it would deny a real result; both are
//! the *same backstop class* with the *same evasion* (a re-encoded, compressed, or framing-split
//! value slips past), and neither is the boundary. Its residual is *corruption-on-collision*: unlike
//! the outbound refusal, masking mutates the stream, so a secret value that coincided with bytes of
//! a legitimate injection-host response would be struck out of it — again entropy- and
//! minimum-length-mitigated, and confined to the one injection-target host.

use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::{IpAddr, TcpStream};
use std::os::unix::io::AsRawFd;
use std::os::unix::net::{UnixListener, UnixStream};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::Duration;

use rustls::{ClientConnection, ServerConnection, StreamOwned};

use crate::allowlist::{self, Decision, L4Decision, Rule};

use super::egress_stats::StatKind;

#[cfg(test)]
mod bench;
mod ca;
mod capture;
mod ctx;
mod dns;
mod h2mitm;
mod inject;
mod pool;
mod ssrf;
mod websocket;
mod wire;
pub(crate) use ca::Ca;
use ca::upstream_server_name;
use capture::{CaptureGuard, CaptureReader};
use ctx::effective_policy;
pub(crate) use ctx::{ProxyCtx, builtin_allow_rules, union_with_builtin};
pub(crate) use inject::{HeaderInjection, SecretNeedle};
use pool::{PoolKey, UpstreamTls};
pub(crate) use ssrf::{AddrRefusal, ip_refusal, names_exact_host};
use ssrf::{checked_address, resolve_checked};
use websocket::*;
use wire::*;

/// Serve the egress proxy on `listener` (the host end of the cage's bound socket), one thread per
/// connection. Each accepted stream gets the per-socket timeouts before it is handled, so a slow
/// or hung peer cannot pin a thread forever.
pub(crate) fn serve(listener: UnixListener, ctx: Arc<ProxyCtx>) -> io::Result<()> {
    for stream in listener.incoming() {
        let stream = match stream {
            Ok(s) => s,
            Err(e) => {
                // A transient accept error (host fd exhaustion, an aborted connection) must not
                // take the whole session's egress down — skip this connection and keep serving. A
                // short sleep avoids a hot spin if the condition persists.
                crate::diag::error(&format!("sbx: egress proxy: accept error: {e}"));
                std::thread::sleep(Duration::from_millis(20));
                continue;
            }
        };
        // Cap live connection threads: a new connection beyond the cap is refused (closed) rather
        // than spawned, so an in-cage agent cannot exhaust host threads/fds by opening connections
        // faster than they complete. The guard decrements on the handler thread's exit.
        if ctx.conns.load(Ordering::Relaxed) >= MAX_CONCURRENT_CONNS {
            drop(stream);
            continue;
        }
        ctx.conns.fetch_add(1, Ordering::Relaxed);
        let ctx = ctx.clone();
        std::thread::spawn(move || {
            struct ConnGuard<'a>(&'a AtomicUsize);
            impl Drop for ConnGuard<'_> {
                fn drop(&mut self) {
                    self.0.fetch_sub(1, Ordering::Relaxed);
                }
            }
            let _guard = ConnGuard(&ctx.conns);
            let _ = stream.set_read_timeout(Some(ctx.timeout));
            let _ = stream.set_write_timeout(Some(ctx.timeout));
            // an error on one connection is that connection's problem, never the proxy's
            let _ = handle_client(stream, &ctx);
        });
    }
    Ok(())
}

/// The most connection-handling threads alive at once. A connection beyond this is refused
/// (fail-closed) rather than spawned, bounding the host threads/fds an in-cage agent can tie up
/// (including a slowloris drip-feed that holds each thread through the per-read timeout window). Far
/// above any realistic concurrent-fetch workload from a single cage.
const MAX_CONCURRENT_CONNS: usize = 512;

/// The largest request head (CONNECT or the decrypted inner request) the proxy will buffer.
const HEAD_MAX: usize = 16 * 1024;

/// The most `ask`-posture requests parked at once. A new one beyond this is denied immediately
/// (fail-closed) rather than enqueued, so an in-cage agent cannot pin unbounded host threads by
/// opening connections that all park — the default ask wait being indefinite. Far above any
/// realistic interactive backlog.
const ASK_PENDING_CAP: usize = 256;

/// Handle one client connection: parse the CONNECT, man-in-the-middle the tunnel, read exactly
/// one inner request, decide it against the policy (with the host/SNI/Host triple agreeing and
/// the SSRF guard applied to the resolved address), and — when permitted — forward it to the
/// validated upstream and stream the response back. Every failure path is fail-closed, and each
/// returns a [`write_refusal`] reason (an `X-Sbx-Egress-Reason` category plus a text body) so the
/// agent can tell an explicit policy refusal from an unreachable host or a name that did not
/// resolve, instead of an opaque status or a dropped connection.
fn handle_client(mut client: UnixStream, ctx: &ProxyCtx) -> io::Result<()> {
    // 1. The CONNECT head, read byte-by-byte so the stream sits exactly at the TLS ClientHello
    //    (a buffered read would swallow the start of the handshake).
    let head = read_head_raw(&mut client, HEAD_MAX)?;
    let parsed = parse_head(&head)?;
    let Some((method, target)) = request_line_parts(&parsed.request_line) else {
        // A malformed request line carries no destination to attribute — log the attempt so it is
        // not dark, but with no host/method/path (the raw line may hold whitespace the wire format
        // cannot carry as a single field).
        ctx.push_log(
            super::control::Proto::Other,
            "",
            0,
            None,
            None,
            super::control::LogVerdict::Blocked,
            "bad-request",
        );
        return write_refusal(
            &mut client,
            "400 Bad Request",
            "bad-request",
            "the CONNECT request line is malformed",
        );
    };
    if method != "CONNECT" {
        // A client with `http_proxy` set sends an **absolute-form** request (`GET http://host/… HTTP/1.1`)
        // for an `http://` URL — no CONNECT. When an `http://` (cleartext L7) rule permits it, this is
        // the inspected-cleartext path; route it there. An absolute-form **`https://`** request (a
        // client treating the proxy as a TLS-terminating forward proxy — the "secure web proxy" form,
        // instead of CONNECT) is routed to the plaintext-client/validated-TLS-upstream forward, gated by
        // the ordinary `https` policy. Anything else (a bare origin-form with no host to route, or a bad
        // method) is refused fail-closed — the method + raw target are the "what is the agent trying to
        // do" signal, so log them (host blank, target as the path).
        if target.starts_with("http://") {
            return handle_cleartext(client, &parsed, &head, &method, &target, ctx);
        }
        if target.starts_with("https://") {
            return handle_https_forward(client, &parsed, &head, &method, &target, ctx);
        }
        ctx.push_log(
            super::control::Proto::Other,
            "",
            0,
            Some(method.as_str()),
            Some(target.as_str()),
            super::control::LogVerdict::Blocked,
            "method-not-allowed",
        );
        return write_refusal(
            &mut client,
            "405 Method Not Allowed",
            "method-not-allowed",
            "this egress proxy tunnels HTTPS (CONNECT), forwards allowed plaintext `http://` requests, \
             and forwards an allowed absolute-form `https://` request over a validated TLS upstream; a \
             bare origin-form request has no host to route",
        );
    }
    // 2. The CONNECT authority.
    let Some((host, port)) = split_authority(&target) else {
        // The authority is malformed (not host:port): log the raw target the agent asked for.
        ctx.push_log(
            super::control::Proto::Other,
            "",
            0,
            Some(method.as_str()),
            Some(target.as_str()),
            super::control::LogVerdict::Blocked,
            "bad-request",
        );
        return write_refusal(
            &mut client,
            "400 Bad Request",
            "bad-request",
            "the CONNECT authority must be host:port",
        );
    };
    let connect_host = allowlist::canonical_host(&host);

    // 2b. The enforcement-layer decision, made from host:port alone (pre-decrypt). A `tcp://` (L4)
    //     allow rule splices the connection raw — no TLS termination, no inspection — so this is
    //     decided before the IP-literal refusal (a raw splice needs no SNI, so an IP-literal target
    //     is fine for it). Anything else (the common case) falls through to the inspected L7 path.
    {
        let policy = effective_policy(ctx);
        if let L4Decision::Splice(rule) = policy.l4_decision(&connect_host, port) {
            return splice_l4(client, &connect_host, port, rule, ctx);
        }
    }

    // An IP-literal target carries no SNI to bind the minted leaf to, so the inspected L7 path
    // refuses it (a hostname target is required to MITM; only the raw splice above accepts an IP).
    if host.parse::<IpAddr>().is_ok() {
        // Log the attempt (host = the IP the agent tried to reach) before refusing. Pre-tunnel, so
        // there is no method/path yet.
        ctx.push_log(
            super::control::Proto::Https,
            &connect_host,
            port,
            None,
            None,
            super::control::LogVerdict::Blocked,
            "ip-literal",
        );
        return write_refusal(
            &mut client,
            "403 Forbidden",
            "ip-literal",
            "an IP-literal CONNECT target is refused for inspected egress; a hostname is required \
             (or allow it raw with a `tcp://` rule)",
        );
    }

    // A designated `[network] http2` host is man-in-the-middled as HTTP/2 (ALPN `h2`, for gRPC)
    // rather than HTTP/1.1. The whole h2 branch runs on a per-connection current-thread tokio runtime
    // confined to [`h2mitm`]; the synchronous HTTP/1.1 path below is untouched. Read from the config
    // policy — h2 selection is launch-static, not `--session`-overlaid.
    if ctx.policy.speaks_http2(&connect_host, port) {
        return h2mitm::handle(client, connect_host, port, ctx);
    }

    // 3. Accept the tunnel, then terminate TLS with a leaf minted for the SNI host.
    write_all_str(&mut client, "HTTP/1.1 200 Connection established\r\n\r\n")?;
    let server_conn = ServerConnection::new(ctx.server_config.clone()).map_err(io::Error::other)?;
    let mut br = BufReader::new(StreamOwned::new(server_conn, client));

    // 4. Read ONE inner request (this drives the handshake to completion, so the SNI is known
    //    afterwards); keep the SAME buffered reader for the body.
    let inner_bytes = read_head_buffered(&mut br, HEAD_MAX)?;
    let sni = br.get_ref().conn.server_name().map(|s| s.to_string());

    // CONNECT-host == SNI: the leaf was minted for the SNI, so a CONNECT to a different host is a
    // domain-fronting attempt.
    if sni
        .as_deref()
        .map(|s| allowlist::canonical_host(s) != connect_host)
        .unwrap_or(true)
    {
        // Pre-parse: the inner request is not decoded yet, so there is no method/path to log.
        ctx.outcome(
            super::control::Proto::Https,
            &connect_host,
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

    let inner = parse_head(&inner_bytes)?;
    let Some((imethod, itarget)) = request_line_parts(&inner.request_line) else {
        ctx.push_log(
            super::control::Proto::Https,
            &connect_host,
            port,
            None,
            None,
            super::control::LogVerdict::Blocked,
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
            super::control::Proto::Https,
            &connect_host,
            port,
            Some(&imethod),
            Some(&itarget),
            super::control::LogVerdict::Blocked,
            "bad-request",
        );
        return respond_refusal_tls(
            &mut br,
            "400 Bad Request",
            "bad-request",
            "the tunneled request target must be origin-form (a path)",
        );
    }
    // Anti request-smuggling, fail-closed. A duplicated Content-Length or Host is an unambiguous
    // desync vector and is refused outright. A `Transfer-Encoding` is refused UNLESS it is exactly
    // `chunked` — the one streaming coding the proxy de-chunks and re-frames with a synthesized
    // Content-Length below (so no CL/TE ambiguity reaches the upstream); any other TE coding is
    // unsupported and refused.
    let te = inner.header("transfer-encoding");
    let cl_count = inner.count("content-length");
    let host_count = inner.count("host");
    let chunked = match te.map(str::trim) {
        Some(v) if v.eq_ignore_ascii_case("chunked") => true,
        Some(_) => {
            ctx.push_log(
                super::control::Proto::Https,
                &connect_host,
                port,
                Some(&imethod),
                Some(&itarget),
                super::control::LogVerdict::Blocked,
                "bad-request:transfer-encoding",
            );
            return respond_refusal_tls(
                &mut br,
                "400 Bad Request",
                "bad-request:transfer-encoding",
                "the request carries a Transfer-Encoding coding other than `chunked`, which this \
                 egress proxy does not forward",
            );
        }
        None => false,
    };
    if cl_count > 1 || host_count > 1 {
        let (reason, detail) = if cl_count > 1 {
            (
                "bad-request:dup-content-length",
                "the request carries a duplicated Content-Length header",
            )
        } else {
            (
                "bad-request:dup-host",
                "the request carries a duplicated Host header",
            )
        };
        ctx.push_log(
            super::control::Proto::Https,
            &connect_host,
            port,
            Some(&imethod),
            Some(&itarget),
            super::control::LogVerdict::Blocked,
            reason,
        );
        return respond_refusal_tls(&mut br, "400 Bad Request", reason, detail);
    }
    // The body length is known up-front only for a Content-Length-framed request; a `chunked`
    // request's length is discovered by de-chunking below, so no Content-Length is parsed here.
    let body_len: u64 = if chunked {
        0
    } else {
        match inner.header("content-length") {
            Some(v) => match v.trim().parse() {
                Ok(n) => n,
                Err(_) => {
                    ctx.push_log(
                        super::control::Proto::Https,
                        &connect_host,
                        port,
                        Some(&imethod),
                        Some(&itarget),
                        super::control::LogVerdict::Blocked,
                        "bad-request:invalid-content-length",
                    );
                    return respond_refusal_tls(
                        &mut br,
                        "400 Bad Request",
                        "bad-request:invalid-content-length",
                        "the Content-Length header is not a valid number",
                    );
                }
            },
            None => 0,
        }
    };

    // CONNECT-host == Host header (== SNI, already checked): the decrypted Host must agree too.
    if inner
        .header("host")
        .map(|h| allowlist::canonical_host(&strip_port(h)) != connect_host)
        .unwrap_or(true)
    {
        ctx.outcome(
            super::control::Proto::Https,
            &connect_host,
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
    if carries_secret(&inner_bytes, &ctx.redactions) {
        ctx.outcome(
            super::control::Proto::Https,
            &connect_host,
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
        &connect_host,
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
                &refusal.message(ctx, &connect_host, port, &imethod),
            );
        }
    };

    // 5b. A credential-injected host cannot also host a WebSocket: the injected secret rides the
    //     handshake, but once the upgrade completes the frames are opaque and cannot be redacted, so
    //     a value the host reflects in a frame would re-enter the cage. Refuse fail-closed here —
    //     before any egress, so no `allow` is recorded — rather than open an unredactable channel
    //     that carries an injected secret. (Reached only when a `{WS}` rule already permitted the
    //     upgrade to this host; a WS to a non-`{WS}` host was denied by method above.)
    if ws_upgrade && !matching_injections(ctx, &connect_host, port, &itarget).is_empty() {
        ctx.outcome(
            super::control::Proto::Https,
            &connect_host,
            port,
            Some(&imethod),
            Some(&itarget),
            StatKind::Blocked,
            "ws-injection-refused",
        );
        return respond_refusal_tls(
            &mut br,
            "403 Forbidden",
            "ws-injection-refused",
            "a WebSocket to a credential-injected host is refused: its frames cannot be redacted",
        );
    }

    // 6. Resolve host-side, then the SSRF guard — one call, which records the refusal whichever way
    //    it goes. A resolution failure for an allowed host is a clean 502 (not a dropped
    //    connection), so the agent sees "the name did not resolve" rather than an ambiguous
    //    transport error.
    let ip = match resolve_checked(
        ctx,
        super::control::Proto::Https,
        &connect_host,
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
                &refusal.message(&connect_host),
            );
        }
    };

    // 7. Match this request's host-scoped credential injections. This runs *after* the verdict, so a
    //    denied request never receives a secret, and is keyed on the already-verified `connect_host`
    //    plus the decrypted path — so the credential reaches exactly the destination it was scoped
    //    to. A redirect to another host opens a new tunnel and re-runs this match, so the secret
    //    cannot ride along to an unintended host. It is settled before any connection is taken,
    //    because which credentials a request carries is half of what partitions the pool below.
    let injected_ids = matching_injection_ids(ctx, &connect_host, port, &itarget);
    let injected = injection_pairs(ctx, &injected_ids);

    // 7a. Whether this request may share its upstream leg with others. It takes a launch that asked
    //     for reuse, an HTTP/1.1 request (the version whose connections persist by default), and no
    //     protocol upgrade — an upgrade takes the connection over entirely. The key pairs the
    //     verified host and port with the exact credential set above, so a connection that carried a
    //     secret is only ever offered to a request that receives the same secret.
    let keep_alive = ctx.pool.is_some()
        && !ws_upgrade
        && inner.request_line.split_whitespace().nth(2) == Some("HTTP/1.1");
    let pool_key = keep_alive.then(|| PoolKey::new(&connect_host, port, &injected_ids));
    // Taking a parked connection is limited to a request the proxy can send a second time, because a
    // connection the upstream closed while it was parked only shows up after the write. That means a
    // request with no body, or a chunked one whose body the de-chunker buffers before forwarding; a
    // body streaming straight from the client is gone once written. Such a request opens its own
    // connection and still leaves it behind for the next one.
    let replayable = chunked || body_len == 0;

    // 7b. Take the upstream connection: a parked one, or a new one to the address just checked (not
    //     a re-resolve, which would reopen the rebinding window) with its certificate validated up
    //     front — a forged or self-signed upstream is refused, never passed through.
    let (mut upstream, mut from_pool) = match acquire_upstream(
        ctx,
        pool_key.as_ref().filter(|_| replayable),
        ip,
        port,
        &connect_host,
    ) {
        Ok(pair) => pair,
        Err(e) => {
            return refuse_upstream(
                br.get_mut(),
                ctx,
                &connect_host,
                port,
                &imethod,
                &itarget,
                e,
            );
        }
    };

    // The request is permitted and the upstream is up — it will now egress. Record the one `allow`
    // outcome here (a single count per request: a refusal above already returned, and the steps
    // below are I/O, not policy verdicts, so this is the sole place a forwarded request is counted).
    let allow_seq = ctx.outcome_l7(
        super::control::Proto::Https,
        super::control::HttpVer::H1,
        // The RPC framing from the inspected inner request's `Content-Type` (gRPC/gRPC-web/Connect
        // streaming); a plain or Connect-*unary* request classifies to `None`.
        super::control::RpcKind::from_content_type(
            inner.header("content-type").unwrap_or_default(),
        ),
        &connect_host,
        port,
        Some(&imethod),
        Some(&itarget),
        StatKind::Allow,
        "allowed",
    );

    // The tunnel is now open — register it for `sbx net live` until this connection returns (the
    // tunnel closes). One guard covers both the one-shot request/response below and a WebSocket
    // upgrade: a WS over TLS is still inspected TLS, so its proto stays `https`. The relay increments
    // the guard's byte counters as data flows (application-plaintext bytes on this inspected path).
    let flow = ctx.register_flow(&connect_host, port, super::control::Proto::Https);

    // 8a. Open the traffic capture for this exchange, when the launch captures. The request head
    //     recorded is the client's own (`inner_bytes`), taken before the reserialization below adds
    //     any injected credential — so a secret cannot reach the capture even in principle; only the
    //     injected header *names* are noted. The guard files on drop, so however this relay ends,
    //     what it saw is filed exactly once.
    let capture = ctx.begin_capture(allow_seq);
    if let Some(c) = &capture {
        c.set_request(&inner_bytes, &injected);
    }

    // 8b. A WebSocket upgrade cannot ride the one-shot request/response path below (which forces
    //     `Connection: close` and relays a single direction). The handshake was inspected by the same
    //     verdict as any request — host, path, method, anti-fronting, SSRF, upstream-cert — and the
    //     outbound-secret tripwire already ran on it above, so the allowlist governs which host/path
    //     may open a WebSocket. Hand it to the upgrade relay, which forwards it with its
    //     `Upgrade`/`Connection` headers preserved and, on a `101`, relays both TLS streams verbatim.
    //
    //     Two known properties of an opened WebSocket, deliberate and bounded to a low-volume agent
    //     stream (documented, not silent):
    //       - Posture: an upgrade is a `GET`, so it rides a `GET`/`{*}` allow. A read-only `{GET}` rule
    //         therefore permits opening a *bidirectional* channel to that host/path. This is accepted
    //         (the handshake is a legitimate GET and the host/path is still gated); a dedicated
    //         `ws://` opt-in scheme, if a read-only-should-forbid-WS case ever arises, is a future
    //         refinement, not a gap here.
    //       - Once opened, the framed bytes are relayed VERBATIM: they are NOT scanned by the
    //         response-side redaction ([`pump_redacting`]), so a secret a peer reflects inside a
    //         frame reaches the cage as it was sent. The boundary stays the empty netns + the
    //         allowlist + the inspected handshake. Masking a frame would mean rewriting the relayed
    //         stream (decode, mask, re-frame, re-mask), which is a far larger change to the one path
    //         that must stay a byte-exact pipe; the traffic capture decodes frames only to copy them
    //         aside, and masks its own buffers, without touching what is relayed.
    if ws_upgrade {
        // The capture follows the handshake into the upgrade relay, which files it at the `101` (it
        // cannot wait for a tunnel that may stay open for hours — see [`relay_upgrade`]).
        return relay_upgrade(
            br,
            upstream,
            &inner,
            &injected,
            ctx,
            allow_seq,
            capture.as_ref(),
            flow.up.clone(),
            flow.down.clone(),
        );
    }

    // 9. Forward this one request and stream the response back — a pipelined second request from the
    //    client is never forwarded, so it cannot skip the per-request check.
    //
    //    The forwarded bytes are materialized whenever the proxy still holds all of them (see
    //    `replayable` above): that is what lets a connection the upstream closed while it was parked
    //    cost a second attempt instead of an empty response. A body streaming straight from the
    //    client is gone once written, which is exactly why such a request never took a parked one.
    let forwarded: Option<Vec<u8>> = if chunked {
        // A `Transfer-Encoding: chunked` request: de-chunk the body into a bounded buffer and
        // forward a clean `Content-Length`-framed request (the `Transfer-Encoding` header is
        // stripped by `reserialize_request` when a length is forced), so no chunked framing — and
        // no CL/TE request-smuggling ambiguity — reaches the upstream. The cap bounds memory for
        // an agent prompt body (KB–MB); a larger chunked upload fails closed.
        //
        // Answer a client `Expect: 100-continue` before reading, else it withholds the body. A
        // de-chunk failure (malformed framing, or over the cap) is fail-closed: log + refuse 400
        // (the interim 100 already sent is harmless — a final 4xx may follow it on one connection).
        if head_expects_continue(&inner) {
            let client = br.get_mut();
            let _ = client.write_all(b"HTTP/1.1 100 Continue\r\n\r\n");
            let _ = client.flush();
        }
        let body = match read_chunked_body(&mut br, CHUNKED_REQUEST_CAP) {
            Ok(b) => b,
            Err(e) => {
                ctx.push_log(
                    super::control::Proto::Https,
                    &connect_host,
                    port,
                    Some(&imethod),
                    Some(&itarget),
                    super::control::LogVerdict::Blocked,
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
    } else if body_len == 0 {
        Some(reserialize_request(&inner, &injected, None, keep_alive))
    } else {
        None
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
                    super::control::Proto::Https,
                    &connect_host,
                    port,
                    Some(&imethod),
                    Some(&itarget),
                    super::control::LogVerdict::Error,
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
            let (fresh, _) = match acquire_upstream(ctx, None, ip, port, &connect_host) {
                Ok(pair) => pair,
                Err(e) => {
                    return refuse_upstream(
                        br.get_mut(),
                        ctx,
                        &connect_host,
                        port,
                        &imethod,
                        &itarget,
                        e,
                    );
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
        match &capture {
            Some(c) => copy_exact(
                &mut CaptureReader::new(&mut br, c.request_body_sink()),
                &mut upstream,
                body_len,
            )?,
            None => copy_exact(&mut br, &mut upstream, body_len)?,
        }
        // Count the forwarded body (`copy_exact` moved exactly `body_len` bytes upstream).
        flow.up.fetch_add(body_len, Ordering::Relaxed);
        upstream.flush().ok();
        // The request is permitted and fully forwarded; the response may now idle between bursts (a
        // streamed completion), so lift the upstream read timeout for the relay below.
        begin_response_stream(&upstream.sock);
    }

    // 9b. Response-side leak backstop: a configured secret can only re-enter the cage by being
    //     *reflected* by a host an injection targets (an echo/debug endpoint, or one that stores
    //     and later returns the credential). So mask the reflected value out of the response — but
    //     only for a response from such a host. Every other response (notably the large built-in
    //     downloads) is streamed untouched, which both avoids the scan cost and confines the
    //     mutate-on-match to the one host the reflection threat actually lives on. Decided here
    //     because it covers the head as much as the body, and the head is relayed first.
    let masks_reflection = !ctx.redactions.is_empty()
        && ctx
            .injections
            .iter()
            .any(|inj| names_exact_host(&connect_host, Some(&inj.rule)));
    let head_masking: &[SecretNeedle] = if masks_reflection {
        &ctx.redactions
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
    let (resp_head, complete) = relay_response_head(
        &mut up_br,
        br.get_mut(),
        &flow.down,
        capture.as_ref(),
        head_masking,
        keep_alive,
    )?;
    // An upstream that closed without answering leaves nothing to relay, and saying so is the honest
    // reply: an empty success is indistinguishable from a genuine zero-byte response, and it would
    // hide the one failure reuse can produce — a connection the far side closed in the window
    // between the pool's probe and the write.
    if resp_head.is_empty() {
        ctx.push_log(
            super::control::Proto::Https,
            &connect_host,
            port,
            Some(&imethod),
            Some(&itarget),
            super::control::LogVerdict::Error,
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
        ctx.set_status(allow_seq, code);
    }
    // A head the upstream never finished sending delimits nothing — relay the rest until it closes.
    let framing = if complete {
        response_framing(&resp_head, &imethod)
    } else {
        BodyFraming::ToEof
    };

    // 10. The body is teed on the way through, ahead of the reflection masking: the capture does its
    //     own masking at filing time (over whole buffers), so what is stored is masked either way,
    //     and what the cage receives is decided by `masks_reflection` alone (the head above was
    //     masked under the same decision). Counted upstream→client (`down`) through the body; the
    //     head was counted as it was relayed.
    let mut framed = FramedBody::new(&mut up_br, framing);
    {
        let response = CountingReader::new(&mut framed, flow.down.clone());
        let mut response: Box<dyn Read + '_> = match &capture {
            Some(c) => Box::new(CaptureReader::new(response, c.response_sink())),
            None => Box::new(response),
        };
        if masks_reflection {
            pump_redacting(&mut response, br.get_mut(), &ctx.redactions)?;
        } else {
            pump_to_eof(&mut response, br.get_mut())?;
        }
    }

    // 11. The response is over. Whether its connection may carry another request takes three answers,
    //     every one of them necessary: the body ended exactly where its framing said (a truncated one
    //     leaves the connection at an unknown position), nothing the head read pulled ahead is still
    //     buffered, and the response itself left the connection reusable. The pool settles the one
    //     remaining question — whether anything is pending on the socket — and closes the connection
    //     when the answer is no. This sits after the relay's `?`, so a relay that ended early parks
    //     nothing.
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
    // The response is fully relayed — close the intercepted TLS cleanly so the client sees a proper
    // end-of-stream, not a bare socket drop (the reported `without sending TLS close_notify`).
    finish_tls(br.get_mut());
    Ok(())
}

/// Parse the numeric HTTP status code from a response's opening bytes (`HTTP/1.1 200 OK\r\n`): the
/// token after the first space, if it is a plausible status (100–599). `None` for anything that is
/// not a well-formed HTTP/1.x status line (so a non-HTTP or truncated response records no status).
fn parse_status_code(prefix: &[u8]) -> Option<u16> {
    let line = prefix.split(|&b| b == b'\n').next()?;
    let text = std::str::from_utf8(line).ok()?;
    if !text.starts_with("HTTP/") {
        return None;
    }
    let code: u16 = text.split_whitespace().nth(1)?.parse().ok()?;
    (100..=599).contains(&code).then_some(code)
}

/// The most raw L4 (`tcp://`) splices open at once. Each one pins a host thread (and ~6 fds) for the
/// connection's lifetime — there is no per-request turnaround as on the inspected L7 path — so an
/// in-cage agent opening many would otherwise exhaust host threads. A new splice beyond this is
/// refused (a `503` `splice-cap`, pre-200, so the client sees a clean reason) rather than queued.
/// Generous for any realistic interactive use (SSH / database sessions), far below a thread bomb.
const MAX_CONCURRENT_SPLICES: usize = 128;

/// An RAII counter guard for the open-splice tally: it increments [`ProxyCtx::splices`] on
/// construction and decrements on drop, so every `splice_l4` exit (including the over-cap refusal and
/// every error path) releases its slot. [`Self::count`] reports the post-increment value, which the
/// caller checks against [`MAX_CONCURRENT_SPLICES`].
struct SpliceGuard<'a> {
    counter: &'a AtomicUsize,
    count: usize,
}

impl<'a> SpliceGuard<'a> {
    fn new(counter: &'a AtomicUsize) -> Self {
        let count = counter.fetch_add(1, Ordering::SeqCst) + 1;
        SpliceGuard { counter, count }
    }

    fn count(&self) -> usize {
        self.count
    }
}

impl Drop for SpliceGuard<'_> {
    fn drop(&mut self) {
        self.counter.fetch_sub(1, Ordering::SeqCst);
    }
}

/// Handle a raw L4 (`tcp://`) splice: a `tcp://` allow rule opted this host:port into an uninspected
/// tunnel ([`EgressPolicy::l4_decision`](crate::allowlist::EgressPolicy::l4_decision)). The connection keeps the controls a raw stream can carry —
/// the host:port allowlist (already matched), host-side DNS, the open-splice cap, and the SSRF guard
/// — but **loses** TLS termination, path/method matching, Host/SNI anti-fronting, and secret
/// redaction (there is no HTTP head to inspect). Failures before the tunnel is accepted are reported
/// as plain-HTTP refusals (the client is still speaking the CONNECT protocol); once `200` is sent the
/// bytes are raw and a mid-stream error simply tears the tunnel down.
fn splice_l4(
    mut client: UnixStream,
    connect_host: &str,
    port: u16,
    deciding: &Rule,
    ctx: &ProxyCtx,
) -> io::Result<()> {
    // Reserve a splice slot up front; the guard releases it on every return below.
    let guard = SpliceGuard::new(&ctx.splices);
    if guard.count() > MAX_CONCURRENT_SPLICES {
        // A raw splice has no HTTP head, so there is no method/path to log.
        ctx.outcome(
            super::control::Proto::Tcp,
            connect_host,
            port,
            None,
            None,
            StatKind::Blocked,
            "splice-cap",
        );
        return write_refusal(
            &mut client,
            "503 Service Unavailable",
            "splice-cap",
            "too many concurrent raw (tcp://) tunnels are open; retry when one closes",
        );
    }

    // Resolve host-side. An IP-literal CONNECT target is allowed for a splice (it needs no SNI), so
    // it is used directly; a hostname is resolved, and a failure is a clean 502 (not a dropped
    // connection). Then the SSRF guard against the deciding rule — a private/metadata address is
    // refused unless the rule names this exact host.
    let checked = match connect_host.parse::<IpAddr>() {
        // An IP-literal target: this path is the only one that accepts one, and there is nothing to
        // resolve — the guard still decides.
        Ok(ip) => checked_address(
            ctx,
            super::control::Proto::Tcp,
            connect_host,
            port,
            None,
            None,
            Some(deciding),
            vec![ip],
        ),
        Err(_) => resolve_checked(
            ctx,
            super::control::Proto::Tcp,
            connect_host,
            port,
            None,
            None,
            Some(deciding),
        ),
    };
    let ip = match checked {
        Ok(ip) => ip,
        Err(refusal) => {
            return write_refusal(
                &mut client,
                refusal.status_line(),
                refusal.tag(),
                &refusal.message(connect_host),
            );
        }
    };

    // Open the raw upstream to the checked address (no TLS, no certificate validation — a raw splice
    // is uninspected by design; the empty netns + the allowlist are the boundary).
    let upstream = match TcpStream::connect((ip, port)) {
        Ok(s) => s,
        Err(_) => {
            ctx.push_log(
                super::control::Proto::Tcp,
                connect_host,
                port,
                None,
                None,
                super::control::LogVerdict::Error,
                "upstream-unreachable",
            );
            return write_refusal(
                &mut client,
                "502 Bad Gateway",
                "upstream-unreachable",
                &format!("`{connect_host}:{port}` is allowed but could not be reached"),
            );
        }
    };

    // Accept the tunnel — from here every byte is raw and uninspected.
    write_all_str(&mut client, "HTTP/1.1 200 Connection established\r\n\r\n")?;
    ctx.outcome(
        super::control::Proto::Tcp,
        connect_host,
        port,
        None,
        None,
        StatKind::Allow,
        "allowed",
    );
    // Register the raw tunnel for `sbx net live` for its whole lifetime: `splice_copy` joins both
    // directions before returning, so this guard (dropped after it) stays registered until the tunnel
    // fully closes. A splice is uninspected, so the byte counters reflect raw ciphertext volume.
    let flow = ctx.register_flow(connect_host, port, super::control::Proto::Tcp);
    splice_copy(client, upstream, flow.up.clone(), flow.down.clone())
}

/// Splice a raw TCP tunnel: copy bytes both directions between the cage `client` and the `upstream`
/// until either side closes, then tear both down so neither copy thread can hang. The per-connection
/// read/write timeouts are cleared first, so an idle long-lived tunnel (an interactive SSH session,
/// say) is not killed mid-session. One direction runs in a spawned thread, the other in this thread;
/// when the first ends, both sockets are shut down fully so the other's blocked read returns and the
/// join always completes (no leaked host thread on a half-open or stalled peer).
fn splice_copy(
    client: UnixStream,
    upstream: TcpStream,
    up: Arc<AtomicU64>,
    down: Arc<AtomicU64>,
) -> io::Result<()> {
    // A raw tunnel may idle indefinitely between bursts, so drop the per-connection timeouts the
    // serve loop set (they exist to bound a slow HTTP head, not a long-lived stream). Set on the
    // originals before cloning, since the timeout is a socket-level option shared by the dups.
    let _ = client.set_read_timeout(None);
    let _ = client.set_write_timeout(None);
    let _ = upstream.set_read_timeout(None);
    let _ = upstream.set_write_timeout(None);

    // Two handles per socket (read + write), plus one each to force a full teardown after the first
    // direction ends. `try_clone` dups the fd, so every handle refers to the same socket.
    let mut client_wr = client.try_clone()?;
    let client_shut = client.try_clone()?;
    let mut client_rd = client;
    let mut up_rd = upstream.try_clone()?;
    let up_shut = upstream.try_clone()?;
    let mut up_wr = upstream;

    let t = std::thread::spawn(move || {
        // Count client→upstream bytes (`up`). The counting writer is temporary, so `up_wr` is free to
        // shut down after the copy. On a raw splice these are ciphertext bytes (the tunnel is opaque).
        let _ = io::copy(&mut client_rd, &mut CountingWriter::new(&mut up_wr, up));
        // client → upstream finished: half-close the upstream's write so it observes EOF.
        let _ = up_wr.shutdown(std::net::Shutdown::Write);
    });
    // Count upstream→client bytes (`down`) through the counting reader (temporary, so `up_rd` remains
    // usable — though it is not needed after this copy).
    let _ = io::copy(&mut CountingReader::new(&mut up_rd, down), &mut client_wr);
    // upstream → client finished: half-close the client's write, then force both sockets fully down
    // so the spawned thread's blocked read returns and the join below always completes.
    let _ = client_wr.shutdown(std::net::Shutdown::Write);
    let _ = client_shut.shutdown(std::net::Shutdown::Both);
    let _ = up_shut.shutdown(std::net::Shutdown::Both);
    let _ = t.join();
    Ok(())
}

/// Handle an **inspected-cleartext** (`http://`) request: the client sent an absolute-form request
/// (`GET http://host/path HTTP/1.1`) because its `http_proxy` points here, and an `http://` allow
/// rule may permit it. This is the plaintext sibling of the MITM path — the *same* HTTP policy (host
/// / port / path / method / the outbound-secret tripwire / the SSRF guard), but on a connection with
/// **no TLS**: no CONNECT tunnel, no leaf minted, no upstream certificate to validate, and — because
/// a bearer must never travel in the clear — **no credential injection** (a secret host can only be
/// an inspected-over-TLS `to`, so [`matching_injections`] is skipped entirely, not merely trusted to
/// return empty). The request is forwarded to the origin server in **origin-form** with the client's
/// own `Host`, and the one response is streamed back. Every failure path is fail-closed with the same
/// [`write_refusal`] reason categories the MITM path uses, so the agent tells a policy refusal from an
/// unreachable host. `head_bytes` is the raw head (for the byte-exact secret tripwire); `head` is its
/// parse.
fn handle_cleartext(
    mut client: UnixStream,
    head: &Head,
    head_bytes: &[u8],
    method: &str,
    target: &str,
    ctx: &ProxyCtx,
) -> io::Result<()> {
    // 1. Parse the absolute-form `http://host[:port]/path` target into (host, port=80 default, path).
    //    The host is canonicalized by the parser; the path is canonicalized inside `explain_clear`.
    let (host, port, path) = match allowlist::parse_url_target(target) {
        Ok(t) => t,
        Err(_) => {
            ctx.push_log(
                super::control::Proto::Http,
                "",
                0,
                Some(method),
                Some(target),
                super::control::LogVerdict::Blocked,
                "bad-request",
            );
            return write_refusal(
                &mut client,
                "400 Bad Request",
                "bad-request",
                "the absolute-form request target is not a valid `http://` URL",
            );
        }
    };

    // 2. Anti request-smuggling, fail-closed — the same guards as the tunneled path: any
    //    Transfer-Encoding (no chunked framing in this path), or a duplicated Content-Length / Host.
    if head.header("transfer-encoding").is_some()
        || head.count("content-length") > 1
        || head.count("host") > 1
    {
        ctx.push_log(
            super::control::Proto::Http,
            &host,
            port,
            Some(method),
            Some(&path),
            super::control::LogVerdict::Blocked,
            "bad-request",
        );
        return write_refusal(
            &mut client,
            "400 Bad Request",
            "bad-request",
            "the request has ambiguous framing (Transfer-Encoding, or a duplicated \
             Content-Length or Host)",
        );
    }
    let body_len: u64 = match head.header("content-length") {
        Some(v) => match v.trim().parse() {
            Ok(n) => n,
            Err(_) => {
                ctx.push_log(
                    super::control::Proto::Http,
                    &host,
                    port,
                    Some(method),
                    Some(&path),
                    super::control::LogVerdict::Blocked,
                    "bad-request",
                );
                return write_refusal(
                    &mut client,
                    "400 Bad Request",
                    "bad-request",
                    "the Content-Length header is not a valid number",
                );
            }
        },
        None => 0,
    };

    // 3. Anti-fronting collapses to one check with no CONNECT/SNI: the absolute-form URL host must
    //    equal the `Host` header, so a request cannot claim one host in the line and another in the
    //    header (the destination the policy checks is the URL host).
    if head
        .header("host")
        .map(|h| allowlist::canonical_host(&strip_port(h)) != host)
        .unwrap_or(true)
    {
        ctx.outcome(
            super::control::Proto::Http,
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
    //    configured secret verbatim. It matters more here than on the TLS path: a leaked secret sent
    //    in the clear is exposed on the wire, not just to the destination.
    if carries_secret(head_bytes, &ctx.redactions) {
        ctx.outcome(
            super::control::Proto::Http,
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

    // 5. The verdict — cleartext is strictly opt-in, so only an explicit `http://` allow rule permits
    //    it (`explain_clear` never consults the default action or parks; deny wins layer-agnostically).
    //    Evaluated against the effective policy, so an `http://` rule loaded live with `sbx net allow
    //    http://host --session` opens it too. The two denial shapes get distinct reasons, and the
    //    `denied-default` suggestion names the `http://` scheme (a bare `sbx net allow host` would add
    //    an https rule that does not open the clear).
    let policy = effective_policy(ctx);
    let deciding: Rule = match policy.explain_clear(&host, port, &path, method) {
        Decision::AllowedBy(rule) => rule.clone(),
        Decision::DeniedBy(_) => {
            ctx.outcome(
                super::control::Proto::Http,
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
                super::control::Proto::Http,
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
                    ctx.allow_suggestion(&format!("http://{host}"))
                ),
            );
        }
    };

    // 6. Resolve host-side, then the SSRF guard against the deciding rule (a private/metadata address
    //    is refused unless the `http://` rule names this exact host). A resolution failure for an
    //    allowed host is a clean 502, distinct from a refusal.
    let ip = match resolve_checked(
        ctx,
        super::control::Proto::Http,
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

    // 7. Open the plaintext upstream to the checked address (no TLS, no certificate — an `http://`
    //    connection is cleartext by definition; the empty netns + the allowlist are the boundary).
    let mut upstream = match TcpStream::connect((ip, port)) {
        Ok(s) => {
            let _ = s.set_read_timeout(Some(ctx.timeout));
            let _ = s.set_write_timeout(Some(ctx.timeout));
            s
        }
        Err(_) => {
            ctx.push_log(
                super::control::Proto::Http,
                &host,
                port,
                Some(method),
                Some(&path),
                super::control::LogVerdict::Error,
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
        super::control::Proto::Http,
        super::control::HttpVer::H1,
        // Cleartext is always HTTP/1.1; a gRPC/Connect-streaming content-type still tags (rare over
        // cleartext, but honest if it occurs).
        super::control::RpcKind::from_content_type(head.header("content-type").unwrap_or_default()),
        &host,
        port,
        Some(method),
        Some(&path),
        StatKind::Allow,
        "allowed",
    );

    // Register the open cleartext tunnel for `sbx net live` until this function returns (the tunnel
    // closes). This is inspected cleartext, so the byte counters reflect application data.
    let flow = ctx.register_flow(&host, port, super::control::Proto::Http);

    // Open the traffic capture. No credential is ever injected on a cleartext request, so the head
    // recorded here is both what arrived and what is forwarded, and no injected names accompany it.
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

    // 9. Relay the response head, then stream its framed body to the client and close. A cleartext
    //    host is never a credential-injection target, so it can carry no *reflected* secret to mask —
    //    the response is relayed unredacted (there is nothing this path could reflect that the
    //    tripwire above did not already refuse outbound).
    let mut up_br = BufReader::new(upstream);
    let (resp_head, complete) = relay_response_head(
        &mut up_br,
        &mut client,
        &flow.down,
        capture.as_ref(),
        &[],
        false,
    )?;
    if let Some(code) = parse_status_code(&resp_head)
        && code >= 200
    {
        ctx.set_status(allow_seq, code);
    }
    let framing = if complete {
        response_framing(&resp_head, method)
    } else {
        BodyFraming::ToEof
    };
    // Count upstream→client (`down`) through the body; the head was counted as it was relayed.
    let response = CountingReader::new(FramedBody::new(up_br, framing), flow.down.clone());
    let mut response: Box<dyn Read + '_> = match &capture {
        Some(c) => Box::new(CaptureReader::new(response, c.response_sink())),
        None => Box::new(response),
    };
    pump_to_eof(&mut response, &mut client)
}

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
fn handle_https_forward(
    mut client: UnixStream,
    head: &Head,
    head_bytes: &[u8],
    method: &str,
    target: &str,
    ctx: &ProxyCtx,
) -> io::Result<()> {
    // 1. Parse the absolute-form `https://host[:port]/path` target into (host, port=443 default, path).
    //    The host is canonicalized by the parser; the path is canonicalized inside `explain`.
    let (host, port, path) = match allowlist::parse_url_target(target) {
        Ok(t) => t,
        Err(_) => {
            ctx.push_log(
                super::control::Proto::Https,
                "",
                0,
                Some(method),
                Some(target),
                super::control::LogVerdict::Blocked,
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

    // 2. Anti request-smuggling, fail-closed — the same guards, and the same sub-categorized
    //    reasons, as the tunneled path. A duplicated Content-Length or Host is an unambiguous desync
    //    vector and is refused outright; a `Transfer-Encoding` is refused UNLESS it is exactly
    //    `chunked`, the one streaming coding the proxy de-chunks and re-frames with a synthesized
    //    Content-Length below (so no CL/TE ambiguity reaches the upstream).
    let chunked = match head.header("transfer-encoding").map(str::trim) {
        Some(v) if v.eq_ignore_ascii_case("chunked") => true,
        Some(_) => {
            ctx.push_log(
                super::control::Proto::Https,
                &host,
                port,
                Some(method),
                Some(&path),
                super::control::LogVerdict::Blocked,
                "bad-request:transfer-encoding",
            );
            return write_refusal(
                &mut client,
                "400 Bad Request",
                "bad-request:transfer-encoding",
                "the request carries a Transfer-Encoding coding other than `chunked`, which this \
                 egress proxy does not forward",
            );
        }
        None => false,
    };
    if head.count("content-length") > 1 || head.count("host") > 1 {
        let (reason, detail) = if head.count("content-length") > 1 {
            (
                "bad-request:dup-content-length",
                "the request carries a duplicated Content-Length header",
            )
        } else {
            (
                "bad-request:dup-host",
                "the request carries a duplicated Host header",
            )
        };
        ctx.push_log(
            super::control::Proto::Https,
            &host,
            port,
            Some(method),
            Some(&path),
            super::control::LogVerdict::Blocked,
            reason,
        );
        return write_refusal(&mut client, "400 Bad Request", reason, detail);
    }
    // The body length is known up-front only for a Content-Length-framed request; a `chunked`
    // request's length is discovered by de-chunking below.
    let body_len: u64 = if chunked {
        0
    } else {
        match head.header("content-length") {
            Some(v) => match v.trim().parse() {
                Ok(n) => n,
                Err(_) => {
                    ctx.push_log(
                        super::control::Proto::Https,
                        &host,
                        port,
                        Some(method),
                        Some(&path),
                        super::control::LogVerdict::Blocked,
                        "bad-request:invalid-content-length",
                    );
                    return write_refusal(
                        &mut client,
                        "400 Bad Request",
                        "bad-request:invalid-content-length",
                        "the Content-Length header is not a valid number",
                    );
                }
            },
            None => 0,
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
            super::control::Proto::Https,
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
    if carries_secret(head_bytes, &ctx.redactions) {
        ctx.outcome(
            super::control::Proto::Https,
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
        super::control::Proto::Https,
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
    let injected_ids = matching_injection_ids(ctx, &host, port, &path);
    let injected = injection_pairs(ctx, &injected_ids);

    // 7a. Whether this request may share its upstream leg with others, on the same terms as the
    //     tunneled path: the launch has to have asked for reuse, and the request has to be HTTP/1.1.
    //     Only a request the proxy can send again takes a parked connection.
    let keep_alive =
        ctx.pool.is_some() && head.request_line.split_whitespace().nth(2) == Some("HTTP/1.1");
    let pool_key = keep_alive.then(|| PoolKey::new(&host, port, &injected_ids));
    let replayable = chunked || body_len == 0;

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
        super::control::Proto::Https,
        super::control::HttpVer::H1,
        super::control::RpcKind::from_content_type(head.header("content-type").unwrap_or_default()),
        &host,
        port,
        Some(method),
        Some(&path),
        StatKind::Allow,
        "allowed",
    );
    let flow = ctx.register_flow(&host, port, super::control::Proto::Https);

    // 8a. Open the traffic capture, recording the client's own head (before the reserialization
    //     below adds any injected credential) plus the injected header names, never their values.
    let capture = ctx.begin_capture(allow_seq);
    if let Some(c) = &capture {
        c.set_request(head_bytes, &injected);
    }

    // 9. Forward the one request in **origin-form** (`POST /path`) with the injected credential (the
    //    reserializer strips hop-by-hop headers and the client's copy of any injected header). A
    //    pipelined second request is never forwarded, so it cannot skip the per-request check. The
    //    forwarded bytes are materialized when the proxy still holds all of them, so a connection the
    //    upstream closed while it was parked costs a second attempt rather than an empty response.
    let version = head
        .request_line
        .split_whitespace()
        .nth(2)
        .unwrap_or("HTTP/1.1");
    let origin = Head {
        request_line: format!("{method} {path} {version}"),
        headers: head.headers.clone(),
    };
    let forwarded: Option<Vec<u8>> = if chunked {
        // A `Transfer-Encoding: chunked` request: de-chunk the body into a bounded buffer and forward
        // a clean `Content-Length`-framed request (the reserializer strips the client's
        // Transfer-Encoding when a length is forced), so no chunked framing — and no CL/TE
        // request-smuggling ambiguity — reaches the upstream. Answer a client `Expect: 100-continue`
        // before reading, else it withholds the body. A de-chunk failure (malformed framing, or over
        // the cap) is fail-closed: log + refuse 400.
        if head_expects_continue(head) {
            let _ = client.write_all(b"HTTP/1.1 100 Continue\r\n\r\n");
            let _ = client.flush();
        }
        // The buffered reader is scoped to the de-chunk: it may read past the body's terminator (a
        // pipelined second request), which this path never forwards anyway.
        let read = {
            let mut reader = BufReader::new(&client);
            read_chunked_body(&mut reader, CHUNKED_REQUEST_CAP)
        };
        let body = match read {
            Ok(b) => b,
            Err(e) => {
                ctx.push_log(
                    super::control::Proto::Https,
                    &host,
                    port,
                    Some(method),
                    Some(&path),
                    super::control::LogVerdict::Blocked,
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
    } else if body_len == 0 {
        Some(reserialize_request(&origin, &injected, None, keep_alive))
    } else {
        None
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
                    super::control::Proto::Https,
                    &host,
                    port,
                    Some(method),
                    Some(&path),
                    super::control::LogVerdict::Error,
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

    // 10. Relay the response head, then stream its framed body to the plaintext client and close.
    //     Mask a reflected secret only for a response from an injection-target host (every other
    //     response streams untouched) — decided before the head is read, because the masking covers
    //     the head as much as the body and the head is relayed first.
    let masks_reflection = !ctx.redactions.is_empty()
        && ctx
            .injections
            .iter()
            .any(|inj| names_exact_host(&host, Some(&inj.rule)));
    let head_masking: &[SecretNeedle] = if masks_reflection {
        &ctx.redactions
    } else {
        &[]
    };
    let mut up_br = BufReader::new(&mut upstream);
    let (resp_head, complete) = relay_response_head(
        &mut up_br,
        &mut client,
        &flow.down,
        capture.as_ref(),
        head_masking,
        keep_alive,
    )?;
    // An upstream that closed without answering leaves nothing to relay, and an empty success would
    // be indistinguishable from a genuine zero-byte response — see the tunneled path.
    if resp_head.is_empty() {
        ctx.push_log(
            super::control::Proto::Https,
            &host,
            port,
            Some(method),
            Some(&path),
            super::control::LogVerdict::Error,
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
    }
    let framing = if complete {
        response_framing(&resp_head, method)
    } else {
        BodyFraming::ToEof
    };
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
            pump_redacting(&mut response, &mut client, &ctx.redactions)?;
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

/// Why the network policy refused an inspected request, for the two paths that put the same question
/// to it: a `CONNECT` tunnel and an absolute-form `https://` forward. Modelled on
/// [`ssrf::ConnectRefusal`]
/// and for the same reason — the verdict records its own outcome and hands back what to answer, so
/// the two paths differ in how they *write* a refusal (inside the terminated TLS, or on the plaintext
/// client socket), not in what it says.
enum PolicyRefusal {
    /// A deny rule matched. Kept distinct from [`Self::DeniedDefault`] so the agent can tell "a rule
    /// said no" from "no rule said yes".
    DeniedByRule,
    /// An allow rule matches the host and path, but its method set excludes this verb — a
    /// method-scoped deny, not a closed host.
    DeniedMethod,
    /// Nothing opened the host. The one refusal that carries a copy-paste `sbx net allow`, sound
    /// precisely because nothing allowed it — never for an explicit deny or a security guard.
    DeniedDefault,
    /// An `ask`-undecided host a live decision refused, or whose ask timeout elapsed.
    AskedDenied,
    /// An `ask`-undecided host on a transport that cannot park one. Only the HTTP/2 path produces
    /// it, and it names that transport in its reason token so the refusal reads as the documented
    /// limitation it is rather than as an ordinary deny. See [`AskPosture::RefuseUnsupported`].
    Http2AskUnsupported,
}

/// Whether the transport asking for a verdict can park a request while a person decides it.
///
/// This is a property of how the path runs, not a preference. The synchronous HTTP/1.1 paths serve
/// one connection per thread, so blocking one to wait for `sbx net pending` costs that request and
/// nothing else. Every stream of an HTTP/2 connection is multiplexed onto ONE current-thread tokio
/// runtime, so parking a single stream there would stall its siblings — it fails closed instead.
#[derive(Clone, Copy)]
enum AskPosture {
    /// Block until a host-side `sbx net pending` answers, or the ask timeout elapses (deny).
    Park,
    /// Refuse an undecided host outright, under [`PolicyRefusal::Http2AskUnsupported`].
    RefuseUnsupported,
}

impl PolicyRefusal {
    /// The status line the HTTP/1.1 paths write. Every policy refusal is a `403`: the request was
    /// understood and reached a verdict, which is what separates these from the `502`s a connect
    /// failure gets.
    fn status_line(&self) -> &'static str {
        "403 Forbidden"
    }

    /// The same status for the HTTP/2 path, which frames a refusal rather than writing it.
    fn status(&self) -> http::StatusCode {
        http::StatusCode::FORBIDDEN
    }

    /// The stable reason token: the `x-sbx-egress-reason` header, and the reason in the log.
    fn tag(&self) -> &'static str {
        match self {
            Self::DeniedByRule => "denied-by-rule",
            Self::DeniedMethod => "denied-method",
            Self::DeniedDefault => "denied-default",
            Self::AskedDenied => "asked-denied",
            Self::Http2AskUnsupported => "http2-ask-unsupported",
        }
    }

    /// The sentence the refusal body carries, naming what the client asked for.
    fn message(&self, ctx: &ProxyCtx, host: &str, port: u16, method: &str) -> String {
        match self {
            Self::DeniedByRule => {
                "this request matches a deny rule in the network policy".to_string()
            }
            Self::DeniedMethod => format!(
                "the `{method}` method is not permitted to `{host}:{port}` by the network policy"
            ),
            // The suggestion rides the response the client already shows, so the agent gets the next
            // step in the reply itself. The *person* running sbx is told separately, through the
            // notification the `outcome` chokepoint raises: the agent is under no obligation to
            // surface a `403` body, and a boundary nobody hears about is one that looks like it never
            // bit. Scoped to the app when this is an `sbx app` launch.
            Self::DeniedDefault => format!(
                "`{host}:{port}` is not allowed by the network policy. Allow it: {}",
                ctx.allow_suggestion(host)
            ),
            Self::AskedDenied => {
                "this request was denied by a live decision or the ask timeout elapsed".to_string()
            }
            // Reached only by the HTTP/2 path, which frames a status and a reason token and sends no
            // body — so this sentence has no writer today. It is spelled anyway: the enum's contract
            // is that every refusal can say what it is, and a variant that cannot would be a trap
            // for whoever gives that path a body later.
            Self::Http2AskUnsupported => format!(
                "`{host}:{port}` is undecided under the `ask` posture, and this HTTP/2 stream \
                 cannot wait for a decision — allow the host explicitly to reach it"
            ),
        }
    }
}

/// The `https` policy verdict for one inspected request: the deciding rule, or the refusal to answer
/// with. `Ok(None)` is allow-by-default (denylist mode) — no rule named the host, so there is no
/// deciding rule and the SSRF guard downstream treats the target as unnamed.
///
/// Built through the SAME canonicalizer `sbx test net` uses, so enforcement cannot drift from the
/// tester's prediction, and evaluated against the effective policy (config plus any live `--session`
/// overlay), so a `--session allow` opens an otherwise-default-denied host and a `--session deny`
/// blocks a config-allowed one. An `ask`-undecided host parks here and blocks until a host-side `sbx
/// net pending` answers it or the timeout elapses (deny — fail-closed); a live allow names this exact
/// host:port as the deciding rule, so the SSRF guard admits a deliberately-approved internal target.
///
/// Every refusal records its own outcome before returning, so a caller cannot answer one without
/// counting it. `ask` is the one arm the callers do not all share, which is what [`AskPosture`]
/// carries: the two HTTP/1.1 paths park, the HTTP/2 path cannot and refuses.
///
/// The cleartext `http://` path is the one consumer of the `https` policy that deliberately does NOT
/// come here. It is strictly opt-in, its `explain_clear` consults neither the default action nor the
/// ask queue, and routing it through this verdict would widen it into a posture it was written to
/// refuse.
fn decide_https(
    ctx: &ProxyCtx,
    host: &str,
    port: u16,
    path: &str,
    method: &str,
    ask: AskPosture,
) -> Result<Option<Rule>, PolicyRefusal> {
    let refuse = |refusal: PolicyRefusal| {
        ctx.outcome(
            super::control::Proto::Https,
            host,
            port,
            Some(method),
            Some(path),
            StatKind::Deny,
            refusal.tag(),
        );
        Err(refusal)
    };
    let policy = effective_policy(ctx);
    match policy.explain(host, port, path, method) {
        Decision::AllowedBy(rule) => Ok(Some(rule.clone())),
        Decision::AllowedDefault => Ok(None),
        Decision::DeniedBy(_) => refuse(PolicyRefusal::DeniedByRule),
        Decision::DeniedDefault => {
            // Which of the two the refusal is gets decided *before* the outcome is recorded, so the
            // log carries the precise category rather than a coarse one.
            if policy.method_denied(host, port, path, method) {
                refuse(PolicyRefusal::DeniedMethod)
            } else {
                refuse(PolicyRefusal::DeniedDefault)
            }
        }
        // Undecided. Parking blocks the calling thread until a person answers, which only a
        // transport that owns its thread may do — the other fails closed rather than stalling every
        // stream sharing its runtime.
        Decision::Ask if matches!(ask, AskPosture::RefuseUnsupported) => {
            refuse(PolicyRefusal::Http2AskUnsupported)
        }
        Decision::Ask => {
            let verdict = ctx.pending.park(
                host,
                port,
                path,
                policy.ask_timeout(),
                ASK_PENDING_CAP,
                |seq| {
                    if ctx.notices {
                        let id = super::control::format_id(std::process::id(), seq);
                        print_egress_notice(
                            &format!("egress decision needed [{id}] {host}:{port}{path}"),
                            &[
                                ("allow", &format!("sbx net pending allow {id}")),
                                ("deny", &format!("sbx net pending deny {id}")),
                            ],
                        );
                    }
                },
            );
            match verdict {
                super::control::Verdict::Allow => Ok(Some(allowlist::host_port_rule(host, port))),
                super::control::Verdict::Deny => refuse(PolicyRefusal::AskedDenied),
            }
        }
    }
}

/// Why a connection to the validated upstream could not be opened, so the refusal can name a
/// distinct motif: the TCP connection failed (the host is down/filtered), or the TLS handshake /
/// certificate validation failed (a forged or otherwise untrusted upstream — never downgraded).
enum UpstreamError {
    /// The TCP connection to the checked address could not be established.
    Unreachable,
    /// The TLS handshake or certificate validation against the upstream failed.
    CertRejected,
}

/// Open a validated TLS connection to a checked upstream address. The TCP target is the
/// already-guarded IP; the certificate is validated against `host` (the name), so the connection
/// goes to the exact address the SSRF guard approved while still authenticating the real server.
/// The handshake is completed here so a validation failure surfaces now (a 502), distinct from a
/// plain unreachable host (also a 502, but a different reason).
fn connect_upstream(
    ip: IpAddr,
    port: u16,
    host: &str,
    ctx: &ProxyCtx,
) -> Result<StreamOwned<ClientConnection, TcpStream>, UpstreamError> {
    let sock = TcpStream::connect((ip, port)).map_err(|_| UpstreamError::Unreachable)?;
    sock.set_read_timeout(Some(ctx.timeout))
        .map_err(|_| UpstreamError::Unreachable)?;
    sock.set_write_timeout(Some(ctx.timeout))
        .map_err(|_| UpstreamError::Unreachable)?;
    let name = upstream_server_name(host).map_err(|_| UpstreamError::CertRejected)?;
    let mut conn = ClientConnection::new(ctx.upstream.clone(), name)
        .map_err(|_| UpstreamError::CertRejected)?;
    let mut sock = sock;
    // drives + validates the TLS handshake now; a forged/self-signed upstream fails here
    conn.complete_io(&mut sock)
        .map_err(|_| UpstreamError::CertRejected)?;
    Ok(StreamOwned::new(conn, sock))
}

/// The upstream connection this request will ride: one an earlier request to the same host left
/// behind when the launch reuses connections and the pool holds a live one, else a freshly connected
/// and validated one. The flag says which, so a connection that dies between the pool's probe and
/// the request write can be named for what it is rather than surfacing as an empty response.
///
/// Reuse deliberately sits **after** the verdict, the name resolution and the address guard, not
/// instead of them: a parked connection shortens the handshake, never the checks. It also cannot
/// outlive what authorized it — the certificate was validated against `host`, which is part of the
/// key, so a reused connection goes to a server that was authenticated for exactly this name.
fn acquire_upstream(
    ctx: &ProxyCtx,
    key: Option<&PoolKey>,
    ip: IpAddr,
    port: u16,
    host: &str,
) -> Result<(UpstreamTls, bool), UpstreamError> {
    if let (Some(pool), Some(key)) = (ctx.pool.as_ref(), key)
        && let Some(stream) = pool.checkout(key)
    {
        return Ok((stream, true));
    }
    connect_upstream(ip, port, host, ctx).map(|stream| (stream, false))
}

/// Refuse a request because its validated upstream could not be opened. Both shapes are a `502`,
/// with distinct reasons so "the host is down" reads differently from "its certificate was
/// rejected". Written straight to whichever client leg asked — the decrypted tunnel on the
/// inspected-TLS path, the plaintext socket on the absolute-form one.
fn refuse_upstream<W: Write>(
    w: &mut W,
    ctx: &ProxyCtx,
    host: &str,
    port: u16,
    method: &str,
    target: &str,
    err: UpstreamError,
) -> io::Result<()> {
    let (reason, detail) = match err {
        UpstreamError::Unreachable => (
            "upstream-unreachable",
            format!("`{host}:{port}` is allowed but could not be reached"),
        ),
        UpstreamError::CertRejected => (
            "upstream-cert-rejected",
            format!(
                "the TLS certificate presented by `{host}` was rejected (upstream validation failed)"
            ),
        ),
    };
    ctx.push_log(
        super::control::Proto::Https,
        host,
        port,
        Some(method),
        Some(target),
        super::control::LogVerdict::Error,
        reason,
    );
    write_refusal(w, "502 Bad Gateway", reason, &detail)
}

/// Whether a method may be sent a second time after a parked connection turns out to be dead.
///
/// The retry runs only when the upstream said nothing at all, which from a live server means it
/// never saw the request. But a server that took the request and died before answering looks exactly
/// the same from here, so replaying a method whose effect is not idempotent could apply it twice.
/// The methods RFC 9110 §9.2.2 defines as idempotent are replayed; `POST` and `PATCH` are not, and
/// the request that loses its connection gets the `502` instead. That is not a worse answer, it is
/// the honest one: whether such a request may be sent again is the client's to decide, and the
/// client is the only layer that knows.
///
/// Compared exactly, so a non-canonical spelling is simply not replayed — an unknown method is one
/// whose effect is unknown too.
fn idempotent_method(method: &str) -> bool {
    matches!(
        method,
        "GET" | "HEAD" | "PUT" | "DELETE" | "OPTIONS" | "TRACE"
    )
}

/// Whether the upstream has anything at all to say on this connection, by a peek that leaves it
/// untouched for the relay that follows.
///
/// Asked of a **reused** connection only, and it answers one question: was the connection still
/// there when the request went out? An upstream may close a parked connection at any moment, and the
/// proxy learns of it only after writing — so this is where that shows up, before a byte of response
/// has reached the client and while the request is still in hand to send again. `false` means the
/// far side is gone.
fn upstream_spoke(sock: &TcpStream) -> bool {
    let mut one = [0u8; 1];
    matches!(sock.peek(&mut one), Ok(n) if n > 0)
}

/// Read a request head byte-by-byte until the blank-line terminator, leaving the stream positioned
/// exactly after it (so the next bytes — a TLS ClientHello — are untouched). Bounded by `max`.
fn read_head_raw<R: Read>(r: &mut R, max: usize) -> io::Result<Vec<u8>> {
    let mut buf = Vec::new();
    let mut one = [0u8; 1];
    loop {
        if r.read(&mut one)? == 0 {
            return Err(invalid(
                "connection closed before the end of the request head",
            ));
        }
        buf.push(one[0]);
        if buf.ends_with(b"\r\n\r\n") {
            return Ok(buf);
        }
        if buf.len() > max {
            return Err(invalid("request head too large"));
        }
    }
}

/// Read a request head from a buffered reader line by line until the blank-line terminator. Any
/// bytes the reader buffered past the head (the body) stay in the reader for the caller to consume.
fn read_head_buffered<R: BufRead>(r: &mut R, max: usize) -> io::Result<Vec<u8>> {
    let mut buf = Vec::new();
    loop {
        let start = buf.len();
        // Cap each line at the remaining budget (+1 to detect overflow): a bare `read_until` would
        // buffer an arbitrarily long line with no terminator *before* the size check below runs, so
        // an in-cage client could force unbounded host-side allocation here (this proxy runs outside
        // the cage's cgroup). With the cap a no-`\n` flood hits the budget and errors.
        let budget = (max - start + 1) as u64;
        if (&mut *r).take(budget).read_until(b'\n', &mut buf)? == 0 {
            return Err(invalid(
                "connection closed before the end of the request head",
            ));
        }
        if buf.len() > max {
            return Err(invalid("request head too large"));
        }
        if matches!(&buf[start..], b"\r\n" | b"\n") {
            return Ok(buf);
        }
    }
}

/// A parsed request head: the request line and its headers.
struct Head {
    request_line: String,
    headers: Vec<(String, String)>,
}

impl Head {
    /// The value of a header by case-insensitive name (the first, if duplicated).
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    /// How many headers carry this name (case-insensitive) — to catch a duplicated header.
    fn count(&self, name: &str) -> usize {
        self.headers
            .iter()
            .filter(|(k, _)| k.eq_ignore_ascii_case(name))
            .count()
    }
}

/// The credential injections (`header`, `value`) whose host/path rule matches this request,
/// canonicalized through the same matcher the verdict used. Borrowed from the context, so no
/// secret is copied beyond the forwarded head.
fn matching_injections<'a>(
    ctx: &'a ProxyCtx,
    host: &str,
    port: u16,
    target: &str,
) -> Vec<(&'a str, &'a str)> {
    injection_pairs(ctx, &matching_injection_ids(ctx, host, port, target))
}

/// The same match as [`matching_injections`], as **positions** in `ctx.injections`.
///
/// This is what identifies a credential set without carrying one: the upstream-connection pool is
/// partitioned by which credentials a request received, and its key has to name them without holding
/// them. Ascending by construction, so two requests matching the same rules produce the same list.
/// The two functions share this one matcher so the partition can never drift from the injection.
fn matching_injection_ids(ctx: &ProxyCtx, host: &str, port: u16, target: &str) -> Vec<usize> {
    ctx.injections
        .iter()
        .enumerate()
        .filter(|(_, inj)| allowlist::rule_matches(&inj.rule, host, port, target))
        .map(|(i, _)| i)
        .collect()
}

/// The `(header, value)` pairs named by positions in `ctx.injections`. Borrowed from the context, so
/// no secret is copied beyond the forwarded head.
fn injection_pairs<'a>(ctx: &'a ProxyCtx, ids: &[usize]) -> Vec<(&'a str, &'a str)> {
    ids.iter()
        .map(|&i| {
            (
                ctx.injections[i].header.as_str(),
                ctx.injections[i].value.as_str(),
            )
        })
        .collect()
}

/// Whether the decrypted client request head carries any configured secret value verbatim — the
/// outbound leak tripwire. Scans the raw head bytes (request line + every client header, before
/// sbx's own injection is added), so it can never self-trip on an injected credential. A backstop,
/// not a boundary: it catches a *verbatim* secret in the *head* only — an encoded value, or one in
/// the streamed body, is out of scope (see the module doc).
fn carries_secret(head_bytes: &[u8], redactions: &[SecretNeedle]) -> bool {
    redactions
        .iter()
        .any(|n| n.find_in(head_bytes, 0).is_some())
}

/// Reserialize a request head for forwarding upstream: keep the request line and headers, but drop
/// any client `Connection`/`Proxy-Connection` — the proxy owns hop-by-hop semantics on both legs and
/// sets this one itself. `Proxy-Authorization` is dropped too: it is a credential for the *proxy
/// hop*, and forwarding it would hand the origin server a secret addressed to sbx.
///
/// `keep_alive` decides what goes in its place, and it is a statement about the **upstream** leg
/// alone. `false` forces `Connection: close`, so the server closes after this one response; that was
/// long the only option, because the relay could not tell the end of a message from the end of a
/// socket and needed the close to know where to stop. `true` says nothing at all, which under
/// HTTP/1.1 is the request to keep the connection open — the proxy then knows where the response
/// ends on its own, and the connection can carry a later request. Neither value reaches the client:
/// its own leg is closed after one response either way (see [`force_close_in_head`]).
///
/// Each `(header, value)` in `injections` is **strip-and-replace**d: every client-supplied copy of
/// that header — over all spellings (case- and `_`/`-`-insensitive, see [`header_name_eq`]) — is
/// dropped, then sbx's value is appended. The agent in the cage is the adversary, so it must never
/// be able to leave its own copy of an injected header alongside sbx's (which a permissive proxy
/// would forward as a second, attacker-controlled value).
fn reserialize_request(
    head: &Head,
    injections: &[(&str, &str)],
    force_content_length: Option<u64>,
    keep_alive: bool,
) -> Vec<u8> {
    let mut out = String::with_capacity(head.request_line.len() + 64);
    out.push_str(&head.request_line);
    out.push_str("\r\n");
    for (k, v) in &head.headers {
        if k.eq_ignore_ascii_case("connection")
            || k.eq_ignore_ascii_case("proxy-connection")
            // A credential the client addressed to the proxy hop, never to the origin server.
            || k.eq_ignore_ascii_case("proxy-authorization")
            // `Expect: 100-continue` is answered by the proxy to the client directly; forwarding it
            // would make the upstream expect a body-handshake the proxy has already resolved.
            || k.eq_ignore_ascii_case("expect")
        {
            continue;
        }
        // strip any client copy of a header sbx is about to inject (all spellings), so the
        // injected value is the only one the upstream sees.
        if injections.iter().any(|(name, _)| header_name_eq(k, name)) {
            continue;
        }
        // A chunked request is re-framed with a synthesized Content-Length below, so drop the
        // client's Transfer-Encoding and any client Content-Length (the forced value is the only
        // one the upstream sees — no CL/TE smuggling ambiguity can reach it).
        if force_content_length.is_some()
            && (k.eq_ignore_ascii_case("transfer-encoding")
                || k.eq_ignore_ascii_case("content-length"))
        {
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
    if let Some(n) = force_content_length {
        out.push_str("Content-Length: ");
        out.push_str(&n.to_string());
        out.push_str("\r\n");
    }
    if !keep_alive {
        out.push_str("Connection: close\r\n");
    }
    out.push_str("\r\n");
    out.into_bytes()
}

/// Enter the response-streaming phase of an inspected (L7) request: lift the per-read timeout on
/// the validated upstream socket so a long-lived or bursty response — server-sent events, a slow
/// completion that idles between tokens — is not aborted mid-flight. The timeout the serve loop set
/// bounds a slowloris on the *request head*; by here the request is permitted and forwarded, so an
/// idle upstream is a legitimate stream, not an attack (the raw L4 splice clears its timeouts for
/// the same reason). Leaving it in place instead abruptly drops the connection at the timeout, which
/// the in-cage client sees as a truncated stream (`peer closed connection without sending TLS
/// close_notify`) — the failure mode that cut streaming agents mid-completion.
///
/// The client *write* timeout is deliberately left untouched, so a stalled in-cage reader still
/// cannot pin a proxy thread indefinitely, and a response whose framing is known ends at its own
/// last byte without waiting for anything. Residual (bounded by `MAX_CONCURRENT_CONNS`,
/// same-tenant): an upstream that neither sends nor closes while its client has gone away can hold a
/// thread until it does — the accepted cost of not killing a genuinely idle stream, as for the L4
/// splice.
///
/// The bound is put back before a finished connection is parked for reuse, since a connection that
/// is not relaying anything has no claim to be left unbounded (see [`pool::UpstreamPool::park`]).
fn begin_response_stream(upstream: &TcpStream) {
    let _ = upstream.set_read_timeout(None);
}

/// Read the upstream's response head and relay it to the client, returning the head **as the
/// upstream sent it** with whether it was terminated. Bytes the buffered reader pulled past the head
/// stay in it for the body relay.
///
/// `redactions` is the response-side reflection backstop, non-empty only for a host an injection
/// targets: an echo or debug endpoint reflects the injected credential in a header of its own as
/// readily as in a body, so the head is masked before it is written to the client. The masking is
/// equal-length, so the framing the caller parses is unaffected either way — and it parses the
/// upstream's own bytes, which is what the returned head is. The capture is handed those same
/// unmasked bytes and does its own masking at filing time, exactly as it does for the body.
///
/// An interim `1xx` — `100 Continue`, or the `103 Early Hints` CDNs emit — is a complete message of
/// its own that the real head follows, so it is relayed and read past rather than mistaken for the
/// response. It is deliberately left out of the capture, which shows the response the request
/// actually got; it is still counted, because those bytes did cross to the cage.
///
/// A head the upstream cuts short is relayed as far as it arrived and reported incomplete, never an
/// error: the caller then delimits the rest by the close, which is what this path did throughout
/// before it framed anything.
///
/// `close_client_leg` rewrites the final head's `Connection` for the client only ([`force_close_in_head`]),
/// which is what keeps the two legs' connection lifetimes independent once the upstream leg is
/// forwarded with keep-alive. Three things stay pinned to the **upstream's own** bytes across that
/// rewrite: the head returned to the caller, so the body framing is decided from what the server
/// actually said; the capture, which records the response as it was served; and the equal-length
/// masking contract, which is applied after the rewrite rather than through it. The byte counter
/// follows the other side — it measures what crossed to the cage, so it counts what was written.
fn relay_response_head<R: BufRead, W: Write>(
    up: &mut R,
    client: &mut W,
    down: &AtomicU64,
    capture: Option<&CaptureGuard>,
    redactions: &[SecretNeedle],
    close_client_leg: bool,
) -> io::Result<(Vec<u8>, bool)> {
    loop {
        let (head, complete) = read_response_head(up, HEAD_MAX);
        if head.is_empty() {
            return Ok((head, false));
        }
        let interim =
            complete && matches!(parse_status_code(&head), Some(c) if (100..200).contains(&c));
        // An interim `1xx` is not the response, so its framing is not the connection's to state.
        let mut wire = if close_client_leg && complete && !interim {
            force_close_in_head(&head)
        } else {
            head.clone()
        };
        if !redactions.is_empty() {
            redact_in_place(&mut wire, redactions);
        }
        client.write_all(&wire)?;
        down.fetch_add(wire.len() as u64, Ordering::Relaxed);
        if interim {
            client.flush().ok();
            continue;
        }
        if let Some(c) = capture {
            c.push_response(&head);
        }
        return Ok((head, complete));
    }
}

/// Cleanly shut down the interception TLS after a response is fully relayed: queue a `close_notify`
/// and flush the connection's pending TLS records to the client socket. The sending half-close is
/// the correct TLS teardown; without it the client sees a bare socket close after the last byte,
/// which a streaming client surfaces as `peer closed connection without sending TLS close_notify`
/// even though the whole body arrived — the same error shape as an idle cut, but at end-of-stream.
/// It matters most for a close-delimited response (no `Content-Length`), where the client relies on
/// the shutdown to know the body ended. Best-effort: a client that already went away just makes the
/// writes fail, which ends the loop.
fn finish_tls(stream: &mut StreamOwned<ServerConnection, UnixStream>) {
    stream.conn.send_close_notify();
    while stream.conn.wants_write() {
        if stream.conn.write_tls(&mut stream.sock).is_err() {
            break;
        }
    }
    let _ = stream.sock.flush();
}

/// Stream `r` to `w` until end of input. A peer that drops the TLS connection without a
/// `close_notify` surfaces as an unexpected EOF, which ends the stream normally rather than erroring.
fn pump_to_eof<R: Read, W: Write>(r: &mut R, w: &mut W) -> io::Result<()> {
    let mut buf = vec![0u8; RELAY_CHUNK];
    loop {
        match r.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => w.write_all(&buf[..n])?,
            Err(ref e) if e.kind() == io::ErrorKind::UnexpectedEof => break,
            Err(e) => return Err(e),
        }
    }
    w.flush().ok();
    Ok(())
}

/// Stream `r` to `w` until end of input like [`pump_to_eof`], but replace every occurrence of any
/// configured secret value ([`SecretNeedle`]) with an equal-length run of `*` — the response-side
/// reflection backstop. Equal-length replacement keeps the response framing intact (`Content-Length`
/// or chunked sizes are unchanged) and `*` is printable so masking can never introduce a CR/LF; the
/// scan is over the raw bytes, with no knowledge of the response's structure. This covers the
/// **body**; a secret reflected in a response *header* is masked by [`relay_response_head`] under
/// the same decision, since the head is relayed before this runs.
///
/// Streaming-safe: a `carry` of the last `max_needle_len - 1` bytes is retained across reads, so a
/// secret split across two reads is still caught — every emitted byte was scanned in a window that
/// held the next `max_needle_len - 1` bytes, and same-length replacement never shifts a position, so
/// re-scanning the carry is harmless. Memory stays bounded at `carry + one read`.
///
/// A backstop, not a wall (see the module doc): a re-encoded, compressed, or framing-split value
/// evades the byte match. The load-bearing boundary remains the empty netns plus the allowlist; this
/// only strips the naive verbatim reflection of an injected credential.
fn pump_redacting<R: Read, W: Write>(
    r: &mut R,
    w: &mut W,
    needles: &[SecretNeedle],
) -> io::Result<()> {
    let max_len = needles
        .iter()
        .map(|n| n.as_bytes().len())
        .max()
        .unwrap_or(0);
    let keep = max_len.saturating_sub(1);
    // One window, reused for the whole stream: the carry sits at its head and each read is appended
    // behind it, so a body of any length costs the two allocations below and no more. Draining the
    // emitted prefix shifts only the carry, which is shorter than the longest needle.
    let mut window: Vec<u8> = Vec::with_capacity(keep + RELAY_CHUNK);
    let mut buf = vec![0u8; RELAY_CHUNK];
    loop {
        let n = match r.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => n,
            Err(ref e) if e.kind() == io::ErrorKind::UnexpectedEof => break,
            Err(e) => return Err(e),
        };
        window.extend_from_slice(&buf[..n]);
        redact_in_place(&mut window, needles);
        // Hold back the last `keep` bytes — a secret could begin there and complete in the next
        // read; emit everything before them.
        let split = window.len().saturating_sub(keep);
        w.write_all(&window[..split])?;
        window.drain(..split);
    }
    // The trailing carry was already scanned in its final window (a needle cannot extend past EOF).
    w.write_all(&window)?;
    w.flush().ok();
    Ok(())
}

/// Replace every occurrence of every needle in `buf` with an equal-length run of `*`, in place.
/// Equal length is the invariant the streaming framing relies on; an empty or over-long needle is
/// skipped (the empty needle is screened out at resolution, but guard here too).
pub(crate) fn redact_in_place(buf: &mut [u8], needles: &[SecretNeedle]) {
    for needle in needles {
        let len = needle.as_bytes().len();
        if len == 0 || len > buf.len() {
            continue;
        }
        // Left to right, non-overlapping: a match is masked and the search resumes past it, so a
        // needle cannot match inside the `*` run its own occurrence just produced.
        let mut at = 0;
        while let Some(found) = needle.find_in(buf, at) {
            buf[found..found + len].fill(b'*');
            at = found + len;
        }
    }
}

/// Compose one egress notice line: a bold-red `sbx:` tag, the red `head`, then each yellow
/// `label: command` action (the first joined by ` — `, the rest by `  |  `). Pure over the
/// palette so it is unit-testable in both the plain and colored forms; [`print_egress_notice`]
/// wraps it with the stderr auto-detect. Used by the `ask`-mode park alert (the interactive
/// posture where a decision is needed live); a `deny`-mode refusal instead carries its hint in
/// the `403` body, which the client already shows.
fn egress_notice_line(p: &crate::style::Palette, head: &str, actions: &[(&str, &str)]) -> String {
    let mut line = format!(
        "{err}sbx:{rst} {err}{head}{rst}",
        err = p.err,
        rst = p.reset
    );
    for (i, (label, cmd)) in actions.iter().enumerate() {
        let sep = if i == 0 { " — " } else { "  |  " };
        line.push_str(&format!(
            "{sep}{ylw}{label}: {cmd}{rst}",
            ylw = p.warn,
            rst = p.reset
        ));
    }
    line
}

/// Print one egress notice line to stderr. Colour auto-detects on stderr — a terminal with
/// `NO_COLOR` unset and `TERM` not `dumb` — via the shared [`crate::style::Palette`], so a pipe or
/// a captured run prints plain text.
fn print_egress_notice(head: &str, actions: &[(&str, &str)]) {
    let p = crate::style::Palette::for_stream(std::io::IsTerminal::is_terminal(&std::io::stderr()));
    eprintln!("{}", egress_notice_line(&p, head, actions));
}

/// Write an sbx-originated refusal: the status line, an `X-Sbx-Egress-Reason` header carrying a
/// stable machine-readable category, and a short `text/plain` body repeating the human detail.
/// A tool (and the agent it serves) can then tell an explicit policy refusal (`403`, category
/// `denied-default`/`denied-by-rule`) from an unreachable host (`502`, `upstream-unreachable`/
/// `dns-failure`) — these are the proxy's *own* statuses, distinct from a real upstream response
/// it relays verbatim (a genuine `404` reaches the agent unchanged). The category is a fixed
/// token, so it is safe in a header; the detail is sbx-authored and only ever echoes what the
/// agent already sent (its own host/port) or a category — never the injected credential, any
/// host-side secret, or the policy's internal rule text (for which `sbx test net` is the tool).
fn write_refusal<W: Write>(
    w: &mut W,
    status: &str,
    category: &str,
    detail: &str,
) -> io::Result<()> {
    let body = format!("sbx egress refused this request: {detail}\n");
    write!(
        w,
        "HTTP/1.1 {status}\r\n\
         X-Sbx-Egress-Reason: {category}\r\n\
         Content-Type: text/plain\r\n\
         Content-Length: {len}\r\n\
         Connection: close\r\n\r\n{body}",
        len = body.len(),
    )?;
    w.flush()
}

/// Write a literal string and flush — used for the cleartext `200 Connection established`.
fn write_all_str<W: Write>(w: &mut W, s: &str) -> io::Result<()> {
    w.write_all(s.as_bytes())?;
    w.flush()
}

/// Write a refusal to the client through the buffered TLS stream (the in-tunnel error paths,
/// after the CONNECT tunnel is established and TLS is terminated).
fn respond_refusal_tls<S: Read + Write>(
    br: &mut BufReader<StreamOwned<ServerConnection, S>>,
    status: &str,
    category: &str,
    detail: &str,
) -> io::Result<()> {
    write_refusal(br.get_mut(), status, category, detail)
}

/// An `InvalidData` error with a static cause, for the proxy's fail-closed paths.
fn invalid(msg: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg)
}

#[cfg(test)]
mod tests;
