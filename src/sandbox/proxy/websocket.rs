//! WebSocket proxying for the inspected (MITM) TLS path.
//!
//! Once a decrypted request is permitted and turns out to be a `Upgrade: websocket`
//! handshake, the proxy stops parsing HTTP and relays the raw bidirectional byte stream
//! between the in-cage client and the validated upstream. These helpers detect the
//! upgrade, reserialize the upgrade request/response, and pump the two directions.
//!
//! The frame decoder the relay drives — the framing, the `permessage-deflate` reassembly, the
//! capture tee and the leak tripwire — is [`super::wsframe`]: none of it is needed to forward a
//! byte, and the relay reaches it only through [`FrameTee`].

use super::capture::CaptureGuard;
use super::wsframe::{Deflate, FrameTee, negotiated_deflate};
use super::*;
use crate::sandbox::control::SecretWay;

/// Whether a decrypted request head is a WebSocket upgrade: `Upgrade: websocket` together with a
/// `Connection` header listing the `upgrade` token (both case-insensitive; `Connection` is a
/// comma-separated token list). Both are required — an `Upgrade` header without `Connection:
/// upgrade` is not an upgrade a client will complete, so it stays on the normal request path.
pub(super) fn is_websocket_upgrade(head: &Head) -> bool {
    let names_token = |header: &str, token: &str| {
        head.header(header)
            .map(|v| v.split(',').any(|t| t.trim().eq_ignore_ascii_case(token)))
            .unwrap_or(false)
    };
    names_token("upgrade", "websocket") && names_token("connection", "upgrade")
}

/// Reserialize a WebSocket upgrade handshake for forwarding upstream. Like [`reserialize_request`]
/// it injects any matching credential and strips the client's copy of an injected header, but it
/// PRESERVES the hop-by-hop `Connection`/`Upgrade` headers (and the `Sec-WebSocket-*` set) so the
/// upstream actually performs the upgrade — the opposite of the normal path, which forces
/// `Connection: close`. `Proxy-Connection` and `Expect` are still stripped (proxy-local hop headers).
pub(super) fn reserialize_upgrade(head: &Head, injections: &[(String, String)]) -> Vec<u8> {
    let mut out = String::with_capacity(head.request_line.len() + 64);
    out.push_str(&head.request_line);
    out.push_str("\r\n");
    for (k, v) in &head.headers {
        if k.eq_ignore_ascii_case("proxy-connection")
            || k.eq_ignore_ascii_case("expect")
            // A credential the client addressed to the proxy hop, never to the origin server —
            // the same rule `reserialize_request` states for every other request, and it was
            // missing only here and on the h2 rebuild. `Connection` is deliberately *not* stripped
            // alongside it: an upgrade needs its `Connection: Upgrade` to survive.
            || k.eq_ignore_ascii_case("proxy-authorization")
        {
            continue;
        }
        if injections.iter().any(|(name, _)| header_name_eq(k, name)) {
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
    out.push_str("\r\n");
    out.into_bytes()
}

/// Forward an allowed WebSocket upgrade and, on a `101`, relay the two TLS streams bidirectionally.
/// The handshake was already inspected by the same verdict as any request (host / path / method /
/// anti-fronting / SSRF / upstream-cert), so the allowlist still governs which host and path may open
/// a WebSocket; from the `101` on, the framed bytes are opaque and relayed verbatim. If the upstream
/// declines the upgrade (any non-`101`), its response is relayed as a normal one and the tunnel closes.
///
/// Takes `br` and `upstream` by value: the response phase owns both streams, and on the `101` path the
/// buffered bytes each `BufReader` read past its head are handed to [`relay_websocket`] to flush first.
///
/// `capture` is the traffic capture of the handshake, already carrying the client's request head. A
/// declined upgrade is captured like any other response (head and body); an accepted one is captured
/// up to and including the `101` and filed there — see the `101` branch for why it cannot wait.
///
/// `redactions` is the response-side reflection backstop, non-empty only for a host an injection
/// targets — the same set [`relay_response_head`] applies to every other relayed head. Both
/// handshake answers pass through it, because an upstream that echoes the injected credential in a
/// header of its own does so as readily here as anywhere else. It reaches no further than the heads:
/// the frames past a `101` are a byte-exact pipe by design, and this function's own contract.
#[allow(clippy::too_many_arguments)]
pub(super) fn relay_upgrade(
    mut br: BufReader<StreamOwned<ServerConnection, UnixStream>>,
    mut upstream: StreamOwned<ClientConnection, TcpStream>,
    inner: &Head,
    injected: &[(String, String)],
    redactions: &[SecretNeedle],
    ctx: &ProxyCtx,
    allow_seq: Option<u64>,
    capture: Option<&CaptureGuard>,
    up: Arc<AtomicU64>,
    down: Arc<AtomicU64>,
) -> io::Result<()> {
    // Forward the handshake with its upgrade headers preserved (a handshake carries no body).
    let handshake = reserialize_upgrade(inner, injected);
    upstream.write_all(&handshake)?;
    up.fetch_add(handshake.len() as u64, Ordering::Relaxed);
    upstream.flush().ok();

    // Read the upstream's response head. A BufReader may read past it into the server's first frames;
    // those buffered bytes are drained below so none is lost.
    let mut up_br = BufReader::new(upstream);
    let resp_head = read_head_buffered(&mut up_br, HEAD_MAX, head_deadline(ctx))?;

    if parse_status_code(&resp_head) != Some(101) {
        // The upstream declined the upgrade — relay its response as a normal one, then close. The
        // upstream keeps the read timeout it was given (the handshake did not force `Connection:
        // close`), so a keep-alive response without an EOF is bounded by that timeout, not hung.
        if let Some(code) = parse_status_code(&resp_head)
            && code >= 200
        {
            ctx.set_status(allow_seq, code);
        }
        // A declined upgrade is an ordinary response and is relayed as one: sbx's own
        // `Connection: close` in place of whatever the upstream said about its socket — this leg is
        // shut down at the end of this branch, and an upstream that answered `keep-alive` anyway
        // would have told the cage it could send a second request into a connection already going
        // away — and the reflection mask over the head. Written out here rather than routed through
        // [`relay_response_head`], which treats a `101` as an interim head to relay and read past.
        write_head_to_client(
            force_close_in_head(&resp_head),
            br.get_mut(),
            &down,
            redactions,
        )?;
        // Capture the head, then tee the body like any other response. The guard files when this
        // handler returns.
        if let Some(c) = capture {
            c.push_response(&resp_head);
        }
        // Framed like any ordinary response, so the relay ends at the end of the message. The
        // handshake was a `GET`, so no bodiless-method rule applies here.
        let framing = response_framing(&resp_head, "GET");
        // Count the declined response body (`down`) as it streams back to the client.
        let counted = CountingReader::new(FramedBody::new(up_br, framing), down.clone());
        let mut body = tee_response(counted, capture);
        // Teed ahead of the masking, as on every other plane: the capture masks its own buffers at
        // filing time, so what is stored is masked either way.
        if redactions.is_empty() {
            pump_to_eof(&mut body, br.get_mut())?;
        } else {
            pump_redacting(&mut body, br.get_mut(), redactions)?;
        }
        finish_tls(br.get_mut());
        return Ok(());
    }

    // What the peers agreed for payload compression, decided by this response alone.
    let deflate = negotiated_deflate(&resp_head);
    ctx.set_status(allow_seq, 101);
    // Relay the `101` to the client so it completes the WebSocket handshake. Its own hop headers
    // stand — rewriting the `Connection: Upgrade` out of it would undo the switch the two peers just
    // agreed — but it is masked like any other head sbx relays. The masking is equal-length, so what
    // the client parses is the head the upstream sent.
    write_head_to_client(resp_head.clone(), br.get_mut(), &down, redactions)?;
    br.get_mut().flush()?;
    // Capture the handshake and file it here rather than letting the guard file on return: a
    // WebSocket tunnel can stay open for hours and the log event carries exactly one amendment, so a
    // capture held open would keep the `101` out of `sbx net logs` until the tunnel closed. What is
    // captured is the handshake, both heads; the frames past it are opaque (masked, framed binary)
    // and are not captured.
    if let Some(c) = capture {
        c.push_response(&resp_head);
        c.file_now();
    }
    // Drain what each BufReader already read past its head, then relay the raw TLS streams.
    let upstream_pending = up_br.buffer().to_vec();
    let upstream = up_br.into_inner();
    let client_pending = br.buffer().to_vec();
    let client = br.into_inner();
    // The host this tunnel is bound for, which decides which learned credential the leak tripwire
    // scans for. Read off the handshake's own `Host` rather than threaded down from the CONNECT:
    // `serve_tunneled_request` refuses the request outright unless the CONNECT target, the SNI and
    // this header all canonicalize to the same name, so there is one host here and not two.
    let dest = inner.header("host").map(strip_port).unwrap_or_default();
    relay_websocket(
        client,
        &client_pending,
        upstream,
        &upstream_pending,
        deflate,
        &dest,
        TunnelObservers {
            up,
            down,
            capture,
            ctx,
            seq: allow_seq,
        },
    )
}

/// Flush a rustls connection's pending TLS output to its (non-blocking) socket, stopping when the
/// buffer is drained or the socket would block (the rest goes out on the next `POLLOUT`).
pub(super) fn flush_tls<D: rustls::SideData>(
    conn: &mut rustls::ConnectionCommon<D>,
    sock: &mut impl Write,
) -> io::Result<()> {
    while conn.wants_write() {
        match conn.write_tls(sock) {
            Ok(0) => break,
            Ok(_) => {}
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

/// Read available plaintext from a rustls connection over its (non-blocking) socket: `Some(n>0)` for
/// plaintext, `Some(0)` for end of stream (clean `close_notify` or a socket EOF), `None` when the
/// socket would block (no more data right now — wait for the next `POLLIN`). A partial TLS record
/// yields `None` rather than blocking.
pub(super) fn read_plaintext<D: rustls::SideData>(
    conn: &mut rustls::ConnectionCommon<D>,
    sock: &mut impl Read,
    buf: &mut [u8],
) -> io::Result<Option<usize>> {
    loop {
        match conn.reader().read(buf) {
            Ok(n) => return Ok(Some(n)),
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
            // An unclean peer close (a TCP FIN with no TLS `close_notify`) surfaces here as
            // `UnexpectedEof`; for a byte relay that is simply end-of-stream, the same as a clean
            // close, so treat it as EOF and half-close this direction rather than failing the relay.
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(Some(0)),
            Err(e) => return Err(e),
        }
        match conn.read_tls(sock) {
            Ok(0) => return Ok(Some(0)),
            Ok(_) => {
                conn.process_new_packets().map_err(io::Error::other)?;
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => return Ok(None),
            Err(e) => return Err(e),
        }
    }
}

/// Everything an established tunnel reports its activity to, gathered so the relay and its decoders
/// pass one value rather than five. They travel together because they answer one question between
/// them — what crossed this tunnel — for three different readers: `sbx net live` (the byte
/// counters), `sbx net logs --with-body` (the transcript), and a secret sighting on the event.
pub(super) struct TunnelObservers<'a> {
    /// Bytes cage → upstream, for the live flow view.
    pub(super) up: Arc<AtomicU64>,
    /// Bytes upstream → cage.
    pub(super) down: Arc<AtomicU64>,
    /// The capture the transcript is filed into, when this launch captures bodies.
    pub(super) capture: Option<&'a CaptureGuard>,
    /// The context a secret sighting is recorded through.
    pub(super) ctx: &'a ProxyCtx,
    /// The log event a sighting amends, or `None` when nothing was logged (tests).
    pub(super) seq: Option<u64>,
}

/// Push one direction's bytes through its decoder and act on both things that can come of it: file
/// the transcript when the capture has just filled, and report a configured secret newly seen
/// crossing. One place, so a call site cannot follow the framing and then forget half of it.
///
/// The transcript is filed whenever a direction reaches its cap, and once more when the tunnel ends
/// (in the capture guard's teardown). Each direction has its own trigger, and each fires at most
/// once: one side of a live stream can fill in seconds while the other trickles for hours, so a
/// single shared trigger would strand whichever filled second. The guard drops a filing that would
/// show what it already showed, which is what keeps the count bounded.
fn follow(
    tee: &mut Option<FrameTee>,
    chunk: &[u8],
    way: SecretWay,
    obs: &TunnelObservers,
) -> Followed {
    let Some(tee) = tee.as_mut() else {
        return Followed::default();
    };
    if tee.push(chunk)
        && let Some(c) = obs.capture
    {
        c.file_frames_snapshot();
    }
    let mut out = Followed {
        seen: false,
        blinded: tee.newly_blinded(),
    };
    for name in tee.sightings() {
        obs.ctx.websocket_secret_seen(obs.seq, &name, way);
        out.seen = true;
    }
    out
}

/// What one pass of a direction's decoder concluded, beyond the bytes it moved.
///
/// Two facts rather than one, because the relay owes each a different answer: a sighting is what
/// `websocket_secret` decides on, and a decoder that stopped is the tunnel losing the control that
/// would make that decision at all.
#[derive(Default)]
struct Followed {
    /// A configured secret was newly seen crossing this direction.
    seen: bool,
    /// The decoder just gave up on the framing while a leak scan was configured — see
    /// [`FrameTee::newly_blinded`].
    blinded: bool,
}

/// The needles a tunnel bound for `dest` scans for, on the same rule the request planes use
/// ([`SecretNeedle::scanned_for`]): every declared secret, and every credential the cage *learned*
/// except on the host it was learned from.
///
/// Scanning the whole set here contradicted that rule on the one path where it costs the most. A
/// tunnel to `chat.example` carries the session token the app obtained from `chat.example` in its
/// very first frame; the tripwire read it as a leak, and under `[network] websocket_secret = block`
/// closed the socket the app had just opened — the app cutting its own session off, reported as an
/// exfiltration attempt. The way back is filtered on the same set, so the credential's own service
/// echoing it is not filed as a secret that "came back" either.
fn tunnel_needles(needles: &[SecretNeedle], dest: &str) -> Vec<SecretNeedle> {
    needles
        .iter()
        .filter(|n| n.scanned_for(dest))
        .cloned()
        .collect()
}

/// Hand the cage's pending bytes — the frames it sent behind its handshake, before the `101` — to
/// the outbound tripwire, and then, only if they are allowed to cross, to the upstream.
///
/// One function because the **order** is the property rather than an ordering detail.
///
/// [`crate::allowlist::WebsocketSecret::Block`] states its guarantee in those terms — "the scan runs
/// on each chunk read from the cage, before that chunk is written on, so a secret whole inside one
/// chunk never crosses" — and the relay loop keeps it for every chunk it reads. On this one chunk it
/// was inverted: the frames were written into the upstream's rustls send buffer first, and what
/// follows a sighting is `send_close_notify` + [`flush_tls`], which drains the already-encrypted
/// application data ahead of the close_notify. The secret was delivered and the tunnel was closed
/// behind it — available exactly once per tunnel, on the ~8 KiB a cage that does not wait for the
/// `101` gets to choose.
///
/// A direction whose decoder has *stopped* is refused on the same terms as a sighting: under `block`
/// a tunnel this posture can no longer police must end rather than relay bytes nothing is watching.
fn seed_outbound_pending(
    to_upstream: &mut impl Write,
    pending: &[u8],
    tee: &mut Option<FrameTee>,
    obs: &TunnelObservers,
    blocking: bool,
) -> io::Result<SeededPending> {
    let followed = follow(tee, pending, SecretWay::Out, obs);
    if blocking && (followed.seen || followed.blinded) {
        return Ok(SeededPending {
            followed,
            crossed: false,
        });
    }
    to_upstream.write_all(pending)?;
    Ok(SeededPending {
        followed,
        crossed: true,
    })
}

/// What became of the bytes the cage sent behind its handshake.
struct SeededPending {
    /// What the decoder concluded about them.
    followed: Followed,
    /// Whether they were written into the upstream. `false` means the outbound gate refused them —
    /// nothing was written, and the caller must close the tunnel without relaying anything.
    crossed: bool,
}

/// Relay an established bidirectional connection (a WebSocket) between the cage `client` and the
/// `upstream`, both TLS-terminated, until each direction closes. The handshake was inspected and
/// allowed; from here every byte is opaque (masked frames), relayed verbatim both ways.
///
/// Single-threaded and **non-blocking**: the two rustls `Connection`s cannot be read and written from
/// two threads without aliasing UB, so one thread multiplexes both directions with `poll`. Each
/// direction reads plaintext from its source and buffers it into the destination's rustls send buffer,
/// which is then drained to the socket; a source is not read while its destination still has unflushed
/// output (`wants_write()`), so the buffering is bounded and neither direction couples head-of-line
/// onto the other — a stalled reader on one side cannot block the other. Idle time is parked in `poll`
/// (never in a read), so a live-but-idle channel is never cut; a dead peer that neither sends nor
/// closes is bounded by the connection cap, as for the L4 splice. Each read-side EOF half-closes only
/// that direction (a `close_notify` to the peer), so the reverse direction drains fully before teardown.
/// The bytes each side already read past its head (`*_pending`) are the tunnel's first frames, not a
/// preamble: they go through the outbound gate before anything is written on, and are seeded into the
/// send buffers only once that gate has let them by.
pub(super) fn relay_websocket(
    mut client: StreamOwned<ServerConnection, UnixStream>,
    client_pending: &[u8],
    mut upstream: StreamOwned<ClientConnection, TcpStream>,
    upstream_pending: &[u8],
    deflate: Deflate,
    dest: &str,
    obs: TunnelObservers,
) -> io::Result<()> {
    // Only a body-keeping capture has anything to file for a tunnel, so it is narrowed once, here,
    // rather than re-tested at each use — which would leave two spellings of "the capture" in scope
    // and invite a later reader to reach for the wrong one.
    let obs = TunnelObservers {
        capture: obs.capture.filter(|c| c.keeps_body()),
        ..obs
    };
    let TunnelObservers { up, down, ctx, .. } = &obs;

    // One frame decoder per direction, present when this launch has something to do with the frames:
    // a traffic capture to fill, a configured secret to watch for, or both. They see exactly the
    // bytes the relay moves — starting with the ones each side already read past its handshake head,
    // which are frames like any other and would otherwise be missed. With neither consumer the
    // framing is not followed at all and the tunnel is a plain pipe.
    let capture = obs.capture;
    let (to_upstream, to_client) = match capture {
        Some(c) => {
            let (u, d) = c.ws_sinks();
            (Some(u), Some(d))
        }
        None => (None, None),
    };
    // Each direction is decompressed under the peer that COMPRESSES it: the cage's frames by the
    // client parameters, the upstream's by the server ones.
    let (up_deflate, down_deflate) = match deflate.negotiated {
        true => (
            Some(deflate.client_no_context_takeover),
            Some(deflate.server_no_context_takeover),
        ),
        false => (None, None),
    };
    let creds = ctx.credentials.snapshot();
    let needles = tunnel_needles(&creds.needles, dest);
    let mut tee_up = FrameTee::new(to_upstream, &needles, up_deflate);
    let mut tee_down = FrameTee::new(to_client, &needles, down_deflate);
    // The transcript is filed whenever a direction reaches its cap, and once more when the tunnel
    // ends (in the capture guard's teardown). Each direction has its own trigger, and each fires at
    // most once: one side of a live stream can fill in seconds while the other trickles for hours,
    // so a single shared trigger would strand whichever filled second. The guard drops a filing that
    // would show what it already showed, which is what keeps the count bounded.
    // Whether a secret leaving through this tunnel closes it, from `[network] websocket_secret`.
    // Read from the config policy rather than the effective one: a `--session` overlay amends the
    // rules and carries every setting through untouched, so the two answer the same and this one
    // costs no clone.
    let blocking = obs.ctx.policy.websocket_secret() == crate::allowlist::WebsocketSecret::Block;
    // Said on the supervisor's stderr, once per direction: the tunnel's own log event carries secret
    // *sightings*, and "the decoder stopped" is not one — filing it as a sighting would name a
    // credential that was never seen. What the reader needs to know is that from here the transcript
    // and the tripwire cover nothing, on a tunnel that may stay open for hours.
    let report_blind = |way: SecretWay| {
        let direction = match way {
            SecretWay::Out => "cage → upstream",
            SecretWay::Back => "upstream → cage",
        };
        crate::diag::warn(&format!(
            "the WebSocket frame decoder for `{dest}` lost the framing on the {direction} \
             direction: the outbound-secret tripwire and the traffic capture cover nothing further \
             on this tunnel"
        ));
    };
    // The bytes the cage already sent behind its handshake are the tunnel's first frames, not a
    // preamble, so they go through the outbound gate before they are written on — see
    // [`seed_outbound_pending`] for why that order is the property and not an ordering detail.
    let pending_up = {
        let mut upstream_writer = upstream.conn.writer();
        seed_outbound_pending(
            &mut upstream_writer,
            client_pending,
            &mut tee_up,
            &obs,
            blocking,
        )?
    };
    if pending_up.followed.blinded {
        report_blind(SecretWay::Out);
    }
    if !pending_up.crossed {
        client.conn.send_close_notify();
        upstream.conn.send_close_notify();
        let _ = flush_tls(&mut client.conn, &mut client.sock);
        let _ = flush_tls(&mut upstream.conn, &mut upstream.sock);
        return Ok(());
    }
    up.fetch_add(client_pending.len() as u64, Ordering::Relaxed);
    // The way back is recorded and never refused, whatever `websocket_secret` says — the same rule
    // the loop below applies to every later inbound chunk — so these are seeded without a gate.
    client.conn.writer().write_all(upstream_pending)?;
    down.fetch_add(upstream_pending.len() as u64, Ordering::Relaxed);
    if follow(&mut tee_down, upstream_pending, SecretWay::Back, &obs).blinded {
        report_blind(SecretWay::Back);
    }

    client.sock.set_nonblocking(true)?;
    upstream.sock.set_nonblocking(true)?;

    let cfd = client.sock.as_raw_fd();
    let ufd = upstream.sock.as_raw_fd();
    let mut c_read_done = false; // client → upstream: client's read side reached EOF
    let mut u_read_done = false; // upstream → client: upstream's read side reached EOF
    let mut buf = [0u8; 16 * 1024];

    loop {
        // Drain pending TLS output on both sides.
        flush_tls(&mut client.conn, &mut client.sock)?;
        flush_tls(&mut upstream.conn, &mut upstream.sock)?;

        // `progressed` tracks whether a read delivered plaintext this pass. One `read_tls` can decrypt
        // several TLS records into rustls's plaintext buffer at once, but a single `reader().read`
        // returns at most `buf`; the rest sits in rustls, invisible to `poll` (which sees only the
        // socket). So while a read makes progress we loop again instead of parking in `poll` — else a
        // burst larger than `buf` on an otherwise-idle stream would strand its tail until the next
        // socket event (which, on a live long-lived WebSocket, may never come).
        let mut progressed = false;

        // client → upstream: read only while the destination can still accept (is not backpressured).
        if !c_read_done && !upstream.conn.wants_write() {
            match read_plaintext(&mut client.conn, &mut client.sock, &mut buf)? {
                Some(0) => {
                    c_read_done = true;
                    upstream.conn.send_close_notify();
                }
                Some(n) => {
                    // Scanned before it is written on, which is the whole of what `block` can
                    // promise: a secret whole inside this chunk does not reach the upstream at all.
                    // One split across chunks had its first part relayed a turn ago, and closing
                    // now stops the rest — the bound is the read size, not the tunnel.
                    let followed = follow(&mut tee_up, &buf[..n], SecretWay::Out, &obs);
                    if followed.blinded {
                        report_blind(SecretWay::Out);
                    }
                    if (followed.seen || followed.blinded) && blocking {
                        // Closed on both legs rather than dropped: a peer told the tunnel ended
                        // stops, where one left waiting on a socket that answers nothing retries.
                        // The sighting is already on the tunnel's own event, which is where a
                        // reader finds out why it ended.
                        client.conn.send_close_notify();
                        upstream.conn.send_close_notify();
                        let _ = flush_tls(&mut client.conn, &mut client.sock);
                        let _ = flush_tls(&mut upstream.conn, &mut upstream.sock);
                        return Ok(());
                    }
                    upstream.conn.writer().write_all(&buf[..n])?;
                    up.fetch_add(n as u64, Ordering::Relaxed);
                    progressed = true;
                }
                None => {}
            }
        }
        // upstream → client: symmetric.
        if !u_read_done && !client.conn.wants_write() {
            match read_plaintext(&mut upstream.conn, &mut upstream.sock, &mut buf)? {
                Some(0) => {
                    u_read_done = true;
                    client.conn.send_close_notify();
                }
                Some(n) => {
                    // The way back is recorded and never refused, whatever `websocket_secret` says.
                    // A secret arriving *into* the cage is not an exfiltration, and the answer the
                    // request planes give it is redaction rather than refusal — which a relay two
                    // peers agreed the framing of cannot do without rewriting their stream.
                    client.conn.writer().write_all(&buf[..n])?;
                    down.fetch_add(n as u64, Ordering::Relaxed);
                    if follow(&mut tee_down, &buf[..n], SecretWay::Back, &obs).blinded {
                        report_blind(SecretWay::Back);
                    }
                    progressed = true;
                }
                None => {}
            }
        }

        // Push out anything just buffered (a close_notify or relayed plaintext) before parking.
        flush_tls(&mut client.conn, &mut client.sock)?;
        flush_tls(&mut upstream.conn, &mut upstream.sock)?;

        // Done when both directions have closed and no TLS output remains to be written.
        if c_read_done && u_read_done && !client.conn.wants_write() && !upstream.conn.wants_write()
        {
            break;
        }

        // A read delivered data — more may be buffered in rustls; drain it before ever blocking. (When
        // both sources are backpressured/closed, nothing progresses and we fall through to `poll` on
        // `POLLOUT`, so this never spins.)
        if progressed {
            continue;
        }

        let mut fds = [
            libc::pollfd {
                fd: cfd,
                events: 0,
                revents: 0,
            },
            libc::pollfd {
                fd: ufd,
                events: 0,
                revents: 0,
            },
        ];
        if !c_read_done && !upstream.conn.wants_write() {
            fds[0].events |= libc::POLLIN;
        }
        if !u_read_done && !client.conn.wants_write() {
            fds[1].events |= libc::POLLIN;
        }
        if client.conn.wants_write() {
            fds[0].events |= libc::POLLOUT;
        }
        if upstream.conn.wants_write() {
            fds[1].events |= libc::POLLOUT;
        }
        // Nothing to wait for (each source is backpressured and neither has pending output) — a state
        // the done-check above normally covers; break rather than spin on a poll with no interest.
        if fds[0].events == 0 && fds[1].events == 0 {
            break;
        }
        // Indefinite: an idle live channel parks here, not in a read, so it is never cut.
        let rc = unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, -1) };
        if rc < 0 {
            if io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
                continue;
            }
            break;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sandbox::proxy::wsframe::{NEEDLE_VALUE, frame, needle};

    /// A tunnel must not scan for a credential the cage learned on the very host the tunnel goes to.
    ///
    /// `carries_secret` already waves that case through on the request planes ([`SecretNeedle::scanned_for`]):
    /// re-sending a session token to the service that issued it is the app using its own sign-in.
    /// The tunnel scanned the whole set instead, so under `[network] websocket_secret = block` the
    /// first frame carrying the app's own token closed the socket it had just opened — the app
    /// cutting off its own session, reported as an exfiltration attempt.
    ///
    /// The declared needle and the needle learned on *another* host are asserted kept in the same
    /// breath, so the filter cannot be satisfied by scanning for nothing.
    #[test]
    fn a_tunnel_does_not_scan_for_a_credential_learned_on_its_own_host() {
        const OWN: &str = "SESSION-TOKEN-OWN-HOST-01";
        const OTHER: &str = "SESSION-TOKEN-OTHER-HOST-1";
        let creds = Credentials::new(
            Vec::new(),
            vec![SecretNeedle::named("declared", NEEDLE_VALUE.to_vec())],
            crate::sandbox::redact::MIN_LEN_DEFAULT,
        );
        assert!(
            creds.observe("Authorization", &format!("Bearer {OWN}"), "chat.example"),
            "the needle learned on the tunnel's own host is the premise of this test"
        );
        assert!(
            creds.observe("Authorization", &format!("Bearer {OTHER}"), "other.example"),
            "the needle learned elsewhere is the premise of this test"
        );

        let all = creds.snapshot();
        let kept = tunnel_needles(&all.needles, "chat.example");
        let has =
            |needles: &[SecretNeedle], value: &[u8]| needles.iter().any(|n| n.as_bytes() == value);
        assert!(
            !has(&kept, OWN.as_bytes()),
            "a credential learned on chat.example must not be scanned for on a tunnel to \
             chat.example — the app's own authenticated stream is not a leak"
        );
        assert!(
            has(&kept, OTHER.as_bytes()),
            "a credential learned on another host is exactly what this tripwire exists to catch"
        );
        assert!(
            has(&kept, NEEDLE_VALUE),
            "a declared secret is scanned for everywhere, destination included"
        );
        // The exemption is scoped to the one host: the same tunnel to anywhere else still scans it.
        assert!(
            has(
                &tunnel_needles(&all.needles, "elsewhere.example"),
                OWN.as_bytes()
            ),
            "the exemption must be the host it was learned on and no other"
        );
    }

    /// The credential the client addressed to the **proxy hop** must not reach the origin server.
    ///
    /// `reserialize_request` drops `Proxy-Authorization` on both HTTP/1.1 planes, saying why in as
    /// many words; the upgrade reserializer did not, so a `ws://`/`wss://` handshake handed the
    /// far end a secret that was meant for sbx. `Connection` is asserted to survive in the same
    /// breath, because an upgrade needs it and a blanket hop-by-hop strip would break the feature
    /// this function exists for.
    #[test]
    fn a_websocket_upgrade_does_not_hand_the_proxy_credential_to_the_origin() {
        let head = Head {
            request_line: "GET /chat HTTP/1.1".to_string(),
            headers: vec![
                ("Host".to_string(), "example.com".to_string()),
                ("Upgrade".to_string(), "websocket".to_string()),
                ("Connection".to_string(), "Upgrade".to_string()),
                (
                    "Proxy-Authorization".to_string(),
                    "Basic c2J4OnNlY3JldA==".to_string(),
                ),
            ],
        };
        let wire = String::from_utf8(reserialize_upgrade(&head, &[])).expect("ascii");
        assert!(
            !wire.to_ascii_lowercase().contains("proxy-authorization"),
            "the proxy-hop credential was forwarded to the origin:\n{wire}"
        );
        assert!(
            !wire.contains("c2J4OnNlY3JldA=="),
            "the credential value survived under some other spelling:\n{wire}"
        );
        assert!(
            wire.contains("Connection: Upgrade"),
            "the upgrade's own Connection header must survive:\n{wire}"
        );
    }

    /// The frames a cage pipelines behind its handshake are gated BEFORE they are written upstream.
    ///
    /// `WebsocketSecret::Block` states its guarantee as an order — "the scan runs on each chunk read
    /// from the cage, before that chunk is written on, so a secret whole inside one chunk never
    /// crosses" — and the relay loop keeps it for every chunk it reads. On this one chunk the write
    /// came first: the frames were already in the upstream's rustls send buffer, and the `flush_tls`
    /// that follows the close drains encrypted application data ahead of the close_notify, so the
    /// secret was delivered and the tunnel was closed behind it. A cage that does not wait for the
    /// `101` chooses those bytes, so the bypass was available exactly once per tunnel, on the frames
    /// the attacker picks.
    #[test]
    fn frames_pipelined_behind_the_handshake_are_gated_before_they_are_written_upstream() {
        let ctx = ProxyCtx::new(
            Arc::new(Ca::ephemeral().unwrap()),
            crate::allowlist::EgressPolicy::default(),
        )
        .unwrap();
        let obs = TunnelObservers {
            up: Arc::new(AtomicU64::new(0)),
            down: Arc::new(AtomicU64::new(0)),
            capture: None,
            ctx: &ctx,
            seq: None,
        };
        // Exactly what a cage writes in the same `write_all` as its upgrade request head: a masked
        // text frame carrying a declared secret.
        let carrying = frame(0x1, NEEDLE_VALUE, Some([0x37, 0xfa, 0x21, 0x3d]));
        let ordinary = frame(0x1, br#"{"hello":"world"}"#, Some([1, 2, 3, 4]));

        let mut tee = FrameTee::new(None, &[needle()], None);
        let mut upstream = Vec::new();
        let seeded = seed_outbound_pending(&mut upstream, &carrying, &mut tee, &obs, true).unwrap();
        assert!(
            seeded.followed.seen,
            "the pipelined frame carries the value the tripwire exists for"
        );
        assert!(!seeded.crossed, "so under `block` it must not cross");
        assert!(
            upstream.is_empty(),
            "not one byte may reach the upstream's send buffer: {upstream:?}"
        );

        // Under `warn` the tunnel stays byte-exact, sighting or not — so this cannot be satisfied by
        // a gate that never writes.
        let mut tee = FrameTee::new(None, &[needle()], None);
        let mut upstream = Vec::new();
        let seeded =
            seed_outbound_pending(&mut upstream, &carrying, &mut tee, &obs, false).unwrap();
        assert!(seeded.followed.seen && seeded.crossed);
        assert_eq!(upstream, carrying, "`warn` records and relays");

        // And ordinary pipelined frames cross under `block` too: what closes the tunnel is the
        // sighting, never the pipelining.
        let mut tee = FrameTee::new(None, &[needle()], None);
        let mut upstream = Vec::new();
        let seeded = seed_outbound_pending(&mut upstream, &ordinary, &mut tee, &obs, true).unwrap();
        assert!(!seeded.followed.seen && seeded.crossed);
        assert_eq!(upstream, ordinary);
    }
}
