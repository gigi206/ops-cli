//! WebSocket proxying for the inspected (MITM) TLS path.
//!
//! Once a decrypted request is permitted and turns out to be a `Upgrade: websocket`
//! handshake, the proxy stops parsing HTTP and relays the raw bidirectional byte stream
//! between the in-cage client and the validated upstream. These helpers detect the
//! upgrade, reserialize the upgrade request/response, and pump the two directions.

use super::*;

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
pub(super) fn reserialize_upgrade(head: &Head, injections: &[(&str, &str)]) -> Vec<u8> {
    let mut out = String::with_capacity(head.request_line.len() + 64);
    out.push_str(&head.request_line);
    out.push_str("\r\n");
    for (k, v) in &head.headers {
        if k.eq_ignore_ascii_case("proxy-connection") || k.eq_ignore_ascii_case("expect") {
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
#[allow(clippy::too_many_arguments)]
pub(super) fn relay_upgrade(
    mut br: BufReader<StreamOwned<ServerConnection, UnixStream>>,
    mut upstream: StreamOwned<ClientConnection, TcpStream>,
    inner: &Head,
    injected: &[(&str, &str)],
    ctx: &ProxyCtx,
    allow_seq: Option<u64>,
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
    let resp_head = read_head_buffered(&mut up_br, HEAD_MAX)?;

    if parse_status_code(&resp_head) != Some(101) {
        // The upstream declined the upgrade — relay its response as a normal one, then close. The
        // upstream keeps the read timeout it was given (the handshake did not force `Connection:
        // close`), so a keep-alive response without an EOF is bounded by that timeout, not hung.
        if let Some(code) = parse_status_code(&resp_head) {
            if code >= 200 {
                ctx.set_status(allow_seq, code);
            }
        }
        br.get_mut().write_all(&resp_head)?;
        down.fetch_add(resp_head.len() as u64, Ordering::Relaxed);
        // Count the declined response body (`down`) as it streams back to the client.
        pump_to_eof(
            &mut CountingReader::new(&mut up_br, down.clone()),
            br.get_mut(),
        )?;
        finish_tls(br.get_mut());
        return Ok(());
    }

    ctx.set_status(allow_seq, 101);
    // Relay the `101` to the client so it completes the WebSocket handshake.
    br.get_mut().write_all(&resp_head)?;
    br.get_mut().flush()?;
    down.fetch_add(resp_head.len() as u64, Ordering::Relaxed);
    // Drain what each BufReader already read past its head, then relay the raw TLS streams.
    let upstream_pending = up_br.buffer().to_vec();
    let upstream = up_br.into_inner();
    let client_pending = br.buffer().to_vec();
    let client = br.into_inner();
    relay_websocket(
        client,
        &client_pending,
        upstream,
        &upstream_pending,
        up,
        down,
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
/// The bytes each side already read past its head (`*_pending`) are seeded into the send buffers first.
pub(super) fn relay_websocket(
    mut client: StreamOwned<ServerConnection, UnixStream>,
    client_pending: &[u8],
    mut upstream: StreamOwned<ClientConnection, TcpStream>,
    upstream_pending: &[u8],
    up: Arc<AtomicU64>,
    down: Arc<AtomicU64>,
) -> io::Result<()> {
    // Seed the already-read bytes into the destination send buffers (the loop flushes them out), and
    // count them (`up` = client→upstream, `down` = upstream→client) toward the live flow view.
    upstream.conn.writer().write_all(client_pending)?;
    client.conn.writer().write_all(upstream_pending)?;
    up.fetch_add(client_pending.len() as u64, Ordering::Relaxed);
    down.fetch_add(upstream_pending.len() as u64, Ordering::Relaxed);
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
                    client.conn.writer().write_all(&buf[..n])?;
                    down.fetch_add(n as u64, Ordering::Relaxed);
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
