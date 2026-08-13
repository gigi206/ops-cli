use super::ca::CertResolver;
use super::*;
use crate::allowlist::{DefaultAction, EgressPolicy, classify};
use crate::testutil::TmpDir;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::os::unix::net::{UnixListener, UnixStream};
use std::thread;

use rustls::pki_types::{CertificateDer, ServerName};
use rustls::{
    ClientConfig, ClientConnection, RootCertStore, ServerConfig, ServerConnection, StreamOwned,
};

#[test]
fn counting_reader_and_writer_tally_bytes() {
    // The building block the relay uses to feed `sbx net live`'s byte counters: every byte read
    // or written is added to the shared atomic.
    let up = Arc::new(AtomicU64::new(0));
    let mut src = io::Cursor::new(vec![0u8; 5000]);
    let mut sink = Vec::new();
    io::copy(&mut CountingReader::new(&mut src, up.clone()), &mut sink).unwrap();
    assert_eq!(up.load(Ordering::Relaxed), 5000, "reader counts every byte");

    let down = Arc::new(AtomicU64::new(0));
    let mut out = Vec::new();
    {
        let mut cw = CountingWriter::new(&mut out, down.clone());
        cw.write_all(&[7u8; 300]).unwrap();
        cw.flush().unwrap();
    }
    assert_eq!(
        down.load(Ordering::Relaxed),
        300,
        "writer counts every byte"
    );
    assert_eq!(
        out.len(),
        300,
        "the wrapped writer still passes bytes through"
    );
}

#[test]
fn splice_copy_tallies_both_directions() {
    // Drive the real `splice_copy` (the L4 path) through an echo upstream and assert both byte
    // counters land — the wiring, not just the wrappers in isolation.
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let echo = thread::spawn(move || {
        let (mut sock, _) = listener.accept().unwrap();
        let mut buf = [0u8; 4096];
        while let Ok(n) = sock.read(&mut buf) {
            if n == 0 || sock.write_all(&buf[..n]).is_err() {
                break;
            }
        }
    });

    let (mut test_end, cage_end) = UnixStream::pair().unwrap();
    let upstream = TcpStream::connect(addr).unwrap();
    let up = Arc::new(AtomicU64::new(0));
    let down = Arc::new(AtomicU64::new(0));
    let (u, d) = (up.clone(), down.clone());
    let splicer = thread::spawn(move || {
        let _ = splice_copy(cage_end, upstream, u, d);
    });

    let payload = vec![42u8; 2000];
    test_end.write_all(&payload).unwrap();
    let mut got = vec![0u8; payload.len()];
    test_end.read_exact(&mut got).unwrap();
    assert_eq!(got, payload, "the echo round-trips the payload");
    // Close the cage side so the splice observes EOF and tears down (its internal join completes).
    test_end.shutdown(std::net::Shutdown::Both).unwrap();

    splicer.join().unwrap();
    echo.join().unwrap();
    assert_eq!(
        up.load(Ordering::Relaxed),
        2000,
        "client→upstream bytes counted (up)"
    );
    assert_eq!(
        down.load(Ordering::Relaxed),
        2000,
        "upstream→client bytes counted (down)"
    );
}

/// A policy allowing exactly the given entries (no deny), for the proxy tests.
fn policy(entries: &[&str]) -> EgressPolicy {
    EgressPolicy::new(
        entries.iter().map(|e| classify(e).unwrap()).collect(),
        vec![],
    )
}

/// A one-shot loopback TLS "upstream": its own ephemeral CA mints a leaf for `host`; it accepts
/// one connection, reads the request head, and replies with `response`. Returns its address,
/// the CA the proxy must trust to validate it, and the join handle.
fn spawn_upstream(
    host: &'static str,
    response: &'static [u8],
) -> (SocketAddr, CertificateDer<'static>, thread::JoinHandle<()>) {
    let ca = Arc::new(Ca::ephemeral().unwrap());
    let ca_der = ca.ca_cert_der();
    let server_config = Arc::new(
        ServerConfig::builder()
            .with_no_client_auth()
            .with_cert_resolver(Arc::new(CertResolver::new(ca))),
    );
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = thread::spawn(move || {
        // tolerate errors: a forged-upstream test makes the proxy's validation fail, which
        // aborts this side's handshake — that must not panic a detached thread.
        let Ok((sock, _)) = listener.accept() else {
            return;
        };
        let Ok(conn) = ServerConnection::new(server_config) else {
            return;
        };
        let mut tls = StreamOwned::new(conn, sock);
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
        let _ = tls.write_all(response);
        let _ = tls.flush();
    });
    let _ = host;
    (addr, ca_der, handle)
}

/// Like [`spawn_upstream`] but streams its reply in two parts with an idle gap between them — a
/// stand-in for a streaming completion / server-sent-events response that pauses between bursts.
/// It sends `head_and_first`, sleeps `idle`, sends `rest`, then closes (EOF ends the relay).
fn spawn_upstream_idle(
    head_and_first: &'static [u8],
    idle: Duration,
    rest: &'static [u8],
) -> (SocketAddr, CertificateDer<'static>, thread::JoinHandle<()>) {
    let ca = Arc::new(Ca::ephemeral().unwrap());
    let ca_der = ca.ca_cert_der();
    let server_config = Arc::new(
        ServerConfig::builder()
            .with_no_client_auth()
            .with_cert_resolver(Arc::new(CertResolver::new(ca))),
    );
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = thread::spawn(move || {
        let Ok((sock, _)) = listener.accept() else {
            return;
        };
        let Ok(conn) = ServerConnection::new(server_config) else {
            return;
        };
        let mut tls = StreamOwned::new(conn, sock);
        // drain the request head so the reply is not pipelined ahead of it
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
        let _ = tls.write_all(head_and_first);
        let _ = tls.flush();
        thread::sleep(idle);
        let _ = tls.write_all(rest);
        let _ = tls.flush();
    });
    (addr, ca_der, handle)
}

/// Like [`spawn_upstream`] but reports the request head it received over a channel, so a test
/// can assert what the proxy actually forwarded (e.g. a forced `Connection: close`).
fn spawn_upstream_capturing(
    response: &'static [u8],
) -> (
    SocketAddr,
    CertificateDer<'static>,
    std::sync::mpsc::Receiver<String>,
) {
    let ca = Arc::new(Ca::ephemeral().unwrap());
    let ca_der = ca.ca_cert_der();
    let server_config = Arc::new(
        ServerConfig::builder()
            .with_no_client_auth()
            .with_cert_resolver(Arc::new(CertResolver::new(ca))),
    );
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let (tx, rx) = std::sync::mpsc::channel();
    thread::spawn(move || {
        let Ok((sock, _)) = listener.accept() else {
            return;
        };
        let Ok(conn) = ServerConnection::new(server_config) else {
            return;
        };
        let mut tls = StreamOwned::new(conn, sock);
        let mut head = String::new();
        {
            let mut br = BufReader::new(&mut tls);
            let mut line = String::new();
            loop {
                line.clear();
                match br.read_line(&mut line) {
                    Ok(0) | Err(_) => break,
                    Ok(_) if line == "\r\n" || line == "\n" => break,
                    Ok(_) => head.push_str(&line),
                }
            }
        }
        let _ = tx.send(head);
        let _ = tls.write_all(response);
        let _ = tls.flush();
    });
    (addr, ca_der, rx)
}

/// Drive one HTTPS request through the proxy over a freshly bound UDS, returning the decrypted
/// response. The client trusts only `proxy_ca` (the proxy's interception CA).
fn through_proxy(
    ctx: Arc<ProxyCtx>,
    proxy_ca: CertificateDer<'static>,
    connect_host: &str,
    sni_host: &str,
    connect_port: u16,
    request: &[u8],
) -> io::Result<String> {
    let dir = TmpDir::new();
    let path = dir.join("proxy.sock");
    let listener = UnixListener::bind(&path).unwrap();
    thread::spawn(move || {
        let _ = serve(listener, ctx);
    });

    let mut sock = UnixStream::connect(&path).unwrap();
    write!(
        sock,
        "CONNECT {connect_host}:{connect_port} HTTP/1.1\r\n\r\n"
    )
    .unwrap();
    sock.flush().unwrap();
    // read the cleartext CONNECT reply up to the blank line (nothing follows until we speak TLS)
    let established = read_until_blank(&mut sock)?;
    assert!(
        established.contains("200 Connection established"),
        "CONNECT not accepted: {established:?}"
    );

    let mut roots = RootCertStore::empty();
    roots.add(proxy_ca).unwrap();
    let client_config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    // the TLS SNI is sent independently of the CONNECT host, so a test can mismatch them
    let name = ServerName::try_from(sni_host.to_string()).unwrap();
    let conn = ClientConnection::new(Arc::new(client_config), name).map_err(io::Error::other)?;
    let mut tls = StreamOwned::new(conn, sock);
    tls.write_all(request)?;
    tls.flush().ok();
    let mut resp = String::new();
    // the proxy closes the tunnel after the one response, so read-to-end terminates
    match tls.read_to_string(&mut resp) {
        Ok(_) => {}
        Err(ref e) if e.kind() == io::ErrorKind::UnexpectedEof => {}
        Err(e) => return Err(e),
    }
    Ok(resp)
}

/// Like [`through_proxy`] but does NOT tolerate a missing TLS `close_notify`: the final read must
/// terminate cleanly (`Ok`), so a test can assert the proxy shuts the intercepted TLS down
/// properly instead of dropping the socket — the exact defect a streaming client reports as
/// `peer closed connection without sending TLS close_notify`.
fn through_proxy_clean_close(
    ctx: Arc<ProxyCtx>,
    proxy_ca: CertificateDer<'static>,
    connect_host: &str,
    connect_port: u16,
    request: &[u8],
) -> io::Result<String> {
    let dir = TmpDir::new();
    let path = dir.join("proxy.sock");
    let listener = UnixListener::bind(&path).unwrap();
    thread::spawn(move || {
        let _ = serve(listener, ctx);
    });
    let mut sock = UnixStream::connect(&path).unwrap();
    write!(
        sock,
        "CONNECT {connect_host}:{connect_port} HTTP/1.1\r\n\r\n"
    )
    .unwrap();
    sock.flush().unwrap();
    let established = read_until_blank(&mut sock)?;
    assert!(
        established.contains("200 Connection established"),
        "CONNECT not accepted: {established:?}"
    );
    let mut roots = RootCertStore::empty();
    roots.add(proxy_ca).unwrap();
    let client_config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let name = ServerName::try_from(connect_host.to_string()).unwrap();
    let conn = ClientConnection::new(Arc::new(client_config), name).map_err(io::Error::other)?;
    let mut tls = StreamOwned::new(conn, sock);
    tls.write_all(request)?;
    tls.flush().ok();
    let mut resp = String::new();
    // Propagate a missing close_notify (UnexpectedEof) instead of swallowing it — the whole point.
    tls.read_to_string(&mut resp)?;
    Ok(resp)
}

/// A one-shot loopback TLS "upstream" that speaks a WebSocket: it reads the upgrade head, replies
/// `101 Switching Protocols`, immediately pushes an unsolicited `S-FIRST;` (server→client, so a
/// test proves that direction and that the bytes buffered past the `101` are not lost), then reads
/// the client's frame and echoes it back as `ECHO:<frame>` (client→upstream→client), then closes.
fn spawn_ws_upstream() -> (SocketAddr, CertificateDer<'static>, thread::JoinHandle<()>) {
    let ca = Arc::new(Ca::ephemeral().unwrap());
    let ca_der = ca.ca_cert_der();
    let server_config = Arc::new(
        ServerConfig::builder()
            .with_no_client_auth()
            .with_cert_resolver(Arc::new(CertResolver::new(ca))),
    );
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = thread::spawn(move || {
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
        let _ = tls.write_all(
            b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\
                  Connection: Upgrade\r\nSec-WebSocket-Accept: test-accept\r\n\r\nS-FIRST;",
        );
        let _ = tls.flush();
        let mut buf = [0u8; 64];
        if let Ok(n) = tls.read(&mut buf) {
            let mut echo = b"ECHO:".to_vec();
            echo.extend_from_slice(&buf[..n]);
            let _ = tls.write_all(&echo);
            let _ = tls.flush();
        }
    });
    (addr, ca_der, handle)
}

/// Read a TLS (or any) stream up to the `\r\n\r\n` blank-line terminator, leaving anything after it
/// unread (so post-`101` frames stay in the stream).
fn read_head_until_blank<R: Read>(r: &mut R) -> io::Result<String> {
    let mut buf = Vec::new();
    let mut one = [0u8; 1];
    loop {
        if r.read(&mut one)? == 0 {
            break;
        }
        buf.push(one[0]);
        if buf.ends_with(b"\r\n\r\n") {
            break;
        }
    }
    Ok(String::from_utf8_lossy(&buf).into_owned())
}

/// Drive one WebSocket upgrade through the proxy: CONNECT + TLS, send the upgrade, read the `101`,
/// send a client frame, then read everything the server sent until close. Returns the whole
/// decrypted transcript (the `101` head + every relayed byte both the server pushed and echoed).
fn through_proxy_websocket(
    ctx: Arc<ProxyCtx>,
    proxy_ca: CertificateDer<'static>,
    connect_host: &str,
    connect_port: u16,
) -> io::Result<String> {
    let dir = TmpDir::new();
    let path = dir.join("proxy.sock");
    let listener = UnixListener::bind(&path).unwrap();
    thread::spawn(move || {
        let _ = serve(listener, ctx);
    });
    let mut sock = UnixStream::connect(&path).unwrap();
    write!(
        sock,
        "CONNECT {connect_host}:{connect_port} HTTP/1.1\r\n\r\n"
    )
    .unwrap();
    sock.flush().unwrap();
    let established = read_until_blank(&mut sock)?;
    assert!(
        established.contains("200 Connection established"),
        "CONNECT not accepted: {established:?}"
    );
    let mut roots = RootCertStore::empty();
    roots.add(proxy_ca).unwrap();
    let client_config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let name = ServerName::try_from(connect_host.to_string()).unwrap();
    let conn = ClientConnection::new(Arc::new(client_config), name).map_err(io::Error::other)?;
    let mut tls = StreamOwned::new(conn, sock);
    let upgrade = format!(
        "GET /chat HTTP/1.1\r\nHost: {connect_host}\r\nUpgrade: websocket\r\n\
             Connection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
             Sec-WebSocket-Version: 13\r\n\r\n"
    );
    // Everything after the CONNECT is best-effort: on a refusal the proxy writes its status over
    // the tunnel and closes, so any of these can hit a closed connection — that is the denied
    // case, where the transcript is simply the refusal the proxy sent.
    let _ = tls.write_all(upgrade.as_bytes());
    let _ = tls.flush();
    let head = read_head_until_blank(&mut tls).unwrap_or_default();
    // Only send a client frame on an established WebSocket. On a non-`101` (a refusal, or an
    // upstream that declined the upgrade) the tunnel is closing, so writing would RST the socket
    // and discard the buffered response body before `read_to_string` can relay it.
    if head.contains("101 Switching Protocols") {
        let _ = tls.write_all(b"client-frame");
        let _ = tls.flush();
    }
    let mut rest = String::new();
    let _ = tls.read_to_string(&mut rest);
    Ok(format!("{head}{rest}"))
}

/// Read bytes until the `\r\n\r\n` blank-line terminator (cleartext CONNECT reply).
fn read_until_blank(sock: &mut UnixStream) -> io::Result<String> {
    let mut buf = Vec::new();
    let mut one = [0u8; 1];
    loop {
        if sock.read(&mut one)? == 0 {
            break;
        }
        buf.push(one[0]);
        if buf.ends_with(b"\r\n\r\n") {
            break;
        }
    }
    Ok(String::from_utf8_lossy(&buf).into_owned())
}

/// A one-shot **plaintext** (no TLS) loopback upstream for the `http://` cleartext path: it
/// accepts one connection, reports the request head it received over a channel (so a test can
/// assert the proxy forwarded origin-form with `Connection: close`), and replies with `response`.
fn spawn_plain_upstream(
    response: &'static [u8],
) -> (SocketAddr, std::sync::mpsc::Receiver<String>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let (tx, rx) = std::sync::mpsc::channel();
    thread::spawn(move || {
        let Ok((mut sock, _)) = listener.accept() else {
            return;
        };
        let mut head = String::new();
        {
            let mut br = BufReader::new(&mut sock);
            let mut line = String::new();
            loop {
                line.clear();
                match br.read_line(&mut line) {
                    Ok(0) | Err(_) => break,
                    Ok(_) if line == "\r\n" || line == "\n" => break,
                    Ok(_) => head.push_str(&line),
                }
            }
        }
        let _ = tx.send(head);
        let _ = sock.write_all(response);
        let _ = sock.flush();
    });
    (addr, rx)
}

/// Drive one **cleartext** (`http://`) absolute-form request through the proxy over a freshly
/// bound UDS — no CONNECT, no TLS, exactly what a tool with `http_proxy` set sends. Returns the
/// plaintext response the proxy relayed (or its refusal).
fn through_cleartext(ctx: Arc<ProxyCtx>, request: &[u8]) -> io::Result<String> {
    let dir = TmpDir::new();
    let path = dir.join("proxy.sock");
    let listener = UnixListener::bind(&path).unwrap();
    thread::spawn(move || {
        let _ = serve(listener, ctx);
    });
    let mut sock = UnixStream::connect(&path).unwrap();
    sock.write_all(request)?;
    sock.flush().ok();
    let mut resp = String::new();
    match sock.read_to_string(&mut resp) {
        Ok(_) => {}
        Err(ref e) if e.kind() == io::ErrorKind::UnexpectedEof => {}
        Err(e) => return Err(e),
    }
    Ok(resp)
}

#[test]
fn ca_cert_is_a_pem_certificate_block() {
    let ca = Ca::ephemeral().unwrap();
    let pem = ca.ca_cert_pem();
    assert!(pem.starts_with("-----BEGIN CERTIFICATE-----"));
    assert!(pem.trim_end().ends_with("-----END CERTIFICATE-----"));
}

#[test]
fn leaf_for_caches_per_host() {
    let ca = Ca::ephemeral().unwrap();
    let a1 = ca.leaf_for("example.com").unwrap();
    let a2 = ca.leaf_for("example.com").unwrap();
    let b = ca.leaf_for("other.com").unwrap();
    assert!(Arc::ptr_eq(&a1, &a2), "same host reuses one minted leaf");
    assert!(!Arc::ptr_eq(&a1, &b), "a different host gets its own leaf");
    assert!(
        !a1.cert.is_empty() && !b.cert.is_empty(),
        "each leaf carries a certificate chain"
    );
}

/// The productized spike: a client that trusts only the ephemeral CA completes a TLS
/// handshake to a server whose certificate is minted on the fly by the [`CertResolver`]
/// for the SNI host. This is the interception seam — if the resolver or the CA signing
/// were wrong, the handshake would fail.
#[test]
fn a_client_trusting_the_ca_handshakes_through_the_resolver() {
    let ca = Arc::new(Ca::ephemeral().unwrap());
    let ca_der = ca.ca_cert_der();

    let server_config = ServerConfig::builder()
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(CertResolver::new(ca.clone())));
    let server_config = Arc::new(server_config);

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let srv = thread::spawn(move || {
        let (sock, _) = listener.accept().unwrap();
        let conn = ServerConnection::new(server_config).unwrap();
        let mut tls = StreamOwned::new(conn, sock);
        let mut buf = [0u8; 64];
        let n = tls.read(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"PING");
        tls.write_all(b"PONG").unwrap();
        tls.flush().ok();
    });

    let mut roots = RootCertStore::empty();
    roots.add(ca_der).unwrap();
    let client_config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let name = ServerName::try_from("example.com").unwrap().to_owned();
    let sock = TcpStream::connect(addr).unwrap();
    let conn = ClientConnection::new(Arc::new(client_config), name).unwrap();
    let mut tls = StreamOwned::new(conn, sock);
    tls.write_all(b"PING").unwrap();
    tls.flush().ok();
    let mut resp = [0u8; 64];
    let n = tls.read(&mut resp).unwrap();
    assert_eq!(&resp[..n], b"PONG");
    srv.join().unwrap();
}

/// The happy path end to end: an allowed request is MITM'd, forwarded to a loopback upstream
/// validated against its own CA, and the response is streamed back. Proves the byte plumbing
/// across both read boundaries (CONNECT head → ClientHello, inner head → response body).
#[test]
fn an_allowed_request_is_proxied_to_a_validated_upstream() {
    let (addr, upstream_ca, up) = spawn_upstream(
        "upstream.test",
        b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello",
    );

    let proxy_ca = Arc::new(Ca::ephemeral().unwrap());
    let proxy_ca_der = proxy_ca.ca_cert_der();
    let mut roots = RootCertStore::empty();
    roots.add(upstream_ca).unwrap();
    let upstream_cfg = Arc::new(
        ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth(),
    );
    // allow the host on any port (the upstream's ephemeral port); resolve it to loopback —
    // permitted only because the deciding rule names this exact host (the explicit-internal case)
    let sdir = TmpDir::new();
    let stats = Arc::new(crate::sandbox::egress_stats::EgressStats::new(
        sdir.join("stats"),
        "/t".into(),
        None,
    ));
    let log = Arc::new(crate::sandbox::control::LogRing::new(
        crate::sandbox::control::LOG_RING_CAP,
    ));
    let ctx = Arc::new(
        ProxyCtx::new(proxy_ca, policy(&["upstream.test:*"]))
            .unwrap()
            .with_upstream(upstream_cfg)
            .with_stats(stats.clone())
            .with_log(log.clone())
            .with_resolver(Box::new(|_| Ok(vec![IpAddr::from([127, 0, 0, 1])]))),
    );

    let resp = through_proxy(
            ctx,
            proxy_ca_der,
            "upstream.test",
            "upstream.test",
            addr.port(),
            b"GET /path HTTP/1.1\r\nHost: upstream.test\r\nContent-Type: application/connect+proto\r\nConnection: close\r\n\r\n",
        )
        .unwrap();
    up.join().unwrap();
    assert!(
        resp.contains("200 OK"),
        "no 200 from the upstream: {resp:?}"
    );
    assert!(
        resp.contains("hello"),
        "the body was not streamed back: {resp:?}"
    );
    // A forwarded request lands in the `allow` bucket (the one bucket counted only after the
    // upstream connects — the refusal buckets are pinned in `each_refusal_site_records_…`).
    assert_eq!(
        stats.snapshot()["upstream.test"].allow,
        1,
        "an egressed request must record one allow"
    );
    // …and the same forwarded request emits exactly one `allow` log event carrying its method
    // and path (the `allow` site the refusal-transcript test cannot reach).
    let events = log.snapshot(None, None, false).events;
    assert_eq!(events.len(), 1, "one allow event: {events:?}");
    assert_eq!(
        events[0].verdict,
        crate::sandbox::control::LogVerdict::Allow
    );
    assert_eq!(events[0].reason, "allowed");
    assert_eq!(events[0].host, "upstream.test");
    assert_eq!(events[0].method.as_deref(), Some("GET"));
    assert_eq!(events[0].path.as_deref(), Some("/path"));
    // The inspected HTTP/1.1 MITM forward is stamped `h1`, and its `Content-Type` is classified —
    // the motivating case (the agent hosts ride HTTP/1.1, so their RPC framing must surface here,
    // not only on the h2 path). A Connect-streaming content-type tags `connect`.
    assert_eq!(
        events[0].http_ver,
        crate::sandbox::control::HttpVer::H1,
        "an inspected h1 MITM forward is stamped h1"
    );
    assert_eq!(
        events[0].rpc,
        crate::sandbox::control::RpcKind::Connect,
        "the request's connect content-type is recognized and tagged"
    );
}

/// A muted refusal (`dontaudit`) is routed away from the default log view yet still counted — the
/// load-bearing routing: `outcome` sends a mute-matched deny to the log's separate ring, so the
/// default snapshot omits it, `--all` recovers it (tagged `muted`), and the stat counter records
/// it regardless (collapse, never destroy). Needs no TLS round-trip — `outcome` is the one
/// decision chokepoint, driven directly.
#[test]
fn a_muted_deny_is_kept_out_of_the_default_log_yet_still_counted() {
    let sdir = TmpDir::new();
    let stats = Arc::new(crate::sandbox::egress_stats::EgressStats::new(
        sdir.join("stats"),
        "/t".into(),
        None,
    ));
    let log = Arc::new(crate::sandbox::control::LogRing::new(
        crate::sandbox::control::LOG_RING_CAP,
    ));
    // Deny-by-default, muting exactly one host.
    let policy = crate::allowlist::EgressPolicy::new(vec![], vec![]).with_mute(vec![
        crate::allowlist::classify("play.googleapis.com").unwrap(),
    ]);
    let ctx = ProxyCtx::new(Arc::new(Ca::ephemeral().unwrap()), policy)
        .unwrap()
        .with_stats(stats.clone())
        .with_log(log.clone());

    // One refusal to the muted host, one to an unmuted host.
    ctx.outcome(
        crate::sandbox::control::Proto::Https,
        "play.googleapis.com",
        443,
        Some("POST"),
        Some("/log"),
        StatKind::Deny,
        "denied-default",
    );
    ctx.outcome(
        crate::sandbox::control::Proto::Https,
        "api.example.com",
        443,
        Some("GET"),
        Some("/x"),
        StatKind::Deny,
        "denied-default",
    );

    // The default view shows ONLY the unmuted refusal.
    let default_view = log.snapshot(None, None, false).events;
    assert_eq!(
        default_view.len(),
        1,
        "the default view hides the muted refusal: {default_view:?}"
    );
    assert_eq!(default_view[0].host, "api.example.com");
    assert!(!default_view[0].muted);

    // `--all` folds the muted ring back in, and the suppressed refusal is tagged.
    let all = log.snapshot(None, None, true).events;
    assert_eq!(all.len(), 2, "--all recovers the muted refusal: {all:?}");
    let muted_ev = all
        .iter()
        .find(|e| e.host == "play.googleapis.com")
        .expect("the muted refusal is recoverable under --all");
    assert!(muted_ev.muted, "the recovered refusal is tagged muted");
    assert_eq!(muted_ev.verdict, crate::sandbox::control::LogVerdict::Deny);

    // Both refusals are counted regardless of muting — the audit collapses, it is not destroyed.
    let snap = stats.snapshot();
    assert_eq!(
        snap["play.googleapis.com"].deny, 1,
        "a muted refusal is still counted in stats"
    );
    assert_eq!(snap["api.example.com"].deny, 1);
}

/// A live `--session` mute (loaded into the manual overlay, no config mute at all) suppresses a
/// deny exactly like a config mute — proving `outcome` consults the *effective* policy (config ∪
/// overlay), which is the whole point of the session path.
#[test]
fn a_session_mute_overlay_suppresses_a_deny_like_a_config_mute() {
    let sdir = TmpDir::new();
    let stats = Arc::new(crate::sandbox::egress_stats::EgressStats::new(
        sdir.join("stats"),
        "/t".into(),
        None,
    ));
    let log = Arc::new(crate::sandbox::control::LogRing::new(
        crate::sandbox::control::LOG_RING_CAP,
    ));
    // The policy carries NO config mute — the suppression can only come from the overlay.
    let ctx = ProxyCtx::new(
        Arc::new(Ca::ephemeral().unwrap()),
        crate::allowlist::EgressPolicy::new(vec![], vec![]),
    )
    .unwrap()
    .with_stats(stats.clone())
    .with_log(log.clone());
    // Load a live session mute — exactly what `REMEMBER MUTE` does on the control socket.
    ctx.manual
        .remember_mute(crate::allowlist::classify("play.googleapis.com").unwrap());

    ctx.outcome(
        crate::sandbox::control::Proto::Https,
        "play.googleapis.com",
        443,
        Some("POST"),
        Some("/log"),
        StatKind::Deny,
        "denied-default",
    );

    assert!(
        log.snapshot(None, None, false).events.is_empty(),
        "a session mute keeps the refusal out of the default view"
    );
    let all = log.snapshot(None, None, true).events;
    assert_eq!(all.len(), 1, "--all recovers the session-muted refusal");
    assert!(all[0].muted, "the recovered refusal is tagged muted");
    assert_eq!(
        stats.snapshot()["play.googleapis.com"].deny,
        1,
        "a session-muted refusal is still counted"
    );
}

/// A streamed response that idles longer than the per-read timeout must not be cut: the failure
/// that truncated streaming agents mid-completion with a rustls "peer closed
/// connection without sending TLS close_notify". The timeout is shrunk to 200 ms and the upstream
/// pauses 500 ms mid-response; the whole body must still arrive. Teeth: without
/// `begin_response_stream` lifting the upstream read timeout, the pause aborts the relay and the
/// second half is lost — the assertion on `second` fails.
#[test]
fn a_streaming_response_that_idles_past_the_timeout_is_not_cut() {
    let (addr, upstream_ca, up) = spawn_upstream_idle(
        b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\nfirst-",
        Duration::from_millis(500),
        b"second",
    );
    let mut roots = RootCertStore::empty();
    roots.add(upstream_ca).unwrap();
    let upstream_cfg = Arc::new(
        ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth(),
    );
    let proxy_ca = Arc::new(Ca::ephemeral().unwrap());
    let proxy_ca_der = proxy_ca.ca_cert_der();
    let ctx = Arc::new(
        ProxyCtx::new(proxy_ca, policy(&["upstream.test:*"]))
            .unwrap()
            .with_upstream(upstream_cfg)
            .with_timeout(Duration::from_millis(200))
            .with_resolver(Box::new(|_| Ok(vec![IpAddr::from([127, 0, 0, 1])]))),
    );

    let resp = through_proxy(
        ctx,
        proxy_ca_der,
        "upstream.test",
        "upstream.test",
        addr.port(),
        b"GET /path HTTP/1.1\r\nHost: upstream.test\r\nConnection: close\r\n\r\n",
    )
    .unwrap();
    up.join().unwrap();
    assert!(resp.contains("200 OK"), "status line missing: {resp:?}");
    assert!(
        resp.contains("first-") && resp.contains("second"),
        "the streamed body was truncated at the idle gap: {resp:?}"
    );
}

/// A completed response closes the intercepted TLS with a proper `close_notify`, so a streaming
/// client does not see the reported `peer closed connection without sending TLS close_notify` at
/// end-of-stream — even for a close-delimited reply (no `Content-Length`), which `Connection:
/// close` can push an upstream toward. Teeth: without `finish_tls` on the completion path, the
/// client's read ends in `UnexpectedEof` and `through_proxy_clean_close` returns that error, so
/// the `unwrap` panics.
#[test]
fn a_completed_response_ends_with_a_clean_tls_close_notify() {
    // A close-delimited reply: no Content-Length, the body is ended by the upstream closing.
    let (addr, upstream_ca, up) = spawn_upstream(
        "upstream.test",
        b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\nstreamed-body",
    );
    let mut roots = RootCertStore::empty();
    roots.add(upstream_ca).unwrap();
    let upstream_cfg = Arc::new(
        ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth(),
    );
    let proxy_ca = Arc::new(Ca::ephemeral().unwrap());
    let proxy_ca_der = proxy_ca.ca_cert_der();
    let ctx = Arc::new(
        ProxyCtx::new(proxy_ca, policy(&["upstream.test:*"]))
            .unwrap()
            .with_upstream(upstream_cfg)
            .with_resolver(Box::new(|_| Ok(vec![IpAddr::from([127, 0, 0, 1])]))),
    );

    let resp = through_proxy_clean_close(
        ctx,
        proxy_ca_der,
        "upstream.test",
        addr.port(),
        b"GET /path HTTP/1.1\r\nHost: upstream.test\r\nConnection: close\r\n\r\n",
    )
    .unwrap();
    up.join().unwrap();
    assert!(
        resp.contains("streamed-body"),
        "the body was not fully relayed: {resp:?}"
    );
}

/// An allowed WebSocket upgrade is relayed bidirectionally: the client gets the `101`, the server's
/// unsolicited push (`S-FIRST;`, proving upstream→client AND that bytes buffered past the `101` are
/// not lost — the buffer-drain), and the echo of its own frame (`ECHO:client-frame`, proving
/// client→upstream→client). Teeth: without the upgrade relay, the one-shot path forces
/// `Connection: close` and never carries the frames, so the echo never comes back.
#[test]
fn a_websocket_upgrade_is_relayed_bidirectionally() {
    let (addr, upstream_ca, up) = spawn_ws_upstream();
    let mut roots = RootCertStore::empty();
    roots.add(upstream_ca).unwrap();
    let upstream_cfg = Arc::new(
        ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth(),
    );
    let proxy_ca = Arc::new(Ca::ephemeral().unwrap());
    let proxy_ca_der = proxy_ca.ca_cert_der();
    let ctx = Arc::new(
        ProxyCtx::new(proxy_ca, policy(&["{WS} upstream.test:*"]))
            .unwrap()
            .with_upstream(upstream_cfg)
            .with_resolver(Box::new(|_| Ok(vec![IpAddr::from([127, 0, 0, 1])]))),
    );

    let transcript =
        through_proxy_websocket(ctx, proxy_ca_der, "upstream.test", addr.port()).unwrap();
    up.join().unwrap();
    assert!(
        transcript.contains("101 Switching Protocols"),
        "the upgrade was not completed: {transcript:?}"
    );
    assert!(
        transcript.contains("S-FIRST;"),
        "the server push (upstream→client, buffered past the 101) was lost: {transcript:?}"
    );
    assert!(
        transcript.contains("ECHO:client-frame"),
        "the client frame did not round-trip (client→upstream→client): {transcript:?}"
    );
}

/// A WebSocket upgrade does not bypass the verdict: an upgrade to a host no rule allows is refused
/// (`403`) at the same gate as any request, and no tunnel is opened. So the allowlist governs which
/// host may open a WebSocket, exactly as for a normal request.
#[test]
fn a_websocket_upgrade_to_a_denied_host_is_refused() {
    let (addr, upstream_ca, _up) = spawn_ws_upstream();
    let mut roots = RootCertStore::empty();
    roots.add(upstream_ca).unwrap();
    let upstream_cfg = Arc::new(
        ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth(),
    );
    let proxy_ca = Arc::new(Ca::ephemeral().unwrap());
    let proxy_ca_der = proxy_ca.ca_cert_der();
    // The policy allows only `allowed.test`, but the upgrade targets `denied.test`.
    let ctx = Arc::new(
        ProxyCtx::new(proxy_ca, policy(&["allowed.test:*"]))
            .unwrap()
            .with_upstream(upstream_cfg)
            .with_resolver(Box::new(|_| Ok(vec![IpAddr::from([127, 0, 0, 1])]))),
    );
    let transcript =
        through_proxy_websocket(ctx, proxy_ca_der, "denied.test", addr.port()).unwrap();
    assert!(
        transcript.contains("403"),
        "a denied-host upgrade must be refused, not tunneled: {transcript:?}"
    );
    assert!(
        !transcript.contains("101"),
        "no tunnel may be established to a denied host: {transcript:?}"
    );
}

/// When the upstream declines the upgrade (any non-`101`), its response is relayed as a normal one
/// and the tunnel closes — it does not hang waiting for a bidirectional channel that will never
/// open. Here the upstream answers a WebSocket upgrade with a `401` and closes; the client must
/// receive that `401` (body and all) and reach EOF.
#[test]
fn a_websocket_upgrade_the_upstream_declines_is_relayed_as_a_normal_response() {
    let (addr, upstream_ca, up) = spawn_upstream(
        "upstream.test",
        b"HTTP/1.1 401 Unauthorized\r\nContent-Length: 14\r\n\r\nnot-upgradable",
    );
    let mut roots = RootCertStore::empty();
    roots.add(upstream_ca).unwrap();
    let upstream_cfg = Arc::new(
        ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth(),
    );
    let proxy_ca = Arc::new(Ca::ephemeral().unwrap());
    let proxy_ca_der = proxy_ca.ca_cert_der();
    let ctx = Arc::new(
        ProxyCtx::new(proxy_ca, policy(&["{WS} upstream.test:*"]))
            .unwrap()
            .with_upstream(upstream_cfg)
            .with_resolver(Box::new(|_| Ok(vec![IpAddr::from([127, 0, 0, 1])]))),
    );
    let transcript =
        through_proxy_websocket(ctx, proxy_ca_der, "upstream.test", addr.port()).unwrap();
    up.join().unwrap();
    assert!(
        transcript.contains("401") && transcript.contains("not-upgradable"),
        "the declined-upgrade response was not relayed: {transcript:?}"
    );
    assert!(
        !transcript.contains("101"),
        "no upgrade was completed: {transcript:?}"
    );
}

/// A WebSocket needs an explicit `{WS}` grant: a host allowed for all HTTP methods (`{*}`) does
/// NOT open a WebSocket. The upgrade is method-denied (host allowed, WS not) and no tunnel opens —
/// the opt-in that keeps a read/write HTTP allowance from silently becoming a bidirectional channel.
#[test]
fn a_websocket_upgrade_needs_an_explicit_ws_grant() {
    let addr = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap();
    let proxy_ca = Arc::new(Ca::ephemeral().unwrap());
    let proxy_ca_der = proxy_ca.ca_cert_der();
    let ctx = Arc::new(
        ProxyCtx::new(proxy_ca, policy(&["{*} upstream.test:*"]))
            .unwrap()
            .with_resolver(Box::new(|_| Ok(vec![IpAddr::from([127, 0, 0, 1])]))),
    );
    let transcript =
        through_proxy_websocket(ctx, proxy_ca_der, "upstream.test", addr.port()).unwrap();
    assert!(
        transcript.contains("403") && transcript.contains("denied-method"),
        "a WebSocket under `{{*}}` (no `{{WS}}`) must be method-denied: {transcript:?}"
    );
    assert!(
        !transcript.contains("101 Switching"),
        "no tunnel opens without an explicit WS grant: {transcript:?}"
    );
}

/// A WebSocket to a credential-injected host is refused: the injected secret rides the handshake,
/// but the frames cannot be redacted, so opening it would risk a reflected secret re-entering the
/// cage. The host permits WS (`{WS}`) AND carries an injection — the upgrade is refused fail-closed.
#[test]
fn a_credential_injected_websocket_is_refused() {
    let addr = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap();
    let proxy_ca = Arc::new(Ca::ephemeral().unwrap());
    let proxy_ca_der = proxy_ca.ca_cert_der();
    let ctx = Arc::new(
        ProxyCtx::new(proxy_ca, policy(&["{WS} secret-host.test:*"]))
            .unwrap()
            .with_injections(vec![injection(
                "secret-host.test:*",
                "Authorization",
                "Bearer s3cr3t",
            )])
            .with_resolver(Box::new(|_| Ok(vec![IpAddr::from([127, 0, 0, 1])]))),
    );
    let transcript =
        through_proxy_websocket(ctx, proxy_ca_der, "secret-host.test", addr.port()).unwrap();
    assert!(
        transcript.contains("403") && transcript.contains("ws-injection-refused"),
        "a credential-injected WebSocket must be refused: {transcript:?}"
    );
    assert!(
        !transcript.contains("101 Switching"),
        "no injected WebSocket tunnel opens: {transcript:?}"
    );
}

/// A deterministic large payload (no `\r\n` runs, so it cannot be mistaken for a head terminator).
fn bulk_payload(n: usize) -> Vec<u8> {
    (0..n).map(|i| (i % 251) as u8).collect()
}

/// Like [`spawn_ws_upstream`] but, after the `101`, pushes a large payload (server→client) then
/// closes — to drive the relay's non-blocking read/flush loop through many `WouldBlock`/`POLLOUT`
/// cycles and its backpressure gating under volume.
fn spawn_ws_upstream_bulk(
    n: usize,
) -> (SocketAddr, CertificateDer<'static>, thread::JoinHandle<()>) {
    let ca = Arc::new(Ca::ephemeral().unwrap());
    let ca_der = ca.ca_cert_der();
    let server_config = Arc::new(
        ServerConfig::builder()
            .with_no_client_auth()
            .with_cert_resolver(Arc::new(CertResolver::new(ca))),
    );
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = thread::spawn(move || {
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
        let _ = tls.write_all(
            b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\
                  Connection: Upgrade\r\nSec-WebSocket-Accept: test-accept\r\n\r\n",
        );
        let _ = tls.write_all(&bulk_payload(n));
        let _ = tls.flush();
    });
    (addr, ca_der, handle)
}

/// Drive a WebSocket upgrade and return the raw bytes relayed after the `101` head (binary-safe,
/// unlike [`through_proxy_websocket`]'s lossy string).
fn through_proxy_ws_bytes(
    ctx: Arc<ProxyCtx>,
    proxy_ca: CertificateDer<'static>,
    connect_host: &str,
    connect_port: u16,
) -> io::Result<Vec<u8>> {
    let dir = TmpDir::new();
    let path = dir.join("proxy.sock");
    let listener = UnixListener::bind(&path).unwrap();
    thread::spawn(move || {
        let _ = serve(listener, ctx);
    });
    let mut sock = UnixStream::connect(&path).unwrap();
    write!(
        sock,
        "CONNECT {connect_host}:{connect_port} HTTP/1.1\r\n\r\n"
    )
    .unwrap();
    sock.flush().unwrap();
    let established = read_until_blank(&mut sock)?;
    assert!(established.contains("200 Connection established"));
    let mut roots = RootCertStore::empty();
    roots.add(proxy_ca).unwrap();
    let client_config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let name = ServerName::try_from(connect_host.to_string()).unwrap();
    let conn = ClientConnection::new(Arc::new(client_config), name).map_err(io::Error::other)?;
    let mut tls = StreamOwned::new(conn, sock);
    let upgrade = format!(
        "GET /chat HTTP/1.1\r\nHost: {connect_host}\r\nUpgrade: websocket\r\n\
             Connection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
             Sec-WebSocket-Version: 13\r\n\r\n"
    );
    tls.write_all(upgrade.as_bytes())?;
    tls.flush().ok();
    let head = read_head_until_blank(&mut tls)?;
    assert!(head.contains("101 Switching Protocols"), "no 101: {head:?}");
    let mut body = Vec::new();
    match tls.read_to_end(&mut body) {
        Ok(_) => {}
        Err(ref e) if e.kind() == io::ErrorKind::UnexpectedEof => {}
        Err(e) => return Err(e),
    }
    Ok(body)
}

/// The non-blocking relay carries a large payload intact — many `WouldBlock`/`POLLOUT` cycles and
/// its backpressure gating (a source is not read while its destination has unflushed output). A
/// byte-for-byte comparison of 256 KiB proves no loss, duplication, or reordering through the
/// buffering. (Backpressure triggers naturally: TLS re-encryption makes the client drain slower
/// than the upstream fills, so the relay hits `wants_write()` on the client and gates its reads.)
#[test]
fn a_large_websocket_payload_is_relayed_intact() {
    const N: usize = 256 * 1024;
    let (addr, upstream_ca, up) = spawn_ws_upstream_bulk(N);
    let mut roots = RootCertStore::empty();
    roots.add(upstream_ca).unwrap();
    let upstream_cfg = Arc::new(
        ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth(),
    );
    let proxy_ca = Arc::new(Ca::ephemeral().unwrap());
    let proxy_ca_der = proxy_ca.ca_cert_der();
    let ctx = Arc::new(
        ProxyCtx::new(proxy_ca, policy(&["{WS} upstream.test:*"]))
            .unwrap()
            .with_upstream(upstream_cfg)
            .with_resolver(Box::new(|_| Ok(vec![IpAddr::from([127, 0, 0, 1])]))),
    );
    let got = through_proxy_ws_bytes(ctx, proxy_ca_der, "upstream.test", addr.port()).unwrap();
    up.join().unwrap();
    assert_eq!(got.len(), N, "the whole payload must arrive");
    assert!(
        got == bulk_payload(N),
        "the payload must be byte-for-byte intact"
    );
}

/// Like [`spawn_ws_upstream_bulk`] but STAYS OPEN after the burst (blocks reading) instead of
/// closing — so the burst's tail cannot be re-driven by a trailing FIN. A relay that parks in
/// `poll` while plaintext still sits in rustls's buffer would strand that tail here.
fn spawn_ws_upstream_burst_then_idle(
    n: usize,
) -> (SocketAddr, CertificateDer<'static>, thread::JoinHandle<()>) {
    let ca = Arc::new(Ca::ephemeral().unwrap());
    let ca_der = ca.ca_cert_der();
    let server_config = Arc::new(
        ServerConfig::builder()
            .with_no_client_auth()
            .with_cert_resolver(Arc::new(CertResolver::new(ca))),
    );
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = thread::spawn(move || {
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
        let _ = tls.write_all(
            b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\
                  Connection: Upgrade\r\nSec-WebSocket-Accept: test-accept\r\n\r\n",
        );
        let _ = tls.write_all(&bulk_payload(n));
        let _ = tls.flush();
        // Stay open: block reading until the client closes (returns 0), so nothing re-drives the
        // burst on the client side except the relay itself delivering rustls's buffered plaintext.
        let mut sink = [0u8; 64];
        let _ = tls.read(&mut sink);
    });
    (addr, ca_der, handle)
}

/// Drive a WebSocket upgrade, then read EXACTLY `n` bytes with a read timeout — so a relay that
/// strands the tail makes this time out (and fail) rather than hang.
fn through_proxy_ws_read_exact(
    ctx: Arc<ProxyCtx>,
    proxy_ca: CertificateDer<'static>,
    connect_host: &str,
    connect_port: u16,
    n: usize,
) -> io::Result<Vec<u8>> {
    let dir = TmpDir::new();
    let path = dir.join("proxy.sock");
    let listener = UnixListener::bind(&path).unwrap();
    thread::spawn(move || {
        let _ = serve(listener, ctx);
    });
    let mut sock = UnixStream::connect(&path).unwrap();
    write!(
        sock,
        "CONNECT {connect_host}:{connect_port} HTTP/1.1\r\n\r\n"
    )
    .unwrap();
    sock.flush().unwrap();
    let established = read_until_blank(&mut sock)?;
    assert!(established.contains("200 Connection established"));
    let mut roots = RootCertStore::empty();
    roots.add(proxy_ca).unwrap();
    let client_config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let name = ServerName::try_from(connect_host.to_string()).unwrap();
    let conn = ClientConnection::new(Arc::new(client_config), name).map_err(io::Error::other)?;
    let mut tls = StreamOwned::new(conn, sock);
    let upgrade = format!(
        "GET /chat HTTP/1.1\r\nHost: {connect_host}\r\nUpgrade: websocket\r\n\
             Connection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
             Sec-WebSocket-Version: 13\r\n\r\n"
    );
    tls.write_all(upgrade.as_bytes())?;
    tls.flush().ok();
    let head = read_head_until_blank(&mut tls)?;
    assert!(head.contains("101 Switching Protocols"), "no 101: {head:?}");
    // A stranded tail must surface as a timeout, not an indefinite hang.
    tls.sock.set_read_timeout(Some(Duration::from_secs(10)))?;
    let mut buf = vec![0u8; n];
    tls.read_exact(&mut buf)?;
    Ok(buf)
}

/// Volume/integrity coverage for the non-blocking relay on a STAY-OPEN connection: a burst larger
/// than the relay's read buffer arrives and the upstream then goes idle without closing, and the
/// whole burst must still be delivered byte-exact. This exercises the drain path (many read/flush
/// cycles, no trailing FIN to help); a broken drain would corrupt or hang. It is NOT a teeth test
/// for the drain-before-poll fix — whether that fix is load-bearing depends on rustls-internal
/// `read_tls` chunking, which a socket-timed test cannot reproduce deterministically (it would
/// flake). The fix is kept as the canonical correct non-blocking pattern regardless.
#[test]
fn a_burst_larger_than_the_read_buffer_then_idle_is_fully_delivered() {
    const N: usize = 128 * 1024; // well over the 16 KiB relay buffer
    let (addr, upstream_ca, up) = spawn_ws_upstream_burst_then_idle(N);
    let mut roots = RootCertStore::empty();
    roots.add(upstream_ca).unwrap();
    let upstream_cfg = Arc::new(
        ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth(),
    );
    let proxy_ca = Arc::new(Ca::ephemeral().unwrap());
    let proxy_ca_der = proxy_ca.ca_cert_der();
    let ctx = Arc::new(
        ProxyCtx::new(proxy_ca, policy(&["{WS} upstream.test:*"]))
            .unwrap()
            .with_upstream(upstream_cfg)
            .with_resolver(Box::new(|_| Ok(vec![IpAddr::from([127, 0, 0, 1])]))),
    );
    let got =
        through_proxy_ws_read_exact(ctx, proxy_ca_der, "upstream.test", addr.port(), N).unwrap();
    assert!(
        got == bulk_payload(N),
        "the whole burst must be delivered even though the upstream then idled without closing"
    );
    // The client drops here, closing the tunnel so the idle upstream's blocked read returns.
    up.join().unwrap();
}

#[test]
fn a_cleartext_http_request_is_forwarded_in_origin_form_when_allowed() {
    // The whole new seam: an absolute-form `http://` request (no CONNECT) that an `http://` allow
    // rule permits is forwarded to the plaintext upstream in ORIGIN-form and its response relayed.
    let (addr, up_head) = spawn_plain_upstream(
        b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello",
    );
    let port = addr.port();
    let sdir = TmpDir::new();
    let stats = Arc::new(crate::sandbox::egress_stats::EgressStats::new(
        sdir.join("stats"),
        "/t".into(),
        None,
    ));
    let log = Arc::new(crate::sandbox::control::LogRing::new(
        crate::sandbox::control::LOG_RING_CAP,
    ));
    let rule = format!("http://upstream.test:{port}");
    let ctx = Arc::new(
        ProxyCtx::new(Arc::new(Ca::ephemeral().unwrap()), policy(&[rule.as_str()]))
            .unwrap()
            .with_stats(stats.clone())
            .with_log(log.clone())
            .with_resolver(Box::new(|_| Ok(vec![IpAddr::from([127, 0, 0, 1])]))),
    );
    let request = format!(
        "GET http://upstream.test:{port}/path HTTP/1.1\r\nHost: upstream.test:{port}\r\n\
             Connection: close\r\n\r\n"
    );
    let resp = through_cleartext(ctx, request.as_bytes()).unwrap();
    assert!(
        resp.contains("200 OK") && resp.contains("hello"),
        "cleartext response was not relayed: {resp:?}"
    );
    // The origin server must receive ORIGIN-form (`GET /path …`), not the absolute-form the proxy
    // received, with the client's Host preserved and `Connection: close` forced.
    let fwd = up_head.recv().unwrap();
    assert!(
        fwd.starts_with("GET /path HTTP/1.1"),
        "upstream did not get an origin-form request line: {fwd:?}"
    );
    assert!(
        !fwd.contains("http://"),
        "the absolute-form URL leaked to the origin server: {fwd:?}"
    );
    assert!(
        fwd.to_ascii_lowercase().contains("connection: close"),
        "the forwarded request must force Connection: close: {fwd:?}"
    );
    // One `allow` outcome recorded, with the request's method and (origin) path.
    assert_eq!(stats.snapshot()["upstream.test"].allow, 1);
    let events = log.snapshot(None, None, false).events;
    assert_eq!(events.len(), 1, "one allow event: {events:?}");
    assert_eq!(events[0].reason, "allowed");
    assert_eq!(events[0].method.as_deref(), Some("GET"));
    assert_eq!(events[0].path.as_deref(), Some("/path"));
}

#[test]
fn a_session_http_overlay_opens_a_cleartext_host_for_an_allowlist_agent() {
    // The user's exact case: a session in **allowlist** mode (deny-by-default, NOT `ask`) whose
    // config does not list the host. A live `sbx net allow http://host --session` folds an
    // `http://` allow into the effective policy, so a cleartext request to that host now proceeds
    // — the whole point of `--session` working outside `ask`. An unscoped overlay allow admits
    // every verb (it is a deliberate live grant), so a POST proceeds too, not just the GET a
    // `curl` would send (the method-scope gotcha a GET-only test would hide).
    use crate::sandbox::control::{ManualRules, Verdict};
    for method in ["GET", "POST"] {
        let (addr, _up_head) = spawn_plain_upstream(
            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
        );
        let port = addr.port();
        let manual = Arc::new(ManualRules::new());
        manual.remember_rule(
            Verdict::Allow,
            classify(&format!("http://target.test:{port}")).unwrap(),
        );
        // An allowlist session (deny-by-default) that allows only an unrelated host — the target
        // is NOT config-permitted, so without the overlay a cleartext request is denied-default.
        let ctx = Arc::new(
            ProxyCtx::new(Arc::new(Ca::ephemeral().unwrap()), policy(&["other.test"]))
                .unwrap()
                .with_manual(manual)
                .with_resolver(Box::new(|_| Ok(vec![IpAddr::from([127, 0, 0, 1])]))),
        );
        let request = format!(
            "{method} http://target.test:{port}/x HTTP/1.1\r\nHost: target.test:{port}\r\n\
                 Connection: close\r\n\r\n"
        );
        let resp = through_cleartext(ctx, request.as_bytes()).unwrap();
        assert!(
            resp.contains("200 OK"),
            "a --session http:// allow must open the cleartext host for a {method}: {resp:?}"
        );
    }
}

#[test]
fn a_session_deny_blocks_a_config_allowed_host() {
    // The reverse override: a live `sbx net deny host --session` cuts a host the config allows.
    // Deny wins in the effective policy, so the request is refused (denied-by-rule) even though the
    // allowlist permits it. The resolver panics if reached — a deny refuses before resolving.
    use crate::sandbox::control::{ManualRules, Verdict};
    let manual = Arc::new(ManualRules::new());
    manual.remember_rule(Verdict::Deny, classify("api.test").unwrap());
    let ca = Arc::new(Ca::ephemeral().unwrap());
    let der = ca.ca_cert_der();
    let ctx = Arc::new(
        ProxyCtx::new(ca, policy(&["api.test:*"]))
            .unwrap()
            .with_manual(manual)
            .with_resolver(Box::new(|_| {
                panic!("a session-denied host must not resolve")
            })),
    );
    let resp = through_proxy(
        ctx,
        der,
        "api.test",
        "api.test",
        443,
        b"GET / HTTP/1.1\r\nHost: api.test\r\nConnection: close\r\n\r\n",
    )
    .unwrap();
    assert!(
        resp.contains("403") && resp.contains("denied-by-rule"),
        "a --session deny must block a config-allowed host: {resp:?}"
    );
}

#[test]
fn a_cleartext_request_needs_an_explicit_http_rule() {
    // Cleartext is strictly opt-in: a bare (inspected-over-TLS) allow rule does NOT open the same
    // host in the clear. So a cleartext request to an https-allowed host is denied-default, and
    // the suggestion names the `http://` scheme (a bare `sbx net allow host` would add an https
    // rule that still would not open the clear).
    let ctx = Arc::new(
        ProxyCtx::new(
            Arc::new(Ca::ephemeral().unwrap()),
            policy(&["upstream.test:*"]),
        )
        .unwrap()
        .with_resolver(Box::new(|_| Ok(vec![IpAddr::from([127, 0, 0, 1])]))),
    );
    let resp = through_cleartext(
        ctx,
        b"GET http://upstream.test/x HTTP/1.1\r\nHost: upstream.test\r\nConnection: close\r\n\r\n",
    )
    .unwrap();
    assert!(
        resp.contains(" 403 ") && resp.contains("X-Sbx-Egress-Reason: denied-default"),
        "cleartext must be denied without an http:// rule: {resp:?}"
    );
    assert!(
        resp.contains("sbx net allow http://upstream.test"),
        "the deny-default suggestion must name the http:// scheme: {resp:?}"
    );
}

#[test]
fn a_cleartext_request_is_denied_by_a_layer_agnostic_deny() {
    // Deny wins across layers: an `http://` allow plus a bare (L7) deny on the same host:port →
    // the cleartext request is denied-by-rule (the same layer-agnostic deny the splice uses).
    let allow = classify("http://evil.test:80").unwrap();
    let deny = classify("evil.test:80").unwrap();
    let ctx = Arc::new(
        ProxyCtx::new(
            Arc::new(Ca::ephemeral().unwrap()),
            EgressPolicy::new(vec![allow], vec![deny]),
        )
        .unwrap()
        .with_resolver(Box::new(|_| Ok(vec![IpAddr::from([127, 0, 0, 1])]))),
    );
    let resp = through_cleartext(
        ctx,
        b"GET http://evil.test/x HTTP/1.1\r\nHost: evil.test\r\nConnection: close\r\n\r\n",
    )
    .unwrap();
    assert!(
        resp.contains(" 403 ") && resp.contains("denied-by-rule"),
        "a deny rule must win over an http:// allow: {resp:?}"
    );
}

/// The SSRF guard holds on the inspected-cleartext (`http://`) path too, and is refused through
/// the counting chokepoint — the `blocked` bucket and the log line, like every other guard. This
/// is the path a tool takes with `http_proxy` set and no CONNECT, so a wildcard `http://` rule
/// covering a name that resolves into loopback is exactly the SSRF wildcard the guard closes; a
/// metadata address is refused even when the rule names the host outright.
#[test]
fn the_cleartext_path_blocks_ssrf_to_private_and_metadata_addresses() {
    use crate::sandbox::control::{LOG_RING_CAP, LogRing, LogVerdict};
    use crate::sandbox::egress_stats::{Counts, EgressStats};

    // wildcard match (no exact-named host) → loopback → blocked
    let dir = TmpDir::new();
    let stats = Arc::new(EgressStats::new(dir.join("stats"), "/t".into(), None));
    let log = Arc::new(LogRing::new(LOG_RING_CAP));
    let ctx = Arc::new(
        ProxyCtx::new(
            Arc::new(Ca::ephemeral().unwrap()),
            policy(&["http://*.corp.test"]),
        )
        .unwrap()
        .with_stats(Arc::clone(&stats))
        .with_log(Arc::clone(&log))
        .with_resolver(Box::new(|_| Ok(vec![IpAddr::from([127, 0, 0, 1])]))),
    );
    let resp = through_cleartext(
        ctx,
        b"POST http://internal.corp.test/admin HTTP/1.1\r\nHost: internal.corp.test\r\n\
              Content-Length: 0\r\nConnection: close\r\n\r\n",
    )
    .unwrap();
    assert!(
        resp.contains(" 403 ") && resp.contains("ssrf-blocked"),
        "a wildcard-matched private target is an SSRF wildcard and must be blocked: {resp:?}"
    );
    assert_eq!(
        stats
            .snapshot()
            .get("internal.corp.test")
            .copied()
            .unwrap_or_default(),
        Counts {
            blocked: 1,
            ..Default::default()
        },
        "an SSRF block is counted, not merely refused"
    );
    let events = log.snapshot(None, None, false).events;
    assert_eq!(events.len(), 1, "one event for one decision: {events:?}");
    assert_eq!(
        (
            events[0].host.as_str(),
            events[0].verdict,
            events[0].reason.as_str(),
            events[0].method.as_deref(),
            events[0].path.as_deref()
        ),
        (
            "internal.corp.test",
            LogVerdict::Blocked,
            "ssrf-blocked",
            Some("POST"),
            Some("/admin")
        )
    );

    // exact host, but the address is cloud metadata → blocked even though explicit
    let ctx = Arc::new(
        ProxyCtx::new(
            Arc::new(Ca::ephemeral().unwrap()),
            policy(&["http://meta.test"]),
        )
        .unwrap()
        .with_resolver(Box::new(|_| Ok(vec![IpAddr::from([169, 254, 169, 254])]))),
    );
    let resp = through_cleartext(
        ctx,
        b"GET http://meta.test/latest/meta-data/ HTTP/1.1\r\nHost: meta.test\r\n\
              Connection: close\r\n\r\n",
    )
    .unwrap();
    assert!(
        resp.contains(" 403 ") && resp.contains("ssrf-blocked"),
        "the cloud-metadata address must be blocked even for an exact host: {resp:?}"
    );
}

/// A top-level **absolute-form `https://`** request (no CONNECT) to an allowed host is forwarded
/// over a *validated TLS* upstream, and the upstream receives it in **origin-form** with a forced
/// `Connection: close` — the "secure web proxy" transport the Kiro IDE's token exchange uses,
/// which without this path is refused `405`.
#[test]
fn an_absolute_form_https_request_is_forwarded_over_a_validated_tls_upstream() {
    let (addr, upstream_ca, rx) = spawn_upstream_capturing(
        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
    );
    let mut roots = RootCertStore::empty();
    roots.add(upstream_ca).unwrap();
    let upstream_cfg = Arc::new(
        ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth(),
    );
    let ctx = Arc::new(
        // Reuse off, so the forwarded head carries the `close` this test is about.
        ProxyCtx::new(
            Arc::new(Ca::ephemeral().unwrap()),
            policy(&["host.test:*"]).with_pool(false),
        )
        .unwrap()
        .with_upstream(upstream_cfg)
        .with_resolver(Box::new(|_| Ok(vec![IpAddr::from([127, 0, 0, 1])]))),
    );
    let request = format!(
        "POST https://host.test:{}/oauth/token HTTP/1.1\r\nHost: host.test\r\n\
             Content-Length: 5\r\n\r\nhello",
        addr.port()
    );
    let resp = through_cleartext(ctx, request.as_bytes()).unwrap();
    assert!(
        resp.contains("200"),
        "the upstream response is relayed to the plaintext client: {resp:?}"
    );
    let upstream_head = rx
        .recv_timeout(Duration::from_secs(5))
        .expect("the upstream received the forwarded request");
    assert!(
        upstream_head.starts_with("POST /oauth/token HTTP/1.1"),
        "the request must reach the upstream in origin-form, not absolute-form: {upstream_head:?}"
    );
    assert!(
        upstream_head
            .to_ascii_lowercase()
            .contains("connection: close"),
        "the proxy must force Connection: close upstream: {upstream_head:?}"
    );
}

/// The **absolute-form** plane holds and digests a body on the same terms as the tunneled one.
///
/// Its own test rather than a parameter of the tunneled one, because the two planes are siblings
/// written out separately: they got the held-body edits by hand, and a property proved on one says
/// nothing about the other. What is asserted is the same triple, read off the head the upstream
/// received, plus the ceiling refusal this plane writes with its own refusal writer.
#[test]
fn the_absolute_form_plane_holds_a_body_to_digest_it_on_the_same_terms() {
    let forwarded = |request: String| -> (String, String) {
        let (addr, upstream_ca, rx) = spawn_upstream_capturing(
            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
        );
        let mut roots = RootCertStore::empty();
        roots.add(upstream_ca).unwrap();
        let upstream_cfg = Arc::new(
            ClientConfig::builder()
                .with_root_certificates(roots)
                .with_no_client_auth(),
        );
        let ctx = Arc::new(
            ProxyCtx::new(
                Arc::new(Ca::ephemeral().unwrap()),
                policy(&["host.test:*"]).with_pool(false),
            )
            .unwrap()
            .with_upstream(upstream_cfg)
            .with_injections(vec![digesting_injection()])
            .with_resolver(Box::new(|_| Ok(vec![IpAddr::from([127, 0, 0, 1])]))),
        );
        let resp = through_cleartext(
            ctx,
            request
                .replace("{port}", &addr.port().to_string())
                .as_bytes(),
        )
        .unwrap();
        let head = rx.recv_timeout(Duration::from_secs(5)).unwrap_or_default();
        (resp, head)
    };
    let lengths = |head: &str| {
        head.lines()
            .filter(|l| l.to_ascii_lowercase().starts_with("content-length:"))
            .count()
    };
    let hello = "X-Body: 11/b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9";

    let (resp, head) = forwarded(
        "POST https://host.test:{port}/ HTTP/1.1\r\nHost: host.test\r\n\
         Content-Length: 11\r\n\r\nhello world"
            .to_string(),
    );
    assert!(resp.contains("200"), "{resp:?}");
    assert!(head.contains(hello), "{head:?}");
    assert_eq!(lengths(&head), 1, "{head:?}");

    let (resp, head) = forwarded(
        "POST https://host.test:{port}/ HTTP/1.1\r\nHost: host.test\r\n\
         Transfer-Encoding: chunked\r\n\r\nb\r\nhello world\r\n0\r\n\r\n"
            .to_string(),
    );
    assert!(resp.contains("200"), "{resp:?}");
    assert!(head.contains(hello), "{head:?}");
    assert!(
        !head.to_ascii_lowercase().contains("transfer-encoding:"),
        "{head:?}"
    );

    let (resp, head) =
        forwarded("GET https://host.test:{port}/ HTTP/1.1\r\nHost: host.test\r\n\r\n".to_string());
    assert!(resp.contains("200"), "{resp:?}");
    assert!(
        head.contains("X-Body: 0/e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
        "{head:?}"
    );
    assert_eq!(
        lengths(&head),
        0,
        "a bodyless request gains no framing on this plane either: {head:?}"
    );

    let (resp, _) = forwarded(format!(
        "POST https://host.test:{{port}}/ HTTP/1.1\r\nHost: host.test\r\nContent-Length: {}\r\n\r\n",
        CHUNKED_REQUEST_CAP + 1
    ));
    assert!(
        resp.contains("413") && resp.contains("signer-body-too-large"),
        "the ceiling is refused with this plane's own writer: {resp:?}"
    );
}

/// An absolute-form `https://` forward to a host with no allow rule is refused `403 denied-default`
/// (the same allowlist verdict a `CONNECT` to that host would get), and never reaches an upstream.
#[test]
fn an_absolute_form_https_forward_to_a_denied_host_is_refused() {
    let ctx = Arc::new(
        ProxyCtx::new(
            Arc::new(Ca::ephemeral().unwrap()),
            policy(&["allowed.test:*"]),
        )
        .unwrap()
        .with_resolver(Box::new(|_| Ok(vec![IpAddr::from([127, 0, 0, 1])]))),
    );
    let resp = through_cleartext(
        ctx,
        b"POST https://evil.test/oauth/token HTTP/1.1\r\nHost: evil.test\r\n\
              Content-Length: 0\r\n\r\n",
    )
    .unwrap();
    assert!(
        resp.contains(" 403 ") && resp.contains("denied-default"),
        "a host not on the allowlist must be refused: {resp:?}"
    );
}

/// The other denial shape on the https-forward path: a deny rule refuses with `denied-by-rule`,
/// not the `denied-default` above. The policy is allow-by-default, so nothing but the rule itself
/// can produce the refusal — which is what makes this the arm and not the fallback. The resolver
/// panics if reached: a deny is decided before any name is looked up.
#[test]
fn an_absolute_form_https_forward_is_refused_by_a_deny_rule() {
    use crate::allowlist::DefaultAction;
    let denylist = EgressPolicy::new(vec![], vec![classify("evil.test:*").unwrap()])
        .with_default(DefaultAction::Allow);
    let ctx = Arc::new(
        ProxyCtx::new(Arc::new(Ca::ephemeral().unwrap()), denylist)
            .unwrap()
            .with_resolver(Box::new(|_| {
                panic!("resolve must not run for a deny-rule host")
            })),
    );
    let resp = through_cleartext(
        ctx,
        b"POST https://evil.test/oauth/token HTTP/1.1\r\nHost: evil.test\r\n\
              Content-Length: 0\r\n\r\n",
    )
    .unwrap();
    assert!(
        resp.contains(" 403 ") && resp.contains("denied-by-rule"),
        "a deny rule must refuse the forward as denied-by-rule: {resp:?}"
    );
}

/// A host the policy opens for reading only refuses a write on the https-forward path with
/// `denied-method`, the same method-scoped reason a `CONNECT` to that host produces — so the
/// agent can tell "not for this verb" from "not this host at all" whichever form it sent.
#[test]
fn a_method_outside_the_allow_set_is_refused_on_the_https_forward_path() {
    let policy = EgressPolicy::new(vec![classify("{GET,HEAD} host.test:*").unwrap()], vec![]);
    let ctx = Arc::new(
        ProxyCtx::new(Arc::new(Ca::ephemeral().unwrap()), policy)
            .unwrap()
            .with_resolver(Box::new(|_| {
                panic!("resolve must not run for a method-denied request")
            })),
    );
    let resp = through_cleartext(
        ctx,
        b"POST https://host.test/submit HTTP/1.1\r\nHost: host.test\r\n\
              Content-Length: 0\r\n\r\n",
    )
    .unwrap();
    assert!(
        resp.contains(" 403 ") && resp.contains("denied-method"),
        "a POST to a GET/HEAD-only host must be refused as denied-method: {resp:?}"
    );
}

/// On the https-forward path, a forged/untrusted upstream certificate is refused `502
/// upstream-cert-rejected` — never downgraded, the same upstream validation the MITM path applies.
#[test]
fn a_forged_upstream_on_the_https_forward_path_is_refused_with_502() {
    let (addr, _upstream_ca, _up) = spawn_upstream(
        "host.test",
        b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
    );
    // No `.with_upstream(...)` — the default webpki-roots config rejects the ephemeral upstream cert.
    let ctx = Arc::new(
        ProxyCtx::new(Arc::new(Ca::ephemeral().unwrap()), policy(&["host.test:*"]))
            .unwrap()
            .with_resolver(Box::new(|_| Ok(vec![IpAddr::from([127, 0, 0, 1])]))),
    );
    let request = format!(
        "POST https://host.test:{}/oauth/token HTTP/1.1\r\nHost: host.test\r\n\
             Content-Length: 0\r\n\r\n",
        addr.port()
    );
    let resp = through_cleartext(ctx, request.as_bytes()).unwrap();
    assert!(
        resp.contains("502") && resp.contains("upstream-cert-rejected"),
        "an untrusted upstream must be refused, not downgraded: {resp:?}"
    );
}

/// The https-forward path injects a host-scoped credential into the upstream request — unlike the
/// cleartext `http://` path, which never sends a header secret — because its upstream leg is
/// encrypted. sbx's injected header reaches the upstream, replacing any client-supplied copy.
#[test]
fn an_absolute_form_https_forward_injects_the_scoped_credential() {
    let (addr, upstream_ca, rx) = spawn_upstream_capturing(
        b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
    );
    let mut roots = RootCertStore::empty();
    roots.add(upstream_ca).unwrap();
    let upstream_cfg = Arc::new(
        ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth(),
    );
    let ctx = Arc::new(
        ProxyCtx::new(Arc::new(Ca::ephemeral().unwrap()), policy(&["host.test:*"]))
            .unwrap()
            .with_upstream(upstream_cfg)
            .with_resolver(Box::new(|_| Ok(vec![IpAddr::from([127, 0, 0, 1])])))
            .with_injections(vec![injection(
                "host.test:*",
                "Authorization",
                "Bearer sbx-secret-value",
            )]),
    );
    // the client sends its OWN Authorization — it must be stripped and replaced by sbx's.
    let request = format!(
        "POST https://host.test:{}/oauth/token HTTP/1.1\r\nHost: host.test\r\n\
             Authorization: Bearer attacker\r\nContent-Length: 0\r\n\r\n",
        addr.port()
    );
    let resp = through_cleartext(ctx, request.as_bytes()).unwrap();
    assert!(resp.contains("200"), "the response flows back: {resp:?}");
    let head = rx.recv_timeout(Duration::from_secs(5)).unwrap_or_default();
    assert!(
        head.contains("Authorization: Bearer sbx-secret-value"),
        "sbx's credential must reach the upstream over the encrypted leg: {head:?}"
    );
    assert!(
        !head.contains("attacker"),
        "the client's own copy of the injected header must be stripped: {head:?}"
    );
}

/// The SSRF guard holds on the https-forward path — the canonical proxy attack: an in-cage agent
/// sending an absolute-form `https://` request to a host that resolves into a private / cloud-
/// metadata range must be blocked. A wildcard-matched host that resolves to loopback is an SSRF
/// wildcard; a metadata address is refused even for an exact host. This discriminates that the
/// deciding rule is threaded into the shared guard the same way the MITM path threads it.
#[test]
fn the_https_forward_path_blocks_ssrf_to_private_and_metadata_addresses() {
    // wildcard match (no exact-named host) → loopback → blocked
    let ctx = Arc::new(
        ProxyCtx::new(
            Arc::new(Ca::ephemeral().unwrap()),
            policy(&["*.corp.test:*"]),
        )
        .unwrap()
        .with_resolver(Box::new(|_| Ok(vec![IpAddr::from([127, 0, 0, 1])]))),
    );
    let resp = through_cleartext(
        ctx,
        b"POST https://internal.corp.test/oauth/token HTTP/1.1\r\n\
              Host: internal.corp.test\r\nContent-Length: 0\r\n\r\n",
    )
    .unwrap();
    assert!(
        resp.contains("403") && resp.contains("ssrf-blocked"),
        "a wildcard-matched private target is an SSRF wildcard and must be blocked: {resp:?}"
    );

    // exact host, but the address is cloud metadata → blocked even though explicit
    let ctx = Arc::new(
        ProxyCtx::new(Arc::new(Ca::ephemeral().unwrap()), policy(&["meta.test:*"]))
            .unwrap()
            .with_resolver(Box::new(|_| Ok(vec![IpAddr::from([169, 254, 169, 254])]))),
    );
    let resp = through_cleartext(
        ctx,
        b"POST https://meta.test/oauth/token HTTP/1.1\r\n\
              Host: meta.test\r\nContent-Length: 0\r\n\r\n",
    )
    .unwrap();
    assert!(
        resp.contains("403") && resp.contains("ssrf-blocked"),
        "the cloud-metadata address must be blocked even for an exact host: {resp:?}"
    );
}

/// The outbound-secret tripwire holds on the https-forward path — and it matters more here because
/// the client leg is cleartext: a request re-sending a configured secret verbatim in its head is
/// refused (block, never strip).
#[test]
fn an_outbound_secret_on_the_https_forward_path_is_refused() {
    let ctx = Arc::new(
        ProxyCtx::new(Arc::new(Ca::ephemeral().unwrap()), policy(&["host.test:*"]))
            .unwrap()
            .with_resolver(Box::new(|_| Ok(vec![IpAddr::from([127, 0, 0, 1])])))
            .with_redactions(vec![SecretNeedle::named(
                "test-secret",
                b"s3cret-reflected-value".to_vec(),
            )]),
    );
    let resp = through_cleartext(
        ctx,
        b"POST https://host.test/oauth/token HTTP/1.1\r\nHost: host.test\r\n\
              X-Leak: s3cret-reflected-value\r\nContent-Length: 0\r\n\r\n",
    )
    .unwrap();
    assert!(
        resp.contains("403") && resp.contains("outbound-secret"),
        "a secret re-sent in an outbound header must be refused: {resp:?}"
    );
}

/// Under the `ask` posture an undecided host on the https-forward path **parks** — exactly as the
/// same host would through a CONNECT — and an out-of-band `allow` lets it proceed to the validated
/// upstream. The teeth are in the deciding rule the allow synthesizes: it names this exact
/// host:port, which is the only reason the loopback upstream passes the SSRF guard. A park that
/// returned no deciding rule would be refused `ssrf-blocked` here.
#[test]
fn an_ask_undecided_host_on_the_https_forward_path_parks_and_proceeds_when_allowed() {
    use crate::allowlist::DefaultAction;
    use crate::sandbox::control::{PendingState, Verdict};
    let (addr, upstream_ca, rx) = spawn_upstream_capturing(
        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
    );
    let mut roots = RootCertStore::empty();
    roots.add(upstream_ca).unwrap();
    let upstream_cfg = Arc::new(
        ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth(),
    );
    let state = Arc::new(PendingState::new());
    let ctx = Arc::new(
        ProxyCtx::new(
            Arc::new(Ca::ephemeral().unwrap()),
            EgressPolicy::default().with_default(DefaultAction::Ask),
        )
        .unwrap()
        .with_upstream(upstream_cfg)
        .with_resolver(Box::new(|_| Ok(vec![IpAddr::from([127, 0, 0, 1])])))
        .with_pending_silent(state.clone()),
    );
    let answerer = {
        let state = state.clone();
        thread::spawn(move || answer_when_parked(&state, Verdict::Allow))
    };
    let request = format!(
        "POST https://undecided.test:{}/oauth/token HTTP/1.1\r\nHost: undecided.test\r\n\
             Content-Length: 0\r\n\r\n",
        addr.port()
    );
    let resp = through_cleartext(ctx, request.as_bytes()).unwrap();
    assert_eq!(
        answerer.join().unwrap().as_deref(),
        Some("undecided.test"),
        "the request must reach the pending queue, not be denied outright"
    );
    assert!(
        resp.contains("200"),
        "an allowed ask must reach the upstream: {resp:?}"
    );
    assert!(
        rx.recv_timeout(Duration::from_secs(5))
            .unwrap_or_default()
            .starts_with("POST /oauth/token HTTP/1.1"),
        "the parked-then-allowed request must be forwarded in origin-form"
    );
}

/// The other half of the park: an out-of-band `deny` refuses the parked https-forward request
/// with `asked-denied`, and the upstream is never contacted (the resolver panics if reached).
#[test]
fn an_ask_undecided_host_on_the_https_forward_path_is_refused_when_denied() {
    use crate::allowlist::DefaultAction;
    use crate::sandbox::control::{PendingState, Verdict};
    let state = Arc::new(PendingState::new());
    let ctx = Arc::new(
        ProxyCtx::new(
            Arc::new(Ca::ephemeral().unwrap()),
            EgressPolicy::default().with_default(DefaultAction::Ask),
        )
        .unwrap()
        .with_resolver(Box::new(|_| {
            panic!("a denied ask must never resolve the host")
        }))
        .with_pending_silent(state.clone()),
    );
    let answerer = {
        let state = state.clone();
        thread::spawn(move || answer_when_parked(&state, Verdict::Deny))
    };
    let resp = through_cleartext(
        ctx,
        b"POST https://undecided.test/oauth/token HTTP/1.1\r\n\
              Host: undecided.test\r\nContent-Length: 0\r\n\r\n",
    )
    .unwrap();
    assert_eq!(answerer.join().unwrap().as_deref(), Some("undecided.test"));
    assert!(
        resp.contains("403") && resp.contains("asked-denied"),
        "a denied ask must refuse with asked-denied: {resp:?}"
    );
}

/// The forwarded origin-form target keeps the **query string, percent-escapes included**,
/// verbatim — while a *path-scoped* rule still decides it. `parse_url_target` returns
/// path-including-query and `explain` canonicalizes internally (decoding `%2F`, resolving `..`),
/// so the two must stay separate: the canonical path is what the rule matches, the raw one is
/// what the upstream receives. Routing the *forwarded* path through the canonicalizer would
/// silently break every OAuth callback (`?code=…&state=…`), and no other test would notice.
#[test]
fn an_absolute_form_https_forward_preserves_the_query_string() {
    let (addr, upstream_ca, rx) = spawn_upstream_capturing(
        b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
    );
    let mut roots = RootCertStore::empty();
    roots.add(upstream_ca).unwrap();
    let upstream_cfg = Arc::new(
        ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth(),
    );
    // A path-scoped rule, so the verdict runs through `explain`'s canonicalizer too.
    let ctx = Arc::new(
        ProxyCtx::new(
            Arc::new(Ca::ephemeral().unwrap()),
            policy(&["host.test:*/oauth/*"]),
        )
        .unwrap()
        .with_upstream(upstream_cfg)
        .with_resolver(Box::new(|_| Ok(vec![IpAddr::from([127, 0, 0, 1])]))),
    );
    let request = format!(
        "GET https://host.test:{}/oauth/callback?code=abc%2Fdef&state=xyz HTTP/1.1\r\n\
             Host: host.test\r\n\r\n",
        addr.port()
    );
    let resp = through_cleartext(ctx, request.as_bytes()).unwrap();
    assert!(resp.contains("200"), "the response flows back: {resp:?}");
    let head = rx.recv_timeout(Duration::from_secs(5)).unwrap_or_default();
    assert!(
        head.starts_with("GET /oauth/callback?code=abc%2Fdef&state=xyz HTTP/1.1"),
        "the query string must reach the upstream verbatim: {head:?}"
    );
}

/// A `Transfer-Encoding: chunked` request on the https-forward path is de-chunked and re-framed
/// with a synthesized `Content-Length` — the same treatment the tunneled path gives it — so a
/// client that streams its body (no up-front length) is served rather than refused `400`, and no
/// CL/TE framing ambiguity reaches the upstream.
#[test]
fn a_chunked_absolute_form_https_forward_is_de_chunked_and_re_framed() {
    let (addr, upstream_ca, rx) = spawn_upstream_capturing(
        b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
    );
    let mut roots = RootCertStore::empty();
    roots.add(upstream_ca).unwrap();
    let upstream_cfg = Arc::new(
        ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth(),
    );
    let ctx = Arc::new(
        ProxyCtx::new(Arc::new(Ca::ephemeral().unwrap()), policy(&["host.test:*"]))
            .unwrap()
            .with_upstream(upstream_cfg)
            .with_resolver(Box::new(|_| Ok(vec![IpAddr::from([127, 0, 0, 1])]))),
    );
    // "grant_type=x" split over two 6-byte chunks (12 bytes total).
    let request = format!(
        "POST https://host.test:{}/oauth/token HTTP/1.1\r\nHost: host.test\r\n\
             Transfer-Encoding: chunked\r\n\r\n6\r\ngrant_\r\n6\r\ntype=x\r\n0\r\n\r\n",
        addr.port()
    );
    let resp = through_cleartext(ctx, request.as_bytes()).unwrap();
    assert!(resp.contains("200"), "the response flows back: {resp:?}");
    let head = rx.recv_timeout(Duration::from_secs(5)).unwrap_or_default();
    let lower = head.to_ascii_lowercase();
    assert!(
        lower.contains("content-length: 12"),
        "the de-chunked body must be re-framed with its length: {head:?}"
    );
    assert!(
        !lower.contains("transfer-encoding"),
        "the client's chunked framing must not reach the upstream: {head:?}"
    );
}

/// `Proxy-Authorization` is a credential the client addressed to the **proxy hop**; it must never
/// be forwarded to the origin server. This path is where a cage tool genuinely speaks the proxy
/// protocol to sbx, so it is where the header actually shows up.
#[test]
fn a_proxy_authorization_header_is_never_forwarded_upstream() {
    let (addr, upstream_ca, rx) = spawn_upstream_capturing(
        b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
    );
    let mut roots = RootCertStore::empty();
    roots.add(upstream_ca).unwrap();
    let upstream_cfg = Arc::new(
        ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth(),
    );
    let ctx = Arc::new(
        ProxyCtx::new(Arc::new(Ca::ephemeral().unwrap()), policy(&["host.test:*"]))
            .unwrap()
            .with_upstream(upstream_cfg)
            .with_resolver(Box::new(|_| Ok(vec![IpAddr::from([127, 0, 0, 1])]))),
    );
    let request = format!(
        "GET https://host.test:{}/ HTTP/1.1\r\nHost: host.test\r\n\
             Proxy-Authorization: Basic dXNlcjpwYXNz\r\n\r\n",
        addr.port()
    );
    let resp = through_cleartext(ctx, request.as_bytes()).unwrap();
    assert!(resp.contains("200"), "the response flows back: {resp:?}");
    let head = rx.recv_timeout(Duration::from_secs(5)).unwrap_or_default();
    assert!(
        !head.to_ascii_lowercase().contains("proxy-authorization"),
        "the proxy-hop credential must be stripped: {head:?}"
    );
}

#[test]
fn parse_status_code_reads_a_well_formed_status_line_only() {
    // A normal status line → the code.
    assert_eq!(parse_status_code(b"HTTP/1.1 200 OK\r\n"), Some(200));
    assert_eq!(parse_status_code(b"HTTP/1.0 404 Not Found\r\n"), Some(404));
    assert_eq!(parse_status_code(b"HTTP/2 503 \r\n"), Some(503));
    // Only the first line is consulted, even when more of the head was read.
    assert_eq!(
        parse_status_code(b"HTTP/1.1 301 Moved\r\nLocation: /x\r\n"),
        Some(301)
    );
    // Not HTTP, no code, or an implausible code → None (records no status).
    assert_eq!(parse_status_code(b"garbage bytes\r\n"), None);
    assert_eq!(parse_status_code(b"HTTP/1.1 OK\r\n"), None);
    assert_eq!(parse_status_code(b"HTTP/1.1 999 X\r\n"), None);
    assert_eq!(parse_status_code(b""), None);
}

#[test]
fn read_response_head_stops_at_the_blank_line_and_leaves_the_body() {
    // The head ends at the blank line and NOT one byte later: the body stays in the reader, which
    // is what lets the framed relay read it without going back to the socket.
    let mut src = io::BufReader::new(io::Cursor::new(
        b"HTTP/1.1 200 OK\r\nheader: v\r\n\r\nbody".to_vec(),
    ));
    let (head, complete) = read_response_head(&mut src, HEAD_MAX);
    assert!(complete, "a terminated head must report complete");
    assert_eq!(head, b"HTTP/1.1 200 OK\r\nheader: v\r\n\r\n");
    assert_eq!(parse_status_code(&head), Some(200));
    let mut rest = Vec::new();
    src.read_to_end(&mut rest).unwrap();
    assert_eq!(rest, b"body", "the body must survive the head read");
}

#[test]
fn read_response_head_hands_back_a_head_the_upstream_cut_short() {
    // A truncated head is a truncated relay, never an error: the caller writes what arrived and
    // delimits the rest by the close. With no code token there is nothing to parse, so the event
    // simply records no status.
    let mut cut = io::BufReader::new(io::Cursor::new(b"HTTP/1.".to_vec()));
    let (head, complete) = read_response_head(&mut cut, HEAD_MAX);
    assert!(!complete, "an unterminated head must report incomplete");
    assert_eq!(head, b"HTTP/1.");
    assert_eq!(parse_status_code(&head), None);
}

/// The `down` byte total for `sbx net live` must equal what actually crossed to the cage — every
/// head, not just the last one. An interim `1xx` is the case that could drift: it is relayed but
/// then read past, so a counter placed only on the returned head would under-report it. Masking
/// is equal-length, so a masked head counts the same as the bytes the upstream sent.
#[test]
fn every_relayed_head_is_counted_including_an_interim_one() {
    let wire = b"HTTP/1.1 103 Early Hints\r\nLink: </s.css>\r\n\r\n\
                     HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok";
    for needles in [
        Vec::new(),
        vec![SecretNeedle::named("test-secret", b"</s.css>".to_vec())],
    ] {
        let mut up = io::BufReader::new(io::Cursor::new(wire.to_vec()));
        let mut client = Vec::new();
        let down = Arc::new(AtomicU64::new(0));
        let (head, complete) =
            relay_response_head(&mut up, &mut client, &down, None, &needles, false).unwrap();
        assert!(complete);
        assert_eq!(
            parse_status_code(&head),
            Some(200),
            "the FINAL head is returned"
        );
        assert_eq!(
            down.load(Ordering::Relaxed),
            client.len() as u64,
            "the counter must equal the bytes written to the client"
        );
        // Both heads crossed, so the count covers the interim one too.
        let heads = wire.len() - b"ok".len();
        assert_eq!(down.load(Ordering::Relaxed), heads as u64);
    }
}

/// The live log captures the **upstream** HTTP status for a completed L7 request (the
/// `--with-status` data). Teeth: two requests sbx permits identically (both `allow`) reach two
/// upstreams that differ ONLY in their response status — so a recorded 200 vs 404 can come only
/// from reading the real response, never from sbx's own verdict.
#[test]
fn an_allowed_request_records_the_upstream_status_code() {
    use crate::sandbox::control::{LOG_RING_CAP, LogRing, LogVerdict};
    let log = Arc::new(LogRing::new(LOG_RING_CAP));

    for response in [
        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nhi".as_slice(),
        b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".as_slice(),
    ] {
        let (addr, upstream_ca, up) = spawn_upstream("upstream.test", response);
        let proxy_ca = Arc::new(Ca::ephemeral().unwrap());
        let proxy_ca_der = proxy_ca.ca_cert_der();
        let mut roots = RootCertStore::empty();
        roots.add(upstream_ca).unwrap();
        let upstream_cfg = Arc::new(
            ClientConfig::builder()
                .with_root_certificates(roots)
                .with_no_client_auth(),
        );
        let ctx = Arc::new(
            ProxyCtx::new(proxy_ca, policy(&["upstream.test:*"]))
                .unwrap()
                .with_upstream(upstream_cfg)
                .with_log(log.clone())
                .with_resolver(Box::new(|_| Ok(vec![IpAddr::from([127, 0, 0, 1])]))),
        );
        let _ = through_proxy(
            ctx,
            proxy_ca_der,
            "upstream.test",
            "upstream.test",
            addr.port(),
            b"GET /p HTTP/1.1\r\nHost: upstream.test\r\nConnection: close\r\n\r\n",
        )
        .unwrap();
        up.join().unwrap();
    }

    let events = log.snapshot(None, None, false).events;
    assert_eq!(events.len(), 2, "one allow event per request: {events:?}");
    // Both are `allow` (sbx permitted both); only the captured upstream status differs.
    assert!(events.iter().all(|e| e.verdict == LogVerdict::Allow));
    assert_eq!(
        events[0].status,
        Some(200),
        "the 200 upstream response is captured"
    );
    assert_eq!(
        events[1].status,
        Some(404),
        "the 404 is captured — distinct from sbx's allow verdict"
    );
}

/// Reading the head must not eat the response: the buffered reader that reads the head pulls
/// body bytes off the socket with it, and the body relay has to continue from THAT reader. A
/// body larger than one pump chunk forces the relay well past whatever the head read buffered,
/// so a mis-wired seam shows up as a short or corrupt body. Teeth: the whole body arrives
/// byte-identical AND the status is still captured off the front of the same stream. A tiny-body
/// test cannot see this — the entire response fits in the buffer, so the seam is never crossed.
#[test]
fn a_large_response_body_relays_intact_past_the_head_read() {
    use crate::sandbox::control::{LOG_RING_CAP, LogRing};
    // Larger than one pump chunk, so the relay must read well past what the head read buffered.
    // Derived from the chunk constant rather than written as a literal, so growing the chunk
    // cannot quietly cost this test its teeth. A leaked static slice satisfies `spawn_upstream`.
    let body = vec![b'x'; RELAY_CHUNK * 2 + 1_000];
    let mut resp =
        format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n", body.len()).into_bytes();
    resp.extend_from_slice(&body);
    let resp: &'static [u8] = Box::leak(resp.into_boxed_slice());

    let (addr, upstream_ca, up) = spawn_upstream("upstream.test", resp);
    let proxy_ca = Arc::new(Ca::ephemeral().unwrap());
    let proxy_ca_der = proxy_ca.ca_cert_der();
    let mut roots = RootCertStore::empty();
    roots.add(upstream_ca).unwrap();
    let upstream_cfg = Arc::new(
        ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth(),
    );
    let log = Arc::new(LogRing::new(LOG_RING_CAP));
    let ctx = Arc::new(
        ProxyCtx::new(proxy_ca, policy(&["upstream.test:*"]))
            .unwrap()
            .with_upstream(upstream_cfg)
            .with_log(log.clone())
            .with_resolver(Box::new(|_| Ok(vec![IpAddr::from([127, 0, 0, 1])]))),
    );
    let got = through_proxy(
        ctx,
        proxy_ca_der,
        "upstream.test",
        "upstream.test",
        addr.port(),
        b"GET /p HTTP/1.1\r\nHost: upstream.test\r\nConnection: close\r\n\r\n",
    )
    .unwrap();
    up.join().unwrap();

    // The whole body survived the head-read seam, byte-identical.
    let sep = got
        .find("\r\n\r\n")
        .expect("the relayed response has a head/body separator");
    let relayed_body = &got[sep + 4..];
    assert_eq!(
        relayed_body.len(),
        RELAY_CHUNK * 2 + 1_000,
        "the whole body relayed intact"
    );
    assert!(
        relayed_body.bytes().all(|b| b == b'x'),
        "the body bytes are unaltered across the head-read seam"
    );
    // …and the status was still read off the front of that same stream.
    assert_eq!(log.snapshot(None, None, false).events[0].status, Some(200));
}

/// A one-shot loopback TLS upstream that sends `response` and then, instead of closing, **holds
/// the connection open** for as long as the test allows. Every relay in this file otherwise ends
/// on the upstream's EOF, so nothing here could tell "the proxy knew where the message ended"
/// apart from "the upstream happened to close". This upstream removes that confound: a relay
/// that finishes against it finished because the framing said so.
fn spawn_upstream_that_never_closes(
    response: &'static [u8],
) -> (
    SocketAddr,
    CertificateDer<'static>,
    Arc<std::sync::atomic::AtomicBool>,
) {
    let ca = Arc::new(Ca::ephemeral().unwrap());
    let ca_der = ca.ca_cert_der();
    let server_config = Arc::new(
        ServerConfig::builder()
            .with_no_client_auth()
            .with_cert_resolver(Arc::new(CertResolver::new(ca))),
    );
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let release = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let held = release.clone();
    thread::spawn(move || {
        let Ok((sock, _)) = listener.accept() else {
            return;
        };
        let Ok(conn) = ServerConnection::new(server_config) else {
            return;
        };
        let mut tls = StreamOwned::new(conn, sock);
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
        let _ = tls.write_all(response);
        let _ = tls.flush();
        // Hold the socket open. Released once the test has its answer, so the thread ends.
        while !held.load(Ordering::Relaxed) {
            thread::sleep(Duration::from_millis(5));
        }
    });
    (addr, ca_der, release)
}

/// Run one request against an upstream that never closes, and require the relay to finish anyway.
/// Returns the relayed response. Panics with a clear message on the failure this guards: a proxy
/// that does not know where the message ends waits forever on a socket that will never EOF.
fn through_non_closing_upstream(response: &'static [u8], request: &'static [u8]) -> String {
    let (addr, upstream_ca, release) = spawn_upstream_that_never_closes(response);
    let proxy_ca = Arc::new(Ca::ephemeral().unwrap());
    let proxy_ca_der = proxy_ca.ca_cert_der();
    let mut roots = RootCertStore::empty();
    roots.add(upstream_ca).unwrap();
    let upstream_cfg = Arc::new(
        ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth(),
    );
    let ctx = Arc::new(
        ProxyCtx::new(proxy_ca, policy(&["upstream.test:*"]))
            .unwrap()
            .with_upstream(upstream_cfg)
            .with_resolver(Box::new(|_| Ok(vec![IpAddr::from([127, 0, 0, 1])]))),
    );
    let port = addr.port();
    let (tx, rx) = std::sync::mpsc::channel();
    thread::spawn(move || {
        let got = through_proxy(
            ctx,
            proxy_ca_der,
            "upstream.test",
            "upstream.test",
            port,
            request,
        );
        let _ = tx.send(got);
    });
    let got = rx.recv_timeout(Duration::from_secs(10));
    release.store(true, Ordering::Relaxed);
    got.expect("the relay must end at the end of the message, not wait for the upstream to close")
        .expect("the relay failed")
}

/// The headline of response framing: the relay ends where the **message** ends, not where the
/// socket does. Every other relay test in this file is satisfied by an upstream that closes, so
/// none of them can tell the two apart. Here the upstream deliberately never closes, so a proxy
/// that still delimits by EOF hangs and the test times out.
#[test]
fn a_content_length_response_ends_without_waiting_for_the_upstream_to_close() {
    let got = through_non_closing_upstream(
        b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello",
        b"GET /p HTTP/1.1\r\nHost: upstream.test\r\n\r\n",
    );
    assert!(got.contains("200 OK"), "{got:?}");
    assert!(got.ends_with("hello"), "the whole body arrived: {got:?}");
}

/// The trap that makes framing worth doing carefully: a `304` (and a `204`, and any response to
/// `HEAD`) routinely carries a `Content-Length` describing the entity that *would* have been
/// sent. A proxy that believes that length waits forever for a body the server will never send —
/// and conditional GETs against a binary cache produce this shape constantly. The status wins.
#[test]
fn a_304_with_a_content_length_ends_at_its_head() {
    let got = through_non_closing_upstream(
        b"HTTP/1.1 304 Not Modified\r\nContent-Length: 4096\r\nETag: \"v1\"\r\n\r\n",
        b"GET /p HTTP/1.1\r\nHost: upstream.test\r\nIf-None-Match: \"v1\"\r\n\r\n",
    );
    assert!(got.contains("304 Not Modified"), "{got:?}");
    assert!(
        got.ends_with("\r\n\r\n"),
        "nothing follows the head: {got:?}"
    );
}

/// A response to `HEAD` is bodiless whatever its head declares — the length describes the body a
/// `GET` would have returned. The method is what decides, so the framing has to be told it.
#[test]
fn a_head_response_ends_at_its_head_despite_its_declared_length() {
    let got = through_non_closing_upstream(
        b"HTTP/1.1 200 OK\r\nContent-Length: 4096\r\n\r\n",
        b"HEAD /p HTTP/1.1\r\nHost: upstream.test\r\n\r\n",
    );
    assert!(got.contains("200 OK"), "{got:?}");
    assert!(
        got.ends_with("\r\n\r\n"),
        "nothing follows the head: {got:?}"
    );
}

/// A chunked response ends at its terminal chunk, and reaches the cage **verbatim** — size lines,
/// CRLFs and trailers included. The proxy learns where the body ends without rewriting a byte.
#[test]
fn a_chunked_response_ends_at_its_terminal_chunk_and_arrives_verbatim() {
    let got = through_non_closing_upstream(
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n3\r\n mo\r\n0\r\n\r\n",
        b"GET /p HTTP/1.1\r\nHost: upstream.test\r\n\r\n",
    );
    let sep = got.find("\r\n\r\n").expect("head/body separator");
    assert_eq!(
        &got[sep + 4..],
        "5\r\nhello\r\n3\r\n mo\r\n0\r\n\r\n",
        "the chunked body must reach the cage byte-identical: {got:?}"
    );
}

/// An interim `1xx` is a complete message of its own that the real response follows. `103 Early
/// Hints` is emitted by real CDNs, so the head read has to loop past it rather than mistake it
/// for the response — and both heads still reach the cage, which is what the client expects.
#[test]
fn an_interim_1xx_is_relayed_and_the_real_response_is_framed_after_it() {
    let got = through_non_closing_upstream(
        b"HTTP/1.1 103 Early Hints\r\nLink: </s.css>; rel=preload\r\n\r\n\
              HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello",
        b"GET /p HTTP/1.1\r\nHost: upstream.test\r\n\r\n",
    );
    assert!(
        got.contains("103 Early Hints"),
        "the hint reaches the client: {got:?}"
    );
    assert!(
        got.contains("200 OK"),
        "the real response follows it: {got:?}"
    );
    assert!(
        got.ends_with("hello"),
        "the body is framed off the FINAL head, not the interim one: {got:?}"
    );
}

/// The framing decides how long to read, never what to forward: a head this proxy cannot
/// delimit falls back to relaying until the upstream closes — exactly what this path did before
/// it framed anything. Teeth: the upstream declares BOTH framings (the classic desync
/// ambiguity) and then closes, and the body still arrives whole rather than being cut or refused.
#[test]
fn an_ambiguously_framed_response_still_relays_whole() {
    let (addr, upstream_ca, up) = spawn_upstream(
        "upstream.test",
        b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\nhello",
    );
    let proxy_ca = Arc::new(Ca::ephemeral().unwrap());
    let proxy_ca_der = proxy_ca.ca_cert_der();
    let mut roots = RootCertStore::empty();
    roots.add(upstream_ca).unwrap();
    let upstream_cfg = Arc::new(
        ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth(),
    );
    let ctx = Arc::new(
        ProxyCtx::new(proxy_ca, policy(&["upstream.test:*"]))
            .unwrap()
            .with_upstream(upstream_cfg)
            .with_resolver(Box::new(|_| Ok(vec![IpAddr::from([127, 0, 0, 1])]))),
    );
    let got = through_proxy(
        ctx,
        proxy_ca_der,
        "upstream.test",
        "upstream.test",
        addr.port(),
        b"GET /p HTTP/1.1\r\nHost: upstream.test\r\n\r\n",
    )
    .unwrap();
    up.join().unwrap();
    assert!(got.ends_with("hello"), "the body relays whole: {got:?}");
}

/// A loopback TLS "upstream" that keeps its connections open: it serves request after request on
/// the same connection, replying `response` to each, and accepts as many connections as it is
/// given. The returned counter is the figure the reuse tests turn on — how many TCP connections
/// it had to accept to serve them all.
/// What a keep-alive upstream reports back: how many TCP connections it had to accept, and the
/// request heads it served, in order.
struct UpstreamWitness {
    accepted: Arc<AtomicUsize>,
    heads: Arc<std::sync::Mutex<Vec<String>>>,
}

impl UpstreamWitness {
    fn connections(&self) -> usize {
        self.accepted.load(Ordering::Relaxed)
    }

    fn heads(&self) -> Vec<String> {
        self.heads.lock().unwrap().clone()
    }
}

fn spawn_keepalive_upstream(
    response: &'static [u8],
) -> (SocketAddr, CertificateDer<'static>, UpstreamWitness) {
    let ca = Arc::new(Ca::ephemeral().unwrap());
    let ca_der = ca.ca_cert_der();
    let server_config = Arc::new(
        ServerConfig::builder()
            .with_no_client_auth()
            .with_cert_resolver(Arc::new(CertResolver::new(ca))),
    );
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let accepted = Arc::new(AtomicUsize::new(0));
    let heads = Arc::new(std::sync::Mutex::new(Vec::new()));
    let counter = accepted.clone();
    let seen = heads.clone();
    thread::spawn(move || {
        while let Ok((sock, _)) = listener.accept() {
            counter.fetch_add(1, Ordering::Relaxed);
            let config = server_config.clone();
            let seen = seen.clone();
            thread::spawn(move || {
                let Ok(conn) = ServerConnection::new(config) else {
                    return;
                };
                let mut tls = StreamOwned::new(conn, sock);
                loop {
                    // One head per iteration, read a byte at a time so nothing of a following
                    // request is swallowed; EOF or an error ends the connection.
                    let mut head = Vec::new();
                    let mut one = [0u8; 1];
                    loop {
                        match tls.read(&mut one) {
                            Ok(0) | Err(_) => return,
                            Ok(_) => head.push(one[0]),
                        }
                        if head.ends_with(b"\r\n\r\n") {
                            break;
                        }
                    }
                    seen.lock()
                        .unwrap()
                        .push(String::from_utf8_lossy(&head).into_owned());
                    if tls.write_all(response).is_err() || tls.flush().is_err() {
                        return;
                    }
                }
            });
        }
    });
    (addr, ca_der, UpstreamWitness { accepted, heads })
}

/// Drive several HTTPS requests through **one** proxy instance, one client connection each — the
/// shape the cage's forwarder produces. A single `ProxyCtx` serves them all, which is what lets a
/// connection one request leaves behind be found by the next. Each response is read to the
/// client-side end of stream before the following request starts, so what the proxy did with its
/// upstream connection has already happened by then.
fn through_proxy_repeatedly(
    ctx: Arc<ProxyCtx>,
    proxy_ca: CertificateDer<'static>,
    connect_host: &str,
    connect_port: u16,
    requests: &[&[u8]],
) -> io::Result<Vec<String>> {
    let dir = TmpDir::new();
    let path = dir.join("proxy.sock");
    let listener = UnixListener::bind(&path).unwrap();
    thread::spawn(move || {
        let _ = serve(listener, ctx);
    });
    let mut roots = RootCertStore::empty();
    roots.add(proxy_ca).unwrap();
    let client_config = Arc::new(
        ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth(),
    );
    let mut out = Vec::new();
    for request in requests {
        let mut sock = UnixStream::connect(&path).unwrap();
        write!(
            sock,
            "CONNECT {connect_host}:{connect_port} HTTP/1.1\r\n\r\n"
        )
        .unwrap();
        sock.flush().unwrap();
        let established = read_until_blank(&mut sock)?;
        assert!(
            established.contains("200 Connection established"),
            "CONNECT not accepted: {established:?}"
        );
        let name = ServerName::try_from(connect_host.to_string()).unwrap();
        let conn = ClientConnection::new(client_config.clone(), name).map_err(io::Error::other)?;
        let mut tls = StreamOwned::new(conn, sock);
        tls.write_all(request)?;
        tls.flush().ok();
        let mut resp = String::new();
        match tls.read_to_string(&mut resp) {
            Ok(_) => {}
            Err(ref e) if e.kind() == io::ErrorKind::UnexpectedEof => {}
            Err(e) => return Err(e),
        }
        out.push(resp);
    }
    Ok(out)
}

/// A context for the reuse tests: allows `upstream.test` on any port, resolves it to loopback,
/// validates against the upstream's own CA, and reuses connections when `pool` is set.
fn reuse_ctx(
    upstream_ca: CertificateDer<'static>,
    pool: bool,
    injections: Vec<HeaderInjection>,
) -> (Arc<ProxyCtx>, CertificateDer<'static>) {
    let proxy_ca = Arc::new(Ca::ephemeral().unwrap());
    let proxy_ca_der = proxy_ca.ca_cert_der();
    let mut roots = RootCertStore::empty();
    roots.add(upstream_ca).unwrap();
    let upstream_cfg = Arc::new(
        ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth(),
    );
    let ctx = ProxyCtx::new(proxy_ca, policy(&["upstream.test:*"]).with_pool(pool))
        .unwrap()
        .with_upstream(upstream_cfg)
        .with_resolver(Box::new(|_| Ok(vec![IpAddr::from([127, 0, 0, 1])])));
    let ctx = if injections.is_empty() {
        ctx
    } else {
        ctx.with_injections(injections)
    };
    (Arc::new(ctx), proxy_ca_der)
}

/// An upstream that serves one request, waits for its connection to be parked, then destroys it
/// with a reset rather than a clean shutdown. `SO_LINGER` at zero is what turns the close into a
/// `RST`: the shape a peer produces when it tears a connection down rather than closing it, and
/// the one a `read` probe cannot always see coming.
fn spawn_upstream_that_resets_after_one(
    response: &'static [u8],
) -> (SocketAddr, CertificateDer<'static>, UpstreamWitness) {
    use std::os::unix::io::AsRawFd;
    let ca = Arc::new(Ca::ephemeral().unwrap());
    let ca_der = ca.ca_cert_der();
    let server_config = Arc::new(
        ServerConfig::builder()
            .with_no_client_auth()
            .with_cert_resolver(Arc::new(CertResolver::new(ca))),
    );
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let accepted = Arc::new(AtomicUsize::new(0));
    let heads = Arc::new(std::sync::Mutex::new(Vec::new()));
    let counter = accepted.clone();
    let seen = heads.clone();
    thread::spawn(move || {
        let mut nth = 0usize;
        while let Ok((sock, _)) = listener.accept() {
            counter.fetch_add(1, Ordering::Relaxed);
            nth += 1;
            let config = server_config.clone();
            let seen = seen.clone();
            thread::spawn(move || {
                let Ok(conn) = ServerConnection::new(config) else {
                    return;
                };
                let mut tls = StreamOwned::new(conn, sock);
                loop {
                    let mut head = Vec::new();
                    let mut one = [0u8; 1];
                    loop {
                        match tls.read(&mut one) {
                            Ok(0) | Err(_) => return,
                            Ok(_) => head.push(one[0]),
                        }
                        if head.ends_with(b"\r\n\r\n") {
                            break;
                        }
                    }
                    seen.lock()
                        .unwrap()
                        .push(String::from_utf8_lossy(&head).into_owned());
                    if tls.write_all(response).is_err() || tls.flush().is_err() {
                        return;
                    }
                    // Only the first connection is destroyed, so the retry has somewhere to go.
                    // The wait lets the proxy finish relaying and park it: a reset arriving
                    // before that is simply a connection the pool never accepts, which is not
                    // the case under test.
                    if nth == 1 {
                        thread::sleep(Duration::from_millis(80));
                        let linger = libc::linger {
                            l_onoff: 1,
                            l_linger: 0,
                        };
                        unsafe {
                            libc::setsockopt(
                                tls.sock.as_raw_fd(),
                                libc::SOL_SOCKET,
                                libc::SO_LINGER,
                                std::ptr::addr_of!(linger).cast(),
                                std::mem::size_of::<libc::linger>() as libc::socklen_t,
                            );
                        }
                        return;
                    }
                }
            });
        }
    });
    (addr, ca_der, UpstreamWitness { accepted, heads })
}

/// A parked connection the far side destroyed must never cost the request that finds it. Two
/// guards stand between the two: the probe at checkout, and — when the close arrives as a reset
/// the probe did not see — the write failing, which retries on a fresh connection exactly as a
/// connection that takes the request and answers nothing does.
///
/// What this pins is the invariant, not which guard caught it, and the distinction is measured
/// rather than assumed: with the write-failure branch removed, this test still passes. Landing a
/// reset in the window between the probe and the write is a microsecond race no harness here can
/// schedule, and forcing it would mean a switch in the serving path that every other test in
/// this binary runs concurrently with. So the branch is covered by reasoning and this test
/// covers the promise: a destroyed parked connection is never what the cage sees.
#[test]
fn a_parked_connection_the_upstream_reset_does_not_fail_the_next_request() {
    let (addr, upstream_ca, upstream) =
        spawn_upstream_that_resets_after_one(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello");
    let (ctx, proxy_ca_der) = reuse_ctx(upstream_ca, true, vec![]);
    let got = through_proxy_repeatedly(
        ctx,
        proxy_ca_der,
        "upstream.test",
        addr.port(),
        &[
            b"GET /one HTTP/1.1\r\nHost: upstream.test\r\n\r\n",
            b"GET /two HTTP/1.1\r\nHost: upstream.test\r\n\r\n",
        ],
    )
    .unwrap();
    for resp in &got {
        assert!(
            resp.ends_with("hello"),
            "a destroyed parked connection must not reach the cage as a failure: {resp:?}"
        );
    }
    assert_eq!(
        upstream.connections(),
        2,
        "the second request cannot have ridden the connection that was reset"
    );
}

/// The retry cannot tell a server that never saw the request from one that took it and died
/// before answering. For a `GET` the distinction does not matter. For a `POST` it decides
/// whether an effect lands once or twice, so that request is not sent again: it gets the `502`,
/// and the client keeps a decision only the client can make.
///
/// The upstream here stops reading after the first request, so the second one always finds a
/// connection that will not answer — no race to schedule, and removing the method check turns
/// this red (the `POST` would be replayed on a second connection and answered).
#[test]
fn a_post_that_loses_its_reused_connection_is_refused_rather_than_sent_again() {
    let (addr, upstream_ca, upstream) =
        spawn_upstream_that_resets_after_one(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello");
    let (ctx, proxy_ca_der) = reuse_ctx(upstream_ca, true, vec![]);
    let got = through_proxy_repeatedly(
        ctx,
        proxy_ca_der,
        "upstream.test",
        addr.port(),
        &[
            b"GET /one HTTP/1.1\r\nHost: upstream.test\r\n\r\n",
            b"POST /two HTTP/1.1\r\nHost: upstream.test\r\nContent-Length: 0\r\n\r\n",
        ],
    )
    .unwrap();
    assert!(
        got[0].ends_with("hello"),
        "the first request is served normally: {:?}",
        got[0]
    );
    assert!(
        got[1].contains("502 Bad Gateway") && got[1].contains("upstream-closed"),
        "the POST must be refused, naming what happened: {:?}",
        got[1]
    );
    assert_eq!(
        upstream.connections(),
        1,
        "and it must not have been sent a second time on a fresh connection"
    );
}

/// The whole point of the increment: two requests to the same host, one TLS handshake. Nothing
/// else in this file could show it — every other upstream helper serves one request and closes,
/// so reuse would look identical to no reuse.
#[test]
fn two_requests_to_one_host_share_a_single_upstream_connection() {
    let (addr, upstream_ca, upstream) =
        spawn_keepalive_upstream(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello");
    let (ctx, proxy_ca_der) = reuse_ctx(upstream_ca, true, vec![]);
    let pool_ctx = ctx.clone();
    let got = through_proxy_repeatedly(
        ctx,
        proxy_ca_der,
        "upstream.test",
        addr.port(),
        &[
            b"GET /one HTTP/1.1\r\nHost: upstream.test\r\n\r\n",
            b"GET /two HTTP/1.1\r\nHost: upstream.test\r\n\r\n",
        ],
    )
    .unwrap();
    for resp in &got {
        assert!(resp.ends_with("hello"), "both responses arrive: {resp:?}");
    }
    assert_eq!(
        upstream.connections(),
        1,
        "the second request must ride the connection the first left behind"
    );
    assert_eq!(
        pool_ctx.pool.as_ref().unwrap().len(),
        1,
        "and it must go back for a third"
    );
}

/// The control for the test above, and the guarantee for every launch that does not ask for
/// reuse: without the setting the proxy opens — and validates — its own connection per request.
#[test]
fn without_the_setting_each_request_opens_its_own_upstream_connection() {
    let (addr, upstream_ca, upstream) =
        spawn_keepalive_upstream(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello");
    let (ctx, proxy_ca_der) = reuse_ctx(upstream_ca, false, vec![]);
    let pool_ctx = ctx.clone();
    through_proxy_repeatedly(
        ctx,
        proxy_ca_der,
        "upstream.test",
        addr.port(),
        &[
            b"GET /one HTTP/1.1\r\nHost: upstream.test\r\n\r\n",
            b"GET /two HTTP/1.1\r\nHost: upstream.test\r\n\r\n",
        ],
    )
    .unwrap();
    assert_eq!(
        upstream.connections(),
        2,
        "no reuse means one upstream connection per request"
    );
    assert!(pool_ctx.pool.is_none(), "and no pool exists to hold one");
}

/// The trap that makes reuse a regression if it is missed: the upstream's `Connection` describes
/// the *upstream* leg. The client leg is one request per connection whatever the upstream says,
/// so a client told `keep-alive` would send its next request into a socket already closing — an
/// idempotent one silently retried (doubling the traffic reuse was meant to save), a `POST`
/// simply failed.
#[test]
fn a_reused_upstream_still_tells_the_client_to_close() {
    let (addr, upstream_ca, _upstream) = spawn_keepalive_upstream(
            b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: keep-alive\r\nKeep-Alive: timeout=60\r\n\r\nhello",
        );
    let (ctx, proxy_ca_der) = reuse_ctx(upstream_ca, true, vec![]);
    let got = through_proxy_repeatedly(
        ctx,
        proxy_ca_der,
        "upstream.test",
        addr.port(),
        &[b"GET /one HTTP/1.1\r\nHost: upstream.test\r\n\r\n"],
    )
    .unwrap();
    let head = got[0].split("\r\n\r\n").next().unwrap().to_lowercase();
    assert!(
        head.contains("connection: close"),
        "the client leg must be told to close: {:?}",
        got[0]
    );
    assert!(
        !head.contains("keep-alive"),
        "and must not see the upstream leg's persistence: {:?}",
        got[0]
    );
    assert!(
        got[0].ends_with("hello"),
        "the body is untouched: {:?}",
        got[0]
    );
}

/// An upstream that says it is closing is taken at its word, however willing the proxy is to
/// reuse: the next request opens its own connection rather than writing into a closing one.
#[test]
fn an_upstream_that_announces_a_close_is_not_reused() {
    let (addr, upstream_ca, upstream) = spawn_keepalive_upstream(
        b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello",
    );
    let (ctx, proxy_ca_der) = reuse_ctx(upstream_ca, true, vec![]);
    through_proxy_repeatedly(
        ctx,
        proxy_ca_der,
        "upstream.test",
        addr.port(),
        &[
            b"GET /one HTTP/1.1\r\nHost: upstream.test\r\n\r\n",
            b"GET /two HTTP/1.1\r\nHost: upstream.test\r\n\r\n",
        ],
    )
    .unwrap();
    assert_eq!(
        upstream.connections(),
        2,
        "a connection the upstream is closing must not be reused"
    );
}

/// The partition that matters most: a credential scoped to one path must not widen its reach
/// through a shared connection. Two requests to the same host and port, one receiving the
/// injection and one not, are two different keys — so they get two different connections, even
/// though everything about the address matches.
#[test]
fn a_path_scoped_credential_partitions_the_pool() {
    let (addr, upstream_ca, upstream) =
        spawn_keepalive_upstream(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello");
    let (ctx, proxy_ca_der) = reuse_ctx(
        upstream_ca,
        true,
        vec![injection(
            "upstream.test:*/secret",
            "Authorization",
            "Bearer sbx",
        )],
    );
    through_proxy_repeatedly(
        ctx,
        proxy_ca_der,
        "upstream.test",
        addr.port(),
        &[
            b"GET /secret HTTP/1.1\r\nHost: upstream.test\r\n\r\n",
            b"GET /public HTTP/1.1\r\nHost: upstream.test\r\n\r\n",
        ],
    )
    .unwrap();
    // Pinned first: the two requests really do differ in what they carry. Without this the
    // assertion below would pass just as well if the injection matched neither of them.
    let heads = upstream.heads();
    assert_eq!(
        heads.len(),
        2,
        "both requests reached the upstream: {heads:?}"
    );
    assert!(
        heads[0]
            .to_ascii_lowercase()
            .contains("authorization: bearer sbx"),
        "the scoped path carries the credential: {heads:?}"
    );
    assert!(
        !heads[1].to_ascii_lowercase().contains("authorization"),
        "the other path carries none: {heads:?}"
    );
    assert_eq!(
        upstream.connections(),
        2,
        "a connection that carried a credential is not offered to a request without it"
    );
}

/// Two requests that DO share a credential share a connection — the other half of the partition,
/// without which the rule above would be indistinguishable from reuse simply not working.
#[test]
fn two_requests_carrying_the_same_credential_share_a_connection() {
    let (addr, upstream_ca, upstream) =
        spawn_keepalive_upstream(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello");
    let (ctx, proxy_ca_der) = reuse_ctx(
        upstream_ca,
        true,
        vec![injection("upstream.test:*", "Authorization", "Bearer sbx")],
    );
    through_proxy_repeatedly(
        ctx,
        proxy_ca_der,
        "upstream.test",
        addr.port(),
        &[
            b"GET /one HTTP/1.1\r\nHost: upstream.test\r\n\r\n",
            b"GET /two HTTP/1.1\r\nHost: upstream.test\r\n\r\n",
        ],
    )
    .unwrap();
    let heads = upstream.heads();
    assert!(
        heads
            .iter()
            .all(|h| h.to_ascii_lowercase().contains("authorization: bearer sbx")),
        "both requests carry the same credential: {heads:?}"
    );
    assert_eq!(upstream.connections(), 1);
}

/// A connection is only reusable if the message that just crossed it accounted for every byte the
/// upstream sent. Anything past the end means the connection has moved on from that message, and
/// nobody knows to what.
///
/// Both body sizes are here because the residue lands somewhere different in each, and a
/// different guard catches it. A small response is read through the proxy's own buffered reader,
/// so the residue stays there; a body past that reader's capacity is read straight through to the
/// TLS session, so the residue ends up inside **rustls** instead. Checking one place would hand a
/// poisoned connection to the next request in the other case.
#[test]
fn a_connection_holding_bytes_past_the_message_is_not_reused() {
    for (len, where_it_lands) in [(5usize, "the proxy's reader"), (RELAY_CHUNK * 2, "rustls")] {
        let mut response = format!("HTTP/1.1 200 OK\r\nContent-Length: {len}\r\n\r\n").into_bytes();
        response.extend(std::iter::repeat_n(b'x', len));
        response.extend_from_slice(b"BYTES-THE-MESSAGE-DID-NOT-CLAIM");
        let response: &'static [u8] = Box::leak(response.into_boxed_slice());

        let (addr, upstream_ca, upstream) = spawn_keepalive_upstream(response);
        let (ctx, proxy_ca_der) = reuse_ctx(upstream_ca, true, vec![]);
        let pool_ctx = ctx.clone();
        let got = through_proxy_repeatedly(
            ctx,
            proxy_ca_der,
            "upstream.test",
            addr.port(),
            &[
                b"GET /one HTTP/1.1\r\nHost: upstream.test\r\n\r\n",
                b"GET /two HTTP/1.1\r\nHost: upstream.test\r\n\r\n",
            ],
        )
        .unwrap();
        // The framing still holds: the cage gets its declared body, and not one byte of the residue.
        assert!(
            !got[0].contains("BYTES-THE-MESSAGE-DID-NOT-CLAIM"),
            "the relay must stop at the end of the message ({where_it_lands})"
        );
        assert_eq!(
            upstream.connections(),
            2,
            "a connection with bytes left in {where_it_lands} must not serve another request"
        );
        assert_eq!(
            pool_ctx.pool.as_ref().unwrap().len(),
            0,
            "nor be parked at all ({where_it_lands})"
        );
    }
}

/// An upstream that closes without answering used to relay nothing and end the tunnel, which the
/// cage reads as a successful empty response. It is now named: a `502 upstream-closed`. That is
/// also where the one failure reuse can produce surfaces — a connection the far side closed
/// between the pool's probe and the write — so it must not be a silent success.
#[test]
fn an_upstream_that_closes_without_answering_is_refused_rather_than_relayed_empty() {
    let (addr, upstream_ca, up) = spawn_upstream("upstream.test", b"");
    let (ctx, proxy_ca_der) = reuse_ctx(upstream_ca, false, vec![]);
    let got = through_proxy(
        ctx,
        proxy_ca_der,
        "upstream.test",
        "upstream.test",
        addr.port(),
        b"GET /p HTTP/1.1\r\nHost: upstream.test\r\n\r\n",
    )
    .unwrap();
    up.join().unwrap();
    assert!(got.contains("502 Bad Gateway"), "expected a 502: {got:?}");
    assert!(
        got.contains("upstream-closed"),
        "and the reason must name what happened: {got:?}"
    );
}

/// The event log redacts a configured secret out of a request's path **before** it enters the
/// ring — the outbound-secret block is the sharp case, since its query is exactly the one
/// carrying the secret. So even in owner-only RAM the log never holds the raw credential.
#[test]
fn a_logged_path_has_its_secret_query_redacted_at_push() {
    use crate::sandbox::control::{LOG_RING_CAP, LogRing, LogVerdict};
    let ca = Arc::new(Ca::ephemeral().unwrap());
    let der = ca.ca_cert_der();
    let log = Arc::new(LogRing::new(LOG_RING_CAP));
    let ctx = Arc::new(
        ProxyCtx::new(ca, policy(&["host.test:*"]))
            .unwrap()
            .with_log(log.clone())
            .with_redactions(vec![SecretNeedle::named(
                "test-secret",
                b"s3cret-token-value".to_vec(),
            )])
            .with_resolver(Box::new(|_| {
                panic!("resolve must not run on a secret leak")
            })),
    );
    let resp = through_proxy(
        ctx,
        der,
        "host.test",
        "host.test",
        8443,
        b"GET /v1/x?token=s3cret-token-value HTTP/1.1\r\nHost: host.test\r\n\r\n",
    )
    .unwrap();
    assert!(resp.contains("outbound-secret"), "{resp:?}");
    let events = log.snapshot(None, None, false).events;
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].verdict, LogVerdict::Blocked);
    assert_eq!(events[0].reason, "outbound-secret");
    let path = events[0].path.as_deref().unwrap();
    assert!(
        !path.contains("s3cret-token-value"),
        "the secret must be masked out of the logged path: {path:?}"
    );
    assert!(
        path.starts_with("/v1/x?token=") && path.contains('*'),
        "the path is kept but the secret run is masked: {path:?}"
    );
}

/// `with_control` turns the stderr park notices on, but honors a policy that silenced them
/// (`[network] ask_notice = false`) — and the union with the built-in set must preserve that.
#[test]
fn with_control_honors_the_policy_ask_notice() {
    let pending = Arc::new(crate::sandbox::control::PendingState::new());
    let manual = Arc::new(crate::sandbox::control::ManualRules::new());

    // Default policy → the notice is on under `with_control`.
    let on = ProxyCtx::new(Arc::new(Ca::ephemeral().unwrap()), EgressPolicy::default())
        .unwrap()
        .with_control(pending.clone(), manual.clone());
    assert!(on.notices, "the park notice is on by default");

    // A policy that silenced the notice → off, surviving the built-in union in `new`.
    let off = ProxyCtx::new(
        Arc::new(Ca::ephemeral().unwrap()),
        EgressPolicy::default().with_ask_notice(false),
    )
    .unwrap()
    .with_control(pending, manual);
    assert!(
        !off.notices,
        "ask_notice = false suppresses the park notice"
    );
}

/// The shared notice renderer: plain when the palette is plain (a captured/piped run), and
/// carrying the ANSI spans when colored — with the `head` red and the actions yellow, joined
/// by ` — ` then `  |  `.
#[test]
fn egress_notice_line_is_plain_or_colored() {
    let actions = [
        ("allow", "sbx net allow x.test"),
        ("deny", "sbx net deny x.test"),
    ];
    let plain = egress_notice_line(
        &crate::style::Palette::plain(),
        "egress refused x.test:443",
        &actions,
    );
    assert_eq!(
        plain,
        "sbx: egress refused x.test:443 — allow: sbx net allow x.test  |  \
             deny: sbx net deny x.test"
    );
    let colored = egress_notice_line(
        &crate::style::Palette::colored(),
        "egress refused x.test:443",
        &actions[..1],
    );
    assert!(
        colored.contains("\x1b[1;31m"),
        "the head carries the red span"
    );
    assert!(
        colored.contains("\x1b[33m"),
        "the action carries the yellow span"
    );
    assert!(colored.ends_with("\x1b[0m"), "the line resets its styling");
}

/// The refusal body's `sbx net allow` suggestion names the app when the launch is an
/// `sbx app <name>` (so the rule is scoped to that app), and stays bare otherwise.
#[test]
fn allow_suggestion_names_the_app_when_set() {
    let bare = ProxyCtx::new(Arc::new(Ca::ephemeral().unwrap()), policy(&[])).unwrap();
    assert_eq!(bare.allow_suggestion("h.test"), "sbx net allow h.test");
    let app = ProxyCtx::new(Arc::new(Ca::ephemeral().unwrap()), policy(&[]))
        .unwrap()
        .with_app(Some("demo-app".into()));
    assert_eq!(
        app.allow_suggestion("h.test"),
        "sbx net allow h.test --app demo-app"
    );
}

/// A request the policy does not allow is refused with 403 inside the tunnel, and the upstream
/// is never contacted (the verdict is reached before any connect).
#[test]
fn a_denied_host_is_refused_with_403() {
    let proxy_ca = Arc::new(Ca::ephemeral().unwrap());
    let proxy_ca_der = proxy_ca.ca_cert_der();
    let ctx = Arc::new(
        ProxyCtx::new(proxy_ca, policy(&["allowed.test:*"]))
            .unwrap()
            .with_resolver(Box::new(|_| {
                panic!("resolve must not run for a denied host")
            })),
    );
    let resp = through_proxy(
        ctx,
        proxy_ca_der,
        "denied.test",
        "denied.test",
        8443,
        b"GET / HTTP/1.1\r\nHost: denied.test\r\nConnection: close\r\n\r\n",
    )
    .unwrap();
    assert!(
        resp.contains("403"),
        "a denied host should get 403: {resp:?}"
    );
    assert!(
        resp.contains("denied-default"),
        "the refusal must name the motif (no allow rule matched): {resp:?}"
    );
    // The body carries the actionable hint (no app here → the bare form), so the human who
    // reads the response also sees how to permit it — no separate host-side message needed.
    assert!(
        resp.contains("Allow it: sbx net allow denied.test"),
        "the denied-default body must suggest `sbx net allow`: {resp:?}"
    );
}

#[test]
fn read_head_buffered_bounds_a_line_with_no_terminator() {
    // a single oversized line with no terminator must error (bounded), not buffer unboundedly
    let mut flood = std::io::Cursor::new(vec![b'a'; 64 * 1024]);
    let err = read_head_buffered(&mut flood, 16 * 1024).unwrap_err();
    assert!(err.to_string().contains("request head too large"), "{err}");
    // a normal head within the bound still parses
    let mut ok = std::io::Cursor::new(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n".to_vec());
    assert!(read_head_buffered(&mut ok, 16 * 1024).is_ok());
}

#[test]
fn read_chunked_body_dechunks_a_well_formed_body() {
    // one chunk + the terminating zero chunk, with a chunk extension on the size line (ignored).
    let body = std::io::Cursor::new(b"b\r\nhello world\r\n0\r\n\r\n".to_vec());
    let mut br = std::io::BufReader::new(body);
    let out = read_chunked_body(&mut br, 1024).unwrap();
    assert_eq!(
        out, b"hello world",
        "de-chunked body is the chunk data alone"
    );
}

/// The two framings a signer's digest may have to cover, read through the one function, so a body
/// held for a signature is the same bytes the upstream is sent whichever way the client framed it.
#[test]
fn a_held_body_is_the_same_bytes_however_the_client_framed_it() {
    let mut chunked = std::io::BufReader::new(std::io::Cursor::new(
        b"5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n".to_vec(),
    ));
    assert_eq!(
        hold_request_body(&mut chunked, true, 0).unwrap(),
        b"hello world"
    );

    let mut framed = std::io::BufReader::new(std::io::Cursor::new(
        b"hello world and a pipelined leftover".to_vec(),
    ));
    assert_eq!(
        hold_request_body(&mut framed, false, 11).unwrap(),
        b"hello world",
        "exactly the Content-Length, never a byte of what follows it"
    );
}

/// A signer that reports the digest it was told, in a header its manifest declares, so a test can
/// read off the forwarded request what the plugin was shown.
struct DigestEcho;

impl crate::sandbox::signer::Signing for DigestEcho {
    fn sign(
        &mut self,
        req: &crate::sandbox::signer::SignRequest<'_>,
    ) -> Result<crate::sandbox::signer::Signature, String> {
        use crate::sandbox::signer::BodyFacts;
        let told = match req.body {
            None => "none".to_string(),
            Some(BodyFacts::Held { bytes, digest, .. }) => format!("{bytes}/{digest}"),
            Some(BodyFacts::Unheld { .. }) => "unheld".to_string(),
        };
        Ok(crate::sandbox::signer::Signature {
            headers: vec![("X-Body".to_string(), told)],
            label: None,
        })
    }
}

fn digesting_injection() -> HeaderInjection {
    digesting_injection_for("host.test:*")
}

fn digesting_injection_for(to: &str) -> HeaderInjection {
    HeaderInjection {
        rule: classify(to).unwrap(),
        form: super::Form::Signed(super::Signed {
            name: "digest-echo".to_string(),
            sets: vec!["X-Body".to_string()],
            sees: Vec::new(),
            key: "the-key".to_string(),
            marker: None,
            process: Arc::new(std::sync::Mutex::new(DigestEcho)),
            body_digest: Some(crate::plugins::signer::BodyDigest::Sha256),
        }),
    }
}

/// Holding a body to digest it changes how sbx **forwards** a request, so what the upstream
/// receives is asserted rather than inferred from the digest alone.
///
/// The second half is the one that has no other witness: a request with no body must reach the
/// upstream framed exactly as it would have been had no signer asked, because forcing a length is
/// how a *re-framed* body is made unambiguous and a bodyless request has nothing to re-frame.
/// Forcing it there put a `Content-Length: 0` on every `GET` to a signed destination.
#[test]
fn holding_a_body_to_digest_it_reframes_only_a_request_that_has_one() {
    let framed = |request: &[u8]| {
        run_with_injections_and_redactions(vec![digesting_injection()], &[], request)
    };
    let lengths = |head: &str| {
        head.lines()
            .filter(|l| l.to_ascii_lowercase().starts_with("content-length:"))
            .count()
    };

    // A `Content-Length` body: held, digested, and forwarded under one length — the client's own
    // copy is dropped and sbx's measurement is the only framing the upstream sees.
    let (resp, head) =
        framed(b"POST / HTTP/1.1\r\nHost: host.test\r\nContent-Length: 11\r\n\r\nhello world");
    assert!(resp.contains("200"), "{resp:?}");
    assert!(
        head.contains(
            "X-Body: 11/b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
        ),
        "the plugin is told the length and the SHA-256 of `hello world`: {head:?}"
    );
    assert_eq!(
        lengths(&head),
        1,
        "one framing reaches the upstream: {head:?}"
    );

    // A `chunked` body: the same digest, and the framing replaced — no coding may survive it.
    let (resp, head) =
        framed(b"POST / HTTP/1.1\r\nHost: host.test\r\nTransfer-Encoding: chunked\r\n\r\nb\r\nhello world\r\n0\r\n\r\n");
    assert!(resp.contains("200"), "{resp:?}");
    assert!(
        head.contains(
            "X-Body: 11/b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
        ),
        "how the client framed the body is not what is digested: {head:?}"
    );
    assert_eq!(lengths(&head), 1, "{head:?}");
    assert!(
        !head.to_ascii_lowercase().contains("transfer-encoding:"),
        "the coding is replaced, never forwarded beside a length: {head:?}"
    );

    // No body: told the digest of nothing, and framed exactly as it was.
    let (resp, head) = framed(b"GET / HTTP/1.1\r\nHost: host.test\r\n\r\n");
    assert!(resp.contains("200"), "{resp:?}");
    assert!(
        head.contains("X-Body: 0/e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
        "the digest of the empty string is a fact, not an absence: {head:?}"
    );
    assert_eq!(
        lengths(&head),
        0,
        "a bodyless request gains no framing because a signer asked for a digest: {head:?}"
    );
}

/// A body held to be digested still reaches the **capture**.
///
/// The tee that fills the request-body sink lives on the streaming relay, and a held body never
/// goes through it: the held path has to hand the bytes over itself. Nothing about signing would
/// fail if it did not, which is exactly why this is asserted — `sbx net capture` would quietly lose
/// the request body of every request a signer touched, and every signer test would stay green.
#[test]
fn a_body_held_to_be_digested_still_reaches_the_capture() {
    use crate::sandbox::control::{CaptureLevel, LOG_RING_CAP, LogRing};

    for framing in [
        "Content-Length: 7\r\n\r\npayload",
        "Transfer-Encoding: chunked\r\n\r\n7\r\npayload\r\n0\r\n\r\n",
    ] {
        let (addr, upstream_ca, up) = spawn_upstream(
            "upstream.test",
            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
        );
        let proxy_ca = Arc::new(Ca::ephemeral().unwrap());
        let proxy_ca_der = proxy_ca.ca_cert_der();
        let mut roots = RootCertStore::empty();
        roots.add(upstream_ca).unwrap();
        let upstream_cfg = Arc::new(
            ClientConfig::builder()
                .with_root_certificates(roots)
                .with_no_client_auth(),
        );
        let log = Arc::new(LogRing::new(LOG_RING_CAP));
        let ctx = capturing_ctx(
            proxy_ca,
            upstream_cfg,
            log.clone(),
            CaptureLevel::Bodies,
            8,
            vec![digesting_injection_for("upstream.test:*")],
            vec![],
        );
        let request =
            format!("POST /p HTTP/1.1\r\nHost: upstream.test\r\nConnection: close\r\n{framing}");
        let resp = through_proxy(
            ctx.clone(),
            proxy_ca_der,
            "upstream.test",
            "upstream.test",
            addr.port(),
            request.as_bytes(),
        )
        .unwrap();
        assert!(resp.contains("200"), "{framing:?}: {resp:?}");
        up.join().unwrap();

        let cap = one_capture(&ctx, &log);
        assert_eq!(
            String::from_utf8(cap.req_body.bytes.clone()).unwrap(),
            "payload",
            "a held body is handed to the capture, not lost with the tee it bypassed ({framing:?})"
        );
    }
}

/// The ceiling is answered **before** the client is invited to send.
///
/// A client that announced `Expect: 100-continue` withholds its body until it sees a `100`, so the
/// order of those two writes is the difference between answering an oversized upload and receiving
/// one. Asserted on the absence of the interim response, which is the only thing that distinguishes
/// the two orderings from outside.
#[test]
fn an_oversized_body_is_refused_before_the_client_is_invited_to_send_it() {
    let ca = Arc::new(Ca::ephemeral().unwrap());
    let der = ca.ca_cert_der();
    let ctx = Arc::new(
        ProxyCtx::new(ca, policy(&["host.test:*"]))
            .unwrap()
            .with_injections(vec![digesting_injection()])
            .with_resolver(Box::new(|_| Ok(vec![IpAddr::from([127, 0, 0, 1])]))),
    );
    let resp = through_proxy(
        ctx,
        der,
        "host.test",
        "host.test",
        8443,
        format!(
            "POST / HTTP/1.1\r\nHost: host.test\r\nExpect: 100-continue\r\n\
             Content-Length: {}\r\n\r\n",
            CHUNKED_REQUEST_CAP + 1
        )
        .as_bytes(),
    )
    .unwrap();
    assert!(
        resp.contains("413") && resp.contains("signer-body-too-large"),
        "{resp:?}"
    );
    assert!(
        !resp.contains("100 Continue"),
        "a body sbx has already decided to refuse must never be invited: {resp:?}"
    );
}

/// A `chunked` body over the ceiling keeps the refusal it always had.
///
/// It declares no length, so there is nothing to answer from the head: the de-chunker meets the
/// ceiling while reading and fails closed, which is `400 bad-request:chunked` — the same answer an
/// over-cap chunked body got before any signer was involved. The guide says so, and this is what
/// makes the sentence checkable; a `413` here would mean the two framings had drifted apart.
#[test]
fn a_chunked_body_over_the_ceiling_keeps_its_own_refusal() {
    let ca = Arc::new(Ca::ephemeral().unwrap());
    let der = ca.ca_cert_der();
    let ctx = Arc::new(
        ProxyCtx::new(ca, policy(&["host.test:*"]))
            .unwrap()
            .with_injections(vec![digesting_injection()])
            .with_resolver(Box::new(|_| Ok(vec![IpAddr::from([127, 0, 0, 1])]))),
    );
    // One chunk declaring 4 GiB. The size line alone trips the cap, so the bytes are never sent.
    let resp = through_proxy(
        ctx,
        der,
        "host.test",
        "host.test",
        8443,
        b"POST / HTTP/1.1\r\nHost: host.test\r\nTransfer-Encoding: chunked\r\n\r\nffffffff\r\n",
    )
    .unwrap();
    assert!(
        resp.contains("400") && resp.contains("bad-request:chunked"),
        "an over-cap chunked body is discovered while reading, not read off the head: {resp:?}"
    );
    assert!(
        !resp.contains("signer-body-too-large"),
        "and it is not the declared-length refusal wearing another framing: {resp:?}"
    );
}

/// The ceiling on a declared body is answered from the head, so an oversized upload is refused
/// before the client is invited to send it rather than after it has crossed the loopback. A chunked
/// request declares no length, so there is nothing to answer from and the de-chunker bounds it.
#[test]
fn a_declared_body_above_the_ceiling_is_known_from_the_head() {
    assert!(body_exceeds_hold(false, CHUNKED_REQUEST_CAP + 1));
    assert!(!body_exceeds_hold(false, CHUNKED_REQUEST_CAP));
    assert!(
        !body_exceeds_hold(true, CHUNKED_REQUEST_CAP + 1),
        "a chunked request's declared length is not its body's"
    );
}

/// A body that ends early is an error rather than a short one silently digested: the signature
/// would cover bytes the upstream never receives.
#[test]
fn a_body_that_ends_before_its_content_length_is_an_error() {
    let mut reader = std::io::BufReader::new(std::io::Cursor::new(b"short".to_vec()));
    assert!(hold_request_body(&mut reader, false, 500).is_err());
}

#[test]
fn read_chunked_body_concatenates_multiple_chunks_and_strips_trailers() {
    // two chunks then a trailer section (discarded) then the final blank line.
    let body =
        std::io::Cursor::new(b"5\r\nhello\r\n6\r\n world\r\n0\r\nX-Trailer: yes\r\n\r\n".to_vec());
    let mut br = std::io::BufReader::new(body);
    let out = read_chunked_body(&mut br, 1024).unwrap();
    assert_eq!(
        out, b"hello world",
        "chunks concatenate; trailers are not in the body"
    );
}

#[test]
fn read_chunked_body_fails_closed_on_malformed_framing() {
    // a non-hex chunk size
    let mut br = std::io::BufReader::new(std::io::Cursor::new(b"zz\r\nx\r\n0\r\n\r\n".to_vec()));
    let err = read_chunked_body(&mut br, 1024).unwrap_err();
    assert!(err.to_string().contains("not hexadecimal"), "{err}");
    // chunk data not followed by CRLF
    let mut br =
        std::io::BufReader::new(std::io::Cursor::new(b"5\r\nhelloXX\r\n0\r\n\r\n".to_vec()));
    let err = read_chunked_body(&mut br, 1024).unwrap_err();
    assert!(err.to_string().contains("CRLF"), "{err}");
    // the body ends before a chunk size (EOF mid-frame)
    let mut br = std::io::BufReader::new(std::io::Cursor::new(Vec::new()));
    let err = read_chunked_body(&mut br, 1024).unwrap_err();
    assert!(err.to_string().contains("ended before"), "{err}");
    // a chunk size line with no terminator (truncated)
    let mut br = std::io::BufReader::new(std::io::Cursor::new(b"5".to_vec()));
    let err = read_chunked_body(&mut br, 1024).unwrap_err();
    assert!(err.to_string().contains("no line terminator"), "{err}");
}

#[test]
fn read_chunked_body_fails_closed_when_the_body_exceeds_the_cap() {
    // a single chunk claiming more than the cap is refused before any oversized allocation.
    let mut br = std::io::BufReader::new(std::io::Cursor::new(b"ffffff\r\n".to_vec()));
    let err = read_chunked_body(&mut br, 64).unwrap_err();
    assert!(err.to_string().contains("exceeds the proxy cap"), "{err}");
}

#[test]
fn read_chunked_body_does_not_overflow_on_a_max_u64_chunk_size() {
    // A running-total overflow: a small first chunk, then a size line of `u64::MAX` (16 hex
    // digits). `buf.len() + size` would overflow — checked_add refuses it (else it panics in
    // resize/the slice). The cap check must catch it as an over-cap error, never panic.
    let mut br = std::io::BufReader::new(std::io::Cursor::new(
        b"1\r\nX\r\nffffffffffffffff\r\n".to_vec(),
    ));
    let err = read_chunked_body(&mut br, 1024).unwrap_err();
    assert!(err.to_string().contains("exceeds the proxy cap"), "{err}");
}

#[test]
fn read_chunked_body_bounds_a_no_newline_size_line_flood() {
    // A chunk-size line with no terminator and more than CHUNK_LINE_MAX bytes must be a hard
    // error (bounded), not unbounded host-side buffering.
    let flood = vec![b'a'; (CHUNK_LINE_MAX + 4096) as usize];
    let mut br = std::io::BufReader::new(std::io::Cursor::new(flood));
    let err = read_chunked_body(&mut br, 64 * 1024 * 1024).unwrap_err();
    assert!(err.to_string().contains("too long"), "{err}");
}

#[test]
fn duplicated_framing_headers_are_refused_with_400_before_the_policy_check() {
    // A duplicated Content-Length or Host is a classic request-desync vector — refused
    // fail-closed at the proxy, before policy/resolve (the resolver panics if reached, so the
    // guard is proven to precede it). (`Transfer-Encoding: chunked` is NOT refused here — it is
    // de-chunked and re-framed; see `a_chunked_request_body_is_dechunked_and_reframed`.)
    for req in [
            b"GET / HTTP/1.1\r\nHost: allowed.test\r\nContent-Length: 0\r\nContent-Length: 5\r\nConnection: close\r\n\r\n".to_vec(),
            b"GET / HTTP/1.1\r\nHost: allowed.test\r\nHost: evil.test\r\nConnection: close\r\n\r\n".to_vec(),
        ] {
            let proxy_ca = Arc::new(Ca::ephemeral().unwrap());
            let proxy_ca_der = proxy_ca.ca_cert_der();
            let ctx = Arc::new(
                ProxyCtx::new(proxy_ca, policy(&["allowed.test:*"]))
                    .unwrap()
                    .with_resolver(Box::new(|_| {
                        panic!("resolve must not run for a framing refusal")
                    })),
            );
            let resp = through_proxy(
                ctx,
                proxy_ca_der,
                "allowed.test",
                "allowed.test",
                8443,
                &req,
            )
            .unwrap();
            assert!(
                resp.contains("400") && resp.contains("bad-request"),
                "expected a 400 bad-request framing refusal: {resp:?}"
            );
        }
}

#[test]
fn a_non_chunked_transfer_encoding_is_refused() {
    // `Transfer-Encoding` codings other than `chunked` are not supported (the proxy de-chunks
    // only `chunked`); anything else is refused fail-closed before policy.
    let proxy_ca = Arc::new(Ca::ephemeral().unwrap());
    let proxy_ca_der = proxy_ca.ca_cert_der();
    let ctx = Arc::new(
        ProxyCtx::new(proxy_ca, policy(&["allowed.test:*"]))
            .unwrap()
            .with_resolver(Box::new(|_| {
                panic!("resolve must not run for a framing refusal")
            })),
    );
    let resp = through_proxy(
            ctx,
            proxy_ca_der,
            "allowed.test",
            "allowed.test",
            8443,
            b"GET / HTTP/1.1\r\nHost: allowed.test\r\nTransfer-Encoding: gzip\r\nConnection: close\r\n\r\n",
        )
        .unwrap();
    assert!(
        resp.contains("400") && resp.contains("bad-request:transfer-encoding"),
        "an unsupported Transfer-Encoding coding must be refused: {resp:?}"
    );
}

#[test]
fn a_chunked_request_body_is_dechunked_and_reframed_with_content_length() {
    // A streaming client (e.g. agy's `POST /v1internal:streamGenerateContent`) sends
    // `Transfer-Encoding: chunked` with no Content-Length. The proxy de-chunks the body and
    // re-frames the request with a synthesized Content-Length, stripping Transfer-Encoding — so
    // the upstream sees one unambiguous CL-framed request (no CL/TE smuggling ambiguity) and the
    // response is relayed. The captured upstream head is the proof.
    let body = b"hello world";
    let chunked = format!(
        "POST /v1internal:streamGenerateContent HTTP/1.1\r\n\
             Host: chunked.test\r\n\
             Transfer-Encoding: chunked\r\n\
             Connection: close\r\n\r\n\
             {size:x}\r\n{data}\r\n0\r\n\r\n",
        size = body.len(),
        data = std::str::from_utf8(body).unwrap(),
    );
    let (addr, upstream_ca, rx) = spawn_upstream_capturing(
        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
    );
    let proxy_ca = Arc::new(Ca::ephemeral().unwrap());
    let proxy_ca_der = proxy_ca.ca_cert_der();
    let mut roots = RootCertStore::empty();
    roots.add(upstream_ca).unwrap();
    let upstream_cfg = Arc::new(
        ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth(),
    );
    let ctx = Arc::new(
        ProxyCtx::new(proxy_ca, policy(&["chunked.test:*"]))
            .unwrap()
            .with_upstream(upstream_cfg)
            .with_resolver(Box::new(|_| Ok(vec![IpAddr::from([127, 0, 0, 1])]))),
    );
    let resp = through_proxy(
        ctx,
        proxy_ca_der,
        "chunked.test",
        "chunked.test",
        addr.port(),
        chunked.as_bytes(),
    )
    .unwrap();
    let head = rx
        .recv_timeout(std::time::Duration::from_secs(5))
        .expect("the upstream must receive the forwarded request");
    assert!(
        head.contains(&format!("Content-Length: {}", body.len())),
        "the upstream head must carry the synthesized Content-Length (re-framed): {head:?}"
    );
    assert!(
        !head.to_ascii_lowercase().contains("transfer-encoding"),
        "the upstream head must NOT carry Transfer-Encoding (de-chunked, not forwarded): {head:?}"
    );
    assert!(
        resp.contains("200 OK"),
        "the upstream response must be relayed back: {resp:?}"
    );
}

#[test]
fn a_chunked_request_carrying_a_content_length_is_reframed_without_ambiguity() {
    // The canonical CL.TE/TE.CL request-smuggling vector: the client sends BOTH
    // `Transfer-Encoding: chunked` and a (misleading) `Content-Length`. The proxy must resolve
    // it deterministically — chunked wins, the body is de-chunked, and the upstream sees ONE
    // synthesized Content-Length (the real de-chunked length) and NO Transfer-Encoding and NOT
    // the client's bogus Content-Length. So no desync can reach the upstream.
    let body = b"hello world";
    let chunked = format!(
        "POST /v1internal:streamGenerateContent HTTP/1.1\r\n\
             Host: smug.test\r\n\
             Transfer-Encoding: chunked\r\n\
             Content-Length: 3\r\n\
             Connection: close\r\n\r\n\
             {size:x}\r\n{data}\r\n0\r\n\r\n",
        size = body.len(),
        data = std::str::from_utf8(body).unwrap(),
    );
    let (addr, upstream_ca, rx) = spawn_upstream_capturing(
        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
    );
    let proxy_ca = Arc::new(Ca::ephemeral().unwrap());
    let proxy_ca_der = proxy_ca.ca_cert_der();
    let mut roots = RootCertStore::empty();
    roots.add(upstream_ca).unwrap();
    let upstream_cfg = Arc::new(
        ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth(),
    );
    let ctx = Arc::new(
        ProxyCtx::new(proxy_ca, policy(&["smug.test:*"]))
            .unwrap()
            .with_upstream(upstream_cfg)
            .with_resolver(Box::new(|_| Ok(vec![IpAddr::from([127, 0, 0, 1])]))),
    );
    let resp = through_proxy(
        ctx,
        proxy_ca_der,
        "smug.test",
        "smug.test",
        addr.port(),
        chunked.as_bytes(),
    )
    .unwrap();
    let head = rx
        .recv_timeout(std::time::Duration::from_secs(5))
        .expect("the upstream must receive the forwarded request");
    // exactly one Content-Length, and it is the real de-chunked length (not the client's `3`).
    assert_eq!(
        head.to_ascii_lowercase().matches("content-length:").count(),
        1,
        "the upstream head must carry exactly one Content-Length: {head:?}"
    );
    assert!(
        head.contains(&format!("Content-Length: {}", body.len())),
        "the one Content-Length must be the de-chunked length, not the client's bogus 3: {head:?}"
    );
    assert!(
        !head.to_ascii_lowercase().contains("transfer-encoding"),
        "the upstream head must NOT carry Transfer-Encoding: {head:?}"
    );
    assert!(
        resp.contains("200 OK"),
        "the response must be relayed: {resp:?}"
    );
}

/// Under the `ask` posture an undecided request parks; an out-of-band `allow` lets it proceed
/// to the validated upstream. The allow synthesizes an exact-host deciding rule, so the loopback
/// upstream passes the SSRF guard (the "I explicitly said yes to an internal host" case) — the
/// parking path's teeth without a live cage.
#[test]
fn an_asked_request_proceeds_when_allowed() {
    use crate::sandbox::control::{PendingState, Verdict};
    let (addr, upstream_ca, up) = spawn_upstream(
        "ask.test",
        b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello",
    );
    let proxy_ca = Arc::new(Ca::ephemeral().unwrap());
    let proxy_ca_der = proxy_ca.ca_cert_der();
    let mut roots = RootCertStore::empty();
    roots.add(upstream_ca).unwrap();
    let upstream_cfg = Arc::new(
        ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth(),
    );
    let state = Arc::new(PendingState::new());
    let ctx = Arc::new(
        ProxyCtx::new(
            proxy_ca,
            EgressPolicy::default().with_default(DefaultAction::Ask),
        )
        .unwrap()
        .with_upstream(upstream_cfg)
        .with_resolver(Box::new(|_| Ok(vec![IpAddr::from([127, 0, 0, 1])])))
        .with_pending_silent(state.clone()),
    );
    // Answer `allow` as soon as the request parks.
    let answerer = {
        let state = state.clone();
        thread::spawn(move || answer_when_parked(&state, Verdict::Allow))
    };
    let resp = through_proxy(
        ctx,
        proxy_ca_der,
        "ask.test",
        "ask.test",
        addr.port(),
        b"GET / HTTP/1.1\r\nHost: ask.test\r\nConnection: close\r\n\r\n",
    )
    .unwrap();
    assert_eq!(answerer.join().unwrap().as_deref(), Some("ask.test"));
    up.join().unwrap();
    assert!(
        resp.contains("200 OK") && resp.contains("hello"),
        "an allowed ask must reach the upstream: {resp:?}"
    );
}

/// Under `ask`, an out-of-band `deny` refuses the parked request with 403 `asked-denied`, and
/// the upstream is never contacted (the resolver panics if reached).
#[test]
fn an_asked_request_is_refused_when_denied() {
    use crate::sandbox::control::{PendingState, Verdict};
    let proxy_ca = Arc::new(Ca::ephemeral().unwrap());
    let proxy_ca_der = proxy_ca.ca_cert_der();
    let state = Arc::new(PendingState::new());
    let sdir = TmpDir::new();
    let stats = Arc::new(crate::sandbox::egress_stats::EgressStats::new(
        sdir.join("stats"),
        "/t".into(),
        None,
    ));
    let ctx = Arc::new(
        ProxyCtx::new(
            proxy_ca,
            EgressPolicy::default().with_default(DefaultAction::Ask),
        )
        .unwrap()
        .with_resolver(Box::new(|_| {
            panic!("resolve must not run for a denied ask")
        }))
        .with_stats(stats.clone())
        .with_pending_silent(state.clone()),
    );
    let answerer = {
        let state = state.clone();
        thread::spawn(move || answer_when_parked(&state, Verdict::Deny))
    };
    let resp = through_proxy(
        ctx,
        proxy_ca_der,
        "ask.test",
        "ask.test",
        8443,
        b"GET / HTTP/1.1\r\nHost: ask.test\r\nConnection: close\r\n\r\n",
    )
    .unwrap();
    answerer.join().unwrap();
    assert!(
        resp.contains("403") && resp.contains("asked-denied"),
        "a denied ask must get 403 asked-denied: {resp:?}"
    );
    // The parked-then-denied site records a deny (the sibling of the manual-deny site).
    assert_eq!(
        stats.snapshot()["ask.test"].deny,
        1,
        "a parked-and-denied request must record one deny"
    );
}

/// A live manual rule (from a prior `--session` answer) short-circuits the ask: a remembered
/// allow lets the request proceed to the upstream **without parking** (no answerer thread — the
/// default ask wait is indefinite, so if the overlay did not decide, this would hang forever and
/// the test would time out), and a remembered deny refuses it. The 4b verdict path, cage-free.
#[test]
fn a_manual_rule_decides_an_ask_without_parking() {
    use crate::sandbox::control::{ManualRules, Verdict};

    // A remembered allow on the upstream's exact host:port → proceeds, never parks.
    let (addr, upstream_ca, up) = spawn_upstream(
        "ask.test",
        b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello",
    );
    let proxy_ca = Arc::new(Ca::ephemeral().unwrap());
    let proxy_ca_der = proxy_ca.ca_cert_der();
    let mut roots = RootCertStore::empty();
    roots.add(upstream_ca).unwrap();
    let upstream_cfg = Arc::new(
        ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth(),
    );
    let manual = Arc::new(ManualRules::new());
    manual.remember(Verdict::Allow, "ask.test", addr.port());
    let ctx = Arc::new(
        ProxyCtx::new(
            proxy_ca,
            EgressPolicy::default().with_default(DefaultAction::Ask),
        )
        .unwrap()
        .with_upstream(upstream_cfg)
        .with_resolver(Box::new(|_| Ok(vec![IpAddr::from([127, 0, 0, 1])])))
        .with_manual(manual),
    );
    let resp = through_proxy(
        ctx,
        proxy_ca_der,
        "ask.test",
        "ask.test",
        addr.port(),
        b"GET / HTTP/1.1\r\nHost: ask.test\r\nConnection: close\r\n\r\n",
    )
    .unwrap();
    up.join().unwrap();
    assert!(
        resp.contains("200 OK") && resp.contains("hello"),
        "a remembered allow must proceed without parking: {resp:?}"
    );

    // A remembered deny refuses without parking; the resolver panics if (wrongly) reached.
    let proxy_ca = Arc::new(Ca::ephemeral().unwrap());
    let proxy_ca_der = proxy_ca.ca_cert_der();
    let manual = Arc::new(ManualRules::new());
    manual.remember(Verdict::Deny, "blocked.test", 443);
    let ctx = Arc::new(
        ProxyCtx::new(
            proxy_ca,
            EgressPolicy::default().with_default(DefaultAction::Ask),
        )
        .unwrap()
        .with_resolver(Box::new(|_| {
            panic!("resolve must not run for a remembered deny")
        }))
        .with_manual(manual),
    );
    let resp = through_proxy(
        ctx,
        proxy_ca_der,
        "blocked.test",
        "blocked.test",
        443,
        b"GET / HTTP/1.1\r\nHost: blocked.test\r\nConnection: close\r\n\r\n",
    )
    .unwrap();
    assert!(
        resp.contains("403") && resp.contains("denied-by-rule"),
        "a remembered deny must 403 without parking (it is now a deny rule in the effective \
             policy): {resp:?}"
    );
}

/// A `--session` allow lives in the overlay, which the proxy consults **only** when the config
/// policy returns Ask. A config *deny* returns DeniedBy first (before the overlay), so loading an
/// overlay allow for a config-denied host must not let it through — the load-bearing security
/// property of the proactive-`--session` path. The resolver panics if reached (a deny refuses
/// before resolving), so a regression that consulted the overlay first would blow up rather than
/// silently pass.
#[test]
fn a_config_deny_is_not_overridable_by_a_session_overlay_allow() {
    use crate::sandbox::control::{ManualRules, Verdict};
    let ca = Arc::new(Ca::ephemeral().unwrap());
    let der = ca.ca_cert_der();
    let manual = Arc::new(ManualRules::new());
    manual.remember_rule(Verdict::Allow, classify("blocked.test").unwrap());
    let ctx = Arc::new(
        ProxyCtx::new(
            ca,
            EgressPolicy::new(vec![], vec![classify("blocked.test").unwrap()])
                .with_default(DefaultAction::Ask),
        )
        .unwrap()
        .with_manual(manual)
        .with_resolver(Box::new(|_| {
            panic!("a config-denied host must refuse before resolving")
        })),
    );
    let resp = through_proxy(
        ctx,
        der,
        "blocked.test",
        "blocked.test",
        443,
        b"GET / HTTP/1.1\r\nHost: blocked.test\r\nConnection: close\r\n\r\n",
    )
    .unwrap();
    assert!(
        resp.contains("403") && resp.contains("denied-by-rule"),
        "a config deny must win over a session overlay allow: {resp:?}"
    );
}

/// The security delta of proactive `--session` rules: an overlay allow carries the rule that
/// *matched* to the SSRF guard, so a **broad** rule does not silently unlock a private address the
/// way an exact-host approval deliberately does. Both resolve to the same loopback IP — the
/// wildcard `*.internal.test` is `ssrf-blocked`, while the exact host is permitted and reaches a
/// real loopback upstream (200). The contrast is the proof the guard treated them differently.
#[test]
fn a_broad_session_overlay_allow_does_not_unlock_a_private_ip() {
    use crate::sandbox::control::{ManualRules, Verdict};

    // A wildcard overlay allow (`:*` so it matches the upstream's random port) → the deciding rule
    // is a subdomain wildcard → the SSRF guard refuses the loopback address.
    let ca = Arc::new(Ca::ephemeral().unwrap());
    let der = ca.ca_cert_der();
    let manual = Arc::new(ManualRules::new());
    manual.remember_rule(Verdict::Allow, classify("*.internal.test:*").unwrap());
    let ctx = Arc::new(
        ProxyCtx::new(ca, EgressPolicy::default().with_default(DefaultAction::Ask))
            .unwrap()
            .with_manual(manual)
            .with_resolver(Box::new(|_| Ok(vec![IpAddr::from([127, 0, 0, 1])]))),
    );
    let resp = through_proxy(
        ctx,
        der,
        "sub.internal.test",
        "sub.internal.test",
        8443,
        b"GET / HTTP/1.1\r\nHost: sub.internal.test\r\nConnection: close\r\n\r\n",
    )
    .unwrap();
    assert!(
        resp.contains("403") && resp.contains("ssrf-blocked"),
        "a wildcard overlay allow must not unlock a private IP: {resp:?}"
    );

    // An exact-host overlay allow for the same private address IS permitted (the deliberate
    // "approve an internal target" behavior): it passes the SSRF guard and reaches a real upstream.
    let (addr, upstream_ca, up) = spawn_upstream(
        "exact.internal.test",
        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
    );
    let proxy_ca = Arc::new(Ca::ephemeral().unwrap());
    let proxy_ca_der = proxy_ca.ca_cert_der();
    let mut roots = RootCertStore::empty();
    roots.add(upstream_ca).unwrap();
    let upstream_cfg = Arc::new(
        ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth(),
    );
    let manual = Arc::new(ManualRules::new());
    manual.remember(Verdict::Allow, "exact.internal.test", addr.port());
    let ctx = Arc::new(
        ProxyCtx::new(
            proxy_ca,
            EgressPolicy::default().with_default(DefaultAction::Ask),
        )
        .unwrap()
        .with_upstream(upstream_cfg)
        .with_resolver(Box::new(|_| Ok(vec![IpAddr::from([127, 0, 0, 1])])))
        .with_manual(manual),
    );
    let resp = through_proxy(
        ctx,
        proxy_ca_der,
        "exact.internal.test",
        "exact.internal.test",
        addr.port(),
        b"GET / HTTP/1.1\r\nHost: exact.internal.test\r\nConnection: close\r\n\r\n",
    )
    .unwrap();
    up.join().unwrap();
    assert!(
        resp.contains("200 OK"),
        "an exact-host overlay allow must reach the approved internal target: {resp:?}"
    );
}

/// The full proactive-`--session` wire path, cage-free: `inject_rule` (the client `sbx net allow
/// --session` drives) loads a rule over a real control `serve` into the overlay the proxy shares,
/// so an otherwise-undecided ask request proceeds to the upstream **without parking**. There is no
/// answerer thread and the default ask wait is indefinite, so a request that (wrongly) parked would
/// hang and time the test out — the 200 is the proof the injected rule decided it.
#[test]
fn a_session_injected_allow_makes_a_request_proceed_without_parking() {
    use crate::sandbox::control::{
        self, LOG_RING_CAP, LogRing, ManualRules, PendingState, Verdict,
    };
    use crate::testutil::TmpDir;
    use std::os::unix::net::UnixListener;

    let (addr, upstream_ca, up) = spawn_upstream(
        "ask.test",
        b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello",
    );

    // Stand up a real control socket sharing the overlay with the proxy below.
    let data = TmpDir::new();
    std::fs::create_dir_all(control::control_dir(data.path())).unwrap();
    let pid = std::process::id();
    let listener = UnixListener::bind(control::control_socket(data.path(), pid)).unwrap();
    let pending = Arc::new(PendingState::new());
    let manual = Arc::new(ManualRules::new());
    let log = Arc::new(LogRing::new(LOG_RING_CAP));
    let flows = Arc::new(control::FlowRegistry::new());
    {
        let (pending, served_manual, log, flows) =
            (pending.clone(), manual.clone(), log.clone(), flows.clone());
        std::thread::spawn(move || {
            let _ = control::serve(listener, pending, served_manual, log, flows, None);
        });
    }

    // Load an allow for the upstream's exact host:port over the socket, exactly as the CLI does.
    let rule = format!("ask.test:{}", addr.port());
    assert!(matches!(
        control::inject_rule(data.path(), pid, Verdict::Allow, &rule).unwrap(),
        control::InjectOutcome::Loaded
    ));

    let proxy_ca = Arc::new(Ca::ephemeral().unwrap());
    let proxy_ca_der = proxy_ca.ca_cert_der();
    let mut roots = RootCertStore::empty();
    roots.add(upstream_ca).unwrap();
    let upstream_cfg = Arc::new(
        ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth(),
    );
    let ctx = Arc::new(
        ProxyCtx::new(
            proxy_ca,
            EgressPolicy::default().with_default(DefaultAction::Ask),
        )
        .unwrap()
        .with_upstream(upstream_cfg)
        .with_resolver(Box::new(|_| Ok(vec![IpAddr::from([127, 0, 0, 1])])))
        .with_manual(manual),
    );
    let resp = through_proxy(
        ctx,
        proxy_ca_der,
        "ask.test",
        "ask.test",
        addr.port(),
        b"GET / HTTP/1.1\r\nHost: ask.test\r\nConnection: close\r\n\r\n",
    )
    .unwrap();
    up.join().unwrap();
    assert!(
        resp.contains("200 OK") && resp.contains("hello"),
        "a session-injected allow must let the request proceed without parking: {resp:?}"
    );
}

/// Block until exactly one request is parked in `state`, answer it with `verdict`, and return
/// the host it was for — so a test thread can answer a request the proxy thread just parked.
fn answer_when_parked(
    state: &crate::sandbox::control::PendingState,
    verdict: crate::sandbox::control::Verdict,
) -> Option<String> {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    loop {
        if let Some(row) = state.list().first() {
            return state
                .answer_like(row.seq, verdict)
                .map(|(host, _port, _count)| host);
        }
        assert!(
            std::time::Instant::now() < deadline,
            "no request parked within the deadline"
        );
        thread::sleep(std::time::Duration::from_millis(5));
    }
}

/// The isolating teeth for the allow-by-default (denylist) mode. The test upstream is on
/// loopback, which the SSRF guard refuses for any host no rule names — so the *new* behavior
/// shows in the refusal *reason* on an identical unlisted request: under deny-by-default the
/// verdict blocks it (`denied-default`), under allow-by-default the verdict passes it and only
/// the SSRF guard stops it (`ssrf-blocked`). The reason is the proof the default action flipped
/// the verdict. A deny rule still wins under allow-by-default. (An unlisted *public* host being
/// reachable end-to-end is the live `tests/run.rs` smoke — it cannot be a loopback unit test.)
#[test]
fn allow_by_default_passes_the_verdict_while_deny_by_default_blocks_it() {
    // deny-by-default: an unlisted host is blocked AT the verdict — the resolver never runs.
    let deny_proxy_ca = Arc::new(Ca::ephemeral().unwrap());
    let deny_ca = deny_proxy_ca.ca_cert_der();
    let deny_ctx = Arc::new(
        ProxyCtx::new(deny_proxy_ca, EgressPolicy::default())
            .unwrap()
            .with_resolver(Box::new(|_| {
                panic!("resolve must not run for a denied verdict")
            })),
    );
    let resp = through_proxy(
        deny_ctx,
        deny_ca,
        "unlisted.test",
        "unlisted.test",
        8443,
        b"GET / HTTP/1.1\r\nHost: unlisted.test\r\nConnection: close\r\n\r\n",
    )
    .unwrap();
    assert!(
        resp.contains("403") && resp.contains("denied-default"),
        "deny-by-default must block an unlisted host at the verdict: {resp:?}"
    );

    // allow-by-default: the SAME unlisted host passes the verdict (the resolver runs), and is
    // stopped only by the SSRF guard on the loopback address — a different reason.
    let allow_proxy_ca = Arc::new(Ca::ephemeral().unwrap());
    let allow_ca_der = allow_proxy_ca.ca_cert_der();
    let allow_ctx = Arc::new(
        ProxyCtx::new(
            allow_proxy_ca,
            EgressPolicy::default().with_default(DefaultAction::Allow),
        )
        .unwrap()
        .with_resolver(Box::new(|_| Ok(vec![IpAddr::from([127, 0, 0, 1])]))),
    );
    let resp = through_proxy(
        allow_ctx,
        allow_ca_der,
        "unlisted.test",
        "unlisted.test",
        8443,
        b"GET / HTTP/1.1\r\nHost: unlisted.test\r\nConnection: close\r\n\r\n",
    )
    .unwrap();
    assert!(
        resp.contains("403") && resp.contains("ssrf-blocked"),
        "allow-by-default must pass the verdict, then the SSRF guard stops the loopback: {resp:?}"
    );

    // deny still wins under allow-by-default: a denied host is blocked at the verdict.
    let denylist = EgressPolicy::new(vec![], vec![classify("evil.test:*").unwrap()])
        .with_default(DefaultAction::Allow);
    let evil_proxy_ca = Arc::new(Ca::ephemeral().unwrap());
    let evil_ca_der = evil_proxy_ca.ca_cert_der();
    let evil_ctx = Arc::new(
        ProxyCtx::new(evil_proxy_ca, denylist)
            .unwrap()
            .with_resolver(Box::new(|_| {
                panic!("resolve must not run for a denied verdict")
            })),
    );
    let resp = through_proxy(
        evil_ctx,
        evil_ca_der,
        "evil.test",
        "evil.test",
        8443,
        b"GET / HTTP/1.1\r\nHost: evil.test\r\nConnection: close\r\n\r\n",
    )
    .unwrap();
    assert!(
        resp.contains("403") && resp.contains("denied-by-rule"),
        "a deny rule must still win under allow-by-default: {resp:?}"
    );
}

/// Because the proxy terminates TLS it sees the path: a deny carve-out wins over a host allow,
/// so a denied path is refused even though the host is allowed.
#[test]
fn a_path_deny_wins_over_a_host_allow() {
    let proxy_ca = Arc::new(Ca::ephemeral().unwrap());
    let proxy_ca_der = proxy_ca.ca_cert_der();
    let policy = EgressPolicy::new(
        vec![classify("host.test:*").unwrap()],
        vec![classify("host.test:*/secret").unwrap()],
    );
    let ctx = Arc::new(
        ProxyCtx::new(proxy_ca, policy)
            .unwrap()
            .with_resolver(Box::new(|_| {
                panic!("resolve must not run for a denied path")
            })),
    );
    let resp = through_proxy(
        ctx,
        proxy_ca_der,
        "host.test",
        "host.test",
        8443,
        b"GET /secret HTTP/1.1\r\nHost: host.test\r\nConnection: close\r\n\r\n",
    )
    .unwrap();
    assert!(
        resp.contains("403"),
        "a denied path should get 403: {resp:?}"
    );
    assert!(
        resp.contains("denied-by-rule"),
        "a deny-rule refusal must be distinguishable from a default deny: {resp:?}"
    );
}

/// The proxy decrypts the request, so it enforces the method: a verb outside a `{GET,HEAD}`
/// allow is refused as `denied-method` (distinct from a host that is not allowed at all). The
/// resolver panics if reached, so a pass would fail the test — proving the method is what blocks
/// it (a method-blind proxy would match the host kind, resolve, and panic).
#[test]
fn a_method_outside_the_allow_set_is_refused_as_denied_method() {
    let proxy_ca = Arc::new(Ca::ephemeral().unwrap());
    let proxy_ca_der = proxy_ca.ca_cert_der();
    let policy = EgressPolicy::new(vec![classify("{GET,HEAD} host.test:*").unwrap()], vec![]);
    let ctx = Arc::new(
        ProxyCtx::new(proxy_ca, policy)
            .unwrap()
            .with_resolver(Box::new(|_| {
                panic!("resolve must not run for a method-denied request")
            })),
    );
    let resp = through_proxy(
        ctx,
        proxy_ca_der,
        "host.test",
        "host.test",
        8443,
        b"POST /submit HTTP/1.1\r\nHost: host.test\r\nConnection: close\r\n\r\n",
    )
    .unwrap();
    assert!(
        resp.contains("403") && resp.contains("denied-method"),
        "a POST to a GET/HEAD-only host must be refused as denied-method: {resp:?}"
    );
}

/// The MITM must not downgrade transport: an upstream the proxy's root store does not trust is
/// refused with 502, never passed through. The default upstream config (webpki-roots) does not
/// trust the loopback upstream's own CA, so validation fails.
#[test]
fn a_forged_upstream_is_refused_with_502() {
    let (addr, _upstream_ca, _up) = spawn_upstream(
        "host.test",
        b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
    );
    let proxy_ca = Arc::new(Ca::ephemeral().unwrap());
    let proxy_ca_der = proxy_ca.ca_cert_der();
    let log = Arc::new(crate::sandbox::control::LogRing::new(
        crate::sandbox::control::LOG_RING_CAP,
    ));
    // NOTE: no `.with_upstream(...)` — the default webpki-roots config will reject the upstream
    let ctx = Arc::new(
        ProxyCtx::new(proxy_ca, policy(&["host.test:*"]))
            .unwrap()
            .with_log(log.clone())
            .with_resolver(Box::new(|_| Ok(vec![IpAddr::from([127, 0, 0, 1])]))),
    );
    let resp = through_proxy(
        ctx,
        proxy_ca_der,
        "host.test",
        "host.test",
        addr.port(),
        b"GET / HTTP/1.1\r\nHost: host.test\r\nConnection: close\r\n\r\n",
    )
    .unwrap();
    assert!(
        resp.contains("502"),
        "an untrusted upstream must be refused, not downgraded: {resp:?}"
    );
    assert!(
        resp.contains("upstream-cert-rejected"),
        "a cert rejection must be distinguishable from an unreachable host: {resp:?}"
    );
    // Logged as an `error` (the host was allowed; its certificate failed downstream).
    let events = log.snapshot(None, None, false).events;
    assert_eq!(events.len(), 1, "one event: {events:?}");
    assert_eq!(
        events[0].verdict,
        crate::sandbox::control::LogVerdict::Error
    );
    assert_eq!(events[0].reason, "upstream-cert-rejected");
}

/// A name that does not resolve, for an *allowed* host, must be a clean 502 with a
/// `dns-failure` reason — not a dropped connection (which the agent could not tell from a
/// transport glitch). The host is on the allowlist, so the request passes the verdict and
/// reaches the resolve step, where the injected resolver fails.
#[test]
fn a_dns_failure_for_an_allowed_host_is_a_clean_502_not_a_dropped_connection() {
    use crate::sandbox::control::{LOG_RING_CAP, LogRing, LogVerdict};
    let proxy_ca = Arc::new(Ca::ephemeral().unwrap());
    let proxy_ca_der = proxy_ca.ca_cert_der();
    let log = Arc::new(LogRing::new(LOG_RING_CAP));
    let ctx = Arc::new(
        ProxyCtx::new(proxy_ca, policy(&["allowed.test:*"]))
            .unwrap()
            .with_log(log.clone())
            .with_resolver(Box::new(|_| {
                Err(io::Error::other("name resolution failed"))
            })),
    );
    let resp = through_proxy(
        ctx,
        proxy_ca_der,
        "allowed.test",
        "allowed.test",
        8443,
        b"GET /q HTTP/1.1\r\nHost: allowed.test\r\nConnection: close\r\n\r\n",
    )
    .unwrap();
    assert!(
        resp.contains("502") && resp.contains("dns-failure"),
        "a DNS failure for an allowed host must be a clean 502 naming the motif, \
             not a dropped connection: {resp:?}"
    );
    // The log records it as an `error` (allowed but failed downstream), NOT a `deny`/`blocked`
    // (we never refused it) — the distinction the log exists to make.
    let events = log.snapshot(None, None, false).events;
    assert_eq!(events.len(), 1, "one event: {events:?}");
    assert_eq!(events[0].verdict, LogVerdict::Error);
    assert_eq!(events[0].reason, "dns-failure");
    assert_eq!(events[0].host, "allowed.test");
    assert_eq!(events[0].path.as_deref(), Some("/q"));
}

/// CONNECT-host must equal the TLS SNI: a domain-fronting attempt (CONNECT one host, SNI
/// another) is refused before any verdict or connect.
#[test]
fn a_connect_host_sni_mismatch_is_refused() {
    let proxy_ca = Arc::new(Ca::ephemeral().unwrap());
    let proxy_ca_der = proxy_ca.ca_cert_der();
    let ctx = Arc::new(
        ProxyCtx::new(proxy_ca, policy(&["allowed.test:*", "evil.test:*"]))
            .unwrap()
            .with_resolver(Box::new(|_| {
                panic!("resolve must not run on a fronting attempt")
            })),
    );
    // CONNECT to allowed.test, but send SNI evil.test (both are allowed individually — the
    // mismatch itself is what must be rejected)
    let resp = through_proxy(
        ctx,
        proxy_ca_der,
        "allowed.test",
        "evil.test",
        8443,
        b"GET / HTTP/1.1\r\nHost: allowed.test\r\nConnection: close\r\n\r\n",
    )
    .unwrap();
    assert!(
        resp.contains("421"),
        "a CONNECT/SNI mismatch must be refused: {resp:?}"
    );
    assert!(
        resp.contains("host-mismatch"),
        "the refusal must name the domain-fronting motif: {resp:?}"
    );
}

/// The SSRF guard: a host that resolves to a private address is reachable only when the
/// deciding rule names it exactly. A `*.domain` (wildcard) match resolving to loopback is
/// blocked; a metadata address is blocked even for an exact-host rule.
#[test]
fn ssrf_guard_blocks_private_and_metadata_addresses() {
    // wildcard match → loopback → blocked
    let proxy_ca = Arc::new(Ca::ephemeral().unwrap());
    let proxy_ca_der = proxy_ca.ca_cert_der();
    let ctx = Arc::new(
        ProxyCtx::new(proxy_ca, policy(&["*.corp.test:*"]))
            .unwrap()
            .with_resolver(Box::new(|_| Ok(vec![IpAddr::from([127, 0, 0, 1])]))),
    );
    let resp = through_proxy(
        ctx,
        proxy_ca_der,
        "internal.corp.test",
        "internal.corp.test",
        8443,
        b"GET / HTTP/1.1\r\nHost: internal.corp.test\r\nConnection: close\r\n\r\n",
    )
    .unwrap();
    assert!(
        resp.contains("403") && resp.contains("ssrf-blocked"),
        "a wildcard-matched private target is an SSRF wildcard and must be blocked: {resp:?}"
    );

    // exact host, but the address is cloud metadata → blocked even though explicit
    let proxy_ca = Arc::new(Ca::ephemeral().unwrap());
    let proxy_ca_der = proxy_ca.ca_cert_der();
    let ctx = Arc::new(
        ProxyCtx::new(proxy_ca, policy(&["meta.test:*"]))
            .unwrap()
            .with_resolver(Box::new(|_| Ok(vec![IpAddr::from([169, 254, 169, 254])]))),
    );
    let resp = through_proxy(
        ctx,
        proxy_ca_der,
        "meta.test",
        "meta.test",
        8443,
        b"GET / HTTP/1.1\r\nHost: meta.test\r\nConnection: close\r\n\r\n",
    )
    .unwrap();
    assert!(
        resp.contains("403") && resp.contains("ssrf-blocked"),
        "the cloud-metadata address must be blocked even for an exact host: {resp:?}"
    );
}

/// The recorded invariant: the proxy's live verdict agrees with what `sbx test net` predicts,
/// because both go through the same `EgressPolicy::explain` on the same canonicalized request.
#[test]
fn proxy_verdict_matches_the_tester() {
    let p = EgressPolicy::new(
        vec![classify("host.test:*").unwrap()],
        vec![classify("host.test:*/secret").unwrap()],
    );
    // what `sbx test net` would report (via parse_url_target + explain) for these URLs
    let denied = allowlist::parse_url_target("https://host.test:8443/secret").unwrap();
    assert!(
        !p.permits(&denied.0, denied.1, &denied.2),
        "tester predicts DENIED"
    );
    let allowed = allowlist::parse_url_target("https://host.test:8443/public").unwrap();
    assert!(
        p.permits(&allowed.0, allowed.1, &allowed.2),
        "tester predicts ALLOWED"
    );

    // the proxy must enforce the same: /secret refused, /public reaches the upstream
    let (addr, upstream_ca, up) = spawn_upstream(
        "host.test",
        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
    );
    let mut roots = RootCertStore::empty();
    roots.add(upstream_ca).unwrap();
    let upstream_cfg = Arc::new(
        ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth(),
    );
    let proxy_ca = Arc::new(Ca::ephemeral().unwrap());
    let proxy_ca_der = proxy_ca.ca_cert_der();
    let ctx = Arc::new(
        ProxyCtx::new(proxy_ca, p)
            .unwrap()
            .with_upstream(upstream_cfg)
            .with_resolver(Box::new(|_| Ok(vec![IpAddr::from([127, 0, 0, 1])]))),
    );

    let denied_resp = through_proxy(
        ctx.clone(),
        proxy_ca_der.clone(),
        "host.test",
        "host.test",
        addr.port(),
        b"GET /secret HTTP/1.1\r\nHost: host.test\r\nConnection: close\r\n\r\n",
    )
    .unwrap();
    assert!(
        denied_resp.contains("403"),
        "proxy must deny /secret: {denied_resp:?}"
    );

    let allowed_resp = through_proxy(
        ctx,
        proxy_ca_der,
        "host.test",
        "host.test",
        addr.port(),
        b"GET /public HTTP/1.1\r\nHost: host.test\r\nConnection: close\r\n\r\n",
    )
    .unwrap();
    up.join().unwrap();
    assert!(
        allowed_resp.contains("200"),
        "proxy must allow /public: {allowed_resp:?}"
    );
}

/// The built-in self-equip allow-set is unioned into every policy (even an empty one) so an
/// untrusted project can still self-equip, and is well-formed.
#[test]
fn builtin_allow_set_is_unioned_regardless_of_trust() {
    let cache = builtin_allow_rules();
    assert!(!cache.is_empty());
    // unioning into an empty (untrusted) policy still permits the cache host
    let p = union_with_builtin(EgressPolicy::default());
    assert!(p.permits("cache.nixos.org", 443, "/nar/abc"));
    assert!(
        p.permits("channels.nixos.org", 443, "/"),
        "*.nixos.org covers channels"
    );
    // a host not in the cache set is still denied by default
    assert!(!p.permits("example.com", 443, "/"));
}

/// With reuse off, the proxy must force `Connection: close` on the request it forwards even when
/// the client sent no `Connection` header: nothing is going to come back for that connection, so
/// leaving it open would hold an upstream socket for a launch that will never use it. The policy
/// says so explicitly here, since reuse is otherwise the default. The capturing upstream reports
/// the head it received.
#[test]
fn the_forwarded_request_forces_connection_close() {
    let (addr, upstream_ca, rx) = spawn_upstream_capturing(
        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
    );
    let mut roots = RootCertStore::empty();
    roots.add(upstream_ca).unwrap();
    let upstream_cfg = Arc::new(
        ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth(),
    );
    let proxy_ca = Arc::new(Ca::ephemeral().unwrap());
    let proxy_ca_der = proxy_ca.ca_cert_der();
    let ctx = Arc::new(
        ProxyCtx::new(proxy_ca, policy(&["host.test:*"]).with_pool(false))
            .unwrap()
            .with_upstream(upstream_cfg)
            .with_resolver(Box::new(|_| Ok(vec![IpAddr::from([127, 0, 0, 1])]))),
    );
    // the client sends NO Connection header
    let resp = through_proxy(
        ctx,
        proxy_ca_der,
        "host.test",
        "host.test",
        addr.port(),
        b"GET / HTTP/1.1\r\nHost: host.test\r\n\r\n",
    )
    .unwrap();
    let upstream_head = rx
        .recv_timeout(Duration::from_secs(5))
        .expect("the upstream received a request");
    assert!(
        resp.contains("200"),
        "the response was not streamed back: {resp:?}"
    );
    assert!(
        upstream_head
            .to_ascii_lowercase()
            .contains("connection: close"),
        "the proxy must force Connection: close upstream: {upstream_head:?}"
    );
}

/// A target that carries a URL in its query (`/page?next=https://…`) is origin-form, not
/// absolute-form, so it must be allowed — the absolute-form check is on the target's start.
#[test]
fn a_url_in_the_query_is_not_absolute_form() {
    let (addr, upstream_ca, up) = spawn_upstream(
        "host.test",
        b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
    );
    let mut roots = RootCertStore::empty();
    roots.add(upstream_ca).unwrap();
    let upstream_cfg = Arc::new(
        ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth(),
    );
    let proxy_ca = Arc::new(Ca::ephemeral().unwrap());
    let proxy_ca_der = proxy_ca.ca_cert_der();
    let ctx = Arc::new(
        ProxyCtx::new(proxy_ca, policy(&["host.test:*"]))
            .unwrap()
            .with_upstream(upstream_cfg)
            .with_resolver(Box::new(|_| Ok(vec![IpAddr::from([127, 0, 0, 1])]))),
    );
    let resp = through_proxy(
        ctx,
        proxy_ca_der,
        "host.test",
        "host.test",
        addr.port(),
        b"GET /page?redirect=https://evil.test/x HTTP/1.1\r\nHost: host.test\r\n\r\n",
    )
    .unwrap();
    up.join().unwrap();
    assert!(
        resp.contains("200"),
        "a URL in the query must not be read as absolute-form: {resp:?}"
    );
}

/// A header injection scoped to `to` (in allowlist-entry syntax), setting `header` to `value`.
fn injection(to: &str, header: &str, value: &str) -> HeaderInjection {
    HeaderInjection::fixed(classify(to).unwrap(), header.to_string(), value.to_string())
}

/// Drive one request through a proxy that allows `allow` and carries `injections`, to a
/// loopback capturing upstream. Returns the client-visible response and the request head the
/// upstream received — so a test can assert exactly what was forwarded (which headers sbx
/// injected, and which client copies it stripped).
fn run_with_injections(
    allow: &[&str],
    injections: Vec<HeaderInjection>,
    connect_host: &str,
    request: &[u8],
) -> (String, String) {
    let (addr, upstream_ca, rx) = spawn_upstream_capturing(
        b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
    );
    let mut roots = RootCertStore::empty();
    roots.add(upstream_ca).unwrap();
    let upstream_cfg = Arc::new(
        ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth(),
    );
    let proxy_ca = Arc::new(Ca::ephemeral().unwrap());
    let proxy_ca_der = proxy_ca.ca_cert_der();
    let ctx = Arc::new(
        ProxyCtx::new(proxy_ca, policy(allow))
            .unwrap()
            .with_upstream(upstream_cfg)
            .with_resolver(Box::new(|_| Ok(vec![IpAddr::from([127, 0, 0, 1])])))
            .with_injections(injections),
    );
    let resp = through_proxy(
        ctx,
        proxy_ca_der,
        connect_host,
        connect_host,
        addr.port(),
        request,
    )
    .unwrap();
    let head = rx.recv_timeout(Duration::from_secs(5)).unwrap_or_default();
    (resp, head)
}

/// The headline: an allowed request to the scoped host gets sbx's credential, and the
/// agent's own copy of the same header is stripped — the injected value is the only one the
/// upstream sees, even though the cage never held the secret.
#[test]
fn an_allowed_request_gets_the_injected_header_replacing_the_clients_copy() {
    let (resp, head) = run_with_injections(
        &["host.test:*"],
        vec![injection(
            "host.test:*",
            "Authorization",
            "Bearer sbx-secret",
        )],
        "host.test",
        b"GET / HTTP/1.1\r\nHost: host.test\r\nauthorization: Bearer attacker\r\n\r\n",
    );
    assert!(resp.contains("200"), "the request was proxied: {resp:?}");
    let auth: Vec<&str> = head
        .lines()
        .filter(|l| l.to_ascii_lowercase().starts_with("authorization:"))
        .collect();
    assert_eq!(
        auth.len(),
        1,
        "exactly one Authorization header reaches the upstream: {head:?}"
    );
    assert!(
        auth[0].contains("sbx-secret"),
        "sbx's value must win: {head:?}"
    );
    assert!(
        !head.contains("attacker"),
        "the client's copy must be stripped: {head:?}"
    );
}

/// An injection is bound to its host: a request to a *different* allowed host never receives
/// it, so a credential cannot ride along to an unintended destination.
#[test]
fn an_injection_is_scoped_to_its_host() {
    let (resp, head) = run_with_injections(
        &["secret.test:*", "other.test:*"],
        vec![injection(
            "secret.test:*",
            "Authorization",
            "Bearer sbx-secret",
        )],
        "other.test",
        b"GET / HTTP/1.1\r\nHost: other.test\r\n\r\n",
    );
    assert!(resp.contains("200"));
    assert!(
        !head.to_ascii_lowercase().contains("authorization"),
        "a host outside the injection scope must get no credential: {head:?}"
    );
}

/// Because the proxy terminates TLS it can scope an injection by path: only the declared path
/// receives the header, a sibling path on the same host does not.
#[test]
fn an_injection_can_be_scoped_to_a_path() {
    let injs = || {
        vec![injection(
            "host.test:*/api",
            "Authorization",
            "Bearer sbx-secret",
        )]
    };
    let (resp, head) = run_with_injections(
        &["host.test:*"],
        injs(),
        "host.test",
        b"GET /api HTTP/1.1\r\nHost: host.test\r\n\r\n",
    );
    assert!(resp.contains("200"));
    assert!(
        head.to_ascii_lowercase()
            .contains("authorization: bearer sbx-secret"),
        "the scoped path must be injected: {head:?}"
    );
    let (resp2, head2) = run_with_injections(
        &["host.test:*"],
        injs(),
        "host.test",
        b"GET /public HTTP/1.1\r\nHost: host.test\r\n\r\n",
    );
    assert!(resp2.contains("200"));
    assert!(
        !head2.to_ascii_lowercase().contains("authorization"),
        "a path outside the injection scope must get no credential: {head2:?}"
    );
}

#[test]
fn header_name_eq_is_case_and_underscore_insensitive() {
    assert!(header_name_eq("Authorization", "authorization"));
    assert!(header_name_eq("X_API_KEY", "x-api-key"));
    assert!(header_name_eq("X-Api-Key", "x_api_key"));
    assert!(!header_name_eq("Authorization", "X-Auth"));
}

/// Strip-and-replace at the byte level: every spelling of an injected header (case, `_`/`-`,
/// duplicates) is removed and sbx's value appended exactly once, while unrelated headers and
/// the forced `Connection: close` survive.
#[test]
fn reserialize_strips_all_spellings_of_an_injected_header() {
    let head = parse_head(
        b"GET / HTTP/1.1\r\nHost: h.test\r\nAuthorization: client\r\nAUTHORIZATION: dup\r\n\
              x_api_key: sneaky\r\nAccept: text/html\r\n\r\n",
    )
    .unwrap();
    let out = reserialize_request(
        &head,
        &[
            ("Authorization".to_string(), "Bearer sbx".to_string()),
            ("X-Api-Key".to_string(), "K".to_string()),
        ],
        None,
        false,
    );
    let s = String::from_utf8(out).unwrap();
    assert_eq!(
        s.matches("Authorization: Bearer sbx").count(),
        1,
        "sbx's Authorization appears exactly once: {s:?}"
    );
    assert!(s.contains("X-Api-Key: K"));
    assert!(
        !s.contains("client") && !s.contains("dup") && !s.contains("sneaky"),
        "every client spelling of an injected header is stripped: {s:?}"
    );
    assert!(
        s.contains("Accept: text/html"),
        "an unrelated header survives"
    );
    assert!(
        s.contains("Connection: close"),
        "Connection: close is forced"
    );
}

/// A deliberately naive substring scan, kept for the tests alone.
///
/// The production path searches with a real substring searcher; asserting against a separate,
/// obviously-correct implementation means a test cannot inherit a bug from the code it checks.
fn contains_subslice(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || needle.len() > haystack.len() {
        return false;
    }
    haystack.windows(needle.len()).any(|w| w == needle)
}

#[test]
fn contains_subslice_matches_a_byte_run() {
    assert!(contains_subslice(b"hello world", b"o wo"));
    assert!(contains_subslice(b"abc", b"abc"));
    assert!(
        !contains_subslice(b"abc", b"abcd"),
        "needle longer than haystack"
    );
    assert!(
        !contains_subslice(b"abc", b""),
        "an empty needle never matches"
    );
    assert!(!contains_subslice(b"hello", b"xyz"));
}

#[test]
fn secret_needle_debug_is_redacted() {
    let n = SecretNeedle::named("test-secret", b"topsecretvalue".to_vec());
    let d = format!("{n:?}");
    assert!(
        !d.contains("topsecretvalue"),
        "the needle value must never appear in Debug: {d}"
    );
    assert!(d.contains("redacted"), "Debug should mark it redacted: {d}");
}

/// Drive one request through a proxy that allows `allow` and redacts `needles`, with a resolver
/// that must NOT run — an outbound-secret refusal fires before any verdict, resolve, or connect.
fn run_with_redactions(allow: &[&str], needles: &[&str], request: &[u8]) -> String {
    let proxy_ca = Arc::new(Ca::ephemeral().unwrap());
    let proxy_ca_der = proxy_ca.ca_cert_der();
    let ctx = Arc::new(
        ProxyCtx::new(proxy_ca, policy(allow))
            .unwrap()
            .with_resolver(Box::new(|_| {
                panic!("an exfil attempt must be refused before any resolve/connect")
            }))
            .with_redactions(
                needles
                    .iter()
                    .map(|n| SecretNeedle::named("test-secret", n.as_bytes().to_vec()))
                    .collect(),
            ),
    );
    through_proxy(ctx, proxy_ca_der, "host.test", "host.test", 8443, request).unwrap()
}

/// A secret value echoed back into an outbound *header* is refused (block, not strip), and the
/// upstream is never contacted (the resolver panics if reached).
#[test]
fn an_outbound_secret_in_a_header_is_refused() {
    let resp = run_with_redactions(
        &["host.test:*"],
        &["s3cret-reflected-value"],
        b"GET / HTTP/1.1\r\nHost: host.test\r\nX-Leak: s3cret-reflected-value\r\n\r\n",
    );
    assert!(
        resp.contains("403") && resp.contains("outbound-secret"),
        "a secret in an outbound header must be refused: {resp:?}"
    );
}

/// A secret value smuggled into the request *URL* (query) is caught too — the scan covers the
/// whole head, request line included.
#[test]
fn an_outbound_secret_in_the_url_is_refused() {
    let resp = run_with_redactions(
        &["host.test:*"],
        &["s3cret-reflected-value"],
        b"GET /steal?x=s3cret-reflected-value HTTP/1.1\r\nHost: host.test\r\n\r\n",
    );
    assert!(
        resp.contains("403") && resp.contains("outbound-secret"),
        "a secret in the request URL must be refused: {resp:?}"
    );
}

/// The stats classification: each refusal site records exactly the bucket its column means —
/// `deny` for a rule / `ask` decision, `blocked` for a security guard. A mis-bucketed guard (an
/// SSRF counted as a deny, say) would pass every other green test, so each of the seven refusal
/// sites is pinned here. The `allow` site (counted only after a real upstream connects) is pinned
/// in the happy-path test and the live allowlist e2e. The counter is keyed on the CONNECT host.
#[test]
fn each_refusal_site_records_its_stat_bucket_and_emits_a_log_event() {
    use crate::allowlist::DefaultAction;
    use crate::sandbox::control::{LOG_RING_CAP, LogRing, LogVerdict};
    use crate::sandbox::egress_stats::{Counts, EgressStats};

    let dir = TmpDir::new();
    // One shared event ring across every block: because `outcome` folds the stat and the log
    // push into one call, proving each site records the right *bucket* AND emits the right
    // *event* proves the two can never drift — a missed site is a missed pair. The blocks run
    // sequentially, so the ring's events are a deterministic, ordered transcript asserted at the
    // end.
    let log = Arc::new(LogRing::new(LOG_RING_CAP));
    let seq = std::sync::atomic::AtomicU32::new(0);
    let fresh = || {
        let i = seq.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        // The file lives in the temp dir; the assertions read the in-memory snapshot.
        Arc::new(EgressStats::new(
            dir.join(&format!("stats-{i}")),
            "/t".into(),
            None,
        ))
    };
    // The recorded count for `host` (a missing host is the zero counts).
    let count =
        |s: &Arc<EgressStats>, host: &str| s.snapshot().get(host).copied().unwrap_or_default();

    // denied-default → deny. No allow rule matches; the resolver must never run.
    {
        let s = fresh();
        let ca = Arc::new(Ca::ephemeral().unwrap());
        let der = ca.ca_cert_der();
        let ctx = Arc::new(
            ProxyCtx::new(ca, policy(&["allowed.test:*"]))
                .unwrap()
                .with_stats(s.clone())
                .with_log(log.clone())
                .with_resolver(Box::new(|_| {
                    panic!("resolve must not run for a denied host")
                })),
        );
        let resp = through_proxy(
            ctx,
            der,
            "denied.test",
            "denied.test",
            8443,
            b"GET / HTTP/1.1\r\nHost: denied.test\r\nConnection: close\r\n\r\n",
        )
        .unwrap();
        assert!(resp.contains("denied-default"), "{resp:?}");
        assert_eq!(
            count(&s, "denied.test"),
            Counts {
                deny: 1,
                ..Default::default()
            }
        );
    }

    // denied-by-rule → deny. A deny rule matches before any resolve.
    {
        let s = fresh();
        let ca = Arc::new(Ca::ephemeral().unwrap());
        let der = ca.ca_cert_der();
        let denylist = EgressPolicy::new(vec![], vec![classify("evil.test:*").unwrap()])
            .with_default(DefaultAction::Allow);
        let ctx = Arc::new(
            ProxyCtx::new(ca, denylist)
                .unwrap()
                .with_stats(s.clone())
                .with_log(log.clone())
                .with_resolver(Box::new(|_| {
                    panic!("resolve must not run for a deny-rule host")
                })),
        );
        let resp = through_proxy(
            ctx,
            der,
            "evil.test",
            "evil.test",
            8443,
            b"GET / HTTP/1.1\r\nHost: evil.test\r\nConnection: close\r\n\r\n",
        )
        .unwrap();
        assert!(resp.contains("denied-by-rule"), "{resp:?}");
        assert_eq!(
            count(&s, "evil.test"),
            Counts {
                deny: 1,
                ..Default::default()
            }
        );
    }

    // asked-denied (an `ask` park that times out with no answer) → deny. A short timeout and no
    // answerer thread makes the park deny by timeout — the still-reachable `asked-denied` path (a
    // remembered/`--session` deny now folds into the effective policy and surfaces as
    // `denied-by-rule`, tested above).
    {
        let s = fresh();
        let ca = Arc::new(Ca::ephemeral().unwrap());
        let der = ca.ca_cert_der();
        let ctx = Arc::new(
            ProxyCtx::new(
                ca,
                EgressPolicy::default()
                    .with_default(DefaultAction::Ask)
                    .with_ask_timeout(Some(std::time::Duration::from_millis(50))),
            )
            .unwrap()
            .with_stats(s.clone())
            .with_log(log.clone())
            .with_resolver(Box::new(|_| {
                panic!("resolve must not run for a timed-out ask")
            })),
        );
        let resp = through_proxy(
            ctx,
            der,
            "blocked.test",
            "blocked.test",
            443,
            b"GET / HTTP/1.1\r\nHost: blocked.test\r\nConnection: close\r\n\r\n",
        )
        .unwrap();
        assert!(resp.contains("asked-denied"), "{resp:?}");
        assert_eq!(
            count(&s, "blocked.test"),
            Counts {
                deny: 1,
                ..Default::default()
            }
        );
    }

    // sni-mismatch (domain-fronting) → blocked.
    {
        let s = fresh();
        let ca = Arc::new(Ca::ephemeral().unwrap());
        let der = ca.ca_cert_der();
        let ctx = Arc::new(
            ProxyCtx::new(ca, policy(&["allowed.test:*", "evil.test:*"]))
                .unwrap()
                .with_stats(s.clone())
                .with_log(log.clone())
                .with_resolver(Box::new(|_| {
                    panic!("resolve must not run on a fronting attempt")
                })),
        );
        let resp = through_proxy(
            ctx,
            der,
            "allowed.test",
            "evil.test",
            8443,
            b"GET / HTTP/1.1\r\nHost: allowed.test\r\nConnection: close\r\n\r\n",
        )
        .unwrap();
        assert!(resp.contains("host-mismatch"), "{resp:?}");
        assert_eq!(
            count(&s, "allowed.test"),
            Counts {
                blocked: 1,
                ..Default::default()
            }
        );
    }

    // host-header-mismatch (SNI matches, decrypted Host disagrees) → blocked.
    {
        let s = fresh();
        let ca = Arc::new(Ca::ephemeral().unwrap());
        let der = ca.ca_cert_der();
        let ctx = Arc::new(
            ProxyCtx::new(ca, policy(&["allowed.test:*"]))
                .unwrap()
                .with_stats(s.clone())
                .with_log(log.clone())
                .with_resolver(Box::new(|_| {
                    panic!("resolve must not run on a host mismatch")
                })),
        );
        let resp = through_proxy(
            ctx,
            der,
            "allowed.test",
            "allowed.test",
            8443,
            b"GET / HTTP/1.1\r\nHost: other.test\r\nConnection: close\r\n\r\n",
        )
        .unwrap();
        assert!(resp.contains("host-mismatch"), "{resp:?}");
        assert_eq!(
            count(&s, "allowed.test"),
            Counts {
                blocked: 1,
                ..Default::default()
            }
        );
    }

    // outbound-secret (a configured value echoed in the head) → blocked.
    {
        let s = fresh();
        let ca = Arc::new(Ca::ephemeral().unwrap());
        let der = ca.ca_cert_der();
        let ctx = Arc::new(
            ProxyCtx::new(ca, policy(&["host.test:*"]))
                .unwrap()
                .with_stats(s.clone())
                .with_log(log.clone())
                .with_redactions(vec![SecretNeedle::named(
                    "test-secret",
                    b"s3cret-reflected-value".to_vec(),
                )])
                .with_resolver(Box::new(|_| {
                    panic!("resolve must not run on a secret leak")
                })),
        );
        let resp = through_proxy(
            ctx,
            der,
            "host.test",
            "host.test",
            8443,
            b"GET / HTTP/1.1\r\nHost: host.test\r\nX-Leak: s3cret-reflected-value\r\n\r\n",
        )
        .unwrap();
        assert!(resp.contains("outbound-secret"), "{resp:?}");
        assert_eq!(
            count(&s, "host.test"),
            Counts {
                blocked: 1,
                ..Default::default()
            }
        );
    }

    // ssrf-blocked (an allowed host resolving to a metadata address) → blocked.
    {
        let s = fresh();
        let ca = Arc::new(Ca::ephemeral().unwrap());
        let der = ca.ca_cert_der();
        let ctx = Arc::new(
            ProxyCtx::new(ca, policy(&["host.test:*"]))
                .unwrap()
                .with_stats(s.clone())
                .with_log(log.clone())
                // the cloud metadata address — always refused, even for an exact-host rule
                .with_resolver(Box::new(|_| Ok(vec![IpAddr::from([169, 254, 169, 254])]))),
        );
        let resp = through_proxy(
            ctx,
            der,
            "host.test",
            "host.test",
            8443,
            b"GET / HTTP/1.1\r\nHost: host.test\r\nConnection: close\r\n\r\n",
        )
        .unwrap();
        assert!(resp.contains("ssrf-blocked"), "{resp:?}");
        assert_eq!(
            count(&s, "host.test"),
            Counts {
                blocked: 1,
                ..Default::default()
            }
        );
    }

    // signer-body-too-large (a declared body above what sbx holds, for a signer that asked to be
    // told a digest of it) → blocked. Refused from the head, so the client sends none of the body
    // it declared and no upstream is opened.
    {
        let s = fresh();
        let ca = Arc::new(Ca::ephemeral().unwrap());
        let der = ca.ca_cert_der();
        let ctx = Arc::new(
            ProxyCtx::new(ca, policy(&["host.test:*"]))
                .unwrap()
                .with_stats(s.clone())
                .with_log(log.clone())
                .with_injections(vec![digesting_injection()])
                .with_resolver(Box::new(|_| Ok(vec![IpAddr::from([127, 0, 0, 1])]))),
        );
        let resp = through_proxy(
            ctx,
            der,
            "host.test",
            "host.test",
            8443,
            format!(
                "POST / HTTP/1.1\r\nHost: host.test\r\nContent-Length: {}\r\n\r\n",
                CHUNKED_REQUEST_CAP + 1
            )
            .as_bytes(),
        )
        .unwrap();
        assert!(
            resp.contains("413") && resp.contains("signer-body-too-large"),
            "{resp:?}"
        );
        assert_eq!(
            count(&s, "host.test"),
            Counts {
                blocked: 1,
                ..Default::default()
            }
        );
    }

    // The shared ring is the ordered transcript of the eight blocks above: each site emitted
    // exactly one event with the host, verdict, and reason category it recorded. A mis-emitted
    // or missing event here is a log/stats drift (or a missed site), even though the per-block
    // stat assertions passed.
    let events = log.snapshot(None, None, false).events;
    let seen: Vec<(String, LogVerdict, String)> = events
        .iter()
        .map(|e| (e.host.clone(), e.verdict, e.reason.clone()))
        .collect();
    let expected = [
        ("denied.test", LogVerdict::Deny, "denied-default"),
        ("evil.test", LogVerdict::Deny, "denied-by-rule"),
        ("blocked.test", LogVerdict::Deny, "asked-denied"),
        ("allowed.test", LogVerdict::Blocked, "host-mismatch"),
        ("allowed.test", LogVerdict::Blocked, "host-mismatch"),
        ("host.test", LogVerdict::Blocked, "outbound-secret"),
        ("host.test", LogVerdict::Blocked, "ssrf-blocked"),
        ("host.test", LogVerdict::Blocked, "signer-body-too-large"),
    ];
    assert_eq!(
        seen.len(),
        expected.len(),
        "one log event per decision site: {seen:?}"
    );
    for (i, (host, verdict, reason)) in expected.iter().enumerate() {
        assert_eq!(
            (seen[i].0.as_str(), seen[i].1, seen[i].2.as_str()),
            (*host, *verdict, *reason),
            "event {i} mismatched"
        );
    }
}

/// Like [`run_with_injections`] but also carrying redaction needles, to a capturing upstream —
/// so a test can assert a clean request still reaches the upstream (the tripwire scans only the
/// client head, never sbx's own injection).
fn run_with_injections_and_redactions(
    injections: Vec<HeaderInjection>,
    needles: &[&str],
    request: &[u8],
) -> (String, String) {
    let (addr, upstream_ca, rx) = spawn_upstream_capturing(
        b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
    );
    let mut roots = RootCertStore::empty();
    roots.add(upstream_ca).unwrap();
    let upstream_cfg = Arc::new(
        ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth(),
    );
    let proxy_ca = Arc::new(Ca::ephemeral().unwrap());
    let proxy_ca_der = proxy_ca.ca_cert_der();
    let ctx = Arc::new(
        ProxyCtx::new(proxy_ca, policy(&["host.test:*"]))
            .unwrap()
            .with_upstream(upstream_cfg)
            .with_resolver(Box::new(|_| Ok(vec![IpAddr::from([127, 0, 0, 1])])))
            .with_injections(injections)
            .with_redactions(
                needles
                    .iter()
                    .map(|n| SecretNeedle::named("test-secret", n.as_bytes().to_vec()))
                    .collect(),
            ),
    );
    let resp = through_proxy(
        ctx,
        proxy_ca_der,
        "host.test",
        "host.test",
        addr.port(),
        request,
    )
    .unwrap();
    let head = rx.recv_timeout(Duration::from_secs(5)).unwrap_or_default();
    (resp, head)
}

/// Drive one request through the proxy against an upstream that answers `status_line`, with a
/// refresher wired, and report the credential state afterwards. The refresher counts its calls, so
/// a test can tell "was not consulted" from "was consulted and changed nothing".
fn run_with_refresh(
    response: &'static [u8],
    injections: Vec<HeaderInjection>,
    request: &[u8],
) -> (Arc<Credentials>, Arc<std::sync::atomic::AtomicUsize>) {
    let (addr, upstream_ca, _rx) = spawn_upstream_capturing(response);
    let mut roots = RootCertStore::empty();
    roots.add(upstream_ca).unwrap();
    let upstream_cfg = Arc::new(
        ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth(),
    );
    let proxy_ca = Arc::new(Ca::ephemeral().unwrap());
    let proxy_ca_der = proxy_ca.ca_cert_der();

    let credentials = Arc::new(Credentials::new(
        injections,
        Vec::new(),
        crate::sandbox::redact::MIN_LEN_DEFAULT,
    ));
    let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let seen = calls.clone();
    let refresh = Arc::new(CredentialRefresh::new(
        credentials.clone(),
        Box::new(move |_| {
            seen.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok((
                vec![injection(
                    "host.test:*",
                    "Authorization",
                    "Bearer refreshed",
                )],
                Vec::new(),
            ))
        }),
    ));

    let ctx = Arc::new(
        ProxyCtx::new(proxy_ca, policy(&["host.test:*"]))
            .unwrap()
            .with_upstream(upstream_cfg)
            .with_resolver(Box::new(|_| Ok(vec![IpAddr::from([127, 0, 0, 1])])))
            .with_shared_credentials(credentials.clone())
            .with_refresh(refresh),
    );
    let _ = through_proxy(
        ctx,
        proxy_ca_der,
        "host.test",
        "host.test",
        addr.port(),
        request,
    );
    (credentials, calls)
}

/// What observing buys, end to end. A token the cage obtained by its own sign-in belongs to no
/// declaration, so nothing used to refuse it on the way out. Once the proxy has seen the cage send
/// it to an allowed host, re-sending it anywhere is refused like a declared secret's — the same
/// tripwire, now covering a credential nobody configured.
///
/// The request that *taught* sbx the value is not itself refused: observing happens after the
/// outbound scan, so a credential can never trip on its own first use.
#[test]
fn a_credential_the_cage_sent_itself_becomes_a_tripwire_for_the_next_request() {
    let (addr, upstream_ca, _rx) = spawn_upstream_capturing(
        b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
    );
    let mut roots = RootCertStore::empty();
    roots.add(upstream_ca).unwrap();
    let upstream_cfg = Arc::new(
        ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth(),
    );
    let proxy_ca = Arc::new(Ca::ephemeral().unwrap());
    let proxy_ca_der = proxy_ca.ca_cert_der();
    let ctx = Arc::new(
        ProxyCtx::new(proxy_ca, policy(&["host.test:*"]))
            .unwrap()
            .with_upstream(upstream_cfg)
            .with_resolver(Box::new(|_| Ok(vec![IpAddr::from([127, 0, 0, 1])]))),
    );

    // The cage authenticates with a credential of its own. Nothing is declared, so this is allowed
    // and proxied — and it is where sbx learns the value.
    let first = through_proxy(
        ctx.clone(),
        proxy_ca_der.clone(),
        "host.test",
        "host.test",
        addr.port(),
        b"GET / HTTP/1.1\r\nHost: host.test\r\nAuthorization: Bearer acquired-token-0123456789\r\n\r\n",
    )
    .unwrap();
    assert!(
        first.contains("200"),
        "the request that teaches the value must not be refused: {first:?}"
    );

    // Re-sending that same value, now in a query string, is exfiltration of a credential the cage
    // holds — and is refused exactly as a declared secret's would be.
    let second = through_proxy(
        ctx,
        proxy_ca_der,
        "host.test",
        "host.test",
        addr.port(),
        b"GET /?leak=acquired-token-0123456789 HTTP/1.1\r\nHost: host.test\r\n\r\n",
    )
    .unwrap();
    assert!(
        second.contains("403") && second.contains("outbound-secret"),
        "an observed credential must be refused on the way out: {second:?}"
    );
}

/// The mechanism end to end: an injection target answering `401` says the credential it was just
/// given is no longer accepted, so the proxy re-resolves and the *next* request will carry the new
/// value. The refused request itself is already lost — its head reached the cage before the status
/// was read — which is why this asserts on the state, not on the response.
#[test]
fn a_401_from_an_injection_target_re_resolves_the_credential() {
    let (credentials, calls) = run_with_refresh(
        b"HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        vec![injection("host.test:*", "Authorization", "Bearer stale")],
        b"GET / HTTP/1.1\r\nHost: host.test\r\n\r\n",
    );
    assert_eq!(
        calls.load(std::sync::atomic::Ordering::SeqCst),
        1,
        "the refusal must consult the source exactly once"
    );
    assert_eq!(
        credentials.snapshot().injections[0].value(),
        "Bearer refreshed",
        "the next request carries the re-resolved value"
    );
}

/// A `200` is not a signal about the credential. Re-resolving on anything but a refusal would spend
/// a resolver run — a bwrap spawn for a plugin source — on every successful request.
#[test]
fn a_successful_response_never_re_resolves() {
    let (credentials, calls) = run_with_refresh(
        b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        vec![injection("host.test:*", "Authorization", "Bearer stale")],
        b"GET / HTTP/1.1\r\nHost: host.test\r\n\r\n",
    );
    assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 0);
    assert_eq!(credentials.snapshot().injections[0].value(), "Bearer stale");
}

/// A `401` from a host carrying no injection says nothing about our credentials. Acting on it would
/// let any allowed host — one the agent chose — drive sbx's resolver at will.
#[test]
fn a_401_from_a_host_we_inject_nothing_into_is_not_a_refresh_signal() {
    let (credentials, calls) = run_with_refresh(
        b"HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        vec![injection("other.test:*", "Authorization", "Bearer stale")],
        b"GET / HTTP/1.1\r\nHost: host.test\r\n\r\n",
    );
    assert_eq!(
        calls.load(std::sync::atomic::Ordering::SeqCst),
        0,
        "an unrelated refusal must not reach the resolver"
    );
    assert_eq!(credentials.snapshot().injections[0].value(), "Bearer stale");
}

/// The scan is on the pre-injection client head, so sbx's own injected credential — whose value
/// equals a redaction needle — never self-trips: a clean client request is still proxied and
/// receives the injection.
#[test]
fn the_redaction_does_not_self_trip_on_the_injected_value() {
    let (resp, head) = run_with_injections_and_redactions(
        vec![injection(
            "host.test:*",
            "Authorization",
            "Bearer sbx-secret-value",
        )],
        &["sbx-secret-value"],
        b"GET / HTTP/1.1\r\nHost: host.test\r\n\r\n",
    );
    assert!(
        resp.contains("200"),
        "a clean request must still be proxied — the scan precedes injection: {resp:?}"
    );
    assert!(
        head.to_ascii_lowercase()
            .contains("authorization: bearer sbx-secret-value"),
        "sbx still injects its credential: {head:?}"
    );
}

/// The interaction with header strip-and-replace: an agent that *replays* the real secret value
/// (learned via a reflection) to the `to` host is now refused outright (not silently
/// stripped+reinjected); a *different* client auth value still hits the normal strip-and-replace
/// path — the two mechanisms coexist.
#[test]
fn replaying_the_secret_is_refused_but_a_different_value_is_stripped_and_replaced() {
    // (a) replaying the real secret → refused, before the strip-and-replace
    let (resp_a, _head_a) = run_with_injections_and_redactions(
        vec![injection(
            "host.test:*",
            "Authorization",
            "Bearer sbx-secret-value",
        )],
        &["sbx-secret-value"],
        b"GET / HTTP/1.1\r\nHost: host.test\r\nAuthorization: Bearer sbx-secret-value\r\n\r\n",
    );
    assert!(
        resp_a.contains("403") && resp_a.contains("outbound-secret"),
        "replaying the real secret must be refused, not stripped+reinjected: {resp_a:?}"
    );

    // (b) a different client auth value → normal strip-and-replace, sbx's value wins
    let (resp_b, head_b) = run_with_injections_and_redactions(
        vec![injection(
            "host.test:*",
            "Authorization",
            "Bearer sbx-secret-value",
        )],
        &["sbx-secret-value"],
        b"GET / HTTP/1.1\r\nHost: host.test\r\nAuthorization: Bearer attacker\r\n\r\n",
    );
    assert!(
        resp_b.contains("200"),
        "a different auth value is proxied: {resp_b:?}"
    );
    let auth: Vec<&str> = head_b
        .lines()
        .filter(|l| l.to_ascii_lowercase().starts_with("authorization:"))
        .collect();
    assert_eq!(
        auth.len(),
        1,
        "exactly one Authorization reaches the upstream: {head_b:?}"
    );
    assert!(
        auth[0].contains("sbx-secret-value"),
        "sbx's value wins: {head_b:?}"
    );
    assert!(
        !head_b.contains("attacker"),
        "the client's copy is stripped: {head_b:?}"
    );
}

/// Drive one request through a proxy (allowing `host.test`, carrying `injections` and redaction
/// `needles`) to a loopback upstream that returns `upstream_response` verbatim — so a test can
/// make the upstream *reflect* a secret in its response and assert what the client finally sees.
fn run_reflecting(
    injections: Vec<HeaderInjection>,
    needles: &[&str],
    upstream_response: &'static [u8],
    request: &[u8],
) -> String {
    let (addr, upstream_ca, up) = spawn_upstream("host.test", upstream_response);
    let mut roots = RootCertStore::empty();
    roots.add(upstream_ca).unwrap();
    let upstream_cfg = Arc::new(
        ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth(),
    );
    let proxy_ca = Arc::new(Ca::ephemeral().unwrap());
    let proxy_ca_der = proxy_ca.ca_cert_der();
    let ctx = Arc::new(
        ProxyCtx::new(proxy_ca, policy(&["host.test:*"]))
            .unwrap()
            .with_upstream(upstream_cfg)
            .with_resolver(Box::new(|_| Ok(vec![IpAddr::from([127, 0, 0, 1])])))
            .with_injections(injections)
            .with_redactions(
                needles
                    .iter()
                    .map(|n| SecretNeedle::named("test-secret", n.as_bytes().to_vec()))
                    .collect(),
            ),
    );
    let resp = through_proxy(
        ctx,
        proxy_ca_der,
        "host.test",
        "host.test",
        addr.port(),
        request,
    )
    .unwrap();
    up.join().unwrap();
    resp
}

/// The headline of the inbound backstop: a host an injection targets *reflects* the injected
/// credential in its response body; the proxy masks the value out before it reaches the cage, so
/// the agent gets the legitimate response with the secret struck out — never the plaintext.
#[test]
fn a_reflected_injected_secret_is_masked_in_the_response() {
    // the injected header is `Authorization: Bearer sbx-secret-value`; the upstream echoes the
    // value in a JSON body (body is 43 bytes; same-length masking keeps Content-Length valid).
    let resp = run_reflecting(
        vec![injection(
            "host.test:*",
            "Authorization",
            "Bearer sbx-secret-value",
        )],
        &["sbx-secret-value"],
        b"HTTP/1.1 200 OK\r\nContent-Length: 43\r\nConnection: close\r\n\r\n\
              {\"authorization\":\"Bearer sbx-secret-value\"}",
        b"GET /headers HTTP/1.1\r\nHost: host.test\r\n\r\n",
    );
    assert!(resp.contains("200"), "the response still flows: {resp:?}");
    assert!(
        !resp.contains("sbx-secret-value"),
        "the reflected secret must be masked out of the response: {resp:?}"
    );
    assert!(
        resp.contains(&"*".repeat("sbx-secret-value".len())),
        "the secret is replaced by an equal-length mask: {resp:?}"
    );
    assert!(
        resp.contains("{\"authorization\":\"Bearer "),
        "the legitimate response content around it survives: {resp:?}"
    );
}

/// The masking is scoped to injection-target hosts: a response from a host with no injection is
/// streamed unmasked even with a redaction needle configured. A secret could be present there
/// only if the agent already had it (and placed it), so masking would buy nothing — and scoping
/// keeps the mutate-on-match off every unrelated lane (notably the nix cache).
#[test]
fn a_response_from_a_non_injection_host_is_not_masked() {
    let resp = run_reflecting(
        // the injection targets a DIFFERENT host than the one being requested (host.test)
        vec![injection(
            "other.test:*",
            "Authorization",
            "Bearer sbx-secret-value",
        )],
        &["sbx-secret-value"],
        b"HTTP/1.1 200 OK\r\nContent-Length: 16\r\nConnection: close\r\n\r\nsbx-secret-value",
        b"GET / HTTP/1.1\r\nHost: host.test\r\n\r\n",
    );
    assert!(
        resp.contains("sbx-secret-value"),
        "a non-injection host's response is streamed unmasked: {resp:?}"
    );
}

/// The backstop covers the response **head**, not just its body. A debug or echo endpoint that
/// mirrors request headers reflects the injected credential in a header of its own — the shape
/// this masking exists for as much as a body echo. The head is masked before it is written to
/// the client, and equal-length replacement is what keeps the framing parsed off it valid.
#[test]
fn a_reflected_injected_secret_is_masked_in_a_response_header() {
    let resp = run_reflecting(
        vec![injection(
            "host.test:*",
            "Authorization",
            "Bearer sbx-secret-value",
        )],
        &["sbx-secret-value"],
        b"HTTP/1.1 200 OK\r\nX-Echo-Authorization: Bearer sbx-secret-value\r\n\
              Content-Length: 2\r\nConnection: close\r\n\r\nok",
        b"GET /echo HTTP/1.1\r\nHost: host.test\r\n\r\n",
    );
    assert!(resp.contains("200"), "the response still flows: {resp:?}");
    assert!(
        !resp.contains("sbx-secret-value"),
        "a secret reflected in a response HEADER must be masked too: {resp:?}"
    );
    assert!(
        resp.contains(&"*".repeat("sbx-secret-value".len())),
        "the secret is replaced by an equal-length mask: {resp:?}"
    );
    assert!(
        resp.contains("X-Echo-Authorization: Bearer "),
        "the header around it survives: {resp:?}"
    );
    assert!(
        resp.ends_with("ok"),
        "the declared length still frames the body after masking: {resp:?}"
    );
}

/// A reader that yields its data in fixed-size chunks, so a test can force a needle to straddle
/// a read boundary and prove the carry logic catches it.
struct ChunkReader {
    data: Vec<u8>,
    pos: usize,
    chunk: usize,
}

impl Read for ChunkReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.pos >= self.data.len() {
            return Ok(0);
        }
        let n = self.chunk.min(buf.len()).min(self.data.len() - self.pos);
        buf[..n].copy_from_slice(&self.data[self.pos..self.pos + n]);
        self.pos += n;
        Ok(n)
    }
}

#[test]
fn redact_in_place_masks_every_occurrence_at_equal_length() {
    let needles = vec![
        SecretNeedle::named("test-secret", b"AAA".to_vec()),
        SecretNeedle::named("test-secret", b"BB".to_vec()),
    ];
    let mut buf = b"AAA-mid-AAA-BB".to_vec();
    let before = buf.len();
    redact_in_place(&mut buf, &needles);
    assert_eq!(
        buf, b"***-mid-***-**",
        "every occurrence of every needle is masked"
    );
    assert_eq!(buf.len(), before, "masking preserves length");
}

/// Masking is left to right and NON-OVERLAPPING: the search resumes past a match, so a needle
/// never matches inside the `*` run its own occurrence produced. Pinned because the search is a
/// substring searcher rather than a hand-rolled walk, and a searcher that resumed one byte
/// later instead of one match later would keep finding the same region.
#[test]
fn redact_in_place_masks_left_to_right_without_overlapping_itself() {
    let needles = vec![SecretNeedle::named("test-secret", b"aaa".to_vec())];
    let mut buf = b"aaaaa".to_vec();
    redact_in_place(&mut buf, &needles);
    assert_eq!(
        buf, b"***aa",
        "the first match is consumed whole and the search resumes after it"
    );

    // A needle made only of the mask byte would, on a re-scanning implementation, keep matching
    // what it just wrote and never terminate.
    let stars = vec![SecretNeedle::named("test-secret", b"**".to_vec())];
    let mut buf = b"a**b**c".to_vec();
    redact_in_place(&mut buf, &stars);
    assert_eq!(buf, b"a**b**c", "masking is idempotent, and it terminates");
}

#[test]
fn redact_in_place_ignores_an_overlong_or_empty_needle() {
    let needles = vec![
        SecretNeedle::named("test-secret", b"WAYTOOLONG".to_vec()),
        SecretNeedle::named("test-secret", Vec::new()),
    ];
    let mut buf = b"short".to_vec();
    redact_in_place(&mut buf, &needles);
    assert_eq!(buf, b"short", "no match, no mutation, no panic");
}

#[test]
fn pump_redacting_masks_a_match_straddling_read_boundaries() {
    let needles = vec![SecretNeedle::named("test-secret", b"SECRET".to_vec())];
    // one byte per read forces the 6-byte needle to span six separate reads
    let mut r = ChunkReader {
        data: b"xxSECRETyy".to_vec(),
        pos: 0,
        chunk: 1,
    };
    let mut out = Vec::new();
    pump_redacting(&mut r, &mut out, &needles).unwrap();
    assert_eq!(
        out, b"xx******yy",
        "a secret split across reads is still masked, length preserved"
    );
}

#[test]
fn pump_redacting_passes_clean_bytes_through_unchanged() {
    let needles = vec![SecretNeedle::named("test-secret", b"SECRET".to_vec())];
    let mut r = ChunkReader {
        data: b"nothing to see here".to_vec(),
        pos: 0,
        chunk: 4,
    };
    let mut out = Vec::new();
    pump_redacting(&mut r, &mut out, &needles).unwrap();
    assert_eq!(
        out, b"nothing to see here",
        "a stream without a secret is untouched"
    );
}

// ---- L4 (`tcp://`) raw splice -------------------------------------------------

/// A raw TCP echo "upstream" for the splice tests: it accepts one connection and echoes every
/// byte back until the peer closes its write half, then exits. Returns its loopback address.
fn spawn_raw_echo() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    thread::spawn(move || {
        if let Ok((mut sock, _)) = listener.accept() {
            let mut buf = [0u8; 4096];
            loop {
                match sock.read(&mut buf) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        if sock.write_all(&buf[..n]).is_err() {
                            break;
                        }
                    }
                }
            }
        }
    });
    addr
}

/// A [`ProxyCtx`] whose resolver maps every name to loopback (so a `tcp://` rule reaches a local
/// echo upstream), with the given allow entries.
fn loopback_ctx(allow: &[&str]) -> Arc<ProxyCtx> {
    let ca = Arc::new(Ca::ephemeral().unwrap());
    Arc::new(
        ProxyCtx::new(ca, policy(allow))
            .unwrap()
            .with_resolver(Box::new(|_h| Ok(vec!["127.0.0.1".parse().unwrap()]))),
    )
}

/// Drive a raw (non-HTTP) payload through the proxy over a fresh UDS: CONNECT, expect `200`, then
/// send `payload`, half-close, and read the echoed bytes back. Proves the L4 splice carries an
/// arbitrary byte stream end-to-end — the headline mechanism.
fn through_proxy_raw(
    ctx: Arc<ProxyCtx>,
    connect_host: &str,
    connect_port: u16,
    payload: &[u8],
) -> io::Result<Vec<u8>> {
    let dir = TmpDir::new();
    let path = dir.join("proxy.sock");
    let listener = UnixListener::bind(&path).unwrap();
    thread::spawn(move || {
        let _ = serve(listener, ctx);
    });
    let mut sock = UnixStream::connect(&path).unwrap();
    sock.set_read_timeout(Some(std::time::Duration::from_secs(10)))
        .ok();
    write!(
        sock,
        "CONNECT {connect_host}:{connect_port} HTTP/1.1\r\n\r\n"
    )
    .unwrap();
    sock.flush().unwrap();
    let established = read_until_blank(&mut sock)?;
    assert!(
        established.contains("200 Connection established"),
        "CONNECT not accepted: {established:?}"
    );
    sock.write_all(payload)?;
    sock.shutdown(std::net::Shutdown::Write)?;
    let mut resp = Vec::new();
    sock.read_to_end(&mut resp)?;
    Ok(resp)
}

/// Connect and read just the CONNECT-stage reply (a `200`, or a pre-tunnel refusal), for the
/// cases the proxy refuses before accepting the tunnel.
fn splice_connect_reply(ctx: Arc<ProxyCtx>, connect_host: &str, connect_port: u16) -> String {
    let dir = TmpDir::new();
    let path = dir.join("proxy.sock");
    let listener = UnixListener::bind(&path).unwrap();
    thread::spawn(move || {
        let _ = serve(listener, ctx);
    });
    let mut sock = UnixStream::connect(&path).unwrap();
    sock.set_read_timeout(Some(std::time::Duration::from_secs(10)))
        .ok();
    write!(
        sock,
        "CONNECT {connect_host}:{connect_port} HTTP/1.1\r\n\r\n"
    )
    .unwrap();
    sock.flush().unwrap();
    read_until_blank(&mut sock).unwrap()
}

#[test]
fn a_tcp_rule_splices_a_raw_stream_end_to_end() {
    let echo = spawn_raw_echo();
    let ctx = loopback_ctx(&[&format!("tcp://splice.test:{}", echo.port())]);
    let resp = through_proxy_raw(ctx, "splice.test", echo.port(), b"PING-OVER-RAW-L4").unwrap();
    assert_eq!(
        resp, b"PING-OVER-RAW-L4",
        "the raw payload must round-trip through the splice uninspected"
    );
}

#[test]
fn an_ip_literal_connect_splices_with_no_sni() {
    // A raw splice needs no SNI, so an IP-literal CONNECT target is accepted when a `tcp://` Ip
    // rule names it — unlike the inspected path, which refuses an IP literal.
    let echo = spawn_raw_echo();
    let ctx = loopback_ctx(&[&format!("tcp://127.0.0.1:{}", echo.port())]);
    let resp = through_proxy_raw(ctx, "127.0.0.1", echo.port(), b"RAW-TO-IP").unwrap();
    assert_eq!(resp, b"RAW-TO-IP");
}

#[test]
fn an_ip_literal_target_without_a_tcp_rule_is_refused_and_logged_blocked() {
    use crate::sandbox::control::{LOG_RING_CAP, LogRing, LogVerdict};
    // With no `tcp://` rule the inspected L7 path refuses an IP-literal CONNECT pre-tunnel; the
    // attempt is logged (host = the IP the agent tried) as a block — a "what is it reaching for"
    // record the stats bucketing never captured.
    let log = Arc::new(LogRing::new(LOG_RING_CAP));
    let ctx = Arc::new(
        ProxyCtx::new(Arc::new(Ca::ephemeral().unwrap()), policy(&["host.test:*"]))
            .unwrap()
            .with_log(log.clone()),
    );
    let reply = splice_connect_reply(ctx, "127.0.0.1", 443);
    assert!(reply.contains("ip-literal"), "{reply:?}");
    let events = log.snapshot(None, None, false).events;
    assert_eq!(events.len(), 1, "one event: {events:?}");
    assert_eq!(events[0].verdict, LogVerdict::Blocked);
    assert_eq!(events[0].reason, "ip-literal");
    assert_eq!(events[0].host, "127.0.0.1");
    assert_eq!(events[0].port, 443);
    assert_eq!(events[0].method, None, "pre-tunnel: no method/path");
}

#[test]
fn an_unroutable_non_connect_request_is_refused_and_logged() {
    use crate::sandbox::control::{LOG_RING_CAP, LogRing, LogVerdict};
    // A non-CONNECT request that is NOT a routable `http://` absolute-form (here a bare
    // origin-form `GET /secret`, which carries no host to route) still hits the `method-not-allowed`
    // branch — an `http://` absolute-form is handled by the cleartext path, but this is neither.
    // It is refused, and logged (host blank, method + raw target) as the "what is the agent trying
    // to do" signal it is.
    let log = Arc::new(LogRing::new(LOG_RING_CAP));
    let ctx = Arc::new(
        ProxyCtx::new(Arc::new(Ca::ephemeral().unwrap()), policy(&["host.test:*"]))
            .unwrap()
            .with_log(log.clone()),
    );
    let dir = TmpDir::new();
    let path = dir.join("proxy.sock");
    let listener = UnixListener::bind(&path).unwrap();
    thread::spawn(move || {
        let _ = serve(listener, ctx);
    });
    let mut sock = UnixStream::connect(&path).unwrap();
    sock.set_read_timeout(Some(std::time::Duration::from_secs(10)))
        .ok();
    sock.write_all(b"GET /secret HTTP/1.1\r\nHost: host.test\r\n\r\n")
        .unwrap();
    sock.flush().unwrap();
    let reply = read_until_blank(&mut sock).unwrap();
    assert!(reply.contains("method-not-allowed"), "{reply:?}");
    let events = log.snapshot(None, None, false).events;
    assert_eq!(events.len(), 1, "one event: {events:?}");
    assert_eq!(events[0].verdict, LogVerdict::Blocked);
    assert_eq!(events[0].reason, "method-not-allowed");
    assert_eq!(
        events[0].host, "",
        "no clean host for a bare origin-form request"
    );
    assert_eq!(events[0].method.as_deref(), Some("GET"));
    assert_eq!(events[0].path.as_deref(), Some("/secret"));
}

#[test]
fn a_splice_to_a_private_address_is_ssrf_blocked_unless_the_rule_names_it() {
    // A `*.corp` subdomain rule does not name an exact host, so the SSRF guard refuses the
    // loopback (private) address it resolves to — a raw splice is still SSRF-guarded.
    let echo = spawn_raw_echo();
    let ctx = loopback_ctx(&[&format!("tcp://*.corp:{}", echo.port())]);
    let reply = splice_connect_reply(ctx, "db.corp", echo.port());
    assert!(
        reply.contains("403") && reply.contains("ssrf-blocked"),
        "a subdomain-ruled splice to a private address must be SSRF-blocked, got: {reply:?}"
    );
}

#[test]
fn the_splice_guard_counts_open_tunnels() {
    let counter = AtomicUsize::new(0);
    {
        let g1 = SpliceGuard::new(&counter);
        assert_eq!(g1.count(), 1);
        let g2 = SpliceGuard::new(&counter);
        assert_eq!(g2.count(), 2);
        assert_eq!(counter.load(Ordering::SeqCst), 2);
    }
    assert_eq!(
        counter.load(Ordering::SeqCst),
        0,
        "both guards released their slot on drop"
    );
}

// ── Traffic capture (`[network] capture`) ─────────────────────────────────────────────────────

/// A capturing proxy, allowing `upstream.test` and capturing at `level`.
#[cfg(test)]
fn capturing_ctx(
    proxy_ca: Arc<Ca>,
    upstream_cfg: Arc<ClientConfig>,
    log: Arc<crate::sandbox::control::LogRing>,
    level: crate::sandbox::control::CaptureLevel,
    body_kb: u64,
    injections: Vec<HeaderInjection>,
    redactions: Vec<SecretNeedle>,
) -> Arc<ProxyCtx> {
    use crate::sandbox::control::{CaptureCaps, CaptureRing};
    let ring = Arc::new(CaptureRing::with_needles(
        CaptureCaps::new(level, body_kb),
        redactions.clone(),
    ));
    Arc::new(
        ProxyCtx::new(proxy_ca, policy(&["upstream.test:*"]))
            .unwrap()
            .with_upstream(upstream_cfg)
            .with_log(log)
            .with_capture(ring)
            .with_injections(injections)
            .with_redactions(redactions)
            .with_resolver(Box::new(|_| Ok(vec![IpAddr::from([127, 0, 0, 1])]))),
    )
}

/// The captured exchange for the single event in `log`, read back the way the control socket
/// serves it (through the ring the ctx holds).
///
/// Waits for it: the capture is filed when the proxy's connection handler returns, which happens
/// on the proxy thread *after* the client has read the last byte — so a test that reads the
/// response and looks immediately would race the filing. This is the same ordering a live
/// `sbx net logs` sees (an exchange in flight simply has no traffic yet), so waiting is the
/// honest synchronization, not a workaround for a product race.
#[cfg(test)]
fn one_capture(
    ctx: &ProxyCtx,
    log: &crate::sandbox::control::LogRing,
) -> crate::sandbox::control::Capture {
    let events = log.snapshot(None, None, false).events;
    assert_eq!(events.len(), 1, "one event expected: {events:?}");
    let ring = ctx.capture.as_ref().expect("a capturing ctx");
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    loop {
        if let Some(cap) = ring.get(&[events[0].seq]).0.into_iter().next() {
            return cap;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "the exchange's capture was never filed"
        );
        thread::sleep(Duration::from_millis(10));
    }
}

/// End to end: an upstream that reflects a configured secret inside a WebSocket frame is
/// reported on the tunnel's own log event — and the cage still receives the frame byte for byte.
///
/// Both halves matter. The report is the whole feature: an open tunnel is relayed exactly, so
/// unlike the two HTTP tripwires nothing is refused or masked, and telling the user is the only
/// outcome there is. The byte-identical relay is what proves the tripwire is an observer: a
/// tripwire that perturbed the stream would break the very protocol it is watching.
///
/// Teeth: this ctx captures NOTHING. The scan must not ride on `[network] capture`, which is a
/// debugging convenience a user turns on and off — a security check that followed it would be
/// absent exactly when it was needed.
#[test]
fn a_secret_reflected_into_a_websocket_frame_is_reported_on_its_event() {
    use crate::sandbox::control::{LOG_RING_CAP, LogRing, SecretWay};
    const LEAK: &[u8] = br#"{"echo":"SECRET-VALUE-0123456789"}"#;
    let (addr, upstream_ca, up) = spawn_leaking_ws_upstream(LEAK);
    let mut roots = RootCertStore::empty();
    roots.add(upstream_ca).unwrap();
    let upstream_cfg = Arc::new(
        ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth(),
    );
    let proxy_ca = Arc::new(Ca::ephemeral().unwrap());
    let proxy_ca_der = proxy_ca.ca_cert_der();
    let log = Arc::new(LogRing::new(LOG_RING_CAP));
    let ctx = Arc::new(
        ProxyCtx::new(proxy_ca, policy(&["{WS} upstream.test:*"]))
            .unwrap()
            .with_upstream(upstream_cfg)
            .with_log(log.clone())
            .with_redactions(vec![SecretNeedle::named(
                "demo-token",
                b"SECRET-VALUE-0123456789".to_vec(),
            )])
            .with_resolver(Box::new(|_| Ok(vec![IpAddr::from([127, 0, 0, 1])]))),
    );

    let relayed =
        through_proxy_ws_frames(ctx.clone(), proxy_ca_der, "upstream.test", addr.port()).unwrap();
    up.join().unwrap();
    assert_eq!(
        relayed,
        ws_frame(0x1, LEAK, None),
        "the frame reaches the cage exactly as it was sent: this reports, it never rewrites"
    );

    // The sighting amends the tunnel's event, so a follow reader sees it without waiting for the
    // tunnel to close. Polled because the relay files it from the proxy thread.
    let deadline = std::time::Instant::now() + Duration::from_secs(60);
    let seen = loop {
        let events = log.snapshot(None, None, false).events;
        match events.iter().find(|e| !e.secrets_seen.is_empty()) {
            Some(e) => break e.secrets_seen.clone(),
            None => assert!(
                std::time::Instant::now() < deadline,
                "the secret crossing the tunnel was never reported: {events:?}"
            ),
        }
        thread::sleep(Duration::from_millis(10));
    };
    assert_eq!(seen.len(), 1, "one credential, reported once: {seen:?}");
    assert_eq!(seen[0].name, "demo-token", "reported by NAME");
    assert_eq!(
        seen[0].way,
        SecretWay::Back,
        "the upstream sent it back, which is not the direction the cage sent"
    );
}

/// End to end over a real TLS MITM: a POST with a body is captured in both directions, and the
/// response the cage receives is byte-identical to what the upstream sent. Teeth: the tee sits in
/// the middle of the relay, so a bug there would either corrupt the relayed body or capture the
/// wrong bytes — this asserts both at once.
#[test]
fn a_capturing_launch_records_both_directions_without_disturbing_the_relay() {
    use crate::sandbox::control::{CaptureLevel, LOG_RING_CAP, LogRing};
    let (addr, upstream_ca, up) = spawn_upstream(
            "upstream.test",
            b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 17\r\nConnection: close\r\n\r\n{\"reply\":\"pong\"}\n",
        );
    let proxy_ca = Arc::new(Ca::ephemeral().unwrap());
    let proxy_ca_der = proxy_ca.ca_cert_der();
    let mut roots = RootCertStore::empty();
    roots.add(upstream_ca).unwrap();
    let upstream_cfg = Arc::new(
        ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth(),
    );
    let log = Arc::new(LogRing::new(LOG_RING_CAP));
    let ctx = capturing_ctx(
        proxy_ca,
        upstream_cfg,
        log.clone(),
        CaptureLevel::Bodies,
        8,
        vec![],
        vec![],
    );
    let got = through_proxy(
            ctx.clone(),
            proxy_ca_der,
            "upstream.test",
            "upstream.test",
            addr.port(),
            b"POST /v1/messages HTTP/1.1\r\nHost: upstream.test\r\nContent-Type: application/json\r\nContent-Length: 16\r\nConnection: close\r\n\r\n{\"prompt\":\"hi\"}\n",
        )
        .unwrap();
    up.join().unwrap();

    assert!(
        got.ends_with("{\"reply\":\"pong\"}\n"),
        "the relayed response is untouched by the tee: {got:?}"
    );

    let cap = one_capture(&ctx, &log);
    let req_head = String::from_utf8(cap.req_head.bytes.clone()).unwrap();
    assert!(
        req_head.starts_with("POST /v1/messages HTTP/1.1"),
        "the request line is captured: {req_head:?}"
    );
    assert!(req_head.contains("Content-Type: application/json"));
    assert_eq!(
        String::from_utf8(cap.req_body.bytes.clone()).unwrap(),
        "{\"prompt\":\"hi\"}\n",
        "the request body is captured"
    );
    let res_head = String::from_utf8(cap.res_head.bytes.clone()).unwrap();
    assert!(res_head.starts_with("HTTP/1.1 200 OK"), "{res_head:?}");
    assert_eq!(
        String::from_utf8(cap.res_body.bytes.clone()).unwrap(),
        "{\"reply\":\"pong\"}\n",
        "the response body is captured"
    );
    assert!(!cap.req_body.truncated && !cap.res_body.truncated);
}

/// The headers level captures the two heads and neither body — the level a user picks precisely
/// so no payload is retained.
#[test]
fn the_headers_level_captures_no_payload_at_all() {
    use crate::sandbox::control::{CaptureLevel, LOG_RING_CAP, LogRing};
    let (addr, upstream_ca, up) = spawn_upstream(
        "upstream.test",
        b"HTTP/1.1 200 OK\r\nContent-Length: 12\r\nConnection: close\r\n\r\nsecret-reply",
    );
    let proxy_ca = Arc::new(Ca::ephemeral().unwrap());
    let proxy_ca_der = proxy_ca.ca_cert_der();
    let mut roots = RootCertStore::empty();
    roots.add(upstream_ca).unwrap();
    let upstream_cfg = Arc::new(
        ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth(),
    );
    let log = Arc::new(LogRing::new(LOG_RING_CAP));
    let ctx = capturing_ctx(
        proxy_ca,
        upstream_cfg,
        log.clone(),
        CaptureLevel::Headers,
        8,
        vec![],
        vec![],
    );
    let got = through_proxy(
            ctx.clone(),
            proxy_ca_der,
            "upstream.test",
            "upstream.test",
            addr.port(),
            b"POST /p HTTP/1.1\r\nHost: upstream.test\r\nContent-Length: 11\r\nConnection: close\r\n\r\nsecret-body",
        )
        .unwrap();
    up.join().unwrap();
    assert!(
        got.ends_with("secret-reply"),
        "the relay still works: {got:?}"
    );

    let cap = one_capture(&ctx, &log);
    assert!(!cap.req_head.bytes.is_empty() && !cap.res_head.bytes.is_empty());
    assert!(
        cap.req_body.is_empty(),
        "no request payload at the headers level"
    );
    assert!(
        cap.res_body.is_empty(),
        "no response payload at the headers level"
    );
}

/// A body over the per-body cap is cut and SAYS it was cut, while the cage still receives every
/// byte. Teeth: the cap is what bounds host memory, so a silent truncation (or a truncated
/// *relay*) would be the dangerous failure.
#[test]
fn a_body_over_the_cap_is_marked_truncated_and_still_relayed_whole() {
    use crate::sandbox::control::{CaptureLevel, LOG_RING_CAP, LogRing};
    // 3 KiB of body against a 1 KiB cap.
    let body = vec![b'y'; 3 * 1024];
    let mut resp =
        format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n", body.len()).into_bytes();
    resp.extend_from_slice(&body);
    let resp: &'static [u8] = Box::leak(resp.into_boxed_slice());

    let (addr, upstream_ca, up) = spawn_upstream("upstream.test", resp);
    let proxy_ca = Arc::new(Ca::ephemeral().unwrap());
    let proxy_ca_der = proxy_ca.ca_cert_der();
    let mut roots = RootCertStore::empty();
    roots.add(upstream_ca).unwrap();
    let upstream_cfg = Arc::new(
        ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth(),
    );
    let log = Arc::new(LogRing::new(LOG_RING_CAP));
    let ctx = capturing_ctx(
        proxy_ca,
        upstream_cfg,
        log.clone(),
        CaptureLevel::Bodies,
        1,
        vec![],
        vec![],
    );
    let got = through_proxy(
        ctx.clone(),
        proxy_ca_der,
        "upstream.test",
        "upstream.test",
        addr.port(),
        b"GET /p HTTP/1.1\r\nHost: upstream.test\r\nConnection: close\r\n\r\n",
    )
    .unwrap();
    up.join().unwrap();
    assert_eq!(
        got.matches('y').count(),
        3 * 1024,
        "the cage receives the whole body regardless of the capture cap"
    );

    let cap = one_capture(&ctx, &log);
    assert_eq!(cap.res_body.bytes.len(), 1024, "cut exactly at the cap");
    assert!(cap.res_body.truncated, "and the cut is reported");
}

/// An injected credential never enters the capture: the head recorded is the CLIENT's (taken
/// before the injection), so only the header's NAME is noted. Teeth: the same request is
/// forwarded upstream WITH the secret, so a capture taken one step later would hold it.
#[test]
fn an_injected_credential_is_named_in_the_capture_but_never_valued() {
    use crate::sandbox::control::{CaptureLevel, LOG_RING_CAP, LogRing};
    let (addr, upstream_ca, up) = spawn_upstream(
        "upstream.test",
        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
    );
    let proxy_ca = Arc::new(Ca::ephemeral().unwrap());
    let proxy_ca_der = proxy_ca.ca_cert_der();
    let mut roots = RootCertStore::empty();
    roots.add(upstream_ca).unwrap();
    let upstream_cfg = Arc::new(
        ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth(),
    );
    let log = Arc::new(LogRing::new(LOG_RING_CAP));
    let ctx = capturing_ctx(
        proxy_ca,
        upstream_cfg,
        log.clone(),
        CaptureLevel::Bodies,
        8,
        vec![injection(
            "upstream.test:*",
            "authorization",
            "Bearer s3cr3t-token",
        )],
        vec![SecretNeedle::named("TOKEN", b"s3cr3t-token".to_vec())],
    );
    let _ = through_proxy(
        ctx.clone(),
        proxy_ca_der,
        "upstream.test",
        "upstream.test",
        addr.port(),
        b"GET /p HTTP/1.1\r\nHost: upstream.test\r\nConnection: close\r\n\r\n",
    )
    .unwrap();
    up.join().unwrap();

    let cap = one_capture(&ctx, &log);
    let whole: Vec<u8> = cap
        .parts()
        .into_iter()
        .flat_map(|(_, b)| b.bytes.clone())
        .collect();
    assert!(
        !contains_subslice(&whole, b"s3cr3t-token"),
        "no part of the capture may carry the injected value"
    );
    assert_eq!(
        String::from_utf8(cap.injected.bytes.clone()).unwrap(),
        "authorization",
        "the injected header is named so the capture does not read as the whole request"
    );
}

/// A response that reflects a configured secret is masked in the capture — the ring never holds
/// a credential even when the upstream hands one back.
#[test]
fn a_reflected_secret_is_masked_out_of_the_capture() {
    use crate::sandbox::control::{CaptureLevel, LOG_RING_CAP, LogRing};
    let (addr, upstream_ca, up) = spawn_upstream(
            "upstream.test",
            b"HTTP/1.1 200 OK\r\nContent-Length: 26\r\nConnection: close\r\n\r\nyou sent s3cr3t-token back",
        );
    let proxy_ca = Arc::new(Ca::ephemeral().unwrap());
    let proxy_ca_der = proxy_ca.ca_cert_der();
    let mut roots = RootCertStore::empty();
    roots.add(upstream_ca).unwrap();
    let upstream_cfg = Arc::new(
        ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth(),
    );
    let log = Arc::new(LogRing::new(LOG_RING_CAP));
    let ctx = capturing_ctx(
        proxy_ca,
        upstream_cfg,
        log.clone(),
        CaptureLevel::Bodies,
        8,
        vec![],
        vec![SecretNeedle::named("TOKEN", b"s3cr3t-token".to_vec())],
    );
    let _ = through_proxy(
        ctx.clone(),
        proxy_ca_der,
        "upstream.test",
        "upstream.test",
        addr.port(),
        b"GET /p HTTP/1.1\r\nHost: upstream.test\r\nConnection: close\r\n\r\n",
    )
    .unwrap();
    up.join().unwrap();

    let cap = one_capture(&ctx, &log);
    let body = String::from_utf8(cap.res_body.bytes.clone()).unwrap();
    assert_eq!(
        body, "you sent ************ back",
        "the reflected secret is masked, at equal length"
    );
}

/// The inspected-cleartext (`http://`) path captures too. Teeth: this is a separate handler from
/// the CONNECT/TLS one, wired separately, so nothing in the tunneled tests covers it.
#[test]
fn a_cleartext_exchange_is_captured_in_both_directions() {
    use crate::sandbox::control::{CaptureCaps, CaptureLevel, CaptureRing, LOG_RING_CAP, LogRing};
    let (addr, _up_head) = spawn_plain_upstream(
        b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello",
    );
    let port = addr.port();
    let log = Arc::new(LogRing::new(LOG_RING_CAP));
    let ring = Arc::new(CaptureRing::with_needles(
        CaptureCaps::new(CaptureLevel::Bodies, 8),
        vec![],
    ));
    let rule = format!("http://upstream.test:{port}");
    let ctx = Arc::new(
        ProxyCtx::new(Arc::new(Ca::ephemeral().unwrap()), policy(&[rule.as_str()]))
            .unwrap()
            .with_log(log.clone())
            .with_capture(ring)
            .with_resolver(Box::new(|_| Ok(vec![IpAddr::from([127, 0, 0, 1])]))),
    );
    let request = format!(
        "POST http://upstream.test:{port}/path HTTP/1.1\r\nHost: upstream.test:{port}\r\n\
             Content-Length: 7\r\nConnection: close\r\n\r\npayload"
    );
    let resp = through_cleartext(ctx.clone(), request.as_bytes()).unwrap();
    assert!(resp.contains("hello"), "the relay still works: {resp:?}");

    let cap = one_capture(&ctx, &log);
    assert!(
        String::from_utf8(cap.req_head.bytes.clone())
            .unwrap()
            .starts_with("POST http://upstream.test")
    );
    assert_eq!(
        String::from_utf8(cap.req_body.bytes.clone()).unwrap(),
        "payload",
        "the cleartext request body is captured"
    );
    assert!(
        String::from_utf8(cap.res_head.bytes.clone())
            .unwrap()
            .starts_with("HTTP/1.1 200 OK")
    );
    assert_eq!(
        String::from_utf8(cap.res_body.bytes.clone()).unwrap(),
        "hello"
    );
}

/// A REQUEST body larger than the cap is marked truncated end to end. Teeth: the request sink is
/// filled by the relay's own read loop, so a body that fills it exactly on a read boundary is the
/// case where a truncation could go unrecorded — and the cage must still receive every byte.
#[test]
fn a_request_body_over_the_cap_is_marked_truncated_and_still_forwarded_whole() {
    use crate::sandbox::control::{CaptureLevel, LOG_RING_CAP, LogRing};
    // Exactly twice the 1 KiB cap, so the relay's copy lands the cut on a boundary.
    let body = "z".repeat(2048);
    let (addr, upstream_ca, up) = spawn_upstream(
        "upstream.test",
        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
    );
    let proxy_ca = Arc::new(Ca::ephemeral().unwrap());
    let proxy_ca_der = proxy_ca.ca_cert_der();
    let mut roots = RootCertStore::empty();
    roots.add(upstream_ca).unwrap();
    let upstream_cfg = Arc::new(
        ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth(),
    );
    let log = Arc::new(LogRing::new(LOG_RING_CAP));
    let ctx = capturing_ctx(
        proxy_ca,
        upstream_cfg,
        log.clone(),
        CaptureLevel::Bodies,
        1,
        vec![],
        vec![],
    );
    let request = format!(
        "POST /p HTTP/1.1\r\nHost: upstream.test\r\nContent-Length: {}\r\n\
             Connection: close\r\n\r\n{body}",
        body.len()
    );
    let _ = through_proxy(
        ctx.clone(),
        proxy_ca_der,
        "upstream.test",
        "upstream.test",
        addr.port(),
        request.as_bytes(),
    )
    .unwrap();
    up.join().unwrap();

    let cap = one_capture(&ctx, &log);
    assert_eq!(cap.req_body.bytes.len(), 1024, "cut at the cap");
    assert!(
        cap.req_body.truncated,
        "a request body cut on a read boundary must still say it was cut"
    );
}

/// A launch that does not capture stores nothing at all — the default costs no memory and leaks
/// no plaintext into the control plane.
#[test]
fn a_non_capturing_launch_files_nothing() {
    use crate::sandbox::control::{LOG_RING_CAP, LogRing};
    let (addr, upstream_ca, up) = spawn_upstream(
        "upstream.test",
        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
    );
    let proxy_ca = Arc::new(Ca::ephemeral().unwrap());
    let proxy_ca_der = proxy_ca.ca_cert_der();
    let mut roots = RootCertStore::empty();
    roots.add(upstream_ca).unwrap();
    let upstream_cfg = Arc::new(
        ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth(),
    );
    let log = Arc::new(LogRing::new(LOG_RING_CAP));
    let ctx = Arc::new(
        ProxyCtx::new(proxy_ca, policy(&["upstream.test:*"]))
            .unwrap()
            .with_upstream(upstream_cfg)
            .with_log(log.clone())
            .with_resolver(Box::new(|_| Ok(vec![IpAddr::from([127, 0, 0, 1])]))),
    );
    let _ = through_proxy(
            ctx.clone(),
            proxy_ca_der,
            "upstream.test",
            "upstream.test",
            addr.port(),
            b"POST /p HTTP/1.1\r\nHost: upstream.test\r\nContent-Length: 6\r\nConnection: close\r\n\r\nsecret",
        )
        .unwrap();
    up.join().unwrap();
    assert!(ctx.capture.is_none(), "no capture ring is even built");
    // The event is still logged — only the traffic is absent.
    assert_eq!(log.snapshot(None, None, false).events.len(), 1);
}

/// A capturing ctx allowing a WebSocket upgrade to `upstream.test`.
#[cfg(test)]
fn capturing_ws_ctx(
    proxy_ca: Arc<Ca>,
    upstream_cfg: Arc<ClientConfig>,
    log: Arc<crate::sandbox::control::LogRing>,
    level: crate::sandbox::control::CaptureLevel,
) -> Arc<ProxyCtx> {
    use crate::sandbox::control::{CaptureCaps, CaptureRing};
    let ring = Arc::new(CaptureRing::with_needles(
        CaptureCaps::new(level, 8),
        vec![],
    ));
    Arc::new(
        ProxyCtx::new(proxy_ca, policy(&["{WS} upstream.test:*"]))
            .unwrap()
            .with_upstream(upstream_cfg)
            .with_log(log)
            .with_capture(ring)
            .with_resolver(Box::new(|_| Ok(vec![IpAddr::from([127, 0, 0, 1])]))),
    )
}

/// A WebSocket upstream that REFLECTS a secret back inside a frame: it accepts the upgrade and
/// pushes one text frame carrying `payload`. The shape the leak tripwire exists for — a
/// cooperating or compromised far side echoing a credential into the tunnel.
#[cfg(test)]
fn spawn_leaking_ws_upstream(
    payload: &'static [u8],
) -> (SocketAddr, CertificateDer<'static>, thread::JoinHandle<()>) {
    let ca = Arc::new(Ca::ephemeral().unwrap());
    let ca_der = ca.ca_cert_der();
    let server_config = Arc::new(
        ServerConfig::builder()
            .with_no_client_auth()
            .with_cert_resolver(Arc::new(CertResolver::new(ca))),
    );
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = thread::spawn(move || {
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
        let mut opening = b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\
                 Connection: Upgrade\r\nSec-WebSocket-Accept: test-accept\r\n\r\n"
            .to_vec();
        opening.extend(ws_frame(0x1, payload, None));
        let _ = tls.write_all(&opening);
        let _ = tls.flush();
        let mut buf = [0u8; 256];
        let _ = tls.read(&mut buf);
    });
    (addr, ca_der, handle)
}

/// Encode one WebSocket frame the way a peer would. A client must mask; a server must not.
#[cfg(test)]
fn ws_frame(opcode: u8, payload: &[u8], mask: Option<[u8; 4]>) -> Vec<u8> {
    let mut out = vec![0x80 | opcode];
    let flag = if mask.is_some() { 0x80u8 } else { 0 };
    out.push(flag | payload.len() as u8);
    match mask {
        Some(key) => {
            out.extend_from_slice(&key);
            out.extend(payload.iter().enumerate().map(|(i, b)| b ^ key[i % 4]));
        }
        None => out.extend_from_slice(payload),
    }
    out
}

/// A WebSocket upstream that speaks real framing: it pushes a text frame **in the same write as
/// the `101`** (so the frame lands in the bytes the proxy read past the handshake head — the path
/// that would silently lose the first message), then echoes a frame back and closes.
#[cfg(test)]
fn spawn_frame_ws_upstream() -> (SocketAddr, CertificateDer<'static>, thread::JoinHandle<()>) {
    let ca = Arc::new(Ca::ephemeral().unwrap());
    let ca_der = ca.ca_cert_der();
    let server_config = Arc::new(
        ServerConfig::builder()
            .with_no_client_auth()
            .with_cert_resolver(Arc::new(CertResolver::new(ca))),
    );
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = thread::spawn(move || {
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
        let mut opening = b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\
                 Connection: Upgrade\r\nSec-WebSocket-Accept: test-accept\r\n\r\n"
            .to_vec();
        opening.extend(ws_frame(0x1, br#"{"from":"server"}"#, None));
        let _ = tls.write_all(&opening);
        let _ = tls.flush();
        let mut buf = [0u8; 256];
        if matches!(tls.read(&mut buf), Ok(n) if n > 0) {
            let _ = tls.write_all(&ws_frame(0x1, br#"{"echo":true}"#, None));
            let _ = tls.flush();
        }
    });
    (addr, ca_der, handle)
}

/// Open a WebSocket through the proxy, send one properly masked text frame, and return every raw
/// byte the cage received after the handshake — so a test can check the relay was untouched.
#[cfg(test)]
fn through_proxy_ws_frames(
    ctx: Arc<ProxyCtx>,
    proxy_ca: CertificateDer<'static>,
    connect_host: &str,
    connect_port: u16,
) -> io::Result<Vec<u8>> {
    let dir = TmpDir::new();
    let path = dir.join("proxy.sock");
    let listener = UnixListener::bind(&path).unwrap();
    thread::spawn(move || {
        let _ = serve(listener, ctx);
    });
    let mut sock = UnixStream::connect(&path).unwrap();
    write!(
        sock,
        "CONNECT {connect_host}:{connect_port} HTTP/1.1\r\n\r\n"
    )?;
    sock.flush()?;
    let _ = read_until_blank(&mut sock)?;
    let mut roots = RootCertStore::empty();
    roots.add(proxy_ca).unwrap();
    let client_config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let name = ServerName::try_from(connect_host.to_string()).unwrap();
    let conn = ClientConnection::new(Arc::new(client_config), name).map_err(io::Error::other)?;
    let mut tls = StreamOwned::new(conn, sock);
    let upgrade = format!(
        "GET /chat HTTP/1.1\r\nHost: {connect_host}\r\nUpgrade: websocket\r\n\
             Connection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
             Sec-WebSocket-Version: 13\r\n\r\n"
    );
    tls.write_all(upgrade.as_bytes())?;
    tls.flush()?;
    let head = read_head_until_blank(&mut tls)?;
    assert!(head.contains("101 Switching Protocols"), "{head:?}");
    tls.write_all(&ws_frame(
        0x1,
        br#"{"from":"cage"}"#,
        Some([0x11, 0x22, 0x33, 0x44]),
    ))?;
    tls.flush()?;
    let mut frames = Vec::new();
    let _ = tls.read_to_end(&mut frames);
    Ok(frames)
}

/// The transcript of an established WebSocket is captured in both directions: the cage's own
/// frames under `ws-up`, the upstream's under `ws-down`, each holding the payloads and nothing
/// else. And the relay is untouched — the cage receives the upstream's frames byte for byte.
///
/// Three teeth in one: a client frame is XOR-masked on the wire, so capturing it verbatim would
/// store noise (the test asserts the plaintext is absent from the relayed bytes but present in
/// the capture); the upstream's first frame rides in the same write as the `101`, so it is only
/// captured if the bytes read past the handshake head are fed through the decoder; and the
/// frames must arrive as a SECOND filing folded into the handshake's entry, not as a duplicate.
#[test]
fn a_websocket_transcript_is_captured_in_both_directions_without_disturbing_the_relay() {
    use crate::sandbox::control::{CaptureLevel, LOG_RING_CAP, LogRing};
    let (addr, upstream_ca, up) = spawn_frame_ws_upstream();
    let mut roots = RootCertStore::empty();
    roots.add(upstream_ca).unwrap();
    let upstream_cfg = Arc::new(
        ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth(),
    );
    let proxy_ca = Arc::new(Ca::ephemeral().unwrap());
    let proxy_ca_der = proxy_ca.ca_cert_der();
    let log = Arc::new(LogRing::new(LOG_RING_CAP));
    let ctx = capturing_ws_ctx(proxy_ca, upstream_cfg, log.clone(), CaptureLevel::Bodies);

    let relayed =
        through_proxy_ws_frames(ctx.clone(), proxy_ca_der, "upstream.test", addr.port()).unwrap();
    up.join().unwrap();

    let mut expected = ws_frame(0x1, br#"{"from":"server"}"#, None);
    expected.extend(ws_frame(0x1, br#"{"echo":true}"#, None));
    assert_eq!(
        relayed, expected,
        "the cage must receive the upstream's frames byte for byte"
    );

    // The frames are filed when the tunnel ends, folded into the handshake's entry.
    let ring = ctx.capture.as_ref().expect("a capturing ctx");
    let deadline = std::time::Instant::now() + Duration::from_secs(60);
    let cap = loop {
        let seqs: Vec<u64> = log
            .snapshot(None, None, false)
            .events
            .iter()
            .map(|e| e.seq)
            .collect();
        match ring.get(&seqs).0.into_iter().next() {
            Some(c) if !c.ws_up.is_empty() && !c.ws_down.is_empty() => break c,
            _ => {}
        }
        assert!(
            std::time::Instant::now() < deadline,
            "the WebSocket transcript was never filed"
        );
        thread::sleep(Duration::from_millis(10));
    };

    assert_eq!(
        String::from_utf8(cap.ws_up.bytes.clone()).unwrap(),
        r#"{"from":"cage"}"#,
        "the cage's own frame is captured unmasked"
    );
    assert_eq!(
        String::from_utf8(cap.ws_down.bytes.clone()).unwrap(),
        r#"{"from":"server"}{"echo":true}"#,
        "both upstream frames are captured, including the one sent with the `101`"
    );
    // The handshake filed earlier is still there: one entry per exchange, not two.
    assert!(
        String::from_utf8_lossy(&cap.req_head.bytes).contains("GET /chat HTTP/1.1")
            && String::from_utf8_lossy(&cap.res_head.bytes).contains("101 Switching Protocols"),
        "the frames folded into the handshake's capture rather than replacing it: {cap:?}"
    );
    assert_eq!(ring.get(&[cap.seq]).0.len(), 1, "no duplicate entry");
}

/// The WebSocket handshake is captured on both sides, INCLUDING the upstream's `101` — and it is
/// filed at the `101` rather than at teardown, so it reaches a reader while the tunnel is still
/// open. Teeth: the capture used to be filed before the upstream response was even read, so the
/// `101` could not appear; and a capture held until the guard dropped would arrive only when the
/// tunnel closed, which for a real WebSocket can be hours.
///
/// This upstream does not speak real framing, which pins the other half of the contract: a byte
/// stream that is not WebSocket framing yields no transcript rather than an invented one.
#[test]
fn a_websocket_handshake_is_captured_including_the_101_but_not_the_frames() {
    use crate::sandbox::control::{CaptureLevel, LOG_RING_CAP, LogRing};
    let (addr, upstream_ca, up) = spawn_ws_upstream();
    let mut roots = RootCertStore::empty();
    roots.add(upstream_ca).unwrap();
    let upstream_cfg = Arc::new(
        ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth(),
    );
    let proxy_ca = Arc::new(Ca::ephemeral().unwrap());
    let proxy_ca_der = proxy_ca.ca_cert_der();
    let log = Arc::new(LogRing::new(LOG_RING_CAP));
    let ctx = capturing_ws_ctx(proxy_ca, upstream_cfg, log.clone(), CaptureLevel::Bodies);

    let transcript =
        through_proxy_websocket(ctx.clone(), proxy_ca_der, "upstream.test", addr.port()).unwrap();
    up.join().unwrap();
    // The relay is untouched by the capture: the `101`, the server's push, and the echo of the
    // client's own frame all still round-trip.
    assert!(
        transcript.contains("101 Switching Protocols")
            && transcript.contains("S-FIRST;")
            && transcript.contains("ECHO:client-frame"),
        "the capture disturbed the relay: {transcript:?}"
    );

    let cap = one_capture(&ctx, &log);
    let req_head = String::from_utf8_lossy(&cap.req_head.bytes).into_owned();
    assert!(
        req_head.contains("GET /chat HTTP/1.1") && req_head.contains("Upgrade: websocket"),
        "the handshake request is captured: {req_head:?}"
    );
    let res_head = String::from_utf8_lossy(&cap.res_head.bytes).into_owned();
    assert!(
        res_head.contains("101 Switching Protocols") && res_head.contains("Sec-WebSocket-Accept"),
        "the upstream's `101` is captured: {res_head:?}"
    );
    for (part, bytes) in cap.parts() {
        let text = String::from_utf8_lossy(&bytes.bytes);
        assert!(
            !text.contains("S-FIRST;") && !text.contains("client-frame"),
            "a WebSocket frame must not reach the capture ({part:?}): {text:?}"
        );
    }
    // The status amendment was released with the capture, so `--with-status` shows the `101`
    // while the tunnel is open rather than after it closes.
    let events = log.snapshot(None, None, false).events;
    assert_eq!(events[0].status, Some(101), "{events:?}");
}

/// A WebSocket upstream that completes the handshake and then HOLDS the tunnel open until it is
/// released, so a test can observe what the proxy filed while the tunnel is **live** rather than
/// only after it closed. Returns the release channel alongside the usual pieces.
#[cfg(test)]
fn spawn_held_ws_upstream() -> (
    SocketAddr,
    CertificateDer<'static>,
    std::sync::mpsc::Sender<()>,
    thread::JoinHandle<()>,
) {
    let ca = Arc::new(Ca::ephemeral().unwrap());
    let ca_der = ca.ca_cert_der();
    let server_config = Arc::new(
        ServerConfig::builder()
            .with_no_client_auth()
            .with_cert_resolver(Arc::new(CertResolver::new(ca))),
    );
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let (release, released) = std::sync::mpsc::channel::<()>();
    let handle = thread::spawn(move || {
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
        let _ = tls.write_all(
            b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\
                  Connection: Upgrade\r\nSec-WebSocket-Accept: test-accept\r\n\r\n",
        );
        let _ = tls.flush();
        // Send nothing more and do not close: the proxy stays inside its relay, which is the
        // state this upstream exists to hold.
        let _ = released.recv();
    });
    (addr, ca_der, release, handle)
}

/// The handshake capture is filed at the `101`, **while the tunnel is still open** — not when the
/// guard drops at teardown. That is a timing property, so it needs a live tunnel to assert
/// against: a real WebSocket can stay open for hours, and a capture held until then would keep
/// the `101` out of `sbx net logs` for exactly as long.
///
/// Teeth: move the filing back to the guard's `Drop` and the poll below never finds a capture,
/// because the only thing that ends this tunnel is the release at the bottom of the test.
#[test]
fn a_websocket_capture_is_filed_while_the_tunnel_is_still_open() {
    use crate::sandbox::control::{CaptureLevel, LOG_RING_CAP, LogRing};
    let (addr, upstream_ca, release, up) = spawn_held_ws_upstream();
    let mut roots = RootCertStore::empty();
    roots.add(upstream_ca).unwrap();
    let upstream_cfg = Arc::new(
        ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth(),
    );
    let proxy_ca = Arc::new(Ca::ephemeral().unwrap());
    let proxy_ca_der = proxy_ca.ca_cert_der();
    let log = Arc::new(LogRing::new(LOG_RING_CAP));
    let ctx = capturing_ws_ctx(proxy_ca, upstream_cfg, log.clone(), CaptureLevel::Headers);

    let dir = TmpDir::new();
    let path = dir.join("proxy.sock");
    let listener = UnixListener::bind(&path).unwrap();
    let serving = ctx.clone();
    thread::spawn(move || {
        let _ = serve(listener, serving);
    });

    // A client that opens the tunnel and then STAYS on it: its final read returns only once the
    // upstream is released, so while this thread is alive the tunnel is provably open.
    let port = addr.port();
    let client = thread::spawn(move || -> String {
        let mut sock = UnixStream::connect(&path).unwrap();
        write!(sock, "CONNECT upstream.test:{port} HTTP/1.1\r\n\r\n").unwrap();
        sock.flush().unwrap();
        let _ = read_until_blank(&mut sock);
        let mut roots = RootCertStore::empty();
        roots.add(proxy_ca_der).unwrap();
        let client_config = ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        let name = ServerName::try_from("upstream.test".to_string()).unwrap();
        let conn = ClientConnection::new(Arc::new(client_config), name).unwrap();
        let mut tls = StreamOwned::new(conn, sock);
        let upgrade = "GET /chat HTTP/1.1\r\nHost: upstream.test\r\nUpgrade: websocket\r\n\
                 Connection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
                 Sec-WebSocket-Version: 13\r\n\r\n";
        let _ = tls.write_all(upgrade.as_bytes());
        let _ = tls.flush();
        let head = read_head_until_blank(&mut tls).unwrap_or_default();
        let mut rest = String::new();
        let _ = tls.read_to_string(&mut rest);
        head
    });

    let ring = ctx.capture.as_ref().expect("a capturing ctx");
    // Generous on purpose: what is being asserted is an ORDERING (filed before the tunnel ends),
    // and the tunnel cannot end until the release at the bottom of this test. The deadline only
    // exists so a regression fails instead of hanging, so it costs nothing when passing and must
    // not be tight enough to trip on a loaded machine running the rest of the suite alongside.
    let deadline = std::time::Instant::now() + Duration::from_secs(60);
    let cap = loop {
        let seqs: Vec<u64> = log
            .snapshot(None, None, false)
            .events
            .iter()
            .map(|e| e.seq)
            .collect();
        if let Some(c) = ring.get(&seqs).0.into_iter().next() {
            break c;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "the handshake capture never arrived while the tunnel was open"
        );
        thread::sleep(Duration::from_millis(10));
    };
    // The observation only means something if the tunnel really is still open, and it is: the
    // client cannot finish until the upstream is released, which happens below.
    assert!(
        !client.is_finished(),
        "the tunnel closed before the capture was observed, so this proves nothing"
    );
    assert!(
        String::from_utf8_lossy(&cap.res_head.bytes).contains("101 Switching Protocols"),
        "{:?}",
        cap.res_head
    );
    assert_eq!(
        log.snapshot(None, None, false).events[0].status,
        Some(101),
        "the status amendment is released with the capture, not at teardown"
    );

    let _ = release.send(());
    let head = client.join().unwrap();
    let _ = up.join();
    assert!(
        head.contains("101 Switching Protocols"),
        "the client completed the handshake: {head:?}"
    );
}

/// An upgrade the upstream declines is not a WebSocket at all — it is an ordinary response, and
/// it is captured like one, body included. Teeth: this branch relays through a different reader
/// than every other response path, so it would be the one to silently miss the tee.
#[test]
fn a_declined_websocket_upgrade_is_captured_like_an_ordinary_response() {
    use crate::sandbox::control::{CaptureLevel, LOG_RING_CAP, LogRing};
    let (addr, upstream_ca, up) = spawn_upstream(
        "upstream.test",
        b"HTTP/1.1 401 Unauthorized\r\nContent-Length: 14\r\n\r\nnot-upgradable",
    );
    let mut roots = RootCertStore::empty();
    roots.add(upstream_ca).unwrap();
    let upstream_cfg = Arc::new(
        ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth(),
    );
    let proxy_ca = Arc::new(Ca::ephemeral().unwrap());
    let proxy_ca_der = proxy_ca.ca_cert_der();
    let log = Arc::new(LogRing::new(LOG_RING_CAP));
    let ctx = capturing_ws_ctx(proxy_ca, upstream_cfg, log.clone(), CaptureLevel::Bodies);

    let transcript =
        through_proxy_websocket(ctx.clone(), proxy_ca_der, "upstream.test", addr.port()).unwrap();
    up.join().unwrap();
    assert!(
        transcript.contains("401") && transcript.contains("not-upgradable"),
        "the declined response was not relayed: {transcript:?}"
    );

    let cap = one_capture(&ctx, &log);
    assert!(
        String::from_utf8_lossy(&cap.res_head.bytes).contains("401 Unauthorized"),
        "{:?}",
        cap.res_head
    );
    assert_eq!(
        cap.res_body.bytes, b"not-upgradable",
        "the declined response's body is captured like any other"
    );
}

/// A signer plugin's own words are answered *into the cage*, so the credential is taken out of
/// them first.
///
/// Every other refusal body is sbx's account of its own policy. This one repeats a third party's,
/// and a signer declaring `reads_secret` holds the credential in clear — so a plugin that named it
/// while explaining why it would not sign would be handing it to the one process that must never
/// have it. The feed applies the same scrub; this sink is the one where it matters.
#[test]
fn a_signer_refusal_answered_into_the_cage_carries_no_credential() {
    let needles = vec![super::SecretNeedle::named(
        "aws",
        b"wJalrXUtnFEMI-the-secret-key".to_vec(),
    )];
    let refusal = super::SignRefusal {
        signer: "aws-sigv4".to_string(),
        why: "cannot sign with wJalrXUtnFEMI-the-secret-key for that region".to_string(),
    };

    let body = super::signer_refusal_message(&refusal, &needles);
    assert!(
        !body.contains("wJalrXUtnFEMI-the-secret-key"),
        "the credential reached the cage: {body}"
    );
    assert!(
        body.contains("****************************"),
        "it is masked in place, as a reflected secret is: {body}"
    );
    // What the refusal exists to say survives the scrub.
    assert!(
        body.contains("`aws-sigv4`") && body.contains("so it was not sent"),
        "{body}"
    );

    // With nothing declared there is nothing to take out, and the plugin's words stand as written.
    let plain = super::signer_refusal_message(&refusal, &[]);
    assert!(plain.contains("wJalrXUtnFEMI-the-secret-key"), "{plain}");
}

/// Both planes answer a refusal with the same sentence.
///
/// The HTTP/1.1 planes serialize the body themselves and the HTTP/2 plane sends it as a DATA
/// frame, so the text is the only thing they share and the only thing that can drift. A caller
/// must not learn a different explanation for the same refusal depending on which protocol
/// version it happened to speak to the proxy over, which is the shape the signer refusal had
/// before: written on one plane, dropped on the other.
#[test]
fn a_refusal_says_the_same_thing_whichever_plane_answers_it() {
    let refusal = super::SignRefusal {
        signer: "aws-sigv4".to_string(),
        why: "this request carries a body".to_string(),
    };
    let detail = super::signer_refusal_message(&refusal, &[]);

    // What the HTTP/1.1 planes put on the wire, taken from the wire.
    let mut written = Vec::new();
    super::write_refusal(&mut written, "403 Forbidden", "signer-refused", &detail).unwrap();
    let written = String::from_utf8(written).unwrap();
    let (head, body) = written.split_once("\r\n\r\n").expect("a head and a body");

    // What the HTTP/2 plane sends as its DATA frame.
    assert_eq!(body, super::refusal_body(&detail));
    assert_eq!(
        head.matches(&format!("Content-Length: {}", body.len()))
            .count(),
        1,
        "the length framing must describe the shared body: {head}"
    );
    assert!(
        body.contains("`aws-sigv4`") && body.contains("so it was not sent"),
        "{body}"
    );
}
