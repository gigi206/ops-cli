//! What the egress proxy's forwarding paths cost, measured rather than reasoned about.
//!
//! Every measurement here drives the **real** serve loop over a real Unix socket, with real TLS on
//! both sides — the same code an in-cage request takes. Nothing is stubbed, so a number here moves
//! when the forwarding path moves.
//!
//! Two axes, because they are bounded by different things:
//!
//! - **Per request** ([`per_request_cost`]): connection setup dominates. Every request opens its own
//!   tunnel, and unless the launch reuses upstream connections it opens its own upstream connection
//!   too. This is what a workload issuing many small requests (a package fetch, an API-chatty agent)
//!   pays.
//! - **Per byte** ([`bulk_throughput`]): the copies and the scans the relay performs on a large
//!   body. This is what a workload moving data pays.
//!
//! **Read every figure as CPU cost on one machine with a loopback upstream.** There is no network
//! round trip in any of it, so the connection-setup share reported here is a *floor*: against a real
//! host, each setup additionally costs its round trips, which are one to two orders of magnitude
//! larger than the CPU. A change that looks marginal on these numbers can still be decisive on a
//! real link.
//!
//! They are `#[ignore]`d: they take seconds, they report rather than assert, and a throughput figure
//! is not a pass/fail property. Run them explicitly, in release — a debug rustls measures the
//! compiler's inlining, not the design:
//!
//! ```sh
//! CARGO_PROFILE_RELEASE_LTO=false cargo test --release --bins -- --ignored --nocapture bench
//! ```

use super::ca::CertResolver;
use super::*;
use crate::allowlist::{EgressPolicy, classify};
use crate::testutil::TmpDir;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::os::unix::net::{UnixListener, UnixStream};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::Instant;

use rustls::pki_types::{CertificateDer, ServerName};
use rustls::{
    ClientConfig, ClientConnection, RootCertStore, ServerConfig, ServerConnection, StreamOwned,
};

/// How many requests a per-request measurement issues. Large enough that a stray scheduling hiccup
/// does not dominate, small enough that the whole file runs in seconds.
const REQUESTS: usize = 200;

/// The body one bulk measurement moves through the relay, in bytes. Sized well past any buffer or
/// capture cap so the steady-state copy cost is what is being timed, not the ramp.
const BULK_BYTES: usize = 96 * 1024 * 1024;

/// A policy allowing exactly the given entries.
fn policy(entries: &[&str]) -> EgressPolicy {
    EgressPolicy::new(
        entries.iter().map(|e| classify(e).unwrap()).collect(),
        vec![],
    )
}

/// A loopback TLS upstream that serves request after request on each connection it accepts, as a
/// real keep-alive server does. Reuse cannot be measured against anything else: an upstream that
/// closes after one response makes a proxy that reuses connections indistinguishable from one that
/// does not. Accepts for as long as the process runs.
fn spawn_keepalive_tls_upstream(
    head: String,
    body: Arc<Vec<u8>>,
) -> (SocketAddr, CertificateDer<'static>) {
    let ca = Arc::new(Ca::ephemeral().unwrap());
    let ca_der = ca.ca_cert_der();
    let server_config = Arc::new(
        ServerConfig::builder()
            .with_no_client_auth()
            .with_cert_resolver(Arc::new(CertResolver::new(ca))),
    );
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    thread::spawn(move || {
        while let Ok((sock, _)) = listener.accept() {
            let cfg = server_config.clone();
            let head = head.clone();
            let body = body.clone();
            thread::spawn(move || {
                let Ok(conn) = ServerConnection::new(cfg) else {
                    return;
                };
                let mut tls = StreamOwned::new(conn, sock);
                loop {
                    // A byte-at-a-time head read, so nothing of a following request is swallowed.
                    let mut seen = Vec::new();
                    let mut one = [0u8; 1];
                    loop {
                        match tls.read(&mut one) {
                            Ok(0) | Err(_) => return,
                            Ok(_) => seen.push(one[0]),
                        }
                        if seen.ends_with(b"\r\n\r\n") {
                            break;
                        }
                    }
                    // Consume a declared request body before replying, or its bytes would be read
                    // as the head of the next request on a connection that never closes. Absent on
                    // a bodyless request, which reads zero and is unaffected.
                    if let Some(n) = declared_length(&seen) {
                        let mut body = vec![0u8; n];
                        if tls.read_exact(&mut body).is_err() {
                            return;
                        }
                    }
                    // Head and body in ONE write: two would leave the second held by Nagle on a
                    // connection that never closes, and the delayed ACK that releases it would show
                    // up as ~40 ms of "proxy cost" that belongs to this test upstream.
                    let mut reply = head.as_bytes().to_vec();
                    reply.extend_from_slice(&body);
                    if tls.write_all(&reply).is_err() || tls.flush().is_err() {
                        return;
                    }
                }
            });
        }
    });
    (addr, ca_der)
}

/// The `Content-Length` a raw request head declares, if any. Enough parsing for a test upstream:
/// the proxy forwards exactly one length, having refused anything ambiguous long before here.
fn declared_length(head: &[u8]) -> Option<usize> {
    String::from_utf8_lossy(head)
        .lines()
        .find_map(|l| {
            l.strip_prefix("Content-Length: ")
                .or(l.strip_prefix("content-length: "))
        })
        .and_then(|v| v.trim().parse().ok())
        .filter(|n| *n > 0)
}

/// A loopback TLS upstream that serves `conns` connections, one request each, replying with
/// `head` followed by `body`. It mirrors what the proxy expects of a real upstream: a
/// `Connection: close` response terminated by EOF.
fn spawn_tls_upstream(
    conns: usize,
    head: String,
    body: Arc<Vec<u8>>,
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
        for _ in 0..conns {
            let Ok((sock, _)) = listener.accept() else {
                return;
            };
            let cfg = server_config.clone();
            let head = head.clone();
            let body = body.clone();
            // One thread per connection: the measurement is of the proxy, so the upstream must
            // never be the queue the client waits behind.
            thread::spawn(move || {
                let Ok(conn) = ServerConnection::new(cfg) else {
                    return;
                };
                let mut tls = StreamOwned::new(conn, sock);
                if read_head(&mut tls).is_err() {
                    return;
                }
                let _ = tls.write_all(head.as_bytes());
                let _ = tls.write_all(&body);
                let _ = tls.flush();
            });
        }
    });
    (addr, ca_der, handle)
}

/// The cleartext twin of [`spawn_tls_upstream`], for isolating what the path costs with no TLS
/// anywhere: the difference between the two is the price of the two handshakes.
fn spawn_plain_upstream(conns: usize, head: String, body: Arc<Vec<u8>>) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    thread::spawn(move || {
        for _ in 0..conns {
            let Ok((mut sock, _)) = listener.accept() else {
                return;
            };
            let head = head.clone();
            let body = body.clone();
            thread::spawn(move || {
                if read_head(&mut sock).is_err() {
                    return;
                }
                let _ = sock.write_all(head.as_bytes());
                let _ = sock.write_all(&body);
                let _ = sock.flush();
            });
        }
    });
    addr
}

/// Read the proxy's cleartext `CONNECT` reply, up to and including the blank line. Nothing may be
/// read past it: what follows is the client's own TLS.
fn read_until_blank<S: Read>(sock: &mut S) -> io::Result<String> {
    let mut out = String::new();
    let mut byte = [0u8; 1];
    while !out.ends_with("\r\n\r\n") && !out.ends_with("\n\n") {
        match sock.read(&mut byte)? {
            0 => break,
            _ => out.push(byte[0] as char),
        }
    }
    Ok(out)
}

/// Read a request head up to the blank line, discarding it.
fn read_head<S: Read>(src: &mut S) -> io::Result<()> {
    let mut br = BufReader::new(src);
    let mut line = String::new();
    loop {
        line.clear();
        match br.read_line(&mut line) {
            Ok(0) => return Err(io::Error::from(io::ErrorKind::UnexpectedEof)),
            Err(e) => return Err(e),
            Ok(_) if line == "\r\n" || line == "\n" => return Ok(()),
            Ok(_) => {}
        }
    }
}

/// Start the real serve loop on its own Unix socket and return the path (with the directory that
/// owns it, which must outlive the measurement).
fn serve_on_uds(ctx: Arc<ProxyCtx>) -> (TmpDir, std::path::PathBuf) {
    let dir = TmpDir::new();
    let path = dir.join("proxy.sock");
    let listener = UnixListener::bind(&path).unwrap();
    thread::spawn(move || {
        let _ = serve(listener, ctx);
    });
    (dir, path)
}

/// The client-side TLS config for talking to the proxy's minted leaves.
///
/// Session resumption is **off** on purpose: in the cage each request typically comes from its own
/// short-lived process (a `curl`, a `nix` fetch), which starts with an empty session cache. Leaving
/// rustls's default cache on would let one long-lived client resume with itself and report a
/// handshake cost no in-cage caller actually sees.
fn client_config(proxy_ca: CertificateDer<'static>) -> Arc<ClientConfig> {
    let mut roots = RootCertStore::empty();
    roots.add(proxy_ca).unwrap();
    let mut cfg = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    cfg.resumption = rustls::client::Resumption::disabled();
    Arc::new(cfg)
}

/// One inspected HTTPS request straight onto the proxy's socket — the forwarding cost with nothing
/// in front of it.
fn one_https_request(
    sock_path: &std::path::Path,
    client_cfg: Arc<ClientConfig>,
    host: &str,
    port: u16,
    request: &[u8],
) -> io::Result<usize> {
    one_https_exchange(
        UnixStream::connect(sock_path)?,
        client_cfg,
        host,
        port,
        request,
    )
}

/// The client half of one inspected HTTPS request, over whatever transport already reaches the
/// proxy: `CONNECT`, handshake against the minted leaf, send the request, read to EOF. Returns the
/// number of response bytes read. Split from the socket it rides so the same exchange can be timed
/// with and without the cage's forwarder in the way.
fn one_https_exchange<S: Read + Write>(
    mut sock: S,
    client_cfg: Arc<ClientConfig>,
    host: &str,
    port: u16,
    request: &[u8],
) -> io::Result<usize> {
    write!(sock, "CONNECT {host}:{port} HTTP/1.1\r\n\r\n")?;
    sock.flush()?;
    let established = read_until_blank(&mut sock)?;
    assert!(
        established.contains("200 Connection established"),
        "CONNECT not accepted: {established:?}"
    );
    let name = ServerName::try_from(host.to_string()).unwrap();
    let conn = ClientConnection::new(client_cfg, name).map_err(io::Error::other)?;
    let mut tls = StreamOwned::new(conn, sock);
    tls.write_all(request)?;
    tls.flush().ok();
    drain(&mut tls)
}

/// Kills a spawned helper when the measurement that needed it ends.
struct KillOnDrop(Child);

impl Drop for KillOnDrop {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// The forwarder the cage runs in front of the proxy: `socat TCP-LISTEN:…,fork UNIX-CONNECT:<uds>`.
/// A request crossing it takes the same two hops an in-cage request takes — the namespace is what is
/// missing here, and the namespace is not what costs.
///
/// It forks once per accepted connection, and the client leg is one connection per request by
/// construction, so this is the one per-request cost that does not shrink when upstream connections
/// are reused. Measuring it rather than adding a separately-timed figure to the proxy's own is the
/// point: the two are not obviously additive.
///
/// Returns `None` when `socat` is not installed or does not come up, which drops the figure rather
/// than failing the run — this file reports, and a missing tool is not a result.
fn spawn_cage_forwarder(uds: &std::path::Path) -> Option<(SocketAddr, KillOnDrop)> {
    // Take a port from the kernel, then hand it to socat: `reuseaddr` covers the gap between letting
    // the probe listener go and socat binding the same port.
    let port = TcpListener::bind(("127.0.0.1", 0))
        .ok()?
        .local_addr()
        .ok()?
        .port();
    let child = Command::new("socat")
        .arg(format!("TCP-LISTEN:{port},bind=127.0.0.1,fork,reuseaddr"))
        .arg(format!("UNIX-CONNECT:{}", uds.display()))
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    let guard = KillOnDrop(child);
    let addr = SocketAddr::from(([127, 0, 0, 1], port));
    // Wait for the listener to answer rather than sleeping a guessed interval: a fixed sleep either
    // wastes the run's time or times the process still starting up.
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        if TcpStream::connect(addr).is_ok() {
            return Some((addr, guard));
        }
        thread::sleep(Duration::from_millis(20));
    }
    None
}

/// One cleartext (`http://`) request through the proxy: absolute-form, no `CONNECT`, no TLS.
fn one_http_request(sock_path: &std::path::Path, request: &[u8]) -> io::Result<usize> {
    let mut sock = UnixStream::connect(sock_path)?;
    sock.write_all(request)?;
    sock.flush()?;
    drain(&mut sock)
}

/// One direct TLS request to the upstream, bypassing the proxy entirely — the floor a client pays
/// for the same exchange with nothing inspecting it.
fn one_direct_request(
    addr: SocketAddr,
    cfg: Arc<ClientConfig>,
    host: &str,
    request: &[u8],
) -> io::Result<usize> {
    let sock = TcpStream::connect(addr)?;
    let name = ServerName::try_from(host.to_string()).unwrap();
    let conn = ClientConnection::new(cfg, name).map_err(io::Error::other)?;
    let mut tls = StreamOwned::new(conn, sock);
    tls.write_all(request)?;
    tls.flush().ok();
    drain(&mut tls)
}

/// Read a stream to EOF, counting bytes and holding none of them — a bulk measurement moves more
/// than fits comfortably in memory twice, and the client's own allocation is not what is timed.
fn drain<S: Read>(src: &mut S) -> io::Result<usize> {
    let mut buf = vec![0u8; 64 * 1024];
    let mut total = 0;
    loop {
        match src.read(&mut buf) {
            Ok(0) => return Ok(total),
            Ok(n) => total += n,
            Err(ref e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(total),
            Err(e) => return Err(e),
        }
    }
}

/// Report one per-request figure.
fn report_rate(label: &str, elapsed: Duration, requests: usize) {
    let per = elapsed.as_secs_f64() / requests as f64;
    println!(
        "  {label:<44} {:>8.0} µs/req   {:>7.0} req/s",
        per * 1e6,
        1.0 / per
    );
}

/// Report one throughput figure.
fn report_rate_bytes(label: &str, elapsed: Duration, bytes: usize) {
    let mib = bytes as f64 / (1024.0 * 1024.0);
    println!(
        "  {label:<44} {:>8.0} MiB/s   ({:.2} s for {:.0} MiB)",
        mib / elapsed.as_secs_f64(),
        elapsed.as_secs_f64(),
        mib
    );
}

const SMALL_BODY: &str = "{\"ok\":true}";

/// The head of a small canned response.
fn small_head() -> String {
    format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        SMALL_BODY.len()
    )
}

/// The same head from a server that keeps its connections open — what an upstream has to say before
/// the proxy will reuse its connection at all.
fn small_head_keepalive() -> String {
    format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n",
        SMALL_BODY.len()
    )
}

/// A signer that answers instantly, so what the figures below show is **sbx's** work rather than a
/// plugin's. What a real plugin costs is a round trip to another process and is its own question.
struct NullSigner;

impl crate::sandbox::signer::Signing for NullSigner {
    fn sign(
        &mut self,
        _req: &crate::sandbox::signer::SignRequest<'_>,
    ) -> Result<crate::sandbox::signer::Signature, String> {
        Ok(crate::sandbox::signer::Signature {
            headers: vec![("Authorization".to_string(), "SIG".to_string())],
            label: None,
        })
    }
}

fn signing_injection(digest: bool) -> HeaderInjection {
    HeaderInjection {
        rule: classify("upstream.test:*").unwrap(),
        form: Form::Signed(Signed {
            name: "bench".to_string(),
            sets: vec!["Authorization".to_string()],
            sees: Vec::new(),
            key: "the-key".to_string(),
            marker: None,
            process: Arc::new(std::sync::Mutex::new(NullSigner)),
            body_digest: digest.then_some(crate::plugins::signer::BodyDigest::Sha256),
        }),
    }
}

/// What holding a request body to digest it costs, and what it buys back — on both framings.
///
/// A signer declaring `body_digest` reverses the order of two things: the body is read into memory
/// and hashed *before* the request is signed, where a `Content-Length` body otherwise streams
/// straight to the upstream. That is work added to the request path, so it is measured rather than
/// assumed — and it is not only a cost, because a body the proxy holds is one it can send a second
/// time, which is what lets such a request take a pooled connection at all.
///
/// Two framings, three signer states, because the two framings start from opposite places:
///
/// - A **`Content-Length`** body streams. Holding it is new work, and new pool eligibility.
/// - A **`chunked`** body was already read into memory and re-framed, whatever any signer wanted.
///   Holding it for a digest adds the hash and nothing else, so that column prices the hash alone.
///
/// The gap between the two `no signer` rows is what de-chunking costs over streaming, which nothing
/// measured before either.
#[test]
#[ignore = "a measurement, not an assertion: run explicitly, in release"]
fn held_body_cost() {
    const BODY: usize = 64 * 1024;
    println!(
        "\nheld body cost ({REQUESTS} requests, {} KiB body, pool on, loopback upstream — no RTT)",
        BODY / 1024
    );
    let reply = Arc::new(SMALL_BODY.as_bytes().to_vec());

    let mut framed =
        format!("POST /v1/thing HTTP/1.1\r\nHost: upstream.test\r\nContent-Length: {BODY}\r\n\r\n")
            .into_bytes();
    framed.extend(std::iter::repeat_n(b'x', BODY));

    // One chunk and its terminator: the framing, not the chunk count, is what differs here.
    let mut chunked =
        b"POST /v1/thing HTTP/1.1\r\nHost: upstream.test\r\nTransfer-Encoding: chunked\r\n\r\n"
            .to_vec();
    chunked.extend(format!("{BODY:x}\r\n").into_bytes());
    chunked.extend(std::iter::repeat_n(b'x', BODY));
    chunked.extend_from_slice(b"\r\n0\r\n\r\n");

    for (framing, request) in [("Content-Length", &framed), ("chunked", &chunked)] {
        for (state, injections) in [
            ("no signer", Vec::new()),
            ("a signer, no digest", vec![signing_injection(false)]),
            (
                "a signer asking for the digest",
                vec![signing_injection(true)],
            ),
        ] {
            let (addr, up_ca) = spawn_keepalive_tls_upstream(small_head_keepalive(), reply.clone());
            let proxy_ca = Arc::new(Ca::ephemeral().unwrap());
            let proxy_ca_der = proxy_ca.ca_cert_der();
            let ctx = Arc::new(
                ProxyCtx::new(proxy_ca, policy(&["upstream.test:*"]).with_pool(true))
                    .unwrap()
                    .with_upstream(client_config(up_ca))
                    .with_injections(injections)
                    .with_resolver(Box::new(|_| Ok(vec![IpAddr::from([127, 0, 0, 1])]))),
            );
            let (_dir, sock) = serve_on_uds(ctx);
            let cfg = client_config(proxy_ca_der);
            let started = Instant::now();
            for _ in 0..REQUESTS {
                one_https_request(&sock, cfg.clone(), "upstream.test", addr.port(), request)
                    .unwrap();
            }
            report_rate(&format!("{framing}, {state}"), started.elapsed(), REQUESTS);
        }
    }
}

/// A loopback TLS upstream that accepts a WebSocket upgrade and then writes `frames` binary frames
/// of `payload_len` bytes each, as fast as it can. The handshake is the shape the proxy requires to
/// enter its frame relay at all; what is measured is what happens after it.
fn spawn_ws_bulk_upstream(
    frames: usize,
    payload_len: usize,
) -> (SocketAddr, CertificateDer<'static>) {
    let ca = Arc::new(Ca::ephemeral().unwrap());
    let ca_der = ca.ca_cert_der();
    let server_config = Arc::new(
        ServerConfig::builder()
            .with_no_client_auth()
            .with_cert_resolver(Arc::new(CertResolver::new(ca))),
    );
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    thread::spawn(move || {
        let Ok((sock, _)) = listener.accept() else {
            return;
        };
        let Ok(conn) = ServerConnection::new(server_config) else {
            return;
        };
        let mut tls = StreamOwned::new(conn, sock);
        if read_head(&mut tls).is_err() {
            return;
        }
        if tls
            .write_all(
                b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\
                  Connection: Upgrade\r\nSec-WebSocket-Accept: bench\r\n\r\n",
            )
            .is_err()
        {
            return;
        }
        // One unmasked binary frame with a 64-bit length: server frames are never masked, and the
        // extended length is what a payload this size uses on the wire.
        let mut frame = vec![0x82u8, 127];
        frame.extend_from_slice(&(payload_len as u64).to_be_bytes());
        frame.extend(std::iter::repeat_n(b'x', payload_len));
        for _ in 0..frames {
            if tls.write_all(&frame).is_err() {
                return;
            }
        }
        let _ = tls.flush();
    });
    (addr, ca_der)
}

/// What the WebSocket relay costs per byte, and what decoding its frames aside costs on top.
///
/// The frame relay is its own path: past the `101` the connection is no longer requests and
/// responses, and every byte crosses [`super::websocket`] rather than the HTTP relay measured by
/// [`bulk_throughput`]. What is relayed is byte-exact and never rewritten, so the axis here is not
/// masking — it is the **capture**, which decodes frames into its own buffers and scans those for a
/// configured secret. That is the one thing on this path that reads a byte more than once.
///
/// Note what cannot be measured because it cannot happen: an upgrade to a credential-injected host
/// is refused outright, since past the `101` nothing can be redacted. So there is no
/// "relay carrying a secret" figure to report, by construction rather than by omission.
#[test]
#[ignore = "a measurement, not an assertion: run explicitly, in release"]
fn websocket_throughput() {
    const FRAMES: usize = 512;
    const PAYLOAD: usize = 64 * 1024;
    println!(
        "\nwebsocket relay ({} MiB of frames, loopback upstream, CPU only — no RTT)",
        FRAMES * PAYLOAD / (1024 * 1024)
    );
    use crate::sandbox::control::{CaptureCaps, CaptureLevel, CaptureRing};

    let needles = vec![SecretNeedle::named(
        "bench-token",
        b"BENCH-SECRET-VALUE-0123456789".to_vec(),
    )];

    for label in ["plain frame relay", "with capture = bodies"] {
        let (addr, up_ca) = spawn_ws_bulk_upstream(FRAMES, PAYLOAD);
        let mut roots = RootCertStore::empty();
        roots.add(up_ca).unwrap();
        let upstream_cfg = Arc::new(
            ClientConfig::builder()
                .with_root_certificates(roots)
                .with_no_client_auth(),
        );
        let proxy_ca = Arc::new(Ca::ephemeral().unwrap());
        let proxy_ca_der = proxy_ca.ca_cert_der();
        // A WebSocket needs its own grant: a host allowed for every HTTP method is still
        // method-denied for an upgrade.
        let mut ctx = ProxyCtx::new(proxy_ca, policy(&["{WS} upstream.test:*"]))
            .unwrap()
            .with_upstream(upstream_cfg)
            .with_resolver(Box::new(|_| Ok(vec![IpAddr::from([127, 0, 0, 1])])));
        if label == "with capture = bodies" {
            // The capture is what decodes frames and scans its own copy. Injecting a credential is
            // not the other axis here: an upgrade to a credential-injected host is refused outright,
            // because past the `101` nothing can be redacted.
            ctx = ctx
                .with_capture(Arc::new(CaptureRing::with_needles(
                    CaptureCaps::new(CaptureLevel::Bodies, 64),
                    needles.clone(),
                )))
                .with_redactions(needles.clone());
        }
        let (_dir, path) = serve_on_uds(Arc::new(ctx));
        let cfg = client_config(proxy_ca_der);
        let upgrade = b"GET /ws HTTP/1.1\r\nHost: upstream.test\r\nUpgrade: websocket\r\n\
             Connection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
             Sec-WebSocket-Version: 13\r\n\r\n";
        let started = Instant::now();
        let read = one_https_request(&path, cfg, "upstream.test", addr.port(), upgrade).unwrap();
        report_rate_bytes(label, started.elapsed(), read);
    }
}

/// What one small request costs, and where the cost sits.
///
/// Six figures, each isolating one layer:
///
/// 1. **direct TLS, no proxy** — one handshake and the exchange, the floor for an inspected design.
/// 2. **cleartext through the proxy** — the whole forwarding path with no TLS at all: parsing, the
///    verdict, the upstream dial, the relay.
/// 3. **HTTPS through the proxy** — what a cage request pays with reuse off: two handshakes on top
///    of (2), because both the tunnel and the upstream connection are opened per request.
/// 4. **HTTPS with an upstream that resumes** — the proxy's upstream config is shared across
///    requests, so rustls's session cache is warm after the first; (3) minus (4) is what resumption
///    already saves without any connection being kept.
/// 5. **HTTPS with the upstream connection reused** (`[network] pool`) — the client leg is unchanged,
///    one connection and one handshake per request, so this isolates the upstream handshake alone.
/// 6. **the same, across the cage's forwarder** — (5) with a real `socat …,fork` hop in front of the
///    proxy, which is what an in-cage client crosses. It forks per connection and the client leg is
///    one connection per request, so this cost is fixed per request no matter what the upstream leg
///    does.
///
/// The gap between (2) and (3) prices connection setup on this path, and (4) minus (5) prices the
/// upstream half of it. On loopback those gaps are CPU alone; against a real host each avoided
/// handshake also saves its round trips, so the same change is worth more there than it reads here.
/// (6) minus (5) is the exception and reads the same everywhere: a fork costs what it costs, so its
/// *share* grows as the rest of the path gets cheaper.
#[test]
#[ignore = "a measurement, not an assertion: run explicitly, in release"]
fn per_request_cost() {
    println!("\nper-request cost ({REQUESTS} requests, loopback upstream, CPU only — no RTT)");
    let body = Arc::new(SMALL_BODY.as_bytes().to_vec());
    let request = b"GET /v1/thing HTTP/1.1\r\nHost: upstream.test\r\nAccept: */*\r\n\r\n";

    // 1. Direct TLS to the upstream, nothing in the middle.
    {
        let (addr, up_ca, _h) = spawn_tls_upstream(REQUESTS, small_head(), body.clone());
        let cfg = client_config(up_ca);
        let started = Instant::now();
        for _ in 0..REQUESTS {
            one_direct_request(addr, cfg.clone(), "upstream.test", request).unwrap();
        }
        report_rate("direct TLS, no proxy", started.elapsed(), REQUESTS);
    }

    // 2. Cleartext through the proxy: every step of the path except TLS.
    {
        let addr = spawn_plain_upstream(REQUESTS, small_head(), body.clone());
        let ctx = Arc::new(
            ProxyCtx::new(
                Arc::new(Ca::ephemeral().unwrap()),
                policy(&["http://upstream.test:*"]),
            )
            .unwrap()
            .with_resolver(Box::new(|_| Ok(vec![IpAddr::from([127, 0, 0, 1])]))),
        );
        let (_dir, path) = serve_on_uds(ctx);
        let req = format!(
            "GET http://upstream.test:{}/v1/thing HTTP/1.1\r\nHost: upstream.test\r\nConnection: close\r\n\r\n",
            addr.port()
        );
        let started = Instant::now();
        for _ in 0..REQUESTS {
            one_http_request(&path, req.as_bytes()).unwrap();
        }
        report_rate("cleartext through the proxy", started.elapsed(), REQUESTS);
    }

    // 3 & 4. HTTPS through the proxy, with the upstream session cache cold and warm.
    for (label, resume) in [
        ("HTTPS through the proxy, no upstream resume", false),
        ("HTTPS through the proxy, upstream resumes", true),
    ] {
        let (addr, up_ca, _h) = spawn_tls_upstream(REQUESTS, small_head(), body.clone());
        let mut roots = RootCertStore::empty();
        roots.add(up_ca).unwrap();
        let mut upstream_cfg = ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        if !resume {
            upstream_cfg.resumption = rustls::client::Resumption::disabled();
        }
        let proxy_ca = Arc::new(Ca::ephemeral().unwrap());
        let proxy_ca_der = proxy_ca.ca_cert_der();
        let ctx = Arc::new(
            ProxyCtx::new(proxy_ca, policy(&["upstream.test:*"]))
                .unwrap()
                .with_upstream(Arc::new(upstream_cfg))
                .with_resolver(Box::new(|_| Ok(vec![IpAddr::from([127, 0, 0, 1])]))),
        );
        let (_dir, path) = serve_on_uds(ctx);
        let cfg = client_config(proxy_ca_der);
        let started = Instant::now();
        for _ in 0..REQUESTS {
            one_https_request(&path, cfg.clone(), "upstream.test", addr.port(), request).unwrap();
        }
        report_rate(label, started.elapsed(), REQUESTS);
    }

    // 5 & 6. HTTPS through the proxy reusing the upstream connection, taken twice on the same proxy
    //    and the same upstream in the same run: first straight onto the proxy's socket, then across
    //    the forwarder the cage actually runs. The client leg is unchanged in both — one connection
    //    and one handshake per request — so (5) isolates the upstream handshake the pool removes and
    //    (6) minus (5) is what the forwarder costs on top of it.
    {
        let (addr, up_ca) = spawn_keepalive_tls_upstream(small_head_keepalive(), body.clone());
        let mut roots = RootCertStore::empty();
        roots.add(up_ca).unwrap();
        let mut upstream_cfg = ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        upstream_cfg.resumption = rustls::client::Resumption::disabled();
        let proxy_ca = Arc::new(Ca::ephemeral().unwrap());
        let proxy_ca_der = proxy_ca.ca_cert_der();
        let ctx = Arc::new(
            ProxyCtx::new(proxy_ca, policy(&["upstream.test:*"]).with_pool(true))
                .unwrap()
                .with_upstream(Arc::new(upstream_cfg))
                .with_resolver(Box::new(|_| Ok(vec![IpAddr::from([127, 0, 0, 1])]))),
        );
        let (_dir, path) = serve_on_uds(ctx);
        let cfg = client_config(proxy_ca_der);
        // One warm-up request, so the figure is the steady state rather than the first handshake
        // amortized over the run.
        one_https_request(&path, cfg.clone(), "upstream.test", addr.port(), request).unwrap();
        let started = Instant::now();
        for _ in 0..REQUESTS {
            one_https_request(&path, cfg.clone(), "upstream.test", addr.port(), request).unwrap();
        }
        report_rate(
            "HTTPS through the proxy, upstream reused",
            started.elapsed(),
            REQUESTS,
        );

        let label = "the same, through the cage's forwarder";
        match spawn_cage_forwarder(&path) {
            Some((forwarder, _socat)) => {
                let started = Instant::now();
                for _ in 0..REQUESTS {
                    one_https_exchange(
                        TcpStream::connect(forwarder).unwrap(),
                        cfg.clone(),
                        "upstream.test",
                        addr.port(),
                        request,
                    )
                    .unwrap();
                }
                report_rate(label, started.elapsed(), REQUESTS);
            }
            None => println!("  {label:<44} {:>8}", "skipped: no socat"),
        }
    }
}

/// What one large response costs per byte, and what each inspection layer adds.
///
/// Four figures over the same body:
///
/// 1. **plain relay** — decrypt, copy, re-encrypt, with nothing inspecting the bytes.
/// 2. **with the outbound-leak scan** — the response is scanned for configured secrets, which
///    happens on every response from an injection-target host.
/// 3. **with `capture = bodies`** — the tee that feeds `sbx net logs --with-body`, bounded by the
///    capture cap, so this should converge on (1) once the cap fills.
/// 4. **raw L4 splice** (`tcp://`) — no TLS termination and no inspection at all: the ceiling any
///    inspected path is measured against.
#[test]
#[ignore = "a measurement, not an assertion: run explicitly, in release"]
fn bulk_throughput() {
    use crate::sandbox::control::{CaptureCaps, CaptureLevel, CaptureRing};

    println!(
        "\nbulk throughput ({} MiB per run, loopback upstream, CPU only — no RTT)",
        BULK_BYTES / (1024 * 1024)
    );
    let body = Arc::new(vec![b'x'; BULK_BYTES]);
    let head =
        format!("HTTP/1.1 200 OK\r\nContent-Length: {BULK_BYTES}\r\nConnection: close\r\n\r\n");
    let request = b"GET /bulk HTTP/1.1\r\nHost: upstream.test\r\nAccept: */*\r\n\r\n";

    // A secret long enough to be scanned, chosen so it never occurs in the body.
    let needles = vec![SecretNeedle::named(
        "bench-token",
        b"BENCH-SECRET-VALUE-0123456789".to_vec(),
    )];
    let injection = || {
        HeaderInjection::fixed(
            classify("upstream.test").unwrap(),
            "authorization".to_string(),
            "Bearer BENCH-SECRET-VALUE-0123456789".to_string(),
        )
    };

    for label in [
        "plain relay",
        "with the outbound-leak scan",
        "with capture = bodies",
    ] {
        let (addr, up_ca, _h) = spawn_tls_upstream(1, head.clone(), body.clone());
        let mut roots = RootCertStore::empty();
        roots.add(up_ca).unwrap();
        let upstream_cfg = Arc::new(
            ClientConfig::builder()
                .with_root_certificates(roots)
                .with_no_client_auth(),
        );
        let proxy_ca = Arc::new(Ca::ephemeral().unwrap());
        let proxy_ca_der = proxy_ca.ca_cert_der();
        let mut ctx = ProxyCtx::new(proxy_ca, policy(&["upstream.test:*"]))
            .unwrap()
            .with_upstream(upstream_cfg)
            .with_resolver(Box::new(|_| Ok(vec![IpAddr::from([127, 0, 0, 1])])));
        if label == "with the outbound-leak scan" {
            ctx = ctx
                .with_injections(vec![injection()])
                .with_redactions(needles.clone());
        }
        if label == "with capture = bodies" {
            ctx = ctx.with_capture(Arc::new(CaptureRing::with_needles(
                CaptureCaps::new(CaptureLevel::Bodies, 64),
                vec![],
            )));
        }
        let (_dir, path) = serve_on_uds(Arc::new(ctx));
        let cfg = client_config(proxy_ca_der);
        let started = Instant::now();
        let read = one_https_request(&path, cfg, "upstream.test", addr.port(), request).unwrap();
        let elapsed = started.elapsed();
        assert!(
            read >= BULK_BYTES,
            "{label}: the whole body must arrive, got {read} of {BULK_BYTES}"
        );
        report_rate_bytes(label, elapsed, BULK_BYTES);
    }

    // 4. The raw L4 splice: a `tcp://` rule, so the proxy never terminates TLS. The client speaks
    //    straight to the upstream through the tunnel, which is what the splice is for.
    {
        let (addr, up_ca, _h) = spawn_tls_upstream(1, head.clone(), body.clone());
        let ctx = Arc::new(
            ProxyCtx::new(
                Arc::new(Ca::ephemeral().unwrap()),
                policy(&[&format!("tcp://upstream.test:{}", addr.port())]),
            )
            .unwrap()
            .with_resolver(Box::new(|_| Ok(vec![IpAddr::from([127, 0, 0, 1])]))),
        );
        let (_dir, path) = serve_on_uds(ctx);
        let started = Instant::now();
        let mut sock = UnixStream::connect(&path).unwrap();
        write!(
            sock,
            "CONNECT upstream.test:{} HTTP/1.1\r\n\r\n",
            addr.port()
        )
        .unwrap();
        sock.flush().unwrap();
        let established = read_until_blank(&mut sock).unwrap();
        assert!(
            established.contains("200 Connection established"),
            "CONNECT not accepted for the splice: {established:?}"
        );
        let cfg = client_config(up_ca);
        let name = ServerName::try_from("upstream.test".to_string()).unwrap();
        let conn = ClientConnection::new(cfg, name).unwrap();
        let mut tls = StreamOwned::new(conn, sock);
        tls.write_all(request).unwrap();
        tls.flush().ok();
        let read = drain(&mut tls).unwrap();
        let elapsed = started.elapsed();
        assert!(
            read >= BULK_BYTES,
            "splice: the whole body must arrive, got {read} of {BULK_BYTES}"
        );
        report_rate_bytes("raw L4 splice (tcp://), no inspection", elapsed, BULK_BYTES);
    }
}

/// A loopback HTTP/2 TLS upstream for the measurement: every stream on every connection gets the
/// same one-message answer with a `grpc-status` trailer, and nothing is recorded.
///
/// Its own OS thread and its own runtime, deliberately. The proxy runs each h2 tunnel on a
/// current-thread runtime, and an upstream sharing that runtime would be one blocking call away
/// from starving the timers meant to bound the exchange — which is not a hypothetical, it is what
/// made the first attempt at this measurement stall.
fn spawn_h2_bench_upstream(
    conns: usize,
    body: Arc<Vec<u8>>,
) -> (SocketAddr, CertificateDer<'static>) {
    use bytes::Bytes;
    use http::Response;

    let ca = Arc::new(Ca::ephemeral().unwrap());
    let ca_der = ca.ca_cert_der();
    let mut cfg = ServerConfig::builder()
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(CertResolver::new(ca)));
    cfg.alpn_protocols = vec![b"h2".to_vec()];
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(cfg));
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    listener.set_nonblocking(true).unwrap();
    thread::spawn(move || {
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
                let acceptor = acceptor.clone();
                let body = body.clone();
                live.push(tokio::spawn(async move {
                    // Nagle off, as the proxy sets it on its own side: this upstream writes a head,
                    // a DATA frame and trailers, and a test upstream that lets the second write
                    // wait on a delayed ACK measures Linux, not the proxy.
                    let _ = sock.set_nodelay(true);
                    let Ok(tls) = acceptor.accept(sock).await else {
                        return;
                    };
                    let Ok(mut conn) = h2::server::handshake(tls).await else {
                        return;
                    };
                    while let Some(Ok((_req, mut respond))) = conn.accept().await {
                        let head = Response::builder()
                            .status(200)
                            .header("content-type", "application/grpc")
                            .body(())
                            .unwrap();
                        let Ok(mut send) = respond.send_response(head, false) else {
                            continue;
                        };
                        send.reserve_capacity(body.len());
                        if send
                            .send_data(Bytes::from(body.as_ref().clone()), false)
                            .is_err()
                        {
                            continue;
                        }
                        let mut trailers = http::HeaderMap::new();
                        trailers.insert("grpc-status", "0".parse().unwrap());
                        let _ = send.send_trailers(trailers);
                    }
                }));
            }
            for task in live {
                let _ = task.await;
            }
        });
    });
    (addr, ca_der)
}

/// A TLS client config trusting exactly `ca` and offering ALPN `h2`, for both legs of this plane:
/// without the offer the proxy refuses the tunnel, and refuses the upstream, HTTP/2 being the only
/// thing it speaks here.
fn h2_tls_config(ca: CertificateDer<'static>) -> Arc<ClientConfig> {
    let mut roots = RootCertStore::empty();
    roots.add(ca).unwrap();
    let mut cfg = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    cfg.alpn_protocols = vec![b"h2".to_vec()];
    cfg.resumption = rustls::client::Resumption::disabled();
    Arc::new(cfg)
}

/// Finish an h2 connection over `io`: TLS, then the h2 handshake. Returns the request sender; the
/// connection is driven by a task that ends with the runtime.
async fn h2_over<S>(
    io: S,
    cfg: Arc<ClientConfig>,
    host: &str,
) -> h2::client::SendRequest<bytes::Bytes>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let name = ServerName::try_from(host.to_string()).unwrap();
    let tls = tokio_rustls::TlsConnector::from(cfg)
        .connect(name, io)
        .await
        .unwrap();
    let (send, conn) = h2::client::handshake(tls).await.unwrap();
    tokio::spawn(async move {
        let _ = conn.await;
    });
    send
}

/// Open one h2 tunnel through the proxy: `CONNECT`, then TLS against the minted leaf.
async fn h2_tunnel(
    sock_path: &std::path::Path,
    cfg: Arc<ClientConfig>,
    host: &str,
    port: u16,
) -> h2::client::SendRequest<bytes::Bytes> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let mut sock = tokio::net::UnixStream::connect(sock_path).await.unwrap();
    sock.write_all(format!("CONNECT {host}:{port} HTTP/1.1\r\n\r\n").as_bytes())
        .await
        .unwrap();
    // Read the cleartext reply one byte at a time up to the blank line: what follows it is the
    // client's own TLS, and reading a byte of that here would take it out of the handshake.
    let mut established = Vec::new();
    let mut byte = [0u8; 1];
    while !established.ends_with(b"\r\n\r\n") {
        assert!(sock.read(&mut byte).await.unwrap() > 0, "tunnel closed");
        established.push(byte[0]);
    }
    assert!(
        String::from_utf8_lossy(&established).contains("200 Connection established"),
        "CONNECT not accepted"
    );
    h2_over(sock, cfg, host).await
}

/// One h2 connection straight to the upstream, nothing in the middle.
async fn h2_direct(
    addr: SocketAddr,
    cfg: Arc<ClientConfig>,
    host: &str,
) -> h2::client::SendRequest<bytes::Bytes> {
    let sock = tokio::net::TcpStream::connect(addr).await.unwrap();
    let _ = sock.set_nodelay(true);
    h2_over(sock, cfg, host).await
}

/// One gRPC-shaped stream, read to its trailers. Returns the message bytes received.
async fn one_h2_stream(send: &mut h2::client::SendRequest<bytes::Bytes>, host: &str) -> usize {
    let req = http::Request::builder()
        .method(http::Method::POST)
        .uri(format!("https://{host}/pkg.Svc/Method"))
        .header("content-type", "application/grpc")
        .header("te", "trailers")
        .body(())
        .unwrap();
    let ready = send.clone().ready().await.unwrap();
    *send = ready;
    let (resp, _body) = send.send_request(req, true).unwrap();
    let (_parts, mut body) = resp.await.unwrap().into_parts();
    let mut got = 0;
    while let Some(chunk) = body.data().await {
        let chunk = chunk.unwrap();
        got += chunk.len();
        // Return the window as it is consumed, or a response past the initial one stalls halfway.
        let _ = body.flow_control().release_capacity(chunk.len());
    }
    let _ = body.trailers().await;
    got
}

/// What one gRPC stream costs on the HTTP/2 plane, and what multiplexing does and does not buy.
///
/// This plane had nothing measuring it because, until its harness existed, nothing here could reach
/// an upstream at all. The axis is not bytes: a gRPC message is small and the relay copies it once.
/// It is **connection setup**, and there are two per stream — the client's tunnel and the upstream's.
///
/// The four rows are the same work with those two removed one at a time. Direct means no proxy, so
/// the pair of direct rows prices an h2 connection on this machine and shows what multiplexing is
/// worth when nothing is in the middle. Through the proxy, reusing the tunnel removes the client
/// leg — and only the client leg. This plane opens a TCP connection, a TLS handshake and an h2
/// handshake **for every stream it relays**, multiplexed or not, because it has no upstream pool
/// (the HTTP/1.1 path does, which is what its own pooled row prices). What stays in the last row is
/// therefore that per-stream upstream connection, which no amount of client-side multiplexing folds
/// away.
#[test]
#[ignore = "a measurement, not an assertion: run explicitly, in release"]
fn h2_stream_cost() {
    println!(
        "\nHTTP/2 stream cost ({REQUESTS} streams, {} B message, loopback upstream — no RTT)",
        SMALL_BODY.len()
    );
    let body = Arc::new(SMALL_BODY.as_bytes().to_vec());
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();

    for (label, via_proxy, streams_per_connection) in [
        ("direct h2, one connection per stream", false, 1),
        ("direct h2, all streams on one connection", false, REQUESTS),
        ("through the proxy, one tunnel per stream", true, 1),
        (
            "through the proxy, all streams on one tunnel",
            true,
            REQUESTS,
        ),
    ] {
        // One upstream connection per stream through the proxy, whichever way the client groups
        // them; direct, the client's own grouping is the upstream's.
        let (addr, up_ca) = spawn_h2_bench_upstream(REQUESTS + 4, body.clone());
        let proxy_ca = Arc::new(Ca::ephemeral().unwrap());
        let proxy_ca_der = proxy_ca.ca_cert_der();
        let mut ctx = ProxyCtx::new(
            proxy_ca,
            policy(&["grpc.test:*"]).with_http2(vec![
                crate::allowlist::Http2Host::parse("grpc.test").unwrap(),
            ]),
        )
        .unwrap()
        .with_resolver(Box::new(|_| Ok(vec![IpAddr::from([127, 0, 0, 1])])));
        ctx.upstream_h2 = h2_tls_config(up_ca.clone());
        let (_dir, sock) = serve_on_uds(Arc::new(ctx));
        let cfg = match via_proxy {
            true => h2_tls_config(proxy_ca_der),
            false => h2_tls_config(up_ca),
        };

        let started = Instant::now();
        rt.block_on(async {
            let mut done = 0;
            while done < REQUESTS {
                let mut send = match via_proxy {
                    true => h2_tunnel(&sock, cfg.clone(), "grpc.test", addr.port()).await,
                    false => h2_direct(addr, cfg.clone(), "grpc.test").await,
                };
                for _ in 0..streams_per_connection.min(REQUESTS - done) {
                    assert_eq!(
                        one_h2_stream(&mut send, "grpc.test").await,
                        SMALL_BODY.len()
                    );
                    done += 1;
                }
            }
        });
        report_rate(label, started.elapsed(), REQUESTS);
    }
}
