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

/// What holding a request body to digest it costs, and what it buys back.
///
/// A signer declaring `body_digest` reverses the order of two things: the body is read into memory
/// and hashed *before* the request is signed, where it otherwise streams straight to the upstream.
/// That is work added to the request path, so it is measured rather than assumed — and it is not
/// only a cost, because a body the proxy holds is one it can send a second time, which is what lets
/// such a request take a pooled connection at all. Before, a `Content-Length` body opened its own
/// upstream connection every time.
///
/// Three figures, each differing from the one above it by exactly one thing:
///
/// 1. **no signer** — the shape before any of this: the body streams, and with reuse on it still
///    opens its own connection every request, because a streamed body cannot be sent again.
/// 2. **a signer, no digest** — (1) plus the per-request signer call, which here costs nothing:
///    this isolates everything the injection machinery does *around* the plugin.
/// 3. **a signer asking for the digest** — (2) plus reading the body into memory and hashing it,
///    minus the upstream handshake it no longer pays, because the request is now poolable.
///
/// (3) minus (2) is the honest price of the feature. That it can come out **negative** is the
/// point: on a link with real round trips the saved handshake is worth far more than the hash, and
/// on loopback it is CPU against CPU.
#[test]
#[ignore = "a measurement, not an assertion: run explicitly, in release"]
fn held_body_cost() {
    const BODY: usize = 64 * 1024;
    println!(
        "\nheld body cost ({REQUESTS} requests, {} KiB body, pool on, loopback upstream — no RTT)",
        BODY / 1024
    );
    let reply = Arc::new(SMALL_BODY.as_bytes().to_vec());
    let mut request =
        format!("POST /v1/thing HTTP/1.1\r\nHost: upstream.test\r\nContent-Length: {BODY}\r\n\r\n")
            .into_bytes();
    request.extend(std::iter::repeat_n(b'x', BODY));

    for (label, injections) in [
        ("no signer, body streams", Vec::new()),
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
            one_https_request(&sock, cfg.clone(), "upstream.test", addr.port(), &request).unwrap();
        }
        report_rate(label, started.elapsed(), REQUESTS);
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
