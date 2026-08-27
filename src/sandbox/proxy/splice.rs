//! The raw L4 (`tcp://`) splice: a tunnel sbx opens and does not read.
//!
//! A `tcp://` allow rule opts a host:port out of inspection entirely, which is what carries a
//! database wire or an ssh session. It keeps the controls a raw stream can carry — the allowlist,
//! host-side DNS, the SSRF guard, the open-splice cap — and loses everything that needs an HTTP head.

use super::*;

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
pub(super) struct SpliceGuard<'a> {
    counter: &'a AtomicUsize,
    count: usize,
}

impl<'a> SpliceGuard<'a> {
    pub(super) fn new(counter: &'a AtomicUsize) -> Self {
        let count = counter.fetch_add(1, Ordering::SeqCst) + 1;
        SpliceGuard { counter, count }
    }

    pub(super) fn count(&self) -> usize {
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
pub(super) fn splice_l4(
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
            crate::sandbox::control::Proto::Tcp,
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
        Ok(ip) => checked_addresses(
            ctx,
            crate::sandbox::control::Proto::Tcp,
            connect_host,
            port,
            None,
            None,
            Some(deciding),
            vec![ip],
        ),
        Err(_) => resolve_checked(
            ctx,
            crate::sandbox::control::Proto::Tcp,
            connect_host,
            port,
            None,
            None,
            Some(deciding),
        ),
    };
    let ips = match checked {
        Ok(ips) => ips,
        Err(refusal) => {
            return write_refusal(
                &mut client,
                refusal.status_line(),
                refusal.tag(),
                &refusal.message(connect_host),
            );
        }
    };

    // Open the raw upstream to a checked address (no TLS, no certificate validation — a raw splice
    // is uninspected by design; the empty netns + the allowlist are the boundary). Every address the
    // guard permitted is tried in turn, under one shared deadline, for the reasons `dial_first`
    // gives; an IP-literal target is a list of one.
    let upstream = match dial_first(&ips, port, ctx) {
        Ok(s) => {
            // Nagle off. A raw splice carries whatever protocol the cage speaks, including
            // interactive ones whose small writes are exactly what Nagle holds back.
            let _ = s.set_nodelay(true);
            s
        }
        Err(_) => {
            ctx.push_log(
                crate::sandbox::control::Proto::Tcp,
                connect_host,
                port,
                None,
                None,
                crate::sandbox::control::LogVerdict::Error,
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
        crate::sandbox::control::Proto::Tcp,
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
    let flow = ctx.register_flow(connect_host, port, crate::sandbox::control::Proto::Tcp);
    splice_copy(client, upstream, flow.up.clone(), flow.down.clone())
}

/// Splice a raw TCP tunnel: copy bytes both directions between the cage `client` and the `upstream`
/// until either side closes, then tear both down so neither copy thread can hang. The per-connection
/// read/write timeouts are cleared first, so an idle long-lived tunnel (an interactive SSH session,
/// say) is not killed mid-session. One direction runs in a spawned thread, the other in this thread;
/// when the first ends, both sockets are shut down fully so the other's blocked read returns and the
/// join always completes (no leaked host thread on a half-open or stalled peer).
pub(super) fn splice_copy(
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
