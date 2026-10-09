//! Reuse of validated upstream TLS connections across in-cage requests.
//!
//! Once a response has been read to the end of its message, the connection to the real server is a
//! working, certificate-validated TLS session that the next request to the same place could use
//! instead of paying for a fresh handshake. This module is where such a connection waits.
//!
//! It holds *upstream* connections only. The client's leg is reused too — an intercepted tunnel
//! serves requests until one leaves it unusable — but that connection never leaves the thread
//! serving it, so it needs no pool: what makes reuse safe there is that every request runs the whole
//! per-request pipeline, not that a connection was admitted anywhere.
//!
//! What it is not: a general-purpose connection cache. Admission is deliberately narrow, and every
//! rule below exists because getting it wrong would hand one request a connection carrying another
//! request's state.
//!
//! - **Partitioned by credential, not only by address.** [`PoolKey`] pairs the host and port with
//!   the exact set of injected credentials the request carried. A connection that carried a secret
//!   is only ever offered to a request that receives the same secret, so reuse can never widen
//!   where a credential has been.
//! - **Only a connection whose position is known.** The relayed response must have ended exactly
//!   where its framing said, with nothing left buffered anywhere — see [`UpstreamPool::park`].
//! - **Bounded in count, not in time.** A parked connection is a held host fd with no thread behind
//!   it, so it sits outside the connection-thread cap that bounds every other holder. [`MAX_PARKED`]
//!   and [`MAX_PER_KEY`] are that bound, in the same shape the rest of the proxy uses. How stale a
//!   connection may be and still be handed over is a separate question, answered by the launch's
//!   idle bound (`[network] idle_timeout`) — the same one the client's tunnel is held for, because
//!   it is the same question asked of the other leg.
//!
//! The residual, stated plainly: an upstream may close a parked connection at any moment. The
//! checkout probe catches that whenever the close has already arrived, which is the overwhelmingly
//! common case, and that idle bound keeps a connection from waiting long enough to make it likely.
//! What remains is the window between the probe and the write — microseconds against an idle period
//! measured in seconds. A request that loses that race gets a `502`, named as such, rather than a
//! silent empty response.

use std::collections::HashMap;
use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use rustls::{ClientConnection, StreamOwned};

/// A validated TLS connection to a real upstream — what the pool holds and hands out.
pub(super) type UpstreamTls = StreamOwned<ClientConnection, RecordTally>;

/// The socket to an upstream, read through a tally of where the TLS records it delivers end.
///
/// rustls takes whatever the socket has into a buffer of its own, and says nothing of the bytes it
/// holds there that do not yet make a whole record. Every byte rustls reads comes through here, from
/// the first of the handshake on, so the tally knows what rustls cannot tell: whether what it was
/// given stops exactly where a record does ([`Self::at_record_boundary`]), or inside one that the
/// rest of has not arrived. A record is a five-byte header — type, version, a big-endian length —
/// and that many bytes of body, in the clear whatever the session encrypts.
///
/// Writes go straight to the socket, and the socket itself is reached through `Deref` for what is
/// asked of it rather than read from it: timeouts, blocking mode, a peek, its address.
pub(super) struct RecordTally {
    sock: TcpStream,
    /// The header of the record being read, as far as it has arrived.
    header: [u8; RECORD_HEADER_LEN],
    /// How many bytes of `header` have arrived; `0` between records and while a body is read.
    header_seen: usize,
    /// How many bytes of the current record's body are still to come.
    body_left: usize,
}

/// A TLS record header: content type, protocol version, and the body's length.
const RECORD_HEADER_LEN: usize = 5;

impl RecordTally {
    /// `sock`, before anything has been read from it.
    pub(super) fn new(sock: TcpStream) -> Self {
        RecordTally {
            sock,
            header: [0; RECORD_HEADER_LEN],
            header_seen: 0,
            body_left: 0,
        }
    }

    /// Whether everything read so far ends exactly where a record does.
    pub(super) fn at_record_boundary(&self) -> bool {
        self.header_seen == 0 && self.body_left == 0
    }

    /// Follow the record framing across `read`, the bytes just delivered.
    fn tally(&mut self, mut read: &[u8]) {
        while !read.is_empty() {
            if self.body_left > 0 {
                let take = self.body_left.min(read.len());
                self.body_left -= take;
                read = &read[take..];
                continue;
            }
            let take = (RECORD_HEADER_LEN - self.header_seen).min(read.len());
            self.header[self.header_seen..self.header_seen + take].copy_from_slice(&read[..take]);
            self.header_seen += take;
            read = &read[take..];
            if self.header_seen == RECORD_HEADER_LEN {
                self.body_left = usize::from(u16::from_be_bytes([self.header[3], self.header[4]]));
                self.header_seen = 0;
            }
        }
    }
}

impl Read for RecordTally {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.sock.read(buf)?;
        self.tally(&buf[..n]);
        Ok(n)
    }
}

impl Write for RecordTally {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.sock.write(buf)
    }

    fn write_vectored(&mut self, bufs: &[io::IoSlice<'_>]) -> io::Result<usize> {
        self.sock.write_vectored(bufs)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.sock.flush()
    }
}

impl std::ops::Deref for RecordTally {
    type Target = TcpStream;

    fn deref(&self) -> &TcpStream {
        &self.sock
    }
}

/// Parked connections per `(host, port, credentials)` key.
const MAX_PER_KEY: usize = 4;

/// Parked connections across every key. Each is a host fd held with no thread behind it, so this is
/// what bounds the pool the way `MAX_CONCURRENT_CONNS` bounds connection threads.
const MAX_PARKED: usize = 64;

/// What partitions the pool: a connection is offered only to a request going to the same host and
/// port **and** carrying the same injected credentials.
///
/// The credentials appear as their positions in `ProxyCtx::injections`, never as their values. The
/// partition has to be exact, and a key is a thing that gets hashed, cloned, and — in a debugger or
/// a panic message — printed; a secret has no business being in one. The positions arrive already
/// ascending from the matcher, so two requests matching the same rules produce the same key.
#[derive(Clone, PartialEq, Eq, Hash)]
pub(super) struct PoolKey {
    host: String,
    port: u16,
    injections: Vec<usize>,
    /// Which generation of the launch's credentials the request carried. The positions above are
    /// exact in *rules* and were therefore equal across a re-resolution: a connection parked while
    /// the old value was in flight stayed on offer to a request carrying the new one. No value goes
    /// in a key — that is the rule this field keeps rather than breaks — so what distinguishes the
    /// two is a count of replacements.
    generation: u64,
}

impl PoolKey {
    pub(super) fn new(host: &str, port: u16, injections: &[usize], generation: u64) -> Self {
        Self {
            host: host.to_string(),
            port,
            injections: injections.to_vec(),
            generation,
        }
    }
}

/// One connection waiting to be reused, with when it started waiting.
struct Parked {
    stream: UpstreamTls,
    since: Instant,
}

/// The parked upstream connections of one launch, shared across every connection thread.
pub(super) struct UpstreamPool {
    idle: Mutex<HashMap<PoolKey, Vec<Parked>>>,
    /// How long a connection may have been waiting and still be reused, from the launch's
    /// `[network] idle_timeout`. Deliberately short by default: upstream keep-alive timeouts run
    /// from a few seconds (Apache's default is 5) to minutes, and a workload that reuse actually
    /// helps — a build fetching from one host — comes back in milliseconds. Waiting longer buys
    /// nothing and only widens the window in which the far side closes first.
    max_idle: Duration,
}

impl UpstreamPool {
    pub(super) fn new(max_idle: Duration) -> Self {
        Self {
            idle: Mutex::new(HashMap::new()),
            max_idle,
        }
    }

    /// Take a live connection for this key, if the pool holds one.
    ///
    /// Candidates are tried newest first: the most recently parked connection has had the least time
    /// to be closed by the far side, and taking it leaves the older ones to age out rather than
    /// keeping every connection marginally alive. Each is probed before it is handed over, and a
    /// connection that fails the probe is dropped here rather than returned to the pool.
    pub(super) fn checkout(&self, key: &PoolKey) -> Option<UpstreamTls> {
        // The expiry walk runs once, ahead of any candidate: it is a walk of the whole map, and
        // repeating it per candidate would make the work under this guard grow with the number of
        // connections that turn out to be dead.
        {
            let mut idle = self.idle.lock().ok()?;
            Self::sweep(&mut idle, self.max_idle);
        }
        // One candidate per lock scope. The probe below is three socket calls, and dropping a
        // candidate that fails it closes a TCP connection — neither is the pool's state, and neither
        // belongs under the pool's mutex. That mutex is shared by every proxy thread of a launch and
        // [`Self::park`] takes it at the end of every relayed response, so a syscall held under it is
        // a syscall the next request waits behind. `park` already probes before it locks; this is the
        // same discipline on the taking side.
        loop {
            let parked = {
                let mut idle = self.idle.lock().ok()?;
                idle.get_mut(key)?.pop()?
            };
            if still_live(&parked.stream.sock) {
                return Some(parked.stream);
            }
        }
    }

    /// Offer a finished connection back to the pool. It is kept only if it is genuinely idle and
    /// there is room; otherwise it is dropped here, which closes it.
    ///
    /// The caller has already decided the *HTTP* question — that the response ended where its
    /// framing said and left the connection reusable. What this settles is the *socket* question:
    /// whether anything at all is still pending on it. The proxy's own buffered reader is drained
    /// by the caller before it gets here; a non-blocking read through the TLS session then takes
    /// what the kernel holds into rustls and answers for rustls's decrypted plaintext, and the
    /// socket's [`RecordTally`] answers for what rustls holds and cannot decrypt yet: the start of a
    /// record whose rest has not arrived, whether this read or the relay's last one took it in.
    /// `WouldBlock` with nothing left inside a record means all of it is empty; anything else —
    /// bytes, part of a record, an end of stream, an error — means this connection has already
    /// moved on from the message that just finished, and it is not offered to anyone.
    pub(super) fn park(&self, key: PoolKey, mut stream: UpstreamTls, timeout: Duration) {
        // The response relay ran with no read timeout so a streaming completion would not be cut.
        // A connection that is not relaying anything has no such claim, so put the bound back before
        // it waits — and with it the blocking mode the probe below borrows.
        if stream.sock.set_read_timeout(Some(timeout)).is_err() || !is_quiet(&mut stream) {
            return;
        }
        let Ok(mut idle) = self.idle.lock() else {
            return;
        };
        Self::sweep(&mut idle, self.max_idle);
        if idle.values().map(Vec::len).sum::<usize>() >= MAX_PARKED {
            return;
        }
        let slot = idle.entry(key).or_default();
        if slot.len() >= MAX_PER_KEY {
            return;
        }
        slot.push(Parked {
            stream,
            since: Instant::now(),
        });
    }

    /// Drop everything that has waited longer than [`Self::max_idle`], and any key left with nothing
    /// under it. It walks every key rather than the one being asked for, so any use of the pool
    /// clears the connections a host visited once left behind. What it deliberately is not is a
    /// timer: a pool nobody touches again keeps what it holds, and [`MAX_PARKED`] rather than the
    /// clock is what bounds that. Time decides what may be *reused*; count decides what may be
    /// *held*.
    fn sweep(idle: &mut HashMap<PoolKey, Vec<Parked>>, max_idle: Duration) {
        let now = Instant::now();
        idle.retain(|_, slot| {
            slot.retain(|p| now.duration_since(p.since) < max_idle);
            !slot.is_empty()
        });
    }

    /// How many connections are parked right now, across every key.
    #[cfg(test)]
    pub(super) fn len(&self) -> usize {
        match self.idle.lock() {
            Ok(idle) => idle.values().map(Vec::len).sum(),
            Err(_) => 0,
        }
    }
}

/// Whether a parked connection still looks live, by a non-blocking peek at the raw socket. Anything
/// readable means the upstream spoke while the connection sat idle, and at that point the only thing
/// it has to say is that it is going away. The peek does not consume, which costs nothing: a
/// connection that fails this check is dropped either way.
fn still_live(sock: &TcpStream) -> bool {
    if sock.set_nonblocking(true).is_err() {
        return false;
    }
    let mut one = [0u8; 1];
    let live = matches!(sock.peek(&mut one), Err(e) if e.kind() == io::ErrorKind::WouldBlock);
    // A socket that cannot be put back into blocking mode must not be handed to a relay that
    // assumes it is.
    sock.set_nonblocking(false).is_ok() && live
}

/// Whether the connection holds nothing beyond the message that just finished — see the reasoning
/// in [`UpstreamPool::park`]. Reading through the TLS session rather than off the socket is what
/// makes this cover rustls's own decrypted buffer, which a large relayed read leaves bytes in, and
/// the tally is what covers the bytes rustls holds and cannot decrypt.
fn is_quiet(stream: &mut UpstreamTls) -> bool {
    if stream.sock.set_nonblocking(true).is_err() {
        return false;
    }
    let mut one = [0u8; 1];
    let quiet = matches!(stream.read(&mut one), Err(e) if e.kind() == io::ErrorKind::WouldBlock)
        && stream.sock.at_record_boundary();
    stream.sock.set_nonblocking(false).is_ok() && quiet
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sandbox::proxy::ca::{Ca, CertResolver};
    use rustls::pki_types::ServerName;
    use rustls::{ClientConfig, RootCertStore, ServerConfig, ServerConnection};
    use std::io::Write;
    use std::net::TcpListener;
    use std::sync::Arc;
    use std::sync::mpsc;
    use std::thread;

    /// A validated client session to a local server that first sends `hello`, then `after` (handed
    /// the server's session and socket) once the client has read it. Returns the client session
    /// once `after` has run.
    fn connected(
        after: impl FnOnce(&mut StreamOwned<ServerConnection, TcpStream>) + Send + 'static,
    ) -> UpstreamTls {
        let ca = Arc::new(Ca::ephemeral().unwrap());
        let mut roots = RootCertStore::empty();
        roots.add(ca.ca_cert_der()).unwrap();
        let server_config = Arc::new(
            ServerConfig::builder()
                .with_no_client_auth()
                .with_cert_resolver(Arc::new(CertResolver::new(ca))),
        );
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let (read_tx, read_rx) = mpsc::channel::<()>();
        let (done_tx, done_rx) = mpsc::channel::<()>();
        thread::spawn(move || {
            let (sock, _) = listener.accept().unwrap();
            let mut tls = StreamOwned::new(ServerConnection::new(server_config).unwrap(), sock);
            tls.write_all(b"hello").unwrap();
            tls.flush().unwrap();
            read_rx.recv().unwrap();
            after(&mut tls);
            done_tx.send(()).unwrap();
            // Held open until the client is done with it.
            let _ = read_rx.recv();
        });
        let client_config = Arc::new(
            ClientConfig::builder()
                .with_root_certificates(roots)
                .with_no_client_auth(),
        );
        let name = ServerName::try_from("upstream.test").unwrap();
        let conn = ClientConnection::new(client_config, name).unwrap();
        let mut client =
            StreamOwned::new(conn, RecordTally::new(TcpStream::connect(addr).unwrap()));
        let mut hello = [0u8; 5];
        client.read_exact(&mut hello).unwrap();
        assert_eq!(&hello, b"hello");
        read_tx.send(()).unwrap();
        done_rx.recv().unwrap();
        // Keep the server's thread (and so its socket) alive past this function.
        std::mem::forget(read_tx);
        client
    }

    /// Wait until the kernel holds bytes for `sock`, so a probe meets them rather than racing them.
    fn wait_readable(sock: &TcpStream) {
        sock.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let mut one = [0u8; 1];
        assert_eq!(sock.peek(&mut one).unwrap(), 1, "the bytes must arrive");
    }

    /// A tally over a socket nothing is read from, so `tally` is driven by hand.
    fn tally() -> RecordTally {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let sock = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        RecordTally::new(sock)
    }

    /// A record header: application data, TLS 1.2 on the wire, `len` bytes of body.
    fn header(len: u16) -> Vec<u8> {
        let mut h = vec![23, 3, 3];
        h.extend_from_slice(&len.to_be_bytes());
        h
    }

    /// The tally follows records however the reads cut them: a header or a body split across two
    /// reads, a record with no body, several records in one read, and a read that stops inside a
    /// header or a body is never at a boundary.
    #[test]
    fn the_tally_finds_where_records_end_however_the_reads_cut_them() {
        let mut t = tally();
        assert!(t.at_record_boundary(), "nothing read yet");

        let mut two = header(3);
        two.extend_from_slice(b"abc");
        two.extend(header(0));
        two.extend(header(2));
        two.extend_from_slice(b"xy");
        t.tally(&two);
        assert!(t.at_record_boundary(), "three whole records in one read");

        let mut one = header(4);
        one.extend_from_slice(b"wxyz");
        for cut in 1..one.len() {
            let mut t = tally();
            t.tally(&one[..cut]);
            assert!(!t.at_record_boundary(), "stopped {cut} bytes in");
            t.tally(&one[cut..]);
            assert!(t.at_record_boundary(), "completed from {cut}");
        }

        let mut t = tally();
        t.tally(&header(0)[..2]);
        assert!(!t.at_record_boundary(), "inside an empty record's header");
        t.tally(&header(0)[2..]);
        assert!(
            t.at_record_boundary(),
            "an empty record ends with its header"
        );
    }

    /// The residual a peek at the socket cannot see: the relay's own read, taking the end of the
    /// message, took in the start of a record past it whose rest has not arrived. The kernel holds
    /// nothing and rustls has nothing to decrypt, and the connection is still not quiet.
    #[test]
    fn a_record_the_last_read_took_half_of_is_not_quiet() {
        let mut client = connected(|tls| {
            tls.conn.writer().write_all(b"world").unwrap();
            let mut bytes = Vec::new();
            tls.conn.write_tls(&mut bytes).unwrap();
            tls.conn.writer().write_all(b"UNSOLICITED").unwrap();
            let mut next = Vec::new();
            tls.conn.write_tls(&mut next).unwrap();
            // One write, so the message and the start of the next record arrive together.
            bytes.extend_from_slice(&next[..next.len() / 2]);
            tls.sock.write_all(&bytes).unwrap();
        });
        let mut world = [0u8; 5];
        client.read_exact(&mut world).unwrap();
        assert_eq!(&world, b"world");
        client.sock.set_nonblocking(true).unwrap();
        let mut one = [0u8; 1];
        assert!(
            matches!(client.sock.peek(&mut one), Err(e) if e.kind() == io::ErrorKind::WouldBlock),
            "the precondition: the kernel holds nothing, the read took it all"
        );
        client.sock.set_nonblocking(false).unwrap();
        assert!(!is_quiet(&mut client));
    }

    #[test]
    fn a_connection_with_nothing_past_the_message_is_quiet() {
        let mut client = connected(|_| {});
        assert!(is_quiet(&mut client));
    }

    /// A TLS record of which only the first part has arrived is bytes past the message, as much as a
    /// whole one: reading it through the session would move it into rustls's buffer and answer
    /// `WouldBlock`, and the rest would then complete it into the next request's response.
    #[test]
    fn a_record_that_has_only_partly_arrived_is_not_quiet() {
        let mut client = connected(|tls| {
            tls.conn.writer().write_all(b"UNSOLICITED").unwrap();
            let mut record = Vec::new();
            tls.conn.write_tls(&mut record).unwrap();
            tls.sock.write_all(&record[..record.len() / 2]).unwrap();
        });
        wait_readable(&client.sock);
        assert!(!is_quiet(&mut client));
    }

    #[test]
    fn a_whole_record_past_the_message_is_not_quiet() {
        let mut client = connected(|tls| {
            tls.write_all(b"UNSOLICITED").unwrap();
            tls.flush().unwrap();
        });
        wait_readable(&client.sock);
        assert!(!is_quiet(&mut client));
    }
}
