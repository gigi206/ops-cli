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
//! common case, and [`MAX_IDLE`] keeps a connection from waiting long enough to make it likely. What
//! remains is the window between the probe and the write — microseconds against an idle period
//! measured in seconds. A request that loses that race gets a `502`, named as such, rather than a
//! silent empty response.

use std::collections::HashMap;
use std::io::{self, Read};
use std::net::TcpStream;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use rustls::{ClientConnection, StreamOwned};

/// A validated TLS connection to a real upstream — what the pool holds and hands out.
pub(super) type UpstreamTls = StreamOwned<ClientConnection, TcpStream>;

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
}

impl PoolKey {
    pub(super) fn new(host: &str, port: u16, injections: &[usize]) -> Self {
        Self {
            host: host.to_string(),
            port,
            injections: injections.to_vec(),
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
        let mut idle = self.idle.lock().ok()?;
        Self::sweep(&mut idle, self.max_idle);
        let slot = idle.get_mut(key)?;
        while let Some(parked) = slot.pop() {
            if still_live(&parked.stream.sock) {
                return Some(parked.stream);
            }
        }
        None
    }

    /// Offer a finished connection back to the pool. It is kept only if it is genuinely idle and
    /// there is room; otherwise it is dropped here, which closes it.
    ///
    /// The caller has already decided the *HTTP* question — that the response ended where its
    /// framing said and left the connection reusable. What this settles is the *socket* question:
    /// whether anything at all is still pending on it. One non-blocking read through the TLS session
    /// answers that for all three places bytes can hide — the proxy's own buffered reader is drained
    /// by the caller before it gets here, while rustls's decrypted plaintext and the kernel's
    /// receive queue are both reached by this single read. `WouldBlock` means all three are empty;
    /// anything else — bytes, an end of stream, an error — means this connection has already moved
    /// on from the message that just finished, and it is not offered to anyone.
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
/// makes this cover rustls's own decrypted buffer, which a large relayed read leaves bytes in.
fn is_quiet(stream: &mut UpstreamTls) -> bool {
    if stream.sock.set_nonblocking(true).is_err() {
        return false;
    }
    let mut one = [0u8; 1];
    let quiet = matches!(stream.read(&mut one), Err(e) if e.kind() == io::ErrorKind::WouldBlock);
    stream.sock.set_nonblocking(false).is_ok() && quiet
}
