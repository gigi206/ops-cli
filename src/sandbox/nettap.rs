//! The transparent-capture tap: the cage's proxy-blind traffic, given a name and handed to the
//! same host proxy as everything else.
//!
//! ## Why
//!
//! Under a filtering posture the cage reaches the proxy because sbx points `http_proxy` at the
//! in-cage forwarder ([`super::egress`]). A client that ignores those variables — Node's undici
//! before `NODE_USE_ENV_PROXY`, a library that builds its own dispatcher, a Go binary with its own
//! transport — connects straight to the real address instead, finds no route in the empty network
//! namespace, and dies at `connect(2)`. That failure is correct (nothing leaks) but it is **mute**:
//! `connect` is neither filtered nor notified, so no log names it and the diagnosis falls to the
//! reader of an `EAI_AGAIN`. The cost has been paid per app, in profile prose, and one case
//! (`examples/app/t3code.toml` — a packaged Electron main process constructing its own `Agent`)
//! cannot be reached by any environment variable at all.
//!
//! The tap closes that class. A `nat OUTPUT REDIRECT` rule — installed in the holder's network
//! namespace, which the cage cannot touch — bends every non-loopback TCP connection to a listener
//! on the cage's loopback, and `SO_ORIGINAL_DST` recovers the address the client meant to reach.
//!
//! ## The name is the point
//!
//! An address alone would be a downgrade: the proxy's policy is written against names and paths,
//! and a captured connection carrying only `IP:443` could be matched on host and port at best. So
//! the tap also **answers the cage's DNS**: `udp/53` and `tcp/53` are redirected here, and each
//! queried name is given a synthetic address out of `198.18.0.0/15` ([`FAKE_NET_HIGH`]) that the
//! tap remembers. When the client then connects to that address, the table turns it back into the
//! name, and the tap opens the proxy connection with a synthesized `CONNECT name:port` — the
//! *same* request an obedient client would have sent. Every downstream decision is therefore the
//! ordinary one: path and method matching, the anti-fronting `Host` check, credential injection,
//! the SSRF guard. The tap adds a doorway, never a second policy.
//!
//! A connect whose address is *not* in the table is a client that bypassed DNS (a literal address,
//! or one cached before the cage existed). It is refused, and — unlike today's silent
//! `ENETUNREACH` — the refusal is a line, not a guess.
//!
//! ## Where it runs, and what that costs
//!
//! The tap is forked by the netns holder ([`super::netns`]) **before** it execs `bwrap`, so it
//! lives in the cage's network namespace but keeps the host's mount and pid namespaces: the cage
//! cannot see it, signal it, or reach its files, and it dials the host-side egress socket by its
//! real path. It has no route of its own either — the namespace is the same empty one — so the
//! only way out remains the bound Unix socket, exactly as before.
//!
//! What is new is the surface: a DNS parser, inside the cage's namespace, reading bytes the
//! workload writes. Three invariants hold it, and every one of them is load-bearing:
//!
//! - **Never resolve.** The tap must not call `getaddrinfo` (nor anything that does, such as
//!   `ToSocketAddrs` on a `host:port` string): its own lookups would be redirected to its own DNS
//!   port and deadlock it. Names travel to the proxy as text, over the Unix socket, and nowhere
//!   else. The only address this module ever dials is a filesystem path.
//! - **Never panic.** A malformed query returns `None` and is dropped; no parse unwraps, indexes
//!   past a checked bound, or trusts a length it read.
//! - **Never block without end.** Reads are bounded and time-limited, and the tables are capped.
//!
//! ## Degraded mode
//!
//! Nothing here is required for egress. Where the redirect rules cannot be installed — a kernel
//! without `CONFIG_NF_NAT`, or `kernel.modules_disabled=1` on a hardened host — the launch keeps
//! the environment-variable path alone and says so. The tap is a net under the working path, not a
//! replacement for it: a client that honours `http_proxy` reaches the forwarder on the cage's
//! loopback, which the redirect rule deliberately excludes, so it never touches this code.

use std::collections::{HashMap, HashSet, VecDeque};
use std::ffi::OsString;
use std::io::{self, Read, Write};
use std::net::{Ipv4Addr, Shutdown, SocketAddrV4, TcpListener, TcpStream};
use std::os::fd::AsRawFd;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// The port the redirect rule sends captured TCP to, on the cage's loopback.
///
/// Deliberately adjacent to [`super::egress`]'s forwarder port so the two in-cage entrances read as
/// one range, and equally clear of the ports a workload picks for itself (8080/3000/8000) and of
/// the ephemeral range, which a source port could otherwise collide with.
pub(crate) const TAP_PORT: u16 = 18044;

/// The port the redirect rule sends captured DNS to (both transports).
pub(crate) const TAP_DNS_PORT: u16 = 18045;

/// The high half of the synthetic address range, `198.18.0.0/15` — the block IANA set aside for
/// inter-network benchmarking, so it is never a real destination. It is also already classified as
/// non-public by the proxy's SSRF guard, which means a synthetic address that somehow reached the
/// proxy as a literal would be refused there rather than dialed.
const FAKE_NET_HIGH: [u8; 2] = [198, 18];

/// The most names held at once — a memory bound, not an address bound. Past it the oldest name
/// that has never been connected to is dropped to make room; see [`FakeIps::alloc`] for why a
/// *connected* name is never dropped.
const FAKE_IP_CAP: usize = 8192;

/// The largest index the synthetic range is walked to. Indices are laid into the low two octets, so
/// stopping here keeps every address inside `198.18.0.0/16` — the low half of the block, leaving
/// the high half free for the addresses the wiring step needs to name (the resolver the cage's
/// `resolv.conf` points at) with no risk of collision.
///
/// It is deliberately far larger than [`FAKE_IP_CAP`]: the table holds at most `FAKE_IP_CAP` names
/// at once, but an index is never reused once reclaimed, so the *session* may hand out this many
/// before it runs out and starts answering `SERVFAIL`. Conflating the two would make eviction
/// useless — it would free a table slot the allocator could not then fill.
const FAKE_IP_MAX_INDEX: u32 = 0xffff;

/// The TTL handed out with a synthetic address, in seconds. Short, because the mapping is only
/// meaningful for this session, and a client that re-asks costs one loopback round trip.
const FAKE_TTL: u32 = 5;

/// The largest DNS message accepted on either transport. A UDP query cannot exceed this without
/// EDNS, and the tap answers nothing that needs a bigger one.
const DNS_MAX: usize = 1232;

/// A ceiling on the connections the tap serves at once, across both its accept loops. The cage can
/// open as many as it likes — a proxy-blind client under a retry loop is exactly the shape that
/// arrives in a burst — so the slot travels inside the worker and is released when it ends, the
/// same discipline (and the same ceiling) the host→cage bridge holds itself to.
const MAX_CONCURRENT_CONNS: usize = 512;

/// The most bytes read while waiting for the proxy's response head. A head longer than this is a
/// proxy that is not answering a `CONNECT`, so the connection is dropped rather than pumped.
const HEAD_MAX: usize = 8 * 1024;

/// How long the tap waits for the proxy to answer the synthesized `CONNECT` before giving up. The
/// proxy resolves the name and opens the upstream in this window, so it is generous; it exists to
/// stop a stuck proxy from pinning a thread, not to bound a healthy request.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);

/// `SO_ORIGINAL_DST`, from `<linux/netfilter_ipv4.h>`. Not exposed by `libc` on every target, and a
/// frozen kernel ABI, so it is spelled out here for the same reason the netlink constants are in
/// [`super::netns`].
const SO_ORIGINAL_DST: libc::c_int = 80;

/// The name↔address table that lets a captured connection carry a name.
///
/// Bounded, because a workload can ask for as many names as it likes. Eviction has one rule that
/// is not negotiable: **an address that has been seen in a connect is never dropped.** A client
/// that caches a synthetic address for longer than the tap remembers it would otherwise have its
/// next connection classified as a DNS bypass — a refusal for a client that did nothing wrong. So
/// a connect pins its address, and only names that were resolved and never used are reclaimed.
#[derive(Debug, Default)]
pub(crate) struct FakeIps {
    by_name: HashMap<String, Ipv4Addr>,
    by_ip: HashMap<Ipv4Addr, String>,
    /// Allocation order, oldest first — the candidates for eviction, in the order they are tried.
    order: VecDeque<Ipv4Addr>,
    /// Addresses a connect has been seen for; never evicted.
    pinned: HashSet<Ipv4Addr>,
    /// The next index to hand out, walked upward and never reused within a session.
    next: u32,
}

/// The synthetic address an allocation index stands for, or `None` past [`FAKE_IP_MAX_INDEX`] —
/// the point at which the session has named more hosts than the low half of the range can express.
fn addr_for(idx: u32) -> Option<Ipv4Addr> {
    if idx == 0 || idx > FAKE_IP_MAX_INDEX {
        return None;
    }
    Some(Ipv4Addr::new(
        FAKE_NET_HIGH[0],
        FAKE_NET_HIGH[1],
        ((idx >> 8) & 0xff) as u8,
        (idx & 0xff) as u8,
    ))
}

impl FakeIps {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// The address for `name`, allocating one on first sight. `None` when the table is full of
    /// names that are all pinned — the caller answers `SERVFAIL`, which is the honest reply: the
    /// tap cannot promise an address it would have to take back.
    pub(crate) fn alloc(&mut self, name: &str) -> Option<Ipv4Addr> {
        if let Some(ip) = self.by_name.get(name) {
            return Some(*ip);
        }
        if self.by_ip.len() >= FAKE_IP_CAP && !self.evict_one() {
            return None;
        }
        // Walk to the next index the range can express. `next` only grows, so a reclaimed address
        // is never handed to a second name inside one session — a client holding a stale answer
        // gets a refusal it can be told about, never another host's traffic.
        self.next = self.next.checked_add(1)?;
        let ip = addr_for(self.next)?;
        self.by_name.insert(name.to_string(), ip);
        self.by_ip.insert(ip, name.to_string());
        self.order.push_back(ip);
        Some(ip)
    }

    /// Drop the oldest never-connected name. `false` when every held name is pinned.
    fn evict_one(&mut self) -> bool {
        for _ in 0..self.order.len() {
            let Some(ip) = self.order.pop_front() else {
                return false;
            };
            if self.pinned.contains(&ip) {
                // Keep it, but move it out of the way so the scan terminates.
                self.order.push_back(ip);
                continue;
            }
            if let Some(name) = self.by_ip.remove(&ip) {
                self.by_name.remove(&name);
            }
            return true;
        }
        false
    }

    /// The name a captured address stands for, pinning it so it survives later eviction. `None`
    /// means the client reached this address without asking the tap for it.
    pub(crate) fn claim(&mut self, ip: Ipv4Addr) -> Option<String> {
        let name = self.by_ip.get(&ip)?.clone();
        self.pinned.insert(ip);
        Some(name)
    }

    /// The name an address stands for, without pinning it — for tests and diagnostics.
    #[cfg(test)]
    fn peek(&self, ip: Ipv4Addr) -> Option<&str> {
        self.by_ip.get(&ip).map(String::as_str)
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.by_ip.len()
    }
}

/// A parsed DNS question: the name asked for, its type, and how many bytes the question section
/// occupies after the 12-byte header (so a reply can echo it back verbatim).
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Question {
    pub(crate) name: String,
    pub(crate) qtype: u16,
    pub(crate) qlen: usize,
}

/// `A` — the only record type the tap answers with an address.
const QTYPE_A: u16 = 1;

/// Read the single question out of a query. `None` for anything this tap will not answer: a
/// truncated message, a header that does not carry exactly one question, a compression pointer
/// (illegal in a question and a loop risk), an over-long label or name, or a non-ASCII byte.
///
/// This is the one function in sbx that parses bytes a caged workload chose, so it trusts no length
/// it reads: every index is bounds-checked against the buffer before use, and the total name length
/// is capped at the protocol's own 255.
pub(crate) fn parse_question(buf: &[u8]) -> Option<Question> {
    if buf.len() < 12 || buf.len() > DNS_MAX {
        return None;
    }
    // QDCOUNT must be exactly one: a query with none has nothing to answer, and one with several
    // is not something a resolver in this position needs to serve.
    if u16::from_be_bytes([buf[4], buf[5]]) != 1 {
        return None;
    }
    let mut off = 12usize;
    let mut labels: Vec<&str> = Vec::new();
    let mut total = 0usize;
    loop {
        let len = *buf.get(off)? as usize;
        if len == 0 {
            off += 1;
            break;
        }
        // The two high bits mark a compression pointer. A question is never compressed, and
        // following one is how a parser is made to chase its own tail.
        if len & 0xc0 != 0 || len > 63 {
            return None;
        }
        total += len + 1;
        if total > 255 {
            return None;
        }
        let end = off.checked_add(1)?.checked_add(len)?;
        let label = buf.get(off + 1..end)?;
        if !label.is_ascii() {
            return None;
        }
        labels.push(std::str::from_utf8(label).ok()?);
        off = end;
    }
    let qtype = u16::from_be_bytes([*buf.get(off)?, *buf.get(off + 1)?]);
    // QCLASS follows; it is read only to establish that the question section is complete.
    let _qclass = u16::from_be_bytes([*buf.get(off + 2)?, *buf.get(off + 3)?]);
    let end = off.checked_add(4)?;
    Some(Question {
        name: labels.join("."),
        qtype,
        qlen: end - 12,
    })
}

/// The reply to a parsed question.
///
/// An `A` question with an address gets that address. An `A` question the table could not serve
/// gets `SERVFAIL`, so the client retries rather than caching a "no such host". Every other type —
/// `AAAA`, `HTTPS`/`SVCB`, anything else — gets `NOERROR` with no answer, which is the correct way
/// to say "this name exists, just not with that record": an `NXDOMAIN` would make a dual-stack
/// client treat the whole name as unknown, and an empty `AAAA` is what steers it onto the `A` the
/// tap can actually route.
pub(crate) fn build_answer(query: &[u8], q: &Question, addr: Option<Ipv4Addr>) -> Option<Vec<u8>> {
    let question = query.get(12..12 + q.qlen)?;
    let mut out = Vec::with_capacity(12 + question.len() + 16);
    out.extend_from_slice(query.get(0..2)?); // the query's id, echoed
    let (flags, ancount) = match (q.qtype, addr) {
        // QR=1, RD=1, RA=1, RCODE=0
        (QTYPE_A, Some(_)) => (0x8180u16, 1u16),
        // QR=1, RD=1, RA=1, RCODE=2 (SERVFAIL)
        (QTYPE_A, None) => (0x8182, 0),
        _ => (0x8180, 0),
    };
    out.extend_from_slice(&flags.to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
    out.extend_from_slice(&ancount.to_be_bytes()); // ANCOUNT
    out.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
    out.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT
    out.extend_from_slice(question);
    if let (QTYPE_A, Some(ip)) = (q.qtype, addr) {
        out.extend_from_slice(&[0xc0, 0x0c]); // NAME: a pointer to the question's name
        out.extend_from_slice(&QTYPE_A.to_be_bytes());
        out.extend_from_slice(&1u16.to_be_bytes()); // CLASS: IN
        out.extend_from_slice(&FAKE_TTL.to_be_bytes());
        out.extend_from_slice(&4u16.to_be_bytes()); // RDLENGTH
        out.extend_from_slice(&ip.octets());
    }
    Some(out)
}

/// Serve one query end to end: parse, allocate, encode. `None` when the query is not one this tap
/// answers, in which case the caller drops it without replying — a resolver that says nothing is
/// what a client already knows how to survive.
pub(crate) fn answer_query(query: &[u8], table: &Mutex<FakeIps>) -> Option<Vec<u8>> {
    let q = parse_question(query)?;
    let addr = if q.qtype == QTYPE_A {
        // A poisoned lock means another thread panicked mid-update. The tap answers nothing rather
        // than reading a table whose invariants may be half-applied.
        table.lock().ok()?.alloc(&q.name)
    } else {
        None
    };
    build_answer(query, &q, addr)
}

/// The `CONNECT` a captured connection is introduced with — byte for byte what a proxy-aware
/// client would have sent, so the proxy's tunnelled plane serves it with no special case.
pub(crate) fn synthesize_connect(host: &str, port: u16) -> String {
    format!("CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n\r\n")
}

/// Whether a response head is a success. The proxy answers `200 Connection established`; anything
/// else is a refusal (`403` for a denied rule, `502` for an upstream that would not validate), and
/// the captured connection is dropped rather than pumped — there is no way to explain an HTTP
/// refusal to a client that believes it is already speaking TLS.
pub(crate) fn head_is_success(head: &[u8]) -> bool {
    let Some(line) = head.split(|b| *b == b'\r' || *b == b'\n').next() else {
        return false;
    };
    let Ok(line) = std::str::from_utf8(line) else {
        return false;
    };
    let mut parts = line.split(' ');
    let Some(version) = parts.next() else {
        return false;
    };
    if !version.starts_with("HTTP/1.") {
        return false;
    }
    parts
        .next()
        .and_then(|code| code.parse::<u16>().ok())
        .is_some_and(|code| (200..300).contains(&code))
}

/// Read a response head, stopping at the blank line that ends it. Bounded by [`HEAD_MAX`] and by
/// the socket's read timeout, so neither a silent proxy nor an endless one holds the thread.
fn read_head(stream: &mut UnixStream) -> io::Result<Vec<u8>> {
    let mut head = Vec::with_capacity(128);
    let mut byte = [0u8; 1];
    while head.len() < HEAD_MAX {
        if stream.read(&mut byte)? == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "proxy closed before answering CONNECT",
            ));
        }
        head.push(byte[0]);
        if head.ends_with(b"\r\n\r\n") || head.ends_with(b"\n\n") {
            return Ok(head);
        }
    }
    Err(io::Error::new(
        io::ErrorKind::InvalidData,
        "proxy response head too long",
    ))
}

/// The address a redirected connection was *meant* for, from the conntrack entry the redirect
/// created. Without this the tap would only ever see its own loopback address.
fn original_dst(stream: &TcpStream) -> io::Result<SocketAddrV4> {
    // SAFETY: `sockaddr_in` is a plain C struct of integer fields, so an all-zero value is a valid
    // (if meaningless) instance; `getsockopt` overwrites it before anything reads it.
    let mut addr: libc::sockaddr_in = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
    // SAFETY: `addr` is a live, correctly-sized `sockaddr_in` and `len` states its size, which is
    // the contract `getsockopt` reads and writes back; the fd is owned by `stream` for the call.
    let rc = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_IP,
            SO_ORIGINAL_DST,
            std::ptr::addr_of_mut!(addr).cast::<libc::c_void>(),
            &mut len,
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    if i32::from(addr.sin_family) != libc::AF_INET {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "original destination is not IPv4",
        ));
    }
    Ok(SocketAddrV4::new(
        Ipv4Addr::from(u32::from_be(addr.sin_addr.s_addr)),
        u16::from_be(addr.sin_port),
    ))
}

/// What the tap decided about one captured connection — the unit the diagnostics are written from,
/// and what the tests assert on instead of reading a log line back.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Capture {
    /// The address carried a name; the proxy accepted the synthesized `CONNECT` and the streams
    /// were pumped.
    Proxied { host: String, port: u16 },
    /// The address carried a name and the proxy refused it. The captured connection is closed.
    Refused { host: String, port: u16 },
    /// The client reached an address the tap never handed out — a literal, or one cached from
    /// before this cage. Nothing is dialed.
    Unmapped { addr: SocketAddrV4 },
    /// The connection was made *to* the tap's own port rather than redirected to it, so there is no
    /// destination behind it. `SO_ORIGINAL_DST` does not fail on such a connection — it answers with
    /// the local address — so without this the client would be told it bypassed DNS, which is the
    /// wrong diagnosis for the wrong connection.
    Direct { port: u16 },
    /// The proxy could not be reached or would not answer.
    ProxyUnreachable { host: String, port: u16 },
}

impl Capture {
    /// The one-line diagnostic, in the tap's own voice. Kept next to the variants so a new outcome
    /// cannot be added without a way to say it.
    pub(crate) fn describe(&self) -> String {
        match self {
            Capture::Proxied { host, port } => format!("captured {host}:{port} -> proxy"),
            Capture::Refused { host, port } => {
                format!("captured {host}:{port} -> refused by policy")
            }
            Capture::Unmapped { addr } => format!(
                "captured {addr} -> refused: no name for this address (the client bypassed DNS)"
            ),
            Capture::Direct { port } => {
                format!("refused a direct connection to the tap's own port {port}")
            }
            Capture::ProxyUnreachable { host, port } => {
                format!("captured {host}:{port} -> proxy unreachable")
            }
        }
    }
}

/// Serve one captured connection: turn its address back into a name, introduce it to the proxy,
/// and pump. `dest` is passed in rather than read from the socket so the whole decision can be
/// exercised over an ordinary loopback connection, with no redirect rule and no privilege.
pub(crate) fn serve_capture(
    client: TcpStream,
    dest: SocketAddrV4,
    table: &Mutex<FakeIps>,
    uds: &Path,
) -> Capture {
    // A connection made straight to the tap's port carries no destination: the redirect did not
    // create it, so the "original" address conntrack reports is the tap's own. Refuse it under its
    // own name rather than letting it read as a DNS bypass.
    if dest.ip().is_loopback() {
        let _ = client.shutdown(Shutdown::Both);
        return Capture::Direct { port: dest.port() };
    }
    let Some(host) = table.lock().ok().and_then(|mut t| t.claim(*dest.ip())) else {
        // Nothing is dialed and nothing is written back: the client believes it is already talking
        // to its destination, so a close is the only honest answer.
        let _ = client.shutdown(Shutdown::Both);
        return Capture::Unmapped { addr: dest };
    };
    let port = dest.port();

    let mut proxy = match UnixStream::connect(uds) {
        Ok(s) => s,
        Err(_) => {
            let _ = client.shutdown(Shutdown::Both);
            return Capture::ProxyUnreachable { host, port };
        }
    };
    let _ = proxy.set_read_timeout(Some(CONNECT_TIMEOUT));
    let _ = proxy.set_write_timeout(Some(CONNECT_TIMEOUT));

    let intro = synthesize_connect(&host, port);
    let established = proxy
        .write_all(intro.as_bytes())
        .and_then(|()| proxy.flush())
        .and_then(|()| read_head(&mut proxy));
    let head = match established {
        Ok(head) => head,
        Err(_) => {
            let _ = client.shutdown(Shutdown::Both);
            let _ = proxy.shutdown(Shutdown::Both);
            return Capture::ProxyUnreachable { host, port };
        }
    };
    if !head_is_success(&head) {
        let _ = client.shutdown(Shutdown::Both);
        let _ = proxy.shutdown(Shutdown::Both);
        return Capture::Refused { host, port };
    }

    // The tunnel is open and may idle for as long as the workload wants; the timeouts existed to
    // bound the handshake above, not the stream below.
    let _ = proxy.set_read_timeout(None);
    let _ = proxy.set_write_timeout(None);
    // One definition of the teardown rule: the same pump the host→cage bridge uses, for the same
    // reason its doc comment gives.
    let _ = super::forward::pump_tcp_uds(client, proxy);
    Capture::Proxied { host, port }
}

/// The `__net-tap` subcommand body. `argv` is `[<egress socket path>]`; the ports are the fixed
/// constants above, because the redirect rule that feeds them is built from the same ones.
///
/// Never returns: it serves until the cage exits, at which point the parent-death signal set by the
/// holder takes it down with `bwrap`.
pub(crate) fn run_tap(argv: &[OsString]) -> ! {
    let Some(uds) = argv.first().map(PathBuf::from) else {
        eprintln!("__net-tap: no egress socket given");
        std::process::exit(2);
    };
    let table = Arc::new(Mutex::new(FakeIps::new()));

    match serve(&uds, &table) {
        Ok(()) => std::process::exit(0),
        Err(e) => {
            eprintln!("__net-tap: {e}");
            std::process::exit(1);
        }
    }
}

/// Bind the three listeners and serve them until the process is taken down.
fn serve(uds: &Path, table: &Arc<Mutex<FakeIps>>) -> io::Result<()> {
    let dns_udp = std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, TAP_DNS_PORT))?;
    let dns_tcp = TcpListener::bind((Ipv4Addr::LOCALHOST, TAP_DNS_PORT))?;
    let captured = TcpListener::bind((Ipv4Addr::LOCALHOST, TAP_PORT))?;

    {
        let table = Arc::clone(table);
        std::thread::spawn(move || serve_dns_udp(&dns_udp, &table));
    }
    {
        let table = Arc::clone(table);
        std::thread::spawn(move || serve_dns_tcp(&dns_tcp, &table));
    }
    serve_captured(&captured, table, uds);
    Ok(())
}

/// The UDP resolver. The socket is bound to loopback on purpose: the redirect rewrites the
/// destination to `127.0.0.1`, and replying from that same address is what makes the conntrack
/// entry translate the source back to the address the client sent to. A reply from any other local
/// address would be dropped by the client as coming from the wrong server.
fn serve_dns_udp(sock: &std::net::UdpSocket, table: &Mutex<FakeIps>) {
    let mut buf = [0u8; DNS_MAX];
    loop {
        let Ok((n, peer)) = sock.recv_from(&mut buf) else {
            continue;
        };
        if let Some(reply) = answer_query(&buf[..n], table) {
            let _ = sock.send_to(&reply, peer);
        }
    }
}

/// The TCP resolver, for clients configured with `options use-vc` and for any answer a client
/// retries over TCP. One connection carries **several** queries (RFC 7766), so each is served until
/// the peer closes; serving only the first is a hang for every client that reuses the connection.
fn serve_dns_tcp(listener: &TcpListener, table: &Arc<Mutex<FakeIps>>) {
    let cap = super::conncap::ConnCap::new(MAX_CONCURRENT_CONNS);
    loop {
        let Ok((stream, _)) = listener.accept() else {
            continue;
        };
        // At the ceiling the connection is let go rather than queued: a resolver that answers late
        // is a client that hangs, and the client's own retry is the better wait.
        let Some(slot) = cap.take() else { continue };
        let table = Arc::clone(table);
        super::conncap::spawn_conn("net-tap-dns", move || {
            let _slot = slot;
            let _ = serve_dns_stream(stream, &table);
        });
    }
}

/// Serve one DNS-over-TCP connection: length-prefixed queries, answered in order, until the peer
/// closes. A message the tap does not answer is dropped and the loop continues — a workload cannot
/// take its own resolver down (and with it the cage's egress) by writing rubbish at it.
fn serve_dns_stream(mut stream: TcpStream, table: &Mutex<FakeIps>) -> io::Result<()> {
    let _ = stream.set_read_timeout(Some(CONNECT_TIMEOUT));
    let mut len = [0u8; 2];
    loop {
        // A short read here is the peer closing between messages, which is ordinary.
        if stream.read_exact(&mut len).is_err() {
            return Ok(());
        }
        let n = usize::from(u16::from_be_bytes(len));
        if n > DNS_MAX {
            return Ok(());
        }
        let mut buf = vec![0u8; n];
        if stream.read_exact(&mut buf).is_err() {
            return Ok(());
        }
        if let Some(reply) = answer_query(&buf, table) {
            let framed = u16::try_from(reply.len()).map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidData, "reply too long to frame")
            })?;
            stream.write_all(&framed.to_be_bytes())?;
            stream.write_all(&reply)?;
        }
    }
}

/// The captured-TCP loop.
fn serve_captured(listener: &TcpListener, table: &Arc<Mutex<FakeIps>>, uds: &Path) {
    let cap = super::conncap::ConnCap::new(MAX_CONCURRENT_CONNS);
    loop {
        let (stream, _) = match listener.accept() {
            Ok(pair) => pair,
            Err(e) => {
                super::conncap::accept_backoff("net-tap", &e);
                continue;
            }
        };
        let dest = match original_dst(&stream) {
            Ok(dest) => dest,
            Err(e) => {
                // Without the original destination there is no name and nothing to dial. This is
                // the shape a connection made *directly* to the tap's port takes — the redirect
                // did not create it, so conntrack has nothing to report.
                eprintln!("__net-tap: no original destination ({e}); connection dropped");
                let _ = stream.shutdown(Shutdown::Both);
                continue;
            }
        };
        let Some(slot) = cap.take() else {
            // At the ceiling, closing is the only answer a captured client can read: it believes it
            // is already talking to its destination, so anything written would be protocol noise.
            let _ = stream.shutdown(Shutdown::Both);
            continue;
        };
        let table = Arc::clone(table);
        let uds = uds.to_path_buf();
        super::conncap::spawn_conn("net-tap", move || {
            let _slot = slot;
            let outcome = serve_capture(stream, dest, &table, &uds);
            eprintln!("__net-tap: {}", outcome.describe());
        });
    }
}

#[cfg(test)]
mod tests;
