//! Which program in a cage holds an egress connection.
//!
//! The proxy sees its client as the bytes on a Unix socket. Most of them come through the in-cage
//! forwarder, a `socat` that accepts a TCP connection on the cage's `127.0.0.1` and forks a child to
//! carry it to the proxy's socket, so the process at the other end of that socket is a `socat`
//! child, not the program that asked. This module names the program anyway, from the supervisor's
//! side, where the cage's `/proc` is readable:
//!
//! 1. the peer of the proxy's socket is named by its pidfd ([`super::peer::peer_pid`]);
//! 2. a peer whose executable is the forwarder's is a **relay**: its one live TCP socket accepted
//!    on the proxy port gives both ends of the client's connection, read from its network
//!    namespace's TCP table. A peer that is the capture tap is one too, but it carries every
//!    connection it captured from one process, so it cannot be read the same way: it states both
//!    ends of its client's connection in the request it forwards ([`Stated`]), and that statement
//!    is believed only because the peer is the tap, which runs sbx's own executable and takes the
//!    addresses from `accept(2)` and the capture, never from the cage, and only while the tap still
//!    holds its own end of that connection;
//! 3. the socket with those two ends is found among the descriptors of the processes sharing that
//!    namespace, and every process holding it is a holder;
//! 4. a holder that is the forwarder's executable again is a relay in front of the first: the
//!    in-cage listener of a `tcp://` rule, or the `socat` of the `ProxyCommand` ssh is given. It is
//!    walked through the same way, from its one other live socket, a few relays deep at most. A
//!    relay with no other socket carries its bytes on its standard streams, and is followed to the
//!    processes holding the other ends of those pipes, of which its parent must be one. Every relay
//!    is held to its command line too ([`Carries`]): socat moves bytes only between the two
//!    addresses it was given, so one whose addresses are not an accepted connection or its
//!    standard streams on one side and the way to the proxy on the other is named after nobody;
//! 5. the caller is the holders' executable, named by its SHA-256, and only when every holder runs
//!    the same one: a socket or a pipe shared by two programs is held by neither alone.
//!
//! A peer that is not a relay is the caller itself: a client that talks to the proxy's socket
//! directly holds the connection, so it is the one named. What cannot be named is `None`, and a
//! caller of `None` is never the program a rule names. Every ambiguity on the way, two candidate
//! sockets or a relay holding something it is not known to use, ends in `None`.
//!
//! The walk reads the network namespace of the proxy socket's peer, which is the cage's. A holder in
//! a namespace of its own is not seen, so a cage allowed to create one (`unshare` reopened in its
//! seccomp policy, which denies it by default) can hold a connection where whoever is visible would
//! be named.
//!
//! The tap is told apart by its content, so the statement rests on the cage not being able to run a
//! byte-identical sbx: a cage is given the store paths its own closure needs, which do not hold
//! sbx, and a launch that installs sbx into the cage as one of its packages gives the cage a tap of
//! its own to state connections with. Even then the statement names only a program whose
//! connection that process accepted, since the tap must hold the far end of what it states.
//!
//! The identity is the executable's content, not its path or name: in a cage the agent writes most
//! of what is on its `PATH`, and a copy of one program under another's name is still the first. It
//! is evidence of what was executed, not of what runs: a library loaded into the program, or a
//! descendant writing into its memory, acts as that program. A rule built on it narrows who is
//! handed a credential; it is not a boundary.

use std::collections::{BTreeSet, HashMap};
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::os::unix::fs::MetadataExt;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// The program holding an egress connection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Caller {
    /// One of the holders, by its number in the PID namespace the supervisor's `/proc` belongs to.
    pub(crate) pid: u32,
    /// Its executable, as `/proc/<pid>/exe` names it: a path inside the cage.
    pub(crate) exe: PathBuf,
    /// The SHA-256 of that executable's content, which every holder shares.
    pub(crate) sha256: [u8; 32],
}

/// Both ends of a captured client's connection, as the capture tap states them: `from`, where the
/// client connected from, as `accept(2)` reported it, and `to`, the destination it dialled, as the
/// capture recorded it. Carried in the `CONNECT` the tap synthesizes
/// ([`super::nettap::TAP_SOURCE_HEADER`]) as `<from> <to>`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Stated {
    pub(crate) from: SocketAddr,
    pub(crate) to: SocketAddr,
}

impl Stated {
    /// The statement as the header carries it.
    pub(crate) fn header_value(&self) -> String {
        format!("{} {}", self.from, self.to)
    }

    /// The statement a header value carries, or `None` when it is not two socket addresses.
    pub(crate) fn parse(value: &str) -> Option<Self> {
        let (from, to) = value.trim().split_once(' ')?;
        Some(Self {
            from: from.trim().parse().ok()?,
            to: to.trim().parse().ok()?,
        })
    }
}

/// The `st` value `/proc/net/tcp` gives a listening socket.
const LISTEN: u8 = 0x0A;
/// The `st` values of a connection that is over: `TIME_WAIT` and `CLOSE`.
const OVER: [u8; 2] = [0x06, 0x07];

/// How many relays in front of the first are walked through. The deepest sbx builds is two (a
/// `tcp://` listener, or the `ProxyCommand` relay, in front of the forwarder); a chain longer than
/// this is named after the relay it stops at, which no rule names.
const MAX_RELAYS: usize = 4;

/// The largest executable hashed, in bytes. The cage writes the file, and a sparse one of any size
/// costs it nothing; one past this is not named rather than read by the supervisor to its end.
const HASH_MAX: u64 = 1 << 30;

/// How many executables' hashes are kept. Past it the cache starts over, so a cage running many
/// distinct files costs the supervisor rehashing rather than memory.
const HASHES_KEPT: usize = 1024;

/// Where a relay's bytes come from, as the two addresses on its command line say: socat moves bytes
/// between those two and nowhere else, whatever else it holds, so this is what makes a walk through
/// it sound. Read from `/proc/<pid>/cmdline`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Carries {
    /// A connection it accepted (`TCP-LISTEN:`).
    Accepted,
    /// Its standard input and output (`-` or `STDIO`), and so not its standard error, which carries
    /// its diagnostics alone.
    Stdio,
}

/// What a relay with the command line `argv` carries toward the proxy: one address must lead to it
/// (`PROXY:` or `UNIX-CONNECT:`), the other must be one [`Carries`] names, written bare. Anything
/// else, a file, another descriptor, a second connection, is `None`.
fn carries_from_argv(argv: &[String]) -> Option<Carries> {
    let prefixed = |address: &str, prefix: &str| {
        address
            .get(..prefix.len())
            .is_some_and(|head| head.eq_ignore_ascii_case(prefix))
    };
    let toward = |address: &str| prefixed(address, "PROXY:") || prefixed(address, "UNIX-CONNECT:");
    let [.., first, second] = argv.get(1..)? else {
        return None;
    };
    let other = match (toward(first), toward(second)) {
        (true, false) => second,
        (false, true) => first,
        _ => return None,
    };
    if other == "-" || other.eq_ignore_ascii_case("STDIO") {
        Some(Carries::Stdio)
    } else if prefixed(other, "TCP-LISTEN:") || prefixed(other, "TCP4-LISTEN:") {
        Some(Carries::Accepted)
    } else {
        None
    }
}

/// What the relay `pid` carries, from its command line ([`carries_from_argv`]).
fn relay_carries(pid: u32) -> Option<Carries> {
    let cmdline = std::fs::read(format!("/proc/{pid}/cmdline")).ok()?;
    let argv: Vec<String> = cmdline
        .split(|b| *b == 0)
        .filter(|arg| !arg.is_empty())
        .map(|arg| String::from_utf8_lossy(arg).into_owned())
        .collect();
    carries_from_argv(&argv)
}

/// Where a relay leads, from the socket the walk reached it by.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Onward {
    /// Its one other live socket, accepted from the next hop: that hop is the socket with this
    /// one's ends reversed.
    Client(TcpRow),
    /// No other socket: it carries its bytes on its standard streams.
    Stdio,
}

/// One row of a `/proc/<pid>/net/tcp` or `tcp6` table: the parts the walk reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct TcpRow {
    local: SocketAddr,
    remote: SocketAddr,
    state: u8,
    inode: u64,
}

impl TcpRow {
    /// Whether the row is a connection still carrying, or able to carry, bytes: not a listener and
    /// not one that is over. A half-closed connection still counts, so that a client which closed
    /// its sending side is still a candidate, and two candidates are an ambiguity rather than one.
    fn live(&self) -> bool {
        self.state != LISTEN && !OVER.contains(&self.state) && self.inode != 0
    }
}

/// A hash taken once per file however many connections ask for it at the same moment.
type HashCell = Arc<OnceLock<Option<[u8; 32]>>>;

/// Names the callers of egress connections, holding the hashes it has already taken.
pub(crate) struct Identify {
    /// The SHA-256 of the forwarder's executable, whose processes are walked through rather than
    /// named.
    relay: [u8; 32],
    /// The SHA-256 of the capture tap's executable, sbx's own: a peer running it is believed about
    /// the connection it says it carries.
    tap: [u8; 32],
    /// The cage port the forwarder accepts on.
    proxy_port: u16,
    /// Executable hashes by the identity of the file hashed: device, inode, size and change time.
    /// A file the cage rewrites in place changes its change time, which the cage cannot set, so a
    /// stale entry is never read for a new content.
    hashes: Mutex<HashMap<FileKey, HashCell>>,
    /// How what a relay carries is read: [`relay_carries`], or in a test, where this process plays
    /// the relay with a command line of its own, an answer fixed in advance.
    carries: fn(u32) -> Option<Carries>,
}

impl Identify {
    /// A walker for connections forwarded by the `relay` executable (the host path of the
    /// forwarder sbx provisions) on cage port `proxy_port`, or captured by the `tap` executable. An
    /// error when either cannot be read, since a walker that cannot recognise them would name them
    /// as every caller.
    pub(crate) fn new(relay: &Path, tap: &Path, proxy_port: u16) -> io::Result<Self> {
        Ok(Self {
            relay: sha256_of(relay)?,
            tap: sha256_of(tap)?,
            proxy_port,
            hashes: Mutex::new(HashMap::new()),
            carries: relay_carries,
        })
    }

    /// The program holding the connection whose proxy-side end is `stream`, or `None` when it
    /// cannot be named. `stated` is what the request on `stream` says about its client's
    /// connection, which only a tap peer is believed about.
    pub(crate) fn caller(&self, stream: &UnixStream, stated: Option<Stated>) -> Option<Caller> {
        let peer = super::peer::peer_pid(stream)?;
        let peer_hash = self.exe_hash(peer)?;
        let relayed = peer_hash == self.relay;
        if !relayed && peer_hash != self.tap {
            return self.named(&[peer]);
        }
        let net = net_ns(peer)?;
        let rows = tcp_rows(peer);
        let held = socket_inodes(peer);
        let (local, remote) = if relayed {
            if (self.carries)(peer)? != Carries::Accepted {
                return None;
            }
            let accepted = accepted_on(&rows, &held, self.proxy_port)?;
            (accepted.remote, accepted.local)
        } else {
            let stated = stated?;
            tap_carries(&rows, &held, stated.from)?;
            (stated.from, stated.to)
        };
        let mut inode = client_inode(&rows, local, remote, &held)?;
        let mut holders = holders_of(Held::Socket(inode), &net);
        for _ in 0..MAX_RELAYS {
            let &[relay] = holders.as_slice() else {
                break;
            };
            if self.exe_hash(relay)? != self.relay {
                break;
            }
            let held = socket_inodes(relay);
            match (onward(&rows, &held, inode)?, (self.carries)(relay)?) {
                (Onward::Client(accepted), Carries::Accepted) => {
                    inode = client_inode(&rows, accepted.remote, accepted.local, &held)?;
                    holders = holders_of(Held::Socket(inode), &net);
                }
                (Onward::Stdio, Carries::Stdio) => {
                    holders = stdio_drivers(relay, &net)?;
                    break;
                }
                _ => return None,
            }
        }
        self.named(&holders)
    }

    /// A walker that recognises the relay and the tap by the hashes given, with the hash of each
    /// file in `known` already taken: what a test needs to make its own process a relay without
    /// hashing a test binary of several hundred megabytes.
    #[cfg(test)]
    pub(crate) fn seeded(
        relay: [u8; 32],
        tap: [u8; 32],
        proxy_port: u16,
        known: &[(&Path, [u8; 32])],
    ) -> Self {
        let hashes = known
            .iter()
            .map(|(path, hash)| {
                let cell = Arc::new(OnceLock::new());
                let _ = cell.set(Some(*hash));
                (file_key(&std::fs::metadata(path).unwrap()), cell)
            })
            .collect();
        Self {
            relay,
            tap,
            proxy_port,
            hashes: Mutex::new(hashes),
            carries: |_| Some(Carries::Accepted),
        }
    }

    /// The caller `holders` make: their common executable, or `None` when there is none or they
    /// run more than one.
    fn named(&self, holders: &[u32]) -> Option<Caller> {
        let mut named: Option<Caller> = None;
        for &pid in holders {
            let sha256 = self.exe_hash(pid)?;
            match &named {
                Some(caller) if caller.sha256 != sha256 => return None,
                Some(_) => {}
                None => {
                    named = Some(Caller {
                        pid,
                        exe: std::fs::read_link(format!("/proc/{pid}/exe")).ok()?,
                        sha256,
                    });
                }
            }
        }
        named
    }

    /// The SHA-256 of the executable `pid` runs: from the cache when that file was hashed before,
    /// taken once when several connections ask at the same moment, and `None` for a file past
    /// [`HASH_MAX`].
    fn exe_hash(&self, pid: u32) -> Option<[u8; 32]> {
        let file = std::fs::File::open(format!("/proc/{pid}/exe")).ok()?;
        let meta = file.metadata().ok()?;
        if meta.len() > HASH_MAX {
            return None;
        }
        let cell = {
            let mut hashes = crate::sandbox::locks::locked(&self.hashes);
            if hashes.len() >= HASHES_KEPT && !hashes.contains_key(&file_key(&meta)) {
                hashes.clear();
            }
            Arc::clone(hashes.entry(file_key(&meta)).or_default())
        };
        *cell.get_or_init(|| sha256_read(file, HASH_MAX).ok().flatten())
    }
}

/// What a hash is cached under: device, inode, size, and the change time in seconds and nanoseconds.
type FileKey = (u64, u64, u64, i64, i64);

/// What a hash is cached under: the file's device and inode, and its size and change time, which a
/// rewrite in place changes and the cage cannot set back.
fn file_key(meta: &std::fs::Metadata) -> FileKey {
    (
        meta.dev(),
        meta.ino(),
        meta.size(),
        meta.ctime(),
        meta.ctime_nsec(),
    )
}

/// The SHA-256 of the file at `path`: sbx's own executable or the forwarder's, read whole.
fn sha256_of(path: &Path) -> io::Result<[u8; 32]> {
    sha256_read(std::fs::File::open(path)?, u64::MAX)?
        .ok_or_else(|| io::Error::other("larger than any file read"))
}

/// The SHA-256 of what `file` reads to its end, or `None` once it has read more than `cap` bytes:
/// the length checked before is the length then, and a file that grows while it is read is held to
/// the same bound.
fn sha256_read(file: std::fs::File, cap: u64) -> io::Result<Option<[u8; 32]>> {
    use std::io::Read;
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; 64 * 1024];
    let mut read = 0u64;
    let mut bounded = file.take(cap.saturating_add(1));
    loop {
        match bounded.read(&mut buf) {
            Ok(0) => return Ok(Some(hasher.finalize().into())),
            Ok(n) => {
                read += n as u64;
                if read > cap {
                    return Ok(None);
                }
                hasher.update(&buf[..n]);
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
}

/// The network namespace `pid` runs in, as its `/proc` link names it.
fn net_ns(pid: u32) -> Option<PathBuf> {
    std::fs::read_link(format!("/proc/{pid}/ns/net")).ok()
}

/// A kernel object a descriptor can name, by inode: what the walk looks for among the processes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Held {
    Socket(u64),
    Pipe(u64),
}

impl Held {
    /// The object a descriptor link such as `socket:[1234]` or `pipe:[1234]` names, if it names
    /// one of the two.
    fn of_link(target: &str) -> Option<Self> {
        let inode = |kind: &str| -> Option<u64> {
            target
                .strip_prefix(kind)?
                .strip_prefix(":[")?
                .strip_suffix(']')?
                .parse()
                .ok()
        };
        inode("socket")
            .map(Held::Socket)
            .or_else(|| inode("pipe").map(Held::Pipe))
    }
}

/// The objects `pid`'s descriptors name, by descriptor number.
fn descriptors(pid: u32) -> Vec<(u32, Option<Held>, String)> {
    let Ok(fds) = std::fs::read_dir(format!("/proc/{pid}/fd")) else {
        return Vec::new();
    };
    fds.filter_map(|fd| {
        let fd = fd.ok()?;
        let number = fd.file_name().to_str()?.parse().ok()?;
        let target = std::fs::read_link(fd.path())
            .ok()?
            .to_string_lossy()
            .into_owned();
        Some((number, Held::of_link(&target), target))
    })
    .collect()
}

/// The inodes of the sockets `pid` holds.
fn socket_inodes(pid: u32) -> BTreeSet<u64> {
    descriptors(pid)
        .into_iter()
        .filter_map(|(_, held, _)| match held {
            Some(Held::Socket(inode)) => Some(inode),
            _ => None,
        })
        .collect()
}

/// The TCP rows of the network namespace `pid` runs in, IPv4 and IPv6 alike.
fn tcp_rows(pid: u32) -> Vec<TcpRow> {
    ["tcp", "tcp6"]
        .iter()
        .filter_map(|table| std::fs::read_to_string(format!("/proc/{pid}/net/{table}")).ok())
        .flat_map(|text| parse_tcp_table(&text))
        .collect()
}

/// An address as a `/proc/net/tcp` table writes it: the IP in hexadecimal, as 32-bit words in host
/// byte order, a colon, and the port. An IPv4 address mapped into IPv6 reads as the IPv4 one, so a
/// socket is compared in one spelling whichever table it is in.
fn parse_addr(text: &str) -> Option<SocketAddr> {
    let (ip, port) = text.rsplit_once(':')?;
    let port = u16::from_str_radix(port, 16).ok()?;
    let word = |hex: &str| u32::from_str_radix(hex, 16).ok().map(u32::to_ne_bytes);
    let ip = match ip.len() {
        8 => IpAddr::V4(Ipv4Addr::from(word(ip)?)),
        32 => {
            let mut bytes = [0u8; 16];
            for (i, chunk) in bytes.chunks_mut(4).enumerate() {
                chunk.copy_from_slice(&word(ip.get(i * 8..i * 8 + 8)?)?);
            }
            Ipv6Addr::from(bytes).to_canonical()
        }
        _ => return None,
    };
    Some(SocketAddr::new(ip, port))
}

/// The rows of a `/proc/net/tcp` or `tcp6` table. A line that does not read is skipped: the header,
/// or a format a later kernel adds, says nothing about the connections this walk follows.
fn parse_tcp_table(text: &str) -> Vec<TcpRow> {
    text.lines()
        .filter_map(|line| {
            let fields: Vec<&str> = line.split_whitespace().collect();
            Some(TcpRow {
                local: parse_addr(fields.get(1)?)?,
                remote: parse_addr(fields.get(2)?)?,
                state: u8::from_str_radix(fields.get(3)?, 16).ok()?,
                inode: fields.get(9)?.parse().ok()?,
            })
        })
        .collect()
}

/// The one live socket a relay holds that was accepted on `proxy_port`, or `None` unless there is
/// exactly one, since a relay carrying two connections cannot say which one this is.
fn accepted_on(rows: &[TcpRow], held: &BTreeSet<u64>, proxy_port: u16) -> Option<TcpRow> {
    let accepted: Vec<&TcpRow> = rows
        .iter()
        .filter(|r| r.live() && held.contains(&r.inode) && r.local.port() == proxy_port)
        .collect();
    match accepted.as_slice() {
        [one] => Some(**one),
        _ => None,
    }
}

/// Whether the tap holds its own end of the connection it states a client made from `from`: one
/// live socket whose far end is that address. A statement about a connection the tap is not
/// carrying is not believed.
fn tap_carries(rows: &[TcpRow], held: &BTreeSet<u64>, from: SocketAddr) -> Option<()> {
    let carrying = rows
        .iter()
        .filter(|r| r.live() && held.contains(&r.inode) && r.remote == from)
        .count();
    (carrying == 1).then_some(())
}

/// Where the relay holding `relay_holds` leads from the socket `came_in` the walk reached it by:
/// its one other live socket, or its standard streams when it holds no other socket. `None` when it
/// has more than one, since a relay carrying two connections cannot say which one this is.
fn onward(rows: &[TcpRow], relay_holds: &BTreeSet<u64>, came_in: u64) -> Option<Onward> {
    let others: Vec<&TcpRow> = rows
        .iter()
        .filter(|r| r.live() && r.inode != came_in && relay_holds.contains(&r.inode))
        .collect();
    match others.as_slice() {
        [] => Some(Onward::Stdio),
        [accepted] => Some(Onward::Client(**accepted)),
        _ => None,
    }
}

/// The inode of the client's end of a connection: the one live socket from `local` to `remote` that
/// the relay does not hold itself. `None` when there is none, or more than one, which no single
/// connection could be.
fn client_inode(
    rows: &[TcpRow],
    local: SocketAddr,
    remote: SocketAddr,
    relay_holds: &BTreeSet<u64>,
) -> Option<u64> {
    let found: BTreeSet<u64> = rows
        .iter()
        .filter(|r| {
            r.live() && r.local == local && r.remote == remote && !relay_holds.contains(&r.inode)
        })
        .map(|r| r.inode)
        .collect();
    match found.len() {
        1 => found.into_iter().next(),
        _ => None,
    }
}

/// The processes driving a relay that carries its bytes on its standard streams: those holding the
/// other ends of the pipes its stdin and stdout are, of which its parent must be one.
///
/// Every condition is what makes "the parent drives it" true rather than assumed. Its command line
/// says its bytes go through its stdin and stdout alone ([`Carries::Stdio`], checked by the
/// caller), so what else it holds carries none of them, its standard error included; those two are
/// each a pipe or `/dev/null`, with at least one pipe; and the parent holds one of those pipes, so
/// the program that launched it is on the other end rather than a stranger it was handed to, and
/// anything else is `None`.
fn stdio_drivers(relay: u32, net: &Path) -> Option<Vec<u32>> {
    let mut pipes = Vec::new();
    for (fd, held, target) in descriptors(relay) {
        match (fd, held) {
            (0 | 1, Some(Held::Pipe(inode))) => pipes.push(inode),
            (0 | 1, _) if target == "/dev/null" => {}
            (0 | 1, _) => return None,
            _ => {}
        }
    }
    if pipes.is_empty() {
        return None;
    }
    let mut drivers: Vec<u32> = pipes
        .iter()
        .flat_map(|&inode| holders_of(Held::Pipe(inode), net))
        .filter(|&pid| pid != relay)
        .collect();
    drivers.sort_unstable();
    drivers.dedup();
    let parent = parent_pid(relay)?;
    drivers.contains(&parent).then_some(drivers)
}

/// The parent of `pid`, from the `PPid:` line of its status.
fn parent_pid(pid: u32) -> Option<u32> {
    std::fs::read_to_string(format!("/proc/{pid}/status"))
        .ok()?
        .lines()
        .find_map(|line| line.strip_prefix("PPid:"))?
        .trim()
        .parse()
        .ok()
        .filter(|&ppid| ppid != 0)
}

/// The processes running in the network namespace `net` that hold `object`.
fn holders_of(object: Held, net: &Path) -> Vec<u32> {
    let Ok(procs) = std::fs::read_dir("/proc") else {
        return Vec::new();
    };
    procs
        .filter_map(|entry| entry.ok()?.file_name().to_str()?.parse::<u32>().ok())
        .filter(|&pid| net_ns(pid).as_deref() == Some(net))
        .filter(|&pid| {
            descriptors(pid)
                .iter()
                .any(|(_, held, _)| *held == Some(object))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::net::TcpListener;

    /// A `/proc/net/tcp` excerpt: a listener on 18043, the forwarder's accepted end of one
    /// connection, and the client's end of it, which talks from port 43210.
    const TABLE: &str = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0100007F:467B 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 111 1 0000000000000000 100 0 0 10 0
   1: 0100007F:467B 0100007F:A8CA 01 00000000:00000000 00:00000000 00000000  1000        0 222 1 0000000000000000 20 4 30 10 -1
   2: 0100007F:A8CA 0100007F:467B 01 00000000:00000000 00:00000000 00000000  1000        0 333 1 0000000000000000 20 4 30 10 -1
";

    /// An address on the cage's loopback.
    fn lo(port: u16) -> SocketAddr {
        SocketAddr::from(([127, 0, 0, 1], port))
    }

    /// An established row from `local` to `remote`.
    fn row(local: SocketAddr, remote: SocketAddr, inode: u64) -> TcpRow {
        TcpRow {
            local,
            remote,
            state: 0x01,
            inode,
        }
    }

    #[test]
    fn a_tcp_table_reads_as_addresses_states_and_inodes() {
        let any = SocketAddr::from(([0, 0, 0, 0], 0));
        assert_eq!(
            parse_tcp_table(TABLE),
            vec![
                TcpRow {
                    local: lo(18043),
                    remote: any,
                    state: LISTEN,
                    inode: 111
                },
                row(lo(18043), lo(43210), 222),
                row(lo(43210), lo(18043), 333),
            ]
        );
        // `::1`, and `127.0.0.1` mapped into IPv6, the second read as the IPv4 address it maps.
        let v6 = "  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000000000000000000001000000:467B 0000000000000000FFFF00000100007F:A8CA 01 00000000:00000000 00:00000000 00000000  1000        0 444 1 0000000000000000 20 4 30 10 -1
";
        assert_eq!(
            parse_tcp_table(v6),
            vec![row(
                SocketAddr::from((Ipv6Addr::LOCALHOST, 18043)),
                lo(43210),
                444
            )]
        );
    }

    #[test]
    fn a_tap_statement_reads_back_as_written() {
        let stated = Stated {
            from: lo(43210),
            to: SocketAddr::from(([93, 184, 216, 34], 443)),
        };
        assert_eq!(stated.header_value(), "127.0.0.1:43210 93.184.216.34:443");
        assert_eq!(Stated::parse(&stated.header_value()), Some(stated));
        assert_eq!(Stated::parse("43210"), None);
        assert_eq!(Stated::parse("127.0.0.1:1 nowhere"), None);
    }

    #[test]
    fn a_relay_leads_to_the_one_client_it_carries_and_to_its_socket() {
        let rows = parse_tcp_table(TABLE);
        let relay: BTreeSet<u64> = [111, 222].into();
        let accepted = accepted_on(&rows, &relay, 18043).expect("one accepted connection");
        assert_eq!(accepted.inode, 222);
        assert_eq!(
            client_inode(&rows, accepted.remote, accepted.local, &relay),
            Some(333)
        );
        // A socket from that port to anywhere else is not the relay's client.
        assert_eq!(client_inode(&rows, lo(43210), lo(443), &relay), None);
        // The relay's own end is never the client's.
        assert_eq!(client_inode(&rows, lo(18043), lo(43210), &relay), None);
        // The listener is held too, but it carries nothing.
        assert_eq!(accepted_on(&rows, &[111].into(), 18043), None);
        // A relay that holds two accepted connections cannot say which one this is.
        let mut two = rows.clone();
        two.push(row(lo(18043), lo(40000), 555));
        assert_eq!(accepted_on(&two, &[222, 555].into(), 18043), None);
    }

    /// A client that closed its sending side is still the client, and a second socket with the same
    /// ends on another state is an ambiguity, not a choice between them.
    #[test]
    fn a_half_closed_client_is_still_a_candidate_and_two_are_none() {
        let mut rows = parse_tcp_table(TABLE);
        let relay: BTreeSet<u64> = [222].into();
        rows.iter_mut().find(|r| r.inode == 333).unwrap().state = 0x05; // FIN_WAIT2
        rows.iter_mut().find(|r| r.inode == 222).unwrap().state = 0x08; // CLOSE_WAIT
        let accepted = accepted_on(&rows, &relay, 18043).expect("still carrying");
        assert_eq!(
            client_inode(&rows, accepted.remote, accepted.local, &relay),
            Some(333)
        );
        rows.push(TcpRow {
            state: 0x01,
            ..row(lo(43210), lo(18043), 999)
        });
        assert_eq!(
            client_inode(&rows, accepted.remote, accepted.local, &relay),
            None
        );
        // A connection that is over is no candidate.
        rows.last_mut().unwrap().state = 0x06; // TIME_WAIT
        assert_eq!(
            client_inode(&rows, accepted.remote, accepted.local, &relay),
            Some(333)
        );
    }

    /// The tap is believed only about a connection it holds the far end of, and the client is the
    /// socket with exactly the two ends it states: one from the same port on another address is
    /// someone else's.
    #[test]
    fn a_tap_statement_is_held_to_both_ends_and_to_the_tap_own_socket() {
        let to = SocketAddr::from(([93, 184, 216, 34], 443));
        let other = SocketAddr::from(([127, 0, 0, 2], 43210));
        let rows = vec![
            row(lo(15001), lo(43210), 10),
            row(lo(43210), to, 11),
            row(other, to, 12),
        ];
        let tap: BTreeSet<u64> = [10].into();
        assert_eq!(tap_carries(&rows, &tap, lo(43210)), Some(()));
        assert_eq!(client_inode(&rows, lo(43210), to, &tap), Some(11));
        assert_eq!(client_inode(&rows, other, to, &tap), Some(12));
        assert_eq!(tap_carries(&rows, &tap, other), None);
    }

    /// A relay in front of the forwarder: reached by its socket toward the forwarder, it leads to
    /// the one connection it accepted, or to its standard streams when it holds no other socket.
    #[test]
    fn a_relay_in_front_leads_to_its_accepted_client_or_to_its_standard_streams() {
        // The `tcp://` listener's child holds 444, from port 50000 to the forwarder on 18043, and
        // 555, accepted on 4022 from the client on 51000, which holds 666.
        let mut rows = parse_tcp_table(TABLE);
        rows.extend([
            row(lo(50000), lo(18043), 444),
            row(lo(4022), lo(51000), 555),
            row(lo(51000), lo(4022), 666),
        ]);
        let listener: BTreeSet<u64> = [444, 555].into();
        let Some(Onward::Client(accepted)) = onward(&rows, &listener, 444) else {
            panic!("the listener leads to its client");
        };
        assert_eq!(
            client_inode(&rows, accepted.remote, accepted.local, &listener),
            Some(666)
        );
        // The `ProxyCommand` relay holds only its socket toward the forwarder.
        assert_eq!(onward(&rows, &[444].into(), 444), Some(Onward::Stdio));
        // One carrying two connections names none.
        rows.push(row(lo(4022), lo(52000), 777));
        assert_eq!(onward(&rows, &[444, 555, 777].into(), 444), None);
    }

    /// A relay is walked through only on the addresses sbx gives its relays: an accepted
    /// connection or its standard streams on one side, the way to the proxy on the other.
    #[test]
    fn a_relay_carries_what_its_two_addresses_say_and_nothing_else() {
        let argv = |args: &[&str]| -> Vec<String> {
            std::iter::once("/nix/store/x-socat/bin/socat")
                .chain(args.iter().copied())
                .map(str::to_string)
                .collect()
        };
        let carries = |args: &[&str]| carries_from_argv(&argv(args));
        assert_eq!(
            carries(&[
                "TCP-LISTEN:18043,bind=127.0.0.1,fork,reuseaddr,nodelay",
                "UNIX-CONNECT:/tmp/sbx-egress.sock"
            ]),
            Some(Carries::Accepted)
        );
        assert_eq!(
            carries(&[
                "TCP-LISTEN:4022,bind=127.0.0.2,fork",
                "PROXY:127.0.0.1:db.test:4022,proxyport=18043,nodelay"
            ]),
            Some(Carries::Accepted)
        );
        assert_eq!(
            carries(&["-", "PROXY:127.0.0.1:github.com:22,proxyport=18043"]),
            Some(Carries::Stdio)
        );
        assert_eq!(
            carries(&["-t", "5", "-", "PROXY:127.0.0.1:h:1,proxyport=18043"]),
            Some(Carries::Stdio)
        );
        // Its bytes from elsewhere: standard error, a descriptor, a file, a second listener.
        for other in [
            "FD:2",
            "STDERR",
            "FD:4",
            "OPEN:/tmp/x",
            "-,ignoreeof",
            "TCP:h:1",
        ] {
            assert_eq!(
                carries(&[other, "PROXY:127.0.0.1:h:1,proxyport=18043"]),
                None,
                "{other}"
            );
        }
        assert_eq!(carries(&["-", "-"]), None);
        assert_eq!(carries(&["PROXY:a:b:1", "UNIX-CONNECT:/x"]), None);
        assert_eq!(carries(&["-"]), None);
    }

    /// The bound on what is hashed holds on the read itself, not only on the length seen before it.
    #[test]
    fn a_hash_stops_past_its_bound() {
        let path = std::env::temp_dir().join(format!("sbx-caller-hash-{}", std::process::id()));
        std::fs::write(&path, b"0123456789").unwrap();
        let open = || std::fs::File::open(&path).unwrap();
        let whole = sha256_read(open(), 10).unwrap();
        assert_eq!(whole, Some(Sha256::digest(b"0123456789").into()));
        assert_eq!(sha256_read(open(), 9).unwrap(), None);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn a_process_parent_is_read_from_its_status() {
        assert_eq!(
            parent_pid(std::process::id()),
            Some(std::os::unix::process::parent_id())
        );
        assert_eq!(parent_pid(u32::MAX), None);
    }

    #[test]
    fn a_descriptor_link_names_a_socket_a_pipe_or_nothing() {
        assert_eq!(Held::of_link("socket:[1234]"), Some(Held::Socket(1234)));
        assert_eq!(Held::of_link("pipe:[1234]"), Some(Held::Pipe(1234)));
        assert_eq!(Held::of_link("/dev/null"), None);
        assert_eq!(Held::of_link("socket:[x]"), None);
    }

    /// A relay on its standard streams is followed to whoever holds the other ends of its pipes,
    /// and only when its parent is one of them: here `sleep`, holding a TCP socket and pipes to this
    /// process, which launched it. With those ends let go, or a stream that is not a pipe, nothing.
    #[test]
    fn a_relay_on_its_standard_streams_is_driven_by_its_parent_or_by_nobody() {
        use std::process::{Command, Stdio};
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let spawn = |stdout: Stdio| {
            Command::new("bash")
                .arg("-c")
                .arg(format!("exec 3<>/dev/tcp/127.0.0.1/{port}; exec sleep 30"))
                .stdin(Stdio::piped())
                .stdout(stdout)
                .stderr(Stdio::null())
                .spawn()
                .expect("spawn the relay")
        };
        // The relay's socket, once `exec sleep` has run: by then its descriptors are final.
        let settled = |pid: u32| -> u64 {
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
            loop {
                let exe = std::fs::read_link(format!("/proc/{pid}/exe")).ok();
                let socket = descriptors(pid)
                    .into_iter()
                    .find_map(|(fd, held, _)| match held {
                        Some(Held::Socket(inode)) if fd == 3 => Some(inode),
                        _ => None,
                    });
                if let (Some(exe), Some(socket)) = (exe, socket)
                    && exe.ends_with("sleep")
                {
                    return socket;
                }
                assert!(
                    std::time::Instant::now() < deadline,
                    "the relay never settled"
                );
                std::thread::sleep(std::time::Duration::from_millis(20));
            }
        };
        let net = net_ns(std::process::id()).unwrap();

        let mut piped = spawn(Stdio::piped());
        let _accepted = listener.accept().unwrap();
        settled(piped.id());
        assert_eq!(
            stdio_drivers(piped.id(), &net),
            Some(vec![std::process::id()])
        );
        // Its pipes let go of: nobody drives it, the parent included.
        drop(piped.stdin.take());
        drop(piped.stdout.take());
        assert_eq!(stdio_drivers(piped.id(), &net), None);
        let _ = piped.kill();
        let _ = piped.wait();

        let file = tempfile_stdout();
        let mut filed = spawn(Stdio::from(file));
        let _accepted = listener.accept().unwrap();
        settled(filed.id());
        assert_eq!(stdio_drivers(filed.id(), &net), None);
        let _ = filed.kill();
        let _ = filed.wait();
    }

    /// A file to point a child's stdout at, unlinked so it leaves nothing behind.
    fn tempfile_stdout() -> std::fs::File {
        let path = std::env::temp_dir().join(format!("sbx-caller-{}", std::process::id()));
        let file = std::fs::File::create(&path).unwrap();
        let _ = std::fs::remove_file(&path);
        file
    }

    /// The walk end to end, with this test process as the relay and a `sleep` as the client: the
    /// test accepts the client's TCP connection on a port of its own, as the forwarder accepts one on
    /// the proxy port, and the Unix socket's peer is this process.
    #[test]
    fn a_connection_through_a_relay_is_named_after_the_program_that_opened_it() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let mut client = std::process::Command::new("bash")
            .arg("-c")
            .arg(format!("exec 3<>/dev/tcp/127.0.0.1/{port}; exec sleep 30"))
            .spawn()
            .expect("spawn the client");
        let (mut accepted, _) = listener.accept().unwrap();
        // Written so the client's end is established before it is looked for.
        let _ = accepted.write_all(b"x");
        let (ours, _theirs) = UnixStream::pair().unwrap();

        let this = Path::new("/proc/self/exe");
        let walker = Identify::seeded([7; 32], [0; 32], port, &[(this, [7; 32])]);
        // The client may still be the shell for a moment, before `exec sleep` replaces it.
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        let caller = loop {
            let caller = walker.caller(&ours, None);
            let exe = caller.as_ref().map(|c| c.exe.clone());
            if exe.as_deref().is_some_and(|e| e.ends_with("sleep"))
                || std::time::Instant::now() > deadline
            {
                break caller;
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        };
        let _ = client.kill();
        let _ = client.wait();
        let caller = caller.expect("the client is named");
        assert_eq!(caller.pid, client.id());
        assert!(caller.exe.ends_with("sleep"), "{caller:?}");
        assert_eq!(caller.sha256, sha256_of(&caller.exe).unwrap());
    }

    /// A peer that is neither the forwarder nor the tap is the caller itself, whatever port the
    /// request states.
    #[test]
    fn a_peer_that_is_not_a_relay_is_the_caller() {
        let (ours, _theirs) = UnixStream::pair().unwrap();
        let this = Path::new("/proc/self/exe");
        let walker = Identify::seeded([1; 32], [2; 32], 18043, &[(this, [9; 32])]);
        let caller = walker
            .caller(
                &ours,
                Some(Stated {
                    from: lo(1),
                    to: lo(2),
                }),
            )
            .expect("this process is named");
        assert_eq!(caller.pid, std::process::id());
        assert_eq!(caller.sha256, [9; 32]);
    }

    /// The tap's case: this process plays the tap, holding an accepted connection, and is believed
    /// about the two ends of its client's connection; without that statement nothing is named,
    /// since a tap carries many connections.
    #[test]
    fn a_tap_peer_is_followed_to_the_port_it_states_and_no_further_without_one() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let mut client = std::process::Command::new("bash")
            .arg("-c")
            .arg(format!("exec 3<>/dev/tcp/127.0.0.1/{port}; exec sleep 30"))
            .spawn()
            .expect("spawn the client");
        let (accepted, from) = listener.accept().unwrap();
        let (ours, _theirs) = UnixStream::pair().unwrap();
        let this = Path::new("/proc/self/exe");
        let walker = Identify::seeded([0; 32], [7; 32], 18043, &[(this, [7; 32])]);
        assert_eq!(
            walker.caller(&ours, None),
            None,
            "a tap peer that states nothing"
        );

        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        let caller = loop {
            let stated = Stated {
                from,
                to: listener.local_addr().unwrap(),
            };
            let caller = walker.caller(&ours, Some(stated));
            if caller.as_ref().is_some_and(|c| c.exe.ends_with("sleep"))
                || std::time::Instant::now() > deadline
            {
                break caller;
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        };
        drop(accepted);
        let _ = client.kill();
        let _ = client.wait();
        let caller = caller.expect("the tap's client is named");
        assert_eq!(caller.pid, client.id());
    }
}
