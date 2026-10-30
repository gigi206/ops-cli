//! Which program in a cage holds an egress connection.
//!
//! The proxy sees its client as the bytes on a Unix socket. Most of them come through the in-cage
//! forwarder, a `socat` that accepts a TCP connection on the cage's `127.0.0.1` and forks a child to
//! carry it to the proxy's socket, so the process at the other end of that socket is a `socat`
//! child, not the program that asked. This module names the program anyway, from the supervisor's
//! side, where the cage's `/proc` is readable:
//!
//! 1. the peer of the proxy's socket is named by its pidfd ([`super::peer::peer_pid`]);
//! 2. a peer whose executable is the forwarder's is a **relay**: its own TCP socket, accepted on the
//!    proxy port, gives the client's source port, read from its network namespace's TCP table. A
//!    peer that is the capture tap is one too, but it carries every connection it captured from one
//!    process, so it cannot be read the same way: it states the client's source port in the request
//!    it forwards, and that statement is believed only because the peer is the tap, which runs sbx's
//!    own executable and takes the port from `accept(2)`, never from the cage;
//! 3. the socket bound to that port is found among the descriptors of the processes sharing that
//!    namespace, and every process holding it is a holder;
//! 4. the caller is the holders' executable, named by its SHA-256, and only when every holder runs
//!    the same one: a socket shared by two programs is held by neither alone.
//!
//! A peer that is not a relay is the caller itself: a client that talks to the proxy's socket
//! directly holds the connection, so it is the one named. What cannot be named is `None`, and a
//! caller of `None` is never the program a rule names.
//!
//! The identity is the executable's content, not its path or name: in a cage the agent writes most
//! of what is on its `PATH`, and a copy of one program under another's name is still the first. It
//! is evidence of what was executed, not of what runs: a library loaded into the program, or a
//! descendant writing into its memory, acts as that program. A rule built on it narrows who is
//! handed a credential; it is not a boundary.

use std::collections::{BTreeSet, HashMap};
use std::io;
use std::os::unix::fs::MetadataExt;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

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

/// The `st` value `/proc/net/tcp` gives an established connection.
const ESTABLISHED: u8 = 0x01;

/// One row of a `/proc/<pid>/net/tcp` or `tcp6` table: the parts the walk reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct TcpRow {
    local_port: u16,
    remote_port: u16,
    state: u8,
    inode: u64,
}

/// Names the callers of egress connections, holding the hashes it has already taken.
pub(crate) struct Identify {
    /// The SHA-256 of the forwarder's executable, whose processes are walked through rather than
    /// named.
    relay: [u8; 32],
    /// The SHA-256 of the capture tap's executable, sbx's own: a peer running it is believed about
    /// the port it says its client connected from.
    tap: [u8; 32],
    /// The cage port the forwarder accepts on.
    proxy_port: u16,
    /// Executable hashes by the identity of the file hashed: device, inode, size and change time.
    /// A file the cage rewrites in place changes its change time, which the cage cannot set, so a
    /// stale entry is never read for a new content.
    hashes: Mutex<HashMap<FileKey, [u8; 32]>>,
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
        })
    }

    /// The program holding the connection whose proxy-side end is `stream`, or `None` when it
    /// cannot be named. `stated` is the source port the request on `stream` says its client
    /// connected from, which only a tap peer is believed about.
    pub(crate) fn caller(&self, stream: &UnixStream, stated: Option<u16>) -> Option<Caller> {
        let peer = super::peer::peer_pid(stream)?;
        let peer_hash = self.exe_hash(peer)?;
        let relayed = peer_hash == self.relay;
        if !relayed && peer_hash != self.tap {
            return self.named(&[peer]);
        }
        let net = net_ns(peer)?;
        let rows = tcp_rows(peer);
        let held = socket_inodes(peer);
        let port = if relayed {
            relayed_port(&rows, &held, self.proxy_port)?
        } else {
            stated?
        };
        let inode = client_inode(&rows, port, &held)?;
        self.named(&holders_of(inode, &net))
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
            .map(|(path, hash)| (file_key(&std::fs::metadata(path).unwrap()), *hash))
            .collect();
        Self {
            relay,
            tap,
            proxy_port,
            hashes: Mutex::new(hashes),
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

    /// The SHA-256 of the executable `pid` runs, from the cache when that file was hashed before.
    fn exe_hash(&self, pid: u32) -> Option<[u8; 32]> {
        let file = std::fs::File::open(format!("/proc/{pid}/exe")).ok()?;
        let key = file_key(&file.metadata().ok()?);
        if let Some(hash) = crate::sandbox::locks::locked(&self.hashes).get(&key) {
            return Some(*hash);
        }
        let hash = sha256_read(file).ok()?;
        crate::sandbox::locks::locked(&self.hashes).insert(key, hash);
        Some(hash)
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

/// The SHA-256 of the file at `path`.
fn sha256_of(path: &Path) -> io::Result<[u8; 32]> {
    sha256_read(std::fs::File::open(path)?)
}

/// The SHA-256 of what `file` reads to its end.
fn sha256_read(mut file: std::fs::File) -> io::Result<[u8; 32]> {
    use std::io::Read;
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        match file.read(&mut buf) {
            Ok(0) => return Ok(hasher.finalize().into()),
            Ok(n) => hasher.update(&buf[..n]),
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
}

/// The network namespace `pid` runs in, as its `/proc` link names it.
fn net_ns(pid: u32) -> Option<PathBuf> {
    std::fs::read_link(format!("/proc/{pid}/ns/net")).ok()
}

/// The inodes of the sockets `pid` holds.
fn socket_inodes(pid: u32) -> BTreeSet<u64> {
    let Ok(fds) = std::fs::read_dir(format!("/proc/{pid}/fd")) else {
        return BTreeSet::new();
    };
    fds.filter_map(|fd| std::fs::read_link(fd.ok()?.path()).ok())
        .filter_map(|target| socket_inode(&target.to_string_lossy()))
        .collect()
}

/// The inode a descriptor link such as `socket:[1234]` names, if it names a socket.
fn socket_inode(target: &str) -> Option<u64> {
    target
        .strip_prefix("socket:[")?
        .strip_suffix(']')?
        .parse()
        .ok()
}

/// The TCP rows of the network namespace `pid` runs in, IPv4 and IPv6 alike.
fn tcp_rows(pid: u32) -> Vec<TcpRow> {
    ["tcp", "tcp6"]
        .iter()
        .filter_map(|table| std::fs::read_to_string(format!("/proc/{pid}/net/{table}")).ok())
        .flat_map(|text| parse_tcp_table(&text))
        .collect()
}

/// The rows of a `/proc/net/tcp` or `tcp6` table. A line that does not read is skipped: the header,
/// or a format a later kernel adds, says nothing about the connections this walk follows.
fn parse_tcp_table(text: &str) -> Vec<TcpRow> {
    let port = |addr: &str| u16::from_str_radix(addr.rsplit_once(':')?.1, 16).ok();
    text.lines()
        .filter_map(|line| {
            let fields: Vec<&str> = line.split_whitespace().collect();
            Some(TcpRow {
                local_port: port(fields.get(1)?)?,
                remote_port: port(fields.get(2)?)?,
                state: u8::from_str_radix(fields.get(3)?, 16).ok()?,
                inode: fields.get(9)?.parse().ok()?,
            })
        })
        .collect()
}

/// The source port of the client a relay carries: the remote port of its one established socket
/// accepted on `proxy_port`. `None` unless there is exactly one, since a relay carrying two
/// connections cannot say which one this is.
fn relayed_port(rows: &[TcpRow], held: &BTreeSet<u64>, proxy_port: u16) -> Option<u16> {
    let ports: BTreeSet<u16> = rows
        .iter()
        .filter(|r| held.contains(&r.inode) && r.state == ESTABLISHED && r.local_port == proxy_port)
        .map(|r| r.remote_port)
        .collect();
    match ports.len() {
        1 => ports.into_iter().next(),
        _ => None,
    }
}

/// The inode of the client's end of a relayed connection: the one established socket bound to
/// `port` that the relay does not hold itself. `None` when there is none, or more than one, which
/// no single connection could be.
fn client_inode(rows: &[TcpRow], port: u16, relay_holds: &BTreeSet<u64>) -> Option<u64> {
    let found: BTreeSet<u64> = rows
        .iter()
        .filter(|r| {
            r.state == ESTABLISHED && r.local_port == port && !relay_holds.contains(&r.inode)
        })
        .map(|r| r.inode)
        .collect();
    match found.len() {
        1 => found.into_iter().next(),
        _ => None,
    }
}

/// The processes running in the network namespace `net` that hold the socket `inode`.
fn holders_of(inode: u64, net: &Path) -> Vec<u32> {
    let Ok(procs) = std::fs::read_dir("/proc") else {
        return Vec::new();
    };
    procs
        .filter_map(|entry| entry.ok()?.file_name().to_str()?.parse::<u32>().ok())
        .filter(|&pid| net_ns(pid).as_deref() == Some(net))
        .filter(|&pid| socket_inodes(pid).contains(&inode))
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

    #[test]
    fn a_tcp_table_reads_as_ports_states_and_inodes() {
        assert_eq!(
            parse_tcp_table(TABLE),
            vec![
                TcpRow {
                    local_port: 18043,
                    remote_port: 0,
                    state: 0x0A,
                    inode: 111
                },
                TcpRow {
                    local_port: 18043,
                    remote_port: 43210,
                    state: ESTABLISHED,
                    inode: 222
                },
                TcpRow {
                    local_port: 43210,
                    remote_port: 18043,
                    state: ESTABLISHED,
                    inode: 333
                },
            ]
        );
        let v6 = "  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000000000000000000001000000:467B 00000000000000000000000001000000:A8CA 01 00000000:00000000 00:00000000 00000000  1000        0 444 1 0000000000000000 20 4 30 10 -1
";
        assert_eq!(
            parse_tcp_table(v6),
            vec![TcpRow {
                local_port: 18043,
                remote_port: 43210,
                state: ESTABLISHED,
                inode: 444
            }]
        );
    }

    #[test]
    fn a_relay_leads_to_the_one_client_it_carries_and_to_its_socket() {
        let rows = parse_tcp_table(TABLE);
        let relay: BTreeSet<u64> = [111, 222].into();
        assert_eq!(relayed_port(&rows, &relay, 18043), Some(43210));
        assert_eq!(client_inode(&rows, 43210, &relay), Some(333));
        // The relay's own end is never the client's.
        assert_eq!(client_inode(&rows, 18043, &relay), None);
        // The listener is held too, but it carries nothing.
        assert_eq!(relayed_port(&rows, &[111].into(), 18043), None);
        // A relay that holds two accepted connections cannot say which one this is.
        let mut two = rows.clone();
        two.push(TcpRow {
            local_port: 18043,
            remote_port: 40000,
            state: ESTABLISHED,
            inode: 555,
        });
        assert_eq!(relayed_port(&two, &[222, 555].into(), 18043), None);
    }

    #[test]
    fn a_descriptor_link_names_a_socket_or_nothing() {
        assert_eq!(socket_inode("socket:[1234]"), Some(1234));
        assert_eq!(socket_inode("pipe:[1234]"), None);
        assert_eq!(socket_inode("/dev/null"), None);
        assert_eq!(socket_inode("socket:[x]"), None);
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
            .caller(&ours, Some(1))
            .expect("this process is named");
        assert_eq!(caller.pid, std::process::id());
        assert_eq!(caller.sha256, [9; 32]);
    }

    /// The tap's case: this process plays the tap, holding an accepted connection, and is believed
    /// about the port its client connected from; without that statement nothing is named, since a
    /// tap carries many connections.
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
            let caller = walker.caller(&ours, Some(from.port()));
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
