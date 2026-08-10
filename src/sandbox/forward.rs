//! Loopback port forwarding — host → cage, the reverse of [`super::egress`].
//!
//! [`super::egress`] bridges the cage's loopback *out* to a host filtering proxy over a bound
//! Unix socket; this module bridges a host loopback TCP port *into* the cage so a host process
//! (a browser chasing an OAuth `localhost:<port>` callback, or a developer opening a cage-run
//! dev server) can reach a service the agent started inside the empty-netns cage.
//!
//! The shape is the egress forwarder's mirror, with the listener and the dialer swapped:
//!
//! - the host binds a `TcpListener` on `127.0.0.1:<port>` (and, best-effort, on `[::1]:<port>` so a
//!   `localhost` callback the browser sends over IPv6 is caught too) for each declared port —
//!   loopback only, never an external interface, and **fail-closed on collision** on the primary
//!   `127.0.0.1` bind (the OAuth redirect URL is baked in, so sbx does not pick an ephemeral
//!   substitute; a port already in use aborts the launch with a clear message);
//! - a per-launch host directory is bound read-write into the cage at `/tmp/sbx-forward`, so the
//!   in-cage forwarder can create its per-port Unix socket there and the host sees the same inode;
//! - inside the cage a `socat UNIX-LISTEN:<cage path>,fork TCP-CONNECT:127.0.0.1:<port>` forwarder
//!   accepts a Unix connection (from the host, for each accepted TCP conn) and bridges it to the
//!   cage's own loopback at the same port — where the agent's service listens;
//! - on the host, each accepted TCP connection is pumped to the matching Unix socket in a
//!   bidirectional copy, so bytes flow browser ↔ cage service through the one shared inode.
//!
//! Teardown is deterministic: the accept loops poll a shared shutdown flag (each listener is
//! non-blocking), so dropping the [`Forwarder`] guard stops them, closes the listeners, and frees
//! the host ports before the drop returns — a later launch (e.g. a sequential `sbx upgrade` group)
//! can rebind the same port.
//!
//! Security does not rest on the forwarder: it is a deliberately-declared, loopback-only,
//! trusted-only inbound hole (see `forward` in the config), not a widening of egress. The empty
//! netns and the egress allowlist are unchanged — the forward is orthogonal to them. Under
//! `network = "shared"` the cage shares the host netns, so a cage service on `127.0.0.1:<port>`
//! is already on host loopback and this forwarder is a redundant no-op (the launcher skips it
//! with a note).

use super::binds::ExtraBind;
use crate::store::Layout;
use std::ffi::OsString;
use std::io;
use std::net::{Shutdown, TcpListener, TcpStream};
use std::os::unix::fs::DirBuilderExt;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::thread::JoinHandle;
use std::time::Duration;

/// Where the per-launch host directory appears in the cage. Under the `/tmp` tmpfs (a writable
/// mountpoint — a bind onto the read-only root would fail), and a single dir carries every
/// per-port socket the in-cage forwarder creates, so one `ExtraBind` covers all ports.
const CAGE_FORWARD_DIR: &str = "/tmp/sbx-forward";

/// A cap on live host→cage pump threads per listener, matching [`super::proxy::serve`]'s shape: a
/// connection beyond the cap is refused (fail-closed) rather than allowed to pin a thread.
const MAX_CONCURRENT_CONNS: usize = 512;

/// How long an accept loop waits between non-blocking `accept()` polls. Small enough that dropping
/// the guard frees the port promptly, large enough that an idle port costs nothing.
const ACCEPT_POLL: Duration = Duration::from_millis(20);

/// A running forward session's host-side resources: the per-launch directory (whose socket files
/// the in-cage forwarder creates) and the accept-loop threads. Dropping the guard signals the loops
/// to stop, joins them (so their listeners close and the host ports are freed), then removes the
/// directory — a socket file the cage left behind goes with it (a dead inode under the `0700` data
/// dir, no security concern).
pub(crate) struct Forwarder {
    dir: PathBuf,
    shutdown: Arc<AtomicBool>,
    accepts: Vec<JoinHandle<()>>,
}

impl Drop for Forwarder {
    fn drop(&mut self) {
        // Signal every accept loop to stop, then join them: each notices the flag within one poll
        // interval, returns, and drops its listener — so the host ports are provably free once this
        // returns (a sequential re-launch can rebind them). Only then remove the per-launch dir.
        self.shutdown.store(true, Ordering::Relaxed);
        for h in self.accepts.drain(..) {
            let _ = h.join();
        }
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// What a forward-bearing launch injects into the cage: the directory bind (so the in-cage
/// forwarder can create its per-port sockets) and the per-port forwards the wrapper script
/// starts.
pub(crate) struct Wiring {
    pub(crate) binds: Vec<ExtraBind>,
    pub(crate) forwards: Vec<Forward>,
}

/// One declared forward: the cage loopback port (where the agent's service listens) and the
/// in-cage path of the Unix socket the host pumps into. The cage port equals the host port
/// (the `forward = [port]` schema), so an OAuth `localhost:<port>` redirect resolves to the same
/// port on both sides.
#[derive(Clone)]
pub(crate) struct Forward {
    pub(crate) cage_port: u16,
    pub(crate) cage_uds: PathBuf,
}

/// Start the host listeners for `ports` and return the cage wiring plus a guard owning the on-disk
/// dir and the accept threads. Each listener is bound before this returns, so the host port answers
/// (its backlog queues connections) from the moment the launch is up — never a first-request race
/// (mirrors [`super::egress::start`]). The primary `127.0.0.1` bind fails the launch **closed** with
/// a message naming the port when it is already in use: the OAuth redirect URL is fixed, so an
/// ephemeral substitute would silently break the callback, and two `sbx app <name>` logins colliding
/// is a one-shot, not a recurring hazard. The `[::1]` bind is best-effort — it catches a `localhost`
/// callback the browser sends over IPv6, but a host with IPv6 disabled simply keeps the v4 path.
pub(crate) fn start(layout: &Layout, mut ports: Vec<u16>) -> io::Result<(Forwarder, Wiring)> {
    crate::store::ensure(layout)?;
    ports.sort_unstable();
    ports.dedup();

    let dir = layout
        .data_dir()
        .join("forward")
        .join(format!("fwd-{}", std::process::id()));
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(&dir)?;

    let shutdown = Arc::new(AtomicBool::new(false));
    let mut accepts: Vec<JoinHandle<()>> = Vec::new();
    let mut forwards = Vec::with_capacity(ports.len());

    for &port in &ports {
        // The host-side socket every listener for this port bridges into; the in-cage forwarder
        // binds it through the shared dir, and the host connects to the same inode.
        let host_sock = dir.join(format!("p-{port}.sock"));

        // v4 loopback is mandatory — `127.0.0.1`, never the wildcard, so the port is never exposed
        // on an external interface. Fail-closed on any bind error, naming the port and both likely
        // causes (already in use, or a privileged port needing capabilities we do not hold).
        let v4 = TcpListener::bind(("127.0.0.1", port)).map_err(|e| {
            io::Error::new(
                e.kind(),
                format!(
                    "cannot bind host port {port} for forward ({e}) — it is already in use \
                     (another login, or a host service on :{port}), or binding it needs privilege"
                ),
            )
        })?;
        accepts.push(spawn_accept(v4, host_sock.clone(), shutdown.clone()));

        // v6 loopback (`::1`) is best-effort: many hosts resolve `localhost` to `::1` first, so
        // binding it too catches an IPv6 callback. A host with IPv6 disabled (or the address
        // already taken) simply skips it — v4 stays the primary path.
        if let Ok(v6) = TcpListener::bind(("::1", port)) {
            accepts.push(spawn_accept(v6, host_sock.clone(), shutdown.clone()));
        }

        forwards.push(Forward {
            cage_port: port,
            cage_uds: PathBuf::from(format!("{CAGE_FORWARD_DIR}/p-{port}.sock")),
        });
    }

    // One bind carries the whole per-launch dir; the in-cage forwarder creates its per-port socket
    // files inside it, and the host connects to the same inode. Writable so the cage can create and
    // unlink its sockets.
    let binds = vec![ExtraBind {
        src: dir.clone(),
        dest: PathBuf::from(CAGE_FORWARD_DIR),
        writable: true,
    }];

    Ok((
        Forwarder {
            dir,
            shutdown,
            accepts,
        },
        Wiring { binds, forwards },
    ))
}

/// Put `listener` into non-blocking mode and spawn its accept loop. Non-blocking so the loop can
/// poll the shutdown flag between accepts and exit promptly when the guard drops.
fn spawn_accept(listener: TcpListener, sock: PathBuf, shutdown: Arc<AtomicBool>) -> JoinHandle<()> {
    let _ = listener.set_nonblocking(true);
    std::thread::spawn(move || accept_loop(listener, sock, shutdown))
}

/// Per-listener accept loop: for each accepted host TCP connection, connect to the in-cage
/// forwarder's Unix socket and pump bytes both ways in a fresh thread. The listener is non-blocking,
/// so the loop polls the `shutdown` flag and returns when the guard signals teardown (dropping the
/// listener, freeing the port). The in-cage socket may not exist yet when the host accepts (the cage
/// forwarder binds it after the cage starts); a connect then fails and the connection is dropped —
/// the browser retries, and a dev server is up long before the user curls. A `MAX_CONCURRENT_CONNS`
/// cap refuses beyond (fail-closed).
fn accept_loop(listener: TcpListener, sock: PathBuf, shutdown: Arc<AtomicBool>) {
    let live = Arc::new(AtomicUsize::new(0));
    loop {
        if shutdown.load(Ordering::Relaxed) {
            return;
        }
        let stream = match listener.accept() {
            Ok((s, _)) => s,
            // No pending connection (non-blocking) or a transient error: nap and re-poll the flag.
            Err(_) => {
                std::thread::sleep(ACCEPT_POLL);
                continue;
            }
        };
        // The accepted stream inherits nothing from the non-blocking listener on Linux, but make it
        // explicit: the bridge uses a simple blocking read/write loop.
        let _ = stream.set_nonblocking(false);
        if live.load(Ordering::Relaxed) >= MAX_CONCURRENT_CONNS {
            // Refuse beyond the cap: dropping the stream closes it (fail-closed).
            continue;
        }
        live.fetch_add(1, Ordering::Relaxed);
        let live = live.clone();
        let sock = sock.clone();
        std::thread::spawn(move || {
            struct Dec<'a>(&'a AtomicUsize);
            impl Drop for Dec<'_> {
                fn drop(&mut self) {
                    self.0.fetch_sub(1, Ordering::Relaxed);
                }
            }
            let _dec = Dec(&live);
            let _ = bridge(stream, &sock);
        });
    }
}

/// Pump one TCP connection to the in-cage forwarder's Unix socket, both ways, until either side
/// closes. Two copy threads, each shutting down the other direction's write half on EOF so the
/// peer sees the close and the second copy terminates — the standard bidirectional bridge.
fn bridge(mut client: TcpStream, sock: &Path) -> io::Result<()> {
    let mut uds = UnixStream::connect(sock)?;
    let mut client_w = client.try_clone()?;
    let mut uds_w = uds.try_clone()?;
    let t1 = std::thread::spawn(move || {
        let _ = std::io::copy(&mut client, &mut uds);
        // The browser half closed (or the TCP conn ended) → tell the cage forwarder by shutting
        // the UDS write half, so it sees EOF and stops responding; the other thread then reads 0.
        let _ = uds.shutdown(Shutdown::Write);
    });
    let t2 = std::thread::spawn(move || {
        let _ = std::io::copy(&mut uds_w, &mut client_w);
        // The cage half closed → tell the browser by shutting the TCP write half.
        let _ = client_w.shutdown(Shutdown::Write);
    });
    let _ = t1.join();
    let _ = t2.join();
    Ok(())
}

/// Wrap `cmd` so the cage starts the in-cage forwarders before running it: a static bash that
/// backgrounds one `socat UNIX-LISTEN → TCP-CONNECT` per declared port (stdio detached so it
/// never touches the terminal), then `exec`s the real command — which therefore stays the cage's
/// main process, leaving an interactive `sbx run`'s pty job control unchanged. The command rides `"$@"`
/// positionally, so nothing the agent controls is ever interpolated into the script (no shell
/// injection, non-UTF-8 argv preserved); only sbx-owned ASCII — the socat store path, the
/// `/tmp/sbx-forward` socket paths, and the port numbers — goes into the script string. Mirrors
/// [`super::egress::wrap_command`].
pub(crate) fn wrap_command(
    socat: &Path,
    bash: &Path,
    forwards: &[Forward],
    cmd: Vec<OsString>,
) -> Vec<OsString> {
    let mut preamble = String::new();
    for f in forwards {
        preamble.push_str(&format!(
            "{socat} UNIX-LISTEN:{uds},fork TCP-CONNECT:127.0.0.1:{port} \
             </dev/null >/dev/null 2>&1 & ",
            socat = socat.to_string_lossy(),
            uds = f.cage_uds.display(),
            port = f.cage_port,
        ));
    }
    // Share the `bash -c '<preamble> exec "$@"'` assembly with the egress forwarder — same
    // positional-argv, exec-the-command shape, only the socat preamble differs.
    super::egress::wrap_background(bash, &preamble, "sbx-forward", cmd)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::TmpDir;
    use std::io::{Read, Write};

    /// `start` binds a host loopback listener and a per-launch dir per port, and returns exactly
    /// one writable `ExtraBind` at the cage forward dir plus one forward per (deduped) port.
    #[test]
    fn start_binds_host_listeners_and_wires_the_cage() {
        let data = TmpDir::new();
        let layout = Layout::under(data.path());
        // Port 0 lets the OS pick a free port so the test never collides; ask twice to prove dedup.
        let free = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let port = free.local_addr().unwrap().port();
        drop(free);

        let (guard, wiring) = start(&layout, vec![port, port]).expect("start binds the port");
        // One directory bind, writable, at the fixed cage path — it carries every per-port socket.
        assert_eq!(wiring.binds.len(), 1);
        assert_eq!(wiring.binds[0].dest, PathBuf::from(CAGE_FORWARD_DIR));
        assert!(wiring.binds[0].writable, "the forward dir must be writable");
        // One forward (the duplicate was deduped), cage port == host port, cage socket under the dir.
        assert_eq!(wiring.forwards.len(), 1);
        assert_eq!(wiring.forwards[0].cage_port, port);
        assert_eq!(
            wiring.forwards[0].cage_uds,
            PathBuf::from(format!("{CAGE_FORWARD_DIR}/p-{port}.sock"))
        );
        // The host listener is live: a fresh bind on the same port must now fail.
        assert!(
            TcpListener::bind(("127.0.0.1", port)).is_err(),
            "the port must be held by the running forwarder"
        );
        drop(guard);
    }

    /// Dropping the guard frees the host port — the accept loops stop and their listeners close, so
    /// a sequential re-launch (an `sbx upgrade` group) can rebind the same port. This is the RAII
    /// property the guard promises; a leaked listener would make the rebind fail.
    #[test]
    fn a_dropped_guard_frees_the_host_port() {
        let data = TmpDir::new();
        let layout = Layout::under(data.path());
        let free = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let port = free.local_addr().unwrap().port();
        drop(free);

        let (guard, _wiring) = start(&layout, vec![port]).expect("start");
        assert!(
            TcpListener::bind(("127.0.0.1", port)).is_err(),
            "the port is held while the guard lives"
        );
        drop(guard);
        // After drop the accept loops have been joined and their listeners closed, so the port is
        // free. Retry briefly to absorb the kernel's TIME_WAIT-free close of a never-connected
        // listener (which is immediate, but be robust to scheduling).
        let mut freed = false;
        for _ in 0..50 {
            if TcpListener::bind(("127.0.0.1", port)).is_ok() {
                freed = true;
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(freed, "dropping the guard must free the host port");
    }

    /// A port already in use fails the launch **closed** — `start` returns an error naming the port,
    /// never an ephemeral substitute (the OAuth redirect URL is fixed).
    #[test]
    fn a_port_collision_fails_closed_naming_the_port() {
        let data = TmpDir::new();
        let layout = Layout::under(data.path());
        // Hold a port, then ask `start` for the same one.
        let held = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let port = held.local_addr().unwrap().port();

        let msg = match start(&layout, vec![port]) {
            Ok(_) => panic!("a taken port must fail closed, not succeed"),
            Err(e) => e.to_string(),
        };
        assert!(
            msg.contains(&port.to_string()) && msg.contains("already in use"),
            "the collision error must name the port: {msg}"
        );
        drop(held);
    }

    /// `wrap_command` backgrounds one `socat UNIX-LISTEN … TCP-CONNECT 127.0.0.1:<port>` per
    /// forward, then `exec "$@"`, with the command positional (never interpolated) and the `$0`
    /// label fixed.
    #[test]
    fn wrap_command_backgrounds_one_socat_per_port_then_execs_positionally() {
        let forwards = vec![
            Forward {
                cage_port: 1455,
                cage_uds: PathBuf::from("/tmp/sbx-forward/p-1455.sock"),
            },
            Forward {
                cage_port: 8080,
                cage_uds: PathBuf::from("/tmp/sbx-forward/p-8080.sock"),
            },
        ];
        let out = wrap_command(
            Path::new("/nix/store/x-socat/bin/socat"),
            Path::new("/nix/store/y-bash/bin/bash"),
            &forwards,
            vec![OsString::from("demo-app"), OsString::from("login")],
        );
        assert_eq!(out[0], OsString::from("/nix/store/y-bash/bin/bash"));
        assert_eq!(out[1], OsString::from("-c"));
        let script = out[2].to_string_lossy();
        assert!(script.contains("UNIX-LISTEN:/tmp/sbx-forward/p-1455.sock,fork"));
        assert!(script.contains("TCP-CONNECT:127.0.0.1:1455"));
        assert!(script.contains("UNIX-LISTEN:/tmp/sbx-forward/p-8080.sock,fork"));
        assert!(script.contains("TCP-CONNECT:127.0.0.1:8080"));
        assert!(script.trim_end().ends_with("exec \"$@\""));
        // `$0` label, then the command positionally — nothing interpolated into the script.
        assert_eq!(out[3], OsString::from("sbx-forward"));
        assert_eq!(out[4], OsString::from("demo-app"));
        assert_eq!(out[5], OsString::from("login"));
    }

    /// The host-side bridge round-trips bytes: a host TCP connection to the listener is pumped
    /// through the per-port Unix socket to a stand-in "cage" that accepts on that socket and echoes
    /// — proving `start`'s accept loop connects host→UDS and copies both ways, without a real cage.
    /// (The in-cage `socat` is what binds the UDS in production; here the test binds it.)
    #[test]
    fn the_host_bridge_round_trips_bytes_through_the_cage_socket() {
        use std::os::unix::net::UnixListener;

        let data = TmpDir::new();
        let layout = Layout::under(data.path());
        let free = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let port = free.local_addr().unwrap().port();
        drop(free);

        let (guard, _wiring) = start(&layout, vec![port]).expect("start");
        // Stand in for the in-cage socat: bind the host-side socket path (the same inode the cage
        // would bind through the dir bind) and echo one line back, uppercased.
        let sock_path = wiring_host_socket(&layout, port);
        let cage = UnixListener::bind(&sock_path).expect("bind the stand-in cage socket");
        let echo = std::thread::spawn(move || {
            if let Ok((mut conn, _)) = cage.accept() {
                let mut buf = [0u8; 64];
                if let Ok(n) = conn.read(&mut buf) {
                    let up = buf[..n].to_ascii_uppercase();
                    let _ = conn.write_all(&up);
                }
            }
        });

        // Connect to the host port and send a line; expect the echo back through the bridge.
        let mut client = TcpStream::connect(("127.0.0.1", port)).expect("connect to host port");
        client.write_all(b"hello\n").unwrap();
        client.shutdown(Shutdown::Write).unwrap();
        let mut got = Vec::new();
        client.read_to_end(&mut got).unwrap();
        assert_eq!(
            got, b"HELLO\n",
            "the bridge must round-trip host↔cage bytes"
        );
        let _ = echo.join();
        drop(guard);
    }

    /// The host-side socket path `start` creates for `port`, so the round-trip test can bind the
    /// stand-in cage there. Mirrors `start`'s construction exactly (keyed by this pid).
    #[cfg(test)]
    fn wiring_host_socket(layout: &Layout, port: u16) -> PathBuf {
        layout
            .data_dir()
            .join("forward")
            .join(format!("fwd-{}", std::process::id()))
            .join(format!("p-{port}.sock"))
    }
}
