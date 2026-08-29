//! Loopback port forwarding — host → cage, the reverse of [`super::egress`].
//!
//! [`super::egress`] bridges the cage's loopback *out* to a host filtering proxy over a bound
//! Unix socket; this module bridges a host loopback TCP port *into* the cage so a host process
//! (a browser chasing an OAuth `localhost:<port>` callback, or a developer opening a cage-run
//! dev server) can reach a service the agent started inside the empty-netns cage.
//!
//! A forward has **two** ports: the one bound on the host, and the one the caged service listens
//! on. `forward = [9119]` makes them equal; `forward = ["9200:9119"]` moves the host side alone,
//! which is how a host-port collision is resolved without touching the app. The cage side is the
//! forward's identity — it names which in-cage service is being published — so it keys the merge
//! and names the socket, and a higher layer restating it moves the host port rather than opening a
//! second hole. See [`ForwardPort`] for what that costs an OAuth callback, whose host port is fixed
//! by its provider and must not be moved.
//!
//! The shape is the egress forwarder's mirror, with the listener and the dialer swapped:
//!
//! - the host binds a `TcpListener` on `127.0.0.1:<host port>` (and, best-effort, on
//!   `[::1]:<host port>` so a `localhost` callback the browser sends over IPv6 is caught too) for
//!   each declared forward — loopback only, never an external interface, and **fail-closed on
//!   collision** on the primary `127.0.0.1` bind: sbx does not pick an ephemeral substitute,
//!   because it cannot know what the caller published, so a port already in use aborts the launch
//!   with a message pointing at the remap form;
//! - a per-launch host directory is bound read-write into the cage at `/tmp/sbx-forward`, so the
//!   in-cage forwarder can create its per-port Unix socket there and the host sees the same inode;
//! - inside the cage a `socat UNIX-LISTEN:<cage path>,fork TCP-CONNECT:127.0.0.1:<cage port>`
//!   forwarder accepts a Unix connection (from the host, for each accepted TCP conn) and bridges it
//!   to the cage's own loopback — where the agent's service listens;
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
use crate::config::ForwardPort;
use crate::store::Layout;
use std::ffi::OsString;
use std::io;
use std::net::{Shutdown, TcpListener, TcpStream};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{DirBuilderExt, FileTypeExt, OpenOptionsExt};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
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
/// in-cage path of the Unix socket the host pumps into. The host port is not named here because
/// nothing inside the cage can observe it — the cage side of a forward is the same whether the
/// host bound the same port or another one.
#[derive(Clone)]
pub(crate) struct Forward {
    pub(crate) cage_port: u16,
    pub(crate) cage_uds: PathBuf,
}

/// Start the host listeners for `ports` and return the cage wiring plus a guard owning the on-disk
/// dir and the accept threads. Each listener is bound before this returns, so the host port answers
/// (its backlog queues connections) from the moment the launch is up — never a first-request race
/// (mirrors [`super::egress::start`]). The primary `127.0.0.1` bind fails the launch **closed** with
/// a message naming the port when it is already in use: sbx does not pick an ephemeral substitute,
/// because nothing tells it what the caller published — an OAuth redirect URL is fixed by its
/// provider, and a moved dev-server port is one the caller must be told about. Moving off a taken
/// host port is the remap form's job, and the message says so. The `[::1]` bind is best-effort — it
/// catches a `localhost` callback the browser sends over IPv6, but a host with IPv6 disabled simply
/// keeps the v4 path.
///
/// A failure part-way through leaves nothing running: the [`Forwarder`] guard is constructed before
/// the first bind and every listener is registered in it as it is spawned, so an error returns by
/// dropping the guard — which is the same teardown a successful launch gets.
pub(crate) fn start(
    layout: &Layout,
    mut ports: Vec<ForwardPort>,
) -> io::Result<(Forwarder, Wiring)> {
    crate::store::ensure(layout)?;
    // Canonical order only. Reducing two entries that share a cage port is resolution's job (it
    // keys them and keeps the last), so by the time a list reaches here every cage port is already
    // distinct and there is nothing left to collapse.
    ports.sort_unstable_by_key(|f| (f.cage, f.host));
    // Two forwards claiming one host port cannot both be bound, and the bind error alone would
    // blame the host ("already in use — another login, or a host service on :9200") for what is
    // sbx's own configuration double-booking a port. Caught here, ahead of the bind, so the message
    // names the two cage ports that collided and the caller knows which entry to change. Resolution
    // keys forwards by cage port, so this is reachable only across *different* cage ports — never
    // from a duplicate of one.
    for (i, a) in ports.iter().enumerate() {
        if let Some(b) = ports[i + 1..].iter().find(|b| b.host == a.host) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "`forward` claims host port {host} twice — for cage port {first} and for \
                     cage port {second}. One host port reaches one cage port; give each its own.",
                    host = a.host,
                    first = a.cage,
                    second = b.cage,
                ),
            ));
        }
    }

    let dir = layout
        .data_dir()
        .join("forward")
        .join(format!("fwd-{}", std::process::id()));
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(&dir)?;

    let shutdown = Arc::new(AtomicBool::new(false));
    // The guard owns the partial state from here on, before the first bind can fail. Every listener
    // is registered in it as it is spawned, so an error on a later port drops the guard on the way
    // out — which stops and joins the accept loops already running, closes their listeners (freeing
    // the host ports) and removes the directory. Built at the end of the loop instead, an early
    // return left those threads detached and their ports bound for the life of the process: a
    // multi-app run (`sbx upgrade`) continues past a failed launch, so the next app to declare that
    // port was refused by sbx's own listener under a message blaming "another login, or a host
    // service".
    let mut guard = Forwarder {
        dir: dir.clone(),
        shutdown: shutdown.clone(),
        accepts: Vec::new(),
    };
    let mut forwards = Vec::with_capacity(ports.len());

    for &fwd in &ports {
        // The host-side socket every listener for this forward bridges into; the in-cage forwarder
        // binds it through the shared dir, and the host connects to the same inode. Named by the
        // **cage** port, which is what identifies a forward — so two entries can never name one
        // socket, and the name matches the `TCP-CONNECT` the in-cage `socat` is given.
        let host_sock = dir.join(format!("p-{}.sock", fwd.cage));
        // A predecessor with this pid that was `SIGKILL`ed never ran `Forwarder::drop`, so its
        // socket file can still be sitting in the directory this launch reuses (the directory is
        // keyed by pid). `socat UNIX-LISTEN` refuses a path that already exists, and the in-cage
        // forwarder runs with its output on `/dev/null` — the forward would simply never carry a
        // byte and say nothing about why. Clearing the name is the same pre-bind removal the egress
        // control socket does, and it is confined to this pid's own directory, which no live
        // process can be using.
        let _ = std::fs::remove_file(&host_sock);

        // v4 loopback is mandatory — `127.0.0.1`, never the wildcard, so the port is never exposed
        // on an external interface. Fail-closed on any bind error, naming the port and both likely
        // causes (already in use, or a privileged port needing capabilities we do not hold), plus
        // the way out: the remap form moves the host side without touching the caged service.
        let host = fwd.host;
        let v4 = TcpListener::bind(("127.0.0.1", host)).map_err(|e| {
            io::Error::new(
                e.kind(),
                format!(
                    "cannot bind host port {host} for forward ({e}) — it is already in use \
                     (another login, or a host service on :{host}), or binding it needs \
                     privilege. To reach the cage's :{cage} from a free host port instead, \
                     forward `<port>:{cage}`",
                    cage = fwd.cage,
                ),
            )
        })?;
        guard
            .accepts
            .push(spawn_accept(v4, host_sock.clone(), shutdown.clone()));

        // v6 loopback (`::1`) is best-effort: many hosts resolve `localhost` to `::1` first, so
        // binding it too catches an IPv6 callback. A host with IPv6 disabled (or the address
        // already taken) simply skips it — v4 stays the primary path.
        if let Ok(v6) = TcpListener::bind(("::1", host)) {
            guard
                .accepts
                .push(spawn_accept(v6, host_sock.clone(), shutdown.clone()));
        }

        forwards.push(Forward {
            cage_port: fwd.cage,
            cage_uds: PathBuf::from(format!("{CAGE_FORWARD_DIR}/p-{}.sock", fwd.cage)),
        });
    }

    // One bind carries the whole per-launch dir; the in-cage forwarder creates its per-port socket
    // files inside it, and the host connects to the same inode. Writable so the cage can create and
    // unlink its sockets — which is why the host resolves one of those names exactly once, in
    // `dial_cage_socket`, rather than on every connection.
    let binds = vec![ExtraBind {
        src: dir,
        dest: PathBuf::from(CAGE_FORWARD_DIR),
        writable: true,
    }];

    Ok((guard, Wiring { binds, forwards }))
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
/// the browser retries, and a dev server is up long before the user curls.
///
/// The ceiling and the accept-error policy are [`super::conncap`]'s, not this loop's own: the slot
/// is taken by the operation that tests it ([`super::conncap::ConnCap::take`]), and an accept that
/// fails for anything but "nothing pending" names this plane and pauses
/// ([`super::conncap::accept_backoff`]) instead of being folded into the idle case, where a listener
/// that had stopped accepting read as an idle port for the rest of the session.
fn accept_loop(listener: TcpListener, sock: PathBuf, shutdown: Arc<AtomicBool>) {
    let cap = super::conncap::ConnCap::new(MAX_CONCURRENT_CONNS);
    loop {
        if shutdown.load(Ordering::Relaxed) {
            return;
        }
        let stream = match listener.accept() {
            Ok((s, _)) => s,
            // The listener is non-blocking, so "nothing pending" is the ordinary idle state: nap
            // and re-poll the shutdown flag. It is matched first because it is the only error this
            // loop is entitled to swallow.
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                std::thread::sleep(ACCEPT_POLL);
                continue;
            }
            // Anything else is a real failure — host fd exhaustion (`EMFILE`) above all, which is
            // when a machine can least afford a spinning thread. Every other plane in this tree
            // says so on stderr; a silent one leaves a forward that answers TCP and carries nothing
            // with no diagnosis anywhere.
            Err(e) => {
                super::conncap::accept_backoff("forward", &e);
                continue;
            }
        };
        // The accepted stream inherits nothing from the non-blocking listener on Linux, but make it
        // explicit: the bridge uses a simple blocking read/write loop.
        let _ = stream.set_nonblocking(false);
        // Past the ceiling the stream is dropped, which closes it (fail-closed) rather than pinning
        // another thread.
        let Some(slot) = cap.take() else { continue };
        let sock = sock.clone();
        std::thread::spawn(move || {
            let _slot = slot;
            let _ = bridge(stream, &sock);
        });
    }
}

/// Pump one TCP connection to the in-cage forwarder's Unix socket, both ways, until the cage side
/// closes, then tear both sockets down so neither copy can hang. The shape is the proxy's raw
/// tunnel (`proxy::splice::splice_copy`), and for the same reason.
///
/// The half-close each direction sends on EOF is what a well-behaved peer needs, and it is not
/// enough on its own: this used to spawn both copies and join both, so the bridge returned only
/// when *both* directions had ended. A cage service that goes away (socat dies with the cage) EOFs
/// the cage→host direction while a host client that is merely idle — a browser holding a keep-alive
/// connection — sends nothing and closes nothing, so the host→cage copy stayed blocked in `read`
/// forever, pinning its thread and, through the [`super::conncap::ConnSlot`] `accept_loop` holds
/// for it, one of the [`MAX_CONCURRENT_CONNS`] slots for the life of the process.
///
/// So the cage→host direction runs inline and decides: when it ends, both sockets are shut down
/// `Both`, which returns the spawned copy's blocked read and makes the join always complete.
///
/// The cage side is reached through [`dial_cage_socket`], never by dialing the path directly: the
/// name lives in a directory the cage can write.
fn bridge(client: TcpStream, sock: &Path) -> io::Result<()> {
    let uds = dial_cage_socket(sock)?;
    // Two handles per socket (read + write), plus one each to force the teardown after the inline
    // copy ends. `try_clone` dups the fd, so every handle refers to the same socket.
    let mut client_rd = client.try_clone()?;
    let client_shut = client.try_clone()?;
    let mut client_wr = client;
    let mut uds_wr = uds.try_clone()?;
    let uds_shut = uds.try_clone()?;
    let mut uds_rd = uds;

    let t = std::thread::spawn(move || {
        let _ = std::io::copy(&mut client_rd, &mut uds_wr);
        // The browser half closed (or the TCP conn ended) → tell the cage forwarder by shutting
        // the UDS write half, so it sees EOF and stops responding; the inline copy then reads 0.
        let _ = uds_wr.shutdown(Shutdown::Write);
    });
    let _ = std::io::copy(&mut uds_rd, &mut client_wr);
    // The cage half closed → tell the browser by shutting the TCP write half, then force both
    // sockets fully down so the spawned copy's read returns and the join below always completes.
    let _ = client_wr.shutdown(Shutdown::Write);
    let _ = client_shut.shutdown(Shutdown::Both);
    let _ = uds_shut.shutdown(Shutdown::Both);
    let _ = t.join();
    Ok(())
}

/// Connect to the in-cage forwarder's socket, refusing to follow a name the cage has replaced.
///
/// The per-launch directory is bound into the cage **read-write** — the in-cage `socat` has to
/// create and unlink its own sockets there — so every name inside it belongs to the workload, and
/// the host dials one of those names once per accepted connection. A path-based `connect(2)`
/// resolves symlinks in the **host's** mount namespace, so `unlink p-9119.sock; ln -s
/// /var/run/docker.sock p-9119.sock` would splice a host client into a host daemon of the cage's
/// choosing: not an exfiltration channel back into the cage (its netns is empty, so it cannot dial
/// the forward itself), but a confused deputy — the host client's bytes reach a service it never
/// asked for, and the forward's one guarantee, that this port reaches the caged service, is gone.
/// The targets need no guessing either: a bind mount shows its source in the cage's own
/// `/proc/self/mountinfo`.
///
/// Re-checking the name before each dial would only narrow the window, since the cage can swap it
/// back and forth as fast as it likes. So the name is resolved **once** and the connection is made
/// to what that resolution pinned. `O_PATH` opens the entry without opening what it holds — a
/// socket cannot be opened for I/O at all — and `O_NOFOLLOW` beside it makes the descriptor refer
/// to a symlink *itself* rather than to its target, so reading the type off that descriptor refuses
/// a link, a regular file, a fifo or a directory left at the name instead of dialing through it.
/// Only a real socket gets past, and the connect then names the pinned inode through
/// `/proc/self/fd`, so what the cage does to the name afterwards cannot move the connection.
///
/// A missing socket keeps its old meaning — the cage forwarder may simply not have bound it yet,
/// and the caller drops that connection for the client to retry.
fn dial_cage_socket(sock: &Path) -> io::Result<UnixStream> {
    // `read(true)` is only there because `OpenOptions` requires an access mode; `O_PATH` makes the
    // kernel ignore it, which is what lets this open a socket at all.
    let pinned = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(sock)?;
    if !pinned.metadata()?.file_type().is_socket() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "`{}` is not a socket — the cage replaced the forward's socket with something \
                 else, and this port reaches nothing until it puts one back",
                sock.display()
            ),
        ));
    }
    UnixStream::connect(format!("/proc/self/fd/{}", pinned.as_raw_fd()))
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

    /// Starts a forwarder on ports the OS has just handed out. A port is chosen by binding and
    /// releasing it, so between the release and the forwarder's own bind there is a window
    /// anything else on the machine can win — including a sibling test, since the binary runs them
    /// in parallel. Losing that race says nothing about what any of these tests assert, so a taken
    /// port is retried with a fresh set; a bind that fails for any other reason still fails.
    fn start_on_free_ports(
        layout: &Layout,
        count: usize,
        wire: impl Fn(&[u16]) -> Vec<ForwardPort>,
    ) -> (Forwarder, Wiring, Vec<u16>) {
        let mut left = 5;
        loop {
            let held: Vec<TcpListener> = (0..count)
                .map(|_| TcpListener::bind(("127.0.0.1", 0)).expect("an ephemeral port"))
                .collect();
            let picked: Vec<u16> = held
                .iter()
                .map(|l| l.local_addr().expect("the bound address").port())
                .collect();
            drop(held);

            match start(layout, wire(&picked)) {
                Ok((guard, wiring)) => break (guard, wiring, picked),
                Err(e) if e.kind() == io::ErrorKind::AddrInUse && left > 0 => left -= 1,
                Err(e) => panic!("start binds the ports it was given: {e:?}"),
            }
        }
    }

    /// `start` binds a host loopback listener and a per-launch dir per port, and returns exactly
    /// one writable `ExtraBind` at the cage forward dir plus one forward per declared entry.
    #[test]
    fn start_binds_host_listeners_and_wires_the_cage() {
        let data = TmpDir::new();
        let layout = Layout::under(data.path());
        let (guard, wiring, picked) =
            start_on_free_ports(&layout, 1, |p| vec![ForwardPort::same(p[0])]);
        let port = picked[0];
        // One directory bind, writable, at the fixed cage path — it carries every per-port socket.
        assert_eq!(wiring.binds.len(), 1);
        assert_eq!(wiring.binds[0].dest, PathBuf::from(CAGE_FORWARD_DIR));
        assert!(wiring.binds[0].writable, "the forward dir must be writable");
        // One forward, cage port == host port, cage socket under the dir.
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
        let (guard, _wiring, picked) =
            start_on_free_ports(&layout, 1, |p| vec![ForwardPort::same(p[0])]);
        let port = picked[0];
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

        let msg = match start(&layout, vec![ForwardPort::same(port)]) {
            Ok(_) => panic!("a taken port must fail closed, not succeed"),
            Err(e) => e.to_string(),
        };
        assert!(
            msg.contains(&port.to_string()) && msg.contains("already in use"),
            "the collision error must name the port: {msg}"
        );
        // The message must also name the way out, because the way out is the whole reason a caller
        // reads it: the cage port stays where the service listens, only the host side moves.
        assert!(
            msg.contains(&format!("forward `<port>:{port}`")),
            "the collision error must point at the remap form: {msg}"
        );
        drop(held);
    }

    /// A remap binds the **host** side and connects the **cage** side: the listener answers on the
    /// host port the caller chose, while the cage wiring — the socat's `TCP-CONNECT` port and the
    /// socket both sides share — stays on the port the caged service actually listens on. Getting
    /// this backwards is the whole failure mode the remap exists to avoid, and it is invisible from
    /// either side alone, so both are asserted here.
    #[test]
    fn a_remap_binds_the_host_side_and_wires_the_cage_side() {
        let data = TmpDir::new();
        let layout = Layout::under(data.path());
        // Two distinct free ports: one to publish on, one standing in for the caged service.
        let (guard, wiring, picked) = start_on_free_ports(&layout, 2, |p| {
            vec![ForwardPort {
                host: p[0],
                cage: p[1],
            }]
        });
        let (host_port, cage_port) = (picked[0], picked[1]);

        // The cage side is the cage port — on the forward, and on the socket path that names it.
        assert_eq!(wiring.forwards.len(), 1);
        assert_eq!(wiring.forwards[0].cage_port, cage_port);
        assert_eq!(
            wiring.forwards[0].cage_uds,
            PathBuf::from(format!("{CAGE_FORWARD_DIR}/p-{cage_port}.sock"))
        );
        // The host side is the host port: it is held, and the cage port is NOT bound on the host —
        // the remap moved the listener rather than adding one.
        assert!(
            TcpListener::bind(("127.0.0.1", host_port)).is_err(),
            "the remapped host port must be held by the forwarder"
        );
        assert!(
            TcpListener::bind(("127.0.0.1", cage_port)).is_ok(),
            "a remap must not bind the cage port on the host"
        );
        drop(guard);
    }

    /// Two forwards claiming one host port is sbx's own configuration double-booking, not the host
    /// being busy. It fails before any bind, with a message naming both cage ports — otherwise the
    /// bind error would blame "another login, or a host service" for a mistake in the config.
    #[test]
    fn two_forwards_on_one_host_port_fail_closed_naming_both_cage_ports() {
        let data = TmpDir::new();
        let layout = Layout::under(data.path());
        let free = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let host_port = free.local_addr().unwrap().port();
        drop(free);

        let msg = match start(
            &layout,
            vec![
                ForwardPort {
                    host: host_port,
                    cage: 9119,
                },
                ForwardPort {
                    host: host_port,
                    cage: 8787,
                },
            ],
        ) {
            Ok(_) => panic!("one host port for two cage ports must fail closed"),
            Err(e) => e.to_string(),
        };
        assert!(
            msg.contains("9119") && msg.contains("8787") && msg.contains(&host_port.to_string()),
            "the double-book error must name the host port and both cage ports: {msg}"
        );
        assert!(
            !msg.contains("already in use"),
            "a config double-book must not be reported as a busy host: {msg}"
        );
        // Nothing was bound: the check runs ahead of every listener, so no port leaked.
        assert!(
            TcpListener::bind(("127.0.0.1", host_port)).is_ok(),
            "a rejected double-book must leave the host port free"
        );
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
        let (guard, _wiring, picked) =
            start_on_free_ports(&layout, 1, |p| vec![ForwardPort::same(p[0])]);
        let port = picked[0];
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

    /// A bridge whose cage side goes away returns, even while the host client sits idle with the
    /// connection open — the shape at cage teardown, when socat dies and a browser keep-alive
    /// connection is still parked on the host port. Joining both copy threads (what this did
    /// before) never returned here: the host→cage copy stayed blocked in `read` on a client that
    /// sends nothing and closes nothing, pinning the thread and one of the `MAX_CONCURRENT_CONNS`
    /// slots for the life of the process. `the_host_bridge_round_trips_bytes_through_the_cage_socket`
    /// is the other half of this: the teardown must not cost the bytes that were in flight.
    #[test]
    fn a_bridge_returns_when_the_cage_side_closes_while_the_client_sits_idle() {
        use std::os::unix::net::UnixListener;

        let tmp = TmpDir::new();
        let sock = tmp.path().join("p-idle.sock");
        let cage = UnixListener::bind(&sock).expect("bind the stand-in cage socket");
        let host = TcpListener::bind("127.0.0.1:0").expect("bind a host listener");
        let addr = host.local_addr().unwrap();
        // The idle client: connected, silent, and deliberately kept alive to the end of the test.
        let client = TcpStream::connect(addr).expect("connect to the host port");
        let (accepted, _) = host.accept().expect("accept the host connection");

        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let _ = bridge(accepted, &sock);
            let _ = tx.send(());
        });
        // Stand in for the in-cage socat: accept, then vanish. Dropping the connection EOFs the
        // cage→host direction while nothing at all happens on the host→cage one.
        let (conn, _) = cage
            .accept()
            .expect("the bridge connects to the cage socket");
        drop(conn);

        rx.recv_timeout(Duration::from_secs(10)).expect(
            "the bridge must return once the cage side closes — an idle client that never closes \
             would otherwise pin the copy thread and its connection slot forever",
        );
        drop(client);
    }

    /// A bind that fails part-way through must leave nothing bound. The accept loops are detached
    /// threads, so anything not owned by the returned guard is unreachable the moment `start`
    /// returns `Err`: the port stays bound and its loop keeps polling for the life of the process.
    /// That bites the multi-app runs, which continue past a failed launch in the same process — the
    /// next app declaring that host port is then refused by sbx's own leaked listener, under a
    /// message blaming "another login, or a host service on :<port>".
    #[test]
    fn a_failed_bind_frees_the_ports_it_already_bound_in_the_same_call() {
        let data = TmpDir::new();
        let layout = Layout::under(data.path());
        // A port nothing can bind: held for the whole test by an unrelated listener.
        let held = TcpListener::bind(("127.0.0.1", 0)).expect("an ephemeral port");
        let taken = held.local_addr().expect("the bound address").port();

        // The forwards are bound in cage-port order, so the lower cage port binds first and the
        // higher one is the failure. A port picked by binding and releasing can be won by anything
        // else on the machine in between (a sibling test included); losing that race says nothing
        // about what this asserts, so a first bind that fails is retried with a fresh port.
        let mut left = 5;
        let good = loop {
            let probe = TcpListener::bind(("127.0.0.1", 0)).expect("an ephemeral port");
            let good = probe.local_addr().expect("the bound address").port();
            drop(probe);
            let msg = match start(
                &layout,
                vec![
                    ForwardPort {
                        host: good,
                        cage: 9119,
                    },
                    ForwardPort {
                        host: taken,
                        cage: 9219,
                    },
                ],
            ) {
                Ok(_) => panic!("a taken host port must fail the whole call"),
                Err(e) => e.to_string(),
            };
            if msg.contains(&format!("cannot bind host port {good} for forward")) && left > 0 {
                left -= 1;
                continue;
            }
            assert!(
                msg.contains(&format!("cannot bind host port {taken} for forward")),
                "the second forward is the one that failed: {msg}"
            );
            break good;
        };

        // The first listener was live when the second failed. The guard owning it is dropped on the
        // way out, which stops its accept loop and closes it — so the port is free. Retried briefly
        // only to absorb scheduling; a leaked listener never frees it.
        let mut freed = false;
        for _ in 0..50 {
            if TcpListener::bind(("127.0.0.1", good)).is_ok() {
                freed = true;
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(
            freed,
            "a failed `start` must not hold the ports it already bound for the life of the process"
        );
        // The per-launch directory goes with them, by the same drop.
        assert!(
            !layout
                .data_dir()
                .join("forward")
                .join(format!("fwd-{}", std::process::id()))
                .exists(),
            "a failed `start` must not leave its socket directory behind"
        );
        drop(held);
    }

    /// The per-launch directory is keyed by pid alone, so a launch can inherit the directory of a
    /// `SIGKILL`ed predecessor that reused the pid — `Forwarder::drop` never ran for it. The
    /// in-cage `socat UNIX-LISTEN` refuses a path that already exists and reports it into
    /// `/dev/null`, so the leftover would silently cost the session every byte of that forward.
    /// `start` clears the name it is about to hand the cage.
    #[test]
    fn a_stale_socket_left_by_a_dead_predecessor_is_cleared_before_the_cage_binds() {
        use std::os::unix::net::UnixListener;

        let data = TmpDir::new();
        let layout = Layout::under(data.path());
        let mut left = 5;
        let (guard, port) = loop {
            let probe = TcpListener::bind(("127.0.0.1", 0)).expect("an ephemeral port");
            let port = probe.local_addr().expect("the bound address").port();
            drop(probe);
            // What the killed predecessor left behind, at the exact name this launch will use.
            let stale = wiring_host_socket(&layout, port);
            std::fs::create_dir_all(stale.parent().expect("the socket sits in a directory"))
                .expect("stage the predecessor's directory");
            std::fs::write(&stale, b"").expect("stage the predecessor's socket file");
            match start(&layout, vec![ForwardPort::same(port)]) {
                Ok((guard, _wiring)) => break (guard, port),
                // The probed port was taken between the probe and the bind — see
                // `start_on_free_ports`.
                Err(e) if e.kind() == io::ErrorKind::AddrInUse && left > 0 => left -= 1,
                Err(e) => panic!("start binds the port it was given: {e:?}"),
            }
        };

        // The in-cage forwarder's bind is the thing that must succeed; here the test stands in for
        // it, because `UNIX-LISTEN` and `UnixListener::bind` fail on an existing path alike.
        let sock = wiring_host_socket(&layout, port);
        let bound = UnixListener::bind(&sock).expect(
            "the cage's socat must be able to bind its socket: a leftover file at that name \
             fails its `UNIX-LISTEN` into `/dev/null`, and the forward carries nothing all session",
        );
        drop(bound);
        drop(guard);
    }

    /// The forward directory is bound into the cage read-**write** — the in-cage `socat` creates
    /// and unlinks its own sockets there — so the cage owns every name in it, and the host dials one
    /// of those names for each connection it accepts. A name replaced by a symlink must be refused
    /// rather than followed: following it splices a host-side client into a host service of the
    /// cage's choosing, and the forward's one guarantee — that this port reaches the caged service —
    /// is gone.
    #[test]
    fn a_forward_socket_the_cage_replaced_with_a_symlink_is_never_dialed() {
        use std::os::unix::net::UnixListener;

        let tmp = TmpDir::new();
        // Stand in for the host service the cage would like the forward aimed at.
        let target = tmp.path().join("host-service.sock");
        let victim = UnixListener::bind(&target).expect("bind the stand-in host service");
        victim
            .set_nonblocking(true)
            .expect("the victim is polled, never waited on");
        // The name the host dials, pointed elsewhere — what the cage can do the moment socat has
        // bound it.
        let name = tmp.path().join("p-9119.sock");
        std::os::unix::fs::symlink(&target, &name).expect("plant the link");

        let host = TcpListener::bind("127.0.0.1:0").expect("bind a host listener");
        let client = TcpStream::connect(host.local_addr().unwrap()).expect("connect to the port");
        let (accepted, _) = host.accept().expect("accept the host connection");

        let (tx, rx) = std::sync::mpsc::channel();
        let dialed = name.clone();
        std::thread::spawn(move || {
            let _ = tx.send(bridge(accepted, &dialed).is_err());
        });
        let refused = rx.recv_timeout(Duration::from_secs(10)).expect(
            "the bridge must refuse the link outright — following it connects the host client to \
             the service the link names, and the copy then sits on that connection",
        );
        assert!(refused, "a symlinked socket name must not be dialed");
        assert!(
            matches!(victim.accept(), Err(e) if e.kind() == io::ErrorKind::WouldBlock),
            "nothing may reach the service the link pointed at"
        );

        // And the real shape is untouched: a socket at the name is dialed, through the descriptor
        // the name resolved to.
        std::fs::remove_file(&name).expect("clear the link");
        let cage = UnixListener::bind(&name).expect("bind the stand-in cage socket");
        let _dialed = dial_cage_socket(&name).expect("a real socket at the name is dialed");
        cage.accept()
            .expect("the dial reached the socket at the name");
        drop(client);
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
