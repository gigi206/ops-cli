//! The egress proxy's own process: what `sbx __proxy` runs, and how the supervisor starts one.
//!
//! The proxy reads what the cage sends, which makes it the part of sbx an attacker in the cage
//! talks to. It runs apart from the supervisor, in a cage of its own ([`cage`]): an empty network
//! namespace, and no host filesystem but the read-only userland its binary may need to load. It
//! holds what its work needs, the policy, the credentials it injects and the authority it mints
//! leaves with, and asks the supervisor for the rest: every upstream connection, every parked
//! request, every refreshed credential ([`super::link`]). What it did leaves it as reports
//! ([`super::events`]).
//!
//! **Starting.** The supervisor binds the cage's socket, starts the proxy holding one descriptor,
//! its end of the link, and sends it a [`Bootstrap`] first: the policy, as the very bytes the
//! supervisor's judge decoded, the credentials, and what the launch keeps of the reports; beside the
//! document, the socket to serve, the proxy's end of the report channel and the signers' sockets.
//! The supervisor keeps no copy of any of them. The proxy mints its certificate authority itself
//! and, once it serves, answers [`Ready`] with the certificate, from which the supervisor writes the
//! cage's trust anchor: the key never exists outside the proxy. A proxy that has not answered within
//! [`START_WAIT`] is stopped and the launch fails, so a cage never starts in front of a proxy that
//! does not serve.
//!
//! **Stopping.** The proxy serves until its link ends, closed by the supervisor
//! ([`super::link::Supervisor::close`]) or with the supervisor's process, and then exits, taking
//! whatever it still had open with it.

use super::inject::Transfer;
use super::link::{Judge, Parks, Supervisor, wire};
use super::{Ca, CredentialRefresh, Credentials, ProxyCtx};
use crate::allowlist::EgressPolicy;
use crate::sandbox::spec::{Mount, NetPolicy, SandboxSpec};
use serde::{Deserialize, Serialize};
use std::ffi::OsString;
use std::fs::File;
use std::io;
use std::os::fd::{AsRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::process::{Child, Command, ExitCode, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Sender, channel};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;

#[cfg(not(test))]
pub(crate) use process::Proxy;
#[cfg(test)]
pub(crate) use stand_in::Proxy;

/// How long the supervisor waits for a proxy it started to say it serves. Far above what a start
/// costs, its cage included: a proxy that has not answered by then is not going to.
const START_WAIT: Duration = Duration::from_secs(10);

/// How long a proxy whose link was closed has to exit before it is killed.
pub(crate) const STOP_WAIT: Duration = Duration::from_secs(2);

/// Where the proxy's binary is inside its cage.
const BINARY: &str = "/sbx";

/// What a proxy is started with. The descriptors handed over beside it are, in order: the socket
/// to serve, the proxy's end of the report channel, then the signers' sockets its credentials name.
#[derive(Serialize, Deserialize)]
struct Bootstrap {
    /// The policy, the bytes the supervisor's judge decoded ([`EgressPolicy::encode`]).
    policy: String,
    /// The credentials' document ([`Credentials::encode`]).
    credentials: String,
    /// The `sbx app` the launch runs, which the fix a refusal suggests names.
    app: Option<String>,
    /// What the launch keeps of the proxy's reports.
    keeps: super::events::Keeps,
}

/// What a proxy says once it serves: the certificate of the authority it mints leaves with, in PEM.
#[derive(Serialize, Deserialize)]
struct Ready {
    ca: String,
}

/// What the supervisor starts a proxy with.
pub(crate) struct Start<'a> {
    /// The bubblewrap that cages it.
    pub(crate) bwrap: &'a Path,
    /// The policy's bytes, the ones the supervisor's judge was built from.
    pub(crate) policy: &'a [u8],
    pub(crate) credentials: &'a Credentials,
    pub(crate) app: Option<&'a str>,
    /// The cage's socket, bound and listening.
    pub(crate) listener: UnixListener,
    /// The proxy's end of the report channel ([`super::events::applied`]).
    pub(crate) reports: UnixStream,
    pub(crate) keeps: super::events::Keeps,
}

/// A proxy the supervisor started: the process, the supervisor's end of its link, and the
/// certificate it mints leaves with, in PEM, for the cage's trust anchor.
pub(crate) struct Launched {
    pub(crate) proxy: Proxy,
    pub(crate) supervisor: Supervisor,
    pub(crate) ca: String,
}

/// Start a proxy as `start` says, and serve its link with `judge`, `parks` and `refresh`: returned
/// once the proxy serves.
pub(crate) fn launch(
    start: Start<'_>,
    judge: Arc<Judge>,
    parks: Parks,
    refresh: Option<Arc<CredentialRefresh>>,
) -> io::Result<Launched> {
    let not_started =
        |e: io::Error| io::Error::new(e.kind(), format!("the egress proxy did not start: {e}"));
    let (down, up) = wire::Socket::pair()?;
    let proxy = Proxy::start(start.bwrap, up, &start.listener).map_err(not_started)?;
    let served = hand_over(&down, start, START_WAIT)
        .and_then(|ca| Ok((ca, super::link::supervising(down, judge, parks, refresh)?)));
    match served {
        Ok((ca, supervisor)) => Ok(Launched {
            proxy,
            supervisor,
            ca,
        }),
        // The supervisor's end of the link is gone by now, so a proxy still reading it reads the
        // end before it is stopped.
        Err(e) => Err(not_started(e)),
    }
}

/// Hand the proxy at the other end of `down` what `start` holds, and wait up to `wait` for it to say
/// it serves: the certificate it mints leaves with.
fn hand_over(down: &wire::Socket, start: Start<'_>, wait: Duration) -> io::Result<String> {
    let (credentials, signers) = start.credentials.encode()?.into_parts();
    let bootstrap = Bootstrap {
        policy: String::from_utf8(start.policy.to_vec())
            .map_err(|_| wire::invalid("a policy that is not text"))?,
        credentials: String::from_utf8(credentials)
            .map_err(|_| wire::invalid("a credential document that is not text"))?,
        app: start.app.map(str::to_string),
        keeps: start.keeps,
    };
    let doc = serde_json::to_vec(&bootstrap)
        .map_err(|_| wire::invalid("a start that does not encode"))?;
    let mut fds = vec![OwnedFd::from(start.listener), OwnedFd::from(start.reports)];
    fds.extend(signers);
    down.send_down(&doc, &fds)?;
    // This process's copies go at once. Kept, they would outlive a proxy that dies: the cage would
    // go on connecting into a queue nobody serves instead of being refused, and the report channel
    // would never end.
    drop(fds);
    // Waited for by `poll` rather than a receive timeout, which would stay on the socket the
    // supervisor's reader then reads: every quiet stretch that long would end the link.
    if !down.readable_within(wait)? {
        return Err(io::Error::new(
            io::ErrorKind::TimedOut,
            format!("no answer within {:?}", wait),
        ));
    }
    let mut buf = vec![0u8; wire::MAX_UP];
    let n = down.recv_up_into(&mut buf)?.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "it ended before it served (its own error, if any, is above)",
        )
    })?;
    let ready: Ready = serde_json::from_slice(&buf[..n])
        .map_err(|_| wire::invalid("an answer that does not parse"))?;
    certificate(&ready.ca)?;
    Ok(ready.ca)
}

/// Refused unless `pem` is one certificate and nothing else: the supervisor writes it into the
/// cage's trust anchor.
fn certificate(pem: &str) -> io::Result<()> {
    use rustls::pki_types::CertificateDer;
    use rustls::pki_types::pem::PemObject;
    let mut certs = CertificateDer::pem_slice_iter(pem.as_bytes());
    let one = matches!((certs.next(), certs.next()), (Some(Ok(_)), None));
    let only = pem.starts_with("-----BEGIN CERTIFICATE-----")
        && pem.trim_end().ends_with("-----END CERTIFICATE-----");
    if one && only {
        Ok(())
    } else {
        Err(wire::invalid("an answer that is not one certificate"))
    }
}

/// `sbx __proxy <fd>`: serve as an egress proxy over the link held as `fd`, until it ends. Started
/// by the supervisor inside a cage of its own ([`launch`]), never by a user.
pub(crate) fn main(argv: &[OsString]) -> ExitCode {
    let fd = match argv {
        [fd] => fd.to_str().and_then(|fd| fd.parse::<RawFd>().ok()),
        _ => None,
    };
    let Some(fd) = fd else {
        crate::diag::error("sbx: __proxy: expects the descriptor of its link, and nothing else");
        return ExitCode::from(2);
    };
    match wire::Socket::adopt(fd).and_then(|link| run(link, &Arc::new(AtomicBool::new(false)))) {
        // Returning ends the process, and every thread the proxy still had with it.
        Ok(_) => ExitCode::SUCCESS,
        Err(e) => {
            crate::diag::error(&format!("sbx: egress proxy: {e}"));
            ExitCode::FAILURE
        }
    }
}

/// Serve as the proxy at the other end of `link` until the link ends: read the start, mint the
/// certificate authority, stand everything up, say so, and serve. Returns the thread accepting the
/// cage's connections, which `stop` ends once it is set and the accept it waits in returns; a
/// process ends it by exiting.
fn run(link: wire::Socket, stop: &Arc<AtomicBool>) -> io::Result<JoinHandle<()>> {
    let (doc, fds) = link.recv_down()?.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "the link ended before the proxy was started",
        )
    })?;
    let start: Bootstrap =
        serde_json::from_slice(&doc).map_err(|_| wire::invalid("a start that does not parse"))?;
    let mut fds = fds.into_iter();
    let (Some(listener), Some(reports)) = (fds.next(), fds.next()) else {
        return Err(wire::invalid(
            "a start that hands over no socket to serve or no channel to report on",
        ));
    };
    let credentials = Credentials::decode(Transfer::from_parts(
        start.credentials.into_bytes(),
        fds.collect(),
    ))?;
    let policy = EgressPolicy::decode(start.policy.as_bytes())?;
    let events = super::events::emitter(UnixStream::from(reports), start.keeps)?;
    let (link, reader) = super::link::attend(link, Some(events.clone()))?;
    let ctx = Arc::new(
        ProxyCtx::linked(Arc::new(Ca::ephemeral()?), policy, link)?
            .with_shared_credentials(Arc::new(credentials))
            .with_app(start.app)
            .with_events(events),
    );
    let ready = serde_json::to_vec(&Ready {
        ca: ctx.ca_cert_pem().to_string(),
    })
    .map_err(|_| wire::invalid("an answer that does not encode"))?;
    let serving = {
        let (ctx, stop) = (Arc::clone(&ctx), Arc::clone(stop));
        let listener = UnixListener::from(listener);
        std::thread::Builder::new()
            .name("sbx-proxy-accept".into())
            .spawn(move || {
                // A serve error ends the accepting, and the cage loses egress: fail-closed.
                let _ = super::serve(listener, ctx, stop);
            })?
    };
    // Last, once everything it serves with stands: the supervisor starts the cage on this.
    ctx.link.announce(&ready)?;
    drop(ctx);
    let _ = reader.join();
    stop.store(true, Ordering::SeqCst);
    Ok(serving)
}

/// The cage a proxy runs in, and the descriptors bwrap reads, the proxy's end of the link `link`
/// among them.
fn command(bwrap: &Path, link: wire::Socket) -> io::Result<(Command, Vec<File>)> {
    // The build that is running, whatever has become of its file since: a proxy started from a
    // binary replaced mid-session would speak another build's messages.
    let binary = File::open("/proc/self/exe")?;
    let spec = cage(
        binary.as_raw_fd(),
        deleted(&binary),
        std::os::fd::AsFd::as_fd(&link).as_raw_fd(),
    )?;
    let (argv, mut files) = crate::sandbox::argv::compose(&spec)?;
    files.push(binary);
    files.push(File::from(OwnedFd::from(link)));
    let mut command = Command::new(bwrap);
    command
        .args(argv)
        .stdin(Stdio::null())
        .stdout(Stdio::null());
    Ok((command, files))
}

/// The cage a proxy runs in: the empty network namespace and the hardening every cage gets, the
/// host's userland read-only for a binary that loads libraries, and the binary open as `binary`
/// at [`BINARY`], bound where it is or `copy`'d when its file is gone. Nothing else of the host.
fn cage(binary: RawFd, copy: bool, link: RawFd) -> io::Result<SandboxSpec> {
    let ro = |p: &str| Mount::RoBind {
        src: p.into(),
        dest: p.into(),
    };
    let symlink = |target: &str, dest: &str| Mount::Symlink {
        target: target.into(),
        dest: dest.into(),
    };
    let mounts = vec![
        ro("/usr"),
        symlink("usr/lib", "/lib"),
        symlink("usr/lib64", "/lib64"),
        Mount::RoBindTry {
            src: "/etc/ld.so.cache".into(),
            dest: "/etc/ld.so.cache".into(),
        },
        if copy {
            Mount::Copy {
                fd: binary,
                dest: BINARY.into(),
            }
        } else {
            // Through the descriptor's own link, which names the file it was opened on even after
            // a rename.
            Mount::RoBind {
                src: format!("/proc/self/fd/{binary}").into(),
                dest: BINARY.into(),
            }
        },
    ];
    SandboxSpec::new(
        "/".into(),
        mounts,
        Vec::new(),
        NetPolicy::Isolated,
        vec![BINARY.into(), "__proxy".into(), link.to_string().into()],
    )
    .map_err(|e| io::Error::other(format!("cannot build the egress proxy's cage: {e:?}")))
}

/// Whether the file `open` was opened on has been deleted since, as its `/proc` link says.
fn deleted(open: &File) -> bool {
    std::fs::read_link(format!("/proc/self/fd/{}", open.as_raw_fd()))
        .is_ok_and(|target| target.as_os_str().as_bytes().ends_with(b" (deleted)"))
}

/// A start the thread in [`spawn_lasting`] runs: the command, the descriptors it reads, and where
/// the outcome goes.
struct Job {
    command: Command,
    files: Vec<File>,
    done: Sender<io::Result<Child>>,
}

/// Start `command`, handing it `files`, from the one thread of this process that lives as long as
/// the process does.
///
/// A cage dies with the thread that started it, not with the process: `--die-with-parent` arms the
/// parent-death signal, which follows the thread (measured when a refresh started a signer). A task
/// starts its proxy from the thread of its invocation, which ends with it, and a proxy started from
/// there would die under a guard that still holds it. This thread starts every proxy instead, and
/// never ends.
fn spawn_lasting(command: Command, files: Vec<File>) -> io::Result<Child> {
    static LAUNCHER: Mutex<Option<Sender<Job>>> = Mutex::new(None);
    let gone = || io::Error::other("the thread that starts the egress proxy is gone");
    let (done, outcome) = channel();
    let job = Job {
        command,
        files,
        done,
    };
    let sender = {
        let mut launcher = crate::sandbox::locks::locked(&LAUNCHER);
        match launcher.as_ref() {
            Some(sender) => sender.clone(),
            None => {
                let (sender, jobs) = channel::<Job>();
                std::thread::Builder::new()
                    .name("sbx-launcher".into())
                    .spawn(move || {
                        for mut job in jobs {
                            crate::sandbox::memfd::inherit_across_exec(
                                &mut job.command,
                                &job.files,
                            );
                            let started = job.command.spawn();
                            // Read by bwrap by now, or never: this process's copies go at once.
                            drop(job.files);
                            let _ = job.done.send(started);
                        }
                    })?;
                *launcher = Some(sender.clone());
                sender
            }
        }
    };
    if sender.send(job).is_err() {
        // The next start makes a new one.
        crate::sandbox::locks::locked(&LAUNCHER).take();
        return Err(gone());
    }
    outcome.recv().map_err(|_| gone())?
}

/// The proxy as a process in its cage.
#[cfg(not(test))]
mod process {
    use super::*;

    /// A proxy running in its cage, stopped when this is dropped.
    pub(crate) struct Proxy {
        child: Option<Child>,
    }

    impl Proxy {
        /// Start a proxy caged by `bwrap`, holding `link`.
        pub(super) fn start(
            bwrap: &Path,
            link: wire::Socket,
            _listener: &UnixListener,
        ) -> io::Result<Proxy> {
            let (command, files) = command(bwrap, link)?;
            Ok(Proxy {
                child: Some(spawn_lasting(command, files)?),
            })
        }

        /// Give the proxy up to `wait` to exit, its link closed, then kill it; and reap it. A proxy
        /// that was given time and did not use it is said so: it stopped serving without seeing
        /// the end of its link.
        pub(crate) fn stop(&mut self, wait: Duration) {
            let Some(mut child) = self.child.take() else {
                return;
            };
            let deadline = std::time::Instant::now() + wait;
            while let Ok(None) = child.try_wait() {
                if std::time::Instant::now() >= deadline {
                    if !wait.is_zero() {
                        crate::diag::warn(&format!(
                            "the egress proxy had not stopped {}s after its link was closed, \
                             and was killed",
                            wait.as_secs()
                        ));
                    }
                    let _ = child.kill();
                    let _ = child.wait();
                    return;
                }
                std::thread::sleep(Duration::from_millis(5));
            }
        }
    }

    impl Drop for Proxy {
        fn drop(&mut self) {
            self.stop(Duration::ZERO);
        }
    }
}

/// The proxy on a thread of the test process.
#[cfg(test)]
mod stand_in {
    use super::*;

    /// A proxy that runs [`run`] on a thread of this process instead of in a cage: a test binary is
    /// not sbx and cannot be started as `sbx __proxy`, and a host without user namespaces (the hosted
    /// CI) has no cage to start. The start, the bytes and everything the proxy stands up are its
    /// own; the process and the cage are not.
    pub(crate) struct Proxy {
        stop: Arc<AtomicBool>,
        /// The cage's socket, which a stop connects to once to unpark the accept its loop waits in.
        poke: Option<std::path::PathBuf>,
        running: Option<JoinHandle<io::Result<JoinHandle<()>>>>,
    }

    impl Proxy {
        pub(super) fn start(
            _bwrap: &Path,
            link: wire::Socket,
            listener: &UnixListener,
        ) -> io::Result<Proxy> {
            let stop = Arc::new(AtomicBool::new(false));
            let poke = listener.local_addr()?.as_pathname().map(Path::to_path_buf);
            let running = {
                let stop = Arc::clone(&stop);
                std::thread::Builder::new()
                    .name("sbx-proxy".into())
                    .spawn(move || run(link, &stop))?
            };
            Ok(Proxy {
                stop,
                poke,
                running: Some(running),
            })
        }

        /// No proxy at all: what a test of the guard alone holds.
        pub(crate) fn none() -> Proxy {
            Proxy {
                stop: Arc::new(AtomicBool::new(true)),
                poke: None,
                running: None,
            }
        }

        /// Give the proxy up to `wait` to see its link end, as a proxy in its cage does, and only
        /// then end its accepting, as that proxy's exit would: the flag first, then one connection
        /// to unpark the accept, which reads the flag as it returns. Ended first, the accepting
        /// would drop the proxy's end of the link and end the link itself, and a stop that never
        /// closed the link would pass for one that did.
        pub(crate) fn stop(&mut self, wait: Duration) {
            let Some(running) = self.running.take() else {
                return;
            };
            let deadline = std::time::Instant::now() + wait;
            while !running.is_finished() && std::time::Instant::now() < deadline {
                std::thread::sleep(Duration::from_millis(1));
            }
            self.stop.store(true, Ordering::SeqCst);
            if let Some(poke) = &self.poke {
                let _ = UnixStream::connect(poke);
            }
            if running.is_finished()
                && let Ok(Ok(serving)) = running.join()
            {
                let _ = serving.join();
            }
        }
    }

    impl Drop for Proxy {
        fn drop(&mut self) {
            self.stop(Duration::ZERO);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sandbox::control::{LOG_RING_CAP, LogRing, PendingState};
    use crate::sandbox::proxy::events::Sinks;
    use crate::testutil::TmpDir;
    use std::io::{BufRead, BufReader, Write};

    /// A proxy started over the default policy, serving a socket bound in `dir` and reporting into
    /// `log`, with nothing to inject; and the socket's path.
    fn started(dir: &TmpDir, log: &Arc<LogRing>) -> (Launched, std::path::PathBuf) {
        let path = dir.join("proxy.sock");
        let listener = UnixListener::bind(&path).unwrap();
        let bytes = EgressPolicy::default().encode().unwrap();
        let judge = Arc::new(Judge::new(&bytes).unwrap());
        let parks = Parks::for_policy(judge.policy(), Arc::new(PendingState::new()));
        let (reports, keeps, _applier) = super::super::events::applied(Sinks {
            log: Some(Arc::clone(log)),
            ..Sinks::default()
        })
        .unwrap();
        let credentials = Credentials::new(
            Vec::new(),
            Vec::new(),
            crate::sandbox::redact::MIN_LEN_DEFAULT,
            Vec::new(),
        );
        let launched = launch(
            Start {
                bwrap: Path::new("/nonexistent/bwrap"),
                policy: &bytes,
                credentials: &credentials,
                app: None,
                listener,
                reports,
                keeps,
            },
            judge,
            parks,
            None,
        )
        .unwrap();
        (launched, path)
    }

    /// The status line the proxy answers a cleartext request to `host` with, over the socket at
    /// `path`.
    fn answer_to_request(path: &Path, host: &str) -> String {
        let mut stream = UnixStream::connect(path).unwrap();
        write!(
            stream,
            "GET http://{host}/ HTTP/1.1\r\nHost: {host}\r\n\r\n"
        )
        .unwrap();
        let mut line = String::new();
        BufReader::new(stream).read_line(&mut line).unwrap();
        line
    }

    /// A started proxy serves the socket it was handed, reports through the channel it was handed,
    /// and says it serves with the certificate of the authority it mints leaves with.
    #[test]
    fn a_started_proxy_serves_its_socket_and_reports_through_its_channel() {
        let dir = TmpDir::new();
        let log = Arc::new(LogRing::new(LOG_RING_CAP));
        let (launched, path) = started(&dir, &log);
        certificate(&launched.ca).unwrap();
        let line = answer_to_request(&path, "nowhere.test");
        assert!(line.starts_with("HTTP/1.1 403"), "{line}");
        launched.supervisor.flush();
        let events = log.snapshot(None, None, true).events;
        assert!(
            events
                .iter()
                .any(|e| e.host == "nowhere.test" && e.reason == "denied-default"),
            "{events:?}"
        );
    }

    /// A proxy whose link the supervisor closes stops on its own, well before it would be killed,
    /// and the socket it served then refuses a connection rather than queueing it: the supervisor
    /// kept no copy of it.
    #[test]
    fn a_proxy_whose_link_is_closed_stops_and_its_socket_refuses() {
        let dir = TmpDir::new();
        let log = Arc::new(LogRing::new(LOG_RING_CAP));
        let (mut launched, path) = started(&dir, &log);
        launched.supervisor.close();
        let begun = std::time::Instant::now();
        launched.proxy.stop(STOP_WAIT);
        assert!(
            begun.elapsed() < STOP_WAIT,
            "the proxy stopped only when its wait ran out: {:?}",
            begun.elapsed()
        );
        let refused = UnixStream::connect(&path).map(drop).map_err(|e| e.kind());
        assert_eq!(refused, Err(io::ErrorKind::ConnectionRefused));
    }

    /// A proxy that does not say it serves with one certificate and nothing else, in time, is not
    /// started: the cage's trust anchor is written from that answer.
    #[test]
    fn a_proxy_that_does_not_answer_with_one_certificate_in_time_is_refused() {
        let one = Ca::ephemeral().unwrap().ca_cert_pem().to_string();
        let two = format!("{one}{}", Ca::ephemeral().unwrap().ca_cert_pem());
        let answer = |ca: &str| Some(serde_json::to_vec(&Ready { ca: ca.to_string() }).unwrap());
        for (answer, kind) in [
            (answer(&one), None),
            (
                answer("not a certificate"),
                Some(io::ErrorKind::InvalidData),
            ),
            (answer(&two), Some(io::ErrorKind::InvalidData)),
            (
                answer(&format!("text before it\n{one}")),
                Some(io::ErrorKind::InvalidData),
            ),
            (Some(b"{}".to_vec()), Some(io::ErrorKind::InvalidData)),
            (None, Some(io::ErrorKind::TimedOut)),
        ] {
            let dir = TmpDir::new();
            let listener = UnixListener::bind(dir.join("proxy.sock")).unwrap();
            let (reports, _) = UnixStream::pair().unwrap();
            let (down, up) = wire::Socket::pair().unwrap();
            let (release, released) = channel::<()>();
            let peer = std::thread::spawn(move || {
                // The start is read first, as a proxy reads it: the link's reader would refuse it.
                let _ = up.recv_down().unwrap();
                let (link, _reader) = super::super::link::attend(up, None).unwrap();
                if let Some(answer) = answer {
                    link.announce(&answer).unwrap();
                }
                // Holds its end until the test is done with it, so the only answer is the one sent.
                let _ = released.recv();
            });
            let credentials = Credentials::new(
                Vec::new(),
                Vec::new(),
                crate::sandbox::redact::MIN_LEN_DEFAULT,
                Vec::new(),
            );
            let handed = hand_over(
                &down,
                Start {
                    bwrap: Path::new("/nonexistent/bwrap"),
                    policy: b"{}",
                    credentials: &credentials,
                    app: None,
                    listener,
                    reports,
                    keeps: super::super::events::Keeps {
                        stats: false,
                        refusals: false,
                        signatures: false,
                        log: false,
                        capture: None,
                        flows: false,
                    },
                },
                Duration::from_millis(300),
            );
            drop(release);
            peer.join().unwrap();
            assert_eq!(
                handed.as_ref().err().map(io::Error::kind),
                kind,
                "{handed:?}"
            );
        }
    }

    /// The cage binds the running binary through its descriptor, or copies it when its file is gone,
    /// and holds nothing else of the host but the read-only userland: no network, no writable path,
    /// no device.
    #[test]
    fn the_proxys_cage_holds_its_binary_and_the_userland_alone() {
        let words = |spec: &SandboxSpec| -> Vec<String> {
            crate::sandbox::argv::to_argv(spec)
                .iter()
                .map(|w| w.to_string_lossy().into_owned())
                .collect()
        };
        let has = |argv: &[String], run: &[&str]| argv.windows(run.len()).any(|w| w == run);
        let bound = words(&cage(9, false, 7).unwrap());
        assert!(
            has(&bound, &["--ro-bind", "/proc/self/fd/9", "/sbx"]),
            "{bound:?}"
        );
        assert!(bound.ends_with(&["--".into(), "/sbx".into(), "__proxy".into(), "7".into()]));
        let copied = words(&cage(9, true, 7).unwrap());
        assert!(
            has(&copied, &["--perms", "0555", "--file", "9", "/sbx"]),
            "{copied:?}"
        );
        assert!(
            !copied.iter().any(|w| w.starts_with("/proc/self/fd")),
            "{copied:?}"
        );
        for argv in [&bound, &copied] {
            assert!(has(argv, &["--unshare-net"]), "{argv:?}");
            let sources: Vec<&str> = argv
                .windows(2)
                .filter(|w| w[0].starts_with("--") && w[0].contains("bind"))
                .map(|w| w[1].as_str())
                .collect();
            let allowed = ["/usr", "/etc/ld.so.cache", "/proc/self/fd/9"];
            assert!(sources.iter().all(|s| allowed.contains(s)), "{sources:?}");
            for absent in ["--bind", "--dev", "--dev-bind", "--dev-bind-try", "--proc"] {
                assert!(!argv.iter().any(|w| w == absent), "{absent} in {argv:?}");
            }
        }
    }

    /// Every descriptor the cage's argv names is one the command hands bwrap: its filters, the
    /// running binary, and the link the proxy is told to serve.
    #[test]
    fn the_command_hands_bwrap_every_descriptor_its_argv_names() {
        let (end, _other) = wire::Socket::pair().unwrap();
        let link = std::os::fd::AsFd::as_fd(&end).as_raw_fd();
        let (command, files) = command(Path::new("/nonexistent/bwrap"), end).unwrap();
        let handed: Vec<RawFd> = files.iter().map(AsRawFd::as_raw_fd).collect();
        let argv: Vec<String> = command
            .get_args()
            .map(|w| w.to_string_lossy().into_owned())
            .collect();
        let mut named = Vec::new();
        for pair in argv.windows(2) {
            if pair[0] == "--add-seccomp-fd" {
                named.push(pair[1].parse::<RawFd>().unwrap());
            }
            if let Some(fd) = pair[1].strip_prefix("/proc/self/fd/") {
                named.push(fd.parse().unwrap());
            }
        }
        named.push(argv.last().unwrap().parse().unwrap());
        assert_eq!(named.last(), Some(&link), "{argv:?}");
        assert!(named.len() >= 3, "{argv:?}");
        for fd in &named {
            assert!(handed.contains(fd), "{fd} named but not handed: {argv:?}");
        }
    }

    /// A file deleted after it was opened reads as such through its descriptor; one still there
    /// does not.
    #[test]
    fn a_binary_deleted_since_it_was_opened_is_seen_as_gone() {
        let dir = TmpDir::new();
        let path = dir.join("sbx");
        std::fs::write(&path, b"x").unwrap();
        let open = File::open(&path).unwrap();
        assert!(!deleted(&open));
        std::fs::rename(&path, dir.join("moved")).unwrap();
        assert!(
            !deleted(&open),
            "a rename leaves the file where the descriptor finds it"
        );
        std::fs::remove_file(dir.join("moved")).unwrap();
        assert!(deleted(&open));
    }

    /// A process the launcher starts lives on after the thread that asked for it ends, though it
    /// dies with the thread that started it: the launcher's own thread, which does not end.
    #[test]
    fn a_process_started_for_a_thread_that_ends_outlives_it() {
        let mut command = Command::new("sleep");
        command.arg("30");
        // SAFETY: `prctl` is async-signal-safe, and the closure allocates nothing.
        unsafe {
            std::os::unix::process::CommandExt::pre_exec(&mut command, || {
                if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) < 0 {
                    return Err(io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let mut child = std::thread::spawn(move || spawn_lasting(command, Vec::new()))
            .join()
            .unwrap()
            .unwrap();
        std::thread::sleep(Duration::from_millis(300));
        let alive = child.try_wait().unwrap().is_none();
        let _ = child.kill();
        let _ = child.wait();
        assert!(alive, "the process died with the thread that asked for it");
    }

    /// The link a process is started holding is taken only when it is the kind of socket a link is.
    #[test]
    fn only_a_link_socket_is_adopted_as_a_link() {
        let (end, _other) = wire::Socket::pair().unwrap();
        let fd = OwnedFd::from(end);
        let raw = std::os::fd::IntoRawFd::into_raw_fd(fd);
        assert!(wire::Socket::adopt(raw).is_ok());
        let (stream, _peer) = UnixStream::pair().unwrap();
        let err = wire::Socket::adopt(stream.as_raw_fd())
            .map(drop)
            .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(wire::Socket::adopt(-1).is_err());
    }
}
