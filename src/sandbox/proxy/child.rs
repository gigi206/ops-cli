//! The egress proxy's own process: what `sbx __proxy` runs, and how the supervisor starts one.
//!
//! The proxy reads what the cage sends, which makes it the part of sbx an attacker in the cage
//! talks to. It runs apart from the supervisor, in a cage of its own ([`cage`]): an empty network
//! namespace, and no host filesystem but the read-only userland its binary may need to load; and
//! under seccomp filters of its own, which name the calls it may make
//! ([`crate::sandbox::seccomp::proxy`]). It holds what its work needs, the policy, the credentials
//! it injects and the authority it mints leaves with, and asks the supervisor for the rest: every
//! upstream connection, every parked request, every refreshed credential ([`super::link`]). What it
//! did leaves it as reports ([`super::events`]).
//!
//! **Starting.** The supervisor binds the cage's socket, starts the proxy holding one descriptor,
//! its end of the link, and sends it a [`Bootstrap`] first: the policy, as the very bytes the
//! supervisor's judge decoded, the credentials, what the launch keeps of the reports, and the
//! host's memory, which the proxy's cage has no `/proc` to read; beside the document, the socket to
//! serve, the proxy's end of the report channel and the signers' sockets. The supervisor keeps no
//! copy of any of them. The proxy mints its certificate authority itself and, once it serves,
//! answers [`Ready`] with the certificate, from which the supervisor writes the cage's trust
//! anchor: the key never exists outside the proxy. A proxy that has not answered within
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
use crate::sandbox::selfcage;
use crate::sandbox::spec::{NetPolicy, SandboxSpec};
use serde::{Deserialize, Serialize};
use std::ffi::OsString;
use std::fs::File;
use std::io;
use std::os::fd::{AsRawFd, OwnedFd, RawFd};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::process::{Child, Command, ExitCode, Stdio};
use std::sync::atomic::AtomicBool;
use std::sync::mpsc::{Sender, channel};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;

pub(crate) use process::Proxy;

/// How long the supervisor waits for a proxy it started to say it serves. Far above what a start
/// costs, its cage included: a proxy that has not answered by then is not going to.
const START_WAIT: Duration = Duration::from_secs(10);

/// How long a proxy whose link was closed has to exit before it is killed.
pub(crate) const STOP_WAIT: Duration = Duration::from_secs(2);

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
    /// The host's memory in bytes, as the supervisor read it ([`super::host_ram`]): it bounds the
    /// request bodies the proxy holds at once, and the proxy's cage has no `/proc` to read it from.
    ram: Option<u64>,
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
    let proxy = Proxy::start(start.bwrap, up).map_err(not_started)?;
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
        ram: super::host_ram(),
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
    match wire::Socket::adopt(fd).and_then(run) {
        // Returning ends the process, and every thread the proxy still had with it.
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            crate::diag::error(&format!("sbx: egress proxy: {e}"));
            ExitCode::FAILURE
        }
    }
}

/// Serve as the proxy at the other end of `link` until the link ends: go under the proxy's seccomp
/// filters, read the start, mint the certificate authority, stand everything up, say so, and serve.
/// Returns once the link has ended, and the process, ending, takes the accepting with it.
fn run(link: wire::Socket) -> io::Result<()> {
    // First, on the thread every other one of the proxy's is started from, before it reads a byte.
    crate::sandbox::seccomp::proxy::confine()?;
    let (doc, fds) = link.recv_down()?.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "the link ended before the proxy was started",
        )
    })?;
    let start: Bootstrap =
        serde_json::from_slice(&doc).map_err(|_| wire::invalid("a start that does not parse"))?;
    let (ctx, listener, reader) = stand_up(start, fds, link)?;
    let ready = serde_json::to_vec(&Ready {
        ca: ctx.ca_cert_pem().to_string(),
    })
    .map_err(|_| wire::invalid("an answer that does not encode"))?;
    {
        let ctx = Arc::clone(&ctx);
        std::thread::Builder::new()
            .name("sbx-proxy-accept".into())
            .spawn(move || {
                // A serve error ends the accepting, and the cage loses egress: fail-closed.
                let _ = super::serve(listener, ctx, Arc::new(AtomicBool::new(false)));
            })?;
    }
    // Last, once everything it serves with stands: the supervisor starts the cage on this.
    ctx.link.announce(&ready)?;
    drop(ctx);
    let _ = reader.join();
    Ok(())
}

/// What a proxy serves with, from its `start` and the descriptors handed over beside it: the context
/// over `link` with its certificate authority minted, the socket to serve, and the thread reading
/// the link, which ends with it.
fn stand_up(
    start: Bootstrap,
    fds: Vec<OwnedFd>,
    link: wire::Socket,
) -> io::Result<(Arc<ProxyCtx>, UnixListener, JoinHandle<()>)> {
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
        ProxyCtx::linked(Arc::new(Ca::ephemeral()?), policy, link, start.ram)?
            .with_shared_credentials(Arc::new(credentials))
            .with_app(start.app)
            .with_events(events),
    );
    Ok((ctx, UnixListener::from(listener), reader))
}

/// The cage a proxy runs in, and the descriptors bwrap reads, the proxy's end of the link `link`
/// among them.
fn command(bwrap: &Path, link: wire::Socket) -> io::Result<(Command, Vec<File>)> {
    let (binary, copy) = selfcage::running()?;
    let spec = cage(
        binary.as_raw_fd(),
        copy,
        std::os::fd::AsFd::as_fd(&link).as_raw_fd(),
    )?;
    let (mut command, mut files) = selfcage::command(bwrap, &spec, binary)?;
    files.push(File::from(OwnedFd::from(link)));
    // Its standard error is a pipe [`relay_stderr`] reads, never this process's own descriptor: a
    // detached session starts its proxy before it moves its output to the session log, and a
    // proxy holding the invoker's stderr would keep it open for the session's whole life.
    command.stdout(Stdio::null()).stderr(Stdio::piped());
    Ok((command, files))
}

/// What a test binary starts as the proxy, holding `link`: `sbx __proxy` as the test binary runs it
/// ([`tests::the_stand_in_proxys_process`]), out of any cage. A test binary is not sbx and cannot be
/// started as `sbx __proxy`, and a host without user namespaces (the hosted CI) has no cage to
/// start. The process, the start, the bytes and everything the proxy stands up are its own; the cage
/// is not.
#[cfg(test)]
fn stand_in(_bwrap: &Path, link: wire::Socket) -> (Command, Vec<File>) {
    let fd = std::os::fd::AsFd::as_fd(&link).as_raw_fd();
    let mut command = crate::testutil::alone(
        concat!(module_path!(), "::tests::the_stand_in_proxys_process"),
        fd.to_string(),
    );
    // Its streams as [`command`] sets the caged proxy's.
    command
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
    (command, vec![File::from(OwnedFd::from(link))])
}

/// How long stopping a proxy waits for the relay to write what the proxy wrote last. The relay ends
/// when every writer of the pipe has closed it, the proxy and anything left in its cage, so the
/// wait is bounded rather than joined.
const RELAY_DRAIN_WAIT: Duration = Duration::from_secs(1);

/// Relay the caged proxy's standard error to this process's standard error, on a thread of its own
/// that ends when the proxy closes it ([`crate::sandbox::observe_feed::relay_lines`]).
///
/// Each line goes to descriptor 2 as it is at the moment of writing, which is the terminal for an
/// inline session and the session log once a detached one has moved its output there.
///
/// Returns what says the relay is done: disconnected once it has written the proxy's last line.
/// Stopping the proxy waits on it, because the error a proxy dies with is what the supervisor's
/// own message then points at ("its own error, if any, is above"). `None` when the thread could
/// not start, and there is nothing to wait for.
fn relay_stderr(stderr: std::process::ChildStderr) -> Option<std::sync::mpsc::Receiver<()>> {
    let (done, finished) = channel::<()>();
    let started = std::thread::Builder::new()
        .name("sbx-proxy-stderr".into())
        .spawn(move || {
            crate::sandbox::observe_feed::relay_lines(stderr, io::stderr());
            drop(done);
        });
    match started {
        Ok(_) => Some(finished),
        Err(e) => {
            crate::diag::warn(&format!(
                "the egress proxy's diagnostics cannot be relayed: {e}"
            ));
            None
        }
    }
}

/// The cage a proxy runs in ([`selfcage::spec`]): the empty network namespace, and nothing of the
/// host but the read-only userland and the binary, open as `binary` and `copy`'d when its file is
/// gone.
fn cage(binary: RawFd, copy: bool, link: RawFd) -> io::Result<SandboxSpec> {
    selfcage::spec(
        "the egress proxy",
        binary,
        copy,
        Vec::new(),
        NetPolicy::Isolated,
        vec!["__proxy".into(), link.to_string().into()],
    )
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

/// The proxy as a process: in its cage, or out of any in a test binary (`stand_in`).
mod process {
    use super::*;

    /// A proxy's process, stopped when this is dropped.
    pub(crate) struct Proxy {
        child: Option<Child>,
        /// Disconnected once the relay of the proxy's standard error has written its last line.
        relayed: Option<std::sync::mpsc::Receiver<()>>,
    }

    impl Proxy {
        /// Start a proxy caged by `bwrap`, holding `link`; in a test binary, one out of any cage.
        pub(super) fn start(bwrap: &Path, link: wire::Socket) -> io::Result<Proxy> {
            #[cfg(not(test))]
            let (command, files) = command(bwrap, link)?;
            #[cfg(test)]
            let (command, files) = stand_in(bwrap, link);
            let mut child = spawn_lasting(command, files)?;
            let relayed = child.stderr.take().and_then(relay_stderr);
            Ok(Proxy {
                child: Some(child),
                relayed,
            })
        }

        /// No proxy at all: what a test of the guard alone holds.
        #[cfg(test)]
        pub(crate) fn none() -> Proxy {
            Proxy {
                child: None,
                relayed: None,
            }
        }

        /// The proxy's process, while this holds one.
        #[cfg(test)]
        pub(crate) fn pid(&self) -> Option<u32> {
            self.child.as_ref().map(Child::id)
        }

        /// Give the proxy up to `wait` to exit, its link closed, then kill it; and reap it. A proxy
        /// that was given time and did not use it is said so: it stopped serving without seeing
        /// the end of its link.
        ///
        /// Whichever way it ends, it then gives the relay up to [`RELAY_DRAIN_WAIT`] to write what
        /// the proxy wrote last, so that line comes before anything the supervisor says next.
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
                    break;
                }
                std::thread::sleep(Duration::from_millis(5));
            }
            if let Some(relayed) = self.relayed.take() {
                let _ = relayed.recv_timeout(RELAY_DRAIN_WAIT);
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
    use crate::sandbox::selfcage::BINARY;
    use crate::testutil::TmpDir;
    use std::io::{BufRead, BufReader, Write};

    /// No credential to inject.
    fn nothing_to_inject() -> Credentials {
        Credentials::new(
            Vec::new(),
            Vec::new(),
            crate::sandbox::redact::MIN_LEN_DEFAULT,
            Vec::new(),
        )
    }

    /// Nothing kept of the proxy's reports.
    fn nothing_kept() -> super::super::events::Keeps {
        super::super::events::Keeps {
            stats: false,
            refusals: false,
            signatures: false,
            log: false,
            capture: None,
            flows: false,
        }
    }

    /// A start over an empty policy, serving a socket bound in `dir`, with `credentials` and nothing
    /// kept of the reports: what a test that plays the proxy itself is handed.
    fn bare_start<'a>(dir: &TmpDir, credentials: &'a Credentials) -> Start<'a> {
        let listener = UnixListener::bind(dir.join("proxy.sock")).unwrap();
        let (reports, _) = UnixStream::pair().unwrap();
        Start {
            bwrap: Path::new("/nonexistent/bwrap"),
            policy: b"{}",
            credentials,
            app: None,
            listener,
            reports,
            keeps: nothing_kept(),
        }
    }

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
        let credentials = nothing_to_inject();
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
        // Waited for rather than tried once: a process another test starts holds a copy of every
        // descriptor this one has from its fork to its exec, this socket among them. A copy the
        // supervisor kept would hold it for good.
        let deadline = std::time::Instant::now() + STOP_WAIT;
        let refused = loop {
            let tried = UnixStream::connect(&path).map(drop).map_err(|e| e.kind());
            if tried.is_err() || std::time::Instant::now() >= deadline {
                break tried;
            }
            std::thread::sleep(Duration::from_millis(1));
        };
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
            let credentials = nothing_to_inject();
            let handed = hand_over(
                &down,
                bare_start(&dir, &credentials),
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

    /// The start carries the host's memory as the supervisor read it: the proxy's cage has no `/proc`,
    /// and a test process, where the proxy's body runs on a thread, has one.
    #[test]
    fn the_start_carries_the_hosts_memory_which_the_proxys_cage_cannot_read() {
        let dir = TmpDir::new();
        let (down, up) = wire::Socket::pair().unwrap();
        let peer = std::thread::spawn(move || up.recv_down().unwrap().unwrap().0);
        let credentials = nothing_to_inject();
        // No answer comes: only what was handed over is looked at.
        let _ = hand_over(
            &down,
            bare_start(&dir, &credentials),
            Duration::from_millis(50),
        );
        let start: Bootstrap = serde_json::from_slice(&peer.join().unwrap()).unwrap();
        let ram = super::super::host_ram();
        assert!(ram.is_some(), "this host's memory is readable here");
        assert_eq!(start.ram, ram);
    }

    /// A proxy bounds the request bodies it holds at once by the memory its start carries, not by
    /// what it can read itself.
    #[test]
    fn a_proxy_bounds_its_bodies_by_the_memory_its_start_carries() {
        const MIB: u64 = 1024 * 1024;
        let dir = TmpDir::new();
        let listener = UnixListener::bind(dir.join("proxy.sock")).unwrap();
        let (reports, _channel) = UnixStream::pair().unwrap();
        let (_down, up) = wire::Socket::pair().unwrap();
        let (credentials, _) = nothing_to_inject().encode().unwrap().into_parts();
        let start = Bootstrap {
            policy: String::from_utf8(EgressPolicy::default().encode().unwrap()).unwrap(),
            credentials: String::from_utf8(credentials).unwrap(),
            app: None,
            keeps: nothing_kept(),
            ram: Some(1024 * MIB),
        };
        let (ctx, _, _) = stand_up(start, vec![listener.into(), reports.into()], up).unwrap();
        // A sixteenth of 1 GiB is one default body of 64 MiB. Any host that runs this has more, so a
        // budget read from here would be larger.
        assert_eq!(ctx.body.total, 64 * MIB);
    }

    /// How many seccomp filters the thread whose `status` is at `path` runs under.
    fn filters(path: &Path) -> Option<u32> {
        std::fs::read_to_string(path)
            .ok()?
            .lines()
            .find_map(|l| l.strip_prefix("Seccomp_filters:"))?
            .trim()
            .parse()
            .ok()
    }

    /// The stand-in proxy's process ([`stand_in`]): `sbx __proxy` over the link it was handed,
    /// until the link ends; anywhere else it does nothing.
    #[test]
    #[ignore = "run alone as the stand-in proxy"]
    fn the_stand_in_proxys_process() {
        crate::testutil::when_run_alone(|link| {
            if main(&[link.to_owned()]) == ExitCode::SUCCESS {
                Ok(())
            } else {
                Err(io::Error::other("the proxy ended with a failure"))
            }
        });
    }

    /// A started proxy runs under its seccomp filters, and so does every thread it starts: the one
    /// accepting the cage's connections carries exactly two filters more than the first thread of
    /// the proxy's process, which never goes under them: those two are the proxy's own.
    #[test]
    fn every_thread_a_proxy_starts_runs_under_its_filters() {
        if filters(Path::new("/proc/thread-self/status")).is_none() {
            skip_incapable!("skipping: this kernel does not count a thread's seccomp filters");
            return;
        }
        let dir = TmpDir::new();
        let log = Arc::new(LogRing::new(LOG_RING_CAP));
        let (launched, _) = started(&dir, &log);
        let process =
            Path::new("/proc").join(launched.proxy.pid().expect("a proxy running").to_string());
        let own = filters(&process.join("status")).expect("the proxy's first thread");
        let accepting_now = || {
            let mut accepting = Vec::new();
            for task in std::fs::read_dir(process.join("task")).unwrap().flatten() {
                // A thread's name as the kernel keeps it, cut to fifteen bytes.
                let comm = std::fs::read_to_string(task.path().join("comm")).unwrap_or_default();
                if comm.trim_end() == "sbx-proxy-accep"
                    && let Some(n) = filters(&task.path().join("status"))
                {
                    accepting.push(n);
                }
            }
            accepting
        };
        // Waited for rather than read once: a thread names itself when it first runs, so for a
        // moment after the proxy says it is ready its accepting thread can still carry the name of
        // the thread that started it.
        let deadline = std::time::Instant::now() + STOP_WAIT;
        let accepting = loop {
            let accepting = accepting_now();
            if !accepting.is_empty() || std::time::Instant::now() >= deadline {
                break accepting;
            }
            std::thread::sleep(Duration::from_millis(1));
        };
        assert!(
            !accepting.is_empty(),
            "no thread accepts the cage's connections"
        );
        assert!(
            accepting.iter().all(|&n| n == own + 2),
            "{own} filters on the proxy's first thread, {accepting:?} on the accepting ones"
        );
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

    /// The variable that tells [`probe_in_the_proxys_cage`] it runs in the proxy's cage, and names
    /// the file of the host it must not find there.
    const PROBE_HOST_FILE: &str = "SBX_PROXY_CAGE_PROBE";

    /// What a process in the proxy's cage reaches, before and after the proxy's own filters: a line
    /// `sbx-probe: <call> <errno>` per call, `0` for one that succeeded. Run in the cage by
    /// [`the_proxys_cage_and_its_filters_hold_what_runs_in_them`]; anywhere else it does nothing.
    ///
    /// It ends its process itself, never handing back to libtest: the harness's thread waits for
    /// the test's end on a lock the filters may leave it unwoken on.
    #[test]
    #[ignore = "run in the proxy's cage by the test that reads what it prints"]
    fn probe_in_the_proxys_cage() {
        let Some(host_file) = std::env::var_os(PROBE_HOST_FILE) else {
            return;
        };
        let errno = |r: io::Result<()>| r.map_or_else(|e| e.raw_os_error().unwrap_or(-1), |()| 0);
        let open = |path: &Path| errno(File::open(path).map(drop));
        let inet =
            || errno(std::net::UdpSocket::bind((std::net::Ipv4Addr::UNSPECIFIED, 0)).map(drop));
        let unix = || errno(std::os::unix::net::UnixDatagram::unbound().map(drop));
        // An address no network of the cage's leads to: without a route the call is refused at
        // once, and with one it would time out.
        let connect = || {
            let to = (std::net::Ipv4Addr::new(192, 0, 2, 1), 443).into();
            errno(std::net::TcpStream::connect_timeout(&to, Duration::from_secs(1)).map(drop))
        };
        let exec = || {
            let argv = [c"/nonexistent".as_ptr(), std::ptr::null()];
            let envp = [std::ptr::null()];
            // SAFETY: NUL-terminated strings in null-terminated lists that outlive the call. The
            // path does not exist, so a call the kernel reaches fails and returns.
            unsafe { libc::execve(argv[0], argv.as_ptr(), envp.as_ptr()) };
            io::Error::last_os_error().raw_os_error().unwrap_or(-1)
        };
        let say = |call: &str, outcome: i32| println!("sbx-probe: {call} {outcome}");
        say("host-file", open(Path::new(&host_file)));
        say("binary", open(Path::new(BINARY)));
        say("inet", inet());
        say("connect", connect());
        say("confine", errno(crate::sandbox::seccomp::proxy::confine()));
        say("binary", open(Path::new(BINARY)));
        say("inet", inet());
        say("unix", unix());
        say("exec", exec());
        let _ = io::stdout().flush();
        // SAFETY: ends the process without running anything more of it.
        unsafe { libc::_exit(0) };
    }

    /// A process in the proxy's cage finds no file of the host and no network, and once under the
    /// proxy's filters opens no file, makes no socket and runs no program. The process is this
    /// test's own binary, bound where the proxy's is and run as [`probe_in_the_proxys_cage`].
    #[test]
    fn the_proxys_cage_and_its_filters_hold_what_runs_in_them() {
        let Some(bwrap) = crate::pathfind::find_on_path("bwrap")
            .filter(|_| matches!(crate::probe_userns(), crate::Userns::Ok))
        else {
            skip_incapable!("skipping the proxy's cage: no bwrap or no capability-bearing userns");
            return;
        };
        let dir = TmpDir::new();
        let host_file = dir.join("of-the-host");
        std::fs::write(&host_file, b"x").unwrap();
        let binary = File::open("/proc/self/exe").unwrap();
        let mut spec = cage(binary.as_raw_fd(), false, 0).unwrap();
        spec.cmd = [
            BINARY,
            "sandbox::proxy::child::tests::probe_in_the_proxys_cage",
            "--exact",
            "--ignored",
            "--nocapture",
            "--test-threads=1",
        ]
        .map(OsString::from)
        .to_vec();
        spec.env = vec![(
            PROBE_HOST_FILE.to_string(),
            host_file.to_string_lossy().into_owned(),
        )];
        let (mut command, files) = selfcage::command(&bwrap, &spec, binary).unwrap();
        crate::sandbox::memfd::inherit_across_exec(&mut command, &files);
        let ran = crate::testutil::run_within(&mut command, "the probe in the proxy's cage");
        drop(files);
        let stdout = &ran.stdout;
        let seen: Vec<&str> = stdout
            .lines()
            .filter_map(|l| l.split_once("sbx-probe: ").map(|(_, said)| said))
            .collect();
        let expected = [
            format!("host-file {}", libc::ENOENT),
            "binary 0".to_string(),
            "inet 0".to_string(),
            format!("connect {}", libc::ENETUNREACH),
            "confine 0".to_string(),
            format!("binary {}", libc::EPERM),
            format!("inet {}", libc::EPERM),
            format!("unix {}", libc::EPERM),
            format!("exec {}", libc::EPERM),
        ];
        assert_eq!(seen, expected, "{stdout}{}", ran.stderr);
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
