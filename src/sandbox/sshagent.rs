//! The filtering ssh-agent broker (`[ssh_agent] allow`).
//!
//! A cage that must `git push` over ssh needs a *signature* from a key it must never hold. The
//! host's own agent already produces exactly that — but binding the host agent's socket into the
//! cage hands over **every** key the agent holds, for as long as it holds them, plus the ability
//! to add keys, remove one, or wipe the whole set. So sbx never binds that socket. It stands up an
//! agent socket of its own in front of it and speaks the agent protocol on both sides:
//!
//! - the cage gets a socket at [`CAGE_UDS`] and an `SSH_AUTH_SOCK` pointing at it — one socket
//!   file, never the directory that holds it (`$XDG_RUNTIME_DIR` also carries the session bus, the
//!   pulse socket and the gpg agent);
//! - every message the cage sends is classified against an **allowlist of message types**: list
//!   identities, sign, and the one extension that *narrows* what a signature authorises. Add,
//!   remove, remove-all, lock, unlock, smartcard, every other extension, and any type this code
//!   has never heard of are answered [`FAILURE`] and never reach the host agent — so a cage cannot
//!   plant a key in the user's agent, and cannot wipe it either;
//! - the identities answer is rebuilt from the keys `allow` names, and a signature request for any
//!   other key is refused **without contacting the host agent** — a key the config does not name is
//!   neither visible nor usable.
//!
//! Admission is re-derived from the host agent on every request rather than cached, so a key added
//! to or removed from the agent mid-session is reflected immediately, and a signature can never be
//! granted against a stale view.
//!
//! **What this does not contain.** Any code in the cage can authenticate as an allowed key to *any*
//! host that trusts it, for as long as the cage runs. The broker bounds *which key* and *which
//! operation*, never *which destination*: a signature request carries the session it belongs to,
//! not the host it will be spent on. The one message that does name a host —
//! [`SESSION_BIND`] — is sent by the client at its own discretion, so it cannot be the basis of a
//! fence here. It is forwarded rather than refused precisely because the *host* agent can fence on
//! it: a key the user loaded with `ssh-add -h <destination>` keeps that constraint, since the agent
//! needs these messages to check it. Destination scoping therefore exists today, enforced by
//! OpenSSH's agent, and sbx's job is to let it through intact.
//!
//! Measured, both directions, through this broker: toward the permitted host the constrained key is
//! offered and signs; toward any other, the agent withholds it from the *bound* identities answer
//! entirely, so it is never even offered. An **unbound** listing still shows it — which is what
//! [`admission`] reads, so a constrained key is admitted at launch like any other and the constraint
//! bites at use rather than at admission.

use super::binds::ExtraBind;
use crate::store::Layout;
use std::io::{self, Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

/// Where the broker's socket appears in the cage. Under the `/tmp` tmpfs (a writable mountpoint — a
/// bind onto the read-only root would fail). The cage cannot unlink it (a bind-mount target is
/// busy) and cannot reach the host agent's own socket, which is in no mount it holds.
const CAGE_UDS: &str = "/tmp/sbx-ssh-agent.sock";

/// The generic refusal. Every message the allowlist does not name is answered with this and goes no
/// further; a client reads it as "the agent will not do that", which is exactly true.
const FAILURE: u8 = 5;

/// Ask for the agent's identities.
const REQUEST_IDENTITIES: u8 = 11;

/// The reply to [`REQUEST_IDENTITIES`]: a count, then a `(blob, comment)` pair per key.
const IDENTITIES_ANSWER: u8 = 12;

/// Ask the agent to sign a blob with one of its keys. Its payload begins with the key blob, which is
/// what admission is decided on.
const SIGN_REQUEST: u8 = 13;

/// A named, open-ended extension request. Allowed for exactly one name ([`SESSION_BIND`]).
const EXTENSION: u8 = 27;

/// The extension a client uses to tell the agent which host this connection reached, letting the
/// agent enforce the destination constraints a key was loaded with (`ssh-add -h`). Forwarded
/// verbatim: it can only ever *narrow* what the host agent will sign.
const SESSION_BIND: &[u8] = b"session-bind@openssh.com";

/// The largest message either side may send, matching OpenSSH's own agent limit. A longer frame is
/// refused by dropping the connection rather than allocating for it.
const MAX_MESSAGE: usize = 256 * 1024;

/// A cap on concurrent cage connections. An ssh client holds its agent connection open for the life
/// of the session, so this is a ceiling on live sessions, not on signatures; beyond it a connection
/// is closed rather than allowed to pin an unbounded number of threads.
const MAX_CONCURRENT_CONNS: usize = 64;

/// One identity the host agent holds: the public key blob it is addressed by, and its comment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Identity {
    blob: Vec<u8>,
    comment: String,
}

impl Identity {
    /// The `SHA256:…` fingerprint, spelled exactly as `ssh-add -l` prints it: base64 of the key
    /// blob's SHA-256, without padding.
    pub(crate) fn fingerprint(&self) -> String {
        use sha2::{Digest, Sha256};
        let digest = Sha256::digest(&self.blob);
        let b64 = crate::config::base64_encode(&digest);
        format!("SHA256:{}", b64.trim_end_matches('='))
    }
}

/// The configured allowlist, resolved against whatever the host agent turns out to hold.
///
/// An entry admits a key when it equals either the key's `SHA256:…` fingerprint or its comment
/// exactly. Both spellings are accepted because both are what `ssh-add -l` puts in front of the
/// user: the fingerprint is exact and survives a re-comment, the comment is what a human
/// recognises. There is no wildcard and no prefix match — an entry names one key.
#[derive(Debug, Clone, Default)]
pub(crate) struct Filter {
    allow: Vec<String>,
}

impl Filter {
    pub(crate) fn new(allow: &[String]) -> Self {
        Self {
            allow: allow.to_vec(),
        }
    }

    /// Whether this key may be seen and used by the cage.
    pub(crate) fn admits(&self, id: &Identity) -> bool {
        let fingerprint = id.fingerprint();
        self.allow
            .iter()
            .any(|entry| entry == &fingerprint || entry.as_str() == id.comment)
    }
}

/// A cursor over an agent message body, refusing to read past its end.
struct Reader<'a> {
    buf: &'a [u8],
    at: usize,
}

impl<'a> Reader<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, at: 0 }
    }

    fn u32(&mut self) -> Option<u32> {
        let end = self.at.checked_add(4)?;
        let bytes: [u8; 4] = self.buf.get(self.at..end)?.try_into().ok()?;
        self.at = end;
        Some(u32::from_be_bytes(bytes))
    }

    /// A length-prefixed byte string, the protocol's only compound type.
    fn string(&mut self) -> Option<&'a [u8]> {
        let len = self.u32()? as usize;
        let end = self.at.checked_add(len)?;
        let s = self.buf.get(self.at..end)?;
        self.at = end;
        Some(s)
    }
}

/// Append a length-prefixed byte string.
fn put_string(out: &mut Vec<u8>, s: &[u8]) {
    out.extend_from_slice(&(s.len() as u32).to_be_bytes());
    out.extend_from_slice(s);
}

/// Parse an identities answer into its keys, or `None` if the message is not one or is malformed.
/// A malformed answer yields `None` rather than a partial list: half a key set is not a safe basis
/// for admitting anything.
fn parse_identities(body: &[u8]) -> Option<Vec<Identity>> {
    let (&kind, rest) = body.split_first()?;
    if kind != IDENTITIES_ANSWER {
        return None;
    }
    let mut r = Reader::new(rest);
    let count = r.u32()? as usize;
    // A count is attacker-independent here (it comes from the user's own agent), but it still sizes
    // an allocation, so bound it by what the remaining bytes could possibly encode: each key costs
    // at least two length prefixes.
    if count > rest.len() / 8 + 1 {
        return None;
    }
    let mut ids = Vec::with_capacity(count);
    for _ in 0..count {
        let blob = r.string()?.to_vec();
        let comment = String::from_utf8_lossy(r.string()?).into_owned();
        ids.push(Identity { blob, comment });
    }
    Some(ids)
}

/// Build an identities answer carrying exactly these keys.
fn identities_answer(ids: &[&Identity]) -> Vec<u8> {
    let mut out = vec![IDENTITIES_ANSWER];
    out.extend_from_slice(&(ids.len() as u32).to_be_bytes());
    for id in ids {
        put_string(&mut out, &id.blob);
        put_string(&mut out, id.comment.as_bytes());
    }
    out
}

/// The key blob a signature request names, or `None` if the payload is malformed.
fn sign_request_key(payload: &[u8]) -> Option<&[u8]> {
    Reader::new(payload).string()
}

/// The name an extension request carries, or `None` if the payload is malformed.
fn extension_name(payload: &[u8]) -> Option<&[u8]> {
    Reader::new(payload).string()
}

/// Read one message body (the frame without its length prefix). An oversized, empty or truncated
/// frame is an error, which ends the connection.
fn read_message(r: &mut impl Read) -> io::Result<Vec<u8>> {
    let mut len = [0u8; 4];
    r.read_exact(&mut len)?;
    let len = u32::from_be_bytes(len) as usize;
    if len == 0 || len > MAX_MESSAGE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "ssh-agent frame out of range",
        ));
    }
    let mut body = vec![0u8; len];
    r.read_exact(&mut body)?;
    Ok(body)
}

/// Write one message body, framed.
fn write_message(w: &mut impl Write, body: &[u8]) -> io::Result<()> {
    w.write_all(&(body.len() as u32).to_be_bytes())?;
    w.write_all(body)?;
    w.flush()
}

/// Send a message to the host agent and return its reply body.
fn exchange<S: Read + Write>(host: &mut S, body: &[u8]) -> io::Result<Vec<u8>> {
    write_message(host, body)?;
    read_message(host)
}

/// The host agent's current identities. A reply that is not a well-formed identities answer yields
/// an empty set, which admits nothing — the fail-closed direction.
fn host_identities<S: Read + Write>(host: &mut S) -> io::Result<Vec<Identity>> {
    let reply = exchange(host, &[REQUEST_IDENTITIES])?;
    Ok(parse_identities(&reply).unwrap_or_default())
}

/// Decide one request and produce the reply body the cage will receive.
///
/// The message type is an **allowlist**, not a denylist: anything not named here — including a type
/// this code has never seen — is refused without reaching the host agent. A denylist would silently
/// admit every future extension of the protocol.
fn respond<S: Read + Write>(request: &[u8], host: &mut S, filter: &Filter) -> io::Result<Vec<u8>> {
    let refused = vec![FAILURE];
    let Some((&kind, payload)) = request.split_first() else {
        return Ok(refused);
    };
    match kind {
        // An identities request carries no payload; a frame with one is not the message it claims
        // to be. The answer is rebuilt rather than filtered in place, so nothing of a withheld key
        // — not its blob, not its comment — is ever spelled toward the cage.
        REQUEST_IDENTITIES if payload.is_empty() => {
            let ids = host_identities(host)?;
            let admitted: Vec<&Identity> = ids.iter().filter(|id| filter.admits(id)).collect();
            Ok(identities_answer(&admitted))
        }
        // The key blob is the whole of admission: the request names it, and only a key the host
        // agent currently holds *and* the config names may be signed with. Re-derived per request,
        // so a key removed from the agent stops working at once.
        SIGN_REQUEST => {
            let Some(blob) = sign_request_key(payload) else {
                return Ok(refused);
            };
            let ids = host_identities(host)?;
            if !ids.iter().any(|id| id.blob == blob && filter.admits(id)) {
                return Ok(refused);
            }
            exchange(host, request)
        }
        // The single allowed extension. It can only narrow what the host agent will sign, so
        // forwarding it costs nothing and preserves the destination constraints a key was loaded
        // with. Every other extension name is refused; a client reads that as "unsupported", which
        // is how an agent without extensions answers too.
        EXTENSION if extension_name(payload) == Some(SESSION_BIND) => exchange(host, request),
        _ => Ok(refused),
    }
}

/// Serve one cage connection: a fresh connection to the host agent, then request/response until the
/// client hangs up. Errors end the connection and nothing else — one client's malformed frame must
/// not take down the broker.
fn serve_conn(mut cage: UnixStream, host_sock: &Path, filter: &Filter) -> io::Result<()> {
    let mut host = UnixStream::connect(host_sock)?;
    loop {
        let request = match read_message(&mut cage) {
            Ok(r) => r,
            // EOF or a malformed frame: the client is done with us.
            Err(_) => return Ok(()),
        };
        let reply = respond(&request, &mut host, filter)?;
        write_message(&mut cage, &reply)?;
    }
}

/// Accept cage connections until the listener closes, serving each on its own thread. Beyond
/// [`MAX_CONCURRENT_CONNS`] a connection is dropped rather than allowed to pin another thread.
pub(crate) fn serve(listener: UnixListener, host_sock: PathBuf, filter: Filter) {
    let live = Arc::new(AtomicUsize::new(0));
    for conn in listener.incoming() {
        let Ok(conn) = conn else { continue };
        if live.fetch_add(1, Ordering::SeqCst) >= MAX_CONCURRENT_CONNS {
            live.fetch_sub(1, Ordering::SeqCst);
            continue;
        }
        let host_sock = host_sock.clone();
        let filter = filter.clone();
        let live = live.clone();
        std::thread::spawn(move || {
            let _ = serve_conn(conn, &host_sock, &filter);
            live.fetch_sub(1, Ordering::SeqCst);
        });
    }
}

/// The host socket the user's own agent listens on, from sbx's environment — never from the cage's
/// resolved `[env]`, which a project can write. An unset or empty variable means no agent.
pub(crate) fn host_socket() -> Option<PathBuf> {
    std::env::var_os("SSH_AUTH_SOCK")
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
}

/// A running broker's host-side resources. The accept loop is detached and dies with sbx (right
/// after the cage); this guard owns the socket file and unlinks it when the launch ends.
pub(crate) struct SshAgent {
    host_uds: PathBuf,
}

impl Drop for SshAgent {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.host_uds);
    }
}

/// What the launcher must add to the cage for the broker to be reachable.
pub(crate) struct Wiring {
    pub(crate) binds: Vec<ExtraBind>,
    pub(crate) env: Vec<(String, String)>,
}

/// Which of the host agent's keys the configured allowlist admits, and which it withholds. Reported
/// at launch so the grant is visible at the moment it is made.
pub(crate) struct Admission {
    pub(crate) admitted: Vec<String>,
    pub(crate) withheld: usize,
}

/// Resolve the allowlist against the host agent's current identities.
pub(crate) fn admission(host_sock: &Path, filter: &Filter) -> io::Result<Admission> {
    let mut host = UnixStream::connect(host_sock)?;
    let ids = host_identities(&mut host)?;
    let mut admitted = Vec::new();
    let mut withheld = 0usize;
    for id in &ids {
        if filter.admits(id) {
            admitted.push(if id.comment.is_empty() {
                id.fingerprint()
            } else {
                id.comment.clone()
            });
        } else {
            withheld += 1;
        }
    }
    Ok(Admission { admitted, withheld })
}

/// Stand up the broker: bind its socket under the data directory, serve it, and return what the
/// cage needs to reach it.
pub(crate) fn start(
    layout: &Layout,
    allow: &[String],
    host_sock: &Path,
) -> io::Result<(SshAgent, Wiring)> {
    use std::fs::DirBuilder;
    use std::os::unix::fs::DirBuilderExt;

    // The data directory is owner-only, and this socket is the reason it must be: anything that can
    // connect to it can ask the user's agent for a signature.
    crate::store::ensure(layout)?;
    let dir = layout.data_dir().join("ssh-agent");
    DirBuilder::new().recursive(true).mode(0o700).create(&dir)?;

    // Keyed by the launcher pid, like the egress and forward sockets, so a crashed predecessor's
    // residue is identifiable — and cleared here, since a stale file would block the bind.
    let host_uds = dir.join(format!("agent-{}.sock", std::process::id()));
    let _ = std::fs::remove_file(&host_uds);
    let listener = UnixListener::bind(&host_uds)?;

    let filter = Filter::new(allow);
    let host_sock = host_sock.to_path_buf();
    std::thread::spawn(move || serve(listener, host_sock, filter));

    Ok((
        SshAgent {
            host_uds: host_uds.clone(),
        },
        Wiring {
            // Read-only: the cage runs same-uid, and a read-only bind is enough to `connect()` — the
            // same property the Wayland socket relies on. Only the socket file crosses, never its
            // directory, which holds every other launch's broker socket.
            binds: vec![ExtraBind {
                src: host_uds,
                dest: PathBuf::from(CAGE_UDS),
                writable: false,
            }],
            // `SSH_AUTH_SOCK` is set by sbx and needs no denylist entry, for the reason the Wayland
            // keys need none: an untrusted `[env]` overriding it can only point an in-cage client at
            // a socket that is not this one — self-DoS, never a redirect of the bind, whose source
            // path is sbx's. The host agent's own socket is in no mount the cage holds.
            env: vec![("SSH_AUTH_SOCK".to_string(), CAGE_UDS.to_string())],
        },
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A stand-in for the host agent: replies are queued, requests are recorded. Lets every
    /// decision be tested without an agent, a socket or a key.
    struct FakeAgent {
        /// Replies handed out in order, one per request received.
        replies: Vec<Vec<u8>>,
        /// Every request body the broker forwarded — the record a test asserts *absence* against.
        seen: Vec<Vec<u8>>,
        /// Request bytes not yet forming a whole frame.
        pending: Vec<u8>,
        /// Framed replies waiting to be read back.
        outbox: Vec<u8>,
        read_at: usize,
    }

    impl FakeAgent {
        fn new(replies: Vec<Vec<u8>>) -> Self {
            Self {
                replies,
                seen: Vec::new(),
                pending: Vec::new(),
                outbox: Vec::new(),
                read_at: 0,
            }
        }
    }

    impl Write for FakeAgent {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.pending.extend_from_slice(buf);
            // A whole frame has arrived: record it and queue the next scripted reply.
            while self.pending.len() >= 4 {
                let len = u32::from_be_bytes(self.pending[..4].try_into().unwrap()) as usize;
                if self.pending.len() < 4 + len {
                    break;
                }
                self.seen.push(self.pending[4..4 + len].to_vec());
                self.pending.drain(..4 + len);
                if !self.replies.is_empty() {
                    let reply = self.replies.remove(0);
                    self.outbox
                        .extend_from_slice(&(reply.len() as u32).to_be_bytes());
                    self.outbox.extend_from_slice(&reply);
                }
            }
            Ok(buf.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl Read for FakeAgent {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            let available = &self.outbox[self.read_at.min(self.outbox.len())..];
            let n = available.len().min(buf.len());
            if n == 0 {
                return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "drained"));
            }
            buf[..n].copy_from_slice(&available[..n]);
            self.read_at += n;
            Ok(n)
        }
    }

    fn id(blob: &[u8], comment: &str) -> Identity {
        Identity {
            blob: blob.to_vec(),
            comment: comment.to_string(),
        }
    }

    /// The scripted identities answer a fake agent replies with.
    fn answer(ids: &[Identity]) -> Vec<u8> {
        let refs: Vec<&Identity> = ids.iter().collect();
        identities_answer(&refs)
    }

    fn sign_request(blob: &[u8]) -> Vec<u8> {
        let mut req = vec![SIGN_REQUEST];
        put_string(&mut req, blob);
        put_string(&mut req, b"data-to-sign");
        req.extend_from_slice(&0u32.to_be_bytes());
        req
    }

    #[test]
    fn a_fingerprint_is_spelled_the_way_ssh_add_prints_it() {
        // The empty blob's SHA-256 is a fixed, published value; base64 of it without padding is
        // what `ssh-add -l` would show for a key whose blob was empty.
        let fp = id(b"", "").fingerprint();
        assert_eq!(fp, "SHA256:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU");
        assert!(!fp.ends_with('='), "a fingerprint carries no padding");
    }

    #[test]
    fn an_entry_admits_by_fingerprint_or_by_comment_and_nothing_else() {
        let key = id(b"blob-one", "work-key");
        let other = id(b"blob-two", "personal-key");

        assert!(Filter::new(&[key.fingerprint()]).admits(&key));
        assert!(Filter::new(&["work-key".into()]).admits(&key));
        assert!(!Filter::new(&["work-key".into()]).admits(&other));

        // No wildcard, no prefix, no substring: an entry names one key.
        assert!(!Filter::new(&["*".into()]).admits(&key));
        assert!(!Filter::new(&["work".into()]).admits(&key));
        assert!(!Filter::new(&["work-key-2".into()]).admits(&key));
        let truncated = key.fingerprint()[..20].to_string();
        assert!(!Filter::new(&[truncated]).admits(&key));
    }

    #[test]
    fn the_identities_answer_carries_only_the_admitted_keys() {
        let admitted = id(b"blob-one", "work-key");
        let withheld = id(b"blob-two", "personal-key");
        let mut host = FakeAgent::new(vec![answer(&[admitted.clone(), withheld.clone()])]);
        let filter = Filter::new(&["work-key".into()]);

        let reply = respond(&[REQUEST_IDENTITIES], &mut host, &filter).unwrap();

        assert_eq!(parse_identities(&reply).unwrap(), vec![admitted]);
        // Not merely absent from the parsed list: no byte of the withheld key is in the reply at
        // all, so neither its blob nor its comment is spelled toward the cage.
        assert!(!reply.windows(8).any(|w| w == b"blob-two"));
        assert!(!reply.windows(12).any(|w| w == b"personal-key"));
    }

    #[test]
    fn a_signature_is_granted_for_an_admitted_key_and_refused_for_every_other() {
        let admitted = id(b"blob-one", "work-key");
        let withheld = id(b"blob-two", "personal-key");
        let filter = Filter::new(&["work-key".into()]);
        let signature = vec![14u8, 1, 2, 3];

        // The admitted key: the request reaches the host agent and its signature comes back.
        let mut host = FakeAgent::new(vec![
            answer(&[admitted.clone(), withheld.clone()]),
            signature.clone(),
        ]);
        let reply = respond(&sign_request(b"blob-one"), &mut host, &filter).unwrap();
        assert_eq!(reply, signature);

        // The withheld key: refused, and — the load-bearing half — the host agent never saw the
        // request, so it was never given the chance to sign it.
        let mut host = FakeAgent::new(vec![answer(&[admitted, withheld])]);
        let reply = respond(&sign_request(b"blob-two"), &mut host, &filter).unwrap();
        assert_eq!(reply, vec![FAILURE]);
        assert!(
            host.seen.iter().all(|m| m.first() != Some(&SIGN_REQUEST)),
            "a refused signature must not be forwarded"
        );

        // A key the config names but the agent no longer holds: still refused. Admission is the
        // intersection, re-derived per request.
        let mut host = FakeAgent::new(vec![answer(&[])]);
        let reply = respond(&sign_request(b"blob-one"), &mut host, &filter).unwrap();
        assert_eq!(reply, vec![FAILURE]);
    }

    #[test]
    fn every_message_type_outside_the_allowlist_is_refused_and_never_forwarded() {
        let filter = Filter::new(&["work-key".into()]);
        // Add, add-constrained, remove, remove-all, lock, unlock, both smartcard verbs — and a type
        // this code has never heard of, which is the point of an allowlist.
        for kind in [17u8, 25, 18, 19, 22, 23, 20, 21, 200, 0] {
            let mut host = FakeAgent::new(vec![vec![6u8]]);
            let reply = respond(&[kind, 0, 0, 0, 0], &mut host, &filter).unwrap();
            assert_eq!(reply, vec![FAILURE], "message type {kind} was not refused");
            assert!(
                host.seen.is_empty(),
                "message type {kind} reached the agent"
            );
        }

        // An empty frame decides nothing and is refused like the rest.
        let mut host = FakeAgent::new(vec![vec![6u8]]);
        assert_eq!(respond(&[], &mut host, &filter).unwrap(), vec![FAILURE]);
        assert!(host.seen.is_empty());
    }

    #[test]
    fn only_the_session_binding_extension_is_forwarded() {
        let filter = Filter::new(&["work-key".into()]);

        let mut bind = vec![EXTENSION];
        put_string(&mut bind, SESSION_BIND);
        put_string(&mut bind, b"host-key");
        let mut host = FakeAgent::new(vec![vec![6u8]]);
        assert_eq!(respond(&bind, &mut host, &filter).unwrap(), vec![6u8]);
        assert_eq!(host.seen, vec![bind]);

        // Any other extension name is refused without reaching the agent, however plausible.
        for name in [
            &b"restrict-destination-v00@openssh.com"[..],
            &b"query"[..],
            &b""[..],
        ] {
            let mut other = vec![EXTENSION];
            put_string(&mut other, name);
            let mut host = FakeAgent::new(vec![vec![6u8]]);
            assert_eq!(respond(&other, &mut host, &filter).unwrap(), vec![FAILURE]);
            assert!(host.seen.is_empty());
        }
    }

    #[test]
    fn an_identities_request_with_a_payload_is_not_an_identities_request() {
        // The frame claims a type whose payload is empty; anything trailing means it is not the
        // message it says it is, so it falls through to the refusal rather than being trusted.
        let filter = Filter::new(&["work-key".into()]);
        let mut host = FakeAgent::new(vec![answer(&[id(b"blob-one", "work-key")])]);
        let reply = respond(&[REQUEST_IDENTITIES, 0xff], &mut host, &filter).unwrap();
        assert_eq!(reply, vec![FAILURE]);
        assert!(host.seen.is_empty());
    }

    #[test]
    fn a_malformed_answer_admits_nothing() {
        // Truncated key set, count larger than the bytes can hold, wrong type: each yields no
        // identities at all rather than a partial list.
        let mut truncated = vec![IDENTITIES_ANSWER];
        truncated.extend_from_slice(&2u32.to_be_bytes());
        put_string(&mut truncated, b"blob-one");
        assert!(parse_identities(&truncated).is_none());

        let mut absurd = vec![IDENTITIES_ANSWER];
        absurd.extend_from_slice(&u32::MAX.to_be_bytes());
        assert!(parse_identities(&absurd).is_none());

        assert!(parse_identities(&[FAILURE]).is_none());
        assert!(parse_identities(&[]).is_none());

        // And a signature request decided against such an answer is refused.
        let filter = Filter::new(&["work-key".into()]);
        let mut host = FakeAgent::new(vec![vec![FAILURE]]);
        let reply = respond(&sign_request(b"blob-one"), &mut host, &filter).unwrap();
        assert_eq!(reply, vec![FAILURE]);
    }

    #[test]
    fn a_frame_beyond_the_protocol_limit_is_refused_before_it_is_allocated() {
        let mut oversized = ((MAX_MESSAGE + 1) as u32).to_be_bytes().to_vec();
        oversized.push(REQUEST_IDENTITIES);
        assert!(read_message(&mut &oversized[..]).is_err());

        let empty = 0u32.to_be_bytes().to_vec();
        assert!(read_message(&mut &empty[..]).is_err());

        // A well-formed frame at the limit's edge still reads.
        let mut ok = 1u32.to_be_bytes().to_vec();
        ok.push(REQUEST_IDENTITIES);
        assert_eq!(
            read_message(&mut &ok[..]).unwrap(),
            vec![REQUEST_IDENTITIES]
        );
    }

    /// A throwaway `ssh-agent`, killed when the test ends whatever the outcome.
    struct ThrowawayAgent {
        pid: u32,
        sock: PathBuf,
    }

    impl Drop for ThrowawayAgent {
        fn drop(&mut self) {
            // SAFETY: the pid is the one this test spawned and has not reaped, so it names that
            // process or nothing at all.
            unsafe { libc::kill(self.pid as libc::pid_t, libc::SIGTERM) };
        }
    }

    /// `ssh-add`/`ssh-keygen`, run against a given agent socket. Never through the process
    /// environment: two tests sharing it would clear each other's agent mid-run.
    fn ssh(bin: &str, sock: &Path, args: &[&str], cwd: &Path) -> std::process::Output {
        std::process::Command::new(bin)
            .args(args)
            .current_dir(cwd)
            .env("SSH_AUTH_SOCK", sock)
            .output()
            .expect("ssh tool runs")
    }

    /// Start an agent holding two generated keys, and return it with the working directory.
    fn agent_with_two_keys(dir: &Path) -> Option<ThrowawayAgent> {
        for bin in ["ssh-agent", "ssh-add", "ssh-keygen"] {
            if crate::pathfind::find_on_path(bin).is_none() {
                eprintln!("skipping ssh-agent broker smoke: no {bin} on PATH");
                return None;
            }
        }
        for (file, comment) in [("alpha", "alpha-key"), ("beta", "beta-key")] {
            let out = std::process::Command::new("ssh-keygen")
                .args(["-q", "-t", "ed25519", "-N", "", "-C", comment, "-f", file])
                .current_dir(dir)
                .output()
                .expect("ssh-keygen runs");
            assert!(out.status.success(), "generating {file}: {out:?}");
        }

        let sock = dir.join("agent.sock");
        let out = std::process::Command::new("ssh-agent")
            .args(["-s", "-a"])
            .arg(&sock)
            .output()
            .expect("ssh-agent runs");
        assert!(out.status.success(), "starting the agent: {out:?}");
        // `ssh-agent -s` prints shell assignments; the pid is the one this test must reap.
        let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
        let pid: u32 = stdout
            .split("SSH_AGENT_PID=")
            .nth(1)
            .and_then(|rest| rest.split(';').next())
            .and_then(|n| n.trim().parse().ok())
            .expect("the agent announces its pid");
        let agent = ThrowawayAgent { pid, sock };

        let out = ssh("ssh-add", &agent.sock, &["alpha", "beta"], dir);
        assert!(out.status.success(), "loading the keys: {out:?}");
        // Only the agent may sign from here on: without the private key files, a signature that
        // succeeds proves the broker carried the request through to the agent.
        for file in ["alpha", "beta"] {
            std::fs::remove_file(dir.join(file)).expect("the private key is removable");
        }
        Some(agent)
    }

    #[test]
    fn a_real_agent_behind_the_broker_exposes_one_key_and_refuses_the_rest() {
        let tmp = crate::testutil::TmpDir::new();
        let dir = tmp.path();
        let Some(agent) = agent_with_two_keys(dir) else {
            return;
        };

        // The broker in front of it, granting `alpha-key` by comment and nothing else.
        let broker_sock = tmp.join("broker.sock");
        let listener = UnixListener::bind(&broker_sock).expect("the broker socket binds");
        let host_sock = agent.sock.clone();
        std::thread::spawn(move || {
            serve(listener, host_sock, Filter::new(&["alpha-key".to_string()]))
        });

        // What the cage sees: one key. The withheld key is absent from the listing entirely — a
        // plain pass-through would show both, which is what makes this assertion discriminating.
        let listed = ssh("ssh-add", &broker_sock, &["-l"], dir);
        assert!(
            listed.status.success(),
            "listing through the broker: {listed:?}"
        );
        let listed = String::from_utf8_lossy(&listed.stdout).into_owned();
        assert!(
            listed.contains("alpha-key"),
            "the granted key is listed: {listed}"
        );
        assert!(
            !listed.contains("beta-key"),
            "the withheld key must not appear: {listed}"
        );

        std::fs::write(dir.join("message"), b"sign me").expect("the message is writable");

        // The granted key signs for real: the agent holds the only copy of it, so a signature file
        // could not exist unless the request reached it.
        let signed = ssh(
            "ssh-keygen",
            &broker_sock,
            &["-Y", "sign", "-f", "alpha.pub", "-n", "test", "message"],
            dir,
        );
        assert!(
            signed.status.success(),
            "signing with the granted key: {signed:?}"
        );
        assert!(
            dir.join("message.sig").exists(),
            "a real signature came back"
        );
        std::fs::remove_file(dir.join("message.sig")).expect("the signature is removable");

        // The withheld key does not sign, though the agent holds it and would have.
        let refused = ssh(
            "ssh-keygen",
            &broker_sock,
            &["-Y", "sign", "-f", "beta.pub", "-n", "test", "message"],
            dir,
        );
        assert!(
            !refused.status.success(),
            "the withheld key must not sign: {refused:?}"
        );
        assert!(!dir.join("message.sig").exists());

        // And the cage cannot wipe the user's agent — the reason a raw socket bind is not an
        // option. The removal is refused, and the agent still holds both keys afterwards.
        let wipe = ssh("ssh-add", &broker_sock, &["-D"], dir);
        assert!(
            !wipe.status.success(),
            "remove-all must be refused: {wipe:?}"
        );
        let still = ssh("ssh-add", &agent.sock, &["-l"], dir);
        let still = String::from_utf8_lossy(&still.stdout).into_owned();
        assert!(
            still.contains("alpha-key") && still.contains("beta-key"),
            "the host agent kept every key: {still}"
        );
    }

    #[test]
    fn an_empty_allowlist_admits_nothing() {
        // The config layer never produces this (an absent or empty `allow` leaves the broker off),
        // but the filter must be closed on its own terms, not by its caller's discipline.
        let key = id(b"blob-one", "work-key");
        assert!(!Filter::new(&[]).admits(&key));

        let mut host = FakeAgent::new(vec![answer(&[key])]);
        let reply = respond(&[REQUEST_IDENTITIES], &mut host, &Filter::new(&[])).unwrap();
        assert_eq!(parse_identities(&reply).unwrap(), vec![]);
    }
}
