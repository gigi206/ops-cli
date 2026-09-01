//! The host-side egress proxy: a TLS-terminating filtering proxy that is the cage's only
//! path to the network under a filtered-egress posture (`[network] mode = "deny"`, `"allow"`, or
//! `"ask"`).
//!
//! The cage runs in an empty network namespace, so its sole egress is a Unix socket bound
//! into it; an in-cage forwarder bridges the tool's `http_proxy`/`https_proxy` to this host
//! process, which is the only one with real network access — and the only place the allowlist
//! is enforced (deny-by-construction). To filter by path (not just host), the proxy must see
//! inside the TLS tunnel, so it man-in-the-middles every CONNECT: it presents a leaf certificate
//! it mints on the fly for the requested host, signed by an **ephemeral, per-session CA** whose
//! certificate is trusted **only inside the cage** (never the host's trust store). It then reads
//! the real request, decides it against the [`crate::allowlist`] policy, and — when permitted —
//! opens its own TLS connection to the true upstream, validating that upstream against the
//! bundled root store so the interception never downgrades transport security.
//!
//! ## Where things live
//!
//! This file is the shared vocabulary: the request head and its framing, the verdict, the upstream,
//! the refusal writers, the response relay, the body-buffer budget. Each way a request can arrive
//! has a module of its own — [`tunnel`] behind a CONNECT, [`cleartext`] and [`forward`] in the
//! absolute form, [`splice`] uninspected, [`h2mitm`] over HTTP/2 — and each is one plane's
//! *sequencing* of decisions that all live here. That is deliberate: every divergence between the
//! planes that has turned into a bug was a decision written out twice, so a decision belongs in one
//! place and only the order and the answering belong to a plane.
//!
//! ## L4 (`tcp://`) raw splice
//!
//! A `tcp://` allow rule selects a **raw L4 splice** instead of inspection: at CONNECT time (on
//! host:port alone, [`crate::allowlist::EgressPolicy::l4_decision`]) the proxy accepts the tunnel
//! and copies the TCP byte stream verbatim to the upstream, without terminating TLS or parsing
//! anything ([`splice_l4`]). This carries a non-HTTP protocol (SSH, a database wire protocol) that
//! cannot be man-in-the-middled. A spliced flow keeps the controls a raw stream can bear — the empty
//! netns, host-side DNS, the host:port allowlist, the SSRF guard, and a concurrent-splice cap — but
//! **loses** path/method matching, Host/SNI anti-fronting, and the secret tripwires (there is no HTTP
//! to inspect). It is strictly opt-in: a host with no `tcp://` rule is always inspected (the MITM
//! path below). The split is decided pre-decrypt, so the splice and the MITM never both run for one
//! connection.
//!
//! ## L7 cleartext (`http://`)
//!
//! An `http://` allow rule permits **inspected cleartext**: a tool with `http_proxy` set sends an
//! absolute-form request (`GET http://host/path HTTP/1.1`, no CONNECT) for an `http://` URL, and
//! [`handle_cleartext`] applies the *same* HTTP policy as the MITM path — host / port / path / method
//! matching, the anti-fronting `Host` check, the outbound-secret tripwire, and the SSRF guard — on a
//! plaintext connection. There is no TLS to terminate, so nothing is decrypted, no leaf is minted, and
//! the upstream is reached over plain TCP with no certificate to validate; the request is forwarded in
//! origin-form and the one response streamed back. It is **strictly opt-in** exactly like the splice
//! (only an explicit `http://` allow enables it; the default action never opens it), and it forgoes
//! **credential injection** — a header secret is never sent in the clear (a secret `to` must be an
//! inspected-over-TLS host). Its one cost versus the default path is transport confidentiality (the
//! bytes travel unencrypted); the empty netns + allowlist boundary is unchanged.
//!
//! ## L7 forward (absolute-form `https://`)
//!
//! Some clients (a bundled proxy library, or a "secure web proxy" configuration) reach an `https://`
//! URL by sending an **absolute-form request straight to the proxy** — `POST https://host/path
//! HTTP/1.1`, no CONNECT — expecting the proxy to make the outbound TLS connection. Without a home
//! this is refused `405`, stranding such a tool (observed: the Kiro IDE's OAuth token exchange).
//! [`handle_https_forward`] serves it as the plaintext-client sibling of the MITM path: the
//! client→proxy leg is cleartext (the cage loopback), but the verdict is the *ordinary* `https` policy
//! ([`EgressPolicy::explain`](crate::allowlist::EgressPolicy::explain), NOT the opt-in `http://` scheme — so a normal allow rule covers it,
//! as an equivalent `CONNECT` would, `ask` park included), the upstream leg is a **validated
//! TLS** connection (a forged upstream is a `502`, never downgraded), and — unlike the cleartext path
//! — a host-scoped **credential IS injected** (it rides only the encrypted upstream leg, and a
//! reflected value is masked out of the response).
//!
//! That equivalence is one of *policy*, and it does not extend to the one refusal the tunneled plane
//! makes before the policy is consulted. An IP-literal target is answered `403 ip-literal` there
//! because a MITM has to mint a leaf and a literal carries no name to bind one to; this plane mints
//! nothing — it is the TLS *client*, validating the upstream certificate against the literal like
//! any other peer name — so an IP literal reaches [`EgressPolicy::explain`](crate::allowlist::EgressPolicy::explain)
//! here and is admitted only by a rule that names the address. The inspected answer is the narrower
//! one: through a `CONNECT` the same address is reachable only by a `tcp://` splice, which inspects
//! nothing. `sbx test net` reports the tunneled verdict and says which plane it belongs to for this
//! reason.
//!
//! The residual is *not* confidentiality on the client leg: that leg is a loopback socket inside the
//! cage, which no cage process can read (no `CAP_NET_RAW` for a packet socket, and `ptrace` is on the
//! seccomp denylist). It is that this transport, like the tunneled one, **does not authenticate its
//! client** — any process in the cage can drive the injected credential to the allowlisted host. That
//! is the already-accepted property of host-side injection, not something this path adds: the bound
//! is the empty netns plus the allowlist plus the `to`-scoping of the credential.
//!
//! This module is the serve loop; the surrounding pieces live in focused submodules — the cert
//! machinery in [`ca`], the running context and policy in [`ctx`], name resolution in [`dns`], the
//! SSRF guard in [`ssrf`], the credential/needle types in [`inject`], and the HTTP/2 (gRPC) branch
//! in [`h2mitm`]. [`super::egress`] wires it into a launch (binding the socket into the cage,
//! injecting the CA into the cage trust store, supervising its lifetime under the
//! network-allowlist posture).
//!
//! ## Refusal reasons
//!
//! Every refusal the proxy *itself* issues (as opposed to a genuine upstream response it relays
//! verbatim) carries an `X-Sbx-Egress-Reason` header with a stable category token, plus a short
//! `text/plain` body repeating it — so the agent can tell an explicit policy refusal from an
//! unreachable host or a name that did not resolve, instead of an opaque status or a dropped
//! connection. The categories:
//!
//! | Status | `X-Sbx-Egress-Reason` | Meaning |
//! |---|---|---|
//! | `403` | `denied-default`         | no allow rule matched the host / port / path |
//! | `403` | `denied-by-rule`         | a deny rule matched (the rule text is not disclosed) |
//! | `403` | `denied-method`          | an allow rule matched the host but not the request's HTTP method (a `{VERB}`-scoped rule) |
//! | `403` | `ws-injection-refused`   | a WebSocket upgrade named a host a `[secret]` is injected into. The credential rides the handshake and the frames past the `101` are opaque, so nothing can redact a reflection of it — the upgrade is refused rather than opened |
//! | `403` | `asked-denied`           | the `ask` posture parked the request and it was not allowed — deliberately conflating an explicit `sbx net pending deny`, the ask timeout, and the pending-queue cap (all three mean "no egress" in Mode B) |
//! | `403` | `http2-ask-unsupported`  | an `ask`-undecided host designated `[network] http2`. Every stream of one HTTP/2 connection is multiplexed onto a single runtime, so parking one to wait for `sbx net pending` would stall its siblings; the stream fails closed under its own reason instead of being parked (see [`AskPosture`]) |
//! | `403` | `ssrf-blocked`           | the host resolved only to private / metadata addresses |
//! | `403` | `ip-literal`             | the CONNECT target was an IP literal on the inspected path (allow it raw with a `tcp://` rule) |
//! | `403` | `outbound-secret`        | the request head carried a configured secret value verbatim (leak refused) |
//! | `403` | `signer-refused`         | a signer plugin would not form this request's credential; the body carries the plugin's own reason, scrubbed of every declared credential |
//! | `413` | `signer-body-too-large`  | a signer asked to be told a digest over the request body, and the request declares a `Content-Length` above what the proxy holds. No plugin refused: sbx did, from the head, before the body was invited. An over-cap `chunked` body declares no length and is discovered while being read, so it keeps the `bad-request:chunked` above |
//! | `503` | `splice-cap`             | the concurrent raw (`tcp://`) tunnel cap was reached (retry when one closes) |
//! | `503` | `connection-cap`         | the proxy is already serving as many client connections as it will serve at once (`[network] max_connections`). Answered on the accept loop, before anything is read, so the caller's own request is still unread when the connection closes and the refusal arrives followed by a reset |
//! | `503` | `body-buffer-cap`        | the proxy is already holding as much request-body data as it will hold at one time (retry when one in flight completes). Nothing is wrong with the request: it is a shared ceiling on host memory, since the proxy buffers host-side and the cage's own `MemoryMax` does not reach it |
//! | `421` | `host-mismatch`          | the TLS SNI or `Host` header disagreed with the CONNECT target (or, on an absolute-form request, with the request-line host) |
//! | `400` | `bad-request`            | the request was malformed or used ambiguous framing. Every inspected plane reads the framing through one shared check ([`inspect_framing`]), so the same request is refused under the same reason whichever plane it arrived on. The reason is sub-categorized: `bad-request:transfer-encoding` (a coding other than `chunked`), `bad-request:dup-content-length`, `bad-request:dup-host`, `bad-request:dup-transfer-encoding`, `bad-request:invalid-content-length`, `bad-request:control-char` (a byte in the request line or a header that another parser could read as a line break — see [`head_carries_control_byte`]), `bad-request:chunked` (a `Transfer-Encoding: chunked` body that was malformed or over the proxy cap), or `bad-request:head` (a head that never arrived whole: truncated, over [`HEAD_MAX`], past [`head_deadline`], or not UTF-8 — read before there is a request line, so it names no host and no method). A well-formed `chunked` request is de-chunked and re-framed with a synthesized `Content-Length` (not refused) |
//! | `405` | `method-not-allowed`     | a non-CONNECT request that is neither a routable `http://` nor `https://` absolute-form (a bare origin-form has no destination) |
//! | `502` | `dns-failure`            | DNS resolution failed for an allowed host |
//! | `502` | `upstream-unreachable`   | the host is allowed but the TCP connection failed |
//! | `502` | `upstream-cert-rejected` | the upstream TLS certificate failed validation (never downgraded) |
//! | `502` | `upstream-http2-unsupported` | a `[network] http2` host will not speak HTTP/2. gRPC is HTTP/2 end to end and this plane does not translate, so it fails closed. Reported whether the upstream refuses the ALPN offer or ignores ALPN and negotiates nothing: both are the same fact about the server, and neither is a certificate problem |
//! | `502` | `upstream-closed`        | the upstream was reached and then closed (or reset the stream) before answering. Distinct from `upstream-unreachable`, which means the connection was never made: this one falls *after* the allow is recorded, so the exchange reads as an allow whose status never arrived, with this error beside it |
//! | `502` | `injected-header-invalid` | a header sbx was adding could not be one (HTTP/2 plane). A backstop, not a live path: a signer's value is refused at the plugin boundary if it carries a newline or a NUL. Named for its cause rather than folded into `bad-request`, which would blame the caller for a header the caller never sent |
//!
//! A genuine upstream status (e.g. a `404`) is streamed back unchanged and carries no such
//! header — save that a reflected secret is masked out of it on the way back (see *Credential
//! injection* below), which never changes the status or the framing. Raw transport breakage — a
//! peer that closed early, an unparseable CONNECT, or a failure mid-response — closes the
//! connection with no status, there being no well-formed HTTP peer to answer. The category and body echo only what the agent already sent (its own host /
//! port) or a fixed token; they never disclose the injected credential, a host-side secret, or
//! the policy's internal rule text (for the deciding rule, `sbx test net` is the host-side tool).
//!
//! Whether the agent *surfaces* the reason depends on its tool: a raw-HTTP client or `curl -i`
//! shows the header and body, while a tool like `nix` reports the status code — but the coarse
//! class is already informative (an explicit `403` refusal vs a `502` unreachable vs a relayed
//! `404`), which is the distinction the reasons sharpen.
//!
//! ## Credential injection
//!
//! Under a configured `[secret]` entry, the proxy injects a host-scoped HTTP header into an allowed
//! request ([`HeaderInjection`]): the plaintext is read host-side at launch and never enters the
//! cage, and the injection fires only *after* the verdict and only for the concrete host (and
//! path) the secret was scoped to, replacing any client-supplied copy of the header. The
//! guarantee is precise: **no plaintext secret ever lives in the cage at rest, and the credential
//! can only egress to the one declared host**. It is *not* "the agent can never obtain the value"
//! — if that host *reflects* the header back (an echo/debug endpoint, or a compromised-but-
//! allowlisted host), the response carries it into the cage. Bounding egress to a single concrete
//! `to` host is what keeps that the agent's own narrow blast radius rather than arbitrary
//! exfiltration; the two tripwires below — one outbound, one inbound — are the backstops around it.
//!
//! An **outbound** tripwire complements the host scoping: the proxy scans each decrypted request
//! *head* for any configured secret's value ([`SecretNeedle`]) and **refuses** the request
//! (`outbound-secret`) — block, never strip — when it carries one verbatim, so a secret the agent
//! *did* obtain (a reflection, an out-of-band leak) cannot be re-sent in the clear to any allowed
//! host. It is deliberately a *tripwire, not a wall*: it inspects the head only (not the streamed
//! body) and matches the value byte-for-byte (any encoding evades it), so the load-bearing boundary
//! stays the empty netns plus the egress allowlist — this only catches naive verbatim re-exfil. Two
//! named residuals: the distinct `outbound-secret` reason is a weak *confirmation oracle* (it tells
//! a prober that an exact byte string is a configured secret), defanged by a high-entropy value plus
//! the resolution-side minimum length — kept distinct deliberately so a legitimately-confused agent
//! is not blinded; and a secret value that happens to be a substring of legitimate traffic on the
//! always-on built-in lane would refuse that request (low-probability, length-mitigated, nonzero).
//!
//! An **inbound** tripwire closes the reflection itself: when the response comes from a host an
//! injection targets — the only place a configured secret can re-enter the cage by reflection — the
//! proxy masks every verbatim occurrence of the value out of the relayed response, replacing it with
//! an equal-length run of `*` ([`pump_redacting`]). So the agent receives the legitimate response
//! content with the credential struck out, never the plaintext. It is scoped to injection-target
//! responses precisely so the always-on built-in downloads are streamed untouched and the
//! mutate-on-match cannot corrupt unrelated traffic. The action differs from the outbound tripwire's
//! — mask here, refuse there — not from a different security claim but because the response also
//! carries content the agent legitimately needs, so refusing it would deny a real result; both are
//! the *same backstop class* with the *same evasion* (a re-encoded, compressed, or framing-split
//! value slips past), and neither is the boundary. Its residual is *corruption-on-collision*: unlike
//! the outbound refusal, masking mutates the stream, so a secret value that coincided with bytes of
//! a legitimate injection-host response would be struck out of it — again entropy- and
//! minimum-length-mitigated, and confined to the one injection-target host.

use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::{IpAddr, TcpStream};
use std::os::unix::io::AsRawFd;
use std::os::unix::net::{UnixListener, UnixStream};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use rustls::{ClientConnection, ServerConnection, StreamOwned};

use crate::allowlist::{self, Decision, L4Decision, Rule};

use super::egress_stats::StatKind;

#[cfg(test)]
mod bench;
mod ca;
mod capture;
mod cleartext;
mod ctx;
mod dns;
mod forward;
mod h2mitm;
mod inject;
mod pool;
mod splice;
mod ssrf;
mod tunnel;
mod websocket;
mod wire;
mod wsframe;
pub(crate) use ca::Ca;
use ca::upstream_server_name;
use capture::{CaptureGuard, tee_request_body, tee_response};
use cleartext::handle_cleartext;
use ctx::effective_policy;
pub(crate) use ctx::{ProxyCtx, builtin_allow_rules, union_with_builtin};
use forward::handle_https_forward;
pub(crate) use inject::{
    CredentialRefresh, CredentialSet, Credentials, Form, HeaderInjection, SecretNeedle, Signed,
};
use inject::{SignRefusal, pairs_for as injection_values};
use pool::{PoolKey, UpstreamTls};
use splice::splice_l4;
pub(crate) use ssrf::{AddrRefusal, ip_refusal, names_exact_host};
use ssrf::{checked_address, resolve_checked};
use tunnel::{Turn, serve_tunneled_request};
use websocket::*;
use wire::*;
// Re-exported crate-wide: the signer manifest validator has to refuse a header by the same rule the
// injection path strips one by, or a manifest can name a spelling the guard does not recognise and
// the injection does. See [`header_name_eq`]'s own doc for why `_` folds onto `-`.
pub(crate) use wire::header_name_eq;

/// Serve the egress proxy on `listener` (the host end of the cage's bound socket), one thread per
/// connection. Each accepted stream gets the per-socket timeouts before it is handled, so a slow
/// or hung peer cannot pin a thread forever.
pub(crate) fn serve(
    listener: UnixListener,
    ctx: Arc<ProxyCtx>,
    stop: Arc<std::sync::atomic::AtomicBool>,
) -> io::Result<()> {
    for stream in listener.incoming() {
        // Checked here rather than only on the happy path, so a woken accept ends the loop whether
        // it woke with a connection or with an error. The owner sets the flag and then connects
        // once to unpark this `accept` — nothing else can, since `incoming()` blocks forever and
        // every accept error below is deliberately transient.
        if stop.load(std::sync::atomic::Ordering::SeqCst) {
            return Ok(());
        }
        let mut stream = match stream {
            Ok(s) => s,
            Err(e) => {
                // A transient accept error (host fd exhaustion, an aborted connection) must not
                // take the whole session's egress down — skip this connection and keep serving. A
                // short sleep avoids a hot spin if the condition persists.
                crate::diag::error(&format!("sbx: egress proxy: accept error: {e}"));
                std::thread::sleep(Duration::from_millis(20));
                continue;
            }
        };
        // Cap live connection threads: a new connection beyond the cap is refused rather than
        // spawned, so an in-cage caller cannot exhaust host threads/fds by opening connections
        // faster than they complete. The guard decrements on the handler thread's exit.
        //
        // Refused with a reason, not dropped. The raw-splice cap a few hundred lines down has always
        // answered `503 splice-cap`, and a caller that hits this one has exactly the same question;
        // a bare close reaches it as a connection reset with nothing anywhere to explain it. The
        // write timeout goes on first and is short: this runs on the accept loop, and a peer that
        // connects and never reads must not be able to hold the loop while it does so.
        //
        // The caller's own request is still unread when this closes, so the close reaches it as a
        // reset — after the refusal itself has been handed over, which is where an HTTP client reads
        // its response from. Draining the request first to make the close clean would put an
        // unbounded read on the accept loop to spare a client something it already handles.
        if ctx.conns.load(Ordering::Relaxed) >= ctx.max_conns {
            ctx.outcome(
                super::control::Proto::Other,
                "",
                0,
                None,
                None,
                StatKind::Blocked,
                CONNECTION_CAP,
            );
            let _ = stream.set_write_timeout(Some(CAP_REFUSAL_WRITE_TIMEOUT));
            let _ = write_refusal(
                &mut stream,
                "503 Service Unavailable",
                CONNECTION_CAP,
                "the egress proxy is already serving as many connections as it will serve at once; \
                 retry when one finishes, or raise `[network] max_connections`",
            );
            continue;
        }
        // A thread the OS refuses is treated exactly like the accept error above, and for the same
        // reason — see [`super::conncap::spawn_conn`], which [`spawn_connection`] hands to and
        // which states it once for every plane: a bare `std::thread::spawn` *panics* when the
        // kernel will not create a thread, and this loop is the body of a detached thread, so the
        // unwind would drop the `UnixListener` and close the cage's only egress for the rest of the
        // session. The refusal is reported and paused for there, and the connection is let go.
        spawn_connection(&ctx, stream);
    }
    Ok(())
}

/// One live connection's slot in [`ProxyCtx::max_conns`], given back when this guard drops.
///
/// It owns its counter (through the shared context) rather than borrowing it, so it can be taken on
/// the accept loop *before* the handler thread exists. That is what makes a refused thread free:
/// [`spawn_connection`] hands the guard to the closure, and a spawn the OS turns down drops the
/// closure — and the slot with it. A guard built inside the thread body would return nothing for a
/// thread that never ran, leaking one slot per refusal until the cap was reached and every later
/// connection was answered `503 connection-cap`.
struct ConnGuard(Arc<ProxyCtx>);

impl Drop for ConnGuard {
    fn drop(&mut self) {
        self.0.conns.fetch_sub(1, Ordering::Relaxed);
    }
}

/// Take a connection slot and hand `stream` to its own thread, reporting through
/// [`super::conncap::spawn_conn`] if the host would not give one. Returns whether the thread was
/// created. The per-socket timeouts go on inside the thread, before anything is read.
fn spawn_connection(ctx: &Arc<ProxyCtx>, stream: UnixStream) -> bool {
    ctx.conns.fetch_add(1, Ordering::Relaxed);
    let guard = ConnGuard(Arc::clone(ctx));
    super::conncap::spawn_conn("egress proxy", move || {
        let ctx = &guard.0;
        let _ = stream.set_read_timeout(Some(ctx.timeout));
        let _ = stream.set_write_timeout(Some(ctx.timeout));
        // an error on one connection is that connection's problem, never the proxy's
        let _ = handle_client(stream, ctx);
    })
}

/// What a connection refused over [`ProxyCtx::max_conns`] is told.
const CONNECTION_CAP: &str = "connection-cap";

/// How long the accept loop will spend telling one over-cap connection why it was refused. The
/// refusal is ~200 bytes into a socket buffer, so this expires only for a peer that connected and
/// stopped reading — and that peer must not be able to hold the loop open while it does.
const CAP_REFUSAL_WRITE_TIMEOUT: Duration = Duration::from_millis(50);

/// The largest request head (CONNECT or the decrypted inner request) the proxy will buffer.
const HEAD_MAX: usize = 16 * 1024;

/// How long a head has to arrive in full, counted from the moment its read starts.
///
/// The launch's own socket timeout, spent once on the whole head instead of once per read of it —
/// [`Deadlined`] carries what that difference costs when it is missing. A head is a few hundred
/// bytes a peer writes in one go, so one that cannot finish inside the time allowed for a single
/// read is not a slow peer, and this needs no setting of its own.
fn head_deadline(ctx: &ProxyCtx) -> Instant {
    Instant::now() + ctx.timeout
}

/// What a first head that never became a request is logged and refused as. Distinct from the
/// `bad-request` a malformed request *line* carries, so an operator can tell a head that never
/// arrived whole from one that arrived and did not parse.
const UNREADABLE_HEAD: &str = "bad-request:head";

/// What a request refused by [`head_carries_control_byte`] is told, on every plane that reads a head.
/// It names the byte class rather than the attack, because a client sending one by accident needs to
/// know what to remove and a client sending one on purpose learns nothing it did not already know.
const CONTROL_BYTE_DETAIL: &str = "a request line or header carries a control byte (a carriage return, a NUL, or another C0 \
     character); another parser could read it as a line break, so it is refused rather than \
     forwarded";

/// The most `ask`-posture requests parked at once. A new one beyond this is denied immediately
/// (fail-closed) rather than enqueued, so an in-cage agent cannot pin unbounded host threads by
/// opening connections that all park — the default ask wait being indefinite. Far above any
/// realistic interactive backlog.
const ASK_PENDING_CAP: usize = 256;

/// Handle one client connection: parse the CONNECT, man-in-the-middle the tunnel, and serve the
/// requests the client sends through it — each one a full turn through [`serve_tunneled_request`],
/// which is where the policy decision and every check around it live. A connection that is not a
/// CONNECT is routed here to the cleartext or absolute-form forward instead. Every failure path is
/// fail-closed, and each returns a [`write_refusal`] reason (an `X-Sbx-Egress-Reason` category plus
/// a text body) so the agent can tell an explicit policy refusal from an unreachable host or a name
/// that did not resolve, instead of an opaque status or a dropped connection.
fn handle_client(mut client: UnixStream, ctx: &ProxyCtx) -> io::Result<()> {
    // 1. The CONNECT head, read byte-by-byte so the stream sits exactly at the TLS ClientHello
    //    (a buffered read would swallow the start of the handshake).
    let mut head = Vec::new();
    if let Err(e) = read_head_raw(&mut client, HEAD_MAX, head_deadline(ctx), &mut head) {
        return refuse_unreadable_head(&mut client, ctx, &head, &e);
    }
    let parsed = match parse_head(&head) {
        Ok(parsed) => parsed,
        Err(e) => return refuse_unreadable_head(&mut client, ctx, &head, &e),
    };
    let Some((method, target)) = request_line_parts(&parsed.request_line) else {
        // A malformed request line carries no destination to attribute — log the attempt so it is
        // not dark, but with no host/method/path (the raw line may hold whitespace the wire format
        // cannot carry as a single field).
        ctx.push_log(
            super::control::Proto::Other,
            "",
            0,
            None,
            None,
            super::control::LogVerdict::Blocked,
            "bad-request",
        );
        return write_refusal(
            &mut client,
            "400 Bad Request",
            "bad-request",
            "the CONNECT request line is malformed",
        );
    };
    if method != "CONNECT" {
        // A client with `http_proxy` set sends an **absolute-form** request (`GET http://host/… HTTP/1.1`)
        // for an `http://` URL — no CONNECT. When an `http://` (cleartext L7) rule permits it, this is
        // the inspected-cleartext path; route it there. An absolute-form **`https://`** request (a
        // client treating the proxy as a TLS-terminating forward proxy — the "secure web proxy" form,
        // instead of CONNECT) is routed to the plaintext-client/validated-TLS-upstream forward, gated by
        // the ordinary `https` policy. Anything else (a bare origin-form with no host to route, or a bad
        // method) is refused fail-closed — the method + raw target are the "what is the agent trying to
        // do" signal, so log them (host blank, target as the path).
        if target.starts_with("http://") {
            return handle_cleartext(client, &parsed, &head, &method, &target, ctx);
        }
        if target.starts_with("https://") {
            return handle_https_forward(client, &parsed, &head, &method, &target, ctx);
        }
        ctx.push_log(
            super::control::Proto::Other,
            "",
            0,
            Some(method.as_str()),
            Some(target.as_str()),
            super::control::LogVerdict::Blocked,
            "method-not-allowed",
        );
        return write_refusal(
            &mut client,
            "405 Method Not Allowed",
            "method-not-allowed",
            "this egress proxy tunnels HTTPS (CONNECT), forwards allowed plaintext `http://` requests, \
             and forwards an allowed absolute-form `https://` request over a validated TLS upstream; a \
             bare origin-form request has no host to route",
        );
    }
    // 2. The CONNECT authority.
    let Some((host, port)) = split_authority(&target) else {
        // The authority is malformed (not host:port): log the raw target the agent asked for.
        ctx.push_log(
            super::control::Proto::Other,
            "",
            0,
            Some(method.as_str()),
            Some(target.as_str()),
            super::control::LogVerdict::Blocked,
            "bad-request",
        );
        return write_refusal(
            &mut client,
            "400 Bad Request",
            "bad-request",
            "the CONNECT authority must be host:port",
        );
    };
    let connect_host = allowlist::canonical_host(&host);

    // 2b. The enforcement-layer decision, made from host:port alone (pre-decrypt). A `tcp://` (L4)
    //     allow rule splices the connection raw — no TLS termination, no inspection — so this is
    //     decided before the IP-literal refusal (a raw splice needs no SNI, so an IP-literal target
    //     is fine for it). Anything else (the common case) falls through to the inspected L7 path.
    {
        let policy = effective_policy(ctx);
        if let L4Decision::Splice(rule) = policy.l4_decision(&connect_host, port) {
            return splice_l4(client, &connect_host, port, rule, ctx);
        }
    }

    // An IP-literal target carries no SNI to bind the minted leaf to, so the inspected L7 path
    // refuses it (a hostname target is required to MITM; a CONNECT to an address is served only as
    // the raw splice above). The refusal is this plane's, not the proxy's as a whole: the
    // absolute-form plane terminates no TLS toward the client and so decides a literal by the
    // ordinary policy — see the module header.
    if host.parse::<IpAddr>().is_ok() {
        // Log the attempt (host = the IP the agent tried to reach) before refusing. Pre-tunnel, so
        // there is no method/path yet.
        ctx.push_log(
            super::control::Proto::Https,
            &connect_host,
            port,
            None,
            None,
            super::control::LogVerdict::Blocked,
            "ip-literal",
        );
        return write_refusal(
            &mut client,
            "403 Forbidden",
            "ip-literal",
            "an IP-literal CONNECT target is refused for inspected egress; a hostname is required \
             (or allow it raw with a `tcp://` rule)",
        );
    }

    // A designated `[network] http2` host is man-in-the-middled as HTTP/2 (ALPN `h2`, for gRPC)
    // rather than HTTP/1.1. The whole h2 branch runs on a per-connection current-thread tokio runtime
    // confined to [`h2mitm`]; the synchronous HTTP/1.1 path below is untouched. Read from the config
    // policy — h2 selection is launch-static, not `--session`-overlaid.
    if ctx.policy.speaks_http2(&connect_host, port) {
        return h2mitm::handle(client, connect_host, port, ctx);
    }

    // 3. Accept the tunnel, then terminate TLS with a leaf minted for the SNI host.
    write_all_str(&mut client, "HTTP/1.1 200 Connection established\r\n\r\n")?;
    let server_conn = ServerConnection::new(ctx.server_config.clone()).map_err(io::Error::other)?;
    let mut br = Box::new(BufReader::new(StreamOwned::new(server_conn, client)));

    // 4. Serve requests off this tunnel until one of them leaves it unusable. Every request is a
    //    full turn through [`serve_tunneled_request`] — head, framing, control bytes, Host/SNI
    //    agreement, verdict, SSRF, injection, capture, stats — with nothing carried across turns but
    //    the tunnel itself. The only exit that returns [`Turn::Continue`] is falling off the end of
    //    that function, so there is no path on which a later request rides an earlier one's verdict.
    //
    //    There is deliberately no ceiling on how many requests one tunnel may carry. A cap would
    //    bound nothing: these requests are served one after another by the single thread this
    //    connection already holds, and an in-cage caller that wanted more of sbx's time would get it
    //    faster by opening connections — which is what [`MAX_CONCURRENT_CONNS`] is for.
    let mut reused = false;
    loop {
        if reused {
            // A tunnel between requests holds a host thread and nothing else, so the wait between
            // them is bounded by `[network] idle_timeout` rather than by the in-request timeout.
            // The turn puts the launch's own timeout back once a byte arrives.
            //
            // `ctx.idle` alone, not `min` with the request timeout. The two answer different
            // questions — how long one request may take, against how long a caller may think
            // between requests — and the `min` silently capped the configured one: with
            // `idle_timeout = "2m"` the tunnel was closed after 30 seconds while the response head
            // told the client `Keep-Alive: timeout=120` ([`super::wire::offer_reuse_in_head`] reads
            // `ctx.idle`). A client that believes what it was told reuses at 60 seconds and finds
            // the connection gone, which for a request the proxy must not repeat is a failed call.
            // The cost of honouring it is the one `idle_timeout` is documented to carry, a host
            // thread and a descriptor per idle connection, bounded by `max_connections`.
            let _ = br.get_ref().sock.set_read_timeout(Some(ctx.idle));
        }
        match serve_tunneled_request(br, ctx, &connect_host, port)? {
            Turn::Continue(tunnel) => {
                br = tunnel;
                reused = true;
            }
            Turn::Close => break,
        }
    }
    Ok(())
}

/// Parse the numeric HTTP status code from a response's opening bytes (`HTTP/1.1 200 OK\r\n`): the
/// token after the first space, if it is a plausible status (100–599). `None` for anything that is
/// not a well-formed HTTP/1.x status line (so a non-HTTP or truncated response records no status).
fn parse_status_code(prefix: &[u8]) -> Option<u16> {
    let line = prefix.split(|&b| b == b'\n').next()?;
    let text = std::str::from_utf8(line).ok()?;
    if !text.starts_with("HTTP/") {
        return None;
    }
    let code: u16 = text.split_whitespace().nth(1)?.parse().ok()?;
    (100..=599).contains(&code).then_some(code)
}

/// Why the network policy refused an inspected request, for the two paths that put the same question
/// to it: a `CONNECT` tunnel and an absolute-form `https://` forward. Modelled on
/// [`ssrf::ConnectRefusal`]
/// and for the same reason — the verdict records its own outcome and hands back what to answer, so
/// the two paths differ in how they *write* a refusal (inside the terminated TLS, or on the plaintext
/// client socket), not in what it says.
enum PolicyRefusal {
    /// A deny rule matched. Kept distinct from [`Self::DeniedDefault`] so the agent can tell "a rule
    /// said no" from "no rule said yes".
    DeniedByRule,
    /// An allow rule matches the host and path, but its method set excludes this verb — a
    /// method-scoped deny, not a closed host.
    DeniedMethod,
    /// Nothing opened the host. The one refusal that carries a copy-paste `sbx net allow`, sound
    /// precisely because nothing allowed it — never for an explicit deny or a security guard.
    DeniedDefault,
    /// An `ask`-undecided host a live decision refused, or whose ask timeout elapsed.
    AskedDenied,
    /// An `ask`-undecided host on a transport that cannot park one. Only the HTTP/2 path produces
    /// it, and it names that transport in its reason token so the refusal reads as the documented
    /// limitation it is rather than as an ordinary deny. See [`AskPosture::RefuseUnsupported`].
    Http2AskUnsupported,
}

/// Whether the transport asking for a verdict can park a request while a person decides it.
///
/// This is a property of how the path runs, not a preference. The synchronous HTTP/1.1 paths serve
/// one connection per thread, so blocking one to wait for `sbx net pending` costs that request and
/// nothing else. Every stream of an HTTP/2 connection is multiplexed onto ONE current-thread tokio
/// runtime, so parking a single stream there would stall its siblings — it fails closed instead.
#[derive(Clone, Copy)]
enum AskPosture {
    /// Block until a host-side `sbx net pending` answers, or the ask timeout elapses (deny).
    Park,
    /// Refuse an undecided host outright, under [`PolicyRefusal::Http2AskUnsupported`].
    RefuseUnsupported,
}

impl PolicyRefusal {
    /// The status line the HTTP/1.1 paths write. Every policy refusal is a `403`: the request was
    /// understood and reached a verdict, which is what separates these from the `502`s a connect
    /// failure gets.
    fn status_line(&self) -> &'static str {
        "403 Forbidden"
    }

    /// The same status for the HTTP/2 path, which frames a refusal rather than writing it.
    fn status(&self) -> http::StatusCode {
        http::StatusCode::FORBIDDEN
    }

    /// The stable reason token: the `x-sbx-egress-reason` header, and the reason in the log.
    fn tag(&self) -> &'static str {
        match self {
            Self::DeniedByRule => "denied-by-rule",
            Self::DeniedMethod => "denied-method",
            Self::DeniedDefault => "denied-default",
            Self::AskedDenied => "asked-denied",
            Self::Http2AskUnsupported => "http2-ask-unsupported",
        }
    }

    /// The sentence the refusal body carries, naming what the client asked for.
    fn message(&self, ctx: &ProxyCtx, host: &str, port: u16, method: &str) -> String {
        match self {
            Self::DeniedByRule => {
                "this request matches a deny rule in the network policy".to_string()
            }
            Self::DeniedMethod => format!(
                "the `{method}` method is not permitted to `{host}:{port}` by the network policy"
            ),
            // The suggestion rides the response the client already shows, so the agent gets the next
            // step in the reply itself. The *person* running sbx is told separately, through the
            // notification the `outcome` chokepoint raises: the agent is under no obligation to
            // surface a `403` body, and a boundary nobody hears about is one that looks like it never
            // bit. Scoped to the app when this is an `sbx app` launch.
            Self::DeniedDefault => format!(
                "`{host}:{port}` is not allowed by the network policy. Allow it: {}",
                ctx.allow_suggestion(&rule_destination(super::control::Proto::Https, host, port))
            ),
            Self::AskedDenied => {
                "this request was denied by a live decision or the ask timeout elapsed".to_string()
            }
            // Reached only by the HTTP/2 path, which frames a status and a reason token and sends no
            // body — so this sentence has no writer today. It is spelled anyway: the enum's contract
            // is that every refusal can say what it is, and a variant that cannot would be a trap
            // for whoever gives that path a body later.
            Self::Http2AskUnsupported => format!(
                "`{host}:{port}` is undecided under the `ask` posture, and this HTTP/2 stream \
                 cannot wait for a decision — allow the host explicitly to reach it"
            ),
        }
    }
}

/// The refused destination spelled as a rule for the plane that refused it, so pasting it after
/// `sbx net allow` writes a rule that admits the very request that was refused.
///
/// The rule grammar's `split_scheme` reads the scheme as the **layer and the default port**: a
/// scheme-less entry is `Layer::L7` on 443, an `http://` entry is `Layer::L7Clear` on 80. So the
/// scheme may be dropped only for the inspected-TLS plane, and the port only when it already *is*
/// that plane's default. Suggesting the bare host for a refusal on `:8443` handed the user a command
/// that changes nothing they can observe: they run it, retry, and are refused again by the same rule
/// they were told to write; a bare `sbx net allow host` for a cleartext refusal is worse still, since
/// it writes an `https`/443 rule that cannot open the clear at all.
///
/// One function for all three sites — the two refusal bodies and the desktop notification the
/// [`ProxyCtx::outcome_l7`] chokepoint raises — because the notification is the channel that exists
/// precisely because the agent may never surface the `403` body, and the two must not tell the user
/// to run different commands about the same refusal. Same shape as the `host_token` net-learn
/// synthesizes its candidate rules with, which learns from these very refusals — the three must not
/// drift.
///
/// [`Proto::Tcp`](super::control::Proto::Tcp) and [`Proto::Other`](super::control::Proto::Other)
/// take the inspected-TLS spelling: neither ever reaches a `denied-default` suggestion (a raw splice
/// is decided on host:port before any scheme is known, and `Other` names no transport), so this is
/// the harmless answer rather than a case worth a fourth spelling.
fn rule_destination(proto: super::control::Proto, host: &str, port: u16) -> String {
    let (scheme, default_port) = match proto {
        super::control::Proto::Http => ("http://", 80),
        _ => ("", 443),
    };
    if port == default_port {
        format!("{scheme}{host}")
    } else {
        format!("{scheme}{host}:{port}")
    }
}

/// The `https` policy verdict for one inspected request: the deciding rule, or the refusal to answer
/// with. `Ok(None)` is allow-by-default (denylist mode) — no rule named the host, so there is no
/// deciding rule and the SSRF guard downstream treats the target as unnamed.
///
/// Built through the SAME canonicalizer `sbx test net` uses, so enforcement cannot drift from the
/// tester's prediction, and evaluated against the effective policy (config plus any live `--session`
/// overlay), so a `--session allow` opens an otherwise-default-denied host and a `--session deny`
/// blocks a config-allowed one. An `ask`-undecided host parks here and blocks until a host-side `sbx
/// net pending` answers it or the timeout elapses (deny — fail-closed); a live allow names this exact
/// host:port as the deciding rule, so the SSRF guard admits a deliberately-approved internal target.
///
/// Every refusal records its own outcome before returning, so a caller cannot answer one without
/// counting it. `ask` is the one arm the callers do not all share, which is what [`AskPosture`]
/// carries: the two HTTP/1.1 paths park, the HTTP/2 path cannot and refuses.
///
/// The cleartext `http://` path is the one consumer of the `https` policy that deliberately does NOT
/// come here. It is strictly opt-in, its `explain_clear` consults neither the default action nor the
/// ask queue, and routing it through this verdict would widen it into a posture it was written to
/// refuse.
fn decide_https(
    ctx: &ProxyCtx,
    host: &str,
    port: u16,
    path: &str,
    method: &str,
    ask: AskPosture,
) -> Result<Option<Rule>, PolicyRefusal> {
    let refuse = |refusal: PolicyRefusal| {
        ctx.outcome(
            super::control::Proto::Https,
            host,
            port,
            Some(method),
            Some(path),
            StatKind::Deny,
            refusal.tag(),
        );
        Err(refusal)
    };
    let policy = effective_policy(ctx);
    match policy.explain(host, port, path, method) {
        Decision::AllowedBy(rule) => Ok(Some(rule.clone())),
        Decision::AllowedDefault => Ok(None),
        Decision::DeniedBy(_) => refuse(PolicyRefusal::DeniedByRule),
        Decision::DeniedDefault => {
            // Which of the two the refusal is gets decided *before* the outcome is recorded, so the
            // log carries the precise category rather than a coarse one.
            if policy.method_denied(host, port, path, method) {
                refuse(PolicyRefusal::DeniedMethod)
            } else {
                refuse(PolicyRefusal::DeniedDefault)
            }
        }
        // Undecided. Parking blocks the calling thread until a person answers, which only a
        // transport that owns its thread may do — the other fails closed rather than stalling every
        // stream sharing its runtime.
        Decision::Ask if matches!(ask, AskPosture::RefuseUnsupported) => {
            refuse(PolicyRefusal::Http2AskUnsupported)
        }
        Decision::Ask => {
            // Masked before it is parked, for the reason the logging branch masks before pushing: a
            // parked request is printed by `sbx net pending` (and by the notice below), so a token
            // riding in a query would reach the operator's terminal — and a `--json` capture — in
            // the clear from a path that is careful about it everywhere else. The outbound
            // tripwire is not a backstop here: `carries_secret` skips a needle whose destination is
            // the host it was learned on, which is exactly the request that parks instead of being
            // refused.
            let path = &ctx.redact_query(path);
            let verdict = ctx.pending.park(
                host,
                port,
                path,
                policy.ask_timeout(),
                ASK_PENDING_CAP,
                |seq| {
                    if ctx.notices {
                        let id = super::control::format_id(std::process::id(), seq);
                        print_egress_notice(
                            &format!("egress decision needed [{id}] {host}:{port}{path}"),
                            &[
                                ("allow", &format!("sbx net pending allow {id}")),
                                ("deny", &format!("sbx net pending deny {id}")),
                            ],
                        );
                    }
                },
            );
            match verdict {
                super::control::Verdict::Allow => Ok(Some(allowlist::host_port_rule(host, port))),
                super::control::Verdict::Deny => refuse(PolicyRefusal::AskedDenied),
            }
        }
    }
}

/// Why a connection to the validated upstream could not be opened, so the refusal can name a
/// distinct motif: the TCP connection failed (the host is down/filtered), or the TLS handshake /
/// certificate validation failed (a forged or otherwise untrusted upstream — never downgraded).
enum UpstreamError {
    /// The TCP connection to the checked address could not be established.
    Unreachable,
    /// The TLS handshake or certificate validation against the upstream failed.
    CertRejected,
}

/// Open a validated TLS connection to a checked upstream address. The TCP target is the
/// already-guarded IP; the certificate is validated against `host` (the name), so the connection
/// goes to the exact address the SSRF guard approved while still authenticating the real server.
/// The handshake is completed here so a validation failure surfaces now (a 502), distinct from a
/// plain unreachable host (also a 502, but a different reason).
fn connect_upstream(
    ip: IpAddr,
    port: u16,
    host: &str,
    ctx: &ProxyCtx,
) -> Result<StreamOwned<ClientConnection, TcpStream>, UpstreamError> {
    let sock = TcpStream::connect((ip, port)).map_err(|_| UpstreamError::Unreachable)?;
    sock.set_read_timeout(Some(ctx.timeout))
        .map_err(|_| UpstreamError::Unreachable)?;
    sock.set_write_timeout(Some(ctx.timeout))
        .map_err(|_| UpstreamError::Unreachable)?;
    // Nagle off. Every relay here writes a head and then a body, and on a connection that stays
    // open the second write waits for the delayed ACK of the first — tens of milliseconds of
    // latency the proxy adds to every request that carries one. Latency over segment count is the
    // trade a proxy in a request's path wants, and it is what the broker's socket already takes.
    let _ = sock.set_nodelay(true);
    let name = upstream_server_name(host).map_err(|_| UpstreamError::CertRejected)?;
    let mut conn = ClientConnection::new(ctx.upstream.clone(), name)
        .map_err(|_| UpstreamError::CertRejected)?;
    let mut sock = sock;
    // drives + validates the TLS handshake now; a forged/self-signed upstream fails here
    conn.complete_io(&mut sock)
        .map_err(|_| UpstreamError::CertRejected)?;
    Ok(StreamOwned::new(conn, sock))
}

/// The upstream connection this request will ride: one an earlier request to the same host left
/// behind when the launch reuses connections and the pool holds a live one, else a freshly connected
/// and validated one. The flag says which, so a connection that dies between the pool's probe and
/// the request write can be named for what it is rather than surfacing as an empty response.
///
/// Reuse deliberately sits **after** the verdict, the name resolution and the address guard, not
/// instead of them: a parked connection shortens the handshake, never the checks. It also cannot
/// outlive what authorized it — the certificate was validated against `host`, which is part of the
/// key, so a reused connection goes to a server that was authenticated for exactly this name.
fn acquire_upstream(
    ctx: &ProxyCtx,
    key: Option<&PoolKey>,
    ip: IpAddr,
    port: u16,
    host: &str,
) -> Result<(UpstreamTls, bool), UpstreamError> {
    if let (Some(pool), Some(key)) = (ctx.pool.as_ref(), key)
        && let Some(stream) = pool.checkout(key)
    {
        return Ok((stream, true));
    }
    connect_upstream(ip, port, host, ctx).map(|stream| (stream, false))
}

/// Refuse a request because the upstream the policy allowed could not be reached at all: an `error`
/// line naming the host, and a `502` telling the agent that the refusal is a transport failure and
/// not a verdict.
///
/// Every transport that opens an upstream of its own ends here — the two inspected-TLS planes
/// through [`refuse_upstream`], [`handle_cleartext`] and [`splice_l4`] directly — because the reason
/// token and the sentence beside it state one fact that does not depend on what carried the request.
/// What genuinely differs is passed in: the `proto` the attempt is recorded under, and the request
/// it belongs to, which a raw splice does not have (it refuses before any HTTP is spoken).
///
/// The HTTP/2 plane keeps its own refusal. It answers a stream with a header-only `502` carrying the
/// reason and no body, so there is no sentence for it to share.
fn refuse_unreachable<W: Write>(
    w: &mut W,
    ctx: &ProxyCtx,
    proto: super::control::Proto,
    host: &str,
    port: u16,
    method: Option<&str>,
    target: Option<&str>,
) -> io::Result<()> {
    ctx.push_log(
        proto,
        host,
        port,
        method,
        target,
        super::control::LogVerdict::Error,
        "upstream-unreachable",
    );
    write_refusal(
        w,
        "502 Bad Gateway",
        "upstream-unreachable",
        &format!("`{host}:{port}` is allowed but could not be reached"),
    )
}

/// Refuse a request because its validated upstream could not be opened. Both shapes are a `502`,
/// with distinct reasons so "the host is down" reads differently from "its certificate was
/// rejected". Written straight to whichever client leg asked — the decrypted tunnel on the
/// inspected-TLS path, the plaintext socket on the absolute-form one.
fn refuse_upstream<W: Write>(
    w: &mut W,
    ctx: &ProxyCtx,
    host: &str,
    port: u16,
    method: &str,
    target: &str,
    err: UpstreamError,
) -> io::Result<()> {
    let (reason, detail) = match err {
        // The shape every plane can produce, answered in the one place that spells it.
        UpstreamError::Unreachable => {
            return refuse_unreachable(
                w,
                ctx,
                super::control::Proto::Https,
                host,
                port,
                Some(method),
                Some(target),
            );
        }
        UpstreamError::CertRejected => (
            "upstream-cert-rejected",
            format!(
                "the TLS certificate presented by `{host}` was rejected (upstream validation failed)"
            ),
        ),
    };
    ctx.push_log(
        super::control::Proto::Https,
        host,
        port,
        Some(method),
        Some(target),
        super::control::LogVerdict::Error,
        reason,
    );
    write_refusal(w, "502 Bad Gateway", reason, &detail)
}

/// Whether a method may be sent a second time after a parked connection turns out to be dead.
///
/// The retry runs only when the upstream said nothing at all, which from a live server means it
/// never saw the request. But a server that took the request and died before answering looks exactly
/// the same from here, so replaying a method whose effect is not idempotent could apply it twice.
/// The methods RFC 9110 §9.2.2 defines as idempotent are replayed; `POST` and `PATCH` are not, and
/// the request that loses its connection gets the `502` instead. That is not a worse answer, it is
/// the honest one: whether such a request may be sent again is the client's to decide, and the
/// client is the only layer that knows.
///
/// Compared exactly, so a non-canonical spelling is simply not replayed — an unknown method is one
/// whose effect is unknown too.
fn idempotent_method(method: &str) -> bool {
    matches!(
        method,
        "GET" | "HEAD" | "PUT" | "DELETE" | "OPTIONS" | "TRACE"
    )
}

/// Whether the upstream has anything at all to say on this connection, by a peek that leaves it
/// untouched for the relay that follows.
///
/// Asked of a **reused** connection only, and it answers one question: was the connection still
/// there when the request went out? An upstream may close a parked connection at any moment, and the
/// proxy learns of it only after writing — so this is where that shows up, before a byte of response
/// has reached the client and while the request is still in hand to send again. `false` means the
/// far side is gone.
fn upstream_spoke(sock: &TcpStream) -> bool {
    let mut one = [0u8; 1];
    matches!(sock.peek(&mut one), Ok(n) if n > 0)
}

/// Whether these bytes end at the blank line that ends a head.
///
/// A head ends at an empty line, and RFC 9112 §2.2 has a recipient accept a bare LF as a line
/// terminator — so the empty line has four spellings: `\r\n\r\n`, `\n\n`, `\r\n\n` and `\n\r\n`.
/// [`read_head_buffered`] reads whole lines and tests each against `\r\n` and `\n`, which accepts all
/// four, and [`parse_head`] splits on both; a byte-wise reader has to name them, or the planes
/// disagree about where a head ends. The byte-wise one is the entrance, the first head every client
/// sends, so a plane that recognized fewer spellings there would leave a bare-LF `CONNECT` with no
/// terminator to find: read to its deadline, then answered by a closed connection.
///
/// Two tests cover the four, because every spelling ends either `\n\n` (which `\r\n\n` ends with
/// too) or `\n\r\n` (which `\r\n\r\n` ends with too).
fn head_terminated(buf: &[u8]) -> bool {
    buf.ends_with(b"\n\n") || buf.ends_with(b"\n\r\n")
}

/// Read a request head byte-by-byte until the blank-line terminator, leaving the stream positioned
/// exactly after it (so the next bytes — a TLS ClientHello — are untouched). Bounded by `max` bytes
/// and by `deadline` (see [`Deadlined`]).
///
/// What arrived is appended to `buf` whether or not the head completes, because the caller has to
/// tell a client that connected and closed without a word — an ordinary probe, nothing to report —
/// from one whose head began and never finished, which is an attempt an operator should be able to
/// see.
fn read_head_raw<R: Read>(
    r: &mut R,
    max: usize,
    deadline: Instant,
    buf: &mut Vec<u8>,
) -> io::Result<()> {
    let mut r = Deadlined::new(r, deadline);
    let mut one = [0u8; 1];
    loop {
        if r.read(&mut one)? == 0 {
            return Err(invalid(
                "connection closed before the end of the request head",
            ));
        }
        buf.push(one[0]);
        if head_terminated(buf) {
            return Ok(());
        }
        if buf.len() > max {
            return Err(invalid("request head too large"));
        }
    }
}

/// Read a request head from a buffered reader line by line until the blank-line terminator. Any
/// bytes the reader buffered past the head (the body) stay in the reader for the caller to consume.
/// Bounded by `max` bytes and by `deadline` (see [`Deadlined`]).
fn read_head_buffered<R: BufRead>(r: &mut R, max: usize, deadline: Instant) -> io::Result<Vec<u8>> {
    let mut r = Deadlined::new(r, deadline);
    let mut buf = Vec::new();
    loop {
        let start = buf.len();
        // Cap each line at the remaining budget (+1 to detect overflow): a bare `read_until` would
        // buffer an arbitrarily long line with no terminator *before* the size check below runs, so
        // an in-cage client could force unbounded host-side allocation here (this proxy runs outside
        // the cage's cgroup). With the cap a no-`\n` flood hits the budget and errors.
        let budget = (max - start + 1) as u64;
        if (&mut r).take(budget).read_until(b'\n', &mut buf)? == 0 {
            return Err(invalid(
                "connection closed before the end of the request head",
            ));
        }
        if buf.len() > max {
            return Err(invalid("request head too large"));
        }
        if matches!(&buf[start..], b"\r\n" | b"\n") {
            return Ok(buf);
        }
    }
}

/// A parsed request head: the request line and its headers.
struct Head {
    request_line: String,
    headers: Vec<(String, String)>,
}

impl Head {
    /// The value of a header by case-insensitive name (the first, if duplicated).
    ///
    /// Case only, deliberately, where [`header_name_eq`] also folds `_` onto `-`. The two rules
    /// answer different questions. That one guards an **application** collision — a CGI-style server
    /// maps `X-Api-Key` and `X_Api_Key` onto one `HTTP_X_API_KEY` — so the injection strip has to
    /// recognize both. These lookups feed the framing and anti-fronting checks, and framing is read
    /// by an HTTP parser matching field names as exact tokens; `_` is a valid token character, so
    /// `Content_Length` is a different header rather than a spelling of this one. The boundary is
    /// pinned by
    /// `wire::the_framing_lookups_fold_case_only_while_the_injection_strip_also_folds_underscores`,
    /// which also names what would overturn it.
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    /// How many headers carry this name (case-insensitive, on the same terms as [`Self::header`]) —
    /// to catch a duplicated header.
    fn count(&self, name: &str) -> usize {
        self.headers
            .iter()
            .filter(|(k, _)| k.eq_ignore_ascii_case(name))
            .count()
    }

    /// Whether this **request** leaves the connection it arrived on able to carry another one — the
    /// client's own statement about the client's leg, the mirror of [`response_keeps_alive`] for the
    /// upstream's. `HTTP/1.1` is the version whose connections persist by default; a `Connection:
    /// close` token says outright that this is the last request on the connection. `HTTP/1.0`
    /// answers no even when it asks to keep alive: that extension carries framing ambiguities of its
    /// own, and every client this proxy exists for speaks 1.1.
    fn keeps_alive(&self) -> bool {
        self.request_line.split_whitespace().nth(2) == Some("HTTP/1.1")
            && !self
                .headers
                .iter()
                .filter(|(k, _)| k.eq_ignore_ascii_case("connection"))
                .flat_map(|(_, v)| v.split(','))
                .any(|t| t.trim().eq_ignore_ascii_case("close"))
    }
}

/// The bytes the proxy will hold in request-body buffers at any one moment, **across every
/// connection**.
///
/// [`BodyLimits::per_request`] bounds one body; this bounds their sum. The distinction matters because
/// the proxy is host-side: [`crate::sandbox::cgroup::wrap`] puts *bwrap* in the launch's systemd
/// scope, so the cage's `MemoryMax` governs the cage and not the supervisor holding these buffers.
/// Without a shared ceiling, as many requests as [`ProxyCtx::max_conns`] admits (`[network]
/// max_connections`, which a launch may raise) each buffering a maximal body would have the host
/// allocate the product of the two — a denial of service an in-cage agent reaches
/// with nothing more than an allowed host and concurrency.
///
/// The ceiling is **derived** from the number below rather than picked as a round figure, because
/// that number is the one a user meets: a `chunked` request reserves the whole per-request ceiling
/// (its length is unknowable until read), so the budget divided by that ceiling is exactly how many
/// chunked uploads may be in flight at once. Making the divisor the constant keeps that visible
/// instead of leaving it to be discovered by division.
pub(crate) const CONCURRENT_CHUNKED_UPLOADS: u64 = 16;

/// The share of host RAM the budget will not exceed, as a divisor.
///
/// The multiple above answers "how many uploads at once". It does not answer "on what machine": a
/// launch on a workstation and one on a small laptop derive the same absolute ceiling from it, and
/// these bytes are reached from inside the cage but allocated outside its cgroup, so on the small
/// host the same in-cage caller takes a far larger share of what the host has. The cage's own limits
/// are already stated as fractions of RAM for that reason (see [`crate::sandbox::cgroup`]), and this
/// states the host-side budget the same way, so the two read alike.
///
/// **Where this bites, stated rather than left to be divided out**: it equals
/// [`CONCURRENT_CHUNKED_UPLOADS`], so with the default `body_max_mb` the two agree at exactly 16 GiB
/// of host RAM. Above that the multiple decides and this changes nothing; below it, this does. That
/// is the intent and not a coincidence: what makes the budget worth bounding is the share of the
/// host it can take, and a gibibyte is a rounding error on a workstation and an eighth of a small
/// laptop. A smaller divisor would trim the budget on machines where it was never the problem, and
/// buy a bound on a poste that is already small there.
///
/// What it bounds is **concurrency, not the peak**: the floor in [`BodyLimits::sized`] always admits
/// one body, so a launch that raises `body_max_mb` past this whole share still holds that one body.
/// The share decides how many at once, and `body_max_mb` decides how large one may be.
const BODY_BUDGET_RAM_SHARE: u64 = 16;

/// Total usable RAM in bytes, or `None` when `/proc/meminfo` cannot be read or parsed.
fn host_ram() -> Option<u64> {
    std::fs::read_to_string("/proc/meminfo")
        .ok()?
        .lines()
        .find_map(|line| line.strip_prefix("MemTotal:"))?
        .split_whitespace()
        .next()?
        .parse::<u64>()
        .ok()?
        .checked_mul(1024)
}

/// What one launch will hold in request-body buffers: one body's ceiling, and the sum across every
/// connection. Resolved once from `[network] body_max_mb` and carried on the context, so the check
/// that refuses a body, the reservation that admits one, and the message that explains the refusal
/// all read the same two numbers.
#[derive(Clone, Copy)]
pub(super) struct BodyLimits {
    /// The most of one request body the proxy holds. Reached by a `chunked` request, which must be
    /// buffered to be re-framed, and by one a signer asked for a digest over.
    per_request: u64,
    /// The bytes held at one moment across every connection — [`CONCURRENT_CHUNKED_UPLOADS`] times
    /// the above, for the reason given there, but never more than
    /// [`BODY_BUDGET_RAM_SHARE`] of what the host has.
    total: u64,
}

impl BodyLimits {
    pub(super) fn new(per_request: u64) -> Self {
        Self::sized(per_request, host_ram())
    }

    /// [`Self::new`] with the host's RAM supplied rather than read, so the arithmetic can be
    /// exercised for a machine of any size — including the one where the share bites, which is not
    /// the machine the tests happen to run on.
    ///
    /// A host whose RAM cannot be read gets the multiple alone: that was the whole bound until now,
    /// and failing open here keeps a launch working where `/proc` is not readable rather than
    /// silently shrinking its budget to zero.
    ///
    /// The floor is one body. A budget below `per_request` would refuse every chunked upload
    /// outright, which turns a bound on *concurrency* into a switch that turns the feature off, and
    /// would make `body_max_mb` mean the opposite of what it says: raising it would forbid more.
    fn sized(per_request: u64, ram: Option<u64>) -> Self {
        let by_count = per_request.saturating_mul(CONCURRENT_CHUNKED_UPLOADS);
        let total = match ram {
            Some(ram) => by_count.min(ram / BODY_BUDGET_RAM_SHARE).max(per_request),
            None => by_count,
        };
        Self { per_request, total }
    }
}

/// The largest `Content-Length` body the proxy reads into memory for **reuse**, when nothing else
/// asked it to.
///
/// A body the proxy holds is one it can send a second time, and that is the whole of what makes a
/// request eligible for a pooled upstream connection: a connection the far side closed while it was
/// parked only shows up after the write, so a body already streamed away cannot be recovered. A
/// streamed body therefore opened its own connection and paid a TLS handshake for it, every time.
///
/// Holding it instead trades a copy for that handshake, so the ceiling is where the two meet. The
/// handshake is a fixed cost and the copy grows with the body, which puts the crossing at several
/// hundred kilobytes on this machine; this sits comfortably below it and covers the request bodies
/// an API client actually sends. Past it the request streams exactly as it did before.
const POOL_HOLD_MAX: u64 = 256 * 1024;

/// The reason token a request refused for want of buffer budget carries. Its own token, and a
/// `503` rather than a `4xx`, because nothing is wrong with the request: the proxy is holding other
/// bodies right now and will take this one when it is not — the same shape as
/// `splice::MAX_CONCURRENT_SPLICES`.
const BODY_BUFFER_CAP: &str = "body-buffer-cap";

/// A reservation against [`BodyLimits::total`], released when it drops.
///
/// Taken **before a byte is read**, because a budget checked afterwards bounds nothing: by then the
/// memory is allocated. Held for as long as the buffer is, which is until the forwarded request has
/// been written.
struct BodyBudget<'a> {
    budget: &'a std::sync::atomic::AtomicU64,
    bytes: u64,
}

impl Drop for BodyBudget<'_> {
    fn drop(&mut self) {
        self.budget.fetch_sub(self.bytes, Ordering::Relaxed);
    }
}

/// Reserve room to buffer one request body, or `None` where the budget is spent.
///
/// A `chunked` request declares no length, so it reserves the per-request ceiling: what it will
/// actually read is unknowable until it is read, and a reservation made after the fact is not one.
/// A declared length reserves exactly itself.
fn reserve_body_buffer(
    budget: &std::sync::atomic::AtomicU64,
    chunked: bool,
    body_len: u64,
    limits: BodyLimits,
) -> Option<BodyBudget<'_>> {
    let bytes = match chunked {
        true => limits.per_request,
        false => body_len,
    };
    let mut seen = budget.load(Ordering::Relaxed);
    loop {
        // Checked, not because the callers can currently overflow it — a body above the per-request
        // ceiling is refused before this is reached — but because a guard whose arithmetic depends
        // on its callers having checked something first is a guard that holds by coincidence. An
        // overflow here would wrap to a small total and admit exactly what the ceiling exists to
        // refuse.
        let total = seen.checked_add(bytes)?;
        if total > limits.total {
            return None;
        }
        match budget.compare_exchange_weak(seen, total, Ordering::Relaxed, Ordering::Relaxed) {
            Ok(_) => return Some(BodyBudget { budget, bytes }),
            Err(now) => seen = now,
        }
    }
}

/// What a request refused for want of buffer budget is told.
fn body_budget_message() -> String {
    "the proxy is already holding as much request-body data as it will hold at one time — this      request was not sent, and the same request will be taken once one in flight completes"
        .to_string()
}

/// Whether a request's declared body is already larger than sbx will hold, before a byte is read.
///
/// Answered from the head alone, and answered **first**: a client waiting on `Expect: 100-continue`
/// must not be invited to send a body sbx has already decided to refuse, or an oversized upload
/// crosses the loopback only to meet a `413`. A `chunked` request declares no length, so there is
/// nothing to answer from and its ceiling is enforced by the de-chunker as it reads.
fn body_exceeds_hold(chunked: bool, body_len: u64, limits: BodyLimits) -> bool {
    !chunked && body_len > limits.per_request
}

/// Read a request's whole body into memory, before the request is signed.
///
/// The proxy otherwise streams a `Content-Length` body straight through and de-chunks a `chunked`
/// one only on its way out, both of which put the bytes past sbx by the time a signature is formed.
/// A signer whose scheme covers the payload needs the digest *in the question*, so for those
/// requests — and only those — the body is held first.
///
/// The same per-request ceiling bounds both shapes, since the memory it bounds is the same memory:
/// for a `chunked` body by the de-chunker as it reads, and for a declared one by
/// [`body_exceeds_hold`], which the caller must have asked before calling this.
fn hold_request_body<R: BufRead>(
    reader: &mut R,
    chunked: bool,
    body_len: u64,
    limits: BodyLimits,
) -> io::Result<Vec<u8>> {
    if chunked {
        return read_chunked_body(reader, limits.per_request);
    }
    // Sized up front, so the read fills one allocation rather than growing geometrically into a
    // transient peak above what was reserved for it. Clamped, because the allocation must be bounded
    // by what this function will accept whatever the caller checked.
    let mut body = Vec::with_capacity(body_len.min(limits.per_request) as usize);
    let read = reader.take(body_len).read_to_end(&mut body)?;
    if read as u64 != body_len {
        return Err(invalid("the request body ended before its Content-Length"));
    }
    Ok(body)
}

/// The **positions** in the credential set of the injections this request receives.
///
/// This is what identifies a credential set without carrying one: the upstream-connection pool is
/// partitioned by which credentials a request received, and its key has to name them without holding
/// them. Ascending by construction, so two requests matching the same rules produce the same list.
/// The two functions share this one matcher so the partition can never drift from the injection.
fn matching_injection_ids(
    creds: &CredentialSet,
    host: &str,
    port: u16,
    target: &str,
) -> Vec<usize> {
    creds
        .injections
        .iter()
        .enumerate()
        .filter(|(_, inj)| allowlist::rule_matches(&inj.rule, host, port, target))
        .map(|(i, _)| i)
        .collect()
}

/// The header names this request's injections **actually** set, read off the formed pairs.
///
/// Read off the answer rather than off the declarations, because for a signer the two differ: a
/// manifest's `sets_headers` is what the plugin *may* set, and a plugin that declines one on this
/// request leaves the client's own copy of that header on the wire. Asking the declaration told
/// `observe_head` to skip a header nothing had replaced, so a credential the cage sent for itself
/// there was never learned — not redacted in `sbx net logs`, and not covered by the outbound
/// tripwire afterwards, on any plane.
///
/// It is also the list [`reserialize_request`] strips by, so the two now answer with one voice:
/// exactly the headers sbx replaced are the ones skipped.
fn injected_names(injected: &[(String, String)]) -> Vec<&str> {
    injected.iter().map(|(name, _)| name.as_str()).collect()
}

/// Whether any credential this request carried is one a `401` says something about — the gate on
/// spending a resolver run. See [`HeaderInjection::refreshable`].
fn any_refreshable(creds: &CredentialSet, ids: &[usize]) -> bool {
    ids.iter().any(|&i| creds.injections[i].refreshable())
}

/// Record a request's FINAL status on its `allow` event, and act on a `401`.
///
/// A `401` from a host this request carried a credential to is the destination itself saying the
/// value is no longer accepted — the one signal worth re-resolving on, and a truer one than any
/// declared expiry. Gated on a *refreshable* injection, so a refusal from a host sbx injects nothing
/// into can never make an in-cage agent drive sbx's resolver, and a host whose credential is signed
/// per request never spends a resolver run on a value that cannot be stale.
///
/// Each inspected plane still decides *when* it holds a final status, because they read it from
/// different places: the two HTTP/1.1 planes parse a status line and skip the interim `1xx` they
/// already relayed, while the h2 plane takes the response's `:status` directly. What happens once
/// they hold one is a single decision, and lives here — written out per plane it had already
/// drifted, the h2 copy recording the status without the refresh, so an injected token that went
/// stale mid-session stayed stale for every later stream on that plane while the very same
/// credential refreshed on the other two.
fn note_final_status(
    ctx: &ProxyCtx,
    seq: Option<u64>,
    creds: &CredentialSet,
    injected_ids: &[usize],
    code: u16,
) {
    ctx.set_status(seq, code);
    if code == 401 && any_refreshable(creds, injected_ids) {
        ctx.credential_refused();
    }
}

/// Refuse a WebSocket upgrade into a credential-injected host, and say whether it did.
///
/// A credential-injected host cannot also host a WebSocket: the injected secret rides the handshake,
/// but once the upgrade completes the frames are opaque and cannot be redacted, so a value the host
/// reflects in a frame would re-enter the cage. The refusal is fail-closed and comes before any
/// egress, so no `allow` is recorded, rather than open an unredactable channel carrying an injected
/// secret. Reached only when a `{WS}` rule already permitted the upgrade to this host — an upgrade
/// to a non-`{WS}` host was denied by method before this.
///
/// The `Blocked` outcome and the `403` are recorded and written here, on the caller's own client
/// socket `w`, so the two inspected HTTP/1.1 planes refuse with one status, one tag and one message;
/// each caller has only to end its own turn on `true`.
fn refuse_ws_into_injected_host<W: Write>(
    w: &mut W,
    ctx: &ProxyCtx,
    creds: &CredentialSet,
    host: &str,
    port: u16,
    method: &str,
    target: &str,
) -> io::Result<bool> {
    if matching_injection_ids(creds, host, port, target).is_empty() {
        return Ok(false);
    }
    ctx.outcome(
        crate::sandbox::control::Proto::Https,
        host,
        port,
        Some(method),
        Some(target),
        StatKind::Blocked,
        "ws-injection-refused",
    );
    write_refusal(
        w,
        "403 Forbidden",
        "ws-injection-refused",
        "a WebSocket to a credential-injected host is refused: its frames cannot be redacted",
    )?;
    Ok(true)
}

/// The reason token a request refused for want of a signature carries: the `x-sbx-egress-reason`
/// header, and the reason in the log. Distinct from every policy tag, because nothing about the
/// policy said no — the credential could not be formed.
const SIGNER_REFUSED: &str = "signer-refused";

/// The reason token a request refused for a body too large to hold carries. Its own token rather
/// than [`SIGNER_REFUSED`], because no plugin refused: sbx did, before asking, and the fix is the
/// request's size and not the credential.
const SIGNER_BODY_TOO_LARGE: &str = "signer-body-too-large";

/// What a request refused for an unholdable body is told. It names the ceiling, because a size limit
/// a caller cannot read is one it can only discover by bisection.
fn body_too_large_message(body_len: u64, limits: BodyLimits) -> String {
    format!(
        "a signer for this destination is told the digest of the request body, so sbx holds the \
         body before signing — and this request's {body_len} bytes are above the {}-byte ceiling \
         for a body it holds (`[network] body_max_mb` moves it)",
        limits.per_request
    )
}

/// The sentence a signer refusal answers with. It names the plugin, because a refusal that does not
/// say who refused leaves the user auditing every declaration, and it says plainly that the request
/// was not sent: an unsigned request reaching the destination would come back as an authentication
/// error for a reason that has nothing to do with the credential.
///
/// **Redacted before it is written, because this one is answered into the cage.** Every other
/// refusal body is sbx's own words about its own policy; a signer's carries the plugin's, and a
/// signer whose manifest declares `reads_secret` holds the credential in clear. The feed already
/// scrubs the same text ([`super::signer_control::SignerRing::push`]); the sink that matters more
/// is this one, since the cage is the adversary and the log is not. Masked in place rather than
/// named, matching what the cage already sees where a reflected secret is taken out of a response
/// body.
fn signer_refusal_message(refusal: &SignRefusal, needles: &[SecretNeedle]) -> String {
    let mut body = format!(
        "the `{}` signer plugin did not sign this request ({}), so it was not sent",
        refusal.signer, refusal.why
    )
    .into_bytes();
    redact_in_place(&mut body, needles);
    String::from_utf8_lossy(&body).into_owned()
}

/// Whether the decrypted client request head carries any secret value verbatim on its way to
/// `dest` — the outbound leak tripwire. Scans the raw head bytes (request line + every client
/// header, before sbx's own injection is added), so it can never self-trip on an injected
/// credential. A backstop, not a boundary: it catches a *verbatim* secret in the *head* only — an
/// encoded value, or one in the streamed body, is out of scope (see the module doc).
///
/// `dest` is the host the request is bound for, and it decides which needles apply
/// ([`SecretNeedle::scanned_for`]): a declared secret is scanned for everywhere, while one the cage
/// obtained for itself is scanned for everywhere EXCEPT the host it was acquired on. Sending such a
/// credential back to its own service is the app using it, not leaking it; refusing that refuses
/// every request after the first one an app makes with its own session.
fn carries_secret(head_bytes: &[u8], redactions: &[SecretNeedle], dest: &str) -> bool {
    redactions
        .iter()
        .filter(|n| n.scanned_for(dest))
        .any(|n| n.find_in(head_bytes, 0).is_some())
}

/// Reserialize a request head for forwarding upstream: keep the request line and headers, but drop
/// any client `Connection`/`Proxy-Connection` — the proxy owns hop-by-hop semantics on both legs and
/// sets this one itself. `Proxy-Authorization` is dropped too: it is a credential for the *proxy
/// hop*, and forwarding it would hand the origin server a secret addressed to sbx.
///
/// `keep_alive` decides what goes in its place, and it is a statement about the **upstream** leg
/// alone. `false` forces `Connection: close`, so the server closes after this one response; that was
/// long the only option, because the relay could not tell the end of a message from the end of a
/// socket and needed the close to know where to stop. `true` says nothing at all, which under
/// HTTP/1.1 is the request to keep the connection open — the proxy then knows where the response
/// ends on its own, and the connection can carry a later request. Neither value reaches the client:
/// its own leg is closed after one response either way (see [`force_close_in_head`]).
///
/// Each `(header, value)` in `injections` is **strip-and-replace**d: every client-supplied copy of
/// that header — over all spellings (case- and `_`/`-`-insensitive, see [`header_name_eq`]) — is
/// dropped, then sbx's value is appended. The agent in the cage is the adversary, so it must never
/// be able to leave its own copy of an injected header alongside sbx's (which a permissive proxy
/// would forward as a second, attacker-controlled value).
fn reserialize_request(
    head: &Head,
    injections: &[(String, String)],
    force_content_length: Option<u64>,
    keep_alive: bool,
) -> Vec<u8> {
    let mut out = String::with_capacity(head.request_line.len() + 64);
    out.push_str(&head.request_line);
    out.push_str("\r\n");
    for (k, v) in &head.headers {
        if k.eq_ignore_ascii_case("connection")
            || k.eq_ignore_ascii_case("proxy-connection")
            // A credential the client addressed to the proxy hop, never to the origin server.
            || k.eq_ignore_ascii_case("proxy-authorization")
            // `Expect: 100-continue` is answered by the proxy to the client directly; forwarding it
            // would make the upstream expect a body-handshake the proxy has already resolved.
            || k.eq_ignore_ascii_case("expect")
        {
            continue;
        }
        // strip any client copy of a header sbx is about to inject (all spellings), so the
        // injected value is the only one the upstream sees.
        if injections.iter().any(|(name, _)| header_name_eq(k, name)) {
            continue;
        }
        // A chunked request is re-framed with a synthesized Content-Length below, so drop the
        // client's Transfer-Encoding and any client Content-Length (the forced value is the only
        // one the upstream sees — no CL/TE smuggling ambiguity can reach it).
        if force_content_length.is_some()
            && (k.eq_ignore_ascii_case("transfer-encoding")
                || k.eq_ignore_ascii_case("content-length"))
        {
            continue;
        }
        out.push_str(k);
        out.push_str(": ");
        out.push_str(v);
        out.push_str("\r\n");
    }
    for (name, value) in injections {
        out.push_str(name);
        out.push_str(": ");
        out.push_str(value);
        out.push_str("\r\n");
    }
    if let Some(n) = force_content_length {
        out.push_str("Content-Length: ");
        out.push_str(&n.to_string());
        out.push_str("\r\n");
    }
    if !keep_alive {
        out.push_str("Connection: close\r\n");
    }
    out.push_str("\r\n");
    out.into_bytes()
}

/// Enter the response-streaming phase of an inspected (L7) request: lift the per-read timeout on
/// the validated upstream socket so a long-lived or bursty response — server-sent events, a slow
/// completion that idles between tokens — is not aborted mid-flight. The timeout the serve loop set
/// bounds a slowloris on the *request head*; by here the request is permitted and forwarded, so an
/// idle upstream is a legitimate stream, not an attack (the raw L4 splice clears its timeouts for
/// the same reason). Leaving it in place instead abruptly drops the connection at the timeout, which
/// the in-cage client sees as a truncated stream (`peer closed connection without sending TLS
/// close_notify`) — the failure mode that cut streaming agents mid-completion.
///
/// The client *write* timeout is deliberately left untouched, so a stalled in-cage reader still
/// cannot pin a proxy thread indefinitely, and a response whose framing is known ends at its own
/// last byte without waiting for anything. Residual (bounded by `MAX_CONCURRENT_CONNS`,
/// same-tenant): an upstream that neither sends nor closes while its client has gone away can hold a
/// thread until it does — the accepted cost of not killing a genuinely idle stream, as for the L4
/// splice.
///
/// The bound is put back before a finished connection is parked for reuse, since a connection that
/// is not relaying anything has no claim to be left unbounded (see [`pool::UpstreamPool::park`]).
fn begin_response_stream(upstream: &TcpStream) {
    let _ = upstream.set_read_timeout(None);
}

/// Read the upstream's response head and relay it to the client, returning the head **as the
/// upstream sent it** with whether it was terminated. Bytes the buffered reader pulled past the head
/// stay in it for the body relay.
///
/// `redactions` is the response-side reflection backstop, non-empty only for a host an injection
/// targets: an echo or debug endpoint reflects the injected credential in a header of its own as
/// readily as in a body, so the head is masked before it is written to the client. The masking is
/// equal-length, so the framing the caller parses is unaffected either way — and it parses the
/// upstream's own bytes, which is what the returned head is. The capture is handed those same
/// unmasked bytes and does its own masking at filing time, exactly as it does for the body.
///
/// An interim `1xx` — `100 Continue`, or the `103 Early Hints` CDNs emit — is a complete message of
/// its own that the real head follows, so it is relayed and read past rather than mistaken for the
/// response. It is deliberately left out of the capture, which shows the response the request
/// actually got; it is still counted, because those bytes did cross to the cage.
///
/// A head the upstream cuts short is relayed as far as it arrived and reported incomplete, never an
/// error: the caller then delimits the rest by the close, which is what this path did throughout
/// before it framed anything. A head that runs past [`HEAD_MAX`] arrives here the same way, and it
/// is relayed the same way, on purpose. Such a head has no terminator yet, so the `Connection`
/// rewrite below declines it (`rewrite_client_connection` returns an unterminated head untouched —
/// dropping a header line out of a head whose remainder the client is still going to read as body
/// would re-attach that remainder to the wrong header). The cage therefore sees the upstream's own
/// hop-by-hop `Connection` on a leg sbx closes anyway: `final_head` is false, so the framing is
/// [`BodyFraming::ToEof`] and `persistent` is false. That is a stale header on a closing connection,
/// not a framing sbx got wrong — and the alternatives are worse: refusing the response would drop a
/// large-but-legitimate head (which is exactly what the tolerant read exists to keep serving), and
/// stopping the relay at the cap would hand the cage a head cut off mid-line.
///
/// `client_leg` decides what the relayed head says about the **client's** connection, which the
/// `Connection` header makes a per-hop question: it is sbx's statement about its own leg, never a
/// copy of the upstream's about the other one. Three things stay pinned to the **upstream's own**
/// bytes across any rewrite: the head returned to the caller, so the body framing is decided from
/// what the server actually said; the capture, which records the response as it was served; and the
/// equal-length masking contract, which is applied after the rewrite rather than through it. The
/// byte counter follows the other side — it measures what crossed to the cage, so it counts what was
/// written.
fn relay_response_head<R: BufRead, W: Write>(
    up: &mut R,
    client: &mut W,
    down: &AtomicU64,
    capture: Option<&CaptureGuard>,
    redactions: &[SecretNeedle],
    request_method: &str,
    client_leg: ClientLeg,
) -> io::Result<RelayedHead> {
    loop {
        let (head, complete) = read_response_head(up, HEAD_MAX);
        if head.is_empty() {
            return Ok(RelayedHead {
                head,
                framing: BodyFraming::ToEof,
                persistent: false,
            });
        }
        let interim =
            complete && matches!(parse_status_code(&head), Some(c) if (100..200).contains(&c));
        // An interim `1xx` is not the response, so its framing is not the connection's to state —
        // the head that follows it is the one every question below is about.
        let final_head = complete && !interim;
        let framing = if final_head {
            response_framing(&head, request_method)
        } else {
            BodyFraming::ToEof
        };
        let persistent = final_head
            && matches!(client_leg, ClientLeg::MayReuse { .. })
            && response_keeps_alive(&head)
            // A body whose end the client can only find by watching for the close cannot be followed
            // by anything: announcing a persistent connection would leave it waiting for a boundary
            // that never comes.
            && !matches!(framing, BodyFraming::ToEof);
        // State sbx's own answer on every final head — `close` when the connection ends here, the
        // offer of another request when it does not, and in both cases with the upstream's hop
        // headers dropped rather than passed off as this leg's. An interim `1xx` is not a head sbx
        // speaks about, so it crosses untouched.
        let wire = match client_leg {
            _ if !final_head => head.clone(),
            ClientLeg::MayReuse { idle } if persistent => offer_reuse_in_head(&head, idle),
            ClientLeg::Close | ClientLeg::MayReuse { .. } => force_close_in_head(&head),
        };
        write_head_to_client(wire, client, down, redactions)?;
        if interim {
            client.flush().ok();
            continue;
        }
        if let Some(c) = capture {
            c.push_response(&head);
        }
        return Ok(RelayedHead {
            head,
            framing,
            persistent,
        });
    }
}

/// Write one response head to the client leg: masked on the way out, and counted as it crosses.
///
/// `wire` is the head **as the client should see it**, and shaping it is the caller's because the
/// answer is not the same for every head. A final head carries sbx's own statement about this leg
/// ([`ClientLeg`]); an interim `1xx` and a WebSocket `101` cross with the upstream's own hop headers,
/// because neither is a head sbx speaks about — rewriting a `101` would undo the very upgrade the
/// two peers just agreed.
///
/// What is *not* the caller's is the pair below it. A head that reaches the cage unmasked is a
/// reflected credential re-entering it, and the counter has to measure what was written rather than
/// what arrived, since the two differ by exactly the rewrite. Both were spelled out again by the
/// upgrade relay, which had quietly lost them; they belong to every head this proxy relays.
fn write_head_to_client<W: Write>(
    mut wire: Vec<u8>,
    client: &mut W,
    down: &AtomicU64,
    redactions: &[SecretNeedle],
) -> io::Result<()> {
    if !redactions.is_empty() {
        redact_in_place(&mut wire, redactions);
    }
    client.write_all(&wire)?;
    down.fetch_add(wire.len() as u64, Ordering::Relaxed);
    Ok(())
}

/// What one relayed response head left behind — see [`relay_response_head`].
struct RelayedHead {
    /// The upstream's head exactly as it arrived, before any `Connection` rewrite and before any
    /// redaction. Every decision downstream is read off these bytes rather than off what was written.
    head: Vec<u8>,
    /// Where this response's body ends, already resolved against the request's method.
    framing: BodyFraming,
    /// Whether the head **as written to the client** announces a connection a further request may
    /// ride on. False unless the caller asked for [`ClientLeg::MayReuse`] and the head answered yes.
    persistent: bool,
}

/// What a relayed head should tell the client about the **client's own** connection.
///
/// Neither variant relays the upstream's answer. What the upstream said describes the *upstream's*
/// socket, and the two legs are not the same connection: a plane that serves one request had been
/// passing a `Connection: close` request's response through untouched, on the reasoning that such a
/// response must itself say `close`. It must, but saying so is the upstream's job, and an upstream
/// that answers `keep-alive` anyway would have told the cage it could send a second request into a
/// connection sbx is about to close. sbx states its own answer instead, which it is the only side
/// in a position to know.
enum ClientLeg {
    /// Rewrite the final head to `Connection: close`: this connection serves one request, and the
    /// client is told so rather than left to find out when the stream ends.
    Close,
    /// Relay the head as the upstream framed it when it leaves the client's connection usable, and
    /// rewrite it to `Connection: close` when it does not. The only variant that reports back, and
    /// the only one that carries the idle bound: what it announces to the client has to be the bound
    /// the tunnel will actually be held for.
    MayReuse { idle: Duration },
}

/// Cleanly shut down the interception TLS after a response is fully relayed: queue a `close_notify`
/// and flush the connection's pending TLS records to the client socket. The sending half-close is
/// the correct TLS teardown; without it the client sees a bare socket close after the last byte,
/// which a streaming client surfaces as `peer closed connection without sending TLS close_notify`
/// even though the whole body arrived — the same error shape as an idle cut, but at end-of-stream.
/// It matters most for a close-delimited response (no `Content-Length`), where the client relies on
/// the shutdown to know the body ended. Best-effort: a client that already went away just makes the
/// writes fail, which ends the loop.
fn finish_tls(stream: &mut StreamOwned<ServerConnection, UnixStream>) {
    stream.conn.send_close_notify();
    while stream.conn.wants_write() {
        if stream.conn.write_tls(&mut stream.sock).is_err() {
            break;
        }
    }
    let _ = stream.sock.flush();
}

/// Stream `r` to `w` until end of input. A peer that drops the TLS connection without a
/// `close_notify` surfaces as an unexpected EOF, which ends the stream normally rather than erroring.
fn pump_to_eof<R: Read, W: Write>(r: &mut R, w: &mut W) -> io::Result<()> {
    let mut buf = vec![0u8; RELAY_CHUNK];
    loop {
        match r.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => w.write_all(&buf[..n])?,
            Err(ref e) if e.kind() == io::ErrorKind::UnexpectedEof => break,
            Err(e) => return Err(e),
        }
    }
    w.flush().ok();
    Ok(())
}

/// Stream `r` to `w` until end of input like [`pump_to_eof`], but replace every occurrence of any
/// configured secret value ([`SecretNeedle`]) with an equal-length run of `*` — the response-side
/// reflection backstop. Equal-length replacement keeps the response framing intact (`Content-Length`
/// or chunked sizes are unchanged) and `*` is printable so masking can never introduce a CR/LF; the
/// scan is over the raw bytes, with no knowledge of the response's structure. This covers the
/// **body**; a secret reflected in a response *header* is masked by [`relay_response_head`] under
/// the same decision, since the head is relayed before this runs.
///
/// Streaming-safe **without delaying the stream**: what is held back after each read is the longest
/// suffix of the window that is a proper prefix of some needle (see [`needle_prefix_suffix`]), which
/// is exactly the run that could still turn out to be the start of a secret the next read completes.
/// Every emitted byte was therefore scanned in a window that held everything a needle covering it
/// could need, and same-length replacement never shifts a position, so re-scanning the carry is
/// harmless. Memory stays bounded at `carry + one read`.
///
/// Holding a *fixed* `max_needle_len - 1` bytes instead would be equally safe and would stall the
/// response this proxy exists to carry. A streaming completion arrives as small server-sent events,
/// and an event that does not end in a needle prefix (they end `\n\n`) would still be held: the cage
/// would see each event only once the *next* one arrived, and the last event before an idle gap not
/// at all until the gap ended. The HTTP/2 twin, `relay_body_redacting` in `h2mitm.rs`, refuses to
/// carry bytes across frames at all for a stronger form of the same reason, an interactive RPC
/// deadlocking rather than lagging; that plane accepts a split secret as the residual, and this one
/// does not have to.
///
/// A backstop, not a wall (see the module doc): a re-encoded, compressed, or framing-split value
/// evades the byte match. The load-bearing boundary remains the empty netns plus the allowlist; this
/// only strips the naive verbatim reflection of an injected credential.
fn pump_redacting<R: Read, W: Write>(
    r: &mut R,
    w: &mut W,
    needles: &[SecretNeedle],
) -> io::Result<()> {
    let max_len = needles
        .iter()
        .map(|n| n.as_bytes().len())
        .max()
        .unwrap_or(0);
    // One window, reused for the whole stream: the carry sits at its head and each read is appended
    // behind it, so a body of any length costs the two allocations below and no more. Draining the
    // emitted prefix shifts only the carry, which is shorter than the longest needle.
    let mut window: Vec<u8> = Vec::with_capacity(max_len.saturating_sub(1) + RELAY_CHUNK);
    let mut buf = vec![0u8; RELAY_CHUNK];
    loop {
        let n = match r.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => n,
            Err(ref e) if e.kind() == io::ErrorKind::UnexpectedEof => break,
            Err(e) => return Err(e),
        };
        window.extend_from_slice(&buf[..n]);
        redact_in_place(&mut window, needles);
        // Hold back only what could still become a secret: the tail that spells the start of one.
        // Everything before it is finished with, whatever the next read brings.
        let split = window.len() - needle_prefix_suffix(&window, needles);
        w.write_all(&window[..split])?;
        window.drain(..split);
    }
    // The trailing carry was already scanned in its final window (a needle cannot extend past EOF).
    w.write_all(&window)?;
    w.flush().ok();
    Ok(())
}

/// The length of the longest suffix of `window` that is a **proper prefix** of some needle.
///
/// This is what a streaming scan must hold back, and no more: a suffix that spells the beginning of
/// a needle may turn out to be that needle once the next read arrives, while a suffix that spells no
/// beginning cannot become one however the stream continues. Ordinary traffic ends in neither, so
/// the usual answer is zero and the stream is passed through untouched.
///
/// A needle already complete inside the window was masked before this is asked, so the suffix
/// considered here is only ever an incomplete one.
fn needle_prefix_suffix(window: &[u8], needles: &[SecretNeedle]) -> usize {
    needles
        .iter()
        .map(|needle| needle.prefix_suffix_len(window))
        .max()
        .unwrap_or(0)
}

/// Replace every occurrence of every needle in `buf` with an equal-length run of `*`, in place.
/// Equal length is the invariant the streaming framing relies on; an empty or over-long needle is
/// skipped (the empty needle is screened out at resolution, but guard here too).
pub(crate) fn redact_in_place(buf: &mut [u8], needles: &[SecretNeedle]) {
    for needle in needles {
        let len = needle.as_bytes().len();
        if len == 0 || len > buf.len() {
            continue;
        }
        // Left to right, non-overlapping: a match is masked and the search resumes past it, so a
        // needle cannot match inside the `*` run its own occurrence just produced.
        let mut at = 0;
        while let Some(found) = needle.find_in(buf, at) {
            buf[found..found + len].fill(b'*');
            at = found + len;
        }
    }
}

/// Compose one egress notice line: a bold-red `sbx:` tag, the red `head`, then each yellow
/// `label: command` action (the first joined by ` — `, the rest by `  |  `). Pure over the
/// palette so it is unit-testable in both the plain and colored forms; [`print_egress_notice`]
/// wraps it with the stderr auto-detect. Used by the `ask`-mode park alert (the interactive
/// posture where a decision is needed live); a `deny`-mode refusal instead carries its hint in
/// the `403` body, which the client already shows.
fn egress_notice_line(p: &crate::style::Palette, head: &str, actions: &[(&str, &str)]) -> String {
    let mut line = format!(
        "{err}sbx:{rst} {err}{head}{rst}",
        err = p.err,
        rst = p.reset
    );
    for (i, (label, cmd)) in actions.iter().enumerate() {
        let sep = if i == 0 { " — " } else { "  |  " };
        line.push_str(&format!(
            "{sep}{ylw}{label}: {cmd}{rst}",
            ylw = p.warn,
            rst = p.reset
        ));
    }
    line
}

/// Print one egress notice line to stderr. Colour auto-detects on stderr — a terminal with
/// `NO_COLOR` unset and `TERM` not `dumb` — via the shared [`crate::style::Palette`], so a pipe or
/// a captured run prints plain text.
fn print_egress_notice(head: &str, actions: &[(&str, &str)]) {
    let p = crate::style::Palette::for_stream(std::io::IsTerminal::is_terminal(&std::io::stderr()));
    eprintln!("{}", egress_notice_line(&p, head, actions));
}

/// The body of a written refusal, in one place because two planes write it.
///
/// The HTTP/1.1 planes serialize it themselves and the HTTP/2 plane sends it as a DATA frame, so
/// nothing but a shared function keeps them saying the same thing: a caller must not learn a
/// different sentence about the same refusal depending on which protocol version it happened to
/// speak to the proxy over.
pub(super) fn refusal_body(detail: &str) -> String {
    format!("sbx egress refused this request: {detail}\n")
}

/// Write an sbx-originated refusal: the status line, an `X-Sbx-Egress-Reason` header carrying a
/// stable machine-readable category, and a short `text/plain` body repeating the human detail.
///
/// A tool (and the agent it serves) can then tell an explicit policy refusal (`403`, category
/// `denied-default`/`denied-by-rule`) from an unreachable host (`502`, `upstream-unreachable`/
/// `dns-failure`) — these are the proxy's *own* statuses, distinct from a real upstream response
/// it relays verbatim (a genuine `404` reaches the agent unchanged). The category is a fixed
/// token, so it is safe in a header; the detail is sbx-authored and only ever echoes what the
/// agent already sent (its own host/port) or a category — never the injected credential, any
/// host-side secret, or the policy's internal rule text (for which `sbx test net` is the tool).
fn write_refusal<W: Write>(
    w: &mut W,
    status: &str,
    category: &str,
    detail: &str,
) -> io::Result<()> {
    let body = refusal_body(detail);
    write!(
        w,
        "HTTP/1.1 {status}\r\n\
         X-Sbx-Egress-Reason: {category}\r\n\
         Content-Type: text/plain\r\n\
         Content-Length: {len}\r\n\
         Connection: close\r\n\r\n{body}",
        len = body.len(),
    )?;
    w.flush()
}

/// A first head that never became a request: log the attempt, tell the caller why, and close.
///
/// Every refusal in [`handle_client`] leaves a line in `sbx net logs` and an `X-Sbx-Egress-Reason`
/// the caller can read, and the two reads that come *before* the request line are no exception: a
/// head that arrives truncated, over [`HEAD_MAX`], past its deadline or not as UTF-8 is an attempt
/// an operator must be able to see, and a caller that gets nothing back cannot tell a refusal from
/// a proxy that died. It is logged with no host and no port, as the malformed request *line* beside
/// it is: a head this proxy could not read carries no destination to attribute it to.
///
/// A client that connected and closed without sending a byte is not that. It is how a probe, a
/// health check or an abandoned connection ends, there is no attempt in it to see, and it stays
/// silent.
fn refuse_unreadable_head(
    client: &mut UnixStream,
    ctx: &ProxyCtx,
    head: &[u8],
    err: &io::Error,
) -> io::Result<()> {
    if head.is_empty() {
        return Ok(());
    }
    ctx.push_log(
        super::control::Proto::Other,
        "",
        0,
        None,
        None,
        super::control::LogVerdict::Blocked,
        UNREADABLE_HEAD,
    );
    write_refusal(
        client,
        "400 Bad Request",
        UNREADABLE_HEAD,
        &unreadable_head_detail(err),
    )
}

/// What a caller is told about a head that never arrived whole, on either plane that reads one.
///
/// A socket that timed out reports the operating system's own words, which name a condition rather
/// than anything the caller did; every other cause is one of this module's own sentences, which
/// already say what is wrong with the head.
fn unreadable_head_detail(err: &io::Error) -> String {
    match err.kind() {
        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut => {
            "the request head stopped arriving and the connection timed out".to_string()
        }
        _ => err.to_string(),
    }
}

/// Write a literal string and flush — used for the cleartext `200 Connection established`.
fn write_all_str<W: Write>(w: &mut W, s: &str) -> io::Result<()> {
    w.write_all(s.as_bytes())?;
    w.flush()
}

/// One absolute-form request as it arrives, before any of it is trusted: the parsed head, the raw
/// head bytes the secret tripwire scans byte-exactly, and the request line's method and target.
/// The four already travel together — `handle_client` passes them as a group to whichever plane
/// handles the request — so naming them keeps [`admit_absolute_form`] readable at its call sites.
struct RawRequest<'a> {
    head: &'a Head,
    head_bytes: &'a [u8],
    method: &'a str,
    target: &'a str,
}

/// Which inspected plane an absolute-form request arrived on. The two differ in exactly three
/// observable ways, and this names them so [`admit_absolute_form`] can be written once.
#[derive(Clone, Copy)]
enum Plane {
    /// `http://` — strictly opt-in, and forwards no chunked framing at all.
    Cleartext,
    /// `https://` — de-chunks and re-frames like the tunneled path, so chunked is forwardable.
    HttpsForward,
}

impl Plane {
    /// The protocol this plane logs and counts under.
    fn proto(self) -> crate::sandbox::control::Proto {
        match self {
            Plane::Cleartext => crate::sandbox::control::Proto::Http,
            Plane::HttpsForward => crate::sandbox::control::Proto::Https,
        }
    }

    /// The scheme a malformed target is named against, so the refusal says which URL was expected.
    fn scheme(self) -> &'static str {
        match self {
            Plane::Cleartext => "http://",
            Plane::HttpsForward => "https://",
        }
    }

    /// Whether this plane may forward chunked framing — the one thing the smuggling check is told
    /// differently per plane.
    fn forwards_chunked(self) -> bool {
        matches!(self, Plane::HttpsForward)
    }
}

/// What an admitted absolute-form request carries into the exchange that follows.
struct AbsoluteForm {
    host: String,
    port: u16,
    path: String,
    framing: Framing,
}

/// The four checks every absolute-form request passes before any policy verdict is reached: parse
/// the target, reject request smuggling, reject request fronting, and refuse an outbound credential
/// leak. `Ok(None)` means the request was refused and the refusal already written.
///
/// Written once for both inspected planes on purpose. The per-plane copy is precisely the mistake
/// [`wire::inspect_framing`] exists to have fixed — its own header records that a bare CR reached
/// two planes after being refused on the third, and that the reason tokens diverged for years,
/// because the check was written per plane. Step 2 here is the call to that fix; steps 1, 3 and 4
/// were still copied, and now are not.
///
/// The `push_log` / `outcome` split is deliberate and load-bearing: steps 1 and 2 log without
/// counting, steps 3 and 4 log and count. It is the part most likely to drift under copying, which
/// is the other reason this is one function.
fn admit_absolute_form(
    client: &mut UnixStream,
    ctx: &ProxyCtx,
    plane: Plane,
    req: RawRequest<'_>,
    needles: &[SecretNeedle],
) -> io::Result<Option<AbsoluteForm>> {
    let RawRequest {
        head,
        head_bytes,
        method,
        target,
    } = req;
    // 1. Parse the absolute-form `<scheme>host[:port]/path` target into (host, port, path). The host
    //    is canonicalized by the parser; the path is canonicalized inside the plane's explainer.
    let (host, port, path) = match allowlist::parse_url_target(target) {
        Ok(t) => t,
        Err(_) => {
            ctx.push_log(
                plane.proto(),
                "",
                0,
                Some(method),
                Some(target),
                crate::sandbox::control::LogVerdict::Blocked,
                "bad-request",
            );
            write_refusal(
                client,
                "400 Bad Request",
                "bad-request",
                &format!(
                    "the absolute-form request target is not a valid `{}` URL",
                    plane.scheme()
                ),
            )?;
            return Ok(None);
        }
    };

    // 2. Anti request-smuggling, fail-closed, through the check every inspected plane shares.
    let framing = match inspect_framing(head, plane.forwards_chunked()) {
        Ok(framing) => framing,
        Err(refusal) => {
            ctx.push_log(
                plane.proto(),
                &host,
                port,
                Some(method),
                Some(&path),
                crate::sandbox::control::LogVerdict::Blocked,
                refusal.reason,
            );
            write_refusal(client, "400 Bad Request", refusal.reason, refusal.detail)?;
            return Ok(None);
        }
    };

    // 3. Anti-fronting collapses to one check with no CONNECT/SNI: the absolute-form URL host must
    //    equal the `Host` header, so a request cannot claim one host in the line and another in the
    //    header (the destination the policy checks is the URL host).
    if head
        .header("host")
        .map(|h| allowlist::canonical_host(&strip_port(h)) != host)
        .unwrap_or(true)
    {
        ctx.outcome(
            plane.proto(),
            &host,
            port,
            Some(method),
            Some(&path),
            StatKind::Blocked,
            "host-mismatch",
        );
        write_refusal(
            client,
            "421 Misdirected Request",
            "host-mismatch",
            "the Host header does not match the request-line host",
        )?;
        return Ok(None);
    }

    // 4. Outbound leak tripwire on the raw head — refuse (block, never strip) a request re-sending a
    //    configured secret verbatim, scanned before sbx's own injection so it cannot self-trip. It
    //    matters more on the cleartext plane: a leaked secret sent in the clear is exposed on the
    //    wire, not just to the destination.
    if carries_secret(head_bytes, needles, &host) {
        ctx.outcome(
            plane.proto(),
            &host,
            port,
            Some(method),
            Some(&path),
            StatKind::Blocked,
            "outbound-secret",
        );
        write_refusal(
            client,
            "403 Forbidden",
            "outbound-secret",
            "the request carries a configured secret value (outbound credential leak refused)",
        )?;
        return Ok(None);
    }

    Ok(Some(AbsoluteForm {
        host,
        port,
        path,
        framing,
    }))
}

/// An `InvalidData` error with a static cause, for the proxy's fail-closed paths.
fn invalid(msg: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg)
}

/// Tests for the accept loop's own bookkeeping, kept beside it rather than in [`tests`] because
/// what they assert is a property of the slot a connection takes, with nothing served.
#[cfg(test)]
mod accept_tests {
    use super::*;

    /// A connection whose handler thread is never created gives its slot back.
    ///
    /// `std::thread::spawn` panics when the kernel refuses a thread (`EAGAIN` under `RLIMIT_NPROC`
    /// or a slice's `TasksMax`), and the accept loop is the body of a detached thread — the unwind
    /// dropped the `UnixListener` and closed the cage's only egress for the rest of the session.
    /// [`spawn_connection`] reports the refusal through [`super::super::conncap::spawn_conn`]
    /// instead, which puts the second half of the fix on the slot: the guard has to travel *inside*
    /// the closure the spawner could not run, because that closure is all the caller gets back.
    /// Taken on the loop and released only by a thread that may never start — the shape this
    /// replaces — every refusal leaked one slot, until the count reached `max_connections` and the
    /// loop answered `503 connection-cap` to a proxy that was serving nothing at all.
    #[test]
    fn a_connection_whose_handler_thread_is_never_created_gives_its_slot_back() {
        let ctx = Arc::new(
            ProxyCtx::new(
                Arc::new(Ca::ephemeral().unwrap()),
                allowlist::EgressPolicy::default(),
            )
            .unwrap(),
        );
        // Exactly what `spawn_connection` builds and hands over, minus the spawn the OS refused.
        ctx.conns.fetch_add(1, Ordering::Relaxed);
        let guard = ConnGuard(Arc::clone(&ctx));
        let never_ran = move || drop(guard);
        assert_eq!(
            ctx.conns.load(Ordering::Relaxed),
            1,
            "the slot is taken on the accept loop, before the thread exists"
        );
        drop(never_ran);
        assert_eq!(
            ctx.conns.load(Ordering::Relaxed),
            0,
            "and comes back with the closure that was never run"
        );

        // The slot a handler *does* take still comes back the ordinary way, so this cannot be
        // satisfied by a counter nothing increments. The peer is closed first, so the handler meets
        // EOF where it would read a head and returns at once.
        let (client, peer) = UnixStream::pair().unwrap();
        drop(peer);
        assert!(
            spawn_connection(&ctx, client),
            "the host gave a thread for one connection"
        );
        let deadline = Instant::now() + Duration::from_secs(10);
        while ctx.conns.load(Ordering::Relaxed) != 0 {
            assert!(
                Instant::now() < deadline,
                "the handler thread's slot was never released"
            );
            std::thread::sleep(Duration::from_millis(5));
        }
    }
}

/// Tests for the refusal sentences' own pieces, kept beside them rather than in [`tests`] because
/// what they assert is a property of the text a refusal prints, with no connection served.
#[cfg(test)]
mod suggestion_tests {
    use super::*;

    /// A `denied-default` body hands the agent a command to run, so that command has to admit the
    /// request it was printed for. A bare host is an `https://` rule on **443**: for a refusal on
    /// `:8443` the suggestion `sbx net allow api.test` wrote a rule that changed nothing observable
    /// — the retry was refused again, by the policy the user had just been told to fix.
    ///
    /// The assertion runs on the sentence [`PolicyRefusal::message`] actually prints, not on the
    /// token helper beside it: the defect was the refusal arm passing the bare host, so a test that
    /// only exercised the helper would pass with the bare host back in the body.
    #[test]
    fn a_denied_default_suggestion_admits_the_port_it_was_refused_on() {
        let ctx = ProxyCtx::new(
            Arc::new(Ca::ephemeral().unwrap()),
            allowlist::EgressPolicy::new(Vec::new(), Vec::new()),
        )
        .unwrap();

        for port in [443u16, 8443, 8080] {
            let body = PolicyRefusal::DeniedDefault.message(&ctx, "api.test", port, "GET");
            let token = suggested_rule(&body);
            let rule = allowlist::classify(token)
                .unwrap_or_else(|e| panic!("`sbx net allow {token}` must be a valid rule: {e}"));
            let policy = allowlist::EgressPolicy::new(vec![rule], Vec::new());
            assert!(
                matches!(
                    policy.explain("api.test", port, "/", "GET"),
                    Decision::AllowedBy(_)
                ),
                "`sbx net allow {token}` must admit the `api.test:{port}` it was suggested for"
            );
            // And it opens that port only — a suggestion that widened the host to every port would
            // admit the refused request while granting far more than the refusal was about.
            let other = if port == 443 { 8443 } else { 443 };
            assert!(
                matches!(
                    policy.explain("api.test", other, "/", "GET"),
                    Decision::DeniedDefault
                ),
                "`sbx net allow {token}` must not also open `api.test:{other}`"
            );
        }

        // The 443 shorthand must survive, or this test could be "satisfied" by pinning every
        // suggestion to `host:port` and making the common refusal uglier for nothing.
        assert_eq!(
            suggested_rule(&PolicyRefusal::DeniedDefault.message(&ctx, "api.test", 443, "GET")),
            "api.test"
        );
        assert_eq!(
            suggested_rule(&PolicyRefusal::DeniedDefault.message(&ctx, "api.test", 8443, "GET")),
            "api.test:8443"
        );
    }

    /// The cleartext plane's suggestion has to admit a *cleartext* refusal, which takes the scheme
    /// and the port both.
    ///
    /// `sbx net allow host` writes an `https`/443 rule, which opens nothing on the clear at all —
    /// the granted egress and the requested egress then have no port and no layer in common. Naming
    /// the scheme and dropping the port, which the cleartext refusal body did, is the same defect
    /// the inspected-TLS suggestion above was fixed for: an `http://` entry defaults to port 80, so
    /// a refusal on `:8080` was answered with a command that opens a port nothing asked for.
    #[test]
    fn a_cleartext_denied_default_suggestion_admits_the_scheme_and_the_port_it_was_refused_on() {
        for port in [80u16, 8080] {
            let token = rule_destination(super::super::control::Proto::Http, "api.test", port);
            let rule = allowlist::classify(&token)
                .unwrap_or_else(|e| panic!("`sbx net allow {token}` must be a valid rule: {e}"));
            let policy = allowlist::EgressPolicy::new(vec![rule], Vec::new());
            assert!(
                matches!(
                    policy.explain_clear("api.test", port, "/", "GET"),
                    Decision::AllowedBy(_)
                ),
                "`sbx net allow {token}` must open the cleartext `api.test:{port}` it was \
                 suggested for"
            );
            // And it opens the clear only — a suggestion that also handed out the inspected-TLS
            // lane would grant a layer the refusal was never about.
            assert!(
                matches!(
                    policy.explain("api.test", port, "/", "GET"),
                    Decision::DeniedDefault
                ),
                "`sbx net allow {token}` must not also open the inspected-TLS lane"
            );
        }
        // The two spellings, pinned side by side: the scheme is never dropped on the clear, and the
        // port is dropped only where it already is the scheme's own default.
        let clear = |port| rule_destination(super::super::control::Proto::Http, "api.test", port);
        assert_eq!(clear(80), "http://api.test");
        assert_eq!(clear(8080), "http://api.test:8080");
        let tls = |port| rule_destination(super::super::control::Proto::Https, "api.test", port);
        assert_eq!(tls(443), "api.test");
        assert_eq!(tls(8443), "api.test:8443");
    }

    /// The rule token a `denied-default` body offers: everything the printed `sbx net allow`
    /// command names, which is what a reader pastes back into a shell.
    fn suggested_rule(body: &str) -> &str {
        body.split_once("sbx net allow ")
            .unwrap_or_else(|| panic!("a denied-default body carries an allow suggestion: {body}"))
            .1
            .trim()
    }
}

#[cfg(test)]
mod tests;
