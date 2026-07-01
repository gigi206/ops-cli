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
//! This module is the cert machinery and the serve loop; [`super::egress`] wires it into a
//! launch (binding the socket into the cage, injecting the CA into the cage trust store,
//! supervising its lifetime under the network-allowlist posture).
//!
//! ## Refusal reasons
//!
//! Every refusal the proxy *itself* issues (as opposed to a genuine upstream response it relays
//! verbatim) carries an `X-Ops-Egress-Reason` header with a stable category token, plus a short
//! `text/plain` body repeating it — so the agent can tell an explicit policy refusal from an
//! unreachable host or a name that did not resolve, instead of an opaque status or a dropped
//! connection. The categories:
//!
//! | Status | `X-Ops-Egress-Reason` | Meaning |
//! |---|---|---|
//! | `403` | `denied-default`         | no allow rule matched the host / port / path |
//! | `403` | `denied-by-rule`         | a deny rule matched (the rule text is not disclosed) |
//! | `403` | `asked-denied`           | the `ask` posture parked the request and it was not allowed — deliberately conflating an explicit `ops net pending deny`, the ask timeout, and the pending-queue cap (all three mean "no egress" in Mode B) |
//! | `403` | `ssrf-blocked`           | the host resolved only to private / metadata addresses |
//! | `403` | `ip-literal`             | the CONNECT target was an IP literal on the inspected path (allow it raw with a `tcp://` rule) |
//! | `403` | `outbound-secret`        | the request head carried a configured secret value verbatim (leak refused) |
//! | `503` | `splice-cap`             | the concurrent raw (`tcp://`) tunnel cap was reached (retry when one closes) |
//! | `421` | `host-mismatch`          | the TLS SNI or `Host` header disagreed with the CONNECT target |
//! | `400` | `bad-request`            | the request was malformed or used ambiguous framing |
//! | `405` | `method-not-allowed`     | a non-CONNECT method (plain-HTTP egress is out of scope) |
//! | `502` | `dns-failure`            | DNS resolution failed for an allowed host |
//! | `502` | `upstream-unreachable`   | the host is allowed but the TCP connection failed |
//! | `502` | `upstream-cert-rejected` | the upstream TLS certificate failed validation (never downgraded) |
//!
//! A genuine upstream status (e.g. a `404`) is streamed back unchanged and carries no such
//! header — save that a reflected secret is masked out of it on the way back (see *Credential
//! injection* below), which never changes the status or the framing. Raw transport breakage — a
//! peer that closed early, an unparseable CONNECT, or a failure mid-response — closes the
//! connection with no status, there being no well-formed HTTP peer to answer. The category and body echo only what the agent already sent (its own host /
//! port) or a fixed token; they never disclose the injected credential, a host-side secret, or
//! the policy's internal rule text (for the deciding rule, `ops test net` is the host-side tool).
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

use std::collections::HashMap;
use std::fmt;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, TcpStream};
use std::os::unix::net::{UnixListener, UnixStream};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use rcgen::{
    BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, KeyPair,
    KeyUsagePurpose,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use rustls::{
    ClientConfig, ClientConnection, RootCertStore, ServerConfig, ServerConnection, StreamOwned,
};

use crate::allowlist::{self, Decision, EgressPolicy, L4Decision, Rule, RuleKind};

use super::egress_stats::{EgressStats, StatKind};

/// Install the `ring` crypto provider as the process default exactly once. With the default
/// crate features turned off there is no auto-installed provider, so every `ServerConfig`/
/// `ClientConfig` builder needs this to have run first. Idempotent and racing-safe.
fn ensure_provider() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        rustls::crypto::ring::default_provider()
            .install_default()
            .expect("install the ring crypto provider");
    });
}

/// An ephemeral certificate authority: a self-signed CA minted fresh for one proxy session,
/// used to sign per-host leaf certificates on demand. The private key lives only in memory and
/// is never written to the host; its certificate is trusted only inside the cage, so the
/// interception cannot be leveraged against the user's own (Mode-A) traffic.
pub(crate) struct Ca {
    /// The CA signing key — kept private; never serialized off-process.
    key: KeyPair,
    /// The CA certificate, the issuer for every minted leaf.
    cert: rcgen::Certificate,
    /// The CA certificate in DER, appended to each leaf's chain.
    cert_der: CertificateDer<'static>,
    /// The CA certificate in PEM, for injection into the cage trust store.
    cert_pem: String,
    /// Minted leaves, cached by host so a repeated connection reuses one certificate.
    leaves: Mutex<HashMap<String, Arc<CertifiedKey>>>,
}

// A manual `Debug` that never prints key material — and frees us from requiring `Debug` on the
// rcgen key/cert types. Needed because the resolver that holds a `Ca` must be `Debug`.
impl fmt::Debug for Ca {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Ca").finish_non_exhaustive()
    }
}

impl Ca {
    /// Mint a fresh ephemeral CA. The certificate carries the key usages a signing CA needs
    /// (`keyCertSign`); the private key stays in memory for the proxy's lifetime only.
    pub(crate) fn ephemeral() -> io::Result<Self> {
        ensure_provider();
        let key = KeyPair::generate().map_err(io::Error::other)?;
        let mut params = CertificateParams::new(Vec::new()).map_err(io::Error::other)?;
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        params
            .distinguished_name
            .push(DnType::CommonName, "ops egress proxy CA");
        let cert = params.self_signed(&key).map_err(io::Error::other)?;
        let cert_der = cert.der().clone();
        let cert_pem = cert.pem();
        Ok(Ca {
            key,
            cert,
            cert_der,
            cert_pem,
            leaves: Mutex::new(HashMap::new()),
        })
    }

    /// The CA certificate in PEM — what a launch injects into the cage's trust store so in-cage
    /// tools accept the minted leaves. The private key is deliberately not exposed.
    pub(crate) fn ca_cert_pem(&self) -> &str {
        &self.cert_pem
    }

    /// The CA certificate in DER, for adding to a rustls root store (a client that should trust
    /// the minted leaves anchors on this). The launch injects the PEM, not the DER; this serves
    /// the in-process tests that build a client trusting the proxy.
    #[cfg(test)]
    pub(crate) fn ca_cert_der(&self) -> CertificateDer<'static> {
        self.cert_der.clone()
    }

    /// A leaf certificate for `host`, minted on first use and cached thereafter. The returned
    /// [`CertifiedKey`] is what the TLS server hands the client for that host.
    pub(crate) fn leaf_for(&self, host: &str) -> io::Result<Arc<CertifiedKey>> {
        // The cache is the fast path; only a miss does the (relatively costly) keygen + signing.
        if let Some(ck) = self.leaves.lock().unwrap().get(host) {
            return Ok(ck.clone());
        }
        let ck = self.mint_leaf(host)?;
        self.leaves
            .lock()
            .unwrap()
            .insert(host.to_string(), ck.clone());
        Ok(ck)
    }

    /// Generate and CA-sign a leaf certificate for `host`, valid for TLS server authentication,
    /// and pair it with a rustls signing key.
    fn mint_leaf(&self, host: &str) -> io::Result<Arc<CertifiedKey>> {
        let leaf_key = KeyPair::generate().map_err(io::Error::other)?;
        let mut params =
            CertificateParams::new(vec![host.to_string()]).map_err(io::Error::other)?;
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        let leaf = params
            .signed_by(&leaf_key, &self.cert, &self.key)
            .map_err(io::Error::other)?;

        let leaf_der = leaf.der().clone();
        let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf_key.serialize_der()));
        let signing_key =
            rustls::crypto::ring::sign::any_supported_type(&key_der).map_err(io::Error::other)?;
        // Send the leaf with the CA appended; the client anchors on the CA, so either order of
        // trust resolves — including the CA is robust against clients that build the full chain.
        Ok(Arc::new(CertifiedKey::new(
            vec![leaf_der, self.cert_der.clone()],
            signing_key,
        )))
    }
}

/// A rustls server certificate resolver that mints (and caches) a leaf for whatever host the
/// client requests by SNI. A handshake with no SNI, or a minting failure, resolves to no
/// certificate, which aborts the handshake — fail-closed.
#[derive(Debug)]
pub(crate) struct CertResolver {
    ca: Arc<Ca>,
}

impl CertResolver {
    pub(crate) fn new(ca: Arc<Ca>) -> Self {
        Self { ca }
    }
}

impl ResolvesServerCert for CertResolver {
    fn resolve(&self, client_hello: ClientHello) -> Option<Arc<CertifiedKey>> {
        let host = client_hello.server_name()?;
        self.ca.leaf_for(host).ok()
    }
}

/// The shared client configuration the proxy uses for its own connections to real upstreams:
/// validate the server against the bundled root certificates (`webpki-roots`), so the
/// interception never weakens the transport — a forged or self-signed upstream is rejected
/// exactly as it would be without the proxy.
pub(crate) fn upstream_config() -> Arc<ClientConfig> {
    ensure_provider();
    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    Arc::new(
        ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth(),
    )
}

/// A static `ServerName` for a host string, for opening the proxy's upstream connection.
/// Shared by the serve loop and the tests so they build it identically.
pub(crate) fn upstream_server_name(host: &str) -> io::Result<ServerName<'static>> {
    ServerName::try_from(host.to_string())
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))
}

/// The hosts of the built-in self-equip allow-set, in allowlist-entry syntax. Sourced once so
/// the policy (`builtin_allow_rules`) and the `ops config` display can never drift.
///
/// All pinned to :443 (every one is HTTPS-only, so closing port 80 is pure least-privilege). The
/// whole set is scoped to `{GET,HEAD}`: substitution, channel and tarball fetches (incl. the
/// `github:`/`mise:github:` source and release downloads, which are GETs), raw content, and the
/// nixhub/mise version indexes are all read-only, so a write verb on this always-on lane serves no
/// self-equip purpose and is refused. A rare git-over-HTTPS push/clone that POSTs to
/// `git-upload-pack` is the user's to allow explicitly (`allow {*} github.com`). The explicit
/// `{GET,HEAD}` also makes every entry immune to a per-app `default_methods` rewrite (only an
/// `Unspecified`/no-prefix rule is rewritten), independent of resolution order. This bounds the
/// lane's verb semantics, not raw exfiltration (a GET query string still carries data out).
pub(crate) fn builtin_allow_hosts() -> &'static [&'static str] {
    &[
        "{GET,HEAD} cache.nixos.org:443",         // binary substitution
        "{GET,HEAD} *.nixos.org:443",             // channels / releases / tarballs
        "{GET,HEAD} github.com:443", // `github:NixOS/nixpkgs/<rev>` source (tarball fetch is GET)
        "{GET,HEAD} api.github.com:443", // the github tarball/redirect endpoint
        "{GET,HEAD} codeload.github.com:443", // the github archive download host
        "{GET,HEAD} *.githubusercontent.com:443", // raw content / release assets
        "{GET,HEAD} search.devbox.sh:443", // the nixhub metadata endpoint the nix resolver GETs
        "{GET,HEAD} mise-versions.jdx.dev:443", // mise's version index — the resolver any `mise:` backend GETs
    ]
}

/// The built-in egress always permitted so a project can self-equip its toolchain even when
/// untrusted: the nix binary cache, the nixpkgs source github fetches, the nixhub metadata
/// endpoint the nix resolver queries, and mise's version index. Both self-equip front-ends —
/// in-cage nix and the always-on `mise:` backends — run regardless of trust, so each front-end's
/// version-resolution host belongs here; the artifact hosts they download from (npm, the per-tool
/// release host) stay per-profile. Unioned into every policy regardless of trust (a user `deny`
/// can still carve it). The exact set is refined empirically against a real self-equip and is
/// shown in `ops config`, so it is never a silent allowance.
pub(crate) fn builtin_allow_rules() -> Vec<Rule> {
    builtin_allow_hosts()
        .iter()
        .map(|e| allowlist::classify(e).expect("a built-in self-equip entry must be a valid rule"))
        .collect()
}

/// Whether a resolved address is public, a private/internal range, or one that is refused
/// outright. The proxy runs on the host with full network reach, so an allowlisted *hostname*
/// (or a rebound DNS answer for it) resolving to an internal address would be an SSRF vector;
/// this classification is the post-resolution guard.
enum IpClass {
    /// A routable public address — reachable subject to the policy.
    Public,
    /// A loopback / RFC1918 / ULA / CGNAT address — reachable only when the policy explicitly
    /// named this exact host (an intentional internal target).
    Private,
    /// Link-local (incl. cloud metadata `169.254.169.254` / `fe80::/10`), multicast, or the
    /// unspecified address — never reachable, even if explicitly listed.
    Blocked,
}

fn classify_ip(ip: IpAddr) -> IpClass {
    match ip {
        IpAddr::V4(v4) => classify_v4(v4),
        // An IPv6 address that embeds a v4 (mapped, NAT64, 6to4, Teredo) is classified as that v4,
        // so an internal/metadata v4 cannot dodge the v4 guard wearing a v6 spelling (e.g.
        // `64:ff9b::a9fe:a9fe`, NAT64 of `169.254.169.254`).
        IpAddr::V6(v6) => match embedded_v4(v6) {
            Some(v4) => classify_v4(v4),
            None => classify_v6(v6),
        },
    }
}

/// The IPv4 address an IPv6 address embeds through a translation/transition form, or `None`.
/// Covers IPv4-mapped (`::ffff:a.b.c.d`), NAT64 well-known (`64:ff9b::/96`, the v4 in the low 32
/// bits), 6to4 (`2002:AABB:CCDD::/16`), and Teredo (`2001:0::/32`, the client v4 in the last two
/// segments, bit-inverted). The host's stack actually routing these is what makes the SSRF real;
/// classifying them by their embedded v4 keeps the metadata/internal guard sound where it does.
fn embedded_v4(v6: Ipv6Addr) -> Option<Ipv4Addr> {
    if let Some(v4) = v6.to_ipv4_mapped() {
        return Some(v4);
    }
    let s = v6.segments();
    let v4_of =
        |hi: u16, lo: u16| Ipv4Addr::new((hi >> 8) as u8, hi as u8, (lo >> 8) as u8, lo as u8);
    // NAT64 well-known prefix 64:ff9b::/96 — the v4 is the low 32 bits.
    if s[0] == 0x0064 && s[1] == 0xff9b && s[2..6] == [0, 0, 0, 0] {
        return Some(v4_of(s[6], s[7]));
    }
    // 6to4 2002::/16 — the v4 is segments 1 and 2.
    if s[0] == 0x2002 {
        return Some(v4_of(s[1], s[2]));
    }
    // Teredo 2001:0::/32 — the client v4 is the last two segments, bit-inverted.
    if s[0] == 0x2001 && s[1] == 0x0000 {
        return Some(v4_of(!s[6], !s[7]));
    }
    None
}

fn classify_v4(v4: Ipv4Addr) -> IpClass {
    // link-local covers the cloud metadata address 169.254.169.254
    if v4.is_link_local() || v4.is_unspecified() || v4.is_multicast() || v4.is_broadcast() {
        return IpClass::Blocked;
    }
    let o = v4.octets();
    // loopback, RFC1918, and the CGNAT shared range 100.64.0.0/10
    if v4.is_loopback() || v4.is_private() || (o[0] == 100 && (64..=127).contains(&o[1])) {
        return IpClass::Private;
    }
    IpClass::Public
}

fn classify_v6(v6: Ipv6Addr) -> IpClass {
    let s = v6.segments();
    // link-local fe80::/10, multicast ff00::/8, unspecified ::
    if v6.is_unspecified() || v6.is_multicast() || (s[0] & 0xffc0) == 0xfe80 {
        return IpClass::Blocked;
    }
    // loopback ::1 and unique-local fc00::/7
    if v6.is_loopback() || (s[0] & 0xfe00) == 0xfc00 {
        return IpClass::Private;
    }
    IpClass::Public
}

/// Whether the proxy may connect to `ip` for a request to `host` that the policy permitted via
/// `deciding`. Public addresses are reachable; a private address is reachable only when the
/// deciding rule named this exact host (a deliberate internal target — not a `*.domain`/regex/
/// built-in match, which would turn into an SSRF wildcard); a blocked address never is.
fn ip_permitted(ip: IpAddr, host: &str, deciding: Option<&Rule>) -> bool {
    match classify_ip(ip) {
        IpClass::Public => true,
        IpClass::Blocked => false,
        IpClass::Private => names_exact_host(host, deciding),
    }
}

/// Whether `deciding` is an explicit, exact-host rule for `host` (not a wildcard/regex). Used to
/// gate the private-IP exception. With no deciding rule — an allow-by-default verdict — the
/// exception never applies, so a private/loopback address is refused (a denylist opens public
/// egress, not the host's own internal services).
fn names_exact_host(host: &str, deciding: Option<&Rule>) -> bool {
    let Some(deciding) = deciding else {
        return false;
    };
    let h = allowlist::canonical_host(host);
    match &deciding.kind {
        RuleKind::Host(rh, _) => *rh == h,
        RuleKind::Url { host: rh, .. } => *rh == h,
        RuleKind::Ip(rip, _) => rip.to_string() == h,
        RuleKind::Subdomain(..) | RuleKind::Regex { .. } => false,
    }
}

/// A host name resolver, injectable so tests can map a name to a fixed address deterministically.
type Resolver = Box<dyn Fn(&str) -> io::Result<Vec<IpAddr>> + Send + Sync>;

fn default_resolve(host: &str) -> io::Result<Vec<IpAddr>> {
    use std::net::ToSocketAddrs;
    // the port is immaterial to name resolution; 443 is a placeholder so `to_socket_addrs` runs
    Ok((host, 443u16)
        .to_socket_addrs()?
        .map(|sa| sa.ip())
        .collect())
}

/// A resolved credential the proxy injects into requests matching its host/path rule. The
/// value is the **fully-formed header value** — the plaintext was read host-side and shaped
/// before this was built, so the proxy never touches the source. Injection happens only
/// after a request is ALLOWED, and only when `rule` matches the verified CONNECT host and the
/// decrypted path, so the secret reaches exactly one known destination.
pub(crate) struct HeaderInjection {
    /// The concrete host/path the secret is scoped to (an `Ip`/`Host`/`Url` rule).
    pub(crate) rule: Rule,
    /// The header name to set.
    pub(crate) header: String,
    /// The fully-formed header value (`prefix` + plaintext, or `Basic <base64>`).
    pub(crate) value: String,
}

// A manual `Debug` that redacts the value — the formed header carries the secret, so it must
// never reach a log or a panic message.
impl fmt::Debug for HeaderInjection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HeaderInjection")
            .field("rule", &self.rule)
            .field("header", &self.header)
            .field("value", &"<redacted>")
            .finish()
    }
}

/// A configured secret's value the proxy refuses to let leave the cage verbatim in an outbound
/// request head — the egress leak tripwire. Held as raw bytes so the byte-substring scan matches
/// whatever spelling reaches the wire (the plaintext, or its base64 form for Basic). Its `Debug`
/// is redacted so the value can never reach a log or a panic message.
pub(crate) struct SecretNeedle(Vec<u8>);

impl SecretNeedle {
    pub(crate) fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    /// The needle bytes — used by the scan, and by the egress tests to confirm a needle was
    /// derived. Deliberately a named method, never `Debug`, so it is only ever read explicitly.
    pub(crate) fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for SecretNeedle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SecretNeedle(<redacted {} bytes>)", self.0.len())
    }
}

/// The running context of the egress proxy: the cert machinery, the upstream-validation config,
/// the resolved (and built-in-augmented) policy, the resolver, the per-socket timeout, and the
/// host-side credential injections.
pub(crate) struct ProxyCtx {
    ca: Arc<Ca>,
    server_config: Arc<ServerConfig>,
    upstream: Arc<ClientConfig>,
    policy: EgressPolicy,
    resolve: Resolver,
    timeout: Duration,
    injections: Vec<HeaderInjection>,
    redactions: Vec<SecretNeedle>,
    /// The shared queue of parked `ask`-posture requests. Under `DefaultAction::Ask` an undecided
    /// request enqueues here and blocks; the control socket ([`super::control`]) answers it. A
    /// throwaway internal queue by default (so a non-ask launch never touches it); the launch
    /// injects the one the control thread also holds via [`Self::with_control`].
    pending: Arc<super::control::PendingState>,
    /// The live manual-rule overlay (`--session` answers). Consulted on the `ask` branch *before*
    /// parking, so a remembered host:port is decided without re-asking. A throwaway empty overlay by
    /// default; the launch injects the shared one via [`Self::with_control`].
    manual: Arc<super::control::ManualRules>,
    /// Whether to print a one-line stderr notice when a request parks, so an interactive user sees
    /// the pending id without polling. Off by default (tests, non-ask launches); the launch turns
    /// it on when it wires the control socket.
    notices: bool,
    /// The per-host decision counters this launch records (one outcome per request), or `None` when
    /// stats are off. The launch ([`super::egress::start`]) attaches the session's
    /// [`EgressStats`] via [`Self::with_stats`]; tests leave it unset.
    stats: Option<Arc<EgressStats>>,
    /// The live event ring this launch pushes each decision into, read by `ops net log`, or `None`
    /// when the log is off (tests). The launch ([`super::egress::start`]) attaches the session's
    /// [`super::control::LogRing`] via [`Self::with_log`]; a decision's outcome is both counted in
    /// `stats` and pushed here through the single [`Self::outcome`] chokepoint.
    log: Option<Arc<super::control::LogRing>>,
    /// The number of raw L4 (`tcp://`) splices currently open. Each splice holds a host thread (and
    /// its fds) for the connection's lifetime, so this caps how many an in-cage agent can open at
    /// once (see [`MAX_CONCURRENT_SPLICES`]); the inspected L7 path never touches it. Shared across
    /// connection threads through the [`Arc<ProxyCtx>`] the serve loop clones.
    splices: AtomicUsize,
}

impl ProxyCtx {
    /// Build the context from the session CA and the launch's resolved egress policy. The policy
    /// is augmented with the built-in self-equip allow-set (regardless of trust). The server
    /// config advertises no ALPN, so the client speaks HTTP/1.1 and every request is re-checked
    /// as its own CONNECT — nothing multiplexes past the filter.
    pub(crate) fn new(ca: Arc<Ca>, user_policy: EgressPolicy) -> io::Result<Self> {
        ensure_provider();
        let server_config = Arc::new(
            ServerConfig::builder()
                .with_no_client_auth()
                .with_cert_resolver(Arc::new(CertResolver::new(ca.clone()))),
        );
        Ok(ProxyCtx {
            ca,
            server_config,
            upstream: upstream_config(),
            policy: union_with_builtin(user_policy),
            resolve: Box::new(default_resolve),
            timeout: Duration::from_secs(30),
            injections: Vec::new(),
            redactions: Vec::new(),
            pending: Arc::new(super::control::PendingState::new()),
            manual: Arc::new(super::control::ManualRules::new()),
            notices: false,
            stats: None,
            log: None,
            splices: AtomicUsize::new(0),
        })
    }

    /// Attach the session's per-host decision counters, so each request's outcome is recorded.
    /// Set once by the launch ([`super::egress::start`]) when stats are enabled.
    pub(crate) fn with_stats(mut self, stats: Arc<EgressStats>) -> Self {
        self.stats = Some(stats);
        self
    }

    /// Attach the session's live event ring, so each request's decision is pushed for `ops net log`.
    /// Set once by the launch ([`super::egress::start`]) whenever the proxy runs.
    pub(crate) fn with_log(mut self, log: Arc<super::control::LogRing>) -> Self {
        self.log = Some(log);
        self
    }

    /// The single decision chokepoint every site in [`handle_client`] calls: it both counts the
    /// outcome for `ops net stats` and pushes one event for the live `ops net log`, so the two can
    /// never drift and a missed site is a missed *pair*, not a silent stats/log mismatch. `method`
    /// and `path` are the inspected request's (absent for an early-CONNECT block or a raw `tcp://`
    /// splice); `reason` is the same stable category token the adjacent refusal writes (or `allowed`
    /// for a permitted request). The path is query-redacted against the configured secret needles
    /// **before** it enters the ring, so even the outbound-secret-blocked event — whose query is
    /// exactly the one carrying a secret — is safe to hold in RAM.
    fn outcome(
        &self,
        host: &str,
        port: u16,
        method: Option<&str>,
        path: Option<&str>,
        kind: StatKind,
        reason: &str,
    ) -> Option<u64> {
        if let Some(stats) = &self.stats {
            stats.record(host, kind);
        }
        let verdict = match kind {
            StatKind::Allow => super::control::LogVerdict::Allow,
            StatKind::Deny => super::control::LogVerdict::Deny,
            StatKind::Blocked => super::control::LogVerdict::Blocked,
        };
        self.push_log(host, port, method, path, verdict, reason)
    }

    /// Push one event into the live log **without** touching the stat counters — for the outcomes the
    /// coarse stats taxonomy does not count but the diagnostic log should: a permitted request that
    /// failed downstream (`Error` — DNS/unreachable/cert) and a request ops declined before any
    /// verdict (`Blocked` — an IP-literal target or a malformed/smuggling request). Stats stay a
    /// pure allow/deny/blocked policy counter; the log is the richer record.
    fn push_log(
        &self,
        host: &str,
        port: u16,
        method: Option<&str>,
        path: Option<&str>,
        verdict: super::control::LogVerdict,
        reason: &str,
    ) -> Option<u64> {
        let log = self.log.as_ref()?;
        let redacted = path.map(|p| self.redact_query(p));
        Some(log.push(host, port, method, redacted.as_deref(), verdict, reason))
    }

    /// Amend the event `seq` (returned by a prior [`outcome`](Self::outcome)) with the upstream HTTP
    /// status its response returned. A clean no-op when no log is configured or no event was pushed
    /// (`seq` is `None`), or when the event has already been evicted from the ring.
    fn set_status(&self, seq: Option<u64>, status: u16) {
        if let (Some(log), Some(seq)) = (&self.log, seq) {
            log.set_status(seq, status);
        }
    }

    /// Mask any configured secret value occurring verbatim in `path` with an equal-length run of
    /// `*`, so a token that rode in a query string never enters the event ring in the clear. Reuses
    /// the same needle set and masking as the outbound/response redaction; `*` is ASCII and
    /// same-length, so the result stays valid UTF-8.
    fn redact_query(&self, path: &str) -> String {
        if self.redactions.is_empty() {
            return path.to_string();
        }
        let mut bytes = path.as_bytes().to_vec();
        redact_in_place(&mut bytes, &self.redactions);
        String::from_utf8_lossy(&bytes).into_owned()
    }

    /// Wire the proxy to the launch's shared pending queue and manual-rule overlay, and turn on the
    /// park notices unless the policy suppressed them (`[network] ask_notice = false`). The launch
    /// ([`super::egress::start`]) passes the same [`super::control::PendingState`] and
    /// [`super::control::ManualRules`] it serves on the control socket, so a request parked here is
    /// answerable by `ops net pending` and a `--session` answer it adds is honored here.
    pub(crate) fn with_control(
        mut self,
        pending: Arc<super::control::PendingState>,
        manual: Arc<super::control::ManualRules>,
    ) -> Self {
        self.pending = pending;
        self.manual = manual;
        self.notices = self.policy.ask_notice();
        self
    }

    /// Attach the resolved host-side credential injections. The proxy applies each to an
    /// allowed request whose host and path its `rule` matches, replacing any client-supplied
    /// copy of the header — so the cage never holds the plaintext yet the request still carries
    /// it. Set once by the launch ([`super::egress::start`]) after resolving the sources.
    pub(crate) fn with_injections(mut self, injections: Vec<HeaderInjection>) -> Self {
        self.injections = injections;
        self
    }

    /// Attach the outbound-redaction needles (the configured secrets' wire values). The proxy
    /// refuses any request whose decrypted head carries one verbatim, so a secret the agent
    /// obtained cannot be re-sent in the clear. Set by the launch ([`super::egress::start`])
    /// from the same resolved sources as the injections; the two never disagree.
    pub(crate) fn with_redactions(mut self, redactions: Vec<SecretNeedle>) -> Self {
        self.redactions = redactions;
        self
    }

    /// The CA certificate (PEM) a launch injects into the cage trust store so in-cage tools accept
    /// the minted leaves.
    pub(crate) fn ca_cert_pem(&self) -> &str {
        self.ca.ca_cert_pem()
    }
}

#[cfg(test)]
impl ProxyCtx {
    /// Replace the name resolver, so a test can map a host to a fixed address deterministically.
    fn with_resolver(mut self, resolve: Resolver) -> Self {
        self.resolve = resolve;
        self
    }

    /// Replace the upstream-validation config, so a test can trust a loopback upstream's own CA.
    fn with_upstream(mut self, upstream: Arc<ClientConfig>) -> Self {
        self.upstream = upstream;
        self
    }

    /// Wire the shared pending queue without turning on the stderr park notices, so a test can
    /// answer a parked request out of band while keeping the test output clean (unlike
    /// [`with_control`](ProxyCtx::with_control), which the launch uses and which prints notices).
    fn with_pending_silent(mut self, pending: Arc<super::control::PendingState>) -> Self {
        self.pending = pending;
        self
    }

    /// Wire the manual-rule overlay alone (notices off), so a test can pre-populate a remembered
    /// decision and assert the proxy honors it without ever parking.
    fn with_manual(mut self, manual: Arc<super::control::ManualRules>) -> Self {
        self.manual = manual;
        self
    }
}

/// Append the built-in self-equip allow rules to a policy's allow list (deny is unchanged, so a
/// user deny still wins over a built-in allow). The default action *and* the ask timeout are
/// carried through unchanged — rebuilding the policy must not silently demote an allow-by-default
/// (denylist) posture to deny-by-default, nor drop the configured ask timeout.
pub(crate) fn union_with_builtin(user: EgressPolicy) -> EgressPolicy {
    let mut allow = user.allow_rules().to_vec();
    allow.extend(builtin_allow_rules());
    EgressPolicy::new(allow, user.deny_rules().to_vec())
        .with_default(user.default_action())
        .with_ask_timeout(user.ask_timeout())
        .with_ask_notice(user.ask_notice())
}

/// Serve the egress proxy on `listener` (the host end of the cage's bound socket), one thread per
/// connection. Each accepted stream gets the per-socket timeouts before it is handled, so a slow
/// or hung peer cannot pin a thread forever.
pub(crate) fn serve(listener: UnixListener, ctx: Arc<ProxyCtx>) -> io::Result<()> {
    for stream in listener.incoming() {
        let stream = stream?;
        let ctx = ctx.clone();
        std::thread::spawn(move || {
            let _ = stream.set_read_timeout(Some(ctx.timeout));
            let _ = stream.set_write_timeout(Some(ctx.timeout));
            // an error on one connection is that connection's problem, never the proxy's
            let _ = handle_client(stream, &ctx);
        });
    }
    Ok(())
}

/// The largest request head (CONNECT or the decrypted inner request) the proxy will buffer.
const HEAD_MAX: usize = 16 * 1024;

/// The most `ask`-posture requests parked at once. A new one beyond this is denied immediately
/// (fail-closed) rather than enqueued, so an in-cage agent cannot pin unbounded host threads by
/// opening connections that all park — the default ask wait being indefinite. Far above any
/// realistic interactive backlog.
const ASK_PENDING_CAP: usize = 256;

/// Handle one client connection: parse the CONNECT, man-in-the-middle the tunnel, read exactly
/// one inner request, decide it against the policy (with the host/SNI/Host triple agreeing and
/// the SSRF guard applied to the resolved address), and — when permitted — forward it to the
/// validated upstream and stream the response back. Every failure path is fail-closed, and each
/// returns a [`write_refusal`] reason (an `X-Ops-Egress-Reason` category plus a text body) so the
/// agent can tell an explicit policy refusal from an unreachable host or a name that did not
/// resolve, instead of an opaque status or a dropped connection.
fn handle_client(mut client: UnixStream, ctx: &ProxyCtx) -> io::Result<()> {
    // 1. The CONNECT head, read byte-by-byte so the stream sits exactly at the TLS ClientHello
    //    (a buffered read would swallow the start of the handshake).
    let head = read_head_raw(&mut client, HEAD_MAX)?;
    let parsed = parse_head(&head)?;
    let Some((method, target)) = request_line_parts(&parsed.request_line) else {
        // A malformed request line carries no destination to attribute — log the attempt so it is
        // not dark, but with no host/method/path (the raw line may hold whitespace the wire format
        // cannot carry as a single field).
        ctx.push_log(
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
        // Plain-HTTP absolute-form egress (`GET http://host/…`) is out of scope for this slice;
        // refuse it fail-closed rather than letting it reach a default branch. It has no clean
        // host:port, but the method + raw target are exactly the "what is the agent trying to do"
        // signal, so log them (host blank, target as the path).
        ctx.push_log(
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
            "only CONNECT (HTTPS tunneling) is supported by this egress proxy",
        );
    }
    // 2. The CONNECT authority.
    let Some((host, port)) = split_authority(&target) else {
        // The authority is malformed (not host:port): log the raw target the agent asked for.
        ctx.push_log(
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
    if let L4Decision::Splice(rule) = ctx.policy.l4_decision(&connect_host, port) {
        return splice_l4(client, &connect_host, port, rule, ctx);
    }

    // An IP-literal target carries no SNI to bind the minted leaf to, so the inspected L7 path
    // refuses it (a hostname target is required to MITM; only the raw splice above accepts an IP).
    if host.parse::<IpAddr>().is_ok() {
        // Log the attempt (host = the IP the agent tried to reach) before refusing. Pre-tunnel, so
        // there is no method/path yet.
        ctx.push_log(
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

    // 3. Accept the tunnel, then terminate TLS with a leaf minted for the SNI host.
    write_all_str(&mut client, "HTTP/1.1 200 Connection established\r\n\r\n")?;
    let server_conn = ServerConnection::new(ctx.server_config.clone()).map_err(io::Error::other)?;
    let mut br = BufReader::new(StreamOwned::new(server_conn, client));

    // 4. Read ONE inner request (this drives the handshake to completion, so the SNI is known
    //    afterwards); keep the SAME buffered reader for the body.
    let inner_bytes = read_head_buffered(&mut br, HEAD_MAX)?;
    let sni = br.get_ref().conn.server_name().map(|s| s.to_string());

    // CONNECT-host == SNI: the leaf was minted for the SNI, so a CONNECT to a different host is a
    // domain-fronting attempt.
    if sni
        .as_deref()
        .map(|s| allowlist::canonical_host(s) != connect_host)
        .unwrap_or(true)
    {
        // Pre-parse: the inner request is not decoded yet, so there is no method/path to log.
        ctx.outcome(
            &connect_host,
            port,
            None,
            None,
            StatKind::Blocked,
            "host-mismatch",
        );
        return respond_refusal_tls(
            &mut br,
            "421 Misdirected Request",
            "host-mismatch",
            "the TLS SNI does not match the CONNECT target (possible domain-fronting)",
        );
    }

    let inner = parse_head(&inner_bytes)?;
    let Some((imethod, itarget)) = request_line_parts(&inner.request_line) else {
        ctx.push_log(
            &connect_host,
            port,
            None,
            None,
            super::control::LogVerdict::Blocked,
            "bad-request",
        );
        return respond_refusal_tls(
            &mut br,
            "400 Bad Request",
            "bad-request",
            "the tunneled request line is malformed",
        );
    };
    // The tunneled request must be origin-form (`/path`); an absolute-form target or `*` is
    // refused. The check is on the start, not a substring, so a URL inside the query
    // (`/login?next=https://…`) is not mistaken for absolute-form.
    if !itarget.starts_with('/') {
        ctx.push_log(
            &connect_host,
            port,
            Some(&imethod),
            Some(&itarget),
            super::control::LogVerdict::Blocked,
            "bad-request",
        );
        return respond_refusal_tls(
            &mut br,
            "400 Bad Request",
            "bad-request",
            "the tunneled request target must be origin-form (a path)",
        );
    }
    // Anti request-smuggling, fail-closed: a Transfer-Encoding at all (no chunked framing in this
    // slice), or a duplicated Content-Length / Host — each a classic request-desync vector.
    if inner.header("transfer-encoding").is_some()
        || inner.count("content-length") > 1
        || inner.count("host") > 1
    {
        ctx.push_log(
            &connect_host,
            port,
            Some(&imethod),
            Some(&itarget),
            super::control::LogVerdict::Blocked,
            "bad-request",
        );
        return respond_refusal_tls(
            &mut br,
            "400 Bad Request",
            "bad-request",
            "the request has ambiguous framing (Transfer-Encoding, or a duplicated \
             Content-Length or Host)",
        );
    }
    let body_len: u64 = match inner.header("content-length") {
        Some(v) => match v.trim().parse() {
            Ok(n) => n,
            Err(_) => {
                ctx.push_log(
                    &connect_host,
                    port,
                    Some(&imethod),
                    Some(&itarget),
                    super::control::LogVerdict::Blocked,
                    "bad-request",
                );
                return respond_refusal_tls(
                    &mut br,
                    "400 Bad Request",
                    "bad-request",
                    "the Content-Length header is not a valid number",
                );
            }
        },
        None => 0,
    };

    // CONNECT-host == Host header (== SNI, already checked): the decrypted Host must agree too.
    if inner
        .header("host")
        .map(|h| allowlist::canonical_host(&strip_port(h)) != connect_host)
        .unwrap_or(true)
    {
        ctx.outcome(
            &connect_host,
            port,
            Some(&imethod),
            Some(&itarget),
            StatKind::Blocked,
            "host-mismatch",
        );
        return respond_refusal_tls(
            &mut br,
            "421 Misdirected Request",
            "host-mismatch",
            "the Host header does not match the CONNECT target (possible domain-fronting)",
        );
    }

    // 4c. Outbound leak tripwire: if the decrypted client head carries a configured secret value
    //     verbatim, refuse the whole request — block, never strip (a partial strip gives false
    //     confidence). Scanned on the pre-injection client bytes, so ops's own injected credential
    //     can never trip it, and reached before the verdict so an exfil attempt never resolves a
    //     name or opens an upstream. A backstop against naive re-exfil only: it sees the head, not
    //     the streamed body, and matches the value byte-for-byte (any encoding evades it).
    if carries_secret(&inner_bytes, &ctx.redactions) {
        ctx.outcome(
            &connect_host,
            port,
            Some(&imethod),
            Some(&itarget),
            StatKind::Blocked,
            "outbound-secret",
        );
        return respond_refusal_tls(
            &mut br,
            "403 Forbidden",
            "outbound-secret",
            "the request carries a configured secret value (outbound credential leak refused)",
        );
    }

    // 5. The verdict — built through the SAME canonicalizer `ops test net` uses, so enforcement
    //    cannot drift from the tester's prediction. The two denial shapes get distinct reasons so
    //    the agent can tell "no rule allowed this" from "a deny rule blocked it".
    let deciding: Option<Rule> = match ctx.policy.explain(&connect_host, port, &itarget, &imethod) {
        Decision::AllowedBy(rule) => Some(rule.clone()),
        // Allow-by-default (denylist mode): no rule named this host, so there is no deciding
        // rule. The SSRF guard below then treats it as unnamed (private addresses refused).
        Decision::AllowedDefault => None,
        Decision::DeniedBy(_) => {
            ctx.outcome(
                &connect_host,
                port,
                Some(&imethod),
                Some(&itarget),
                StatKind::Deny,
                "denied-by-rule",
            );
            return respond_refusal_tls(
                &mut br,
                "403 Forbidden",
                "denied-by-rule",
                "this request matches a deny rule in the network policy",
            );
        }
        Decision::DeniedDefault => {
            // Distinguish "this host is allowed, but not for this verb" from "this host is not
            // allowed at all": if an allow rule matches the host/path but its method set excludes
            // the request's verb, say so, so the agent can tell a method-scoped deny apart. The
            // reason is decided *before* the outcome is recorded, so the log carries the precise
            // category (`denied-method`/`denied-default`), not a coarse one.
            let method_denied = ctx
                .policy
                .method_denied(&connect_host, port, &itarget, &imethod);
            let reason = if method_denied {
                "denied-method"
            } else {
                "denied-default"
            };
            ctx.outcome(
                &connect_host,
                port,
                Some(&imethod),
                Some(&itarget),
                StatKind::Deny,
                reason,
            );
            if method_denied {
                return respond_refusal_tls(
                    &mut br,
                    "403 Forbidden",
                    "denied-method",
                    &format!(
                        "the `{imethod}` method is not permitted to `{connect_host}:{port}` by \
                         the network policy"
                    ),
                );
            }
            return respond_refusal_tls(
                &mut br,
                "403 Forbidden",
                "denied-default",
                &format!("`{connect_host}:{port}` is not allowed by the network policy"),
            );
        }
        // Ask-by-default: no config rule decided. First consult the live manual overlay (decisions
        // a prior `--session` answer remembered) — a remembered allow/deny short-circuits the park,
        // so the same request is not asked twice. Only if nothing is remembered does the request
        // park and block until a host-side `ops net pending` answers it or the timeout elapses (deny
        // — fail-closed). An allow (remembered or fresh) names this exact host:port as the deciding
        // rule so the SSRF guard permits a deliberately-approved internal target.
        Decision::Ask => match ctx.manual.decide(&connect_host, port, &itarget) {
            Some(true) => Some(allowlist::host_port_rule(&connect_host, port)),
            Some(false) => {
                ctx.outcome(
                    &connect_host,
                    port,
                    Some(&imethod),
                    Some(&itarget),
                    StatKind::Deny,
                    "asked-denied",
                );
                return respond_refusal_tls(
                    &mut br,
                    "403 Forbidden",
                    "asked-denied",
                    "this host:port was denied by a live `ops net pending deny --session` \
                         decision",
                );
            }
            None => {
                let verdict = ctx.pending.park(
                    &connect_host,
                    port,
                    &itarget,
                    ctx.policy.ask_timeout(),
                    ASK_PENDING_CAP,
                    |seq| {
                        if ctx.notices {
                            let id = super::control::format_id(std::process::id(), seq);
                            // Paint the alert when stderr is a terminal (the canonical NO_COLOR / dumb
                            // / is-tty predicate, borrowed from the shared palette): `ops:` bold red
                            // (no underline), the rest of the alert red, and the two copy-paste
                            // commands yellow with a bold-yellow `allow`/`deny` label so the actions
                            // stand out.
                            let colored = !crate::style::Palette::for_stream(
                                std::io::IsTerminal::is_terminal(&std::io::stderr()),
                            )
                            .err
                            .is_empty();
                            let (ops, red, ylw, bylw, rst) = if colored {
                                (
                                    "\x1b[1;31m",
                                    "\x1b[31m",
                                    "\x1b[33m",
                                    "\x1b[1;33m",
                                    "\x1b[0m",
                                )
                            } else {
                                ("", "", "", "", "")
                            };
                            eprintln!(
                                "{ops}ops:{rst}{red} egress decision needed [{id}] \
                                 {connect_host}:{port}{itarget}{rst} — {bylw}allow{ylw}: ops net \
                                 pending allow {id}{rst}  |  {bylw}deny{ylw}: ops net pending deny \
                                 {id}{rst}"
                            );
                        }
                    },
                );
                match verdict {
                    super::control::Verdict::Allow => {
                        Some(allowlist::host_port_rule(&connect_host, port))
                    }
                    super::control::Verdict::Deny => {
                        ctx.outcome(
                            &connect_host,
                            port,
                            Some(&imethod),
                            Some(&itarget),
                            StatKind::Deny,
                            "asked-denied",
                        );
                        return respond_refusal_tls(
                            &mut br,
                            "403 Forbidden",
                            "asked-denied",
                            "this request was denied by a live decision or the ask timeout \
                                 elapsed",
                        );
                    }
                }
            }
        },
    };

    // 6. Resolve host-side, then the SSRF guard. A resolution failure for an allowed host is a
    //    clean 502 (not a dropped connection), so the agent sees "the name did not resolve"
    //    rather than an ambiguous transport error.
    let ips = match (ctx.resolve)(&connect_host) {
        Ok(ips) => ips,
        Err(_) => {
            // Allowed, but the name did not resolve: an `error`, not a refusal — the log's whole
            // point is that this reads differently from "we said no".
            ctx.push_log(
                &connect_host,
                port,
                Some(&imethod),
                Some(&itarget),
                super::control::LogVerdict::Error,
                "dns-failure",
            );
            return respond_refusal_tls(
                &mut br,
                "502 Bad Gateway",
                "dns-failure",
                &format!("DNS resolution failed for `{connect_host}`"),
            );
        }
    };
    let Some(ip) = ips
        .into_iter()
        .find(|ip| ip_permitted(*ip, &connect_host, deciding.as_ref()))
    else {
        ctx.outcome(
            &connect_host,
            port,
            Some(&imethod),
            Some(&itarget),
            StatKind::Blocked,
            "ssrf-blocked",
        );
        return respond_refusal_tls(
            &mut br,
            "403 Forbidden",
            "ssrf-blocked",
            &format!(
                "`{connect_host}` resolved only to disallowed addresses (a private or \
                 metadata range)"
            ),
        );
    };

    // 7. Connect to the address we just checked (not a re-resolve, which would reopen the
    //    rebinding window) and validate the upstream certificate up front; a forged or self-signed
    //    upstream is refused, never passed through. The two failure shapes get distinct reasons so
    //    "the host is down" reads differently from "its certificate was rejected".
    let mut upstream = match connect_upstream(ip, port, &connect_host, ctx) {
        Ok(u) => u,
        Err(UpstreamError::Unreachable) => {
            ctx.push_log(
                &connect_host,
                port,
                Some(&imethod),
                Some(&itarget),
                super::control::LogVerdict::Error,
                "upstream-unreachable",
            );
            return respond_refusal_tls(
                &mut br,
                "502 Bad Gateway",
                "upstream-unreachable",
                &format!("`{connect_host}` is allowed but could not be reached"),
            );
        }
        Err(UpstreamError::CertRejected) => {
            ctx.push_log(
                &connect_host,
                port,
                Some(&imethod),
                Some(&itarget),
                super::control::LogVerdict::Error,
                "upstream-cert-rejected",
            );
            return respond_refusal_tls(
                &mut br,
                "502 Bad Gateway",
                "upstream-cert-rejected",
                &format!(
                    "the TLS certificate presented by `{connect_host}` was rejected \
                     (upstream validation failed)"
                ),
            );
        }
    };

    // The request is permitted and the upstream is up — it will now egress. Record the one `allow`
    // outcome here (a single count per request: a refusal above already returned, and the steps
    // below are I/O, not policy verdicts, so this is the sole place a forwarded request is counted).
    let allow_seq = ctx.outcome(
        &connect_host,
        port,
        Some(&imethod),
        Some(&itarget),
        StatKind::Allow,
        "allowed",
    );

    // 8. Inject any matching host-scoped credentials. This runs *after* the verdict, so a
    //    denied request never receives a secret, and is keyed on the already-verified
    //    `connect_host` plus the decrypted path — so the credential reaches exactly the
    //    destination it was scoped to. A redirect to another host opens a new tunnel and
    //    re-runs this match, so the secret cannot ride along to an unintended host.
    let injected = matching_injections(ctx, &connect_host, port, &itarget);

    // 9. Forward this one request and stream the response back, then close — a pipelined second
    //    request is never forwarded, so it cannot skip the per-request check. The head is
    //    reserialized with `Connection: close` forced so a keep-alive upstream closes after the
    //    one response (otherwise there is no EOF and the read would block until the timeout).
    upstream.write_all(&reserialize_request(&inner, &injected))?;
    copy_exact(&mut br, &mut upstream, body_len)?;
    upstream.flush().ok();

    // 9b. Peek the response status line for the live log, best-effort. The bytes read here are NOT
    //     consumed — they are chained back ahead of the rest of the response, so the relay (and its
    //     redaction) still sees the whole stream unaltered. `set_status` amends the `allow` event
    //     pushed above; on an L4 splice, a refusal, or an error there is no such amend (no response).
    let prefix = read_status_prefix(&mut upstream);
    if let Some(code) = parse_status_code(&prefix) {
        ctx.set_status(allow_seq, code);
    }
    let mut response = io::Cursor::new(prefix).chain(&mut upstream);

    // 10. Response-side leak backstop: a configured secret can only re-enter the cage by being
    //     *reflected* by a host an injection targets (an echo/debug endpoint, or one that stores
    //     and later returns the credential). So mask the reflected value out of the response — but
    //     only for a response from such a host. Every other response (notably the large built-in
    //     downloads) is streamed untouched, which both avoids the scan cost and confines the
    //     mutate-on-match to the one host the reflection threat actually lives on.
    let masks_reflection = !ctx.redactions.is_empty()
        && ctx
            .injections
            .iter()
            .any(|inj| names_exact_host(&connect_host, Some(&inj.rule)));
    if masks_reflection {
        pump_redacting(&mut response, br.get_mut(), &ctx.redactions)?;
    } else {
        pump_to_eof(&mut response, br.get_mut())?;
    }
    Ok(())
}

/// Read the first bytes of an upstream response — up to and including the first `\n` (the status
/// line's terminator), a small cap, or the first read that returns nothing/errors — so the HTTP
/// status can be parsed for the live log. **Best-effort and non-consuming in effect:** the returned
/// bytes are chained back ahead of the rest of the response by the caller, so nothing is lost; a
/// partial read (a slow or silent upstream) simply yields no status rather than blocking a second
/// time (the caller's relay then surfaces the same condition as before this peek existed).
fn read_status_prefix<R: Read>(r: &mut R) -> Vec<u8> {
    // A status line is short; 512 bytes is ample and bounds a no-newline flood.
    const STATUS_LINE_MAX: usize = 512;
    let mut prefix = Vec::new();
    let mut buf = [0u8; 64];
    while prefix.len() < STATUS_LINE_MAX {
        match r.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                prefix.extend_from_slice(&buf[..n]);
                if prefix.contains(&b'\n') {
                    break;
                }
            }
            // Any read error/timeout: return what we have rather than blocking again — the caller's
            // relay re-hits the upstream and reports the condition as it would have without the peek.
            Err(_) => break,
        }
    }
    prefix
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

/// The most raw L4 (`tcp://`) splices open at once. Each one pins a host thread (and ~6 fds) for the
/// connection's lifetime — there is no per-request turnaround as on the inspected L7 path — so an
/// in-cage agent opening many would otherwise exhaust host threads. A new splice beyond this is
/// refused (a `503` `splice-cap`, pre-200, so the client sees a clean reason) rather than queued.
/// Generous for any realistic interactive use (SSH / database sessions), far below a thread bomb.
const MAX_CONCURRENT_SPLICES: usize = 128;

/// An RAII counter guard for the open-splice tally: it increments [`ProxyCtx::splices`] on
/// construction and decrements on drop, so every `splice_l4` exit (including the over-cap refusal and
/// every error path) releases its slot. [`Self::count`] reports the post-increment value, which the
/// caller checks against [`MAX_CONCURRENT_SPLICES`].
struct SpliceGuard<'a> {
    counter: &'a AtomicUsize,
    count: usize,
}

impl<'a> SpliceGuard<'a> {
    fn new(counter: &'a AtomicUsize) -> Self {
        let count = counter.fetch_add(1, Ordering::SeqCst) + 1;
        SpliceGuard { counter, count }
    }

    fn count(&self) -> usize {
        self.count
    }
}

impl Drop for SpliceGuard<'_> {
    fn drop(&mut self) {
        self.counter.fetch_sub(1, Ordering::SeqCst);
    }
}

/// Handle a raw L4 (`tcp://`) splice: a `tcp://` allow rule opted this host:port into an uninspected
/// tunnel ([`EgressPolicy::l4_decision`]). The connection keeps the controls a raw stream can carry —
/// the host:port allowlist (already matched), host-side DNS, the open-splice cap, and the SSRF guard
/// — but **loses** TLS termination, path/method matching, Host/SNI anti-fronting, and secret
/// redaction (there is no HTTP head to inspect). Failures before the tunnel is accepted are reported
/// as plain-HTTP refusals (the client is still speaking the CONNECT protocol); once `200` is sent the
/// bytes are raw and a mid-stream error simply tears the tunnel down.
fn splice_l4(
    mut client: UnixStream,
    connect_host: &str,
    port: u16,
    deciding: &Rule,
    ctx: &ProxyCtx,
) -> io::Result<()> {
    // Reserve a splice slot up front; the guard releases it on every return below.
    let guard = SpliceGuard::new(&ctx.splices);
    if guard.count() > MAX_CONCURRENT_SPLICES {
        // A raw splice has no HTTP head, so there is no method/path to log.
        ctx.outcome(
            connect_host,
            port,
            None,
            None,
            StatKind::Blocked,
            "splice-cap",
        );
        return write_refusal(
            &mut client,
            "503 Service Unavailable",
            "splice-cap",
            "too many concurrent raw (tcp://) tunnels are open; retry when one closes",
        );
    }

    // Resolve host-side. An IP-literal CONNECT target is allowed for a splice (it needs no SNI), so
    // it is used directly; a hostname is resolved, and a failure is a clean 502 (not a dropped
    // connection). Then the SSRF guard against the deciding rule — a private/metadata address is
    // refused unless the rule names this exact host.
    let ips = match connect_host.parse::<IpAddr>() {
        Ok(ip) => vec![ip],
        Err(_) => match (ctx.resolve)(connect_host) {
            Ok(ips) => ips,
            Err(_) => {
                ctx.push_log(
                    connect_host,
                    port,
                    None,
                    None,
                    super::control::LogVerdict::Error,
                    "dns-failure",
                );
                return write_refusal(
                    &mut client,
                    "502 Bad Gateway",
                    "dns-failure",
                    &format!("DNS resolution failed for `{connect_host}`"),
                );
            }
        },
    };
    let Some(ip) = ips
        .into_iter()
        .find(|ip| ip_permitted(*ip, connect_host, Some(deciding)))
    else {
        ctx.outcome(
            connect_host,
            port,
            None,
            None,
            StatKind::Blocked,
            "ssrf-blocked",
        );
        return write_refusal(
            &mut client,
            "403 Forbidden",
            "ssrf-blocked",
            &format!(
                "`{connect_host}` resolved only to disallowed addresses (a private or \
                 metadata range)"
            ),
        );
    };

    // Open the raw upstream to the checked address (no TLS, no certificate validation — a raw splice
    // is uninspected by design; the empty netns + the allowlist are the boundary).
    let upstream = match TcpStream::connect((ip, port)) {
        Ok(s) => s,
        Err(_) => {
            ctx.push_log(
                connect_host,
                port,
                None,
                None,
                super::control::LogVerdict::Error,
                "upstream-unreachable",
            );
            return write_refusal(
                &mut client,
                "502 Bad Gateway",
                "upstream-unreachable",
                &format!("`{connect_host}:{port}` is allowed but could not be reached"),
            );
        }
    };

    // Accept the tunnel — from here every byte is raw and uninspected.
    write_all_str(&mut client, "HTTP/1.1 200 Connection established\r\n\r\n")?;
    ctx.outcome(connect_host, port, None, None, StatKind::Allow, "allowed");
    splice_copy(client, upstream)
}

/// Splice a raw TCP tunnel: copy bytes both directions between the cage `client` and the `upstream`
/// until either side closes, then tear both down so neither copy thread can hang. The per-connection
/// read/write timeouts are cleared first, so an idle long-lived tunnel (an interactive SSH session,
/// say) is not killed mid-session. One direction runs in a spawned thread, the other in this thread;
/// when the first ends, both sockets are shut down fully so the other's blocked read returns and the
/// join always completes (no leaked host thread on a half-open or stalled peer).
fn splice_copy(client: UnixStream, upstream: TcpStream) -> io::Result<()> {
    // A raw tunnel may idle indefinitely between bursts, so drop the per-connection timeouts the
    // serve loop set (they exist to bound a slow HTTP head, not a long-lived stream). Set on the
    // originals before cloning, since the timeout is a socket-level option shared by the dups.
    let _ = client.set_read_timeout(None);
    let _ = client.set_write_timeout(None);
    let _ = upstream.set_read_timeout(None);
    let _ = upstream.set_write_timeout(None);

    // Two handles per socket (read + write), plus one each to force a full teardown after the first
    // direction ends. `try_clone` dups the fd, so every handle refers to the same socket.
    let mut client_wr = client.try_clone()?;
    let client_shut = client.try_clone()?;
    let mut client_rd = client;
    let mut up_rd = upstream.try_clone()?;
    let up_shut = upstream.try_clone()?;
    let mut up_wr = upstream;

    let t = std::thread::spawn(move || {
        let _ = io::copy(&mut client_rd, &mut up_wr);
        // client → upstream finished: half-close the upstream's write so it observes EOF.
        let _ = up_wr.shutdown(std::net::Shutdown::Write);
    });
    let _ = io::copy(&mut up_rd, &mut client_wr);
    // upstream → client finished: half-close the client's write, then force both sockets fully down
    // so the spawned thread's blocked read returns and the join below always completes.
    let _ = client_wr.shutdown(std::net::Shutdown::Write);
    let _ = client_shut.shutdown(std::net::Shutdown::Both);
    let _ = up_shut.shutdown(std::net::Shutdown::Both);
    let _ = t.join();
    Ok(())
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
    let name = upstream_server_name(host).map_err(|_| UpstreamError::CertRejected)?;
    let mut conn = ClientConnection::new(ctx.upstream.clone(), name)
        .map_err(|_| UpstreamError::CertRejected)?;
    let mut sock = sock;
    // drives + validates the TLS handshake now; a forged/self-signed upstream fails here
    conn.complete_io(&mut sock)
        .map_err(|_| UpstreamError::CertRejected)?;
    Ok(StreamOwned::new(conn, sock))
}

/// Read a request head byte-by-byte until the blank-line terminator, leaving the stream positioned
/// exactly after it (so the next bytes — a TLS ClientHello — are untouched). Bounded by `max`.
fn read_head_raw<R: Read>(r: &mut R, max: usize) -> io::Result<Vec<u8>> {
    let mut buf = Vec::new();
    let mut one = [0u8; 1];
    loop {
        if r.read(&mut one)? == 0 {
            return Err(invalid(
                "connection closed before the end of the request head",
            ));
        }
        buf.push(one[0]);
        if buf.ends_with(b"\r\n\r\n") {
            return Ok(buf);
        }
        if buf.len() > max {
            return Err(invalid("request head too large"));
        }
    }
}

/// Read a request head from a buffered reader line by line until the blank-line terminator. Any
/// bytes the reader buffered past the head (the body) stay in the reader for the caller to consume.
fn read_head_buffered<R: BufRead>(r: &mut R, max: usize) -> io::Result<Vec<u8>> {
    let mut buf = Vec::new();
    loop {
        let start = buf.len();
        // Cap each line at the remaining budget (+1 to detect overflow): a bare `read_until` would
        // buffer an arbitrarily long line with no terminator *before* the size check below runs, so
        // an in-cage client could force unbounded host-side allocation here (this proxy runs outside
        // the cage's cgroup). With the cap a no-`\n` flood hits the budget and errors.
        let budget = (max - start + 1) as u64;
        if (&mut *r).take(budget).read_until(b'\n', &mut buf)? == 0 {
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
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    /// How many headers carry this name (case-insensitive) — to catch a duplicated header.
    fn count(&self, name: &str) -> usize {
        self.headers
            .iter()
            .filter(|(k, _)| k.eq_ignore_ascii_case(name))
            .count()
    }
}

/// The credential injections (`header`, `value`) whose host/path rule matches this request,
/// canonicalized through the same matcher the verdict used. Borrowed from the context, so no
/// secret is copied beyond the forwarded head.
fn matching_injections<'a>(
    ctx: &'a ProxyCtx,
    host: &str,
    port: u16,
    target: &str,
) -> Vec<(&'a str, &'a str)> {
    ctx.injections
        .iter()
        .filter(|inj| allowlist::rule_matches(&inj.rule, host, port, target))
        .map(|inj| (inj.header.as_str(), inj.value.as_str()))
        .collect()
}

/// Whether the decrypted client request head carries any configured secret value verbatim — the
/// outbound leak tripwire. Scans the raw head bytes (request line + every client header, before
/// ops's own injection is added), so it can never self-trip on an injected credential. A backstop,
/// not a boundary: it catches a *verbatim* secret in the *head* only — an encoded value, or one in
/// the streamed body, is out of scope (see the module doc).
fn carries_secret(head_bytes: &[u8], redactions: &[SecretNeedle]) -> bool {
    redactions
        .iter()
        .any(|n| contains_subslice(head_bytes, n.as_bytes()))
}

/// Whether `needle` occurs as a contiguous byte run in `haystack`. An empty or over-long needle
/// never matches (the empty needle is screened out at resolution, but guard here too).
fn contains_subslice(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || needle.len() > haystack.len() {
        return false;
    }
    haystack.windows(needle.len()).any(|w| w == needle)
}

/// Reserialize a request head for forwarding upstream: keep the request line and headers, but
/// drop any client `Connection`/`Proxy-Connection` (the proxy owns hop-by-hop semantics) and
/// force `Connection: close`, so a keep-alive upstream closes after this one response — giving the
/// proxy a prompt EOF instead of a blocked read. One request per tunnel makes this safe.
///
/// Each `(header, value)` in `injections` is **strip-and-replace**d: every client-supplied copy of
/// that header — over all spellings (case- and `_`/`-`-insensitive, see [`header_name_eq`]) — is
/// dropped, then ops's value is appended. The agent in the cage is the adversary, so it must never
/// be able to leave its own copy of an injected header alongside ops's (which a permissive proxy
/// would forward as a second, attacker-controlled value).
fn reserialize_request(head: &Head, injections: &[(&str, &str)]) -> Vec<u8> {
    let mut out = String::with_capacity(head.request_line.len() + 64);
    out.push_str(&head.request_line);
    out.push_str("\r\n");
    for (k, v) in &head.headers {
        if k.eq_ignore_ascii_case("connection") || k.eq_ignore_ascii_case("proxy-connection") {
            continue;
        }
        // strip any client copy of a header ops is about to inject (all spellings), so the
        // injected value is the only one the upstream sees.
        if injections.iter().any(|(name, _)| header_name_eq(k, name)) {
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
    out.push_str("Connection: close\r\n\r\n");
    out.into_bytes()
}

/// Whether two header names denote the same header for stripping: case-insensitive, and
/// treating `_` and `-` as equivalent (some servers fold `X_API_KEY` onto `X-Api-Key`). So a
/// client cannot dodge the strip-and-replace with an alternate spelling of a header ops injects.
fn header_name_eq(a: &str, b: &str) -> bool {
    let norm = |s: &str| -> Vec<u8> {
        s.bytes()
            .map(|c| {
                if c == b'_' {
                    b'-'
                } else {
                    c.to_ascii_lowercase()
                }
            })
            .collect()
    };
    norm(a) == norm(b)
}

/// Parse a request head's bytes into its request line and headers. A non-UTF-8 or empty head is an
/// error.
fn parse_head(bytes: &[u8]) -> io::Result<Head> {
    let text = std::str::from_utf8(bytes).map_err(|_| invalid("non-UTF-8 request head"))?;
    let mut lines = text.split("\r\n").flat_map(|l| l.split('\n'));
    let request_line = lines.next().unwrap_or("").to_string();
    if request_line.is_empty() {
        return Err(invalid("empty request line"));
    }
    let mut headers = Vec::new();
    for line in lines {
        if line.is_empty() {
            break;
        }
        if let Some((k, v)) = line.split_once(':') {
            headers.push((k.trim().to_string(), v.trim().to_string()));
        }
    }
    Ok(Head {
        request_line,
        headers,
    })
}

/// The method and target of a request line, requiring all three space-separated tokens
/// (`METHOD target HTTP/x`).
fn request_line_parts(line: &str) -> Option<(String, String)> {
    let mut it = line.split_whitespace();
    let method = it.next()?.to_string();
    let target = it.next()?.to_string();
    it.next()?; // the HTTP-version token must be present
    Some((method, target))
}

/// Split a CONNECT authority `host:port` (port required) into its parts, handling a bracketed
/// IPv6 literal.
fn split_authority(authority: &str) -> Option<(String, u16)> {
    if let Some(rest) = authority.strip_prefix('[') {
        let (addr, tail) = rest.split_once(']')?;
        let port = tail.strip_prefix(':')?.parse().ok()?;
        return Some((addr.to_string(), port));
    }
    let (h, p) = authority.rsplit_once(':')?;
    Some((h.to_string(), p.parse().ok()?))
}

/// A `Host` header value with any `:port` removed (handling a bracketed IPv6 literal).
fn strip_port(authority: &str) -> String {
    if let Some(rest) = authority.strip_prefix('[') {
        if let Some((addr, _)) = rest.split_once(']') {
            return addr.to_string();
        }
    }
    match authority.rsplit_once(':') {
        Some((h, p)) if !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()) => h.to_string(),
        _ => authority.to_string(),
    }
}

/// Copy exactly `n` bytes from `r` to `w`; a short read is an error (a truncated body).
fn copy_exact<R: Read, W: Write>(r: &mut R, w: &mut W, mut n: u64) -> io::Result<()> {
    let mut buf = [0u8; 8192];
    while n > 0 {
        let want = n.min(buf.len() as u64) as usize;
        let got = r.read(&mut buf[..want])?;
        if got == 0 {
            return Err(invalid("request body shorter than Content-Length"));
        }
        w.write_all(&buf[..got])?;
        n -= got as u64;
    }
    Ok(())
}

/// Stream `r` to `w` until end of input. A peer that drops the TLS connection without a
/// `close_notify` surfaces as an unexpected EOF, which ends the stream normally rather than erroring.
fn pump_to_eof<R: Read, W: Write>(r: &mut R, w: &mut W) -> io::Result<()> {
    let mut buf = [0u8; 8192];
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
/// scan is over the raw bytes, so a secret reflected in either a response header or the body is
/// covered without parsing the response.
///
/// Streaming-safe: a `carry` of the last `max_needle_len - 1` bytes is retained across reads, so a
/// secret split across two reads is still caught — every emitted byte was scanned in a window that
/// held the next `max_needle_len - 1` bytes, and same-length replacement never shifts a position, so
/// re-scanning the carry is harmless. Memory stays bounded at `carry + one read`.
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
    let keep = max_len.saturating_sub(1);
    let mut carry: Vec<u8> = Vec::new();
    let mut buf = [0u8; 8192];
    loop {
        let n = match r.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => n,
            Err(ref e) if e.kind() == io::ErrorKind::UnexpectedEof => break,
            Err(e) => return Err(e),
        };
        let mut window = std::mem::take(&mut carry);
        window.extend_from_slice(&buf[..n]);
        redact_in_place(&mut window, needles);
        // Hold back the last `keep` bytes — a secret could begin there and complete in the next
        // read; emit everything before them.
        let split = window.len().saturating_sub(keep);
        w.write_all(&window[..split])?;
        carry = window[split..].to_vec();
    }
    // The trailing carry was already scanned in its final window (a needle cannot extend past EOF).
    w.write_all(&carry)?;
    w.flush().ok();
    Ok(())
}

/// Replace every occurrence of every needle in `buf` with an equal-length run of `*`, in place.
/// Equal length is the invariant the streaming framing relies on; an empty or over-long needle is
/// skipped (the empty needle is screened out at resolution, but guard here too).
fn redact_in_place(buf: &mut [u8], needles: &[SecretNeedle]) {
    for needle in needles {
        let n = needle.as_bytes();
        if n.is_empty() || n.len() > buf.len() {
            continue;
        }
        let mut i = 0;
        while i + n.len() <= buf.len() {
            if &buf[i..i + n.len()] == n {
                buf[i..i + n.len()].fill(b'*');
                i += n.len();
            } else {
                i += 1;
            }
        }
    }
}

/// Write an ops-originated refusal: the status line, an `X-Ops-Egress-Reason` header carrying a
/// stable machine-readable category, and a short `text/plain` body repeating the human detail.
/// A tool (and the agent it serves) can then tell an explicit policy refusal (`403`, category
/// `denied-default`/`denied-by-rule`) from an unreachable host (`502`, `upstream-unreachable`/
/// `dns-failure`) — these are the proxy's *own* statuses, distinct from a real upstream response
/// it relays verbatim (a genuine `404` reaches the agent unchanged). The category is a fixed
/// token, so it is safe in a header; the detail is ops-authored and only ever echoes what the
/// agent already sent (its own host/port) or a category — never the injected credential, any
/// host-side secret, or the policy's internal rule text (for which `ops test net` is the tool).
fn write_refusal<W: Write>(
    w: &mut W,
    status: &str,
    category: &str,
    detail: &str,
) -> io::Result<()> {
    let body = format!("ops egress refused this request: {detail}\n");
    write!(
        w,
        "HTTP/1.1 {status}\r\n\
         X-Ops-Egress-Reason: {category}\r\n\
         Content-Type: text/plain\r\n\
         Content-Length: {len}\r\n\
         Connection: close\r\n\r\n{body}",
        len = body.len(),
    )?;
    w.flush()
}

/// Write a literal string and flush — used for the cleartext `200 Connection established`.
fn write_all_str<W: Write>(w: &mut W, s: &str) -> io::Result<()> {
    w.write_all(s.as_bytes())?;
    w.flush()
}

/// Write a refusal to the client through the buffered TLS stream (the in-tunnel error paths,
/// after the CONNECT tunnel is established and TLS is terminated).
fn respond_refusal_tls<S: Read + Write>(
    br: &mut BufReader<StreamOwned<ServerConnection, S>>,
    status: &str,
    category: &str,
    detail: &str,
) -> io::Result<()> {
    write_refusal(br.get_mut(), status, category, detail)
}

/// An `InvalidData` error with a static cause, for the proxy's fail-closed paths.
fn invalid(msg: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::allowlist::{classify, DefaultAction};
    use crate::testutil::TmpDir;
    use std::io::{BufRead, BufReader, Read, Write};
    use std::net::{SocketAddr, TcpListener, TcpStream};
    use std::os::unix::net::{UnixListener, UnixStream};
    use std::thread;

    use rustls::{ClientConnection, ServerConfig, ServerConnection, StreamOwned};

    /// A policy allowing exactly the given entries (no deny), for the proxy tests.
    fn policy(entries: &[&str]) -> EgressPolicy {
        EgressPolicy::new(
            entries.iter().map(|e| classify(e).unwrap()).collect(),
            vec![],
        )
    }

    /// A one-shot loopback TLS "upstream": its own ephemeral CA mints a leaf for `host`; it accepts
    /// one connection, reads the request head, and replies with `response`. Returns its address,
    /// the CA the proxy must trust to validate it, and the join handle.
    fn spawn_upstream(
        host: &'static str,
        response: &'static [u8],
    ) -> (SocketAddr, CertificateDer<'static>, thread::JoinHandle<()>) {
        let ca = Arc::new(Ca::ephemeral().unwrap());
        let ca_der = ca.ca_cert_der();
        let server_config = Arc::new(
            ServerConfig::builder()
                .with_no_client_auth()
                .with_cert_resolver(Arc::new(CertResolver::new(ca))),
        );
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = thread::spawn(move || {
            // tolerate errors: a forged-upstream test makes the proxy's validation fail, which
            // aborts this side's handshake — that must not panic a detached thread.
            let Ok((sock, _)) = listener.accept() else {
                return;
            };
            let Ok(conn) = ServerConnection::new(server_config) else {
                return;
            };
            let mut tls = StreamOwned::new(conn, sock);
            let mut br = BufReader::new(&mut tls);
            let mut line = String::new();
            loop {
                line.clear();
                match br.read_line(&mut line) {
                    Ok(0) | Err(_) => return,
                    Ok(_) if line == "\r\n" || line == "\n" => break,
                    Ok(_) => {}
                }
            }
            let _ = tls.write_all(response);
            let _ = tls.flush();
        });
        let _ = host;
        (addr, ca_der, handle)
    }

    /// Like [`spawn_upstream`] but reports the request head it received over a channel, so a test
    /// can assert what the proxy actually forwarded (e.g. a forced `Connection: close`).
    fn spawn_upstream_capturing(
        response: &'static [u8],
    ) -> (
        SocketAddr,
        CertificateDer<'static>,
        std::sync::mpsc::Receiver<String>,
    ) {
        let ca = Arc::new(Ca::ephemeral().unwrap());
        let ca_der = ca.ca_cert_der();
        let server_config = Arc::new(
            ServerConfig::builder()
                .with_no_client_auth()
                .with_cert_resolver(Arc::new(CertResolver::new(ca))),
        );
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let (tx, rx) = std::sync::mpsc::channel();
        thread::spawn(move || {
            let Ok((sock, _)) = listener.accept() else {
                return;
            };
            let Ok(conn) = ServerConnection::new(server_config) else {
                return;
            };
            let mut tls = StreamOwned::new(conn, sock);
            let mut head = String::new();
            {
                let mut br = BufReader::new(&mut tls);
                let mut line = String::new();
                loop {
                    line.clear();
                    match br.read_line(&mut line) {
                        Ok(0) | Err(_) => break,
                        Ok(_) if line == "\r\n" || line == "\n" => break,
                        Ok(_) => head.push_str(&line),
                    }
                }
            }
            let _ = tx.send(head);
            let _ = tls.write_all(response);
            let _ = tls.flush();
        });
        (addr, ca_der, rx)
    }

    /// Drive one HTTPS request through the proxy over a freshly bound UDS, returning the decrypted
    /// response. The client trusts only `proxy_ca` (the proxy's interception CA).
    fn through_proxy(
        ctx: Arc<ProxyCtx>,
        proxy_ca: CertificateDer<'static>,
        connect_host: &str,
        sni_host: &str,
        connect_port: u16,
        request: &[u8],
    ) -> io::Result<String> {
        let dir = TmpDir::new();
        let path = dir.join("proxy.sock");
        let listener = UnixListener::bind(&path).unwrap();
        thread::spawn(move || {
            let _ = serve(listener, ctx);
        });

        let mut sock = UnixStream::connect(&path).unwrap();
        write!(
            sock,
            "CONNECT {connect_host}:{connect_port} HTTP/1.1\r\n\r\n"
        )
        .unwrap();
        sock.flush().unwrap();
        // read the cleartext CONNECT reply up to the blank line (nothing follows until we speak TLS)
        let established = read_until_blank(&mut sock)?;
        assert!(
            established.contains("200 Connection established"),
            "CONNECT not accepted: {established:?}"
        );

        let mut roots = RootCertStore::empty();
        roots.add(proxy_ca).unwrap();
        let client_config = ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        // the TLS SNI is sent independently of the CONNECT host, so a test can mismatch them
        let name = ServerName::try_from(sni_host.to_string()).unwrap();
        let conn =
            ClientConnection::new(Arc::new(client_config), name).map_err(io::Error::other)?;
        let mut tls = StreamOwned::new(conn, sock);
        tls.write_all(request)?;
        tls.flush().ok();
        let mut resp = String::new();
        // the proxy closes the tunnel after the one response, so read-to-end terminates
        match tls.read_to_string(&mut resp) {
            Ok(_) => {}
            Err(ref e) if e.kind() == io::ErrorKind::UnexpectedEof => {}
            Err(e) => return Err(e),
        }
        Ok(resp)
    }

    /// Read bytes until the `\r\n\r\n` blank-line terminator (cleartext CONNECT reply).
    fn read_until_blank(sock: &mut UnixStream) -> io::Result<String> {
        let mut buf = Vec::new();
        let mut one = [0u8; 1];
        loop {
            if sock.read(&mut one)? == 0 {
                break;
            }
            buf.push(one[0]);
            if buf.ends_with(b"\r\n\r\n") {
                break;
            }
        }
        Ok(String::from_utf8_lossy(&buf).into_owned())
    }

    #[test]
    fn ca_cert_is_a_pem_certificate_block() {
        let ca = Ca::ephemeral().unwrap();
        let pem = ca.ca_cert_pem();
        assert!(pem.starts_with("-----BEGIN CERTIFICATE-----"));
        assert!(pem.trim_end().ends_with("-----END CERTIFICATE-----"));
    }

    #[test]
    fn leaf_for_caches_per_host() {
        let ca = Ca::ephemeral().unwrap();
        let a1 = ca.leaf_for("example.com").unwrap();
        let a2 = ca.leaf_for("example.com").unwrap();
        let b = ca.leaf_for("other.com").unwrap();
        assert!(Arc::ptr_eq(&a1, &a2), "same host reuses one minted leaf");
        assert!(!Arc::ptr_eq(&a1, &b), "a different host gets its own leaf");
        assert!(
            !a1.cert.is_empty() && !b.cert.is_empty(),
            "each leaf carries a certificate chain"
        );
    }

    #[test]
    fn upstream_config_builds() {
        // Constructing it exercises the provider install and the root store load.
        let _ = upstream_config();
        assert!(upstream_server_name("cache.nixos.org").is_ok());
    }

    /// The productized spike: a client that trusts only the ephemeral CA completes a TLS
    /// handshake to a server whose certificate is minted on the fly by the [`CertResolver`]
    /// for the SNI host. This is the interception seam — if the resolver or the CA signing
    /// were wrong, the handshake would fail.
    #[test]
    fn a_client_trusting_the_ca_handshakes_through_the_resolver() {
        let ca = Arc::new(Ca::ephemeral().unwrap());
        let ca_der = ca.ca_cert_der();

        let server_config = ServerConfig::builder()
            .with_no_client_auth()
            .with_cert_resolver(Arc::new(CertResolver::new(ca.clone())));
        let server_config = Arc::new(server_config);

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let srv = thread::spawn(move || {
            let (sock, _) = listener.accept().unwrap();
            let conn = ServerConnection::new(server_config).unwrap();
            let mut tls = StreamOwned::new(conn, sock);
            let mut buf = [0u8; 64];
            let n = tls.read(&mut buf).unwrap();
            assert_eq!(&buf[..n], b"PING");
            tls.write_all(b"PONG").unwrap();
            tls.flush().ok();
        });

        let mut roots = RootCertStore::empty();
        roots.add(ca_der).unwrap();
        let client_config = ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        let name = ServerName::try_from("example.com").unwrap().to_owned();
        let sock = TcpStream::connect(addr).unwrap();
        let conn = ClientConnection::new(Arc::new(client_config), name).unwrap();
        let mut tls = StreamOwned::new(conn, sock);
        tls.write_all(b"PING").unwrap();
        tls.flush().ok();
        let mut resp = [0u8; 64];
        let n = tls.read(&mut resp).unwrap();
        assert_eq!(&resp[..n], b"PONG");
        srv.join().unwrap();
    }

    /// The happy path end to end: an allowed request is MITM'd, forwarded to a loopback upstream
    /// validated against its own CA, and the response is streamed back. Proves the byte plumbing
    /// across both read boundaries (CONNECT head → ClientHello, inner head → response body).
    #[test]
    fn an_allowed_request_is_proxied_to_a_validated_upstream() {
        let (addr, upstream_ca, up) = spawn_upstream(
            "upstream.test",
            b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello",
        );

        let proxy_ca = Arc::new(Ca::ephemeral().unwrap());
        let proxy_ca_der = proxy_ca.ca_cert_der();
        let mut roots = RootCertStore::empty();
        roots.add(upstream_ca).unwrap();
        let upstream_cfg = Arc::new(
            ClientConfig::builder()
                .with_root_certificates(roots)
                .with_no_client_auth(),
        );
        // allow the host on any port (the upstream's ephemeral port); resolve it to loopback —
        // permitted only because the deciding rule names this exact host (the explicit-internal case)
        let sdir = TmpDir::new();
        let stats = Arc::new(crate::sandbox::egress_stats::EgressStats::new(
            sdir.join("stats"),
            "/t".into(),
            None,
        ));
        let log = Arc::new(crate::sandbox::control::LogRing::new(
            crate::sandbox::control::LOG_RING_CAP,
        ));
        let ctx = Arc::new(
            ProxyCtx::new(proxy_ca, policy(&["upstream.test:*"]))
                .unwrap()
                .with_upstream(upstream_cfg)
                .with_stats(stats.clone())
                .with_log(log.clone())
                .with_resolver(Box::new(|_| Ok(vec![IpAddr::from([127, 0, 0, 1])]))),
        );

        let resp = through_proxy(
            ctx,
            proxy_ca_der,
            "upstream.test",
            "upstream.test",
            addr.port(),
            b"GET /path HTTP/1.1\r\nHost: upstream.test\r\nConnection: close\r\n\r\n",
        )
        .unwrap();
        up.join().unwrap();
        assert!(
            resp.contains("200 OK"),
            "no 200 from the upstream: {resp:?}"
        );
        assert!(
            resp.contains("hello"),
            "the body was not streamed back: {resp:?}"
        );
        // A forwarded request lands in the `allow` bucket (the one bucket counted only after the
        // upstream connects — the refusal buckets are pinned in `each_refusal_site_records_…`).
        assert_eq!(
            stats.snapshot()["upstream.test"].allow,
            1,
            "an egressed request must record one allow"
        );
        // …and the same forwarded request emits exactly one `allow` log event carrying its method
        // and path (the `allow` site the refusal-transcript test cannot reach).
        let events = log.snapshot(None).events;
        assert_eq!(events.len(), 1, "one allow event: {events:?}");
        assert_eq!(
            events[0].verdict,
            crate::sandbox::control::LogVerdict::Allow
        );
        assert_eq!(events[0].reason, "allowed");
        assert_eq!(events[0].host, "upstream.test");
        assert_eq!(events[0].method.as_deref(), Some("GET"));
        assert_eq!(events[0].path.as_deref(), Some("/path"));
    }

    #[test]
    fn parse_status_code_reads_a_well_formed_status_line_only() {
        // A normal status line → the code.
        assert_eq!(parse_status_code(b"HTTP/1.1 200 OK\r\n"), Some(200));
        assert_eq!(parse_status_code(b"HTTP/1.0 404 Not Found\r\n"), Some(404));
        assert_eq!(parse_status_code(b"HTTP/2 503 \r\n"), Some(503));
        // Only the first line is consulted, even when more of the head was read.
        assert_eq!(
            parse_status_code(b"HTTP/1.1 301 Moved\r\nLocation: /x\r\n"),
            Some(301)
        );
        // Not HTTP, no code, or an implausible code → None (records no status).
        assert_eq!(parse_status_code(b"garbage bytes\r\n"), None);
        assert_eq!(parse_status_code(b"HTTP/1.1 OK\r\n"), None);
        assert_eq!(parse_status_code(b"HTTP/1.1 999 X\r\n"), None);
        assert_eq!(parse_status_code(b""), None);
    }

    #[test]
    fn read_status_prefix_captures_the_status_line_and_loses_nothing() {
        // It reads until it has seen the first `\n` (a chunk may carry bytes past it — those are kept,
        // since the caller chains the whole prefix back ahead of the rest, so nothing is lost). The
        // status line is present, so the code parses; any trailing head bytes are harmless.
        let mut src = io::Cursor::new(b"HTTP/1.1 200 OK\r\nheader: v\r\n\r\nbody".to_vec());
        let prefix = read_status_prefix(&mut src);
        assert!(prefix.starts_with(b"HTTP/1.1 200 OK\r\n"), "{prefix:?}");
        assert_eq!(parse_status_code(&prefix), Some(200));
        // A stream cut before the code yields whatever it had (best-effort); with no code token there
        // is nothing to parse, so the event simply records none.
        let mut cut = io::Cursor::new(b"HTTP/1.".to_vec());
        let partial = read_status_prefix(&mut cut);
        assert_eq!(partial, b"HTTP/1.");
        assert_eq!(parse_status_code(&partial), None);
    }

    /// The live log captures the **upstream** HTTP status for a completed L7 request (the
    /// `--with-status` data). Teeth: two requests ops permits identically (both `allow`) reach two
    /// upstreams that differ ONLY in their response status — so a recorded 200 vs 404 can come only
    /// from reading the real response, never from ops's own verdict.
    #[test]
    fn an_allowed_request_records_the_upstream_status_code() {
        use crate::sandbox::control::{LogRing, LogVerdict, LOG_RING_CAP};
        let log = Arc::new(LogRing::new(LOG_RING_CAP));

        for response in [
            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nhi".as_slice(),
            b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".as_slice(),
        ] {
            let (addr, upstream_ca, up) = spawn_upstream("upstream.test", response);
            let proxy_ca = Arc::new(Ca::ephemeral().unwrap());
            let proxy_ca_der = proxy_ca.ca_cert_der();
            let mut roots = RootCertStore::empty();
            roots.add(upstream_ca).unwrap();
            let upstream_cfg = Arc::new(
                ClientConfig::builder()
                    .with_root_certificates(roots)
                    .with_no_client_auth(),
            );
            let ctx = Arc::new(
                ProxyCtx::new(proxy_ca, policy(&["upstream.test:*"]))
                    .unwrap()
                    .with_upstream(upstream_cfg)
                    .with_log(log.clone())
                    .with_resolver(Box::new(|_| Ok(vec![IpAddr::from([127, 0, 0, 1])]))),
            );
            let _ = through_proxy(
                ctx,
                proxy_ca_der,
                "upstream.test",
                "upstream.test",
                addr.port(),
                b"GET /p HTTP/1.1\r\nHost: upstream.test\r\nConnection: close\r\n\r\n",
            )
            .unwrap();
            up.join().unwrap();
        }

        let events = log.snapshot(None).events;
        assert_eq!(events.len(), 2, "one allow event per request: {events:?}");
        // Both are `allow` (ops permitted both); only the captured upstream status differs.
        assert!(events.iter().all(|e| e.verdict == LogVerdict::Allow));
        assert_eq!(
            events[0].status,
            Some(200),
            "the 200 upstream response is captured"
        );
        assert_eq!(
            events[1].status,
            Some(404),
            "the 404 is captured — distinct from ops's allow verdict"
        );
    }

    /// The status peek must not eat the response: a body larger than both the peek's first read and a
    /// pump chunk forces the relay to continue reading from `upstream` past the drained status-line
    /// cursor (the `Cursor::new(prefix).chain(upstream)` seam). Teeth: the whole body arrives
    /// byte-identical AND the status is still captured off the front of the same stream. A tiny-body
    /// test cannot see this — the entire response fits in the first peek read, so `upstream` is never
    /// touched.
    #[test]
    fn a_large_response_body_relays_intact_past_the_status_peek() {
        use crate::sandbox::control::{LogRing, LOG_RING_CAP};
        // 20 000 bytes > the 64-byte peek read AND the 8192-byte pump chunk, so the relay must read
        // from `upstream` well past the cursor. A leaked static slice satisfies `spawn_upstream`.
        let body = vec![b'x'; 20_000];
        let mut resp =
            format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n", body.len()).into_bytes();
        resp.extend_from_slice(&body);
        let resp: &'static [u8] = Box::leak(resp.into_boxed_slice());

        let (addr, upstream_ca, up) = spawn_upstream("upstream.test", resp);
        let proxy_ca = Arc::new(Ca::ephemeral().unwrap());
        let proxy_ca_der = proxy_ca.ca_cert_der();
        let mut roots = RootCertStore::empty();
        roots.add(upstream_ca).unwrap();
        let upstream_cfg = Arc::new(
            ClientConfig::builder()
                .with_root_certificates(roots)
                .with_no_client_auth(),
        );
        let log = Arc::new(LogRing::new(LOG_RING_CAP));
        let ctx = Arc::new(
            ProxyCtx::new(proxy_ca, policy(&["upstream.test:*"]))
                .unwrap()
                .with_upstream(upstream_cfg)
                .with_log(log.clone())
                .with_resolver(Box::new(|_| Ok(vec![IpAddr::from([127, 0, 0, 1])]))),
        );
        let got = through_proxy(
            ctx,
            proxy_ca_der,
            "upstream.test",
            "upstream.test",
            addr.port(),
            b"GET /p HTTP/1.1\r\nHost: upstream.test\r\nConnection: close\r\n\r\n",
        )
        .unwrap();
        up.join().unwrap();

        // The full 20k body survived the prefix→upstream chain, byte-identical.
        let sep = got
            .find("\r\n\r\n")
            .expect("the relayed response has a head/body separator");
        let relayed_body = &got[sep + 4..];
        assert_eq!(relayed_body.len(), 20_000, "the whole body relayed intact");
        assert!(
            relayed_body.bytes().all(|b| b == b'x'),
            "the body bytes are unaltered across the chain seam"
        );
        // …and the status was still read off the front of that same stream.
        assert_eq!(log.snapshot(None).events[0].status, Some(200));
    }

    /// The event log redacts a configured secret out of a request's path **before** it enters the
    /// ring — the outbound-secret block is the sharp case, since its query is exactly the one
    /// carrying the secret. So even in owner-only RAM the log never holds the raw credential.
    #[test]
    fn a_logged_path_has_its_secret_query_redacted_at_push() {
        use crate::sandbox::control::{LogRing, LogVerdict, LOG_RING_CAP};
        let ca = Arc::new(Ca::ephemeral().unwrap());
        let der = ca.ca_cert_der();
        let log = Arc::new(LogRing::new(LOG_RING_CAP));
        let ctx = Arc::new(
            ProxyCtx::new(ca, policy(&["host.test:*"]))
                .unwrap()
                .with_log(log.clone())
                .with_redactions(vec![SecretNeedle::new(b"s3cret-token-value".to_vec())])
                .with_resolver(Box::new(|_| {
                    panic!("resolve must not run on a secret leak")
                })),
        );
        let resp = through_proxy(
            ctx,
            der,
            "host.test",
            "host.test",
            8443,
            b"GET /v1/x?token=s3cret-token-value HTTP/1.1\r\nHost: host.test\r\n\r\n",
        )
        .unwrap();
        assert!(resp.contains("outbound-secret"), "{resp:?}");
        let events = log.snapshot(None).events;
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].verdict, LogVerdict::Blocked);
        assert_eq!(events[0].reason, "outbound-secret");
        let path = events[0].path.as_deref().unwrap();
        assert!(
            !path.contains("s3cret-token-value"),
            "the secret must be masked out of the logged path: {path:?}"
        );
        assert!(
            path.starts_with("/v1/x?token=") && path.contains('*'),
            "the path is kept but the secret run is masked: {path:?}"
        );
    }

    /// `with_control` turns the stderr park notices on, but honors a policy that silenced them
    /// (`[network] ask_notice = false`) — and the union with the built-in set must preserve that.
    #[test]
    fn with_control_honors_the_policy_ask_notice() {
        let pending = Arc::new(crate::sandbox::control::PendingState::new());
        let manual = Arc::new(crate::sandbox::control::ManualRules::new());

        // Default policy → the notice is on under `with_control`.
        let on = ProxyCtx::new(Arc::new(Ca::ephemeral().unwrap()), EgressPolicy::default())
            .unwrap()
            .with_control(pending.clone(), manual.clone());
        assert!(on.notices, "the park notice is on by default");

        // A policy that silenced the notice → off, surviving the built-in union in `new`.
        let off = ProxyCtx::new(
            Arc::new(Ca::ephemeral().unwrap()),
            EgressPolicy::default().with_ask_notice(false),
        )
        .unwrap()
        .with_control(pending, manual);
        assert!(
            !off.notices,
            "ask_notice = false suppresses the park notice"
        );
    }

    /// A request the policy does not allow is refused with 403 inside the tunnel, and the upstream
    /// is never contacted (the verdict is reached before any connect).
    #[test]
    fn a_denied_host_is_refused_with_403() {
        let proxy_ca = Arc::new(Ca::ephemeral().unwrap());
        let proxy_ca_der = proxy_ca.ca_cert_der();
        let ctx = Arc::new(
            ProxyCtx::new(proxy_ca, policy(&["allowed.test:*"]))
                .unwrap()
                .with_resolver(Box::new(|_| {
                    panic!("resolve must not run for a denied host")
                })),
        );
        let resp = through_proxy(
            ctx,
            proxy_ca_der,
            "denied.test",
            "denied.test",
            8443,
            b"GET / HTTP/1.1\r\nHost: denied.test\r\nConnection: close\r\n\r\n",
        )
        .unwrap();
        assert!(
            resp.contains("403"),
            "a denied host should get 403: {resp:?}"
        );
        assert!(
            resp.contains("denied-default"),
            "the refusal must name the motif (no allow rule matched): {resp:?}"
        );
    }

    #[test]
    fn classify_ip_unwraps_v6_embedded_v4_translation_forms() {
        let c = |s: &str| classify_ip(s.parse::<IpAddr>().unwrap());
        // NAT64 well-known of the metadata address 169.254.169.254 → blocked, not public
        assert!(matches!(c("64:ff9b::a9fe:a9fe"), IpClass::Blocked));
        // NAT64 of loopback → private
        assert!(matches!(c("64:ff9b::7f00:1"), IpClass::Private));
        // 6to4 of 10.0.0.1 (RFC1918) → private
        assert!(matches!(c("2002:0a00:0001::"), IpClass::Private));
        // Teredo carrying 169.254.169.254 (client v4 bit-inverted: !0xa9fe = 0x5601) → blocked
        assert!(matches!(c("2001:0:0:0:0:0:5601:5601"), IpClass::Blocked));
        // a genuine public v6 (no embedded v4) stays public
        assert!(matches!(c("2606:4700:4700::1111"), IpClass::Public));
        // the pre-existing v4-mapped case still folds to its v4 class
        assert!(matches!(c("::ffff:127.0.0.1"), IpClass::Private));
    }

    #[test]
    fn read_head_buffered_bounds_a_line_with_no_terminator() {
        // a single oversized line with no terminator must error (bounded), not buffer unboundedly
        let mut flood = std::io::Cursor::new(vec![b'a'; 64 * 1024]);
        let err = read_head_buffered(&mut flood, 16 * 1024).unwrap_err();
        assert!(err.to_string().contains("request head too large"), "{err}");
        // a normal head within the bound still parses
        let mut ok = std::io::Cursor::new(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n".to_vec());
        assert!(read_head_buffered(&mut ok, 16 * 1024).is_ok());
    }

    #[test]
    fn ambiguous_framing_is_refused_with_400_before_the_policy_check() {
        // Transfer-Encoding, or a duplicated Content-Length / Host, is a classic request-desync
        // vector — refused fail-closed at the proxy, before policy/resolve (the resolver panics if
        // reached, so the guard is proven to precede it).
        for req in [
            b"GET / HTTP/1.1\r\nHost: allowed.test\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n".to_vec(),
            b"GET / HTTP/1.1\r\nHost: allowed.test\r\nContent-Length: 0\r\nContent-Length: 5\r\nConnection: close\r\n\r\n".to_vec(),
            b"GET / HTTP/1.1\r\nHost: allowed.test\r\nHost: evil.test\r\nConnection: close\r\n\r\n".to_vec(),
        ] {
            let proxy_ca = Arc::new(Ca::ephemeral().unwrap());
            let proxy_ca_der = proxy_ca.ca_cert_der();
            let ctx = Arc::new(
                ProxyCtx::new(proxy_ca, policy(&["allowed.test:*"]))
                    .unwrap()
                    .with_resolver(Box::new(|_| {
                        panic!("resolve must not run for a framing refusal")
                    })),
            );
            let resp = through_proxy(
                ctx,
                proxy_ca_der,
                "allowed.test",
                "allowed.test",
                8443,
                &req,
            )
            .unwrap();
            assert!(
                resp.contains("400") && resp.contains("bad-request"),
                "expected a 400 bad-request framing refusal: {resp:?}"
            );
        }
    }

    /// Under the `ask` posture an undecided request parks; an out-of-band `allow` lets it proceed
    /// to the validated upstream. The allow synthesizes an exact-host deciding rule, so the loopback
    /// upstream passes the SSRF guard (the "I explicitly said yes to an internal host" case) — the
    /// parking path's teeth without a live cage.
    #[test]
    fn an_asked_request_proceeds_when_allowed() {
        use crate::sandbox::control::{PendingState, Verdict};
        let (addr, upstream_ca, up) = spawn_upstream(
            "ask.test",
            b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello",
        );
        let proxy_ca = Arc::new(Ca::ephemeral().unwrap());
        let proxy_ca_der = proxy_ca.ca_cert_der();
        let mut roots = RootCertStore::empty();
        roots.add(upstream_ca).unwrap();
        let upstream_cfg = Arc::new(
            ClientConfig::builder()
                .with_root_certificates(roots)
                .with_no_client_auth(),
        );
        let state = Arc::new(PendingState::new());
        let ctx = Arc::new(
            ProxyCtx::new(
                proxy_ca,
                EgressPolicy::default().with_default(DefaultAction::Ask),
            )
            .unwrap()
            .with_upstream(upstream_cfg)
            .with_resolver(Box::new(|_| Ok(vec![IpAddr::from([127, 0, 0, 1])])))
            .with_pending_silent(state.clone()),
        );
        // Answer `allow` as soon as the request parks.
        let answerer = {
            let state = state.clone();
            thread::spawn(move || answer_when_parked(&state, Verdict::Allow))
        };
        let resp = through_proxy(
            ctx,
            proxy_ca_der,
            "ask.test",
            "ask.test",
            addr.port(),
            b"GET / HTTP/1.1\r\nHost: ask.test\r\nConnection: close\r\n\r\n",
        )
        .unwrap();
        assert_eq!(answerer.join().unwrap().as_deref(), Some("ask.test"));
        up.join().unwrap();
        assert!(
            resp.contains("200 OK") && resp.contains("hello"),
            "an allowed ask must reach the upstream: {resp:?}"
        );
    }

    /// Under `ask`, an out-of-band `deny` refuses the parked request with 403 `asked-denied`, and
    /// the upstream is never contacted (the resolver panics if reached).
    #[test]
    fn an_asked_request_is_refused_when_denied() {
        use crate::sandbox::control::{PendingState, Verdict};
        let proxy_ca = Arc::new(Ca::ephemeral().unwrap());
        let proxy_ca_der = proxy_ca.ca_cert_der();
        let state = Arc::new(PendingState::new());
        let sdir = TmpDir::new();
        let stats = Arc::new(crate::sandbox::egress_stats::EgressStats::new(
            sdir.join("stats"),
            "/t".into(),
            None,
        ));
        let ctx = Arc::new(
            ProxyCtx::new(
                proxy_ca,
                EgressPolicy::default().with_default(DefaultAction::Ask),
            )
            .unwrap()
            .with_resolver(Box::new(|_| {
                panic!("resolve must not run for a denied ask")
            }))
            .with_stats(stats.clone())
            .with_pending_silent(state.clone()),
        );
        let answerer = {
            let state = state.clone();
            thread::spawn(move || answer_when_parked(&state, Verdict::Deny))
        };
        let resp = through_proxy(
            ctx,
            proxy_ca_der,
            "ask.test",
            "ask.test",
            8443,
            b"GET / HTTP/1.1\r\nHost: ask.test\r\nConnection: close\r\n\r\n",
        )
        .unwrap();
        answerer.join().unwrap();
        assert!(
            resp.contains("403") && resp.contains("asked-denied"),
            "a denied ask must get 403 asked-denied: {resp:?}"
        );
        // The parked-then-denied site records a deny (the sibling of the manual-deny site).
        assert_eq!(
            stats.snapshot()["ask.test"].deny,
            1,
            "a parked-and-denied request must record one deny"
        );
    }

    /// A live manual rule (from a prior `--session` answer) short-circuits the ask: a remembered
    /// allow lets the request proceed to the upstream **without parking** (no answerer thread — the
    /// default ask wait is indefinite, so if the overlay did not decide, this would hang forever and
    /// the test would time out), and a remembered deny refuses it. The 4b verdict path, cage-free.
    #[test]
    fn a_manual_rule_decides_an_ask_without_parking() {
        use crate::sandbox::control::{ManualRules, Verdict};

        // A remembered allow on the upstream's exact host:port → proceeds, never parks.
        let (addr, upstream_ca, up) = spawn_upstream(
            "ask.test",
            b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello",
        );
        let proxy_ca = Arc::new(Ca::ephemeral().unwrap());
        let proxy_ca_der = proxy_ca.ca_cert_der();
        let mut roots = RootCertStore::empty();
        roots.add(upstream_ca).unwrap();
        let upstream_cfg = Arc::new(
            ClientConfig::builder()
                .with_root_certificates(roots)
                .with_no_client_auth(),
        );
        let manual = Arc::new(ManualRules::new());
        manual.remember(Verdict::Allow, "ask.test", addr.port());
        let ctx = Arc::new(
            ProxyCtx::new(
                proxy_ca,
                EgressPolicy::default().with_default(DefaultAction::Ask),
            )
            .unwrap()
            .with_upstream(upstream_cfg)
            .with_resolver(Box::new(|_| Ok(vec![IpAddr::from([127, 0, 0, 1])])))
            .with_manual(manual),
        );
        let resp = through_proxy(
            ctx,
            proxy_ca_der,
            "ask.test",
            "ask.test",
            addr.port(),
            b"GET / HTTP/1.1\r\nHost: ask.test\r\nConnection: close\r\n\r\n",
        )
        .unwrap();
        up.join().unwrap();
        assert!(
            resp.contains("200 OK") && resp.contains("hello"),
            "a remembered allow must proceed without parking: {resp:?}"
        );

        // A remembered deny refuses without parking; the resolver panics if (wrongly) reached.
        let proxy_ca = Arc::new(Ca::ephemeral().unwrap());
        let proxy_ca_der = proxy_ca.ca_cert_der();
        let manual = Arc::new(ManualRules::new());
        manual.remember(Verdict::Deny, "blocked.test", 443);
        let ctx = Arc::new(
            ProxyCtx::new(
                proxy_ca,
                EgressPolicy::default().with_default(DefaultAction::Ask),
            )
            .unwrap()
            .with_resolver(Box::new(|_| {
                panic!("resolve must not run for a remembered deny")
            }))
            .with_manual(manual),
        );
        let resp = through_proxy(
            ctx,
            proxy_ca_der,
            "blocked.test",
            "blocked.test",
            443,
            b"GET / HTTP/1.1\r\nHost: blocked.test\r\nConnection: close\r\n\r\n",
        )
        .unwrap();
        assert!(
            resp.contains("403") && resp.contains("asked-denied"),
            "a remembered deny must 403 without parking: {resp:?}"
        );
    }

    /// Block until exactly one request is parked in `state`, answer it with `verdict`, and return
    /// the host it was for — so a test thread can answer a request the proxy thread just parked.
    fn answer_when_parked(
        state: &crate::sandbox::control::PendingState,
        verdict: crate::sandbox::control::Verdict,
    ) -> Option<String> {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        loop {
            if let Some(row) = state.list().first() {
                return state
                    .answer_like(row.seq, verdict)
                    .map(|(host, _port, _count)| host);
            }
            assert!(
                std::time::Instant::now() < deadline,
                "no request parked within the deadline"
            );
            thread::sleep(std::time::Duration::from_millis(5));
        }
    }

    /// The isolating teeth for the allow-by-default (denylist) mode. The test upstream is on
    /// loopback, which the SSRF guard refuses for any host no rule names — so the *new* behavior
    /// shows in the refusal *reason* on an identical unlisted request: under deny-by-default the
    /// verdict blocks it (`denied-default`), under allow-by-default the verdict passes it and only
    /// the SSRF guard stops it (`ssrf-blocked`). The reason is the proof the default action flipped
    /// the verdict. A deny rule still wins under allow-by-default. (An unlisted *public* host being
    /// reachable end-to-end is the live `tests/run.rs` smoke — it cannot be a loopback unit test.)
    #[test]
    fn allow_by_default_passes_the_verdict_while_deny_by_default_blocks_it() {
        // deny-by-default: an unlisted host is blocked AT the verdict — the resolver never runs.
        let deny_proxy_ca = Arc::new(Ca::ephemeral().unwrap());
        let deny_ca = deny_proxy_ca.ca_cert_der();
        let deny_ctx = Arc::new(
            ProxyCtx::new(deny_proxy_ca, EgressPolicy::default())
                .unwrap()
                .with_resolver(Box::new(|_| {
                    panic!("resolve must not run for a denied verdict")
                })),
        );
        let resp = through_proxy(
            deny_ctx,
            deny_ca,
            "unlisted.test",
            "unlisted.test",
            8443,
            b"GET / HTTP/1.1\r\nHost: unlisted.test\r\nConnection: close\r\n\r\n",
        )
        .unwrap();
        assert!(
            resp.contains("403") && resp.contains("denied-default"),
            "deny-by-default must block an unlisted host at the verdict: {resp:?}"
        );

        // allow-by-default: the SAME unlisted host passes the verdict (the resolver runs), and is
        // stopped only by the SSRF guard on the loopback address — a different reason.
        let allow_proxy_ca = Arc::new(Ca::ephemeral().unwrap());
        let allow_ca_der = allow_proxy_ca.ca_cert_der();
        let allow_ctx = Arc::new(
            ProxyCtx::new(
                allow_proxy_ca,
                EgressPolicy::default().with_default(DefaultAction::Allow),
            )
            .unwrap()
            .with_resolver(Box::new(|_| Ok(vec![IpAddr::from([127, 0, 0, 1])]))),
        );
        let resp = through_proxy(
            allow_ctx,
            allow_ca_der,
            "unlisted.test",
            "unlisted.test",
            8443,
            b"GET / HTTP/1.1\r\nHost: unlisted.test\r\nConnection: close\r\n\r\n",
        )
        .unwrap();
        assert!(
            resp.contains("403") && resp.contains("ssrf-blocked"),
            "allow-by-default must pass the verdict, then the SSRF guard stops the loopback: {resp:?}"
        );

        // deny still wins under allow-by-default: a denied host is blocked at the verdict.
        let denylist = EgressPolicy::new(vec![], vec![classify("evil.test:*").unwrap()])
            .with_default(DefaultAction::Allow);
        let evil_proxy_ca = Arc::new(Ca::ephemeral().unwrap());
        let evil_ca_der = evil_proxy_ca.ca_cert_der();
        let evil_ctx = Arc::new(
            ProxyCtx::new(evil_proxy_ca, denylist)
                .unwrap()
                .with_resolver(Box::new(|_| {
                    panic!("resolve must not run for a denied verdict")
                })),
        );
        let resp = through_proxy(
            evil_ctx,
            evil_ca_der,
            "evil.test",
            "evil.test",
            8443,
            b"GET / HTTP/1.1\r\nHost: evil.test\r\nConnection: close\r\n\r\n",
        )
        .unwrap();
        assert!(
            resp.contains("403") && resp.contains("denied-by-rule"),
            "a deny rule must still win under allow-by-default: {resp:?}"
        );
    }

    /// Because the proxy terminates TLS it sees the path: a deny carve-out wins over a host allow,
    /// so a denied path is refused even though the host is allowed.
    #[test]
    fn a_path_deny_wins_over_a_host_allow() {
        let proxy_ca = Arc::new(Ca::ephemeral().unwrap());
        let proxy_ca_der = proxy_ca.ca_cert_der();
        let policy = EgressPolicy::new(
            vec![classify("host.test:*").unwrap()],
            vec![classify("host.test:*/secret").unwrap()],
        );
        let ctx = Arc::new(
            ProxyCtx::new(proxy_ca, policy)
                .unwrap()
                .with_resolver(Box::new(|_| {
                    panic!("resolve must not run for a denied path")
                })),
        );
        let resp = through_proxy(
            ctx,
            proxy_ca_der,
            "host.test",
            "host.test",
            8443,
            b"GET /secret HTTP/1.1\r\nHost: host.test\r\nConnection: close\r\n\r\n",
        )
        .unwrap();
        assert!(
            resp.contains("403"),
            "a denied path should get 403: {resp:?}"
        );
        assert!(
            resp.contains("denied-by-rule"),
            "a deny-rule refusal must be distinguishable from a default deny: {resp:?}"
        );
    }

    /// The proxy decrypts the request, so it enforces the method: a verb outside a `{GET,HEAD}`
    /// allow is refused as `denied-method` (distinct from a host that is not allowed at all). The
    /// resolver panics if reached, so a pass would fail the test — proving the method is what blocks
    /// it (a method-blind proxy would match the host kind, resolve, and panic).
    #[test]
    fn a_method_outside_the_allow_set_is_refused_as_denied_method() {
        let proxy_ca = Arc::new(Ca::ephemeral().unwrap());
        let proxy_ca_der = proxy_ca.ca_cert_der();
        let policy = EgressPolicy::new(vec![classify("{GET,HEAD} host.test:*").unwrap()], vec![]);
        let ctx = Arc::new(
            ProxyCtx::new(proxy_ca, policy)
                .unwrap()
                .with_resolver(Box::new(|_| {
                    panic!("resolve must not run for a method-denied request")
                })),
        );
        let resp = through_proxy(
            ctx,
            proxy_ca_der,
            "host.test",
            "host.test",
            8443,
            b"POST /submit HTTP/1.1\r\nHost: host.test\r\nConnection: close\r\n\r\n",
        )
        .unwrap();
        assert!(
            resp.contains("403") && resp.contains("denied-method"),
            "a POST to a GET/HEAD-only host must be refused as denied-method: {resp:?}"
        );
    }

    /// The MITM must not downgrade transport: an upstream the proxy's root store does not trust is
    /// refused with 502, never passed through. The default upstream config (webpki-roots) does not
    /// trust the loopback upstream's own CA, so validation fails.
    #[test]
    fn a_forged_upstream_is_refused_with_502() {
        let (addr, _upstream_ca, _up) = spawn_upstream(
            "host.test",
            b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        );
        let proxy_ca = Arc::new(Ca::ephemeral().unwrap());
        let proxy_ca_der = proxy_ca.ca_cert_der();
        let log = Arc::new(crate::sandbox::control::LogRing::new(
            crate::sandbox::control::LOG_RING_CAP,
        ));
        // NOTE: no `.with_upstream(...)` — the default webpki-roots config will reject the upstream
        let ctx = Arc::new(
            ProxyCtx::new(proxy_ca, policy(&["host.test:*"]))
                .unwrap()
                .with_log(log.clone())
                .with_resolver(Box::new(|_| Ok(vec![IpAddr::from([127, 0, 0, 1])]))),
        );
        let resp = through_proxy(
            ctx,
            proxy_ca_der,
            "host.test",
            "host.test",
            addr.port(),
            b"GET / HTTP/1.1\r\nHost: host.test\r\nConnection: close\r\n\r\n",
        )
        .unwrap();
        assert!(
            resp.contains("502"),
            "an untrusted upstream must be refused, not downgraded: {resp:?}"
        );
        assert!(
            resp.contains("upstream-cert-rejected"),
            "a cert rejection must be distinguishable from an unreachable host: {resp:?}"
        );
        // Logged as an `error` (the host was allowed; its certificate failed downstream).
        let events = log.snapshot(None).events;
        assert_eq!(events.len(), 1, "one event: {events:?}");
        assert_eq!(
            events[0].verdict,
            crate::sandbox::control::LogVerdict::Error
        );
        assert_eq!(events[0].reason, "upstream-cert-rejected");
    }

    /// A name that does not resolve, for an *allowed* host, must be a clean 502 with a
    /// `dns-failure` reason — not a dropped connection (which the agent could not tell from a
    /// transport glitch). The host is on the allowlist, so the request passes the verdict and
    /// reaches the resolve step, where the injected resolver fails.
    #[test]
    fn a_dns_failure_for_an_allowed_host_is_a_clean_502_not_a_dropped_connection() {
        use crate::sandbox::control::{LogRing, LogVerdict, LOG_RING_CAP};
        let proxy_ca = Arc::new(Ca::ephemeral().unwrap());
        let proxy_ca_der = proxy_ca.ca_cert_der();
        let log = Arc::new(LogRing::new(LOG_RING_CAP));
        let ctx = Arc::new(
            ProxyCtx::new(proxy_ca, policy(&["allowed.test:*"]))
                .unwrap()
                .with_log(log.clone())
                .with_resolver(Box::new(|_| {
                    Err(io::Error::other("name resolution failed"))
                })),
        );
        let resp = through_proxy(
            ctx,
            proxy_ca_der,
            "allowed.test",
            "allowed.test",
            8443,
            b"GET /q HTTP/1.1\r\nHost: allowed.test\r\nConnection: close\r\n\r\n",
        )
        .unwrap();
        assert!(
            resp.contains("502") && resp.contains("dns-failure"),
            "a DNS failure for an allowed host must be a clean 502 naming the motif, \
             not a dropped connection: {resp:?}"
        );
        // The log records it as an `error` (allowed but failed downstream), NOT a `deny`/`blocked`
        // (we never refused it) — the distinction the log exists to make.
        let events = log.snapshot(None).events;
        assert_eq!(events.len(), 1, "one event: {events:?}");
        assert_eq!(events[0].verdict, LogVerdict::Error);
        assert_eq!(events[0].reason, "dns-failure");
        assert_eq!(events[0].host, "allowed.test");
        assert_eq!(events[0].path.as_deref(), Some("/q"));
    }

    /// CONNECT-host must equal the TLS SNI: a domain-fronting attempt (CONNECT one host, SNI
    /// another) is refused before any verdict or connect.
    #[test]
    fn a_connect_host_sni_mismatch_is_refused() {
        let proxy_ca = Arc::new(Ca::ephemeral().unwrap());
        let proxy_ca_der = proxy_ca.ca_cert_der();
        let ctx = Arc::new(
            ProxyCtx::new(proxy_ca, policy(&["allowed.test:*", "evil.test:*"]))
                .unwrap()
                .with_resolver(Box::new(|_| {
                    panic!("resolve must not run on a fronting attempt")
                })),
        );
        // CONNECT to allowed.test, but send SNI evil.test (both are allowed individually — the
        // mismatch itself is what must be rejected)
        let resp = through_proxy(
            ctx,
            proxy_ca_der,
            "allowed.test",
            "evil.test",
            8443,
            b"GET / HTTP/1.1\r\nHost: allowed.test\r\nConnection: close\r\n\r\n",
        )
        .unwrap();
        assert!(
            resp.contains("421"),
            "a CONNECT/SNI mismatch must be refused: {resp:?}"
        );
        assert!(
            resp.contains("host-mismatch"),
            "the refusal must name the domain-fronting motif: {resp:?}"
        );
    }

    /// The SSRF guard: a host that resolves to a private address is reachable only when the
    /// deciding rule names it exactly. A `*.domain` (wildcard) match resolving to loopback is
    /// blocked; a metadata address is blocked even for an exact-host rule.
    #[test]
    fn ssrf_guard_blocks_private_and_metadata_addresses() {
        // wildcard match → loopback → blocked
        let proxy_ca = Arc::new(Ca::ephemeral().unwrap());
        let proxy_ca_der = proxy_ca.ca_cert_der();
        let ctx = Arc::new(
            ProxyCtx::new(proxy_ca, policy(&["*.corp.test:*"]))
                .unwrap()
                .with_resolver(Box::new(|_| Ok(vec![IpAddr::from([127, 0, 0, 1])]))),
        );
        let resp = through_proxy(
            ctx,
            proxy_ca_der,
            "internal.corp.test",
            "internal.corp.test",
            8443,
            b"GET / HTTP/1.1\r\nHost: internal.corp.test\r\nConnection: close\r\n\r\n",
        )
        .unwrap();
        assert!(
            resp.contains("403") && resp.contains("ssrf-blocked"),
            "a wildcard-matched private target is an SSRF wildcard and must be blocked: {resp:?}"
        );

        // exact host, but the address is cloud metadata → blocked even though explicit
        let proxy_ca = Arc::new(Ca::ephemeral().unwrap());
        let proxy_ca_der = proxy_ca.ca_cert_der();
        let ctx = Arc::new(
            ProxyCtx::new(proxy_ca, policy(&["meta.test:*"]))
                .unwrap()
                .with_resolver(Box::new(|_| Ok(vec![IpAddr::from([169, 254, 169, 254])]))),
        );
        let resp = through_proxy(
            ctx,
            proxy_ca_der,
            "meta.test",
            "meta.test",
            8443,
            b"GET / HTTP/1.1\r\nHost: meta.test\r\nConnection: close\r\n\r\n",
        )
        .unwrap();
        assert!(
            resp.contains("403") && resp.contains("ssrf-blocked"),
            "the cloud-metadata address must be blocked even for an exact host: {resp:?}"
        );
    }

    /// The recorded invariant: the proxy's live verdict agrees with what `ops test net` predicts,
    /// because both go through the same `EgressPolicy::explain` on the same canonicalized request.
    #[test]
    fn proxy_verdict_matches_the_tester() {
        let p = EgressPolicy::new(
            vec![classify("host.test:*").unwrap()],
            vec![classify("host.test:*/secret").unwrap()],
        );
        // what `ops test net` would report (via parse_url_target + explain) for these URLs
        let denied = allowlist::parse_url_target("https://host.test:8443/secret").unwrap();
        assert!(
            !p.permits(&denied.0, denied.1, &denied.2),
            "tester predicts DENIED"
        );
        let allowed = allowlist::parse_url_target("https://host.test:8443/public").unwrap();
        assert!(
            p.permits(&allowed.0, allowed.1, &allowed.2),
            "tester predicts ALLOWED"
        );

        // the proxy must enforce the same: /secret refused, /public reaches the upstream
        let (addr, upstream_ca, up) = spawn_upstream(
            "host.test",
            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
        );
        let mut roots = RootCertStore::empty();
        roots.add(upstream_ca).unwrap();
        let upstream_cfg = Arc::new(
            ClientConfig::builder()
                .with_root_certificates(roots)
                .with_no_client_auth(),
        );
        let proxy_ca = Arc::new(Ca::ephemeral().unwrap());
        let proxy_ca_der = proxy_ca.ca_cert_der();
        let ctx = Arc::new(
            ProxyCtx::new(proxy_ca, p)
                .unwrap()
                .with_upstream(upstream_cfg)
                .with_resolver(Box::new(|_| Ok(vec![IpAddr::from([127, 0, 0, 1])]))),
        );

        let denied_resp = through_proxy(
            ctx.clone(),
            proxy_ca_der.clone(),
            "host.test",
            "host.test",
            addr.port(),
            b"GET /secret HTTP/1.1\r\nHost: host.test\r\nConnection: close\r\n\r\n",
        )
        .unwrap();
        assert!(
            denied_resp.contains("403"),
            "proxy must deny /secret: {denied_resp:?}"
        );

        let allowed_resp = through_proxy(
            ctx,
            proxy_ca_der,
            "host.test",
            "host.test",
            addr.port(),
            b"GET /public HTTP/1.1\r\nHost: host.test\r\nConnection: close\r\n\r\n",
        )
        .unwrap();
        up.join().unwrap();
        assert!(
            allowed_resp.contains("200"),
            "proxy must allow /public: {allowed_resp:?}"
        );
    }

    /// The built-in self-equip allow-set is unioned into every policy (even an empty one) so an
    /// untrusted project can still self-equip, and is well-formed.
    #[test]
    fn builtin_allow_set_is_unioned_regardless_of_trust() {
        let cache = builtin_allow_rules();
        assert!(!cache.is_empty());
        // unioning into an empty (untrusted) policy still permits the cache host
        let p = union_with_builtin(EgressPolicy::default());
        assert!(p.permits("cache.nixos.org", 443, "/nar/abc"));
        assert!(
            p.permits("channels.nixos.org", 443, "/"),
            "*.nixos.org covers channels"
        );
        // a host not in the cache set is still denied by default
        assert!(!p.permits("example.com", 443, "/"));
    }

    /// The proxy must force `Connection: close` on the request it forwards even when the client
    /// sent no `Connection` header — otherwise a keep-alive upstream never closes and the read
    /// blocks until the timeout. The capturing upstream reports the head it received.
    #[test]
    fn the_forwarded_request_forces_connection_close() {
        let (addr, upstream_ca, rx) = spawn_upstream_capturing(
            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
        );
        let mut roots = RootCertStore::empty();
        roots.add(upstream_ca).unwrap();
        let upstream_cfg = Arc::new(
            ClientConfig::builder()
                .with_root_certificates(roots)
                .with_no_client_auth(),
        );
        let proxy_ca = Arc::new(Ca::ephemeral().unwrap());
        let proxy_ca_der = proxy_ca.ca_cert_der();
        let ctx = Arc::new(
            ProxyCtx::new(proxy_ca, policy(&["host.test:*"]))
                .unwrap()
                .with_upstream(upstream_cfg)
                .with_resolver(Box::new(|_| Ok(vec![IpAddr::from([127, 0, 0, 1])]))),
        );
        // the client sends NO Connection header
        let resp = through_proxy(
            ctx,
            proxy_ca_der,
            "host.test",
            "host.test",
            addr.port(),
            b"GET / HTTP/1.1\r\nHost: host.test\r\n\r\n",
        )
        .unwrap();
        let upstream_head = rx
            .recv_timeout(Duration::from_secs(5))
            .expect("the upstream received a request");
        assert!(
            resp.contains("200"),
            "the response was not streamed back: {resp:?}"
        );
        assert!(
            upstream_head
                .to_ascii_lowercase()
                .contains("connection: close"),
            "the proxy must force Connection: close upstream: {upstream_head:?}"
        );
    }

    /// A target that carries a URL in its query (`/page?next=https://…`) is origin-form, not
    /// absolute-form, so it must be allowed — the absolute-form check is on the target's start.
    #[test]
    fn a_url_in_the_query_is_not_absolute_form() {
        let (addr, upstream_ca, up) = spawn_upstream(
            "host.test",
            b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        );
        let mut roots = RootCertStore::empty();
        roots.add(upstream_ca).unwrap();
        let upstream_cfg = Arc::new(
            ClientConfig::builder()
                .with_root_certificates(roots)
                .with_no_client_auth(),
        );
        let proxy_ca = Arc::new(Ca::ephemeral().unwrap());
        let proxy_ca_der = proxy_ca.ca_cert_der();
        let ctx = Arc::new(
            ProxyCtx::new(proxy_ca, policy(&["host.test:*"]))
                .unwrap()
                .with_upstream(upstream_cfg)
                .with_resolver(Box::new(|_| Ok(vec![IpAddr::from([127, 0, 0, 1])]))),
        );
        let resp = through_proxy(
            ctx,
            proxy_ca_der,
            "host.test",
            "host.test",
            addr.port(),
            b"GET /page?redirect=https://evil.test/x HTTP/1.1\r\nHost: host.test\r\n\r\n",
        )
        .unwrap();
        up.join().unwrap();
        assert!(
            resp.contains("200"),
            "a URL in the query must not be read as absolute-form: {resp:?}"
        );
    }

    /// A header injection scoped to `to` (in allowlist-entry syntax), setting `header` to `value`.
    fn injection(to: &str, header: &str, value: &str) -> HeaderInjection {
        HeaderInjection {
            rule: classify(to).unwrap(),
            header: header.to_string(),
            value: value.to_string(),
        }
    }

    /// Drive one request through a proxy that allows `allow` and carries `injections`, to a
    /// loopback capturing upstream. Returns the client-visible response and the request head the
    /// upstream received — so a test can assert exactly what was forwarded (which headers ops
    /// injected, and which client copies it stripped).
    fn run_with_injections(
        allow: &[&str],
        injections: Vec<HeaderInjection>,
        connect_host: &str,
        request: &[u8],
    ) -> (String, String) {
        let (addr, upstream_ca, rx) = spawn_upstream_capturing(
            b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        );
        let mut roots = RootCertStore::empty();
        roots.add(upstream_ca).unwrap();
        let upstream_cfg = Arc::new(
            ClientConfig::builder()
                .with_root_certificates(roots)
                .with_no_client_auth(),
        );
        let proxy_ca = Arc::new(Ca::ephemeral().unwrap());
        let proxy_ca_der = proxy_ca.ca_cert_der();
        let ctx = Arc::new(
            ProxyCtx::new(proxy_ca, policy(allow))
                .unwrap()
                .with_upstream(upstream_cfg)
                .with_resolver(Box::new(|_| Ok(vec![IpAddr::from([127, 0, 0, 1])])))
                .with_injections(injections),
        );
        let resp = through_proxy(
            ctx,
            proxy_ca_der,
            connect_host,
            connect_host,
            addr.port(),
            request,
        )
        .unwrap();
        let head = rx.recv_timeout(Duration::from_secs(5)).unwrap_or_default();
        (resp, head)
    }

    /// The headline: an allowed request to the scoped host gets ops's credential, and the
    /// agent's own copy of the same header is stripped — the injected value is the only one the
    /// upstream sees, even though the cage never held the secret.
    #[test]
    fn an_allowed_request_gets_the_injected_header_replacing_the_clients_copy() {
        let (resp, head) = run_with_injections(
            &["host.test:*"],
            vec![injection(
                "host.test:*",
                "Authorization",
                "Bearer ops-secret",
            )],
            "host.test",
            b"GET / HTTP/1.1\r\nHost: host.test\r\nauthorization: Bearer attacker\r\n\r\n",
        );
        assert!(resp.contains("200"), "the request was proxied: {resp:?}");
        let auth: Vec<&str> = head
            .lines()
            .filter(|l| l.to_ascii_lowercase().starts_with("authorization:"))
            .collect();
        assert_eq!(
            auth.len(),
            1,
            "exactly one Authorization header reaches the upstream: {head:?}"
        );
        assert!(
            auth[0].contains("ops-secret"),
            "ops's value must win: {head:?}"
        );
        assert!(
            !head.contains("attacker"),
            "the client's copy must be stripped: {head:?}"
        );
    }

    /// An injection is bound to its host: a request to a *different* allowed host never receives
    /// it, so a credential cannot ride along to an unintended destination.
    #[test]
    fn an_injection_is_scoped_to_its_host() {
        let (resp, head) = run_with_injections(
            &["secret.test:*", "other.test:*"],
            vec![injection(
                "secret.test:*",
                "Authorization",
                "Bearer ops-secret",
            )],
            "other.test",
            b"GET / HTTP/1.1\r\nHost: other.test\r\n\r\n",
        );
        assert!(resp.contains("200"));
        assert!(
            !head.to_ascii_lowercase().contains("authorization"),
            "a host outside the injection scope must get no credential: {head:?}"
        );
    }

    /// Because the proxy terminates TLS it can scope an injection by path: only the declared path
    /// receives the header, a sibling path on the same host does not.
    #[test]
    fn an_injection_can_be_scoped_to_a_path() {
        let injs = || {
            vec![injection(
                "host.test:*/api",
                "Authorization",
                "Bearer ops-secret",
            )]
        };
        let (resp, head) = run_with_injections(
            &["host.test:*"],
            injs(),
            "host.test",
            b"GET /api HTTP/1.1\r\nHost: host.test\r\n\r\n",
        );
        assert!(resp.contains("200"));
        assert!(
            head.to_ascii_lowercase()
                .contains("authorization: bearer ops-secret"),
            "the scoped path must be injected: {head:?}"
        );
        let (resp2, head2) = run_with_injections(
            &["host.test:*"],
            injs(),
            "host.test",
            b"GET /public HTTP/1.1\r\nHost: host.test\r\n\r\n",
        );
        assert!(resp2.contains("200"));
        assert!(
            !head2.to_ascii_lowercase().contains("authorization"),
            "a path outside the injection scope must get no credential: {head2:?}"
        );
    }

    #[test]
    fn header_name_eq_is_case_and_underscore_insensitive() {
        assert!(header_name_eq("Authorization", "authorization"));
        assert!(header_name_eq("X_API_KEY", "x-api-key"));
        assert!(header_name_eq("X-Api-Key", "x_api_key"));
        assert!(!header_name_eq("Authorization", "X-Auth"));
    }

    /// Strip-and-replace at the byte level: every spelling of an injected header (case, `_`/`-`,
    /// duplicates) is removed and ops's value appended exactly once, while unrelated headers and
    /// the forced `Connection: close` survive.
    #[test]
    fn reserialize_strips_all_spellings_of_an_injected_header() {
        let head = parse_head(
            b"GET / HTTP/1.1\r\nHost: h.test\r\nAuthorization: client\r\nAUTHORIZATION: dup\r\n\
              x_api_key: sneaky\r\nAccept: text/html\r\n\r\n",
        )
        .unwrap();
        let out = reserialize_request(
            &head,
            &[("Authorization", "Bearer ops"), ("X-Api-Key", "K")],
        );
        let s = String::from_utf8(out).unwrap();
        assert_eq!(
            s.matches("Authorization: Bearer ops").count(),
            1,
            "ops's Authorization appears exactly once: {s:?}"
        );
        assert!(s.contains("X-Api-Key: K"));
        assert!(
            !s.contains("client") && !s.contains("dup") && !s.contains("sneaky"),
            "every client spelling of an injected header is stripped: {s:?}"
        );
        assert!(
            s.contains("Accept: text/html"),
            "an unrelated header survives"
        );
        assert!(
            s.contains("Connection: close"),
            "Connection: close is forced"
        );
    }

    #[test]
    fn contains_subslice_matches_a_byte_run() {
        assert!(contains_subslice(b"hello world", b"o wo"));
        assert!(contains_subslice(b"abc", b"abc"));
        assert!(
            !contains_subslice(b"abc", b"abcd"),
            "needle longer than haystack"
        );
        assert!(
            !contains_subslice(b"abc", b""),
            "an empty needle never matches"
        );
        assert!(!contains_subslice(b"hello", b"xyz"));
    }

    #[test]
    fn secret_needle_debug_is_redacted() {
        let n = SecretNeedle::new(b"topsecretvalue".to_vec());
        let d = format!("{n:?}");
        assert!(
            !d.contains("topsecretvalue"),
            "the needle value must never appear in Debug: {d}"
        );
        assert!(d.contains("redacted"), "Debug should mark it redacted: {d}");
    }

    /// Drive one request through a proxy that allows `allow` and redacts `needles`, with a resolver
    /// that must NOT run — an outbound-secret refusal fires before any verdict, resolve, or connect.
    fn run_with_redactions(allow: &[&str], needles: &[&str], request: &[u8]) -> String {
        let proxy_ca = Arc::new(Ca::ephemeral().unwrap());
        let proxy_ca_der = proxy_ca.ca_cert_der();
        let ctx = Arc::new(
            ProxyCtx::new(proxy_ca, policy(allow))
                .unwrap()
                .with_resolver(Box::new(|_| {
                    panic!("an exfil attempt must be refused before any resolve/connect")
                }))
                .with_redactions(
                    needles
                        .iter()
                        .map(|n| SecretNeedle::new(n.as_bytes().to_vec()))
                        .collect(),
                ),
        );
        through_proxy(ctx, proxy_ca_der, "host.test", "host.test", 8443, request).unwrap()
    }

    /// A secret value echoed back into an outbound *header* is refused (block, not strip), and the
    /// upstream is never contacted (the resolver panics if reached).
    #[test]
    fn an_outbound_secret_in_a_header_is_refused() {
        let resp = run_with_redactions(
            &["host.test:*"],
            &["s3cret-reflected-value"],
            b"GET / HTTP/1.1\r\nHost: host.test\r\nX-Leak: s3cret-reflected-value\r\n\r\n",
        );
        assert!(
            resp.contains("403") && resp.contains("outbound-secret"),
            "a secret in an outbound header must be refused: {resp:?}"
        );
    }

    /// A secret value smuggled into the request *URL* (query) is caught too — the scan covers the
    /// whole head, request line included.
    #[test]
    fn an_outbound_secret_in_the_url_is_refused() {
        let resp = run_with_redactions(
            &["host.test:*"],
            &["s3cret-reflected-value"],
            b"GET /steal?x=s3cret-reflected-value HTTP/1.1\r\nHost: host.test\r\n\r\n",
        );
        assert!(
            resp.contains("403") && resp.contains("outbound-secret"),
            "a secret in the request URL must be refused: {resp:?}"
        );
    }

    /// The stats classification: each refusal site records exactly the bucket its column means —
    /// `deny` for a rule / `ask` decision, `blocked` for a security guard. A mis-bucketed guard (an
    /// SSRF counted as a deny, say) would pass every other green test, so each of the seven refusal
    /// sites is pinned here. The `allow` site (counted only after a real upstream connects) is pinned
    /// in the happy-path test and the live allowlist e2e. The counter is keyed on the CONNECT host.
    #[test]
    fn each_refusal_site_records_its_stat_bucket_and_emits_a_log_event() {
        use crate::allowlist::DefaultAction;
        use crate::sandbox::control::{LogRing, LogVerdict, ManualRules, Verdict, LOG_RING_CAP};
        use crate::sandbox::egress_stats::{Counts, EgressStats};

        let dir = TmpDir::new();
        // One shared event ring across every block: because `outcome` folds the stat and the log
        // push into one call, proving each site records the right *bucket* AND emits the right
        // *event* proves the two can never drift — a missed site is a missed pair. The blocks run
        // sequentially, so the ring's events are a deterministic, ordered transcript asserted at the
        // end.
        let log = Arc::new(LogRing::new(LOG_RING_CAP));
        let seq = std::sync::atomic::AtomicU32::new(0);
        let fresh = || {
            let i = seq.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            // The file lives in the temp dir; the assertions read the in-memory snapshot.
            Arc::new(EgressStats::new(
                dir.join(&format!("stats-{i}")),
                "/t".into(),
                None,
            ))
        };
        // The recorded count for `host` (a missing host is the zero counts).
        let count =
            |s: &Arc<EgressStats>, host: &str| s.snapshot().get(host).copied().unwrap_or_default();

        // denied-default → deny. No allow rule matches; the resolver must never run.
        {
            let s = fresh();
            let ca = Arc::new(Ca::ephemeral().unwrap());
            let der = ca.ca_cert_der();
            let ctx = Arc::new(
                ProxyCtx::new(ca, policy(&["allowed.test:*"]))
                    .unwrap()
                    .with_stats(s.clone())
                    .with_log(log.clone())
                    .with_resolver(Box::new(|_| {
                        panic!("resolve must not run for a denied host")
                    })),
            );
            let resp = through_proxy(
                ctx,
                der,
                "denied.test",
                "denied.test",
                8443,
                b"GET / HTTP/1.1\r\nHost: denied.test\r\nConnection: close\r\n\r\n",
            )
            .unwrap();
            assert!(resp.contains("denied-default"), "{resp:?}");
            assert_eq!(
                count(&s, "denied.test"),
                Counts {
                    deny: 1,
                    ..Default::default()
                }
            );
        }

        // denied-by-rule → deny. A deny rule matches before any resolve.
        {
            let s = fresh();
            let ca = Arc::new(Ca::ephemeral().unwrap());
            let der = ca.ca_cert_der();
            let denylist = EgressPolicy::new(vec![], vec![classify("evil.test:*").unwrap()])
                .with_default(DefaultAction::Allow);
            let ctx = Arc::new(
                ProxyCtx::new(ca, denylist)
                    .unwrap()
                    .with_stats(s.clone())
                    .with_log(log.clone())
                    .with_resolver(Box::new(|_| {
                        panic!("resolve must not run for a deny-rule host")
                    })),
            );
            let resp = through_proxy(
                ctx,
                der,
                "evil.test",
                "evil.test",
                8443,
                b"GET / HTTP/1.1\r\nHost: evil.test\r\nConnection: close\r\n\r\n",
            )
            .unwrap();
            assert!(resp.contains("denied-by-rule"), "{resp:?}");
            assert_eq!(
                count(&s, "evil.test"),
                Counts {
                    deny: 1,
                    ..Default::default()
                }
            );
        }

        // asked-denied (a remembered manual deny) → deny.
        {
            let s = fresh();
            let ca = Arc::new(Ca::ephemeral().unwrap());
            let der = ca.ca_cert_der();
            let manual = Arc::new(ManualRules::new());
            manual.remember(Verdict::Deny, "blocked.test", 443);
            let ctx = Arc::new(
                ProxyCtx::new(ca, EgressPolicy::default().with_default(DefaultAction::Ask))
                    .unwrap()
                    .with_stats(s.clone())
                    .with_log(log.clone())
                    .with_manual(manual)
                    .with_resolver(Box::new(|_| {
                        panic!("resolve must not run for a manual deny")
                    })),
            );
            let resp = through_proxy(
                ctx,
                der,
                "blocked.test",
                "blocked.test",
                443,
                b"GET / HTTP/1.1\r\nHost: blocked.test\r\nConnection: close\r\n\r\n",
            )
            .unwrap();
            assert!(resp.contains("asked-denied"), "{resp:?}");
            assert_eq!(
                count(&s, "blocked.test"),
                Counts {
                    deny: 1,
                    ..Default::default()
                }
            );
        }

        // sni-mismatch (domain-fronting) → blocked.
        {
            let s = fresh();
            let ca = Arc::new(Ca::ephemeral().unwrap());
            let der = ca.ca_cert_der();
            let ctx = Arc::new(
                ProxyCtx::new(ca, policy(&["allowed.test:*", "evil.test:*"]))
                    .unwrap()
                    .with_stats(s.clone())
                    .with_log(log.clone())
                    .with_resolver(Box::new(|_| {
                        panic!("resolve must not run on a fronting attempt")
                    })),
            );
            let resp = through_proxy(
                ctx,
                der,
                "allowed.test",
                "evil.test",
                8443,
                b"GET / HTTP/1.1\r\nHost: allowed.test\r\nConnection: close\r\n\r\n",
            )
            .unwrap();
            assert!(resp.contains("host-mismatch"), "{resp:?}");
            assert_eq!(
                count(&s, "allowed.test"),
                Counts {
                    blocked: 1,
                    ..Default::default()
                }
            );
        }

        // host-header-mismatch (SNI matches, decrypted Host disagrees) → blocked.
        {
            let s = fresh();
            let ca = Arc::new(Ca::ephemeral().unwrap());
            let der = ca.ca_cert_der();
            let ctx = Arc::new(
                ProxyCtx::new(ca, policy(&["allowed.test:*"]))
                    .unwrap()
                    .with_stats(s.clone())
                    .with_log(log.clone())
                    .with_resolver(Box::new(|_| {
                        panic!("resolve must not run on a host mismatch")
                    })),
            );
            let resp = through_proxy(
                ctx,
                der,
                "allowed.test",
                "allowed.test",
                8443,
                b"GET / HTTP/1.1\r\nHost: other.test\r\nConnection: close\r\n\r\n",
            )
            .unwrap();
            assert!(resp.contains("host-mismatch"), "{resp:?}");
            assert_eq!(
                count(&s, "allowed.test"),
                Counts {
                    blocked: 1,
                    ..Default::default()
                }
            );
        }

        // outbound-secret (a configured value echoed in the head) → blocked.
        {
            let s = fresh();
            let ca = Arc::new(Ca::ephemeral().unwrap());
            let der = ca.ca_cert_der();
            let ctx = Arc::new(
                ProxyCtx::new(ca, policy(&["host.test:*"]))
                    .unwrap()
                    .with_stats(s.clone())
                    .with_log(log.clone())
                    .with_redactions(vec![SecretNeedle::new(b"s3cret-reflected-value".to_vec())])
                    .with_resolver(Box::new(|_| {
                        panic!("resolve must not run on a secret leak")
                    })),
            );
            let resp = through_proxy(
                ctx,
                der,
                "host.test",
                "host.test",
                8443,
                b"GET / HTTP/1.1\r\nHost: host.test\r\nX-Leak: s3cret-reflected-value\r\n\r\n",
            )
            .unwrap();
            assert!(resp.contains("outbound-secret"), "{resp:?}");
            assert_eq!(
                count(&s, "host.test"),
                Counts {
                    blocked: 1,
                    ..Default::default()
                }
            );
        }

        // ssrf-blocked (an allowed host resolving to a metadata address) → blocked.
        {
            let s = fresh();
            let ca = Arc::new(Ca::ephemeral().unwrap());
            let der = ca.ca_cert_der();
            let ctx = Arc::new(
                ProxyCtx::new(ca, policy(&["host.test:*"]))
                    .unwrap()
                    .with_stats(s.clone())
                    .with_log(log.clone())
                    // the cloud metadata address — always refused, even for an exact-host rule
                    .with_resolver(Box::new(|_| Ok(vec![IpAddr::from([169, 254, 169, 254])]))),
            );
            let resp = through_proxy(
                ctx,
                der,
                "host.test",
                "host.test",
                8443,
                b"GET / HTTP/1.1\r\nHost: host.test\r\nConnection: close\r\n\r\n",
            )
            .unwrap();
            assert!(resp.contains("ssrf-blocked"), "{resp:?}");
            assert_eq!(
                count(&s, "host.test"),
                Counts {
                    blocked: 1,
                    ..Default::default()
                }
            );
        }

        // The shared ring is the ordered transcript of the seven blocks above: each site emitted
        // exactly one event with the host, verdict, and reason category it recorded. A mis-emitted
        // or missing event here is a log/stats drift (or a missed site), even though the per-block
        // stat assertions passed.
        let events = log.snapshot(None).events;
        let seen: Vec<(String, LogVerdict, String)> = events
            .iter()
            .map(|e| (e.host.clone(), e.verdict, e.reason.clone()))
            .collect();
        let expected = [
            ("denied.test", LogVerdict::Deny, "denied-default"),
            ("evil.test", LogVerdict::Deny, "denied-by-rule"),
            ("blocked.test", LogVerdict::Deny, "asked-denied"),
            ("allowed.test", LogVerdict::Blocked, "host-mismatch"),
            ("allowed.test", LogVerdict::Blocked, "host-mismatch"),
            ("host.test", LogVerdict::Blocked, "outbound-secret"),
            ("host.test", LogVerdict::Blocked, "ssrf-blocked"),
        ];
        assert_eq!(
            seen.len(),
            expected.len(),
            "one log event per decision site: {seen:?}"
        );
        for (i, (host, verdict, reason)) in expected.iter().enumerate() {
            assert_eq!(
                (seen[i].0.as_str(), seen[i].1, seen[i].2.as_str()),
                (*host, *verdict, *reason),
                "event {i} mismatched"
            );
        }
    }

    /// Like [`run_with_injections`] but also carrying redaction needles, to a capturing upstream —
    /// so a test can assert a clean request still reaches the upstream (the tripwire scans only the
    /// client head, never ops's own injection).
    fn run_with_injections_and_redactions(
        injections: Vec<HeaderInjection>,
        needles: &[&str],
        request: &[u8],
    ) -> (String, String) {
        let (addr, upstream_ca, rx) = spawn_upstream_capturing(
            b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        );
        let mut roots = RootCertStore::empty();
        roots.add(upstream_ca).unwrap();
        let upstream_cfg = Arc::new(
            ClientConfig::builder()
                .with_root_certificates(roots)
                .with_no_client_auth(),
        );
        let proxy_ca = Arc::new(Ca::ephemeral().unwrap());
        let proxy_ca_der = proxy_ca.ca_cert_der();
        let ctx = Arc::new(
            ProxyCtx::new(proxy_ca, policy(&["host.test:*"]))
                .unwrap()
                .with_upstream(upstream_cfg)
                .with_resolver(Box::new(|_| Ok(vec![IpAddr::from([127, 0, 0, 1])])))
                .with_injections(injections)
                .with_redactions(
                    needles
                        .iter()
                        .map(|n| SecretNeedle::new(n.as_bytes().to_vec()))
                        .collect(),
                ),
        );
        let resp = through_proxy(
            ctx,
            proxy_ca_der,
            "host.test",
            "host.test",
            addr.port(),
            request,
        )
        .unwrap();
        let head = rx.recv_timeout(Duration::from_secs(5)).unwrap_or_default();
        (resp, head)
    }

    /// The scan is on the pre-injection client head, so ops's own injected credential — whose value
    /// equals a redaction needle — never self-trips: a clean client request is still proxied and
    /// receives the injection.
    #[test]
    fn the_redaction_does_not_self_trip_on_the_injected_value() {
        let (resp, head) = run_with_injections_and_redactions(
            vec![injection(
                "host.test:*",
                "Authorization",
                "Bearer ops-secret-value",
            )],
            &["ops-secret-value"],
            b"GET / HTTP/1.1\r\nHost: host.test\r\n\r\n",
        );
        assert!(
            resp.contains("200"),
            "a clean request must still be proxied — the scan precedes injection: {resp:?}"
        );
        assert!(
            head.to_ascii_lowercase()
                .contains("authorization: bearer ops-secret-value"),
            "ops still injects its credential: {head:?}"
        );
    }

    /// The interaction with header strip-and-replace: an agent that *replays* the real secret value
    /// (learned via a reflection) to the `to` host is now refused outright (not silently
    /// stripped+reinjected); a *different* client auth value still hits the normal strip-and-replace
    /// path — the two mechanisms coexist.
    #[test]
    fn replaying_the_secret_is_refused_but_a_different_value_is_stripped_and_replaced() {
        // (a) replaying the real secret → refused, before the strip-and-replace
        let (resp_a, _head_a) = run_with_injections_and_redactions(
            vec![injection(
                "host.test:*",
                "Authorization",
                "Bearer ops-secret-value",
            )],
            &["ops-secret-value"],
            b"GET / HTTP/1.1\r\nHost: host.test\r\nAuthorization: Bearer ops-secret-value\r\n\r\n",
        );
        assert!(
            resp_a.contains("403") && resp_a.contains("outbound-secret"),
            "replaying the real secret must be refused, not stripped+reinjected: {resp_a:?}"
        );

        // (b) a different client auth value → normal strip-and-replace, ops's value wins
        let (resp_b, head_b) = run_with_injections_and_redactions(
            vec![injection(
                "host.test:*",
                "Authorization",
                "Bearer ops-secret-value",
            )],
            &["ops-secret-value"],
            b"GET / HTTP/1.1\r\nHost: host.test\r\nAuthorization: Bearer attacker\r\n\r\n",
        );
        assert!(
            resp_b.contains("200"),
            "a different auth value is proxied: {resp_b:?}"
        );
        let auth: Vec<&str> = head_b
            .lines()
            .filter(|l| l.to_ascii_lowercase().starts_with("authorization:"))
            .collect();
        assert_eq!(
            auth.len(),
            1,
            "exactly one Authorization reaches the upstream: {head_b:?}"
        );
        assert!(
            auth[0].contains("ops-secret-value"),
            "ops's value wins: {head_b:?}"
        );
        assert!(
            !head_b.contains("attacker"),
            "the client's copy is stripped: {head_b:?}"
        );
    }

    /// Drive one request through a proxy (allowing `host.test`, carrying `injections` and redaction
    /// `needles`) to a loopback upstream that returns `upstream_response` verbatim — so a test can
    /// make the upstream *reflect* a secret in its response and assert what the client finally sees.
    fn run_reflecting(
        injections: Vec<HeaderInjection>,
        needles: &[&str],
        upstream_response: &'static [u8],
        request: &[u8],
    ) -> String {
        let (addr, upstream_ca, up) = spawn_upstream("host.test", upstream_response);
        let mut roots = RootCertStore::empty();
        roots.add(upstream_ca).unwrap();
        let upstream_cfg = Arc::new(
            ClientConfig::builder()
                .with_root_certificates(roots)
                .with_no_client_auth(),
        );
        let proxy_ca = Arc::new(Ca::ephemeral().unwrap());
        let proxy_ca_der = proxy_ca.ca_cert_der();
        let ctx = Arc::new(
            ProxyCtx::new(proxy_ca, policy(&["host.test:*"]))
                .unwrap()
                .with_upstream(upstream_cfg)
                .with_resolver(Box::new(|_| Ok(vec![IpAddr::from([127, 0, 0, 1])])))
                .with_injections(injections)
                .with_redactions(
                    needles
                        .iter()
                        .map(|n| SecretNeedle::new(n.as_bytes().to_vec()))
                        .collect(),
                ),
        );
        let resp = through_proxy(
            ctx,
            proxy_ca_der,
            "host.test",
            "host.test",
            addr.port(),
            request,
        )
        .unwrap();
        up.join().unwrap();
        resp
    }

    /// The headline of the inbound backstop: a host an injection targets *reflects* the injected
    /// credential in its response body; the proxy masks the value out before it reaches the cage, so
    /// the agent gets the legitimate response with the secret struck out — never the plaintext.
    #[test]
    fn a_reflected_injected_secret_is_masked_in_the_response() {
        // the injected header is `Authorization: Bearer ops-secret-value`; the upstream echoes the
        // value in a JSON body (body is 43 bytes; same-length masking keeps Content-Length valid).
        let resp = run_reflecting(
            vec![injection(
                "host.test:*",
                "Authorization",
                "Bearer ops-secret-value",
            )],
            &["ops-secret-value"],
            b"HTTP/1.1 200 OK\r\nContent-Length: 43\r\nConnection: close\r\n\r\n\
              {\"authorization\":\"Bearer ops-secret-value\"}",
            b"GET /headers HTTP/1.1\r\nHost: host.test\r\n\r\n",
        );
        assert!(resp.contains("200"), "the response still flows: {resp:?}");
        assert!(
            !resp.contains("ops-secret-value"),
            "the reflected secret must be masked out of the response: {resp:?}"
        );
        assert!(
            resp.contains(&"*".repeat("ops-secret-value".len())),
            "the secret is replaced by an equal-length mask: {resp:?}"
        );
        assert!(
            resp.contains("{\"authorization\":\"Bearer "),
            "the legitimate response content around it survives: {resp:?}"
        );
    }

    /// The masking is scoped to injection-target hosts: a response from a host with no injection is
    /// streamed unmasked even with a redaction needle configured. A secret could be present there
    /// only if the agent already had it (and placed it), so masking would buy nothing — and scoping
    /// keeps the mutate-on-match off every unrelated lane (notably the nix cache).
    #[test]
    fn a_response_from_a_non_injection_host_is_not_masked() {
        let resp = run_reflecting(
            // the injection targets a DIFFERENT host than the one being requested (host.test)
            vec![injection(
                "other.test:*",
                "Authorization",
                "Bearer ops-secret-value",
            )],
            &["ops-secret-value"],
            b"HTTP/1.1 200 OK\r\nContent-Length: 16\r\nConnection: close\r\n\r\nops-secret-value",
            b"GET / HTTP/1.1\r\nHost: host.test\r\n\r\n",
        );
        assert!(
            resp.contains("ops-secret-value"),
            "a non-injection host's response is streamed unmasked: {resp:?}"
        );
    }

    /// A reader that yields its data in fixed-size chunks, so a test can force a needle to straddle
    /// a read boundary and prove the carry logic catches it.
    struct ChunkReader {
        data: Vec<u8>,
        pos: usize,
        chunk: usize,
    }

    impl Read for ChunkReader {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            if self.pos >= self.data.len() {
                return Ok(0);
            }
            let n = self.chunk.min(buf.len()).min(self.data.len() - self.pos);
            buf[..n].copy_from_slice(&self.data[self.pos..self.pos + n]);
            self.pos += n;
            Ok(n)
        }
    }

    #[test]
    fn redact_in_place_masks_every_occurrence_at_equal_length() {
        let needles = vec![
            SecretNeedle::new(b"AAA".to_vec()),
            SecretNeedle::new(b"BB".to_vec()),
        ];
        let mut buf = b"AAA-mid-AAA-BB".to_vec();
        let before = buf.len();
        redact_in_place(&mut buf, &needles);
        assert_eq!(
            buf, b"***-mid-***-**",
            "every occurrence of every needle is masked"
        );
        assert_eq!(buf.len(), before, "masking preserves length");
    }

    #[test]
    fn redact_in_place_ignores_an_overlong_or_empty_needle() {
        let needles = vec![
            SecretNeedle::new(b"WAYTOOLONG".to_vec()),
            SecretNeedle::new(Vec::new()),
        ];
        let mut buf = b"short".to_vec();
        redact_in_place(&mut buf, &needles);
        assert_eq!(buf, b"short", "no match, no mutation, no panic");
    }

    #[test]
    fn pump_redacting_masks_a_match_straddling_read_boundaries() {
        let needles = vec![SecretNeedle::new(b"SECRET".to_vec())];
        // one byte per read forces the 6-byte needle to span six separate reads
        let mut r = ChunkReader {
            data: b"xxSECRETyy".to_vec(),
            pos: 0,
            chunk: 1,
        };
        let mut out = Vec::new();
        pump_redacting(&mut r, &mut out, &needles).unwrap();
        assert_eq!(
            out, b"xx******yy",
            "a secret split across reads is still masked, length preserved"
        );
    }

    #[test]
    fn pump_redacting_passes_clean_bytes_through_unchanged() {
        let needles = vec![SecretNeedle::new(b"SECRET".to_vec())];
        let mut r = ChunkReader {
            data: b"nothing to see here".to_vec(),
            pos: 0,
            chunk: 4,
        };
        let mut out = Vec::new();
        pump_redacting(&mut r, &mut out, &needles).unwrap();
        assert_eq!(
            out, b"nothing to see here",
            "a stream without a secret is untouched"
        );
    }

    // ---- L4 (`tcp://`) raw splice -------------------------------------------------

    /// A raw TCP echo "upstream" for the splice tests: it accepts one connection and echoes every
    /// byte back until the peer closes its write half, then exits. Returns its loopback address.
    fn spawn_raw_echo() -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        thread::spawn(move || {
            if let Ok((mut sock, _)) = listener.accept() {
                let mut buf = [0u8; 4096];
                loop {
                    match sock.read(&mut buf) {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            if sock.write_all(&buf[..n]).is_err() {
                                break;
                            }
                        }
                    }
                }
            }
        });
        addr
    }

    /// A [`ProxyCtx`] whose resolver maps every name to loopback (so a `tcp://` rule reaches a local
    /// echo upstream), with the given allow entries.
    fn loopback_ctx(allow: &[&str]) -> Arc<ProxyCtx> {
        let ca = Arc::new(Ca::ephemeral().unwrap());
        Arc::new(
            ProxyCtx::new(ca, policy(allow))
                .unwrap()
                .with_resolver(Box::new(|_h| Ok(vec!["127.0.0.1".parse().unwrap()]))),
        )
    }

    /// Drive a raw (non-HTTP) payload through the proxy over a fresh UDS: CONNECT, expect `200`, then
    /// send `payload`, half-close, and read the echoed bytes back. Proves the L4 splice carries an
    /// arbitrary byte stream end-to-end — the headline mechanism.
    fn through_proxy_raw(
        ctx: Arc<ProxyCtx>,
        connect_host: &str,
        connect_port: u16,
        payload: &[u8],
    ) -> io::Result<Vec<u8>> {
        let dir = TmpDir::new();
        let path = dir.join("proxy.sock");
        let listener = UnixListener::bind(&path).unwrap();
        thread::spawn(move || {
            let _ = serve(listener, ctx);
        });
        let mut sock = UnixStream::connect(&path).unwrap();
        sock.set_read_timeout(Some(std::time::Duration::from_secs(10)))
            .ok();
        write!(
            sock,
            "CONNECT {connect_host}:{connect_port} HTTP/1.1\r\n\r\n"
        )
        .unwrap();
        sock.flush().unwrap();
        let established = read_until_blank(&mut sock)?;
        assert!(
            established.contains("200 Connection established"),
            "CONNECT not accepted: {established:?}"
        );
        sock.write_all(payload)?;
        sock.shutdown(std::net::Shutdown::Write)?;
        let mut resp = Vec::new();
        sock.read_to_end(&mut resp)?;
        Ok(resp)
    }

    /// Connect and read just the CONNECT-stage reply (a `200`, or a pre-tunnel refusal), for the
    /// cases the proxy refuses before accepting the tunnel.
    fn splice_connect_reply(ctx: Arc<ProxyCtx>, connect_host: &str, connect_port: u16) -> String {
        let dir = TmpDir::new();
        let path = dir.join("proxy.sock");
        let listener = UnixListener::bind(&path).unwrap();
        thread::spawn(move || {
            let _ = serve(listener, ctx);
        });
        let mut sock = UnixStream::connect(&path).unwrap();
        sock.set_read_timeout(Some(std::time::Duration::from_secs(10)))
            .ok();
        write!(
            sock,
            "CONNECT {connect_host}:{connect_port} HTTP/1.1\r\n\r\n"
        )
        .unwrap();
        sock.flush().unwrap();
        read_until_blank(&mut sock).unwrap()
    }

    #[test]
    fn a_tcp_rule_splices_a_raw_stream_end_to_end() {
        let echo = spawn_raw_echo();
        let ctx = loopback_ctx(&[&format!("tcp://splice.test:{}", echo.port())]);
        let resp = through_proxy_raw(ctx, "splice.test", echo.port(), b"PING-OVER-RAW-L4").unwrap();
        assert_eq!(
            resp, b"PING-OVER-RAW-L4",
            "the raw payload must round-trip through the splice uninspected"
        );
    }

    #[test]
    fn an_ip_literal_connect_splices_with_no_sni() {
        // A raw splice needs no SNI, so an IP-literal CONNECT target is accepted when a `tcp://` Ip
        // rule names it — unlike the inspected path, which refuses an IP literal.
        let echo = spawn_raw_echo();
        let ctx = loopback_ctx(&[&format!("tcp://127.0.0.1:{}", echo.port())]);
        let resp = through_proxy_raw(ctx, "127.0.0.1", echo.port(), b"RAW-TO-IP").unwrap();
        assert_eq!(resp, b"RAW-TO-IP");
    }

    #[test]
    fn an_ip_literal_target_without_a_tcp_rule_is_refused_and_logged_blocked() {
        use crate::sandbox::control::{LogRing, LogVerdict, LOG_RING_CAP};
        // With no `tcp://` rule the inspected L7 path refuses an IP-literal CONNECT pre-tunnel; the
        // attempt is logged (host = the IP the agent tried) as a block — a "what is it reaching for"
        // record the stats bucketing never captured.
        let log = Arc::new(LogRing::new(LOG_RING_CAP));
        let ctx = Arc::new(
            ProxyCtx::new(Arc::new(Ca::ephemeral().unwrap()), policy(&["host.test:*"]))
                .unwrap()
                .with_log(log.clone()),
        );
        let reply = splice_connect_reply(ctx, "127.0.0.1", 443);
        assert!(reply.contains("ip-literal"), "{reply:?}");
        let events = log.snapshot(None).events;
        assert_eq!(events.len(), 1, "one event: {events:?}");
        assert_eq!(events[0].verdict, LogVerdict::Blocked);
        assert_eq!(events[0].reason, "ip-literal");
        assert_eq!(events[0].host, "127.0.0.1");
        assert_eq!(events[0].port, 443);
        assert_eq!(events[0].method, None, "pre-tunnel: no method/path");
    }

    #[test]
    fn a_plain_http_attempt_through_the_proxy_is_refused_and_logged() {
        use crate::sandbox::control::{LogRing, LogVerdict, LOG_RING_CAP};
        // A malformed-handshake case with no clean host:port — a plain-HTTP absolute-form request
        // instead of a CONNECT tunnel. It is refused, and logged (host blank, method + raw target)
        // as the "what is the agent trying to do" signal it is.
        let log = Arc::new(LogRing::new(LOG_RING_CAP));
        let ctx = Arc::new(
            ProxyCtx::new(Arc::new(Ca::ephemeral().unwrap()), policy(&["host.test:*"]))
                .unwrap()
                .with_log(log.clone()),
        );
        let dir = TmpDir::new();
        let path = dir.join("proxy.sock");
        let listener = UnixListener::bind(&path).unwrap();
        thread::spawn(move || {
            let _ = serve(listener, ctx);
        });
        let mut sock = UnixStream::connect(&path).unwrap();
        sock.set_read_timeout(Some(std::time::Duration::from_secs(10)))
            .ok();
        sock.write_all(b"GET http://host.test/secret HTTP/1.1\r\nHost: host.test\r\n\r\n")
            .unwrap();
        sock.flush().unwrap();
        let reply = read_until_blank(&mut sock).unwrap();
        assert!(reply.contains("method-not-allowed"), "{reply:?}");
        let events = log.snapshot(None).events;
        assert_eq!(events.len(), 1, "one event: {events:?}");
        assert_eq!(events[0].verdict, LogVerdict::Blocked);
        assert_eq!(events[0].reason, "method-not-allowed");
        assert_eq!(events[0].host, "", "no clean host for a plain-HTTP attempt");
        assert_eq!(events[0].method.as_deref(), Some("GET"));
        assert_eq!(events[0].path.as_deref(), Some("http://host.test/secret"));
    }

    #[test]
    fn a_splice_to_a_private_address_is_ssrf_blocked_unless_the_rule_names_it() {
        // A `*.corp` subdomain rule does not name an exact host, so the SSRF guard refuses the
        // loopback (private) address it resolves to — a raw splice is still SSRF-guarded.
        let echo = spawn_raw_echo();
        let ctx = loopback_ctx(&[&format!("tcp://*.corp:{}", echo.port())]);
        let reply = splice_connect_reply(ctx, "db.corp", echo.port());
        assert!(
            reply.contains("403") && reply.contains("ssrf-blocked"),
            "a subdomain-ruled splice to a private address must be SSRF-blocked, got: {reply:?}"
        );
    }

    #[test]
    fn the_splice_guard_counts_open_tunnels() {
        let counter = AtomicUsize::new(0);
        {
            let g1 = SpliceGuard::new(&counter);
            assert_eq!(g1.count(), 1);
            let g2 = SpliceGuard::new(&counter);
            assert_eq!(g2.count(), 2);
            assert_eq!(counter.load(Ordering::SeqCst), 2);
        }
        assert_eq!(
            counter.load(Ordering::SeqCst),
            0,
            "both guards released their slot on drop"
        );
    }
}
