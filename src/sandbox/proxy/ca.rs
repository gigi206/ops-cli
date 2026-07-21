//! The proxy's certificate machinery: an ephemeral per-session CA that mints (and caches) a leaf
//! per requested host, the rustls resolver that hands those leaves out by SNI, and the upstream
//! client configs that validate the real server against the bundled roots so the interception
//! never weakens transport security.

use std::collections::HashMap;
use std::fmt;
use std::io;
use std::sync::{Arc, Mutex};

use rcgen::{
    BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, KeyPair,
    KeyUsagePurpose,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use rustls::{ClientConfig, RootCertStore};

/// Install the `ring` crypto provider as the process default exactly once. With the default
/// crate features turned off there is no auto-installed provider, so every `ServerConfig`/
/// `ClientConfig` builder needs this to have run first. Idempotent and racing-safe.
pub(super) fn ensure_provider() {
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
    /// Minted leaves, cached by host so a repeated connection reuses one certificate. Bounded at
    /// [`LEAF_CACHE_CAP`] — the key is the attacker-controlled SNI, so it must not grow without end.
    leaves: Mutex<HashMap<String, Arc<CertifiedKey>>>,
}

/// The most host leaves cached at once. Past this, a new host is minted per request but not stored,
/// so a flood of unique SNIs from the cage cannot grow host memory without bound. Far above the
/// handful of hosts any real workload contacts.
const LEAF_CACHE_CAP: usize = 1024;

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
            .push(DnType::CommonName, "sbx egress proxy CA");
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
        // The cache key is the attacker-controlled SNI, minted before any policy check, so it must
        // not grow without bound: past the cap, mint per request but stop inserting (a legitimate
        // workload reaches few hosts; only a flood of unique SNIs hits the cap). This bounds host
        // memory; the connection cap bounds the concurrent keygen cost.
        let mut leaves = self.leaves.lock().unwrap();
        if leaves.len() < LEAF_CACHE_CAP {
            leaves.insert(host.to_string(), ck.clone());
        }
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

/// The upstream config for the HTTP/2 branch: identical trust anchoring to [`upstream_config`] (so
/// the interception never weakens transport — a forged upstream is still rejected), but advertising
/// ALPN `h2` so the proxy negotiates HTTP/2 with the real gRPC server. gRPC is HTTP/2 end-to-end;
/// the h2 branch does not translate to HTTP/1.1, so an upstream that will not speak `h2` fails closed.
pub(crate) fn upstream_config_h2() -> Arc<ClientConfig> {
    ensure_provider();
    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let mut cfg = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    cfg.alpn_protocols = vec![b"h2".to_vec()];
    Arc::new(cfg)
}

/// A static `ServerName` for a host string, for opening the proxy's upstream connection.
/// Shared by the serve loop and the tests so they build it identically.
pub(crate) fn upstream_server_name(host: &str) -> io::Result<ServerName<'static>> {
    ServerName::try_from(host.to_string())
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn upstream_config_builds() {
        // Constructing it exercises the provider install and the root store load.
        let _ = upstream_config();
        assert!(upstream_server_name("cache.nixos.org").is_ok());
    }
}
