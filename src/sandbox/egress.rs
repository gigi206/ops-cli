//! Model-B egress wiring: the host-side MITM allowlisting proxy plus the in-cage
//! forwarder that bridges the cage's loopback to it over a bound Unix socket.
//!
//! Only the network-allowlist posture uses any of this; `shared` and `none` never
//! touch it. The shape is the one the spikes proved:
//!
//! - the cage has an **empty network namespace** (loopback only), so the *single*
//!   egress is a bound Unix socket — nothing else leaves, by construction;
//! - inside the cage a `socat TCP-LISTEN:…,fork UNIX-CONNECT:<bound socket>` forwarder
//!   accepts the proxy-aware tools' connections on `127.0.0.1` and pumps each to that
//!   socket (a fresh connection per accept — `,fork`);
//! - on the host the socket is served by the [`super::proxy`] MITM CONNECT proxy, which
//!   decides each request against the resolved allowlist, validates the upstream, and
//!   relays — the only thing that ever reaches the real network;
//! - the cage trusts the proxy's per-session CA through the broad set of CA-bundle
//!   environment variables ([`CA_FILE_ENV_KEYS`]), and points `http_proxy`/`https_proxy`
//!   at the in-cage forwarder.
//!
//! Security does not rest on the forwarder's integrity: bypassing it from inside the
//! cage reaches only the same allowlisting socket, or nothing (empty netns) — the
//! boundary is the empty namespace plus the host proxy, not socat.

use super::binds::ExtraBind;
use super::proxy::{Ca, HeaderInjection, ProxyCtx, SecretNeedle};
use crate::allowlist::EgressPolicy;
use crate::config::{HeaderSecret, SecretSource};
use crate::store::Layout;
use std::ffi::OsString;
use std::io;
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::sync::Arc;

/// The loopback port inside the cage the forwarder listens on and the tools point their
/// proxy environment at. Each cage has its own empty netns, so this never collides between
/// cages — but the *agent* might run its own service on the cage loopback, so this is a high,
/// uncommon port (well clear of 8080/3000/8000 and the like) to make that clash unlikely, and
/// below the ephemeral range so it cannot clash with an outbound connection's source port.
const CAGE_PROXY_PORT: u16 = 18043;

/// Where the bound egress socket appears in the cage. Under the `/tmp` tmpfs (a writable
/// mountpoint — a bind onto the read-only root would fail); the forwarder `UNIX-CONNECT`s
/// to it. The cage cannot unlink it (a bind-mount target is busy) or reach anything else.
const CAGE_UDS: &str = "/tmp/ops-egress.sock";

/// Where the proxy's CA certificate appears in the cage, read-only. Under `/opt/ops`
/// (already a cage directory for the mise plugin and shell rc), so the agent cannot
/// rewrite the trust anchor.
const CAGE_CA: &str = "/opt/ops/egress-ca.pem";

/// The CA-bundle environment variables ops sets so the cage's toolchains trust its
/// per-session CA, and — being the keys it sets — exactly the keys an untrusted project
/// is forbidden to set (see `config::is_reserved_env_key`, which consumes this list so
/// the two can never drift). All are *file*-valued and point at [`CAGE_CA`]; since every
/// cage connection is ops-minted under the empty netns, trusting only this CA is complete
/// (replace, not append). A tool that reads `/etc/ssl` directly and honors none of these
/// simply fails closed.
pub(crate) const CA_FILE_ENV_KEYS: &[&str] = &[
    "NIX_SSL_CERT_FILE",   // nix's libcurl (the self-equip path the spike proved)
    "SSL_CERT_FILE",       // openssl default file (curl, python, many others)
    "CURL_CA_BUNDLE",      // curl
    "GIT_SSL_CAINFO",      // git over https
    "REQUESTS_CA_BUNDLE",  // python requests / pip
    "NODE_EXTRA_CA_CERTS", // node (additive there, but harmless)
    "PIP_CERT",            // pip
    "npm_config_cafile",   // npm
];

/// A running egress session's host-side resources: the bound socket and the CA file. The
/// proxy serves on a detached thread that dies when ops exits (right after the cage); this
/// guard only owns the on-disk artifacts, unlinking them when the launch ends.
pub(crate) struct Egress {
    host_uds: PathBuf,
    ca_file: PathBuf,
}

impl Drop for Egress {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.host_uds);
        let _ = std::fs::remove_file(&self.ca_file);
    }
}

/// What an allowlist launch injects into the cage: the extra binds (the egress socket and
/// the CA) and the extra environment (the proxy address and the CA-bundle variables).
pub(crate) struct Wiring {
    pub(crate) binds: Vec<ExtraBind>,
    pub(crate) env: Vec<(String, String)>,
}

/// Wrap `cmd` so the cage starts the forwarder before running it: a static bash that
/// backgrounds `socat` (stdio detached so it never touches the terminal) and then
/// `exec`s the real command — which therefore stays the cage's main process, leaving
/// `ops shell`'s pty job control unchanged. The command rides `"$@"` positionally, so
/// nothing the agent controls is ever interpolated into the script (no shell injection,
/// non-UTF-8 argv preserved); only ops-owned ASCII store paths and the fixed port/socket
/// go into the script string.
pub(crate) fn wrap_command(socat: &Path, bash: &Path, cmd: Vec<OsString>) -> Vec<OsString> {
    let script = format!(
        "{socat} TCP-LISTEN:{port},bind=127.0.0.1,fork,reuseaddr UNIX-CONNECT:{uds} \
         </dev/null >/dev/null 2>&1 & exec \"$@\"",
        socat = socat.to_string_lossy(),
        port = CAGE_PROXY_PORT,
        uds = CAGE_UDS,
    );
    let mut out = vec![
        bash.as_os_str().to_os_string(),
        OsString::from("-c"),
        OsString::from(script),
        // `$0` — a label, not the command; the command is `$@` (the args after it).
        OsString::from("ops-egress-forward"),
    ];
    out.extend(cmd);
    out
}

/// Start the host proxy for `policy` on a fresh per-launch Unix socket, write its CA, and
/// return the cage wiring plus a guard owning the on-disk artifacts. The proxy is serving
/// before this returns (the listener is bound and a thread is accepting), so the cage's
/// first connection is never refused. The built-in nix-cache allow-set is added by the
/// proxy regardless of trust, so an untrusted project can still self-equip.
///
/// `secrets` are resolved here, host-side: each source ([`SecretSource`]) is read to a
/// plaintext, validated, and shaped into the final header value, then handed to the proxy as
/// a [`HeaderInjection`]. The plaintext never crosses into the cage — only the per-host
/// injection does, applied by the proxy to matching allowed requests. A missing or malformed
/// source aborts the launch (fail-closed), so the proxy never injects an empty credential.
pub(crate) fn start(
    layout: &Layout,
    policy: EgressPolicy,
    secrets: &[HeaderSecret],
) -> io::Result<(Egress, Wiring)> {
    use std::fs::DirBuilder;
    use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};

    // Resolve the credentials before standing anything up, so a missing secret fails the
    // launch cleanly rather than after a socket and a thread are live. The redaction needles
    // come from the same resolved values, so they cannot disagree with the injections.
    let (injections, redactions) = resolve_injections(secrets)?;

    let dir = layout.data_dir().join("egress");
    DirBuilder::new().recursive(true).mode(0o700).create(&dir)?;

    // Per-launch names (the pid keeps concurrent launches from colliding). A stale file
    // from a crashed predecessor with a reused pid would block the bind, so clear it first.
    let pid = std::process::id();
    let host_uds = dir.join(format!("proxy-{pid}.sock"));
    let ca_file = dir.join(format!("ca-{pid}.pem"));
    let _ = std::fs::remove_file(&host_uds);

    let ctx = Arc::new(
        ProxyCtx::new(Arc::new(Ca::ephemeral()?), policy)?
            .with_injections(injections)
            .with_redactions(redactions),
    );

    // Write the CA owner-only, outside every writable mount, then bind it read-only — the
    // agent gets a trust anchor it cannot rewrite.
    {
        use std::io::Write;
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&ca_file)?;
        f.write_all(ctx.ca_cert_pem().as_bytes())?;
    }

    // Bind+listen happens here on the main thread, before the thread accepts, so connections
    // queue from the moment the cage can reach the socket — no first-request race.
    let listener = UnixListener::bind(&host_uds)?;
    let serve_ctx = ctx.clone();
    std::thread::spawn(move || {
        // A serve error ends the proxy thread; the cage then loses egress (fail-closed).
        let _ = super::proxy::serve(listener, serve_ctx);
    });

    let proxy_url = format!("http://127.0.0.1:{CAGE_PROXY_PORT}");
    // Exempt loopback from the proxy: an agent's own in-cage service (a dev server, a test
    // harness on `127.0.0.1`) is intra-cage under the empty netns — never egress — so routing
    // it through the proxy would only get it refused (the proxy rejects an IP-literal CONNECT).
    // ops sets `no_proxy` itself; it being reserved-for-untrusted does not stop that.
    let no_proxy = "localhost,127.0.0.1,::1".to_string();
    let mut env = vec![
        ("http_proxy".to_string(), proxy_url.clone()),
        ("https_proxy".to_string(), proxy_url.clone()),
        ("HTTP_PROXY".to_string(), proxy_url.clone()),
        ("HTTPS_PROXY".to_string(), proxy_url),
        ("no_proxy".to_string(), no_proxy.clone()),
        ("NO_PROXY".to_string(), no_proxy),
    ];
    env.extend(
        CA_FILE_ENV_KEYS
            .iter()
            .map(|k| ((*k).to_string(), CAGE_CA.to_string())),
    );

    let binds = vec![
        // The egress socket: writable so a connect is never refused on a permission subtlety;
        // the agent can write to it (that is using the proxy) but not unlink it.
        ExtraBind {
            src: host_uds.clone(),
            dest: PathBuf::from(CAGE_UDS),
            writable: true,
        },
        // The CA, read-only and immutable.
        ExtraBind {
            src: ca_file.clone(),
            dest: PathBuf::from(CAGE_CA),
            writable: false,
        },
    ];

    Ok((Egress { host_uds, ca_file }, Wiring { binds, env }))
}

/// A secret shorter than this many bytes is not added to the outbound-redaction set: such a value
/// would match too many benign requests and refuse legitimate egress (a self-inflicted denial),
/// and is too low-entropy to be a credential worth a tripwire. The injection still applies — only
/// the leak tripwire is skipped, and loudly (a silent skip would be a false-confidence trap).
const REDACT_MIN_LEN: usize = 8;

/// Resolve each declared header secret into a proxy injection plus the outbound-redaction needles,
/// reading every source host-side. Fail-closed: a missing or empty source, or one carrying a
/// header-splitting byte, aborts the whole launch (so a partially-resolved set is never used). The
/// needles derive from the same resolved values as the injections, so a launch with no secrets
/// yields no needles (and can never raise a surprise `outbound-secret` refusal).
fn resolve_injections(
    secrets: &[HeaderSecret],
) -> io::Result<(Vec<HeaderInjection>, Vec<SecretNeedle>)> {
    let mut injections = Vec::with_capacity(secrets.len());
    let mut redactions = Vec::new();
    for secret in secrets {
        let (injection, needles) = resolve_one(secret)?;
        injections.push(injection);
        redactions.extend(needles);
    }
    Ok((injections, redactions))
}

/// Read one secret's plaintext host-side, validate it, and shape it into a [`HeaderInjection`] plus
/// its outbound-redaction needles. The plaintext is read into a local, formed into the header value
/// and into the needles, and dropped — it never reaches the cage. Every error names the **source**,
/// never the value: an unset variable, an unreadable or empty file, or a value with an embedded
/// CR/LF/NUL (which would split the request head and inject arbitrary headers upstream — the common
/// trip is a file's trailing newline, stripped here before the check). A value below
/// [`REDACT_MIN_LEN`] is injected but not redacted (warned, never silently).
fn resolve_one(secret: &HeaderSecret) -> io::Result<(HeaderInjection, Vec<SecretNeedle>)> {
    let (plaintext, label) = match &secret.source {
        SecretSource::Env(var) => {
            let value = std::env::var(var).map_err(|_| {
                io::Error::other(format!(
                    "the secret for `{}` reads ${var}, which is not set in ops's environment",
                    secret.header
                ))
            })?;
            (value, format!("${var}"))
        }
        SecretSource::File(path) => {
            let value = std::fs::read_to_string(path).map_err(|e| {
                io::Error::other(format!(
                    "the secret for `{}` cannot read {}: {e}",
                    secret.header,
                    path.display()
                ))
            })?;
            (value, path.display().to_string())
        }
    };

    // A file (and the odd variable) commonly ends in a trailing newline; strip one line ending,
    // then reject any embedded CR/LF/NUL — none can appear in an HTTP header value. Empty after
    // trimming is treated as missing.
    let trimmed = plaintext.strip_suffix('\n').unwrap_or(&plaintext);
    let trimmed = trimmed.strip_suffix('\r').unwrap_or(trimmed);
    if trimmed.is_empty() {
        return Err(io::Error::other(format!(
            "the secret for `{}` from {label} is empty",
            secret.header
        )));
    }
    if trimmed.bytes().any(|b| b == b'\r' || b == b'\n' || b == 0) {
        return Err(io::Error::other(format!(
            "the secret for `{}` from {label} contains a newline or NUL \
             (it cannot be an HTTP header value)",
            secret.header
        )));
    }

    let needles = if trimmed.len() < REDACT_MIN_LEN {
        eprintln!(
            "ops: warning: the secret for `{}` is too short ({} bytes) to redact from outbound \
             requests safely; outbound leak-blocking is disabled for it (the injection still applies)",
            secret.header,
            trimmed.len()
        );
        Vec::new()
    } else {
        secret
            .shape
            .needles(trimmed)
            .into_iter()
            .map(SecretNeedle::new)
            .collect()
    };

    Ok((
        HeaderInjection {
            rule: secret.to.clone(),
            header: secret.header.clone(),
            value: secret.shape.format(trimmed),
        },
        needles,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::TmpDir;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn wrap_command_backgrounds_socat_and_execs_the_command_positionally() {
        let cmd = vec![OsString::from("jq"), OsString::from("--version")];
        let argv = wrap_command(
            Path::new("/nix/store/abc-socat/bin/socat"),
            Path::new("/nix/store/def-bash/bin/bash"),
            cmd,
        );
        // bash -c <script> <label> jq --version
        assert_eq!(argv[0], OsString::from("/nix/store/def-bash/bin/bash"));
        assert_eq!(argv[1], OsString::from("-c"));
        let script = argv[2].to_string_lossy();
        assert!(script.contains("/nix/store/abc-socat/bin/socat"));
        assert!(script.contains(&format!("TCP-LISTEN:{CAGE_PROXY_PORT}")));
        assert!(script.contains(&format!("UNIX-CONNECT:{CAGE_UDS}")));
        // the command is positional, after the `$0` label — never interpolated into the script.
        assert!(script.contains("exec \"$@\""));
        assert!(
            !script.contains("jq"),
            "the command must not be interpolated into the script"
        );
        assert_eq!(argv[3], OsString::from("ops-egress-forward"));
        assert_eq!(argv[4], OsString::from("jq"));
        assert_eq!(argv[5], OsString::from("--version"));
    }

    #[test]
    fn start_serves_the_proxy_and_wires_the_cage_then_cleans_up() {
        let data = TmpDir::new();
        let layout = Layout::under(data.path());
        std::fs::create_dir_all(layout.data_dir()).unwrap();

        let (guard, wiring) =
            start(&layout, EgressPolicy::default(), &[]).expect("start the egress proxy");

        // the proxy address reaches the in-cage forwarder
        let url = format!("http://127.0.0.1:{CAGE_PROXY_PORT}");
        for k in ["http_proxy", "https_proxy", "HTTP_PROXY", "HTTPS_PROXY"] {
            let v = wiring
                .env
                .iter()
                .find(|(key, _)| key == k)
                .map(|(_, v)| v.as_str());
            assert_eq!(v, Some(url.as_str()), "{k} must point at the forwarder");
        }
        // loopback is exempt, so the agent's own in-cage service is not routed through the proxy
        for k in ["no_proxy", "NO_PROXY"] {
            let v = wiring
                .env
                .iter()
                .find(|(key, _)| key == k)
                .map(|(_, v)| v.as_str());
            assert_eq!(
                v,
                Some("localhost,127.0.0.1,::1"),
                "{k} must exempt loopback"
            );
        }
        // every CA-bundle key points at the in-cage CA; the set it sets == the set the
        // denylist protects.
        for k in CA_FILE_ENV_KEYS {
            let v = wiring
                .env
                .iter()
                .find(|(key, _)| key == k)
                .map(|(_, v)| v.as_str());
            assert_eq!(v, Some(CAGE_CA), "{k} must point at the cage CA");
        }

        // the two binds: the socket (writable) at the cage socket path, the CA (read-only)
        let sock = wiring
            .binds
            .iter()
            .find(|b| b.dest == Path::new(CAGE_UDS))
            .unwrap();
        assert!(sock.writable);
        assert!(sock.src.exists(), "the host socket must be bound");
        let ca = wiring
            .binds
            .iter()
            .find(|b| b.dest == Path::new(CAGE_CA))
            .unwrap();
        assert!(!ca.writable);
        // the CA file is owner-only and a real certificate
        let mode = std::fs::metadata(&ca.src).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "the CA key/cert file must be owner-only");
        assert!(std::fs::read_to_string(&ca.src)
            .unwrap()
            .contains("BEGIN CERTIFICATE"));

        let (host_uds, ca_file) = (guard.host_uds.clone(), guard.ca_file.clone());
        drop(guard);
        // the guard unlinks both artifacts when the launch ends
        assert!(!host_uds.exists(), "the socket must be unlinked on drop");
        assert!(!ca_file.exists(), "the CA file must be unlinked on drop");
    }

    fn secret(
        source: SecretSource,
        to: &str,
        header: &str,
        shape: crate::config::HeaderShape,
    ) -> HeaderSecret {
        HeaderSecret {
            source,
            to: crate::allowlist::classify(to).unwrap(),
            header: header.to_string(),
            shape,
        }
    }

    #[test]
    fn resolve_injections_reads_env_and_shapes_the_value() {
        std::env::set_var("OPS_TEST_EGRESS_TOKEN", "s3cret-token-value");
        let s = secret(
            SecretSource::Env("OPS_TEST_EGRESS_TOKEN".into()),
            "api.github.com",
            "Authorization",
            crate::config::HeaderShape::new("Bearer ", false),
        );
        let (injs, needles) = resolve_injections(&[s]).unwrap();
        std::env::remove_var("OPS_TEST_EGRESS_TOKEN");
        assert_eq!(injs.len(), 1);
        assert_eq!(injs[0].header, "Authorization");
        assert_eq!(injs[0].value, "Bearer s3cret-token-value");
        assert_eq!(
            injs[0].rule,
            crate::allowlist::classify("api.github.com").unwrap()
        );
        // a bearer secret contributes exactly one needle: the raw plaintext (what travels on the
        // wire after the static `Bearer ` prefix), so the outbound tripwire can catch its re-exfil.
        assert_eq!(needles.len(), 1, "one needle per bearer secret");
        assert_eq!(needles[0].as_bytes(), b"s3cret-token-value");
    }

    #[test]
    fn a_missing_env_source_fails_closed_naming_the_source() {
        let s = secret(
            SecretSource::Env("OPS_TEST_EGRESS_DEFINITELY_UNSET".into()),
            "h.test",
            "Authorization",
            crate::config::HeaderShape::new("Bearer ", false),
        );
        let err = resolve_injections(&[s]).unwrap_err().to_string();
        assert!(
            err.contains("OPS_TEST_EGRESS_DEFINITELY_UNSET"),
            "the error must name the missing source: {err}"
        );
    }

    #[test]
    fn an_empty_source_fails_closed() {
        // a value that is only a newline trims to empty → treated as missing
        std::env::set_var("OPS_TEST_EGRESS_EMPTY", "\n");
        let s = secret(
            SecretSource::Env("OPS_TEST_EGRESS_EMPTY".into()),
            "h.test",
            "H",
            crate::config::HeaderShape::new("", false),
        );
        let err = resolve_injections(&[s]).unwrap_err().to_string();
        std::env::remove_var("OPS_TEST_EGRESS_EMPTY");
        assert!(
            err.contains("empty"),
            "an empty source must fail closed: {err}"
        );
    }

    #[test]
    fn a_file_secret_strips_a_trailing_newline_and_rejects_an_embedded_one() {
        let dir = TmpDir::new();
        let ok = dir.join("ok");
        std::fs::write(&ok, "tok3n-from-a-file\n").unwrap();
        let (injs, _needles) = resolve_injections(&[secret(
            SecretSource::File(ok),
            "h.test",
            "Authorization",
            crate::config::HeaderShape::new("Bearer ", false),
        )])
        .unwrap();
        assert_eq!(
            injs[0].value, "Bearer tok3n-from-a-file",
            "a file's trailing newline is stripped"
        );

        let bad = dir.join("bad");
        std::fs::write(&bad, "to\nken").unwrap();
        let err = resolve_injections(&[secret(
            SecretSource::File(bad),
            "h.test",
            "Authorization",
            crate::config::HeaderShape::new("Bearer ", false),
        )])
        .unwrap_err()
        .to_string();
        assert!(
            err.contains("newline or NUL"),
            "an embedded newline must fail closed (header-splitting): {err}"
        );
    }

    #[test]
    fn a_basic_secret_redacts_both_the_pair_and_its_base64() {
        std::env::set_var("OPS_TEST_EGRESS_BASIC", "alice:correct-horse");
        let s = secret(
            SecretSource::Env("OPS_TEST_EGRESS_BASIC".into()),
            "h.test",
            "Authorization",
            crate::config::HeaderShape::new("Basic ", true),
        );
        let (injs, needles) = resolve_injections(&[s]).unwrap();
        std::env::remove_var("OPS_TEST_EGRESS_BASIC");
        // basic carries the base64 on the wire, so BOTH the raw user:pass and its base64 are
        // needles — a reflecting upstream echoes the base64, the raw pair is the underlying secret.
        let raw = b"alice:correct-horse".to_vec();
        // tie the base64 needle to what `format()` actually emits, without re-deriving base64 here
        let wire = injs[0]
            .value
            .strip_prefix("Basic ")
            .unwrap()
            .as_bytes()
            .to_vec();
        let bytes: Vec<Vec<u8>> = needles.iter().map(|n| n.as_bytes().to_vec()).collect();
        assert_eq!(bytes.len(), 2, "basic yields the pair and its base64");
        assert!(
            bytes.contains(&raw),
            "the raw user:pass is a needle: {bytes:?}"
        );
        assert!(
            bytes.contains(&wire),
            "the base64 (wire) form is a needle, matching format()'s output"
        );
    }

    #[test]
    fn a_short_secret_is_injected_but_not_redacted() {
        std::env::set_var("OPS_TEST_EGRESS_SHORT", "abc"); // 3 bytes, below REDACT_MIN_LEN
        let s = secret(
            SecretSource::Env("OPS_TEST_EGRESS_SHORT".into()),
            "h.test",
            "Authorization",
            crate::config::HeaderShape::new("Bearer ", false),
        );
        let (injs, needles) = resolve_injections(&[s]).unwrap();
        std::env::remove_var("OPS_TEST_EGRESS_SHORT");
        assert_eq!(injs[0].value, "Bearer abc", "the injection still applies");
        assert!(
            needles.is_empty(),
            "a too-short secret is not redacted — it would refuse benign traffic (self-DoS)"
        );
    }
}
