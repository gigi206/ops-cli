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
use std::process::Command;
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

/// A running egress session's host-side resources: the bound proxy socket, the CA file, and — under
/// the `ask` posture — the control socket a host-side `ops net pending` reaches. The proxy and
/// control threads are detached and die when ops exits (right after the cage); this guard only owns
/// the on-disk artifacts, unlinking them when the launch ends. The control socket is deliberately
/// not among the cage's binds (see [`start`]).
pub(crate) struct Egress {
    host_uds: PathBuf,
    ca_file: PathBuf,
    /// The `ask`-posture control socket, present only when the policy asks by default.
    control_uds: Option<PathBuf>,
}

impl Drop for Egress {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.host_uds);
        let _ = std::fs::remove_file(&self.ca_file);
        if let Some(control) = &self.control_uds {
            let _ = std::fs::remove_file(control);
        }
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
    project_root: &Path,
    bwrap: &Path,
) -> io::Result<(Egress, Wiring)> {
    use std::fs::DirBuilder;
    use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};

    // Tighten the data directory to owner-only before anything reads from it. A resolver plugin
    // is trusted by location — it is run only because it sits under `<data>/plugins`, a tree a
    // project cannot write — and that perimeter rests on `<data>` being `0700`; establish it here,
    // ahead of resolving any plugin-backed secret.
    crate::store::ensure(layout)?;

    // Resolve the credentials before standing anything up, so a missing secret fails the
    // launch cleanly rather than after a socket and a thread are live. The redaction needles
    // come from the same resolved values, so they cannot disagree with the injections. A
    // relative `sops` file resolves against the project root (the `.ops.toml`'s directory). A
    // plugin-backed source runs its resolver host-side under `bwrap` (never inside the cage).
    let (injections, redactions) = resolve_injections(secrets, project_root, bwrap)?;

    let dir = layout.data_dir().join("egress");
    DirBuilder::new().recursive(true).mode(0o700).create(&dir)?;

    // Per-launch names (the pid keeps concurrent launches from colliding). A stale file
    // from a crashed predecessor with a reused pid would block the bind, so clear it first.
    let pid = std::process::id();
    let host_uds = dir.join(format!("proxy-{pid}.sock"));
    let ca_file = dir.join(format!("ca-{pid}.pem"));
    let _ = std::fs::remove_file(&host_uds);

    // Read the posture before the policy moves into the proxy context: only `ask` needs a control
    // plane.
    let asks = policy.default_action() == crate::allowlist::DefaultAction::Ask;
    let mut ctx = ProxyCtx::new(Arc::new(Ca::ephemeral()?), policy)?
        .with_injections(injections)
        .with_redactions(redactions);

    // Under the `ask` posture, stand up the control socket the host-side `ops net pending` reaches
    // to answer parked requests, sharing one pending queue with the proxy. It lives under the
    // `0700` egress dir beside `<data>` and is **never** bound into the cage (only the proxy socket
    // and the CA cross in) — in Mode B the in-cage agent must not be able to answer its own asks.
    // Other postures never park, so they skip it entirely.
    let control_uds = if asks {
        let control_uds = dir.join(format!("control-{pid}.sock"));
        let _ = std::fs::remove_file(&control_uds);
        let pending = Arc::new(super::control::PendingState::new());
        ctx = ctx.with_control(pending.clone());
        // Bind+listen here, before the serving thread, so the control plane is reachable the moment
        // the launch is up — never a race with the first `ops net pending`.
        let control_listener = UnixListener::bind(&control_uds)?;
        std::thread::spawn(move || {
            let _ = super::control::serve(control_listener, pending);
        });
        Some(control_uds)
    } else {
        None
    };
    let ctx = Arc::new(ctx);

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

    Ok((
        Egress {
            host_uds,
            ca_file,
            control_uds,
        },
        Wiring { binds, env },
    ))
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
    project_root: &Path,
    bwrap: &Path,
) -> io::Result<(Vec<HeaderInjection>, Vec<SecretNeedle>)> {
    let mut injections = Vec::with_capacity(secrets.len());
    let mut redactions = Vec::new();
    for secret in secrets {
        let (injection, needles) = resolve_one(secret, project_root, bwrap)?;
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
fn resolve_one(
    secret: &HeaderSecret,
    project_root: &Path,
    bwrap: &Path,
) -> io::Result<(HeaderInjection, Vec<SecretNeedle>)> {
    // Try each source in order, the first that resolves winning. A clean "absent" (an unset
    // variable, a missing file, an empty value) falls through to the next source; a HARD error
    // (a file that exists but cannot be read, a value carrying a header-splitting byte) aborts the
    // whole launch fail-closed — it must never silently downgrade to a weaker fallback source.
    let mut tried = Vec::with_capacity(secret.sources.len());
    let mut resolved = None;
    for source in &secret.sources {
        tried.push(source.describe());
        if let Some(value) = read_source(source, &secret.header, project_root, bwrap)? {
            resolved = Some(value);
            break;
        }
    }
    let trimmed = resolved.ok_or_else(|| {
        io::Error::other(format!(
            "no source resolved the secret for `{}` (tried: {})",
            secret.header,
            tried.join(", ")
        ))
    })?;
    let trimmed = trimmed.as_str();

    let needles = if trimmed.len() < REDACT_MIN_LEN {
        crate::diag::warn(&format!(
            "the secret for `{}` is too short ({} bytes) to redact from outbound \
             requests safely; outbound leak-blocking is disabled for it (the injection still applies)",
            secret.header,
            trimmed.len()
        ));
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

/// Read one source host-side, classifying the outcome so the fallback chain stays safe:
/// `Ok(Some(value))` resolved, `Ok(None)` a clean **absent** (try the next source), `Err` a **hard**
/// error (abort the launch). The error classification is the security property of the chain: only a
/// genuinely-missing source (an unset variable, a not-found file) is "absent"; an unreadable file or
/// a non-Unicode variable is a hard error, never silently downgraded to a weaker fallback. The value
/// is never logged — every error names the source locator, not the secret.
fn read_source(
    source: &SecretSource,
    header: &str,
    project_root: &Path,
    bwrap: &Path,
) -> io::Result<Option<String>> {
    match source {
        SecretSource::Env(var) => match std::env::var(var) {
            Ok(value) => classify_value(value, header, &format!("${var}")),
            Err(std::env::VarError::NotPresent) => Ok(None),
            Err(std::env::VarError::NotUnicode(_)) => Err(io::Error::other(format!(
                "the secret for `{header}` reads ${var}, which is not valid Unicode"
            ))),
        },
        SecretSource::File(path) => match std::fs::read_to_string(path) {
            Ok(value) => classify_value(value, header, &path.display().to_string()),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(io::Error::other(format!(
                "the secret for `{header}` cannot read {}: {e}",
                path.display()
            ))),
        },
        SecretSource::Sops { file, key } => {
            let path = sops_path(file, project_root);
            // A confirmed-missing encrypted file is a clean absent (fall through), like `file://`;
            // an existing one goes to sops. A path whose existence cannot be determined — an
            // unreadable parent directory — is a hard error, never silently treated as absent
            // (which would let a permission problem downgrade to a weaker fallback source).
            match path.try_exists() {
                Ok(false) => Ok(None),
                Ok(true) => run_sops(Path::new("sops"), &path, key.as_deref(), header),
                Err(e) => Err(io::Error::other(format!(
                    "the secret for `{header}` cannot stat {}: {e}",
                    path.display()
                ))),
            }
        }
        // A resolver plugin is run host-side in its own least-privilege bwrap cage, never inside
        // the agent's cage. The full ref (`scheme://locator`) reconstructs exactly — `parse_secret_ref`
        // split it on the first `://` — and goes to the plugin as `argv[1]`. Its stdout flows
        // through the same `classify_value` as every other source: empty → a clean absent (fall
        // through to the next source in the chain), an embedded CR/LF/NUL → a hard error. A non-zero
        // exit is already a hard error inside `resolver::run`, propagated here (never a silent absent).
        SecretSource::Plugin { plugin, locator } => {
            let reff = format!("{}://{locator}", plugin.scheme);
            let raw = super::resolver::run(bwrap, plugin, &reff)?;
            classify_value(raw, header, &format!("{} {locator}", plugin.scheme))
        }
    }
}

/// Resolve a sops file path: a relative one against the project root (the `.ops.toml`'s directory),
/// an absolute one as-is.
fn sops_path(file: &Path, project_root: &Path) -> PathBuf {
    if file.is_absolute() {
        file.to_path_buf()
    } else {
        project_root.join(file)
    }
}

/// Build sops's `--extract` argument from a validated dotted key: `db.password` →
/// `["db"]["password"]`. The key is charset-validated at parse time, so no segment can break the
/// bracket expression.
fn sops_extract_expr(key: &str) -> String {
    key.split('.').map(|seg| format!("[\"{seg}\"]")).collect()
}

/// Decrypt a sops file host-side with the `sops` CLI and classify the result like any other source.
/// `sops_bin` is the binary to run (`"sops"` in production; an explicit path in tests, so no PATH
/// mutation). With a `key`, only that value is extracted; without one the whole file is decrypted —
/// which, being multi-line, [`classify_value`] turns into a hard error (it cannot be a single header
/// value), the correct fail-closed outcome. Every failure is a hard error that names the source and
/// folds in sops's own stderr diagnostic (the plaintext is on stdout, never stderr), never the value.
fn run_sops(
    sops_bin: &Path,
    file: &Path,
    key: Option<&str>,
    header: &str,
) -> io::Result<Option<String>> {
    let mut cmd = Command::new(sops_bin);
    cmd.arg("--decrypt");
    if let Some(k) = key {
        cmd.arg("--extract").arg(sops_extract_expr(k));
    }
    cmd.arg(file);
    let output = match cmd.output() {
        Ok(out) => out,
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            return Err(io::Error::other(format!(
                "the secret for `{header}` needs sops, which is not installed or not on PATH"
            )));
        }
        Err(e) => {
            return Err(io::Error::other(format!(
                "the secret for `{header}` could not run sops: {e}"
            )));
        }
    };
    if !output.status.success() {
        let detail = String::from_utf8_lossy(&output.stderr);
        let detail = detail.trim();
        return Err(io::Error::other(format!(
            "the secret for `{header}` failed to decrypt {} with sops{}",
            file.display(),
            if detail.is_empty() {
                String::new()
            } else {
                format!(": {detail}")
            }
        )));
    }
    let value = String::from_utf8(output.stdout).map_err(|_| {
        io::Error::other(format!(
            "the secret for `{header}` from sops {} is not valid UTF-8",
            file.display()
        ))
    })?;
    classify_value(value, header, &format!("sops {}", file.display()))
}

/// Trim and classify a value read from a source: strip a single trailing line ending (a file
/// commonly ends in one), then an empty result is a clean **absent** (`Ok(None)` — fall through to
/// the next source), while an embedded CR/LF/NUL is a **hard** error (`Err`) — it cannot be an HTTP
/// header value, and a found-but-malformed secret must fail closed rather than fall through.
fn classify_value(raw: String, header: &str, label: &str) -> io::Result<Option<String>> {
    let trimmed = raw.strip_suffix('\n').unwrap_or(&raw);
    let trimmed = trimmed.strip_suffix('\r').unwrap_or(trimmed);
    if trimmed.is_empty() {
        return Ok(None);
    }
    if trimmed.bytes().any(|b| b == b'\r' || b == b'\n' || b == 0) {
        return Err(io::Error::other(format!(
            "the secret for `{header}` from {label} contains a newline or NUL \
             (it cannot be an HTTP header value)"
        )));
    }
    Ok(Some(trimmed.to_string()))
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

        let (guard, wiring) = start(
            &layout,
            EgressPolicy::default(),
            &[],
            Path::new("/"),
            Path::new(UNUSED_BWRAP),
        )
        .expect("start the egress proxy");

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
        // a non-ask posture stands up no control socket
        assert!(
            guard.control_uds.is_none(),
            "deny mode needs no control socket"
        );
        drop(guard);
        // the guard unlinks both artifacts when the launch ends
        assert!(!host_uds.exists(), "the socket must be unlinked on drop");
        assert!(!ca_file.exists(), "the CA file must be unlinked on drop");
    }

    /// The load-bearing security property of the `ask` posture: the control socket — over which a
    /// request is answered — is created host-side but **never** bound into the cage. In Mode B the
    /// in-cage agent is the adversary; if it could reach this socket it could answer its own asks.
    /// Only the proxy socket and the CA cross in.
    #[test]
    fn the_ask_control_socket_is_created_but_never_bound_into_the_cage() {
        let data = TmpDir::new();
        let layout = Layout::under(data.path());
        std::fs::create_dir_all(layout.data_dir()).unwrap();

        let ask = EgressPolicy::default().with_default(crate::allowlist::DefaultAction::Ask);
        let (guard, wiring) = start(&layout, ask, &[], Path::new("/"), Path::new(UNUSED_BWRAP))
            .expect("start the ask egress proxy");

        // ask mode binds a control socket under the egress dir...
        let control = guard
            .control_uds
            .clone()
            .expect("ask mode must bind a control socket");
        assert!(control.exists(), "the control socket must be bound");
        assert!(control
            .file_name()
            .unwrap()
            .to_string_lossy()
            .starts_with("control-"));

        // ...but it is NEVER among the cage's binds — the proxy socket and the CA are all that cross
        // in, so the in-cage agent cannot reach the control plane to answer its own asks.
        for b in &wiring.binds {
            assert_ne!(
                b.src, control,
                "the control socket must not be bound into the cage"
            );
        }
        assert_eq!(
            wiring.binds.len(),
            2,
            "ask mode adds no cage bind beyond the proxy socket and the CA"
        );

        drop(guard);
        assert!(
            !control.exists(),
            "the control socket is unlinked when the launch ends"
        );
    }

    fn secret(
        source: SecretSource,
        to: &str,
        header: &str,
        shape: crate::config::HeaderShape,
    ) -> HeaderSecret {
        secret_chain(vec![source], to, header, shape)
    }

    /// Like [`secret`] but with an explicit fallback chain of sources.
    fn secret_chain(
        sources: Vec<SecretSource>,
        to: &str,
        header: &str,
        shape: crate::config::HeaderShape,
    ) -> HeaderSecret {
        HeaderSecret {
            sources,
            to: crate::allowlist::classify(to).unwrap(),
            header: header.to_string(),
            shape,
        }
    }

    /// A bwrap path that is never invoked: the env/file/sops tests carry no plugin source, so the
    /// resolver runner — the only consumer of bwrap — never fires.
    const UNUSED_BWRAP: &str = "/nonexistent/bwrap";

    /// Resolve with a throwaway project root — the env/file tests never read it (only a relative
    /// `sops` source would); the sops tests below pass their own root explicitly.
    fn resolve_injections_at_root(
        secrets: &[HeaderSecret],
    ) -> io::Result<(Vec<HeaderInjection>, Vec<SecretNeedle>)> {
        resolve_injections(secrets, Path::new("/"), Path::new(UNUSED_BWRAP))
    }

    /// Write an executable fake `sops` to `dir/sops` that runs `body` (a bash script with the
    /// invocation's args in `$@`), so a test can exercise [`run_sops`] hermetically without the
    /// real sops or any decryption key — and without mutating PATH (the binary path is passed in).
    fn fake_sops(dir: &TmpDir, body: &str) -> PathBuf {
        let path = dir.join("sops");
        std::fs::write(&path, format!("#!/usr/bin/env bash\n{body}\n")).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        path
    }

    /// Run [`run_sops`], retrying briefly on a transient spawn failure.
    ///
    /// A fake `sops` is written then immediately executed. Under the parallel test runner another
    /// thread's `fork` can momentarily hold the just-written executable open across the fork→exec
    /// window, so `execve` transiently fails with ETXTBSY ("text file busy") — a property of
    /// running a freshly-written binary in a multithreaded process, not of [`run_sops`] (production
    /// `sops` is an installed binary). Only the spawn-error branch is retried (its message is
    /// distinct), so a genuine decrypt/extract/classify error surfaces on the first attempt and
    /// still fails the test.
    fn run_sops_retrying_spawn(
        sops: &Path,
        file: &Path,
        key: Option<&str>,
        header: &str,
    ) -> io::Result<Option<String>> {
        let mut attempt = run_sops(sops, file, key, header);
        for _ in 0..100 {
            match &attempt {
                Err(e) if e.to_string().contains("could not run sops") => {
                    std::thread::sleep(std::time::Duration::from_millis(5));
                    attempt = run_sops(sops, file, key, header);
                }
                _ => break,
            }
        }
        attempt
    }

    #[test]
    fn sops_extract_expr_brackets_each_dotted_segment() {
        assert_eq!(sops_extract_expr("db"), "[\"db\"]");
        assert_eq!(sops_extract_expr("db.password"), "[\"db\"][\"password\"]");
    }

    #[test]
    fn sops_path_resolves_relative_against_the_project_root() {
        let root = Path::new("/proj");
        assert_eq!(
            sops_path(Path::new("secrets/x.yaml"), root),
            root.join("secrets/x.yaml")
        );
        // an absolute sops path is used as-is
        assert_eq!(
            sops_path(Path::new("/abs/x.yaml"), root),
            Path::new("/abs/x.yaml")
        );
    }

    #[test]
    fn run_sops_passes_decrypt_extract_and_returns_stdout() {
        let dir = TmpDir::new();
        // the fake sops records its args and prints a plaintext
        let args_log = dir.join("args");
        let sops = fake_sops(
            &dir,
            &format!(
                "printf '%s\\n' \"$*\" > {}\necho -n 'ghp-the-secret-value'",
                args_log.display()
            ),
        );
        let file = dir.join("prod.enc.yaml");
        std::fs::write(&file, "anything").unwrap();
        let got = run_sops_retrying_spawn(&sops, &file, Some("github.token"), "Authorization")
            .unwrap()
            .unwrap();
        assert_eq!(got, "ghp-the-secret-value");
        let args = std::fs::read_to_string(&args_log).unwrap();
        assert!(
            args.contains("--decrypt")
                && args.contains("--extract")
                && args.contains("[\"github\"][\"token\"]")
                && args.contains(&file.display().to_string()),
            "sops was invoked with decrypt+extract+file: {args:?}"
        );
    }

    #[test]
    fn run_sops_fails_closed_on_a_nonzero_exit_with_the_stderr_detail() {
        let dir = TmpDir::new();
        let sops = fake_sops(&dir, "echo 'no key could decrypt' >&2\nexit 1");
        let file = dir.join("prod.enc.yaml");
        std::fs::write(&file, "anything").unwrap();
        let err = run_sops_retrying_spawn(&sops, &file, Some("k"), "Authorization")
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("failed to decrypt") && err.contains("no key could decrypt"),
            "a sops failure must be a hard error folding in its stderr: {err}"
        );
    }

    #[test]
    fn run_sops_whole_file_decrypt_is_a_hard_error_when_multiline() {
        // no key → whole-file decrypt; a multi-line blob cannot be a single header value, so
        // classify_value makes it a hard error (the intended fail-closed outcome, not a bug).
        let dir = TmpDir::new();
        let sops = fake_sops(&dir, "printf 'line1\\nline2\\n'");
        let file = dir.join("prod.enc.yaml");
        std::fs::write(&file, "anything").unwrap();
        let err = run_sops_retrying_spawn(&sops, &file, None, "Authorization").unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::Other);
    }

    #[test]
    fn a_missing_sops_file_is_absent_and_falls_through() {
        // a sops source whose file does not exist is a clean absent: the chain falls through to a
        // set env fallback (no sops is ever invoked, so this is hermetic).
        std::env::set_var("OPS_TEST_EGRESS_SOPS_FB", "fallback-token-value");
        let dir = TmpDir::new();
        let (injs, _n) = resolve_injections(
            &[secret_chain(
                vec![
                    SecretSource::Sops {
                        file: PathBuf::from("does-not-exist.enc.yaml"),
                        key: Some("k".into()),
                    },
                    SecretSource::Env("OPS_TEST_EGRESS_SOPS_FB".into()),
                ],
                "h.test",
                "Authorization",
                crate::config::HeaderShape::new("Bearer ", false),
            )],
            dir.path(),
            Path::new(UNUSED_BWRAP),
        )
        .unwrap();
        std::env::remove_var("OPS_TEST_EGRESS_SOPS_FB");
        assert_eq!(injs[0].value, "Bearer fallback-token-value");
    }

    #[test]
    fn an_unreadable_sops_parent_is_a_hard_error_not_absent() {
        // `try_exists` on a path under a directory we cannot search returns an error; that must be
        // a hard failure (fail-closed), never a silent "absent" that downgrades to a weaker
        // source. (Root bypasses the permission, so the error path is unreachable there — skip.)
        if unsafe { libc::geteuid() } == 0 {
            return;
        }
        let dir = TmpDir::new();
        let locked = dir.join("locked");
        std::fs::create_dir(&locked).unwrap();
        let secret_path = locked.join("prod.enc.yaml");
        // no permissions on the parent → a stat of the child cannot determine existence
        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o000)).unwrap();
        let res = read_source(
            &SecretSource::Sops {
                file: secret_path,
                key: Some("k".into()),
            },
            "Authorization",
            dir.path(),
            Path::new(UNUSED_BWRAP),
        );
        // restore so the temp dir can be cleaned up regardless of the outcome
        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o755)).unwrap();
        let err = res.expect_err("an unreadable parent must be a hard error, not absent");
        assert!(err.to_string().contains("cannot stat"), "{err}");
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
        let (injs, needles) = resolve_injections_at_root(&[s]).unwrap();
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
        let err = resolve_injections_at_root(&[s]).unwrap_err().to_string();
        assert!(
            err.contains("OPS_TEST_EGRESS_DEFINITELY_UNSET"),
            "the error must name the missing source: {err}"
        );
    }

    #[test]
    fn an_empty_source_fails_closed() {
        // a value that is only a newline trims to empty → a clean "absent"; with no other source
        // the whole chain resolves nothing, which fails closed naming the secret.
        std::env::set_var("OPS_TEST_EGRESS_EMPTY", "\n");
        let s = secret(
            SecretSource::Env("OPS_TEST_EGRESS_EMPTY".into()),
            "h.test",
            "H",
            crate::config::HeaderShape::new("", false),
        );
        let err = resolve_injections_at_root(&[s]).unwrap_err().to_string();
        std::env::remove_var("OPS_TEST_EGRESS_EMPTY");
        assert!(
            err.contains("no source resolved") && err.contains('H'),
            "an empty source must fail closed naming the secret: {err}"
        );
    }

    #[test]
    fn a_fallback_chain_uses_the_first_resolved_source() {
        // first source absent (unset var) → falls through to the second (a file)
        std::env::remove_var("OPS_TEST_EGRESS_FALLBACK");
        let dir = TmpDir::new();
        let file = dir.join("tok");
        std::fs::write(&file, "tok3n-from-the-file\n").unwrap();
        let (injs, _n) = resolve_injections_at_root(&[secret_chain(
            vec![
                SecretSource::Env("OPS_TEST_EGRESS_FALLBACK".into()),
                SecretSource::File(file.clone()),
            ],
            "h.test",
            "Authorization",
            crate::config::HeaderShape::new("Bearer ", false),
        )])
        .unwrap();
        assert_eq!(injs[0].value, "Bearer tok3n-from-the-file");

        // once the first source IS set, it wins — the file fallback is not consulted
        std::env::set_var("OPS_TEST_EGRESS_FALLBACK", "tok3n-from-the-env");
        let (injs, _n) = resolve_injections_at_root(&[secret_chain(
            vec![
                SecretSource::Env("OPS_TEST_EGRESS_FALLBACK".into()),
                SecretSource::File(file),
            ],
            "h.test",
            "Authorization",
            crate::config::HeaderShape::new("Bearer ", false),
        )])
        .unwrap();
        std::env::remove_var("OPS_TEST_EGRESS_FALLBACK");
        assert_eq!(injs[0].value, "Bearer tok3n-from-the-env");
    }

    #[test]
    fn a_hard_error_aborts_and_does_not_fall_through_to_a_later_source() {
        // a *directory* at a file source: read_to_string fails with a non-NotFound error, so it is a
        // HARD error — the launch must fail closed even though a perfectly good second source is set,
        // proving a hard error is never silently downgraded to the fallback.
        let dir = TmpDir::new();
        std::env::set_var(
            "OPS_TEST_EGRESS_HARD_FALLBACK",
            "would-resolve-if-consulted",
        );
        let s = secret_chain(
            vec![
                SecretSource::File(dir.path().to_path_buf()),
                SecretSource::Env("OPS_TEST_EGRESS_HARD_FALLBACK".into()),
            ],
            "h.test",
            "Authorization",
            crate::config::HeaderShape::new("Bearer ", false),
        );
        let err = resolve_injections_at_root(&[s]).map(|_| ());
        std::env::remove_var("OPS_TEST_EGRESS_HARD_FALLBACK");
        assert!(
            err.is_err(),
            "an unreadable first source must fail closed, not fall through to the set second source"
        );
    }

    #[test]
    fn a_file_secret_strips_a_trailing_newline_and_rejects_an_embedded_one() {
        let dir = TmpDir::new();
        let ok = dir.join("ok");
        std::fs::write(&ok, "tok3n-from-a-file\n").unwrap();
        let (injs, _needles) = resolve_injections_at_root(&[secret(
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
        let err = resolve_injections_at_root(&[secret(
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
        let (injs, needles) = resolve_injections_at_root(&[s]).unwrap();
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
    fn a_plugin_source_resolves_host_side_through_the_runner() {
        // The full host-side path for a plugin-backed source: the runner execs the resolver under
        // bwrap, its stdout flows through the shared classify + shape, and the needles derive from
        // the same value. Skipped where the host cannot sandbox.
        let Some(bwrap) = crate::pathfind::find_on_path("bwrap")
            .filter(|_| matches!(crate::probe_userns(), crate::Userns::Ok))
        else {
            eprintln!("skipping plugin resolve: no bwrap or no capability-bearing userns");
            return;
        };
        // a fake resolver that returns the locator part of the ref as the plaintext
        let dir = TmpDir::new();
        let exec = dir.join("resolve");
        std::fs::write(&exec, "#!/bin/sh\nprintf '%s' \"${1#test://}\"\n").unwrap();
        std::fs::set_permissions(&exec, std::fs::Permissions::from_mode(0o755)).unwrap();
        let plugin = crate::plugins::ResolverPlugin {
            name: "test".into(),
            scheme: "test".into(),
            dir: dir.path().to_path_buf(),
            exec,
            sandbox: crate::plugins::SandboxGrant::default(),
            version: None,
            description: None,
        };
        let s = secret(
            SecretSource::Plugin {
                plugin,
                locator: "ghp-from-the-plugin".into(),
            },
            "api.github.com",
            "Authorization",
            crate::config::HeaderShape::new("Bearer ", false),
        );
        let (injs, needles) = resolve_injections(&[s], Path::new("/"), &bwrap).unwrap();
        assert_eq!(injs[0].value, "Bearer ghp-from-the-plugin");
        assert_eq!(needles.len(), 1);
        assert_eq!(needles[0].as_bytes(), b"ghp-from-the-plugin");
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
        let (injs, needles) = resolve_injections_at_root(&[s]).unwrap();
        std::env::remove_var("OPS_TEST_EGRESS_SHORT");
        assert_eq!(injs[0].value, "Bearer abc", "the injection still applies");
        assert!(
            needles.is_empty(),
            "a too-short secret is not redacted — it would refuse benign traffic (self-DoS)"
        );
    }
}
