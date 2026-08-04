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
const CAGE_UDS: &str = "/tmp/sbx-egress.sock";

/// Where the proxy's CA certificate appears in the cage, read-only. Under `/opt/sbx`
/// (already a cage directory for the mise plugin and shell rc), so the agent cannot
/// rewrite the trust anchor.
pub(crate) const CAGE_CA: &str = "/opt/sbx/egress-ca.pem";

/// The CA-bundle environment variables sbx sets so the cage's toolchains trust its
/// per-session CA, and — being the keys it sets — exactly the keys an untrusted project
/// is forbidden to set (see `config::is_reserved_env_key`, which consumes this list so
/// the two can never drift). All are *file*-valued and point at [`CAGE_CA`], whose bundle is
/// the per-session MITM CA followed by the base root bundle: every cage connection is sbx-minted
/// under the empty netns, so the MITM CA alone verifies the wire, but a bundle of a single cert
/// is unusual and trips tools that reject a "too small" CA file, so it is paired with the normal
/// roots to stay a full, ordinary bundle (the extra roots are inert for egress). A tool that reads
/// `/etc/ssl` directly and honors none of these simply fails closed.
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

/// A running egress session's host-side resources: the bound proxy socket, the CA file, and the
/// control socket a host-side `sbx net pending`/`sbx net log` reaches. The proxy and control threads
/// are detached and die when sbx exits (right after the cage); this guard only owns the on-disk
/// artifacts, unlinking them when the launch ends. The control socket is deliberately not among the
/// cage's binds (see [`start`]).
pub(crate) struct Egress {
    host_uds: PathBuf,
    ca_file: PathBuf,
    /// The per-session control socket (pending answers + the live egress log), present whenever the
    /// proxy runs — always `Some` here, an `Option` only so the guard's unlink stays uniform.
    control_uds: Option<PathBuf>,
    /// The session's per-host decision counters, when stats are on. The guard owns a flush on a
    /// graceful exit — but unlike the socket and CA, the session stat file is **not** removed: it
    /// persists for `sbx net stats` to aggregate after the session ends (cleared by `--reset`).
    stats: Option<Arc<super::egress_stats::EgressStats>>,
    /// The live egress event ring, shared with the proxy and control threads. Held here so a
    /// supervised launch can snapshot the run's decisions after the cage exits — the source
    /// `sbx app <name> --net-learn` synthesizes rules from. The proxy appends to it; this is a
    /// read handle.
    log: Arc<super::control::LogRing>,
}

impl Egress {
    /// A snapshot of every egress decision this session logged, newest last. Taken after the cage
    /// exits (no more requests can arrive), it is the run's full record for `--net-learn`.
    pub(crate) fn observed_events(&self) -> Vec<super::control::LogEvent> {
        // The run's full record includes muted refusals (`--all`) — a `mute` rule only suppresses a
        // live log *view*, it never removes a decision from what `--net-learn` observed.
        self.log.snapshot(None, None, true).events
    }
}

impl Drop for Egress {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.host_uds);
        let _ = std::fs::remove_file(&self.ca_file);
        if let Some(control) = &self.control_uds {
            let _ = std::fs::remove_file(control);
        }
        // A final flush for a graceful exit; the per-decision flush already keeps the file current
        // for the common case of a killed session, where this Drop never runs.
        if let Some(stats) = &self.stats {
            stats.flush_final();
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
/// an interactive `sbx run`'s pty job control unchanged. The command rides `"$@"` positionally, so
/// nothing the agent controls is ever interpolated into the script (no shell injection,
/// non-UTF-8 argv preserved); only sbx-owned ASCII store paths and the fixed port/socket
/// go into the script string.
pub(crate) fn wrap_command(
    socat: &Path,
    bash: &Path,
    cmd: Vec<OsString>,
    tcp: &[TcpDestination],
) -> Vec<OsString> {
    let preamble = format!(
        "{socat} TCP-LISTEN:{port},bind=127.0.0.1,fork,reuseaddr UNIX-CONNECT:{uds} \
         </dev/null >/dev/null 2>&1 & {tcp_forwarders}",
        socat = socat.to_string_lossy(),
        port = CAGE_PROXY_PORT,
        uds = CAGE_UDS,
        tcp_forwarders = tcp_forwarders(socat, tcp),
    );
    wrap_background(bash, &preamble, "sbx-egress-forward", cmd)
}

/// A `tcp://` destination given a place of its own inside the cage.
///
/// A raw-splice rule is only half of reaching a database: the proxy will splice the stream, but the
/// cage's single way out is an HTTP `CONNECT` proxy, and a database client does not speak one. So
/// each destination gets its own loopback address and a listener per declared port, and the name is
/// resolved to that address by the cage's `/etc/hosts` — which makes the connection the declaration
/// already describes (`-h db.internal -p 5432`) work verbatim, with no tunnel for an author to write
/// and no in-cage port number invented by sbx for them to look up.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TcpDestination {
    /// The host exactly as the rule names it — a name, or an IP literal.
    pub(crate) host: String,
    /// The declared ports, each of which gets a listener.
    pub(crate) ports: Vec<u16>,
    /// The address the cage listens on for this destination.
    pub(crate) cage_addr: std::net::Ipv4Addr,
    /// Whether `/etc/hosts` must map [`host`](Self::host) to [`cage_addr`](Self::cage_addr). False
    /// for an IP literal, which is already an address: the cage listens on the very address the
    /// client was going to dial.
    pub(crate) map_name: bool,
}

/// A `tcp://` destination that gets no listener because the port it names is **privileged**, and so
/// must be reached by asking the in-cage `CONNECT` proxy for it explicitly.
///
/// Kept apart from [`TcpPlan::skipped`]'s prose because something can still be done for it: an ssh
/// client reaches it through a generated `ProxyCommand` ([`ssh_config_contents`]), which is the
/// overwhelmingly common case — port 22.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ConnectOnly {
    /// The host exactly as the rule names it.
    pub(crate) host: String,
    /// The privileged ports declared for it.
    pub(crate) ports: Vec<u16>,
}

/// What [`tcp_destinations`] made of a policy's raw-splice rules.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub(crate) struct TcpPlan {
    pub(crate) destinations: Vec<TcpDestination>,
    /// Destinations reachable only through an explicit `CONNECT` — see [`ConnectOnly`].
    pub(crate) connect_only: Vec<ConnectOnly>,
    /// Rules that name no single port to listen on, or an address the cage cannot hold. Returned
    /// rather than warned about here so the caller decides how loudly to say it — and so this stays
    /// a pure function of the policy.
    pub(crate) skipped: Vec<String>,
}

/// Where the per-destination addresses start. `127.0.0.1` is taken — it is where the `CONNECT`
/// proxy itself listens, and where a cage's own services bind — so allocation begins after it and
/// walks up through `127.0.0.0/8`, which is loopback in full and usable inside the cage's own
/// network namespace (verified, not assumed).
const FIRST_CAGE_ADDR: u32 = 0x7f00_0002; // 127.0.0.2
const LAST_CAGE_ADDR: u32 = 0x7fff_fffe;

/// The lowest port the cage can bind. Below it a bind needs `CAP_NET_BIND_SERVICE`, and the cage
/// holds no capability — so an in-cage listener there is impossible, not merely unusual. The cage's
/// network namespace starts at the kernel default and nothing inside it can lower that.
const FIRST_UNPRIVILEGED_PORT: u16 = 1024;

/// Names the cage's synthetic `/etc/hosts` already maps to `127.0.0.1`. A destination called one of
/// these cannot be given an address of its own: the built-in line comes first in the file and wins
/// the lookup, so the listener would sit somewhere the client never dials — and it would fail
/// silently, which is the worst way for a fence to be missing. Instead the listener goes where the
/// name already points, which is also what the author meant: `tcp://localhost:5432` is the service
/// on *their* loopback, reached from a cage whose own loopback is a different machine's.
const ALREADY_LOOPBACK: &[&str] = &["localhost", "ip6-localhost", "ip6-loopback"];

/// The prefix of the cage's own hostname (`sbx-<slug>`), which the synthetic hosts file also maps.
/// A destination in that space is refused rather than quietly shadowed.
const CAGE_HOSTNAME_PREFIX: &str = "sbx-";

/// Plan a cage-side address for every `tcp://` destination in `policy`.
///
/// One address **per host**, not per rule: two ports on one database are two listeners on one
/// address, which is what a name means. Order follows the policy, so the plan is deterministic and
/// a launch is reproducible.
///
/// A rule is skipped when it names no single port (`:*`, or a range — sbx will not open a thousand
/// listeners on a guess), a **privileged** port (below 1024, which a capability-less cage cannot
/// bind), or a non-loopback IP literal, which the cage's network namespace has no way to hold.
/// Skipping is reported, never silent: the rule still governs the proxy's verdict, so what the
/// author loses is the convenience, and they need to know they must tunnel themselves.
pub(crate) fn tcp_destinations(policy: &crate::allowlist::EgressPolicy) -> TcpPlan {
    use crate::allowlist::{Layer, Ports, RuleKind};
    use std::net::{IpAddr, Ipv4Addr};

    let mut plan = TcpPlan::default();
    let mut next = FIRST_CAGE_ADDR;
    for rule in policy.allow_rules() {
        if rule.layer != Layer::L4 {
            continue;
        }
        let (host, ports, literal) = match &rule.kind {
            RuleKind::Host(h, ports) => (h.clone(), ports, None),
            RuleKind::Ip(ip, ports) => (ip.to_string(), ports, Some(*ip)),
            other => {
                plan.skipped.push(format!(
                    "{other:?} — only an exact host or address can be given a listener"
                ));
                continue;
            }
        };
        let ports = match ports {
            Ports::Ranges(ranges) if ranges.iter().all(|(lo, hi)| lo == hi) => {
                ranges.iter().map(|(p, _)| *p).collect::<Vec<u16>>()
            }
            _ => {
                plan.skipped.push(format!(
                    "tcp://{host} names no single port — a listener needs one port, not a range"
                ));
                continue;
            }
        };
        // A port below 1024 is privileged, and the cage holds no capability at all — the bind would
        // fail, leaving the name pointing at an address nothing listens on, which reads as a flat
        // "connection refused" with no clue why. Recorded apart and dropped from the listener set,
        // so a rule naming both a privileged and an ordinary port still gets a listener for the one
        // it can hold — and the privileged one still gets its `ProxyCommand`.
        let (ports, privileged): (Vec<u16>, Vec<u16>) = ports
            .into_iter()
            .partition(|p| *p >= FIRST_UNPRIVILEGED_PORT);
        if !privileged.is_empty() && !ssh_config_host_ok(&host) {
            // Not spellable in the generated ssh config, so not even ssh is wired for it: this one
            // really is on its author to tunnel, which is what `skipped` says.
            plan.skipped.push(format!(
                "tcp://{host} — a port below {FIRST_UNPRIVILEGED_PORT} needs an explicit CONNECT, \
                 and this host cannot be written into the cage's ssh config"
            ));
        } else if !privileged.is_empty() {
            match plan.connect_only.iter_mut().find(|c| c.host == host) {
                Some(existing) => {
                    for port in privileged {
                        if !existing.ports.contains(&port) {
                            existing.ports.push(port);
                        }
                    }
                }
                None => plan.connect_only.push(ConnectOnly {
                    host: host.clone(),
                    ports: privileged,
                }),
            }
        }
        if ports.is_empty() {
            continue;
        }
        // An IP literal is its own address: the cage listens where the client was going to dial. A
        // loopback one it can hold; anything else would need an address the netns does not have.
        let (addr, map_name) = match literal {
            Some(IpAddr::V4(v4)) if v4.is_loopback() => (v4, false),
            Some(_) => {
                plan.skipped.push(format!(
                    "tcp://{host} is an address the cage's network namespace cannot hold — only \
                     loopback, or use a name"
                ));
                continue;
            }
            None if ALREADY_LOOPBACK.contains(&host.as_str()) => {
                // The cage already resolves this name to its own loopback, so that is where the
                // listener goes. No new `/etc/hosts` line: adding one would sit after the built-in
                // and never be read.
                (Ipv4Addr::LOCALHOST, false)
            }
            None if host.starts_with(CAGE_HOSTNAME_PREFIX) => {
                plan.skipped.push(format!(
                    "tcp://{host} — `{CAGE_HOSTNAME_PREFIX}*` is the cage's own hostname inside the \
                     sandbox, so this name cannot be pointed anywhere else"
                ));
                continue;
            }
            None => {
                // A host already planned keeps its address; only its ports are added.
                if let Some(existing) = plan.destinations.iter_mut().find(|d| d.host == host) {
                    for port in ports {
                        if !existing.ports.contains(&port) {
                            existing.ports.push(port);
                        }
                    }
                    continue;
                }
                if next > LAST_CAGE_ADDR {
                    plan.skipped
                        .push(format!("tcp://{host} — no cage address left to give it"));
                    continue;
                }
                let addr = Ipv4Addr::from(next);
                next += 1;
                (addr, true)
            }
        };
        match plan.destinations.iter_mut().find(|d| d.host == host) {
            Some(existing) => {
                for port in ports {
                    if !existing.ports.contains(&port) {
                        existing.ports.push(port);
                    }
                }
            }
            None => plan.destinations.push(TcpDestination {
                host,
                ports,
                cage_addr: addr,
                map_name,
            }),
        }
    }
    plan
}

/// The `socat` clauses that give each planned destination its listener, for the cage preamble.
///
/// Each listener speaks `CONNECT` to the in-cage proxy port on the destination's behalf, naming the
/// host **as written**: socat sends the name rather than resolving it (verified), so the `/etc/hosts`
/// entry pointing that name at the cage address cannot loop the connection back on itself.
fn tcp_forwarders(socat: &Path, destinations: &[TcpDestination]) -> String {
    let mut out = String::new();
    for dest in destinations {
        for port in &dest.ports {
            out.push_str(&format!(
                "{socat} TCP-LISTEN:{port},bind={addr},fork,reuseaddr \
                 PROXY:127.0.0.1:{host}:{port},proxyport={proxy} </dev/null >/dev/null 2>&1 & ",
                socat = socat.to_string_lossy(),
                addr = dest.cage_addr,
                host = dest.host,
                proxy = CAGE_PROXY_PORT,
            ));
        }
    }
    out
}

/// Whether a host may be written into a generated `ssh_config` as itself.
///
/// A `Host` line is a **pattern**, not a name: a `*` or `?` in it would silently widen the block to
/// destinations the rule never named, and a newline would close the block and turn the rest of the
/// string into directives of its own — at the top level of a system-wide file, where they would
/// apply to every destination. The rule's host is already validated a layer away (an exact hostname
/// or an IP literal), but a generated file must not rest on a property proved elsewhere, so the
/// emitter admits exactly the characters a hostname or IPv4 literal is made of and refuses the rest.
/// An IPv6 literal's colons are refused here too: it would additionally need bracketing in the
/// `CONNECT` clause, which is a different spelling than the one written below.
fn ssh_config_host_ok(host: &str) -> bool {
    !host.is_empty()
        && host.len() <= 253
        && host
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_'))
}

/// The synthetic system-wide ssh client config that reaches the [`ConnectOnly`] destinations, or
/// `None` when there is nothing to write.
///
/// A privileged port cannot have an in-cage listener, so the name-resolves-and-just-works path the
/// other `tcp://` destinations get is unavailable — and port 22 is what a privileged `tcp://` rule
/// almost always names. What remains is asking the cage's `CONNECT` proxy explicitly, which ssh can
/// do on its own with a `ProxyCommand`. Writing it here means `git push` and `ssh <host>` work as
/// written, instead of every author having to rediscover the same incantation.
///
/// It goes in the **system-wide** file, which is the last one ssh consults: since the first value
/// obtained for a keyword wins, a `~/.ssh/config` block of the user's (or the agent's) own overrides
/// this one. Every directive stays inside a `Host` block, so nothing here applies to a destination
/// it does not name. This is ergonomics, not a fence — the rule the proxy enforces is the fence, and
/// it is unchanged whether the client finds this file or not.
pub(crate) fn ssh_config_contents(socat: &Path, connect_only: &[ConnectOnly]) -> Option<String> {
    let usable: Vec<&ConnectOnly> = connect_only
        .iter()
        .filter(|c| ssh_config_host_ok(&c.host))
        .collect();
    if usable.is_empty() {
        return None;
    }
    let mut out = String::from(
        "# Written by sbx for this cage, and read-only: a `tcp://<host>:<port>` rule whose port is\n\
         # below 1024 gets no in-cage listener, because that bind needs a capability the cage does\n\
         # not hold. ssh reaches those destinations through the cage's own CONNECT proxy instead —\n\
         # the same proxy, and the same rule, that governs every other request.\n\
         #\n\
         # This is the system-wide file, the last one ssh reads: a `Host` block of your own in\n\
         # ~/.ssh/config takes precedence over anything here.\n",
    );
    for dest in usable {
        let ports: Vec<String> = dest.ports.iter().map(u16::to_string).collect();
        out.push_str(&format!(
            "\n# declared as tcp://{host}:{ports}\n\
             Host {host}\n    \
             ProxyCommand {socat} - PROXY:127.0.0.1:%h:%p,proxyport={CAGE_PROXY_PORT}\n",
            host = dest.host,
            ports = ports.join(","),
            socat = socat.display(),
        ));
    }
    Some(out)
}

/// Assemble the `bash -c '<preamble> exec "$@"'` forwarder wrapper shared by the egress and
/// the host→cage forward ([`super::forward`]) socat bridges: `preamble` backgrounds the socat(s) (it must end
/// with a trailing `& `), `label` is the `$0`, and `cmd` rides `"$@"` **positionally** so nothing
/// the agent controls is ever interpolated into the script (no shell injection, non-UTF-8 argv
/// preserved). `exec` keeps the inner command the cage's main process, leaving an interactive `sbx run`'s pty
/// job control unchanged.
pub(super) fn wrap_background(
    bash: &Path,
    preamble: &str,
    label: &str,
    cmd: Vec<OsString>,
) -> Vec<OsString> {
    let script = format!("{preamble}exec \"$@\"");
    let mut out = vec![
        bash.as_os_str().to_os_string(),
        OsString::from("-c"),
        OsString::from(script),
        // `$0` — a label, not the command; the command is `$@` (the args after it).
        OsString::from(label),
    ];
    out.extend(cmd);
    out
}

/// Start the host proxy for `policy` on a fresh per-launch Unix socket, write its CA, and
/// return the cage wiring plus a guard owning the on-disk artifacts. The proxy is serving
/// before this returns (the listener is bound and a thread is accepting), so the cage's
/// first connection is never refused. The built-in allow-set is added by the
/// proxy regardless of trust, so an untrusted project can still self-equip.
///
/// `secrets` are resolved here, host-side: each source ([`SecretSource`]) is read to a
/// plaintext, validated, and shaped into the final header value, then handed to the proxy as
/// a [`HeaderInjection`]. The plaintext never crosses into the cage — only the per-host
/// injection does, applied by the proxy to matching allowed requests. A missing or malformed
/// source aborts the launch (fail-closed), so the proxy never injects an empty credential.
#[allow(clippy::too_many_arguments)]
pub(crate) fn start(
    layout: &Layout,
    policy: EgressPolicy,
    secrets: &[HeaderSecret],
    project_root: &Path,
    bwrap: &Path,
    app: Option<&str>,
    stats_enabled: bool,
    ca_bundle: Option<&Path>,
    // What distinguishes this proxy's host-side paths from another's in the same process. Keep it
    // short: these become `AF_UNIX` paths, which the kernel caps at `SUN_LEN`.
    instance: &str,
    // Where a refused request is announced, and the credential set the announcement is redacted
    // against. `None` on the paths that raise no notifications (a task's per-invocation proxy runs
    // under the session's notifier, attached by the engine).
    notify: Option<&super::notify_sink::NotifyWiring>,
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
    // relative `sops` file resolves against the project root (the `.sbx.toml`'s directory). A
    // plugin-backed source runs its resolver host-side under `bwrap` (never inside the cage).
    let (injections, redactions) = resolve_injections(secrets, project_root, bwrap)?;

    let dir = layout.data_dir().join("egress");
    DirBuilder::new().recursive(true).mode(0o700).create(&dir)?;

    // Per-**proxy** names. The pid separates concurrent launches, but one launch can stand up more
    // than one proxy at a time — a session serving two task invocations at once does exactly that —
    // and the pid alone would have them race for the same paths: both clear the path before either
    // binds, so the loser either fails with `EADDRINUSE` or has its live socket unlinked out from
    // under it. `instance` is what makes each proxy's names its own; the session's own proxy passes
    // an empty one, so its paths are unchanged. A stale file from a crashed predecessor with a
    // reused pid would block the bind, so clear it first.
    let pid = std::process::id();
    let host_uds = dir.join(format!("proxy-{pid}{instance}.sock"));
    let ca_file = dir.join(format!("ca-{pid}{instance}.pem"));
    let _ = std::fs::remove_file(&host_uds);

    // The persisted stats file outlives its session (it is aggregated later), so it must be keyed
    // by this *incarnation* — pid plus start-time ticks — not the pid alone: a later process that
    // reuses the pid would otherwise overwrite a prior session's still-wanted counters.
    let session_tag = crate::session::current_start_ticks()
        .map(|ticks| format!("{pid}-{ticks}"))
        .unwrap_or_else(|| pid.to_string());

    // Per-host decision counters for this session, keyed by the project's canonical path (the same
    // identity `sbx net stats` derives from a cwd, so a launch's record and a later read agree).
    // Disabled by `[network] stats = false`; otherwise best-effort — a project that cannot be
    // canonicalised simply records no stats, never a launch failure. The proxy flushes the file
    // after each decision (robust to a killed session); it persists after the session for aggregation.
    let stats = if stats_enabled {
        super::binds::project_identity(project_root)
            .ok()
            .map(|(_, canon)| {
                Arc::new(super::egress_stats::EgressStats::new(
                    dir.join(format!("stats-{session_tag}")),
                    canon.display().to_string(),
                    app.map(str::to_string),
                ))
            })
    } else {
        None
    };

    // Publish the resolved needles to the notifier before any request can be refused, so no
    // announcement can ever be composed against an empty set. The notifier is stood up earlier than
    // this (the exec supervisor needs it first) and nothing is refused in between.
    //
    // Added to rather than replacing what is there: one session's notifier also serves the
    // per-invocation proxies its declared tasks stand up, and each of those resolves its own
    // credentials. Replacing would let a task's set erase the session's — a credential that then
    // reaches a notification body unredacted. The union is bounded by the number of *distinct*
    // credentials declared, not by the number of invocations, because an identical needle is
    // recognised and skipped.
    if let Some(wiring) = notify {
        if let Ok(mut shared) = wiring.needles.write() {
            for needle in &redactions {
                let known = shared
                    .iter()
                    .any(|n| n.name() == needle.name() && n.as_bytes() == needle.as_bytes());
                if !known {
                    shared.push(needle.clone());
                }
            }
        }
    }

    // The traffic capture (`[network] capture`), off unless a trusted layer asked for it. It holds
    // the same needles the proxy redacts with, so every captured byte is masked on the way in.
    let capture_level = policy.capture_level();
    let capture = capture_level.captures().then(|| {
        Arc::new(super::control::CaptureRing::new(
            super::control::CaptureCaps::new(capture_level, policy.capture_body_kb()),
            redactions.clone(),
        ))
    });

    let mut ctx = ProxyCtx::new(Arc::new(Ca::ephemeral()?), policy)?
        .with_injections(injections)
        .with_redactions(redactions)
        .with_app(app.map(str::to_string));
    if let Some(capture) = &capture {
        ctx = ctx.with_capture(capture.clone());
    }
    if let Some(wiring) = notify {
        ctx = ctx.with_notifier(Arc::clone(&wiring.notifier));
    }

    // Stand up the control socket the host-side `sbx net pending`/`sbx net log`/`sbx net allow
    // --session` reach. It lives under the `0700` egress dir beside `<data>` and is **never** bound
    // into the cage (only the proxy socket and the CA cross in) — in Mode B the in-cage agent must not
    // answer its own asks, read its own log, or load its own rules. One pending queue + manual-rule
    // overlay + event ring are shared between the proxy and the control thread. The overlay is wired
    // into the proxy for **every** filtering posture (not only `ask`): the proxy folds it into its
    // effective policy per request, so `sbx net allow|deny --session` takes effect on an allowlist or
    // denylist session too, not just `ask`. Only `ask` ever parks into the pending queue, but wiring
    // it unconditionally is harmless (a non-ask posture never parks), and the ring is always wired so
    // every proxy session has a live log.
    // The event ring is created here, before the control block, so a clone can be kept on the guard
    // for `--net-learn` to snapshot after the run — the control thread and the proxy get their own
    // clones of the same `Arc`.
    let log = Arc::new(super::control::LogRing::new(super::control::LOG_RING_CAP));
    let control_uds = {
        let control_uds = dir.join(format!("control-{pid}{instance}.sock"));
        let _ = std::fs::remove_file(&control_uds);
        let pending = Arc::new(super::control::PendingState::new());
        let manual = Arc::new(super::control::ManualRules::new());
        // The live flow registry — the proxy and the control thread share the same `Arc` (the proxy
        // registers a flow per open tunnel; `sbx net live` reads them over the control socket).
        let flows = Arc::new(super::control::FlowRegistry::new());
        ctx = ctx.with_control(pending.clone(), manual.clone());
        ctx = ctx.with_log(log.clone());
        ctx = ctx.with_flows(flows.clone());
        // Bind+listen here, before the serving thread, so the control plane is reachable the moment
        // the launch is up — never a race with the first `sbx net pending`/`sbx net log`.
        let control_listener = UnixListener::bind(&control_uds)?;
        let control_log = log.clone();
        let control_capture = capture.clone();
        std::thread::spawn(move || {
            let _ = super::control::serve(
                control_listener,
                pending,
                manual,
                control_log,
                flows,
                control_capture,
            );
        });
        Some(control_uds)
    };
    if let Some(stats) = &stats {
        ctx = ctx.with_stats(stats.clone());
    }
    let ctx = Arc::new(ctx);

    // Write the CA bundle owner-only, outside every writable mount, then bind it read-only — the
    // agent gets a trust anchor it cannot rewrite. The bundle is the per-session MITM CA FOLLOWED BY
    // the base root bundle (`ca_bundle`, the same Mozilla roots sbx binds at /etc/ssl): every allowed
    // egress is MITM'd and so presents the MITM CA, but a bundle of a single cert is unusual and trips
    // tools that heuristically reject a "too small" CA file (e.g. a client that sanity-checks
    // `certifi`), so pairing it with the normal roots keeps the file a full, ordinary bundle.
    //
    // The extra roots authenticate nothing here: the MITM CA is what verifies the wire, and the
    // empty netns permits no un-proxied TLS. They are not free, though, and reading otherwise sends
    // the next reader looking for this cost somewhere else. The file runs to ~460 KB and 120
    // certificates, and a client that loads its store per connection pays for all of it — measured
    // in a cage, `curl` spends ~13 ms in its TLS phase against ~1.4 ms when pointed at the MITM CA
    // alone. Trimming it would be a trade rather than a fix: a `tcp://` rule and a shared-network
    // launch both end TLS at the real server, where these roots are what verifies it.
    {
        use std::io::Write;
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&ca_file)?;
        f.write_all(ctx.ca_cert_pem().as_bytes())?;
        if let Some(bundle) = ca_bundle {
            if let Ok(roots) = std::fs::read(bundle) {
                f.write_all(b"\n")?;
                f.write_all(&roots)?;
            }
        }
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
    // sbx sets `no_proxy` itself; it being reserved-for-untrusted does not stop that.
    let no_proxy = "localhost,127.0.0.1,::1".to_string();
    let mut env = vec![
        ("http_proxy".to_string(), proxy_url.clone()),
        ("https_proxy".to_string(), proxy_url.clone()),
        ("HTTP_PROXY".to_string(), proxy_url.clone()),
        ("HTTPS_PROXY".to_string(), proxy_url.clone()),
        // WebSocket proxy vars. A client library resolves a proxy per URL *scheme*, so a `ws://` or
        // `wss://` connection does NOT match `http_proxy`/`https_proxy` — without a `ws_proxy`/
        // `wss_proxy` it connects directly, which in the empty netns fails at DNS ("Temporary failure
        // in name resolution"). The sbx proxy is an HTTP CONNECT proxy, which is exactly what a WS
        // client tunnels through, so it is the correct value here too. Agnostic — any WebSocket client
        // that honors these (aiohttp `trust_env`, etc.) then routes through the proxy.
        ("ws_proxy".to_string(), proxy_url.clone()),
        ("wss_proxy".to_string(), proxy_url.clone()),
        ("WS_PROXY".to_string(), proxy_url.clone()),
        ("WSS_PROXY".to_string(), proxy_url),
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
            stats,
            log,
        },
        Wiring { binds, env },
    ))
}

/// The shortest value worth substituting, shared with the text-sink substituter so the wire and a
/// task's output can never disagree on the threshold. Below it the injection still applies — only
/// the leak tripwire is skipped, and loudly (a silent skip would be a false-confidence trap).
use super::redact::REDACT_MIN_LEN;

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
    let trimmed = resolve_chain(&secret.sources, &secret.header, project_root, bwrap)?;
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
        // Every spelling of one credential carries that credential's logical name: the wire path
        // ignores it (it substitutes length-preserving `*`), a text sink renders `${name}`.
        secret
            .shape
            .needles(trimmed)
            .into_iter()
            .map(|bytes| SecretNeedle::named(&secret.name, bytes))
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

/// Read a credential's source chain host-side and return the first value that resolves, trimmed.
///
/// Try each source in order, the first that resolves winning. A clean "absent" (an unset variable, a
/// missing file, an empty value) falls through to the next source; a HARD error (a file that exists
/// but cannot be read, a value carrying a header-splitting byte) aborts fail-closed — it must never
/// silently downgrade to a weaker fallback source. `label` names the consumer in an error message (a
/// header name for a wire injection, a variable name for a task credential), so a failure says which
/// declaration it belongs to without ever naming a value.
///
/// Shared with the task engine, which resolves a credential per invocation: one resolver path for
/// both consumers, so a source that works for an injection works for a task and vice versa.
pub(crate) fn resolve_chain(
    sources: &[crate::config::SecretSource],
    label: &str,
    project_root: &Path,
    bwrap: &Path,
) -> io::Result<String> {
    let mut tried = Vec::with_capacity(sources.len());
    for source in sources {
        tried.push(source.describe());
        if let Some(value) = read_source(source, label, project_root, bwrap)? {
            return Ok(value);
        }
    }
    Err(io::Error::other(format!(
        "no source resolved the secret for `{label}` (tried: {})",
        tried.join(", ")
    )))
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

/// Resolve a sops file path: a relative one against the project root (the `.sbx.toml`'s directory),
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

/// Strip the single trailing line ending a source's raw output commonly carries and which is not
/// part of the secret (a file's last newline, a program's `echo`). The one definition of that rule:
/// the resolver runner reads it too, so "this source resolved nothing" means the same thing when a
/// value is classified and when a plugin's silence is explained.
pub(super) fn strip_trailing_line_ending(s: &str) -> &str {
    let s = s.strip_suffix('\n').unwrap_or(s);
    s.strip_suffix('\r').unwrap_or(s)
}

/// Trim and classify a value read from a source: strip a single trailing line ending (a file
/// commonly ends in one), then an empty result is a clean **absent** (`Ok(None)` — fall through to
/// the next source), while an embedded CR/LF/NUL is a **hard** error (`Err`) — it cannot be an HTTP
/// header value, and a found-but-malformed secret must fail closed rather than fall through.
fn classify_value(raw: String, header: &str, label: &str) -> io::Result<Option<String>> {
    let trimmed = strip_trailing_line_ending(&raw);
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
            &[],
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
        assert_eq!(argv[3], OsString::from("sbx-egress-forward"));
        assert_eq!(argv[4], OsString::from("jq"));
        assert_eq!(argv[5], OsString::from("--version"));
    }

    #[test]
    fn start_serves_the_proxy_and_wires_the_cage_then_cleans_up() {
        let data = TmpDir::new();
        let layout = Layout::under(data.path());
        std::fs::create_dir_all(layout.data_dir()).unwrap();

        // A stand-in base root bundle, to prove the injected CA file pairs the MITM CA with the roots.
        let roots = data.path().join("roots.pem");
        std::fs::write(
            &roots,
            "# sbx-test-base-roots\n-----BEGIN CERTIFICATE-----\nZm9v\n-----END CERTIFICATE-----\n",
        )
        .unwrap();

        let (guard, wiring) = start(
            &layout,
            EgressPolicy::default(),
            &[],
            Path::new("/"),
            Path::new(UNUSED_BWRAP),
            None,
            false,
            Some(roots.as_path()),
            "-1",
            None,
        )
        .expect("start the egress proxy");

        // the proxy address reaches the in-cage forwarder — for HTTP and WebSocket schemes alike (a
        // WS client resolves its proxy by URL scheme, so it needs its own ws/wss vars, not http/https).
        let url = format!("http://127.0.0.1:{CAGE_PROXY_PORT}");
        for k in [
            "http_proxy",
            "https_proxy",
            "HTTP_PROXY",
            "HTTPS_PROXY",
            "ws_proxy",
            "wss_proxy",
            "WS_PROXY",
            "WSS_PROXY",
        ] {
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
        let ca_pem = std::fs::read_to_string(&ca.src).unwrap();
        assert!(ca_pem.contains("BEGIN CERTIFICATE"));
        // it is a full bundle: the per-session MITM CA PLUS the base roots (a lone cert trips tools
        // that reject a "too small" CA bundle).
        assert!(
            ca_pem.contains("# sbx-test-base-roots"),
            "the CA file must append the base root bundle to the MITM CA"
        );

        let (host_uds, ca_file) = (guard.host_uds.clone(), guard.ca_file.clone());
        // Every proxy posture — even this allowlist (non-ask) one — now stands up the control
        // socket, because it also serves the live egress log (`sbx net logs`). It lives host-side…
        let control = guard
            .control_uds
            .clone()
            .expect("a proxy session stands up the control socket for the live log");
        assert!(
            control.exists(),
            "the control socket must be bound host-side"
        );
        // …and is **never** bound into the cage (only the proxy socket and the CA cross in).
        assert!(
            !wiring
                .binds
                .iter()
                .any(|b| b.src == control || b.dest == control),
            "the control socket must not be a cage bind"
        );
        drop(guard);
        // the guard unlinks every artifact when the launch ends — the new control socket included
        assert!(!host_uds.exists(), "the socket must be unlinked on drop");
        assert!(!ca_file.exists(), "the CA file must be unlinked on drop");
        assert!(
            !control.exists(),
            "the control socket must be unlinked on drop"
        );
    }

    /// The load-bearing security property of the `ask` posture: the control socket — over which a
    /// request is answered — is created host-side but **never** bound into the cage. In Mode B the
    /// in-cage agent is the adversary; if it could reach this socket it could answer its own asks.
    /// Only the proxy socket and the CA cross in.
    fn tcp_policy(entries: &[&str]) -> crate::allowlist::EgressPolicy {
        let rules = entries
            .iter()
            .map(|e| crate::allowlist::classify(e).expect("a valid rule"))
            .collect();
        crate::allowlist::EgressPolicy::new(rules, Vec::new())
    }

    /// Each destination gets its own address, and a host declared on two ports gets one address with
    /// two listeners — because that is what a name means. `127.0.0.1` is never handed out: the
    /// CONNECT proxy is already there.
    #[test]
    fn each_tcp_host_gets_one_address_and_a_listener_per_port() {
        let plan = tcp_destinations(&tcp_policy(&[
            "tcp://db.internal:5432",
            "tcp://db.internal:5433",
            "tcp://cache.internal:6379",
        ]));

        assert!(plan.skipped.is_empty(), "{:?}", plan.skipped);
        assert_eq!(plan.destinations.len(), 2, "{:?}", plan.destinations);
        let db = &plan.destinations[0];
        assert_eq!(db.host, "db.internal");
        assert_eq!(db.ports, vec![5432, 5433], "one address, both ports");
        assert_eq!(db.cage_addr.to_string(), "127.0.0.2");
        assert!(db.map_name, "a name has to resolve to the address");
        let cache = &plan.destinations[1];
        assert_eq!(
            cache.cage_addr.to_string(),
            "127.0.0.3",
            "a distinct address"
        );
        assert_ne!(
            db.cage_addr.to_string(),
            "127.0.0.1",
            "the proxy already listens there"
        );
    }

    /// A loopback address is its own answer: the cage listens exactly where the client was going to
    /// dial, and no name is invented for it.
    #[test]
    fn a_loopback_literal_is_listened_on_directly() {
        let plan = tcp_destinations(&tcp_policy(&["tcp://127.0.0.1:55432"]));

        assert!(plan.skipped.is_empty(), "{:?}", plan.skipped);
        let dest = &plan.destinations[0];
        assert_eq!(dest.cage_addr.to_string(), "127.0.0.1");
        assert!(!dest.map_name, "an address needs no `/etc/hosts` entry");
    }

    /// A privileged port cannot be bound by a capability-less cage, so it gets no listener — and is
    /// recorded as reachable only through an explicit CONNECT. Measured, not assumed: in a live cage
    /// a `tcp://github.com:22` rule left the mapped name pointing at an address nothing listened on,
    /// and ssh reported a bare "connection refused". A rule naming an ordinary port beside it keeps
    /// that one, so a host declared on both is served both ways.
    #[test]
    fn a_privileged_port_gets_no_listener_but_a_connect_route() {
        let plan = tcp_destinations(&tcp_policy(&["tcp://github.com:22,2200"]));

        let dest = &plan.destinations[0];
        assert_eq!(
            dest.ports,
            vec![2200],
            "only the bindable port is listened on"
        );
        assert!(
            plan.skipped.is_empty(),
            "ssh is wired for it, so there is nothing to warn about: {:?}",
            plan.skipped
        );
        assert_eq!(plan.connect_only.len(), 1, "{:?}", plan.connect_only);
        assert_eq!(plan.connect_only[0].host, "github.com");
        assert_eq!(plan.connect_only[0].ports, vec![22]);

        // A rule with nothing but a privileged port yields no destination at all — and so no
        // `/etc/hosts` line, which is the honest outcome: the name does not resolve rather than
        // resolving to a dead address. The CONNECT route is what carries it instead.
        let plan = tcp_destinations(&tcp_policy(&["tcp://github.com:22"]));
        assert!(plan.destinations.is_empty());
        assert_eq!(plan.connect_only.len(), 1, "{:?}", plan.connect_only);
    }

    /// The generated ssh config sends exactly the CONNECT-only hosts through the cage's proxy, each
    /// inside its own `Host` block — a directive at the top level of a system-wide file would apply
    /// to every destination, including the ones with a listener of their own.
    #[test]
    fn the_generated_ssh_config_routes_only_the_declared_hosts() {
        let plan = tcp_destinations(&tcp_policy(&[
            "tcp://github.com:22",
            "tcp://db.internal:5432",
            "tcp://192.168.1.10:22",
        ]));
        let socat = Path::new("/nix/store/abc-socat/bin/socat");
        let cfg = ssh_config_contents(socat, &plan.connect_only).expect("a config");

        assert!(cfg.contains("\nHost github.com\n"), "{cfg}");
        assert!(
            cfg.contains("\nHost 192.168.1.10\n"),
            "an address too: {cfg}"
        );
        assert!(
            !cfg.contains("db.internal"),
            "a host with a listener needs no ProxyCommand: {cfg}"
        );
        assert!(
            cfg.contains(&format!(
                "ProxyCommand {} - PROXY:127.0.0.1:%h:%p,proxyport={CAGE_PROXY_PORT}",
                socat.display()
            )),
            "{cfg}"
        );
        for line in cfg.lines() {
            let directive = line.trim_start();
            assert!(
                line.starts_with('#')
                    || line.trim().is_empty()
                    || line.starts_with("Host ")
                    || (line.starts_with(' ') && directive.starts_with("ProxyCommand ")),
                "every directive stays inside a Host block: {line:?}"
            );
        }

        // Nothing to route means no file at all, rather than one with only a header in it.
        assert!(ssh_config_contents(socat, &[]).is_none());
    }

    /// A `Host` line is a *pattern*: a wildcard in it would widen the route to destinations the rule
    /// never named, and a newline would close the block and turn what follows into top-level
    /// directives. The emitter admits only what a hostname or IPv4 literal is made of — checked here
    /// against the emitter itself, not against the parser one layer away that is supposed to have
    /// rejected these already.
    #[test]
    fn a_host_that_is_not_plainly_a_name_is_never_written_into_the_config() {
        for host in [
            "*",
            "*.example.com",
            "gh?b.com",
            "github.com\nHost *",
            "github.com ProxyJump evil",
            "::1",
            "",
        ] {
            assert!(!ssh_config_host_ok(host), "{host:?} must be refused");
            let only = [ConnectOnly {
                host: host.to_string(),
                ports: vec![22],
            }];
            assert!(
                ssh_config_contents(Path::new("/nix/store/abc-socat/bin/socat"), &only).is_none(),
                "{host:?} must reach no config"
            );
        }
        assert!(ssh_config_host_ok("github.com"));
        assert!(ssh_config_host_ok("192.168.1.10"));
        assert!(ssh_config_host_ok("build-01_internal"));
    }

    /// A destination the config cannot spell falls back to the plain report: not even ssh is wired
    /// for it, so its author has to know they are on their own.
    #[test]
    fn an_unspellable_privileged_host_is_reported_instead() {
        let plan = tcp_destinations(&tcp_policy(&["tcp://[::1]:22"]));

        assert!(plan.connect_only.is_empty(), "{:?}", plan.connect_only);
        assert_eq!(plan.skipped.len(), 1, "{:?}", plan.skipped);
        assert!(plan.skipped[0].contains("::1"), "{:?}", plan.skipped);
    }

    /// What cannot be given a listener is reported, never dropped in silence: the rule still governs
    /// the proxy, so the author has to know the convenience is what they lost.
    #[test]
    fn a_rule_with_no_single_port_is_reported_rather_than_guessed() {
        let plan = tcp_destinations(&tcp_policy(&["tcp://db.internal:*"]));

        assert!(plan.destinations.is_empty());
        assert_eq!(plan.skipped.len(), 1, "{:?}", plan.skipped);
        assert!(
            plan.skipped[0].contains("db.internal"),
            "{:?}",
            plan.skipped
        );
    }

    /// An inspected rule is not a raw splice and gets no listener — the tools that use those speak
    /// to the proxy directly.
    #[test]
    fn only_raw_splice_rules_get_a_listener() {
        let plan = tcp_destinations(&tcp_policy(&[
            "api.example.com",
            "http://plain.example.com",
        ]));
        assert!(plan.destinations.is_empty(), "{:?}", plan.destinations);
        assert!(plan.skipped.is_empty(), "{:?}", plan.skipped);
    }

    /// `localhost` is the name a developer most naturally writes for a service on their own machine,
    /// and the cage already maps it — to a *different* machine's loopback. So the listener goes where
    /// the name already points, rather than to an address of its own that the name would never
    /// resolve to. Getting this wrong fails silently, which is why it is pinned here.
    #[test]
    fn localhost_listens_where_the_cage_already_resolves_it() {
        let plan = tcp_destinations(&tcp_policy(&["tcp://localhost:5432"]));

        assert!(plan.skipped.is_empty(), "{:?}", plan.skipped);
        let dest = &plan.destinations[0];
        assert_eq!(
            dest.cage_addr.to_string(),
            "127.0.0.1",
            "the built-in `localhost` line wins the lookup, so the listener must be there"
        );
        assert!(
            !dest.map_name,
            "a second `localhost` line would sit after the built-in one and never be read"
        );
    }

    /// The cage's own hostname lives in `sbx-*`, which the synthetic hosts file maps. A destination
    /// there is refused out loud rather than pointed somewhere the name will not follow.
    #[test]
    fn a_destination_in_the_cages_own_name_space_is_refused() {
        let plan = tcp_destinations(&tcp_policy(&["tcp://sbx-myproject:5432"]));

        assert!(plan.destinations.is_empty(), "{:?}", plan.destinations);
        assert_eq!(plan.skipped.len(), 1);
        assert!(
            plan.skipped[0].contains("sbx-myproject"),
            "{:?}",
            plan.skipped
        );
    }

    /// The preamble carries a listener per port, each speaking CONNECT for the host **as written**.
    /// The name matters: it is what the proxy matches its allowlist on, and socat sends it rather
    /// than resolving it — which is the only reason pointing that name at the cage address in
    /// `/etc/hosts` does not send the connection back to the listener itself.
    #[test]
    fn the_preamble_forwards_each_destination_by_name() {
        let plan = tcp_destinations(&tcp_policy(&["tcp://db.internal:5432"]));
        let argv = wrap_command(
            Path::new("/nix/store/abc-socat/bin/socat"),
            Path::new("/nix/store/def-bash/bin/bash"),
            vec![OsString::from("psql")],
            &plan.destinations,
        );
        let script = argv[2].to_string_lossy().into_owned();

        assert!(
            script.contains("TCP-LISTEN:5432,bind=127.0.0.2"),
            "the listener must sit where the name resolves: {script}"
        );
        assert!(
            script.contains("PROXY:127.0.0.1:db.internal:5432,proxyport=18043"),
            "the CONNECT must name the host, not the cage address: {script}"
        );
        assert!(
            script.contains(&format!("TCP-LISTEN:{CAGE_PROXY_PORT}")),
            "the proxy bridge itself must still be there: {script}"
        );
    }

    #[test]
    fn the_ask_control_socket_is_created_but_never_bound_into_the_cage() {
        let data = TmpDir::new();
        let layout = Layout::under(data.path());
        std::fs::create_dir_all(layout.data_dir()).unwrap();

        let ask = EgressPolicy::default().with_default(crate::allowlist::DefaultAction::Ask);
        let (guard, wiring) = start(
            &layout,
            ask,
            &[],
            Path::new("/"),
            Path::new(UNUSED_BWRAP),
            None,
            false,
            None,
            "-2",
            None,
        )
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

    #[test]
    fn the_stats_toggle_controls_whether_a_session_file_is_written() {
        // Whether any per-session stats file (`stats-<pid>-<ticks>`) was written under the dir.
        let has_stats_file = |layout: &Layout| {
            std::fs::read_dir(layout.data_dir().join("egress"))
                .map(|entries| {
                    entries.flatten().any(|e| {
                        e.file_name()
                            .to_str()
                            .is_some_and(|n| n.starts_with("stats-") && !n.contains(".tmp."))
                    })
                })
                .unwrap_or(false)
        };

        // stats OFF → no session file, even after the guard's final flush on drop.
        let off = TmpDir::new();
        let layout = Layout::under(off.path());
        std::fs::create_dir_all(layout.data_dir()).unwrap();
        let (guard, _w) = start(
            &layout,
            EgressPolicy::default(),
            &[],
            Path::new("/"),
            Path::new(UNUSED_BWRAP),
            None,
            false,
            None,
            "-3",
            None,
        )
        .expect("start with stats off");
        drop(guard);
        assert!(
            !has_stats_file(&layout),
            "stats off must write no session file"
        );

        // stats ON → the guard's final flush writes the session file (a separate data dir).
        let on = TmpDir::new();
        let layout = Layout::under(on.path());
        std::fs::create_dir_all(layout.data_dir()).unwrap();
        let (guard, _w) = start(
            &layout,
            EgressPolicy::default(),
            &[],
            Path::new("/"),
            Path::new(UNUSED_BWRAP),
            None,
            true,
            None,
            "-4",
            None,
        )
        .expect("start with stats on");
        drop(guard);
        assert!(
            has_stats_file(&layout),
            "stats on must write a session file"
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
            name: to.to_string(),
            description: None,
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
        std::env::set_var("SBX_TEST_EGRESS_SSBX_FB", "fallback-token-value");
        let dir = TmpDir::new();
        let (injs, _n) = resolve_injections(
            &[secret_chain(
                vec![
                    SecretSource::Sops {
                        file: PathBuf::from("does-not-exist.enc.yaml"),
                        key: Some("k".into()),
                    },
                    SecretSource::Env("SBX_TEST_EGRESS_SSBX_FB".into()),
                ],
                "h.test",
                "Authorization",
                crate::config::HeaderShape::new("Bearer ", false),
            )],
            dir.path(),
            Path::new(UNUSED_BWRAP),
        )
        .unwrap();
        std::env::remove_var("SBX_TEST_EGRESS_SSBX_FB");
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
        std::env::set_var("SBX_TEST_EGRESS_TOKEN", "s3cret-token-value");
        let s = secret(
            SecretSource::Env("SBX_TEST_EGRESS_TOKEN".into()),
            "api.github.com",
            "Authorization",
            crate::config::HeaderShape::new("Bearer ", false),
        );
        let (injs, needles) = resolve_injections_at_root(&[s]).unwrap();
        std::env::remove_var("SBX_TEST_EGRESS_TOKEN");
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
            SecretSource::Env("SBX_TEST_EGRESS_DEFINITELY_UNSET".into()),
            "h.test",
            "Authorization",
            crate::config::HeaderShape::new("Bearer ", false),
        );
        let err = resolve_injections_at_root(&[s]).unwrap_err().to_string();
        assert!(
            err.contains("SBX_TEST_EGRESS_DEFINITELY_UNSET"),
            "the error must name the missing source: {err}"
        );
    }

    #[test]
    fn an_empty_source_fails_closed() {
        // a value that is only a newline trims to empty → a clean "absent"; with no other source
        // the whole chain resolves nothing, which fails closed naming the secret.
        std::env::set_var("SBX_TEST_EGRESS_EMPTY", "\n");
        let s = secret(
            SecretSource::Env("SBX_TEST_EGRESS_EMPTY".into()),
            "h.test",
            "H",
            crate::config::HeaderShape::new("", false),
        );
        let err = resolve_injections_at_root(&[s]).unwrap_err().to_string();
        std::env::remove_var("SBX_TEST_EGRESS_EMPTY");
        assert!(
            err.contains("no source resolved") && err.contains('H'),
            "an empty source must fail closed naming the secret: {err}"
        );
    }

    #[test]
    fn a_fallback_chain_uses_the_first_resolved_source() {
        // first source absent (unset var) → falls through to the second (a file)
        std::env::remove_var("SBX_TEST_EGRESS_FALLBACK");
        let dir = TmpDir::new();
        let file = dir.join("tok");
        std::fs::write(&file, "tok3n-from-the-file\n").unwrap();
        let (injs, _n) = resolve_injections_at_root(&[secret_chain(
            vec![
                SecretSource::Env("SBX_TEST_EGRESS_FALLBACK".into()),
                SecretSource::File(file.clone()),
            ],
            "h.test",
            "Authorization",
            crate::config::HeaderShape::new("Bearer ", false),
        )])
        .unwrap();
        assert_eq!(injs[0].value, "Bearer tok3n-from-the-file");

        // once the first source IS set, it wins — the file fallback is not consulted
        std::env::set_var("SBX_TEST_EGRESS_FALLBACK", "tok3n-from-the-env");
        let (injs, _n) = resolve_injections_at_root(&[secret_chain(
            vec![
                SecretSource::Env("SBX_TEST_EGRESS_FALLBACK".into()),
                SecretSource::File(file),
            ],
            "h.test",
            "Authorization",
            crate::config::HeaderShape::new("Bearer ", false),
        )])
        .unwrap();
        std::env::remove_var("SBX_TEST_EGRESS_FALLBACK");
        assert_eq!(injs[0].value, "Bearer tok3n-from-the-env");
    }

    #[test]
    fn a_hard_error_aborts_and_does_not_fall_through_to_a_later_source() {
        // a *directory* at a file source: read_to_string fails with a non-NotFound error, so it is a
        // HARD error — the launch must fail closed even though a perfectly good second source is set,
        // proving a hard error is never silently downgraded to the fallback.
        let dir = TmpDir::new();
        std::env::set_var(
            "SBX_TEST_EGRESS_HARD_FALLBACK",
            "would-resolve-if-consulted",
        );
        let s = secret_chain(
            vec![
                SecretSource::File(dir.path().to_path_buf()),
                SecretSource::Env("SBX_TEST_EGRESS_HARD_FALLBACK".into()),
            ],
            "h.test",
            "Authorization",
            crate::config::HeaderShape::new("Bearer ", false),
        );
        let err = resolve_injections_at_root(&[s]).map(|_| ());
        std::env::remove_var("SBX_TEST_EGRESS_HARD_FALLBACK");
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
        std::env::set_var("SBX_TEST_EGRESS_BASIC", "alice:correct-horse");
        let s = secret(
            SecretSource::Env("SBX_TEST_EGRESS_BASIC".into()),
            "h.test",
            "Authorization",
            crate::config::HeaderShape::new("Basic ", true),
        );
        let (injs, needles) = resolve_injections_at_root(&[s]).unwrap();
        std::env::remove_var("SBX_TEST_EGRESS_BASIC");
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
    fn a_plugin_that_resolves_nothing_falls_through_to_the_next_source() {
        // A resolver that exits 0 with nothing is an *absent*, even when it explains itself on
        // stderr — the diagnostic the runner relays must not turn a fall-through into a failure,
        // or a plugin could never be anything but the last source in a chain.
        let Some(bwrap) = crate::pathfind::find_on_path("bwrap")
            .filter(|_| matches!(crate::probe_userns(), crate::Userns::Ok))
        else {
            eprintln!("skipping plugin fall-through: no bwrap or no capability-bearing userns");
            return;
        };
        let dir = TmpDir::new();
        let exec = dir.join("resolve");
        std::fs::write(
            &exec,
            "#!/bin/sh\necho \"no entry for ${1#test://}\" >&2\nexit 0\n",
        )
        .unwrap();
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
        std::env::set_var("SBX_TEST_CHAIN_FALLBACK", "from-the-next-source");
        let value = resolve_chain(
            &[
                SecretSource::Plugin {
                    plugin,
                    locator: "missing".into(),
                },
                SecretSource::Env("SBX_TEST_CHAIN_FALLBACK".into()),
            ],
            "Authorization",
            Path::new("/"),
            &bwrap,
        );
        std::env::remove_var("SBX_TEST_CHAIN_FALLBACK");
        assert_eq!(value.unwrap(), "from-the-next-source");
    }

    #[test]
    fn a_short_secret_is_injected_but_not_redacted() {
        std::env::set_var("SBX_TEST_EGRESS_SHORT", "abc"); // 3 bytes, below REDACT_MIN_LEN
        let s = secret(
            SecretSource::Env("SBX_TEST_EGRESS_SHORT".into()),
            "h.test",
            "Authorization",
            crate::config::HeaderShape::new("Bearer ", false),
        );
        let (injs, needles) = resolve_injections_at_root(&[s]).unwrap();
        std::env::remove_var("SBX_TEST_EGRESS_SHORT");
        assert_eq!(injs[0].value, "Bearer abc", "the injection still applies");
        assert!(
            needles.is_empty(),
            "a too-short secret is not redacted — it would refuse benign traffic (self-DoS)"
        );
    }
}
