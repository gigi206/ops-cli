//! The proxy's running context and the policy it evaluates against.
//!
//! [`ProxyCtx`] holds the cert machinery, the upstream-validation configs, the resolved (and
//! built-in-augmented) egress policy, the name resolver, the per-socket timeout, the host-side
//! credential injections and redaction needles, and the live control/stats/log/flow handles a
//! launch attaches. [`union_with_builtin`] augments a user policy with the always-on self-equip
//! allow-set, and [`effective_policy`] folds a live `--session` overlay onto the config policy.

use std::io;
use std::sync::atomic::AtomicUsize;
use std::sync::Arc;
use std::time::Duration;

use rustls::{ClientConfig, ServerConfig};

use crate::allowlist::{self, EgressPolicy, Rule};
use crate::sandbox::egress_stats::{EgressStats, StatKind};

use super::ca::{ensure_provider, upstream_config, upstream_config_h2, Ca, CertResolver};
use super::dns::{caching_resolver, Resolver};
use super::inject::{HeaderInjection, SecretNeedle};
use super::redact_in_place;

/// The hosts of the built-in self-equip allow-set, in allowlist-entry syntax. Sourced once so
/// the policy (`builtin_allow_rules`) and the `sbx config` display can never drift.
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
/// shown in `sbx config`, so it is never a silent allowance.
pub(crate) fn builtin_allow_rules() -> Vec<Rule> {
    builtin_allow_hosts()
        .iter()
        .map(|e| allowlist::classify(e).expect("a built-in self-equip entry must be a valid rule"))
        .collect()
}

/// The running context of the egress proxy: the cert machinery, the upstream-validation config,
/// the resolved (and built-in-augmented) policy, the resolver, the per-socket timeout, and the
/// host-side credential injections.
pub(crate) struct ProxyCtx {
    pub(super) ca: Arc<Ca>,
    pub(super) server_config: Arc<ServerConfig>,
    /// The cage-facing TLS config for a designated `[network] http2` host: identical to
    /// `server_config` but advertising ALPN `h2` only, so the client speaks HTTP/2 (gRPC). Built
    /// once; used solely by the h2 branch ([`h2mitm`]).
    pub(super) server_config_h2: Arc<ServerConfig>,
    pub(super) upstream: Arc<ClientConfig>,
    /// The upstream-validation config for the h2 branch: like `upstream` but advertising ALPN `h2`,
    /// so the proxy negotiates HTTP/2 with the real gRPC server (validated against the same roots).
    pub(super) upstream_h2: Arc<ClientConfig>,
    pub(super) policy: EgressPolicy,
    pub(super) resolve: Resolver,
    pub(super) timeout: Duration,
    pub(super) injections: Vec<HeaderInjection>,
    pub(super) redactions: Vec<SecretNeedle>,
    /// The shared queue of parked `ask`-posture requests. Under `DefaultAction::Ask` an undecided
    /// request enqueues here and blocks; the control socket ([`crate::sandbox::control`]) answers it. A
    /// throwaway internal queue by default (so a non-ask launch never touches it); the launch
    /// injects the one the control thread also holds via [`Self::with_control`].
    pub(super) pending: Arc<crate::sandbox::control::PendingState>,
    /// The live manual-rule overlay (`--session` answers). Consulted on the `ask` branch *before*
    /// parking, so a remembered host:port is decided without re-asking. A throwaway empty overlay by
    /// default; the launch injects the shared one via [`Self::with_control`].
    pub(super) manual: Arc<crate::sandbox::control::ManualRules>,
    /// Whether to print a one-line stderr notice when a request parks, so an interactive user sees
    /// the pending id without polling. Off by default (tests, non-ask launches); the launch turns
    /// it on when it wires the control socket.
    pub(super) notices: bool,
    /// The per-host decision counters this launch records (one outcome per request), or `None` when
    /// stats are off. The launch ([`crate::sandbox::egress::start`]) attaches the session's
    /// [`EgressStats`] via [`Self::with_stats`]; tests leave it unset.
    pub(super) stats: Option<Arc<EgressStats>>,
    /// The live event ring this launch pushes each decision into, read by `sbx net log`, or `None`
    /// when the log is off (tests). The launch ([`crate::sandbox::egress::start`]) attaches the session's
    /// [`crate::sandbox::control::LogRing`] via [`Self::with_log`]; a decision's outcome is both counted in
    /// `stats` and pushed here through the single [`Self::outcome`] chokepoint.
    pub(super) log: Option<Arc<crate::sandbox::control::LogRing>>,
    /// The live registry of egress tunnels currently open, read by `sbx net live`, or `None` when
    /// off (tests). The launch ([`crate::sandbox::egress::start`]) attaches the session's
    /// [`crate::sandbox::control::FlowRegistry`] via [`Self::with_flows`]; each permitted tunnel registers a
    /// flow for its lifetime through a [`crate::sandbox::control::FlowGuard`], and the relay increments the
    /// guard's byte counters. Shared through the `Arc<ProxyCtx>`.
    pub(super) flows: Option<Arc<crate::sandbox::control::FlowRegistry>>,
    /// The number of raw L4 (`tcp://`) splices currently open. Each splice holds a host thread (and
    /// its fds) for the connection's lifetime, so this caps how many an in-cage agent can open at
    /// once (see [`MAX_CONCURRENT_SPLICES`]); the inspected L7 path never touches it. Shared across
    /// connection threads through the [`Arc<ProxyCtx>`] the serve loop clones.
    pub(super) splices: AtomicUsize,
    /// The number of connection-handling threads currently live. Each in-cage connection spawns a
    /// host thread (and holds host fds), so this caps how many an in-cage agent can open at once
    /// (see [`MAX_CONCURRENT_CONNS`]) — a burst of connections cannot exhaust host threads/fds and
    /// take the whole session's egress down. Shared through the `Arc<ProxyCtx>`.
    pub(super) conns: AtomicUsize,
    /// The `sbx app <name>` this launch runs, if any — used only to scope the `sbx net allow`
    /// suggestion in a `denied-default` refusal body to the app (`--app <name>`). `None` for a bare
    /// `sbx run`/`shell`.
    pub(super) app: Option<String>,
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
        // The h2 variant of the cage-facing config: same minted-leaf resolver, but advertising ALPN
        // `h2` so a designated `[network] http2` (gRPC) host negotiates HTTP/2 with the client.
        let mut server_config_h2 = ServerConfig::builder()
            .with_no_client_auth()
            .with_cert_resolver(Arc::new(CertResolver::new(ca.clone())));
        server_config_h2.alpn_protocols = vec![b"h2".to_vec()];
        let server_config_h2 = Arc::new(server_config_h2);
        let policy = union_with_builtin(user_policy);
        // The proxy re-resolves per request; a long build fetching one host thousands of times would
        // re-hit the resolver each time (and any hiccup fails a fetch). A short-TTL cache resolves
        // each host once and reuses it — tunable via `[network] dns_cache_ttl` (default 60s, `0`
        // disables the cache).
        let resolve = caching_resolver(policy.dns_cache_ttl().unwrap_or(Duration::from_secs(60)));
        Ok(ProxyCtx {
            ca,
            server_config,
            server_config_h2,
            upstream: upstream_config(),
            upstream_h2: upstream_config_h2(),
            policy,
            resolve,
            timeout: Duration::from_secs(30),
            injections: Vec::new(),
            redactions: Vec::new(),
            pending: Arc::new(crate::sandbox::control::PendingState::new()),
            manual: Arc::new(crate::sandbox::control::ManualRules::new()),
            notices: false,
            stats: None,
            log: None,
            flows: None,
            splices: AtomicUsize::new(0),
            conns: AtomicUsize::new(0),
            app: None,
        })
    }

    /// Name the `sbx app <name>` this launch runs, so the refusal notice scopes its `sbx net allow`
    /// suggestion to that app. Set once by the launch ([`crate::sandbox::egress::start`]); left unset (a bare
    /// `sbx run`/`shell`) the suggestion targets the project baseline.
    pub(crate) fn with_app(mut self, app: Option<String>) -> Self {
        self.app = app;
        self
    }

    /// Attach the session's per-host decision counters, so each request's outcome is recorded.
    /// Set once by the launch ([`crate::sandbox::egress::start`]) when stats are enabled.
    pub(crate) fn with_stats(mut self, stats: Arc<EgressStats>) -> Self {
        self.stats = Some(stats);
        self
    }

    /// Attach the session's live event ring, so each request's decision is pushed for `sbx net log`.
    /// Set once by the launch ([`crate::sandbox::egress::start`]) whenever the proxy runs.
    pub(crate) fn with_log(mut self, log: Arc<crate::sandbox::control::LogRing>) -> Self {
        self.log = Some(log);
        self
    }

    /// Attach the session's live flow registry, so each permitted tunnel registers itself for its
    /// lifetime and `sbx net live` can read the tunnels open right now. Set once by the launch
    /// ([`crate::sandbox::egress::start`]) whenever the proxy runs.
    pub(crate) fn with_flows(mut self, flows: Arc<crate::sandbox::control::FlowRegistry>) -> Self {
        self.flows = Some(flows);
        self
    }

    /// Register a permitted tunnel in the live flow registry, returning its RAII guard — hold it for
    /// the tunnel's lifetime so the flow stays visible until it closes, then drops off the
    /// `sbx net live` view. Always returns a guard (a **detached** one, counting into throwaway
    /// counters, when no registry is attached — tests), so the relay's counting wrappers work
    /// uniformly with no branch. Call only after the request is permitted and the upstream is connected.
    pub(super) fn register_flow(
        &self,
        host: &str,
        port: u16,
        proto: crate::sandbox::control::Proto,
    ) -> crate::sandbox::control::FlowGuard {
        match &self.flows {
            Some(f) => f.register(host, port, proto),
            None => crate::sandbox::control::FlowGuard::detached(),
        }
    }

    /// The single decision chokepoint every site in [`handle_client`] calls: it both counts the
    /// outcome for `sbx net stats` and pushes one event for the live `sbx net log`, so the two can
    /// never drift and a missed site is a missed *pair*, not a silent stats/log mismatch. `method`
    /// and `path` are the inspected request's (absent for an early-CONNECT block or a raw `tcp://`
    /// splice); `reason` is the same stable category token the adjacent refusal writes (or `allowed`
    /// for a permitted request). The path is query-redacted against the configured secret needles
    /// **before** it enters the ring, so even the outbound-secret-blocked event — whose query is
    /// exactly the one carrying a secret — is safe to hold in RAM.
    #[allow(clippy::too_many_arguments)]
    pub(super) fn outcome(
        &self,
        proto: crate::sandbox::control::Proto,
        host: &str,
        port: u16,
        method: Option<&str>,
        path: Option<&str>,
        kind: StatKind,
        reason: &str,
    ) -> Option<u64> {
        // The common case — a refusal, or any site with no inspected HTTP head — carries no HTTP
        // version or RPC framing. The three inspected-forward sites call [`outcome_l7`] instead, with
        // the real version + `Content-Type`-derived framing.
        self.outcome_l7(
            proto,
            crate::sandbox::control::HttpVer::Unknown,
            crate::sandbox::control::RpcKind::None,
            host,
            port,
            method,
            path,
            kind,
            reason,
        )
    }

    /// [`outcome`](Self::outcome) with the inspected request's HTTP version and RPC framing attached
    /// — called only where the head was read and the request is forwarded, so the live log can render
    /// `https/h2` (transport + version) and a `grpc`/`grpc-web`/`connect` tag. Every other site funnels
    /// through the version-less [`outcome`](Self::outcome).
    #[allow(clippy::too_many_arguments)]
    pub(super) fn outcome_l7(
        &self,
        proto: crate::sandbox::control::Proto,
        http_ver: crate::sandbox::control::HttpVer,
        rpc: crate::sandbox::control::RpcKind,
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
            StatKind::Allow => crate::sandbox::control::LogVerdict::Allow,
            StatKind::Deny => crate::sandbox::control::LogVerdict::Deny,
            StatKind::Blocked => crate::sandbox::control::LogVerdict::Blocked,
        };
        // A `mute` (`dontaudit`) rule suppresses a *denied* request's log line — never a verdict, an
        // allow, or a security-guard `blocked` — so the refusal drops out of the default view but its
        // stat counter (bumped just above) still records it. Consulted through the **effective**
        // policy (config mutes ∪ the live `--session` mute overlay), so a session mute takes effect
        // the same as a config one.
        let muted = matches!(kind, StatKind::Deny)
            && effective_policy(self).muted(host, port, path, method);
        self.push_log_maybe_muted(
            muted, proto, http_ver, rpc, host, port, method, path, verdict, reason,
        )
    }

    /// The copy-paste `sbx net allow` command a `denied-default` refusal body suggests. When the
    /// launch is an `sbx app <name>` (the app hint is set), it names the app — `sbx net allow
    /// <host> --app <name>` writes the allow into that app's config rather than the project
    /// baseline, which is what the user almost always means when an *app's* egress was blocked.
    /// Pure so it is unit-testable. The `--app` write defaults to the project scope (least
    /// privilege); the user adds `-g` to reach a global profile.
    pub(super) fn allow_suggestion(&self, host: &str) -> String {
        match &self.app {
            Some(name) => format!("sbx net allow {host} --app {name}"),
            None => format!("sbx net allow {host}"),
        }
    }

    /// Push one event into the live log **without** touching the stat counters — for the outcomes the
    /// coarse stats taxonomy does not count but the diagnostic log should: a permitted request that
    /// failed downstream (`Error` — DNS/unreachable/cert) and a request sbx declined before any
    /// verdict (`Blocked` — an IP-literal target or a malformed/smuggling request). Stats stay a
    /// pure allow/deny/blocked policy counter; the log is the richer record.
    #[allow(clippy::too_many_arguments)]
    pub(super) fn push_log(
        &self,
        proto: crate::sandbox::control::Proto,
        host: &str,
        port: u16,
        method: Option<&str>,
        path: Option<&str>,
        verdict: crate::sandbox::control::LogVerdict,
        reason: &str,
    ) -> Option<u64> {
        self.push_log_maybe_muted(
            false,
            proto,
            crate::sandbox::control::HttpVer::Unknown,
            crate::sandbox::control::RpcKind::None,
            host,
            port,
            method,
            path,
            verdict,
            reason,
        )
    }

    /// The muted-aware inner of [`Self::push_log`]: when `muted` (a denied request matched a `mute`
    /// rule), the event is routed to the log's separate muted ring so it is kept out of the default
    /// `sbx net log` view yet still recoverable via `--all` — the stat counter was already bumped by
    /// the caller, so a muted refusal is *collapsed*, never destroyed. All non-deny sites route here
    /// with `muted = false` via [`Self::push_log`].
    #[allow(clippy::too_many_arguments)]
    fn push_log_maybe_muted(
        &self,
        muted: bool,
        proto: crate::sandbox::control::Proto,
        http_ver: crate::sandbox::control::HttpVer,
        rpc: crate::sandbox::control::RpcKind,
        host: &str,
        port: u16,
        method: Option<&str>,
        path: Option<&str>,
        verdict: crate::sandbox::control::LogVerdict,
        reason: &str,
    ) -> Option<u64> {
        let log = self.log.as_ref()?;
        let redacted = path.map(|p| self.redact_query(p));
        Some(log.push(
            muted,
            host,
            port,
            method,
            redacted.as_deref(),
            verdict,
            reason,
            proto,
            http_ver,
            rpc,
        ))
    }

    /// Amend the event `seq` (returned by a prior [`outcome`](Self::outcome)) with the upstream HTTP
    /// status its response returned. A clean no-op when no log is configured or no event was pushed
    /// (`seq` is `None`), or when the event has already been evicted from the ring.
    pub(super) fn set_status(&self, seq: Option<u64>, status: u16) {
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
    /// ([`crate::sandbox::egress::start`]) passes the same [`crate::sandbox::control::PendingState`] and
    /// [`crate::sandbox::control::ManualRules`] it serves on the control socket, so a request parked here is
    /// answerable by `sbx net pending` and a `--session` answer it adds is honored here.
    pub(crate) fn with_control(
        mut self,
        pending: Arc<crate::sandbox::control::PendingState>,
        manual: Arc<crate::sandbox::control::ManualRules>,
    ) -> Self {
        self.pending = pending;
        self.manual = manual;
        self.notices = self.policy.ask_notice();
        self
    }

    /// Attach the resolved host-side credential injections. The proxy applies each to an
    /// allowed request whose host and path its `rule` matches, replacing any client-supplied
    /// copy of the header — so the cage never holds the plaintext yet the request still carries
    /// it. Set once by the launch ([`crate::sandbox::egress::start`]) after resolving the sources.
    pub(crate) fn with_injections(mut self, injections: Vec<HeaderInjection>) -> Self {
        self.injections = injections;
        self
    }

    /// Attach the outbound-redaction needles (the configured secrets' wire values). The proxy
    /// refuses any request whose decrypted head carries one verbatim, so a secret the agent
    /// obtained cannot be re-sent in the clear. Set by the launch ([`crate::sandbox::egress::start`])
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
    pub(super) fn with_resolver(mut self, resolve: Resolver) -> Self {
        self.resolve = resolve;
        self
    }

    /// Shrink the per-socket timeout, so a test can provoke an idle-timeout window in milliseconds
    /// instead of the production 30 s.
    pub(super) fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Replace the upstream-validation config, so a test can trust a loopback upstream's own CA.
    pub(super) fn with_upstream(mut self, upstream: Arc<ClientConfig>) -> Self {
        self.upstream = upstream;
        self
    }

    /// Wire the shared pending queue without turning on the stderr park notices, so a test can
    /// answer a parked request out of band while keeping the test output clean (unlike
    /// [`with_control`](ProxyCtx::with_control), which the launch uses and which prints notices).
    pub(super) fn with_pending_silent(
        mut self,
        pending: Arc<crate::sandbox::control::PendingState>,
    ) -> Self {
        self.pending = pending;
        self
    }

    /// Wire the manual-rule overlay alone (notices off), so a test can pre-populate a remembered
    /// decision and assert the proxy honors it without ever parking.
    pub(super) fn with_manual(mut self, manual: Arc<crate::sandbox::control::ManualRules>) -> Self {
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
        // Carry the mute (`dontaudit`) set through — it is log-only, so the built-in allow union
        // does not touch it, but a rebuild that dropped it would silently un-suppress the refusals.
        .with_mute(user.mute_rules().to_vec())
        // Carry the DNS cache TTL through — a rebuild that dropped it would silently revert the
        // configured value to the default.
        .with_dns_cache_ttl(user.dns_cache_ttl())
        // Carry the HTTP/2 host set through — a rebuild that dropped it would silently demote a
        // designated gRPC host back to HTTP/1.1, failing every h2-only client.
        .with_http2(user.http2_hosts().to_vec())
}

/// The policy the proxy evaluates for a request: the immutable config policy, or — when a live
/// `--session` overlay is present — that policy with the overlay's allow/deny rules folded in. The
/// fold reuses the full policy machinery (deny-wins, layer partitioning, path/method matching), so a
/// `--session` rule is enforced identically to a config rule, in **every** filtering posture
/// (allowlist, denylist, `ask`) and at every enforcement layer (inspected TLS, inspected cleartext,
/// raw splice) — not only when a request would otherwise park. The common case (an empty overlay)
/// borrows the config policy with no allocation.
pub(super) fn effective_policy(ctx: &ProxyCtx) -> std::borrow::Cow<'_, EgressPolicy> {
    if ctx.manual.is_empty() {
        return std::borrow::Cow::Borrowed(&ctx.policy);
    }
    let (overlay_allow, overlay_deny) = ctx.manual.snapshot();
    let mut allow = ctx.policy.allow_rules().to_vec();
    allow.extend(overlay_allow);
    let mut deny = ctx.policy.deny_rules().to_vec();
    deny.extend(overlay_deny);
    // The mute (`dontaudit`) overlay — a live `sbx net mute --session` — folds onto the config
    // mutes, so a suppressed refusal is honored identically whether it came from config or the
    // session. Carried through this rebuild (like default_action/ask), or it would be dropped.
    let mut mute = ctx.policy.mute_rules().to_vec();
    mute.extend(ctx.manual.mute_snapshot());
    // Carry default_action + ask_timeout + ask_notice through unchanged — a pure allow/deny merge
    // would silently flip the posture (lose the timeout, or demote deny↔ask), the same contract
    // `union_with_builtin` keeps.
    std::borrow::Cow::Owned(
        EgressPolicy::new(allow, deny)
            .with_default(ctx.policy.default_action())
            .with_ask_timeout(ctx.policy.ask_timeout())
            .with_ask_notice(ctx.policy.ask_notice())
            .with_mute(mute)
            .with_dns_cache_ttl(ctx.policy.dns_cache_ttl())
            .with_http2(ctx.policy.http2_hosts().to_vec()),
    )
}
