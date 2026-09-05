//! The proxy's running context and the policy it evaluates against.
//!
//! [`ProxyCtx`] holds the cert machinery, the upstream-validation configs, the resolved (and
//! built-in-augmented) egress policy, the name resolver, the per-socket timeout, the host-side
//! credential injections and redaction needles, and the live control/stats/log/flow handles a
//! launch attaches. [`union_with_builtin`] augments a user policy with the always-on self-equip
//! allow-set, and [`effective_policy`] folds a live `--session` overlay onto the config policy.

use std::io;
use std::sync::Arc;
use std::sync::atomic::AtomicUsize;
use std::time::Duration;

use rustls::{ClientConfig, ServerConfig};

use crate::allowlist::{self, EgressPolicy, Rule};
use crate::sandbox::control::SecretWay;
use crate::sandbox::egress_stats::{EgressStats, StatKind};

use super::ca::{Ca, CertResolver, ensure_provider, upstream_config, upstream_config_h2};
use super::dns::{Resolver, caching_resolver};
use super::inject::{CredentialRefresh, Credentials};
#[cfg(test)]
use super::inject::{HeaderInjection, SecretNeedle};
use super::redact_record_in_place;

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
    /// once; used solely by the h2 branch ([`h2mitm`](super::h2mitm)).
    pub(super) server_config_h2: Arc<ServerConfig>,
    pub(super) upstream: Arc<ClientConfig>,
    /// The upstream-validation config for the h2 branch: like `upstream` but advertising ALPN `h2`,
    /// so the proxy negotiates HTTP/2 with the real gRPC server (validated against the same roots).
    pub(super) upstream_h2: Arc<ClientConfig>,
    pub(super) policy: EgressPolicy,
    pub(super) resolve: Resolver,
    pub(super) timeout: Duration,
    /// The live credential state: the injections to apply and the needles to scan for, as one
    /// unit. Shared rather than owned because a credential can be re-resolved mid-session, and
    /// because the capture ring masks with the same needles — one state, three consumers.
    pub(super) credentials: Arc<Credentials>,
    /// How to re-resolve those credentials when an injection target refuses one. `None` for a
    /// launch with nothing to refresh.
    pub(super) refresh: Option<Arc<CredentialRefresh>>,
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
    /// Which plane this proxy is — stamped on every event it pushes, because the ring above may be
    /// shared with the per-invocation proxies of declared tasks, which enforce policies of their
    /// own. [`crate::sandbox::control::Plane::Agent`] unless the launch says otherwise via
    /// [`Self::with_plane`], since the session's own proxy is the common case and every test's.
    pub(super) plane: crate::sandbox::control::Plane,
    /// The live registry of egress tunnels currently open, read by `sbx net live`, or `None` when
    /// off (tests). The launch ([`crate::sandbox::egress::start`]) attaches the session's
    /// [`crate::sandbox::control::FlowRegistry`] via [`Self::with_flows`]; each permitted tunnel registers a
    /// flow for its lifetime through a [`crate::sandbox::control::FlowGuard`], and the relay increments the
    /// guard's byte counters. Shared through the `Arc<ProxyCtx>`.
    pub(super) flows: Option<Arc<crate::sandbox::control::FlowRegistry>>,
    /// The number of raw L4 (`tcp://`) splices currently open. Each splice holds a host thread (and
    /// its fds) for the connection's lifetime, so this caps how many an in-cage agent can open at
    /// once (see `splice::MAX_CONCURRENT_SPLICES`); the inspected L7 path never touches it. Shared
    /// across connection threads through the [`Arc<ProxyCtx>`] the serve loop clones.
    pub(super) splices: AtomicUsize,
    /// The number of connection-handling threads currently live. Each in-cage connection spawns a
    /// host thread (and holds host fds), so this caps how many an in-cage agent can open at once
    /// (see [`Self::max_conns`], the launch's `[network] max_connections`) — a burst of connections
    /// cannot exhaust host threads/fds and take the whole session's egress down. Shared through the
    /// `Arc<ProxyCtx>`.
    pub(super) conns: AtomicUsize,
    /// The bytes currently reserved across every connection for buffering a **request body**.
    ///
    /// Per request the buffer is bounded by `BodyLimits::per_request` (the launch's `[network]
    /// body_max_mb`), but that bound is per request: [`Self::max_conns`] of them can be in flight at
    /// once, and the proxy runs **host-side**, outside the cage's own memory cgroup (`cgroup::wrap`
    /// puts bwrap in the scope, not the supervisor). Without a shared ceiling an in-cage agent could
    /// make the host allocate the product of the two. The sum is what [`super::BodyLimits`] bounds,
    /// through its `total`.
    pub(super) held_bodies: std::sync::atomic::AtomicU64,
    /// The `sbx app <name>` this launch runs, if any — used only to scope the `sbx net allow`
    /// suggestion in a `denied-default` refusal body to the app (`--app <name>`). `None` for a bare
    /// `sbx run`/`shell`.
    pub(super) app: Option<String>,
    /// Where a refused request is announced (`[notify] events.network`), or `None` when the launch
    /// wired none (tests). Attached by [`crate::sandbox::egress::start`] via [`Self::with_notifier`]
    /// and consulted from the one [`Self::outcome_l7`] chokepoint, so a refusal site added later
    /// cannot forget to announce itself.
    pub(super) notifier: Option<Arc<crate::sandbox::notify_sink::Notifier>>,
    /// The session's traffic capture (`[network] capture`), or `None` — the default — when nothing
    /// is captured. Attached by [`crate::sandbox::egress::start`] via [`Self::with_capture`]; every
    /// inspected forwarding path opens a capture through the one [`Self::begin_capture`] entry
    /// point, so a path that does not ask for one simply captures nothing.
    pub(super) capture: Option<Arc<crate::sandbox::control::CaptureRing>>,
    /// The validated upstream connections a finished request left behind, for a later request to
    /// the same host with the same credentials to reuse (`[network] pool`), or `None` — the default
    /// — when the launch opens a fresh connection per request. Shared across connection threads
    /// through the `Arc<ProxyCtx>`; see [`super::pool`] for what may enter it and why.
    pub(super) pool: Option<super::pool::UpstreamPool>,
    /// How long a connection may sit idle before it is let go, on either leg (`[network]
    /// idle_timeout`, else [`crate::allowlist::DEFAULT_IDLE_TIMEOUT`]). Resolved here rather than
    /// read from the policy at each use, so the tunnel that waits and the pool that ages out a
    /// parked connection cannot end up answering the same question two ways.
    pub(super) idle: Duration,
    /// The most connection threads alive at once (`[network] max_connections`, else
    /// [`crate::allowlist::DEFAULT_MAX_CONNECTIONS`]). A connection beyond it is refused rather than
    /// spawned; see [`super::serve`].
    pub(super) max_conns: usize,
    /// What this launch holds in request-body buffers (`[network] body_max_mb`, else
    /// [`crate::allowlist::DEFAULT_BODY_MAX`]): one body's ceiling and the sum across every
    /// connection. Resolved here so the refusal, the reservation and the message that explains
    /// them cannot read three different numbers.
    pub(super) body: super::BodyLimits,
    /// The session's record of what its signer plugins formed, read by `sbx logs --feed signer`, or
    /// `None` when the launch declared no signer (and in tests). Attached by
    /// [`crate::sandbox::egress::start`] via [`Self::with_signer_log`]; every path that forms a
    /// credential reaches it through the one [`super::inject::pairs_for`] call, so a request whose
    /// signature was formed elsewhere does not exist.
    pub(super) signer_log: Option<Arc<crate::sandbox::signer_control::SignerRing>>,
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
        // each host once and reuses it — tunable via `[network] dns_cache_ttl`, where `0` disables
        // the cache and an unset field takes the named default.
        let resolve = caching_resolver(
            policy
                .dns_cache_ttl()
                .unwrap_or(crate::allowlist::DEFAULT_DNS_CACHE_TTL),
        );
        // Built only when the launch asks for reuse, so a launch that does not is byte-for-byte the
        // connection-per-request path and cannot inherit any of reuse's failure modes.
        // Both resolved once, here, so every place that asks reads the same answer.
        let policy_idle = policy
            .idle_timeout()
            .unwrap_or(crate::allowlist::DEFAULT_IDLE_TIMEOUT);
        let pool = policy
            .pool()
            .then(|| super::pool::UpstreamPool::new(policy_idle));
        let policy_max_conns = policy
            .max_connections()
            .unwrap_or(crate::allowlist::DEFAULT_MAX_CONNECTIONS);
        let policy_body = super::BodyLimits::new(
            policy
                .body_max()
                .unwrap_or(crate::allowlist::DEFAULT_BODY_MAX),
        );
        Ok(ProxyCtx {
            ca,
            server_config,
            server_config_h2,
            upstream: upstream_config(),
            upstream_h2: upstream_config_h2(),
            policy,
            resolve,
            timeout: Duration::from_secs(30),
            // Empty, and on the built-in floor: a launch with credentials replaces this wholesale
            // with the set it resolved (and that set's own floor) through `with_shared_credentials`.
            credentials: Arc::new(Credentials::new(
                Vec::new(),
                Vec::new(),
                crate::sandbox::redact::MIN_LEN_DEFAULT,
                Vec::new(),
            )),
            refresh: None,
            pending: Arc::new(crate::sandbox::control::PendingState::new()),
            manual: Arc::new(crate::sandbox::control::ManualRules::new()),
            notices: false,
            stats: None,
            log: None,
            plane: crate::sandbox::control::Plane::Agent,
            flows: None,
            splices: AtomicUsize::new(0),
            conns: AtomicUsize::new(0),
            held_bodies: std::sync::atomic::AtomicU64::new(0),
            app: None,
            notifier: None,
            capture: None,
            pool,
            idle: policy_idle,
            max_conns: policy_max_conns,
            body: policy_body,
            signer_log: None,
        })
    }

    /// Attach the launch's refusal notifier, so every request this policy turns down is announced.
    /// Left unset (tests, and any path with no notification policy) nothing is announced and the
    /// decision path is unchanged.
    pub(crate) fn with_notifier(
        mut self,
        notifier: Arc<crate::sandbox::notify_sink::Notifier>,
    ) -> Self {
        self.notifier = Some(notifier);
        self
    }

    /// Name the `sbx app <name>` this launch runs, so the refusal notice scopes its `sbx net allow`
    /// suggestion to that app. Set once by the launch ([`crate::sandbox::egress::start`]); left unset (a bare
    /// `sbx run`/`shell`) the suggestion targets the project baseline.
    pub(crate) fn with_app(mut self, app: Option<String>) -> Self {
        self.app = app;
        self
    }

    /// Attach the session's per-host decision counters, so each request's outcome is recorded.
    ///
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

    /// Name the plane this proxy enforces for, so the events it pushes can be told apart from those
    /// of another proxy sharing the same ring. Set once by the launch
    /// ([`crate::sandbox::egress::start`]); the session's own proxy leaves the
    /// [`crate::sandbox::control::Plane::Agent`] default.
    pub(crate) fn with_plane(mut self, plane: crate::sandbox::control::Plane) -> Self {
        self.plane = plane;
        self
    }

    /// Attach the session's live flow registry, so each permitted tunnel registers itself for its
    /// lifetime and `sbx net live` can read the tunnels open right now. Set once by the launch
    /// ([`crate::sandbox::egress::start`]) whenever the proxy runs.
    pub(crate) fn with_flows(mut self, flows: Arc<crate::sandbox::control::FlowRegistry>) -> Self {
        self.flows = Some(flows);
        self
    }

    /// Attach the session's signer feed, so every credential a plugin forms — and every request it
    /// would not sign — is recorded for `sbx logs --feed signer`. Set by the launch
    /// ([`crate::sandbox::egress::start`]) only when a signer is declared; left unset the forming
    /// path is unchanged and records nothing.
    pub(crate) fn with_signer_log(
        mut self,
        log: Arc<crate::sandbox::signer_control::SignerRing>,
    ) -> Self {
        self.signer_log = Some(log);
        self
    }

    /// The session's signer feed, for the one call that forms credentials.
    pub(super) fn signer_log(&self) -> Option<&crate::sandbox::signer_control::SignerRing> {
        self.signer_log.as_deref()
    }

    /// Attach the session's traffic capture, so each inspected exchange files what it carried for
    /// `sbx net logs --with-headers/--with-body`. Set by the launch
    /// ([`crate::sandbox::egress::start`]) only when a **trusted** layer turned the capture on;
    /// left unset nothing is ever buffered on the forwarding path.
    pub(crate) fn with_capture(
        mut self,
        capture: Arc<crate::sandbox::control::CaptureRing>,
    ) -> Self {
        self.capture = Some(capture);
        self
    }

    /// Open a capture for the permitted exchange logged as `seq`, or `None` when this launch does
    /// not capture (or nothing was logged). The returned guard files the exchange when it is
    /// dropped, however the relay ends — hold it for the exchange's lifetime.
    ///
    /// Call only for a *permitted* request: a refusal forwards nothing, so there is no traffic to
    /// show, and the decision itself is already the log event.
    pub(super) fn begin_capture(
        &self,
        seq: Option<u64>,
        host: &str,
    ) -> Option<super::capture::CaptureGuard> {
        let (capture, log, seq) = (self.capture.as_ref()?, self.log.as_ref()?, seq?);
        // Tell the event ring a capture is coming, so an arriving status waits for it and the event
        // is re-emitted exactly once with everything.
        log.expect_capture(seq);
        Some(super::capture::CaptureGuard::new(
            capture.clone(),
            log.clone(),
            seq,
            host,
        ))
    }

    /// Record that the configured secret `name` was seen crossing the WebSocket tunnel logged as
    /// `seq`, in the direction `way`. A no-op when nothing was logged (tests) or the launch has no
    /// event ring.
    ///
    /// This is a report, never a verdict: the tunnel stays open and its bytes are relayed exactly as
    /// they crossed. Blocking would mean tearing down a live tunnel on a byte-exact match, and
    /// masking would mean rewriting a stream two peers agreed the framing of — so what the proxy
    /// does here is tell the user, on the tunnel's own event, while it is still open.
    pub(super) fn websocket_secret_seen(&self, seq: Option<u64>, name: &str, way: SecretWay) {
        let (Some(log), Some(seq)) = (self.log.as_ref(), seq) else {
            return;
        };
        log.secret_seen(seq, name, way);
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

    /// The single decision chokepoint every site in [`handle_client`](super::handle_client) calls: it both counts the
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
        self.announce_refusal(proto, host, port, kind, reason, muted);
        self.push_log_maybe_muted(
            muted, proto, http_ver, rpc, host, port, method, path, verdict, reason,
        )
    }

    /// Announce a refused request, from the same chokepoint that counts and logs it.
    ///
    /// Here rather than at each refusal site on purpose: a request can be turned down in five places
    /// today (an explicit deny rule, nothing allowing it, a method the rule excludes, an ask that was
    /// answered no or timed out, and the security guards), and a sixth added later would have to
    /// remember to announce itself. Funnelling it through `outcome` makes that impossible to forget —
    /// the same reasoning that put stats and the log here.
    ///
    /// Three refusals are deliberately **not** announced:
    /// - an allow (nothing was blocked);
    /// - a `mute`d denial — a `dontaudit` rule says "stop telling me about this one", and honouring
    ///   that for the log while still raising a desktop notification would defeat the point;
    /// - an `asked-denied` while the interactive park notices are on, because the person was already
    ///   asked about this exact request and answered (or let it time out).
    ///
    /// `proto` is carried in for one reason: the copy-paste fix. A notification is the channel that
    /// exists *because* the agent may never surface the refusal body, so the command it offers has to
    /// be the one that body offers — which means the same [`rule_destination`](super::rule_destination)
    /// spelling, scheme and port included. Built from the bare host, it told the user to run
    /// `sbx net allow host` for a refusal on `:8443` (an https rule on 443, which admits nothing they
    /// asked for) or for a cleartext one (an https rule, which cannot open the clear at all).
    fn announce_refusal(
        &self,
        proto: crate::sandbox::control::Proto,
        host: &str,
        port: u16,
        kind: StatKind,
        reason: &str,
        muted: bool,
    ) {
        let Some(notifier) = &self.notifier else {
            return;
        };
        if let Some(block) = refusal_block(
            host,
            port,
            kind,
            reason,
            muted,
            self.notices,
            &self.allow_suggestion(&super::rule_destination(proto, host, port)),
        ) {
            notifier.block(block);
        }
    }

    /// The copy-paste `sbx net allow` command a `denied-default` refusal suggests, wrapped around
    /// the rule `destination` its caller spelled with [`rule_destination`](super::rule_destination)
    /// — this decides the *scoping*, never what is being allowed. When the launch is an `sbx app
    /// <name>` (the app hint is set), it names the app — `sbx net allow <destination> --app <name>`
    /// writes the allow into that app's config rather than the project baseline, which is what the
    /// user almost always means when an *app's* egress was blocked. Pure so it is unit-testable. The
    /// `--app` write defaults to the project scope (least privilege); the user adds `-g` to reach a
    /// global profile.
    pub(super) fn allow_suggestion(&self, destination: &str) -> String {
        match &self.app {
            Some(name) => format!("sbx net allow {destination} --app {name}"),
            None => format!("sbx net allow {destination}"),
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
        let redacted = path.map(|p| self.redact_query(host, p));
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
            self.plane,
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
    ///
    /// Reached from the **park** as well as the log ([`super::decide_https`]): a parked request is
    /// printed by `sbx net pending` and by the park notice, so a path that is masked on its way into
    /// the ring and unmasked on its way into the pending queue is the same token in the same
    /// terminal by another route.
    pub(super) fn redact_query(&self, host: &str, path: &str) -> String {
        let creds = self.credentials.snapshot();
        if creds.needles.is_empty() {
            return path.to_string();
        }
        let mut bytes = path.as_bytes().to_vec();
        redact_record_in_place(&mut bytes, &creds.needles, host);
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

    /// Share an already-built credential state, so a consumer outside the proxy (the capture ring's
    /// masking) scans for exactly what this proxy injects, including after a refresh.
    pub(crate) fn with_shared_credentials(mut self, credentials: Arc<Credentials>) -> Self {
        self.credentials = credentials;
        self
    }

    /// Wire re-resolution, so an upstream that refuses the injected credential can be answered with
    /// a freshly resolved one on the next request. Absent by default: a launch that never resolved a
    /// credential has nothing to refresh, and one whose sources are all static gains nothing.
    pub(crate) fn with_refresh(mut self, refresh: Arc<CredentialRefresh>) -> Self {
        self.refresh = Some(refresh);
        self
    }

    /// Tell the refresher that an injection target refused the credential it was given.
    ///
    /// Called only for a `401` from a host that actually carries an injection: an unrelated refusal
    /// says nothing about our credential, and spending a resolver run on it would let any allowed
    /// host drive sbx's resolver. The refresher applies its own bounds on top (see
    /// [`CredentialRefresh::on_refusal`]), so this is safe to call on every such response.
    ///
    /// The request that met the `401` is already lost: its head has been relayed to the cage by the
    /// time the status is read. What a refresh buys is the *next* one, which is enough for a client
    /// that retries — and every agent CLI observed here does.
    pub(super) fn credential_refused(&self) {
        if let Some(refresh) = &self.refresh {
            refresh.on_refusal();
        }
    }

    /// Set the injections alone, keeping the needles. **Tests only**, and deliberately so: the
    /// production path goes through [`Self::with_credentials`], where the pairing is the shape of
    /// the call and cannot be half-done. A test that exercises one side without the other is
    /// stating exactly that, which is why the asymmetry is allowed here and nowhere else.
    #[cfg(test)]
    pub(crate) fn with_injections(self, injections: Vec<HeaderInjection>) -> Self {
        let needles = self.credentials.snapshot().needles.clone();
        let min_len = self.credentials.min_len();
        self.with_shared_credentials(Arc::new(Credentials::new(
            injections,
            needles,
            min_len,
            Vec::new(),
        )))
    }

    /// Set the needles alone, keeping the injections. **Tests only** — see [`Self::with_injections`].
    ///
    /// The needles are taken as given: this stands in for a launch that already admitted them, so a
    /// test may hand over a short one to exercise the scan itself.
    #[cfg(test)]
    pub(crate) fn with_redactions(self, needles: Vec<SecretNeedle>) -> Self {
        let injections = self.credentials.snapshot().injections.clone();
        let min_len = self.credentials.min_len();
        self.with_shared_credentials(Arc::new(Credentials::new(
            injections,
            needles,
            min_len,
            Vec::new(),
        )))
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

/// Whether one decision is announced, and as what — the whole rule, pure over its inputs so every
/// branch is pinned by a test rather than only reachable through a live proxy.
///
/// `suggestion` is the `sbx net allow …` the caller would offer; whether it is actually attached is
/// decided here, because *when* a fix may be suggested is a security judgement, not a formatting one.
fn refusal_block(
    host: &str,
    port: u16,
    kind: StatKind,
    reason: &str,
    muted: bool,
    notices: bool,
    suggestion: &str,
) -> Option<crate::notify::Block> {
    if matches!(kind, StatKind::Allow) || muted || (reason == "asked-denied" && notices) {
        return None;
    }
    // Only a host that nothing allowed gets a copy-paste `sbx net allow`. A request stopped by an
    // explicit deny rule, or by a security guard (a credential on its way out, an SSRF target), must
    // never carry one: telling the user to allow a credential leak would be actively harmful advice,
    // and re-allowing what they deliberately denied is not the fix either.
    let fix = if reason == "denied-default" {
        suggestion.to_string()
    } else {
        String::new()
    };
    Some(crate::notify::Block {
        event: crate::notify::NotifyEvent::Network,
        subject: format!("{host}:{port}"),
        reason: reason.to_string(),
        detail: refusal_detail(reason).to_string(),
        fix,
    })
}

/// One sentence explaining a refusal category to the person the notification is for.
///
/// The categories are the stable tokens the refusal bodies and `sbx net logs` already use, so a
/// notification and the log line for the same request name the same thing. Pure, and total: an
/// unrecognized token still yields a usable sentence rather than an empty body, which is what keeps a
/// refusal category added later from silently announcing nothing.
fn refusal_detail(reason: &str) -> &'static str {
    match reason {
        "denied-default" => "no rule in the network policy allows this host",
        "denied-by-rule" => "an explicit deny rule in the network policy blocked it",
        "denied-method" => "the host is allowed, but not for this HTTP method",
        "asked-denied" => "the live decision was `deny`, or the ask timed out",
        "outbound-secret" => {
            "the request was carrying a configured secret out of the cage (credential leak refused)"
        }
        "ssrf-blocked" => "the target resolves to a private or link-local address",
        "host-mismatch" => "the request's `Host` did not match the host it was tunnelled to",
        "splice-cap" => "too many raw tunnels are already open for this session",
        "ws-injection-refused" => "a credential cannot be injected into a WebSocket upgrade",
        "http2-ask-unsupported" => "an HTTP/2 host cannot be decided interactively",
        _ => "the network policy refused it",
    }
}

/// Append the built-in self-equip allow rules to a policy's allow list (deny is unchanged, so a
/// user deny still wins over a built-in allow).
///
/// It **amends** the policy rather than rebuilding one, and that is the whole point: this is the
/// policy the proxy context reads every transport setting from, and a rebuild carries only the
/// settings someone remembered to name. The list was right until each new setting was added — the
/// idle bound and the connection cap were both dropped here on their first day, found by a test that
/// asked what the wire actually said. [`EgressPolicy::with_rules`] cannot drop what it never
/// touches.
pub(crate) fn union_with_builtin(user: EgressPolicy) -> EgressPolicy {
    let mut allow = user.allow_rules().to_vec();
    allow.extend(builtin_allow_rules());
    let deny = user.deny_rules().to_vec();
    user.with_rules(allow, deny)
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
    // Amended, not rebuilt, for the reason [`union_with_builtin`] gives: a merge that names the
    // settings it carries loses the ones it does not, and a `--session` overlay must change what is
    // allowed and nothing else.
    std::borrow::Cow::Owned(ctx.policy.clone().with_rules(allow, deny).with_mute(mute))
}

#[cfg(test)]
mod notify_tests {
    use super::*;

    const SUGGEST: &str = "sbx net allow api.example.com";

    fn block_for(reason: &str, kind: StatKind) -> Option<crate::notify::Block> {
        refusal_block("api.example.com", 443, kind, reason, false, false, SUGGEST)
    }

    #[test]
    fn a_host_nothing_allowed_carries_the_command_that_allows_it() {
        let b = block_for("denied-default", StatKind::Deny).expect("a denial is announced");
        assert_eq!(b.subject, "api.example.com:443");
        assert_eq!(b.reason, "denied-default");
        assert_eq!(b.fix, SUGGEST);
        assert!(b.detail.contains("no rule"));
    }

    #[test]
    fn a_security_refusal_never_suggests_allowing_it() {
        // The harmful advice this guards: a request is refused *because* it was carrying a
        // credential out of the cage, and the notification tells the user to allow that host —
        // which would open the very leak the guard just closed. Same for an SSRF target.
        for reason in ["outbound-secret", "ssrf-blocked", "host-mismatch"] {
            let b = block_for(reason, StatKind::Blocked).expect("a security refusal is announced");
            assert_eq!(b.fix, "", "`{reason}` must offer no fix, got {:?}", b.fix);
        }
        // And an explicit deny rule is a decision already taken — not something to undo in a toast.
        let b = block_for("denied-by-rule", StatKind::Deny).unwrap();
        assert_eq!(b.fix, "");
    }

    #[test]
    fn an_allowed_request_is_not_announced() {
        assert!(block_for("allowed", StatKind::Allow).is_none());
    }

    #[test]
    fn a_muted_denial_is_not_announced() {
        // A `mute` (`dontaudit`) rule says "stop telling me about this one". Honouring that for the
        // log while still raising a desktop notification would defeat the point of the rule.
        assert!(
            refusal_block(
                "api.example.com",
                443,
                StatKind::Deny,
                "denied-default",
                true,
                false,
                SUGGEST
            )
            .is_none()
        );
    }

    #[test]
    fn an_answered_ask_is_not_announced_twice() {
        // Under the interactive posture the person was already shown this exact request and answered
        // it (or let it time out). A second, after-the-fact notification is pure noise.
        assert!(
            refusal_block(
                "api.example.com",
                443,
                StatKind::Deny,
                "asked-denied",
                false,
                true,
                SUGGEST
            )
            .is_none()
        );
        // With the park notices off, nothing announced it the first time, so the refusal is said.
        assert!(
            refusal_block(
                "api.example.com",
                443,
                StatKind::Deny,
                "asked-denied",
                false,
                false,
                SUGGEST
            )
            .is_some()
        );
    }

    #[test]
    fn every_refusal_category_the_proxy_emits_has_its_own_sentence() {
        // A category with no sentence would announce a blank explanation. The list is the set of
        // tokens the refusal sites record; the fallback covers one added later, but every token that
        // exists today must be spelled out.
        for reason in [
            "denied-default",
            "denied-by-rule",
            "denied-method",
            "asked-denied",
            "outbound-secret",
            "ssrf-blocked",
            "host-mismatch",
            "splice-cap",
            "ws-injection-refused",
            "http2-ask-unsupported",
        ] {
            assert_ne!(
                refusal_detail(reason),
                refusal_detail("something-added-later"),
                "`{reason}` must have its own sentence, not the fallback"
            );
        }
    }
}

#[cfg(test)]
mod wiring_tests {
    use super::*;
    use crate::notify::{NotifyMode, NotifyPolicy};
    use crate::sandbox::notify_sink::{Notifier, Sink};
    use std::sync::Mutex;

    struct Recorder(Arc<Mutex<Vec<String>>>);

    impl Sink for Recorder {
        fn deliver(
            &mut self,
            summary: &str,
            body: &str,
            _: Option<u32>,
        ) -> Result<Option<u32>, ()> {
            self.0.lock().unwrap().push(format!("{summary}|{body}"));
            Ok(None)
        }
    }

    /// A refusal recorded through the decision chokepoint reaches the notifier.
    ///
    /// The unit tests above pin what `refusal_block` *decides*; this pins that `outcome` actually
    /// calls it. Without this, removing the announcement from the chokepoint — or dropping the
    /// `with_notifier` a launch attaches — would leave every test green and every refusal silent,
    /// which is the one regression nothing else here would catch.
    #[test]
    fn a_refusal_recorded_through_the_chokepoint_reaches_the_notifier() {
        let seen = Arc::new(Mutex::new(Vec::new()));
        let notifier = Arc::new(Notifier::recording(
            NotifyPolicy::uniform(NotifyMode::Once),
            Box::new(Recorder(Arc::clone(&seen))),
        ));
        {
            let ctx = ProxyCtx::new(
                Arc::new(crate::sandbox::proxy::ca::Ca::ephemeral().unwrap()),
                EgressPolicy::default(),
            )
            .unwrap()
            .with_notifier(Arc::clone(&notifier));

            ctx.outcome(
                crate::sandbox::control::Proto::Https,
                "api.example.com",
                443,
                Some("GET"),
                Some("/v1/thing"),
                StatKind::Deny,
                "denied-default",
            );
            // An allowed request through the same chokepoint announces nothing.
            ctx.outcome(
                crate::sandbox::control::Proto::Https,
                "ok.example.com",
                443,
                Some("GET"),
                Some("/"),
                StatKind::Allow,
                "allowed",
            );
        }
        drop(
            Arc::try_unwrap(notifier)
                .map_err(|_| "the notifier is still shared")
                .unwrap(),
        );
        let out = seen.lock().unwrap().clone();
        assert_eq!(out.len(), 1, "only the refusal is announced: {out:?}");
        // The host leads the summary, so a desktop that truncates to one line still shows what was
        // refused; the explanation and the fix follow in the body.
        assert!(out[0].starts_with("Blocked: api.example.com:443|"));
    }

    /// The command a refusal *notification* offers is the command the refusal *body* offers.
    ///
    /// The notification exists precisely because the agent is under no obligation to surface a `403`
    /// body, so the copy-paste fix a person actually reads is this one — and it was built from the
    /// bare host while both bodies spelled a destination. A `denied-default` on `:8443` told the
    /// user to run `sbx net allow api.test`, which writes an https rule on **443** and leaves the
    /// retry refused by the very policy they had just been told to fix; a cleartext refusal got the
    /// same command, which writes an https rule that cannot open the clear at all. Both now go
    /// through the one [`rule_destination`](super::rule_destination) the bodies use.
    #[test]
    fn a_refusal_notification_offers_the_destination_it_was_refused_on() {
        fn announced(proto: crate::sandbox::control::Proto, port: u16) -> String {
            let seen = Arc::new(Mutex::new(Vec::new()));
            let notifier = Arc::new(Notifier::recording(
                NotifyPolicy::uniform(NotifyMode::Once),
                Box::new(Recorder(Arc::clone(&seen))),
            ));
            {
                let ctx = ProxyCtx::new(
                    Arc::new(crate::sandbox::proxy::ca::Ca::ephemeral().unwrap()),
                    EgressPolicy::default(),
                )
                .unwrap()
                .with_notifier(Arc::clone(&notifier));
                ctx.outcome(
                    proto,
                    "api.test",
                    port,
                    Some("GET"),
                    Some("/v1/thing"),
                    StatKind::Deny,
                    "denied-default",
                );
            }
            drop(
                Arc::try_unwrap(notifier)
                    .map_err(|_| "the notifier is still shared")
                    .unwrap(),
            );
            let out = seen.lock().unwrap().clone();
            assert_eq!(out.len(), 1, "one refusal, one announcement: {out:?}");
            out[0].clone()
        }

        use crate::sandbox::control::Proto;
        for (proto, port, expected) in [
            // Inspected TLS: the bare host only where the port already is the scheme's default.
            (Proto::Https, 443u16, "sbx net allow api.test"),
            (Proto::Https, 8443, "sbx net allow api.test:8443"),
            // Cleartext: the scheme always (a bare host is an https/443 rule), and the port past 80.
            (Proto::Http, 80, "sbx net allow http://api.test"),
            (Proto::Http, 8080, "sbx net allow http://api.test:8080"),
        ] {
            let body = announced(proto, port);
            assert!(
                body.ends_with(&format!(" · allow it: {expected}")),
                "a {proto:?} refusal on :{port} must offer `{expected}`, got {body:?}"
            );
        }
    }
}
