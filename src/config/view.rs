//! The presentation-agnostic view model for `ops config`.
//!
//! [`ConfigView`] is a serializable projection of the resolved configuration: every value is a
//! plain `String`/`bool`/local enum, so it carries no dependency on the resolution internals
//! (`allowlist::Rule`, `trust::TrustState`, the channel-lock types) and any front-end can render
//! or serialize it without pulling those in. [`build`] assembles it — the same data `ops config`
//! has always shown — by loading and projecting the resolved configuration plus the channel
//! locks. The CLI presenter and a future management UI are both adapters over this one model.
//!
//! It carries the provenance of each baseline value — which layer (`Default`/`Global`/`Project`)
//! supplied it: per-entry for `env`/`binds`, and per-field for the scalar postures (`network`,
//! `gui`) and the cgroup `limits` — so `ops config` can show where every value came from. What it
//! still does *not* carry: a queryable schema, an affordance for a management UI that does not yet
//! exist; it is added when that consumer is concrete, against its real shape.

use std::collections::BTreeMap;
use std::path::Path;

use serde::Serialize;

use super::{Backend, NetworkPolicy, Resolved};
use crate::trust::TrustState;
use crate::{sandbox, store};

/// A serializable projection of the resolved configuration for a directory — the model both the
/// `ops config` CLI and a future management front-end render. Field order mirrors the CLI's
/// long-standing display order so a presenter can walk it top to bottom.
#[derive(Serialize)]
pub(crate) struct ConfigView {
    /// The directory this configuration was resolved for.
    pub(crate) cwd: String,
    /// Extra environment, in application order (a later entry wins at the same key).
    pub(crate) env: Vec<EnvVar>,
    /// Extra host paths bound read-only, already canonicalized to what the launch would mount,
    /// each tagged with the layer that declared it.
    pub(crate) binds: Vec<BindView>,
    /// Declared `[packages]` tools, each with its backend and trust verdict.
    pub(crate) packages: Vec<PackageView>,
    /// The project's mise file and whether it would be honored, when one is present.
    pub(crate) mise: Option<MiseView>,
    /// The tools the project's mise file declares (parsed only — nothing realised).
    pub(crate) tools: ToolsView,
    /// The nixpkgs source the tools resolve against, and its locked revision when resolved.
    pub(crate) nixpkgs: ChannelView,
    /// The mise engine's own channel and locked revision (decoupled from the base channel).
    pub(crate) engine: ChannelView,
    /// The resolved network posture.
    pub(crate) network: NetworkView,
    /// Which layer supplied the network posture (`Default` when neither config set it).
    pub(crate) network_origin: ProvenanceView,
    /// Whether the egress proxy records `ops net stats` (on by default; off via `[network] stats =
    /// false`). Only meaningful under a filtering posture (the proxy runs only then).
    pub(crate) egress_stats: bool,
    /// The resolved GUI posture.
    pub(crate) gui: GuiView,
    /// Which layer supplied the GUI posture (`Default` when neither config set it).
    pub(crate) gui_origin: ProvenanceView,
    /// The cage's effective cgroup resource limits (anti-DoS), each a config override or the default.
    pub(crate) limits: LimitsView,
    /// Credentials the egress proxy injects (by destination and source locator, never the value).
    pub(crate) secrets: Vec<SecretView>,
    /// Named application profiles, each a gated overlay over the baseline.
    pub(crate) apps: Vec<AppView>,
    /// Notes about what was dropped or ignored and why — rendered out of band (the CLI's stderr).
    pub(crate) warnings: Vec<String>,
}

/// One extra environment entry, with the layer whose value won at this key.
#[derive(Serialize)]
pub(crate) struct EnvVar {
    pub(crate) key: String,
    pub(crate) value: String,
    /// Which config layer supplied the winning value, when known.
    pub(crate) layer: Option<ProvenanceView>,
}

/// One extra read-only bind: the canonical host path and the layer that declared it.
#[derive(Serialize)]
pub(crate) struct BindView {
    pub(crate) path: String,
    /// Which config layer declared the bind, when known.
    pub(crate) layer: Option<ProvenanceView>,
}

/// Where a resolved value came from — the presentation-agnostic mirror of [`super::Provenance`].
/// `Default` is ops's built-in, `Global`/`Project` the two config files; `Inherited` is the per-app
/// view's marker for a field the app overlay did not set (it takes the baseline's value).
#[derive(Serialize, Clone, Copy, PartialEq, Eq, Default, Debug)]
pub(crate) enum ProvenanceView {
    #[default]
    Default,
    Global,
    Project,
    Inherited,
}

impl From<super::Provenance> for ProvenanceView {
    fn from(p: super::Provenance) -> Self {
        match p {
            super::Provenance::Default => ProvenanceView::Default,
            super::Provenance::Global => ProvenanceView::Global,
            super::Provenance::Project => ProvenanceView::Project,
        }
    }
}

/// A declared package: its name, backend (`nix`/`mise`/`flake`) and locator, how it is realised,
/// and whether the layer that declared it was trusted (an untrusted layer's package is withheld).
#[derive(Serialize)]
pub(crate) struct PackageView {
    pub(crate) name: String,
    pub(crate) backend: String,
    pub(crate) locator: String,
    /// How the backend realises the package — a host-side store path, an in-cage mise fetch, …
    pub(crate) realised: String,
    pub(crate) trusted: bool,
    /// Why it was withheld, when it was (`None` for a trusted, admitted package).
    pub(crate) withheld_reason: Option<String>,
    /// The locked revision when this is a `flake:` package `ops upgrade flake` has pinned; `None`
    /// for a floating flake package (no lock entry) or any non-flake backend.
    pub(crate) pinned_rev: Option<String>,
}

/// The project's mise file: its name and whether the project's trust would honor it.
#[derive(Serialize)]
pub(crate) struct MiseView {
    pub(crate) name: String,
    pub(crate) trusted: bool,
    pub(crate) withheld_reason: Option<String>,
}

/// The tools a mise file declares, split by how the launcher would equip each.
#[derive(Serialize, Default)]
pub(crate) struct ToolsView {
    /// `nix:` tools — host-provisioned, gated by the mise file's trust.
    pub(crate) nix: Vec<NixToolView>,
    /// Tools for another backend — auto-equipped in-cage by mise (so honored regardless of trust).
    pub(crate) non_nix: Vec<NonNixToolView>,
    /// Malformed `nix:` tokens that cannot be resolved.
    pub(crate) malformed: Vec<String>,
}

impl ToolsView {
    pub(crate) fn is_empty(&self) -> bool {
        self.nix.is_empty() && self.non_nix.is_empty() && self.malformed.is_empty()
    }
}

/// A `nix:` tool a mise file declares: package, version, and trust verdict.
#[derive(Serialize)]
pub(crate) struct NixToolView {
    pub(crate) pkg: String,
    pub(crate) version: String,
    pub(crate) trusted: bool,
    pub(crate) withheld_reason: Option<String>,
}

/// A non-`nix:` tool a mise file declares. `equipped` is false when the network posture is
/// `none`, which prevents the in-cage fetch.
#[derive(Serialize)]
pub(crate) struct NonNixToolView {
    pub(crate) token: String,
    pub(crate) version: String,
    pub(crate) equipped: bool,
}

/// A managed channel (the base nixpkgs or the mise engine): its source, where the source came
/// from, and the full revision its lock is pinned to when one has been resolved.
#[derive(Serialize)]
pub(crate) struct ChannelView {
    pub(crate) source: String,
    pub(crate) origin: String,
    /// The full locked revision (the presenter shortens it for display), or `None` when unlocked.
    pub(crate) locked_rev: Option<String>,
}

/// What a request matching no rule gets under the filtered-egress posture: `Deny` (the classic
/// allowlist — nothing but the listed/built-in hosts reaches), `Allow` (a denylist — everything
/// public reaches except the deny carve-outs, proxy still active), or `Ask` (the request parks for
/// a live host-side decision).
#[derive(Serialize, Clone, Copy, PartialEq, Eq)]
pub(crate) enum NetDefaultView {
    Deny,
    Allow,
    Ask,
}

impl From<crate::allowlist::DefaultAction> for NetDefaultView {
    fn from(action: crate::allowlist::DefaultAction) -> Self {
        match action {
            crate::allowlist::DefaultAction::Deny => NetDefaultView::Deny,
            crate::allowlist::DefaultAction::Allow => NetDefaultView::Allow,
            crate::allowlist::DefaultAction::Ask => NetDefaultView::Ask,
        }
    }
}

/// The resolved network posture.
#[derive(Serialize)]
pub(crate) enum NetworkView {
    /// The host network (the default; no confidentiality guarantee yet).
    Shared,
    /// An empty netns — no network at all.
    Isolated,
    /// Filtered egress enforced by the host proxy through an empty-netns cage. `default_action`
    /// is the verdict for an unmatched request; `builtin` is the always-allowed nix-cache set,
    /// surfaced so it is never a silent allowance; `ask_timeout` is the parked-request wait under
    /// the `ask` default (`Some("90s")`, `Some("none")` for an indefinite wait, or `None` when the
    /// default is not `ask` so the field is moot); `ask_notice` is whether the park notice prints
    /// under the `ask` default (`None` when moot).
    Allowlist {
        default_action: NetDefaultView,
        ask_timeout: Option<String>,
        ask_notice: Option<bool>,
        allow: Vec<String>,
        deny: Vec<String>,
        builtin: Vec<String>,
    },
}

/// Whether a listed egress rule allows or denies.
#[derive(Serialize, Clone, Copy, PartialEq, Eq)]
pub(crate) enum NetRuleKind {
    Allow,
    Deny,
}

/// Where a listed egress rule came from: the resolved config (`.ops.toml`/global, after the trust
/// gate), the always-allowed built-in nix-cache set, or `Manual` — a runtime rule a live `ask`
/// session remembered from a `--session` answer (it lives in that session's memory, not config).
#[derive(Serialize, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RuleSourceView {
    Config,
    Builtin,
    Manual,
}

/// One egress rule projected for `ops net rules`: its kind, its source, and its display text.
#[derive(Serialize, Clone)]
pub(crate) struct NetRuleView {
    pub(crate) kind: NetRuleKind,
    pub(crate) source: RuleSourceView,
    pub(crate) rule: String,
}

/// Project a filtered-egress policy's rules for listing: the config allow rules, then the config
/// deny rules, then the built-in nix-cache allow set — each tagged with its source. The built-in
/// set is the same one [`network_view`] surfaces, so the two cannot drift. Only meaningful under a
/// filtering posture; `shared`/`none` carry no rules, which the caller handles.
pub(crate) fn net_rules_view(policy: &crate::allowlist::EgressPolicy) -> Vec<NetRuleView> {
    let mut rules = Vec::new();
    for r in policy.allow_rules() {
        rules.push(NetRuleView {
            kind: NetRuleKind::Allow,
            source: RuleSourceView::Config,
            rule: r.to_string(),
        });
    }
    for r in policy.deny_rules() {
        rules.push(NetRuleView {
            kind: NetRuleKind::Deny,
            source: RuleSourceView::Config,
            rule: r.to_string(),
        });
    }
    for h in sandbox::nix_cache_hosts() {
        rules.push(NetRuleView {
            kind: NetRuleKind::Allow,
            source: RuleSourceView::Builtin,
            rule: h.to_string(),
        });
    }
    rules
}

/// The resolved GUI posture.
#[derive(Serialize)]
pub(crate) enum GuiView {
    None,
    Wayland,
}

/// The cage's effective cgroup resource limits: the throttle threshold, the hard memory ceiling,
/// and the task cap, each its config override when set or ops's built-in default otherwise.
#[derive(Serialize, Default)]
pub(crate) struct LimitsView {
    pub(crate) memory_high: LimitView,
    pub(crate) memory_max: LimitView,
    pub(crate) tasks_max: LimitView,
}

/// One effective resource limit: its value and which layer supplied it (`Default` for the built-in
/// value, `Global`/`Project` for a config `[limits]` override).
#[derive(Serialize, Default)]
pub(crate) struct LimitView {
    pub(crate) value: String,
    pub(crate) origin: ProvenanceView,
}

/// An injected credential, by destination and source — never the plaintext, which ops reads only
/// host-side at launch.
#[derive(Serialize)]
pub(crate) struct SecretView {
    pub(crate) header: String,
    pub(crate) to: String,
    pub(crate) shape: String,
    pub(crate) sources: String,
}

/// One environment entry an app overlay adds over the baseline. It carries no per-entry layer:
/// the resolved overlay flattens its global and project sources into one list, so unlike the
/// baseline `env` there is no single layer to attribute. The value is shown as-is — `env` is a
/// free field that enters the cage (an in-cage placeholder for a credential profile), not the
/// injected secret, which never appears.
#[derive(Serialize)]
pub(crate) struct AppEnvVar {
    pub(crate) key: String,
    pub(crate) value: String,
}

/// An app overlay's own network posture, projected for display. An allowlist carries its declared
/// allow/deny rules and the always-allowed built-in nix-cache set: the proxy unions that set into
/// whatever policy is in effect at launch, so for an app it is part of what `ops app <name>` can
/// reach — and the baseline `network` section shows it only when the *baseline* is an allowlist, so
/// a profile that puts its allowlist in the app overlay (the common case) would otherwise show it
/// nowhere. The CLI shows this compactly by default and expands the rules under `--details`.
#[derive(Serialize)]
pub(crate) enum AppNetworkView {
    Shared,
    Isolated,
    Allowlist {
        default_action: NetDefaultView,
        ask_timeout: Option<String>,
        ask_notice: Option<bool>,
        allow: Vec<String>,
        deny: Vec<String>,
        builtin: Vec<String>,
    },
}

/// An app overlay's own cgroup limit overrides, projected for display: only the fields the app
/// itself tunes, each as its systemd token. Unlike the baseline `limits` view (which shows the
/// effective value or the built-in default), an app inherits the baseline's *resolved* value for
/// an unset field — possibly itself an override — so reporting a default here would misstate what
/// the app changes. `None` overall means the app tunes no limit and inherits the baseline whole.
#[derive(Serialize)]
pub(crate) struct AppLimitsView {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) memory_high: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) memory_max: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) tasks_max: Option<String>,
}

/// A named application profile: the command it runs and what its gated overlay adds.
#[derive(Serialize)]
pub(crate) struct AppView {
    pub(crate) name: String,
    /// The argv joined for display, or `None` when no layer declared a command.
    pub(crate) cmd: Option<String>,
    /// Where the app's persistent home is keyed, as a human phrase.
    pub(crate) home_scope: String,
    /// The environment this overlay adds over the baseline (the app wins on a key collision when
    /// the two are merged at launch) — the overlay's own entries, not the baseline-merged set. A
    /// count by default, each `KEY=value` under `--details`.
    pub(crate) env: Vec<AppEnvVar>,
    /// The read-only host binds this overlay adds over the baseline — a security field, gated like
    /// the baseline binds. The overlay's own paths, canonicalized to what a launch would mount. A
    /// count by default, each path under `--details`.
    pub(crate) binds: Vec<String>,
    /// The packages this overlay declares — the same projection the baseline `packages` section
    /// carries (backend, locator, realisation, trust verdict, and a `flake:` pin), so an untrusted
    /// app package reads as withheld here exactly as it would be withheld at launch, and the
    /// backend is visible under `--details`. The overlay's own packages, not the baseline-merged
    /// set. A compact name list by default; each full line under `--details`.
    pub(crate) packages: Vec<PackageView>,
    /// The app's own network posture, with an allowlist's rules, when it set one.
    pub(crate) network: Option<AppNetworkView>,
    /// The app's own GUI posture, when it set one — the same [`GuiView`] the baseline `gui` field
    /// carries, so the overlay and the baseline render and serialize a display identically.
    pub(crate) gui: Option<GuiView>,
    /// The cgroup limits this overlay overrides, when it tunes any — its *own* fields, not the
    /// baseline-merged set, so an app that changes nothing shows nothing.
    pub(crate) limits: Option<AppLimitsView>,
    /// The credentials this overlay injects, host-side at launch — its *own* `[secret]` sections
    /// (global and project), gated, not the baseline's. The merge unions them with the baseline
    /// only for the launch itself; the view shows the overlay's additions. Each carries only its
    /// destination, header, shape, and source locator — never the value. The CLI shows a count by
    /// default and lists each under `--details`.
    pub(crate) secrets: Vec<SecretView>,
    /// Per-app notes about what its resolution dropped or ignored.
    pub(crate) notes: Vec<String>,
}

/// The *effective* configuration one app launches with — the baseline folded with the app's
/// overlay — annotated, field by field, with where each value came from: `inherited` (the overlay
/// set none of its own, so the baseline's value stands), `app:global`/`app:project` (the app
/// declaration in that config file set it). This is what `ops config show --app <name>` renders,
/// and it answers "what does this app actually run with, and which of it did the app change?" — a
/// view the compact baseline `apps:` section (overlay-own only) cannot give. Scalars carry their
/// effective value plus a [`ProvenanceView`]; collections carry the overlay's *own* additions plus
/// a count of how many baseline entries they inherit (never the inherited entries themselves —
/// those live in the baseline `ops config show`, one hop away).
#[derive(Serialize)]
pub(crate) struct AppDetailView {
    pub(crate) name: String,
    pub(crate) cwd: String,
    /// The argv joined for display, or `None` when no layer declared one (an unlaunchable app).
    pub(crate) cmd: Option<String>,
    /// Which app layer set the command (`Global`/`Project`); never inherited (the baseline has no
    /// command of its own).
    pub(crate) cmd_origin: ProvenanceView,
    pub(crate) home_scope: String,
    /// `Default` for the built-in `global` scope, else which app layer set it.
    pub(crate) home_scope_origin: ProvenanceView,
    /// The effective network posture (the app's own, else the baseline's).
    pub(crate) network: NetworkView,
    pub(crate) network_origin: ProvenanceView,
    /// The effective GUI posture (the app's own, else the baseline's).
    pub(crate) gui: GuiView,
    pub(crate) gui_origin: ProvenanceView,
    /// The effective cgroup limits — the app's overrides folded onto the baseline — each field
    /// carrying its provenance (`Inherited` when the app left it to the baseline).
    pub(crate) limits: LimitsView,
    /// The environment this app *adds* over the baseline (its overlay-own entries), and how many
    /// baseline entries it inherits unchanged.
    pub(crate) env: Vec<AppEnvVar>,
    pub(crate) env_inherited: usize,
    /// The read-only binds this app adds, and the count it inherits from the baseline.
    pub(crate) binds: Vec<String>,
    pub(crate) binds_inherited: usize,
    /// The packages this app declares (its own), and the count it inherits from the baseline.
    pub(crate) packages: Vec<PackageView>,
    pub(crate) packages_inherited: usize,
    /// The credentials this app injects (its own), and the count it inherits from the baseline.
    /// Both are zero when the app's effective network is not an allowlist: the launch injects no
    /// credential then, so the view does not report one either (mirroring the launch's posture).
    pub(crate) secrets: Vec<SecretView>,
    pub(crate) secrets_inherited: usize,
    /// Notes about what this app's resolution dropped or ignored.
    pub(crate) notes: Vec<String>,
}

/// Assemble the view for a directory: load and resolve the configuration, then project it (plus
/// the channel locks, which need a touch of I/O) into the serializable model. This is the data
/// gathering only — no realisation, no nix, no network — exactly as `ops config` has always been.
pub(crate) fn build(cwd: &Path) -> ConfigView {
    build_scoped(cwd, super::Source::All)
}

/// Assemble the view restricted to one configuration `source` — the single-source `ops config show
/// --global/--local/--default` views. `build(cwd)` is `build_scoped(cwd, Source::All)`; a
/// restricted form projects the same model from fewer layers, so each value's provenance tag reads
/// as what that source contributes over the built-in defaults.
pub(crate) fn build_scoped(cwd: &Path, source: super::Source) -> ConfigView {
    let resolved = super::load_scoped(cwd, source);

    let env = resolved
        .env
        .iter()
        .map(|(k, v)| EnvVar {
            key: k.clone(),
            value: v.clone(),
            layer: resolved.env_layer.get(k).copied().map(ProvenanceView::from),
        })
        .collect();

    let binds = resolved
        .ro_binds
        .iter()
        .map(|b| BindView {
            path: b.display().to_string(),
            layer: resolved
                .bind_layer
                .get(b)
                .copied()
                .map(ProvenanceView::from),
        })
        .collect();

    // The pinned revisions of any `flake:` packages, read network-free from the per-project lock —
    // the same source the launch consults — so the view can show a pin without resolving anything.
    let flake_pins = sandbox::flake_pinned_revs(cwd);

    let packages = resolved
        .packages
        .iter()
        .map(|p| package_view(p, &flake_pins))
        .collect();

    let mise = resolved.mise.as_ref().map(|m| MiseView {
        name: m.name.clone(),
        trusted: m.state == TrustState::Trusted,
        withheld_reason: (m.state != TrustState::Trusted)
            .then(|| super::untrusted_reason(m.state).to_string()),
    });

    let tools = resolved
        .mise
        .as_ref()
        .map(|m| tools_view(m, &resolved))
        .unwrap_or_default();

    let nixpkgs = nixpkgs_channel(cwd, &resolved);
    let engine = engine_channel(&resolved);
    let network = network_view(&resolved.network);
    let gui = match resolved.gui {
        super::GuiPolicy::Wayland => GuiView::Wayland,
        super::GuiPolicy::None => GuiView::None,
    };
    let limits = limits_view(&resolved.limits, &resolved.limits_origin);

    let secrets = resolved
        .secrets
        .iter()
        .map(|s| SecretView {
            header: s.header.clone(),
            to: s.to.to_string(),
            shape: s.shape.describe(),
            sources: s.describe_sources(),
        })
        .collect();

    let apps = resolved
        .apps
        .iter()
        .map(|(name, app)| {
            // The app's effective network decides whether its credentials inject — the same posture
            // the launch enforces. Pass it so the compact roster agrees with the launch (and the
            // `--app` detail view), never claiming an injection a narrowed network drops.
            let eff_network = app.network.as_ref().unwrap_or(&resolved.network);
            app_view(name, app, eff_network, &flake_pins)
        })
        .collect();

    ConfigView {
        cwd: cwd.display().to_string(),
        env,
        binds,
        packages,
        mise,
        tools,
        nixpkgs,
        engine,
        network,
        network_origin: resolved.network_origin.into(),
        egress_stats: resolved.egress_stats,
        gui,
        gui_origin: resolved.gui_origin.into(),
        limits,
        secrets,
        apps,
        warnings: resolved.warnings.clone(),
    }
}

/// Project one declared package, recording its backend, how it is realised, the trust verdict,
/// and — for a `flake:` package — its locked revision from the per-project lock (`None` floats).
fn package_view(p: &super::Package, flake_pins: &BTreeMap<String, String>) -> PackageView {
    let realised = match p.backend {
        Backend::Nix(_) => "host-side, durable",
        Backend::Mise(_) => "in-cage via mise, fetched at launch",
        Backend::Flake(_) => "in-cage via nix build, fetched at launch",
    };
    let trusted = p.state == TrustState::Trusted;
    PackageView {
        name: p.name.clone(),
        backend: p.backend.label().to_string(),
        locator: p.backend.locator().to_string(),
        realised: realised.to_string(),
        trusted,
        withheld_reason: (!trusted).then(|| super::untrusted_reason(p.state).to_string()),
        pinned_rev: flake_pinned_rev(&p.backend, flake_pins),
    }
}

/// The locked revision for a `flake:` package, looked up by its declared reference (the lock key,
/// byte-identical to the locator); `None` for a floating flake package or any other backend.
fn flake_pinned_rev(backend: &Backend, flake_pins: &BTreeMap<String, String>) -> Option<String> {
    match backend {
        Backend::Flake(reference) => flake_pins.get(reference).cloned(),
        Backend::Nix(_) | Backend::Mise(_) => None,
    }
}

/// Project the tools a mise file declares: `nix:` tools carry the file's trust verdict; a
/// non-`nix:` tool is equipped in-cage unless `network = "none"` prevents the fetch.
fn tools_view(m: &super::MiseConfig, resolved: &Resolved) -> ToolsView {
    let declared = sandbox::parse_nix_tools(&m.files);
    let trusted = m.state == TrustState::Trusted;
    let withheld = (!trusted).then(|| super::untrusted_reason(m.state).to_string());
    let net_none = matches!(resolved.network, NetworkPolicy::Isolated);

    ToolsView {
        nix: declared
            .nix
            .iter()
            .map(|t| NixToolView {
                pkg: t.pkg.clone(),
                version: t.version.clone(),
                trusted,
                withheld_reason: withheld.clone(),
            })
            .collect(),
        non_nix: declared
            .non_nix
            .iter()
            .map(|t| NonNixToolView {
                token: t.token.clone(),
                version: t.version.clone(),
                equipped: !net_none,
            })
            .collect(),
        malformed: declared.malformed.clone(),
    }
}

/// The nixpkgs channel view, routed through the launch's own channel decision so it reports
/// exactly the lock a launch would consult. Best-effort: if the data dir or project identity
/// cannot be resolved, it falls back to the source and origin alone.
fn nixpkgs_channel(cwd: &Path, resolved: &Resolved) -> ChannelView {
    if let Some(layout) = store::Layout::from_env() {
        if let Ok(target) = sandbox::effective_lock_target(cwd, &layout, resolved) {
            return ChannelView {
                source: target.source().to_string(),
                origin: target.origin().label().to_string(),
                locked_rev: target.locked_revision(),
            };
        }
    }
    let (source, origin) = match (&resolved.nixpkgs_project, &resolved.nixpkgs_global) {
        (Some(p), _) => (p.as_str(), "project pin"),
        (None, Some(g)) => (g.as_str(), "global"),
        (None, None) => ("nixos-unstable", "default"),
    };
    ChannelView {
        source: source.to_string(),
        origin: origin.to_string(),
        locked_rev: None,
    }
}

/// The mise-engine channel view, from its dedicated lock (a project pin never moves the engine).
/// Best-effort like [`nixpkgs_channel`].
fn engine_channel(resolved: &Resolved) -> ChannelView {
    if let Some(layout) = store::Layout::from_env() {
        let target = store::LockTarget::engine(&layout, resolved.nixpkgs_global.as_deref());
        return ChannelView {
            source: target.source().to_string(),
            origin: target.origin().label().to_string(),
            locked_rev: target.locked_revision(),
        };
    }
    let (source, origin) = match &resolved.nixpkgs_global {
        Some(g) => (g.as_str(), "global"),
        None => ("nixos-unstable", "default"),
    };
    ChannelView {
        source: source.to_string(),
        origin: origin.to_string(),
        locked_rev: None,
    }
}

/// Project the network posture, surfacing an allowlist's allow/deny rules and the always-allowed
/// nix-cache set so the effective policy is visible at a glance.
fn network_view(network: &NetworkPolicy) -> NetworkView {
    match network {
        NetworkPolicy::Shared => NetworkView::Shared,
        NetworkPolicy::Isolated => NetworkView::Isolated,
        NetworkPolicy::Allowlist(a) => NetworkView::Allowlist {
            default_action: a.default_action().into(),
            ask_timeout: ask_timeout_view(a),
            ask_notice: ask_notice_view(a),
            allow: a.allow_rules().iter().map(|r| r.to_string()).collect(),
            deny: a.deny_rules().iter().map(|r| r.to_string()).collect(),
            builtin: sandbox::nix_cache_hosts()
                .iter()
                .map(|h| h.to_string())
                .collect(),
        },
    }
}

/// Whether the `ask` park notice prints, projected for display: `None` when the default action is
/// not `ask` (moot), else `Some(true)` (shown, the default) or `Some(false)` (silenced by
/// `ask_notice = false`). Surfaced so a silenced notice is visible in `ops config`.
fn ask_notice_view(a: &crate::allowlist::EgressPolicy) -> Option<bool> {
    if a.default_action() != crate::allowlist::DefaultAction::Ask {
        return None;
    }
    Some(a.ask_notice())
}

/// The ask-default's parked-request wait, projected for display: `None` when the default action is
/// not `ask` (the field is moot), `Some("none")` for an indefinite wait, or `Some("90s")` for a
/// configured bound. Surfaced so a configured timeout is visible in `ops config`.
fn ask_timeout_view(a: &crate::allowlist::EgressPolicy) -> Option<String> {
    if a.default_action() != crate::allowlist::DefaultAction::Ask {
        return None;
    }
    Some(match a.ask_timeout() {
        None => "none".to_string(),
        Some(d) => fmt_secs(d.as_secs()),
    })
}

/// Format a whole-second duration compactly: `2h`/`5m` when it divides evenly into hours/minutes,
/// else plain seconds (`90s`). Used only for display, so the coarse forms are fine.
fn fmt_secs(secs: u64) -> String {
    if secs != 0 && secs.is_multiple_of(3600) {
        format!("{}h", secs / 3600)
    } else if secs != 0 && secs.is_multiple_of(60) {
        format!("{}m", secs / 60)
    } else {
        format!("{secs}s")
    }
}

/// Project the cage's effective resource limits — each the config override when set, or ops's
/// built-in default — with the layer that supplied it, so `ops config` shows what the launch would
/// actually apply and where each limit came from.
fn limits_view(limits: &sandbox::cgroup::Limits, origin: &super::LimitsOrigin) -> LimitsView {
    let project = |(value, _overridden): (String, bool), origin: super::Provenance| LimitView {
        value,
        origin: origin.into(),
    };
    LimitsView {
        memory_high: project(limits.memory_high(), origin.memory_high),
        memory_max: project(limits.memory_max(), origin.memory_max),
        tasks_max: project(limits.tasks_max(), origin.tasks_max),
    }
}

/// Project one app overlay for display: its command, home scope, and the gated fields it adds.
fn app_view(
    name: &str,
    app: &super::ResolvedApp,
    eff_network: &NetworkPolicy,
    flake_pins: &BTreeMap<String, String>,
) -> AppView {
    // A credential injects only under an allowlist (the proxy that performs it). When the app's
    // effective network is anything else, the launch injects none, so the roster shows none too —
    // the same posture `enforce_secret_posture` applies at merge, kept consistent across views.
    let injects = matches!(eff_network, NetworkPolicy::Allowlist(_));
    AppView {
        name: name.to_string(),
        cmd: (!app.cmd.is_empty()).then(|| app.cmd.join(" ")),
        home_scope: match app.home_scope {
            super::AppHomeScope::Global => "global (shared across projects)".to_string(),
            super::AppHomeScope::Project => "per-project".to_string(),
        },
        env: app
            .env
            .iter()
            .map(|(key, value)| AppEnvVar {
                key: key.clone(),
                value: value.clone(),
            })
            .collect(),
        binds: app
            .ro_binds
            .iter()
            .map(|b| b.display().to_string())
            .collect(),
        packages: app
            .packages
            .iter()
            .map(|p| package_view(p, flake_pins))
            .collect(),
        network: app.network.as_ref().map(|n| match n {
            NetworkPolicy::Shared => AppNetworkView::Shared,
            NetworkPolicy::Isolated => AppNetworkView::Isolated,
            NetworkPolicy::Allowlist(a) => AppNetworkView::Allowlist {
                default_action: a.default_action().into(),
                ask_timeout: ask_timeout_view(a),
                ask_notice: ask_notice_view(a),
                allow: a.allow_rules().iter().map(|r| r.to_string()).collect(),
                deny: a.deny_rules().iter().map(|r| r.to_string()).collect(),
                builtin: sandbox::nix_cache_hosts()
                    .iter()
                    .map(|h| h.to_string())
                    .collect(),
            },
        }),
        gui: app.gui.as_ref().map(|g| match g {
            super::GuiPolicy::Wayland => GuiView::Wayland,
            super::GuiPolicy::None => GuiView::None,
        }),
        limits: app_limits_view(&app.limits),
        secrets: if injects {
            app.secrets
                .iter()
                .map(|s| SecretView {
                    header: s.header.clone(),
                    to: s.to.to_string(),
                    shape: s.shape.describe(),
                    sources: s.describe_sources(),
                })
                .collect()
        } else {
            Vec::new()
        },
        notes: app.warnings.clone(),
    }
}

/// Project an app overlay's *own* limit overrides — only the fields it set — or `None` when it
/// tunes nothing (it then inherits the baseline limits whole).
fn app_limits_view(limits: &sandbox::cgroup::Limits) -> Option<AppLimitsView> {
    let overrides_something =
        limits.memory_high.is_some() || limits.memory_max.is_some() || limits.tasks_max.is_some();
    overrides_something.then(|| AppLimitsView {
        memory_high: limits.memory_high.clone(),
        memory_max: limits.memory_max.clone(),
        tasks_max: limits.tasks_max.clone(),
    })
}

/// Assemble the per-app detail view for `name` in `cwd` — the effective configuration `ops app
/// <name>` would launch with, annotated with provenance. `None` when no such app is declared (the
/// CLI then errors, listing the available names). Pure data gathering, like [`build`].
pub(crate) fn build_app_detail(cwd: &Path, name: &str) -> Option<AppDetailView> {
    let resolved = super::load(cwd);
    let app = resolved.apps.get(name)?;
    let flake_pins = sandbox::flake_pinned_revs(cwd);
    Some(app_detail_view(cwd, name, app, &resolved, &flake_pins))
}

/// Project one app's effective configuration plus per-field provenance: a scalar the app set is
/// attributed to its app layer, one it left alone is `Inherited` and shows the baseline's value;
/// collections carry the overlay's own entries and a count of the baseline entries they inherit
/// (those a same-key overlay entry shadows are not counted as inherited). Credentials additionally
/// mirror the launch's secret-vs-network posture: when the effective network is not an allowlist,
/// the launch injects none, so the view reports none (and carries the same drop note).
fn app_detail_view(
    cwd: &Path,
    name: &str,
    app: &super::ResolvedApp,
    baseline: &Resolved,
    flake_pins: &BTreeMap<String, String>,
) -> AppDetailView {
    // Effective network/GUI: the app's own posture when it set one, else the baseline's.
    let eff_network = app.network.as_ref().unwrap_or(&baseline.network);
    let network = network_view(eff_network);
    let network_origin = origin_or_inherited(app.network.is_some(), app.network_origin);
    let eff_gui = app.gui.unwrap_or(baseline.gui);
    let gui = match eff_gui {
        super::GuiPolicy::Wayland => GuiView::Wayland,
        super::GuiPolicy::None => GuiView::None,
    };
    let gui_origin = origin_or_inherited(app.gui.is_some(), app.gui_origin);

    // Effective limits: the app's overrides folded onto the baseline; each field's origin is the
    // app's when it set the field, else inherited from the baseline.
    let mut eff_limits = baseline.limits.clone();
    super::overlay_limits(&mut eff_limits, app.limits.clone());
    let limit = |(value, _ov): (String, bool), set: bool, origin: super::Provenance| LimitView {
        value,
        origin: origin_or_inherited(set, origin),
    };
    let limits = LimitsView {
        memory_high: limit(
            eff_limits.memory_high(),
            app.limits.memory_high.is_some(),
            app.limits_origin.memory_high,
        ),
        memory_max: limit(
            eff_limits.memory_max(),
            app.limits.memory_max.is_some(),
            app.limits_origin.memory_max,
        ),
        tasks_max: limit(
            eff_limits.tasks_max(),
            app.limits.tasks_max.is_some(),
            app.limits_origin.tasks_max,
        ),
    };

    // Collections: the overlay's own entries, plus how many baseline entries are inherited. A
    // baseline entry shadowed by a same-key/-name/-target overlay entry is not inherited (it is the
    // app's own) — `merge_app` dedups env/packages/binds and folds secrets through the same
    // `(to, header)` upsert, so the inherited counts mirror that.
    let env_inherited = baseline
        .env
        .iter()
        .filter(|(k, _)| !app.env.iter().any(|(ak, _)| ak == k))
        .count();
    let packages_inherited = baseline
        .packages
        .iter()
        .filter(|p| !app.packages.iter().any(|ap| ap.name == p.name))
        .count();

    // Effective credentials mirror `merge_app`: the baseline's plus the app's, then
    // `enforce_secret_posture` clears *all* of them when the effective network is not an
    // allowlist (the proxy that injects them runs only under one). Reproduce that check so the
    // count — and the note — match what `ops app <name>` would actually inject; otherwise the
    // view over-reports credentials an app silently drops by narrowing its network.
    let mut eff_secrets = baseline.declared_secrets.clone();
    eff_secrets.extend(app.secrets.iter().cloned());
    let mut secret_notes = Vec::new();
    super::enforce_secret_posture(eff_network, &mut eff_secrets, &mut secret_notes);
    let secrets_dropped =
        eff_secrets.is_empty() && !(baseline.declared_secrets.is_empty() && app.secrets.is_empty());
    let mut notes = app.warnings.clone();
    notes.extend(secret_notes);

    AppDetailView {
        name: name.to_string(),
        cwd: cwd.display().to_string(),
        cmd: (!app.cmd.is_empty()).then(|| app.cmd.join(" ")),
        cmd_origin: app.cmd_origin.into(),
        home_scope: match app.home_scope {
            super::AppHomeScope::Global => "global (shared across projects)".to_string(),
            super::AppHomeScope::Project => "per-project".to_string(),
        },
        home_scope_origin: app
            .home_scope_origin
            .map_or(ProvenanceView::Default, Into::into),
        network,
        network_origin,
        gui,
        gui_origin,
        limits,
        env: app
            .env
            .iter()
            .map(|(key, value)| AppEnvVar {
                key: key.clone(),
                value: value.clone(),
            })
            .collect(),
        env_inherited,
        binds: app
            .ro_binds
            .iter()
            .map(|b| b.display().to_string())
            .collect(),
        binds_inherited: baseline
            .ro_binds
            .iter()
            .filter(|b| !app.ro_binds.contains(b))
            .count(),
        packages: app
            .packages
            .iter()
            .map(|p| package_view(p, flake_pins))
            .collect(),
        packages_inherited,
        secrets: if secrets_dropped {
            Vec::new()
        } else {
            app.secrets
                .iter()
                .map(|s| SecretView {
                    header: s.header.clone(),
                    to: s.to.to_string(),
                    shape: s.shape.describe(),
                    sources: s.describe_sources(),
                })
                .collect()
        },
        secrets_inherited: if secrets_dropped {
            0
        } else {
            baseline
                .declared_secrets
                .iter()
                .filter(|b| {
                    !app.secrets
                        .iter()
                        .any(|a| a.to == b.to && a.header.eq_ignore_ascii_case(&b.header))
                })
                .count()
        },

        notes,
    }
}

/// A scalar app field's provenance for the detail view: the app layer that set it when it did,
/// else `Inherited` (the field took the baseline's value).
fn origin_or_inherited(app_set: bool, origin: super::Provenance) -> ProvenanceView {
    if app_set {
        origin.into()
    } else {
        ProvenanceView::Inherited
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn net_rules_view_projects_allow_deny_and_builtin_by_source() {
        use crate::allowlist::{classify, EgressPolicy};
        let policy = EgressPolicy::new(
            vec![classify("github.com").unwrap()],
            vec![classify("evil.com").unwrap()],
        );
        let rules = net_rules_view(&policy);
        assert!(rules.iter().any(|r| r.rule == "github.com"
            && r.kind == NetRuleKind::Allow
            && r.source == RuleSourceView::Config));
        assert!(rules.iter().any(|r| r.rule == "evil.com"
            && r.kind == NetRuleKind::Deny
            && r.source == RuleSourceView::Config));
        // Every built-in entry is an allow tagged `builtin`, and the set matches the one
        // `network_view` surfaces (the same `nix_cache_hosts` call) so the two cannot drift.
        let builtin: Vec<&str> = rules
            .iter()
            .filter(|r| r.source == RuleSourceView::Builtin)
            .map(|r| r.rule.as_str())
            .collect();
        assert!(builtin.contains(&"cache.nixos.org"));
        assert!(rules
            .iter()
            .filter(|r| r.source == RuleSourceView::Builtin)
            .all(|r| r.kind == NetRuleKind::Allow));
        assert_eq!(builtin.len(), sandbox::nix_cache_hosts().len());
    }

    #[test]
    fn ask_timeout_view_reflects_only_the_ask_default() {
        use crate::allowlist::{DefaultAction, EgressPolicy};
        use std::time::Duration;
        // Not ask → moot (None), regardless of any timeout the policy happens to carry.
        let deny = EgressPolicy::default();
        assert_eq!(ask_timeout_view(&deny), None);
        let allow = EgressPolicy::default().with_default(DefaultAction::Allow);
        assert_eq!(ask_timeout_view(&allow), None);
        // Ask with no timeout → an explicit "none" (indefinite), distinct from the moot None.
        let ask = EgressPolicy::default().with_default(DefaultAction::Ask);
        assert_eq!(ask_timeout_view(&ask), Some("none".to_string()));
        // Ask with a timeout → the compact form.
        let timed = ask.clone().with_ask_timeout(Some(Duration::from_secs(90)));
        assert_eq!(ask_timeout_view(&timed), Some("90s".to_string()));
        let mins = ask.with_ask_timeout(Some(Duration::from_secs(300)));
        assert_eq!(ask_timeout_view(&mins), Some("5m".to_string()));
    }

    #[test]
    fn fmt_secs_picks_the_coarsest_even_unit() {
        assert_eq!(fmt_secs(90), "90s");
        assert_eq!(fmt_secs(300), "5m");
        assert_eq!(fmt_secs(7200), "2h");
        assert_eq!(fmt_secs(0), "0s");
        assert_eq!(fmt_secs(3661), "3661s"); // not an even minute or hour
    }

    /// The view model serializes to a JSON object — the property a management front-end relies on,
    /// and the foundation a `--json` output stands on. Built here by hand (not through [`build`],
    /// which needs I/O) so the test pins the *serialization contract*: every field is plain data,
    /// the enums carry their variant, and nothing forces `Serialize` onto a resolution-internal
    /// type.
    #[test]
    fn the_view_model_serializes_to_a_json_object() {
        let view = ConfigView {
            cwd: "/proj".into(),
            env: vec![EnvVar {
                key: "A".into(),
                value: "1".into(),
                layer: Some(ProvenanceView::Project),
            }],
            binds: vec![BindView {
                path: "/data".into(),
                layer: Some(ProvenanceView::Global),
            }],
            packages: vec![PackageView {
                name: "jq".into(),
                backend: "nix".into(),
                locator: "jq".into(),
                realised: "host-side, durable".into(),
                trusted: true,
                withheld_reason: None,
                pinned_rev: None,
            }],
            mise: Some(MiseView {
                name: ".mise.toml".into(),
                trusted: false,
                withheld_reason: Some("the project is untrusted".into()),
            }),
            tools: ToolsView::default(),
            nixpkgs: ChannelView {
                source: "nixos-unstable".into(),
                origin: "default".into(),
                locked_rev: None,
            },
            engine: ChannelView {
                source: "nixos-unstable".into(),
                origin: "default".into(),
                locked_rev: Some("abc1234def".into()),
            },
            network: NetworkView::Allowlist {
                default_action: NetDefaultView::Deny,
                ask_timeout: None,
                ask_notice: None,
                allow: vec!["github.com".into()],
                deny: vec![],
                builtin: vec!["cache.nixos.org".into()],
            },
            network_origin: ProvenanceView::Project,
            egress_stats: true,
            gui: GuiView::Wayland,
            gui_origin: ProvenanceView::Global,
            limits: Default::default(),
            secrets: vec![],
            apps: vec![AppView {
                name: "demo-app".into(),
                cmd: Some("demo-app".into()),
                home_scope: "global (shared across projects)".into(),
                env: vec![AppEnvVar {
                    key: "DEMO_API_KEY".into(),
                    value: "placeholder".into(),
                }],
                binds: vec!["/data/cache".into()],
                packages: vec![PackageView {
                    name: "demo-tool".into(),
                    backend: "mise".into(),
                    locator: "aqua:example/demo-tool".into(),
                    realised: "in-cage via mise, fetched at launch".into(),
                    trusted: true,
                    withheld_reason: None,
                    pinned_rev: None,
                }],
                network: Some(AppNetworkView::Allowlist {
                    default_action: NetDefaultView::Deny,
                    ask_timeout: None,
                    ask_notice: None,
                    allow: vec!["api.example.com".into()],
                    deny: vec!["api.example.com/admin".into()],
                    builtin: vec!["cache.nixos.org".into()],
                }),
                gui: None,
                limits: Some(AppLimitsView {
                    memory_high: None,
                    memory_max: Some("8G".into()),
                    tasks_max: None,
                }),
                secrets: vec![SecretView {
                    header: "x-api-key".into(),
                    to: "api.example.com".into(),
                    shape: "raw".into(),
                    sources: "env DEMO_API_KEY".into(),
                }],
                notes: vec![],
            }],
            warnings: vec!["a note".into()],
        };

        let json = serde_json::to_value(&view).expect("ConfigView serializes");
        assert_eq!(json["cwd"], "/proj");
        assert_eq!(json["env"][0]["key"], "A");
        // The free-field provenance is part of the serialization contract.
        assert_eq!(json["env"][0]["layer"], "Project");
        assert_eq!(json["binds"][0]["path"], "/data");
        assert_eq!(json["binds"][0]["layer"], "Global");
        assert_eq!(json["packages"][0]["trusted"], true);
        assert_eq!(json["mise"]["withheld_reason"], "the project is untrusted");
        assert_eq!(json["nixpkgs"]["source"], "nixos-unstable");
        assert_eq!(json["nixpkgs"]["locked_rev"], serde_json::Value::Null);
        assert_eq!(json["engine"]["locked_rev"], "abc1234def");
        // A struct enum variant is externally tagged; a unit variant is its name as a string.
        assert!(json["network"]["Allowlist"]["allow"][0] == "github.com");
        // The filtered-egress default action travels with the policy in the JSON contract.
        assert_eq!(json["network"]["Allowlist"]["default_action"], "Deny");
        assert_eq!(json["gui"], "Wayland");
        // The scalar postures' provenance is part of the serialization contract — a value's origin
        // (default/global/project) travels with it.
        assert_eq!(json["network_origin"], "Project");
        assert_eq!(json["gui_origin"], "Global");
        // An app overlay's allowlist serializes its rules and the built-in set in full, so the
        // JSON form carries what `ops app <name>` can reach without a `--details` equivalent.
        let app_net = &json["apps"][0]["network"]["Allowlist"];
        assert_eq!(app_net["default_action"], "Deny");
        assert_eq!(app_net["allow"][0], "api.example.com");
        assert_eq!(app_net["deny"][0], "api.example.com/admin");
        assert_eq!(app_net["builtin"][0], "cache.nixos.org");
        // An app overlay's env and binds serialize in full — the overlay's own additions, the same
        // metadata the baseline `env`/`binds` sections carry (no per-entry layer, since the overlay
        // is flattened). The env value is the placeholder, a free field, never an injected secret.
        assert_eq!(json["apps"][0]["env"][0]["key"], "DEMO_API_KEY");
        assert_eq!(json["apps"][0]["env"][0]["value"], "placeholder");
        assert_eq!(json["apps"][0]["binds"][0], "/data/cache");
        // An app overlay's packages serialize as the full package projection — the backend and
        // trust verdict the baseline `packages` carries — so the JSON form shows an untrusted app
        // package as withheld without a `--details` equivalent.
        assert_eq!(json["apps"][0]["packages"][0]["name"], "demo-tool");
        assert_eq!(json["apps"][0]["packages"][0]["backend"], "mise");
        assert_eq!(json["apps"][0]["packages"][0]["trusted"], true);
        // An app overlay's injected credentials serialize by destination and source — never the
        // value — so the JSON form carries what `ops app <name>` injects without a `--details` flag.
        let app_secret = &json["apps"][0]["secrets"][0];
        assert_eq!(app_secret["header"], "x-api-key");
        assert_eq!(app_secret["to"], "api.example.com");
        assert_eq!(app_secret["sources"], "env DEMO_API_KEY");
        // An app overlay's own limit overrides serialize as only the fields it tunes — the ceiling
        // here — and an unset field (the throttle) is omitted, so the JSON shows exactly what the
        // app changes, not a misleading default it actually inherits from the baseline.
        let app_limits = &json["apps"][0]["limits"];
        assert_eq!(app_limits["memory_max"], "8G");
        assert_eq!(app_limits["memory_high"], serde_json::Value::Null);
        assert_eq!(app_limits["tasks_max"], serde_json::Value::Null);
    }

    /// A `flake:` package's pinned revision surfaces in its view, looked up by the package locator
    /// — and a floating package (no lock entry) shows none. The lookup key is the declared
    /// reference, which is byte-identical to the locator; asserting that here guards the silent
    /// miss the projection would otherwise hide if the two ever diverged. Covers both the baseline
    /// `packages:` line and an app's compact package list, since a profile may declare its flake
    /// package in an app overlay rather than the baseline.
    #[test]
    fn a_pinned_flake_revision_surfaces_keyed_by_the_locator() {
        use crate::config::{AppHomeScope, Package, ResolvedApp};

        let reference = "github:example/pinned-tool#default";
        let rev = "a1b2c3d4e5f60718293a4b5c6d7e8f9012345678";
        let pins = BTreeMap::from([(reference.to_string(), rev.to_string())]);

        let flake = Package {
            name: "pinned-tool".into(),
            backend: Backend::Flake(reference.into()),
            state: TrustState::Trusted,
        };
        // The key the upgrade/launch path writes is the package locator, so a view that looks up by
        // locator hits it. This equality is what makes the lookup work; pin it against drift.
        assert_eq!(flake.backend.locator(), reference);

        // Baseline projection: a pinned package shows the rev; the same package with an empty lock
        // floats (`None`), so "no rev" reads as "not pinned", never ambiguous.
        assert_eq!(package_view(&flake, &pins).pinned_rev.as_deref(), Some(rev));
        assert_eq!(package_view(&flake, &BTreeMap::new()).pinned_rev, None);

        // A non-flake package never carries a rev, whether or not pins exist.
        let nixpkg = Package {
            name: "jq".into(),
            backend: Backend::Nix("jq".into()),
            state: TrustState::Trusted,
        };
        assert_eq!(package_view(&nixpkg, &pins).pinned_rev, None);

        // App projection: the compact list carries the same pin, keyed identically.
        let app = ResolvedApp {
            cmd: vec!["pinned-tool".into()],
            home_scope: AppHomeScope::Global,
            env: vec![],
            ro_binds: vec![],
            packages: vec![flake],
            network: None,
            gui: None,
            limits: Default::default(),
            secrets: vec![],
            cmd_origin: Default::default(),
            network_origin: Default::default(),
            gui_origin: Default::default(),
            limits_origin: Default::default(),
            home_scope_origin: None,
            warnings: vec![],
        };
        let view = app_view("demo-app", &app, &NetworkPolicy::Shared, &pins);
        assert_eq!(view.packages[0].name, "pinned-tool");
        assert_eq!(view.packages[0].pinned_rev.as_deref(), Some(rev));
    }

    /// The increment's core guard: `app_detail_view` computes the effective network/gui/limits by
    /// mirroring `merge_app`'s precedence rather than calling it (it needs the per-field "did the
    /// app set this" the merge discards). Pin the two together — a drift in `merge_app` must fail
    /// here, not silently make `config show --app` misreport what the app actually launches with.
    /// A minimal HTTP-header credential, for the secret-posture agreement below.
    fn a_header_secret() -> crate::config::HeaderSecret {
        crate::config::HeaderSecret {
            sources: vec![crate::config::SecretSource::Env("TOKEN".into())],
            to: crate::allowlist::Rule::Host(
                "api.example.com".into(),
                crate::allowlist::Ports::Any,
            ),
            header: "Authorization".into(),
            shape: crate::config::HeaderShape::new("Bearer ", false),
        }
    }

    #[test]
    fn the_detail_views_effective_scalars_agree_with_merge_app() {
        use crate::config::{AppHomeScope, GuiPolicy, Provenance, ResolvedApp};
        // A baseline credential the app inherits — and that the app's narrowed network drops, the
        // residual this pins: the detail view's secret count must equal merge_app's.
        let baseline = Resolved {
            env: vec![],
            env_layer: Default::default(),
            ro_binds: vec![],
            bind_layer: Default::default(),
            packages: vec![],
            nixpkgs_global: None,
            nixpkgs_project: None,
            mise: None,
            network: NetworkPolicy::Shared,
            network_origin: Provenance::Default,
            egress_stats: true,
            gui: GuiPolicy::Wayland,
            gui_origin: Provenance::Global,
            limits: sandbox::cgroup::Limits {
                memory_high: Some("50%".into()),
                memory_max: None,
                tasks_max: None,
            },
            limits_origin: Default::default(),
            secrets: vec![a_header_secret()],
            declared_secrets: vec![a_header_secret()],
            apps: Default::default(),
            warnings: vec![],
        };
        // The app overrides the network and the task cap, leaves the GUI and the throttle alone.
        let app = ResolvedApp {
            cmd: vec!["demo".into()],
            home_scope: AppHomeScope::Global,
            env: vec![],
            ro_binds: vec![],
            packages: vec![],
            network: Some(NetworkPolicy::Isolated),
            gui: None,
            limits: sandbox::cgroup::Limits {
                memory_high: None,
                memory_max: None,
                tasks_max: Some("99".into()),
            },
            secrets: vec![],
            cmd_origin: Provenance::Global,
            network_origin: Provenance::Global,
            gui_origin: Provenance::Default,
            limits_origin: crate::config::LimitsOrigin {
                memory_high: Provenance::Default,
                memory_max: Provenance::Default,
                tasks_max: Provenance::Global,
            },
            home_scope_origin: None,
            warnings: vec![],
        };

        let mut merged = baseline.clone();
        merged.merge_app(app.clone());
        let detail = app_detail_view(
            std::path::Path::new("/proj"),
            "demo",
            &app,
            &baseline,
            &BTreeMap::new(),
        );

        // Network (the app overrode it) and GUI (the app inherited it) must both equal what the
        // merge launches; comparing the projected forms keeps it independent of the policy types.
        assert_eq!(
            serde_json::to_value(&detail.network).unwrap(),
            serde_json::to_value(network_view(&merged.network)).unwrap(),
            "effective network must match merge_app"
        );
        assert_eq!(
            matches!(merged.gui, GuiPolicy::Wayland),
            matches!(detail.gui, GuiView::Wayland),
            "effective GUI must match merge_app"
        );
        // Every limit field's effective value must equal merge_app's, override or inherited.
        assert_eq!(
            detail.limits.memory_high.value,
            merged.limits.memory_high().0
        );
        assert_eq!(detail.limits.memory_max.value, merged.limits.memory_max().0);
        assert_eq!(detail.limits.tasks_max.value, merged.limits.tasks_max().0);

        // Credentials must agree with merge_app too: the app narrowed the network to `none`, so
        // merge_app's posture check clears the inherited secret — and the detail view, mirroring it,
        // must report zero (own + inherited), not the over-count of the unenforced baseline.
        assert_eq!(
            merged.secrets.len(),
            0,
            "merge_app drops the inherited secret"
        );
        assert_eq!(
            detail.secrets.len() + detail.secrets_inherited,
            merged.secrets.len(),
            "effective credential count must match merge_app"
        );
    }
}
