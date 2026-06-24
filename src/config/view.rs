//! The presentation-agnostic view model for `ops config`.
//!
//! [`ConfigView`] is a serializable projection of the resolved configuration: every value is a
//! plain `String`/`bool`/local enum, so it carries no dependency on the resolution internals
//! (`allowlist::Rule`, `trust::TrustState`, the channel-lock types) and any front-end can render
//! or serialize it without pulling those in. [`build`] assembles it — the same data `ops config`
//! has always shown — by loading and projecting the resolved configuration plus the channel
//! locks. The CLI presenter and a future management UI are both adapters over this one model.
//!
//! It carries the per-layer provenance of the free fields (`env`/`binds`) — which layer, global
//! or project, supplied each value — so `ops config` can show a value's source. What it still
//! does *not* carry: a queryable schema, an affordance for a management UI that does not yet
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
    /// The resolved GUI posture.
    pub(crate) gui: GuiView,
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
    pub(crate) layer: Option<LayerView>,
}

/// One extra read-only bind: the canonical host path and the layer that declared it.
#[derive(Serialize)]
pub(crate) struct BindView {
    pub(crate) path: String,
    /// Which config layer declared the bind, when known.
    pub(crate) layer: Option<LayerView>,
}

/// Which configuration layer supplied a free-field value — the global `ops.toml` or the
/// project `.ops.toml`. The presentation-agnostic mirror of [`super::Layer`].
#[derive(Serialize, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LayerView {
    Global,
    Project,
}

impl From<super::Layer> for LayerView {
    fn from(l: super::Layer) -> Self {
        match l {
            super::Layer::Global => LayerView::Global,
            super::Layer::Project => LayerView::Project,
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

/// The resolved network posture.
#[derive(Serialize)]
pub(crate) enum NetworkView {
    /// The host network (the default; no confidentiality guarantee yet).
    Shared,
    /// An empty netns — no network at all.
    Isolated,
    /// A filtering allowlist enforced by the host proxy through an empty-netns cage. `builtin` is
    /// the always-allowed nix-cache set, surfaced so it is never a silent allowance.
    Allowlist {
        allow: Vec<String>,
        deny: Vec<String>,
        builtin: Vec<String>,
    },
}

/// The resolved GUI posture.
#[derive(Serialize)]
pub(crate) enum GuiView {
    None,
    Wayland,
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

/// One package an app's overlay declares: its name and, when it is a `flake:` package pinned by
/// `ops upgrade flake`, the locked revision — so the app's compact package list can show the pin
/// beside the name without expanding to the baseline section's full backend/realisation line.
#[derive(Serialize)]
pub(crate) struct AppPackageView {
    pub(crate) name: String,
    pub(crate) pinned_rev: Option<String>,
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
        allow: Vec<String>,
        deny: Vec<String>,
        builtin: Vec<String>,
    },
}

/// A named application profile: the command it runs and what its gated overlay adds.
#[derive(Serialize)]
pub(crate) struct AppView {
    pub(crate) name: String,
    /// The argv joined for display, or `None` when no layer declared a command.
    pub(crate) cmd: Option<String>,
    /// Where the app's persistent home is keyed, as a human phrase.
    pub(crate) home_scope: String,
    pub(crate) packages: Vec<AppPackageView>,
    /// The app's own network posture, with an allowlist's rules, when it set one.
    pub(crate) network: Option<AppNetworkView>,
    /// The app's own GUI posture as a word (`wayland`/`none`), when it set one.
    pub(crate) gui: Option<String>,
    /// The credentials this app injects — its overlay plus any inherited baseline secret, since
    /// secrets are unioned at merge (not overridden, unlike `network`). Each carries only its
    /// destination, header, shape, and source locator — never the value, which ops reads host-side
    /// at launch. The CLI shows a count by default and lists each under `--details`.
    pub(crate) secrets: Vec<SecretView>,
    /// Per-app notes about what its resolution dropped or ignored.
    pub(crate) notes: Vec<String>,
}

/// Assemble the view for a directory: load and resolve the configuration, then project it (plus
/// the channel locks, which need a touch of I/O) into the serializable model. This is the data
/// gathering only — no realisation, no nix, no network — exactly as `ops config` has always been.
pub(crate) fn build(cwd: &Path) -> ConfigView {
    let resolved = super::load(cwd);

    let env = resolved
        .env
        .iter()
        .map(|(k, v)| EnvVar {
            key: k.clone(),
            value: v.clone(),
            layer: resolved.env_layer.get(k).copied().map(LayerView::from),
        })
        .collect();

    let binds = resolved
        .ro_binds
        .iter()
        .map(|b| BindView {
            path: b.display().to_string(),
            layer: resolved.bind_layer.get(b).copied().map(LayerView::from),
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
        .map(|(name, app)| app_view(name, app, &flake_pins))
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
        gui,
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
            allow: a.allow_rules().iter().map(|r| r.to_string()).collect(),
            deny: a.deny_rules().iter().map(|r| r.to_string()).collect(),
            builtin: sandbox::nix_cache_hosts()
                .iter()
                .map(|h| h.to_string())
                .collect(),
        },
    }
}

/// Project one app overlay for display: its command, home scope, and the gated fields it adds.
fn app_view(
    name: &str,
    app: &super::ResolvedApp,
    flake_pins: &BTreeMap<String, String>,
) -> AppView {
    AppView {
        name: name.to_string(),
        cmd: (!app.cmd.is_empty()).then(|| app.cmd.join(" ")),
        home_scope: match app.home_scope {
            super::AppHomeScope::Global => "global (shared across projects)".to_string(),
            super::AppHomeScope::Project => "per-project".to_string(),
        },
        packages: app
            .packages
            .iter()
            .map(|p| AppPackageView {
                name: p.name.clone(),
                pinned_rev: flake_pinned_rev(&p.backend, flake_pins),
            })
            .collect(),
        network: app.network.as_ref().map(|n| match n {
            NetworkPolicy::Shared => AppNetworkView::Shared,
            NetworkPolicy::Isolated => AppNetworkView::Isolated,
            NetworkPolicy::Allowlist(a) => AppNetworkView::Allowlist {
                allow: a.allow_rules().iter().map(|r| r.to_string()).collect(),
                deny: a.deny_rules().iter().map(|r| r.to_string()).collect(),
                builtin: sandbox::nix_cache_hosts()
                    .iter()
                    .map(|h| h.to_string())
                    .collect(),
            },
        }),
        gui: app.gui.as_ref().map(|g| match g {
            super::GuiPolicy::Wayland => "wayland".to_string(),
            super::GuiPolicy::None => "none".to_string(),
        }),
        secrets: app
            .secrets
            .iter()
            .map(|s| SecretView {
                header: s.header.clone(),
                to: s.to.to_string(),
                shape: s.shape.describe(),
                sources: s.describe_sources(),
            })
            .collect(),
        notes: app.warnings.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
                layer: Some(LayerView::Project),
            }],
            binds: vec![BindView {
                path: "/data".into(),
                layer: Some(LayerView::Global),
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
                allow: vec!["github.com".into()],
                deny: vec![],
                builtin: vec!["cache.nixos.org".into()],
            },
            gui: GuiView::Wayland,
            secrets: vec![],
            apps: vec![AppView {
                name: "claude".into(),
                cmd: Some("claude".into()),
                home_scope: "global (shared across projects)".into(),
                packages: vec![],
                network: Some(AppNetworkView::Allowlist {
                    allow: vec!["api.anthropic.com".into()],
                    deny: vec!["api.anthropic.com/admin".into()],
                    builtin: vec!["cache.nixos.org".into()],
                }),
                gui: None,
                secrets: vec![SecretView {
                    header: "x-api-key".into(),
                    to: "api.anthropic.com".into(),
                    shape: "raw".into(),
                    sources: "env ANTHROPIC_API_KEY".into(),
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
        assert_eq!(json["gui"], "Wayland");
        // An app overlay's allowlist serializes its rules and the built-in set in full, so the
        // JSON form carries what `ops app <name>` can reach without a `--details` equivalent.
        let app_net = &json["apps"][0]["network"]["Allowlist"];
        assert_eq!(app_net["allow"][0], "api.anthropic.com");
        assert_eq!(app_net["deny"][0], "api.anthropic.com/admin");
        assert_eq!(app_net["builtin"][0], "cache.nixos.org");
        // An app overlay's injected credentials serialize by destination and source — never the
        // value — so the JSON form carries what `ops app <name>` injects without a `--details` flag.
        let app_secret = &json["apps"][0]["secrets"][0];
        assert_eq!(app_secret["header"], "x-api-key");
        assert_eq!(app_secret["to"], "api.anthropic.com");
        assert_eq!(app_secret["sources"], "env ANTHROPIC_API_KEY");
    }

    /// A `flake:` package's pinned revision surfaces in its view, looked up by the package locator
    /// — and a floating package (no lock entry) shows none. The lookup key is the declared
    /// reference, which is byte-identical to the locator; asserting that here guards the silent
    /// miss the projection would otherwise hide if the two ever diverged. Covers both the baseline
    /// `packages:` line and an app's compact package list, since the motivating profile (hermes)
    /// declares its flake package in an app overlay, not the baseline.
    #[test]
    fn a_pinned_flake_revision_surfaces_keyed_by_the_locator() {
        use crate::config::{AppHomeScope, Package, ResolvedApp};

        let reference = "github:NousResearch/hermes-agent#default";
        let rev = "a1b2c3d4e5f60718293a4b5c6d7e8f9012345678";
        let pins = BTreeMap::from([(reference.to_string(), rev.to_string())]);

        let flake = Package {
            name: "hermes".into(),
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
            cmd: vec!["hermes".into()],
            home_scope: AppHomeScope::Global,
            env: vec![],
            ro_binds: vec![],
            packages: vec![flake],
            network: None,
            gui: None,
            secrets: vec![],
            warnings: vec![],
        };
        let view = app_view("hermes", &app, &pins);
        assert_eq!(view.packages[0].name, "hermes");
        assert_eq!(view.packages[0].pinned_rev.as_deref(), Some(rev));
    }
}
