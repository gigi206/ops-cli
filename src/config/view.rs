//! The presentation-agnostic view model for `sbx config`.
//!
//! [`ConfigView`] is a serializable projection of the resolved configuration: every value is a
//! plain `String`/`bool`/local enum, so it carries no dependency on the resolution internals
//! (`allowlist::Rule`, `trust::TrustState`, the channel-lock types) and any front-end can render
//! or serialize it without pulling those in. [`build`] assembles it — the same data `sbx config`
//! has always shown — by loading and projecting the resolved configuration plus the channel
//! locks. The CLI presenter and a future management UI are both adapters over this one model.
//!
//! It carries the provenance of each baseline value — which layer (`Default`/`Global`/`Project`)
//! supplied it: per-entry for `env`/`binds`, and per-field for the scalar postures (`network`,
//! `gui`) and the cgroup `limits` — so `sbx config` can show where every value came from. What it
//! still does *not* carry: a queryable schema, an affordance for a management UI that does not yet
//! exist; it is added when that consumer is concrete, against its real shape.

use std::collections::BTreeMap;
use std::path::Path;

use serde::Serialize;

use super::{Backend, NetworkPolicy, Resolved};
use crate::trust::TrustState;
use crate::{sandbox, store};

/// A serializable projection of the resolved configuration for a directory — the model both the
/// `sbx config` CLI and a future management front-end render. Field order mirrors the CLI's
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
    /// Whether the egress proxy records `sbx net stats` (on by default; off via `[network] stats =
    /// false`). Only meaningful under a filtering posture (the proxy runs only then).
    pub(crate) egress_stats: bool,
    /// The resolved process/exec posture.
    pub(crate) proc: ProcView,
    /// Which layer supplied the proc posture (`Default` when neither config set it).
    pub(crate) proc_origin: ProvenanceView,
    /// The resolved refusal-notification policy.
    pub(crate) notify: NotifyView,
    /// Which layer supplied the notification policy (`Default` when neither config set it).
    pub(crate) notify_origin: ProvenanceView,
    /// The resolved GUI posture.
    pub(crate) gui: GuiView,
    /// Which layer supplied the GUI posture (`Default` when neither config set it).
    pub(crate) gui_origin: ProvenanceView,
    /// Whether hardware-accelerated GPU rendering is open (`gpu = true`).
    pub(crate) gpu: bool,
    /// Which layer supplied the GPU posture (`Default` when neither config set it).
    pub(crate) gpu_origin: ProvenanceView,
    /// Whether audio (microphone + playback) is open (`audio = true`).
    pub(crate) audio: bool,
    /// Which layer supplied the audio posture (`Default` when neither config set it).
    pub(crate) audio_origin: ProvenanceView,
    /// The resolved D-Bus posture (off, filtered host bus, or in-cage portal).
    pub(crate) dbus: bool,
    /// Which layer supplied the D-Bus posture (`Default` when neither config set it).
    pub(crate) dbus_origin: ProvenanceView,
    /// Host loopback TCP ports forwarded into the cage (`forward`), each a port number. Empty when
    /// no layer declared any.
    pub(crate) forward: Vec<u16>,
    /// Which layer supplied the `forward` set (`Default` when neither config set it).
    pub(crate) forward_origin: ProvenanceView,
    /// The seccomp denylist relaxation, as the canonical `[seccomp] allow` tokens a trusted config
    /// re-permitted. Empty when the mandatory denylist stands (no `[seccomp]` config).
    pub(crate) seccomp: Vec<String>,
    /// Which layer supplied the seccomp relaxation (`Default` when neither config did).
    pub(crate) seccomp_origin: ProvenanceView,
    /// The host device nodes granted into the cage (`[devices] allow`), each an absolute `/dev/`
    /// path. Empty when the cage's minimal, hostless `/dev` stands (no `[devices]` config).
    pub(crate) devices: Vec<String>,
    /// Which layer supplied the device grant (`Default` when neither config did).
    pub(crate) devices_origin: ProvenanceView,
    /// The project paths closed inside the cage (`[fs] deny`), and those it may read but not write
    /// (`[fs] readonly`), each as the entry that declared it. Empty when no layer closed anything.
    pub(crate) fs_deny: Vec<String>,
    pub(crate) fs_readonly: Vec<String>,
    /// Which layer supplied the masks (`Default` when no config did).
    pub(crate) fs_origin: ProvenanceView,
    /// The declared operations (`[task.<name>]`) a cage would offer, after the trust gate. This is
    /// the *static* view: `sbx task ls` reads a running session, so without it there was no way to
    /// confirm a `[task]` block survived validation short of launching one.
    pub(crate) tasks: Vec<TaskView>,
    /// The ssh-agent keys the cage may sign with (`[ssh_agent] allow`), each naming one key by its
    /// `SHA256:…` fingerprint or its comment. Empty when the cage gets no agent at all.
    pub(crate) ssh_agent: Vec<String>,
    /// Which layer supplied the ssh-agent grant (`Default` when neither config did).
    pub(crate) ssh_agent_origin: ProvenanceView,
    /// Whether every signature must be confirmed on the host desktop first (`[ssh_agent] confirm`).
    pub(crate) ssh_agent_confirm: bool,
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

/// One extra bind: the canonical host path, whether the cage may write to it, and the layer
/// that declared it (when known — an app overlay's binds carry no per-bind provenance).
#[derive(Serialize)]
pub(crate) struct BindView {
    pub(crate) path: String,
    /// Whether the bind is read-write (`mode = "rw"`); read-only otherwise.
    pub(crate) writable: bool,
    /// Which config layer declared the bind, when known.
    pub(crate) layer: Option<ProvenanceView>,
}

/// Where a resolved value came from — the presentation-agnostic mirror of [`super::Provenance`].
/// `Default` is sbx's built-in, `Global`/`Project` the two config files; `Inherited` is the per-app
/// view's marker for a field the app overlay did not set (it takes the baseline's value).
#[derive(Serialize, Clone, Copy, PartialEq, Eq, Default, Debug)]
pub(crate) enum ProvenanceView {
    #[default]
    Default,
    Global,
    Project,
    Inherited,
    /// A one-shot command-line/environment override — the final word for this invocation.
    Override,
}

/// A [`BindView`] for an app overlay's bind: path and mode, no per-bind provenance (an app's
/// binds are its own additions, not tracked per layer like the baseline's).
fn app_bind_view(bind: &super::Bind) -> BindView {
    BindView {
        path: bind.path.display().to_string(),
        writable: bind.writable,
        layer: None,
    }
}

impl From<super::Provenance> for ProvenanceView {
    fn from(p: super::Provenance) -> Self {
        match p {
            super::Provenance::Default => ProvenanceView::Default,
            super::Provenance::Global => ProvenanceView::Global,
            super::Provenance::Project => ProvenanceView::Project,
            super::Provenance::Override => ProvenanceView::Override,
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
    /// The locked revision when this is a `flake:` package `sbx upgrade flake` has pinned; `None`
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
//
// The `Allowlist` variant runs to a few hundred bytes against two unit variants, which the size
// lint flags. Boxing it would buy an allocation and a dereference on a value built once per render
// and never moved in a loop, inside a view already carrying larger `Vec`s — and it would push every
// reader through an indirection to reach fields whose whole purpose is to be read. The flat shape
// stays.
#[allow(clippy::large_enum_variant)]
#[derive(Serialize)]
pub(crate) enum NetworkView {
    /// The host network (the default; no confidentiality guarantee yet).
    Shared,
    /// An empty netns — no network at all.
    Isolated,
    /// Filtered egress enforced by the host proxy through an empty-netns cage. `default_action`
    /// is the verdict for an unmatched request; `builtin` is the always-allowed built-in set,
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
        /// `mute` (`dontaudit`) rules: refusals suppressed from the default `sbx net log` view (still
        /// counted in `sbx net stats`, shown by `sbx net log --all`). Surfaced so the suppression is
        /// never silent. Empty for a policy that mutes nothing.
        mute: Vec<String>,
        /// `http2` hosts: CONNECT targets the proxy man-in-the-middles as HTTP/2 (ALPN `h2`, for
        /// gRPC) instead of HTTP/1.1. A transport choice, orthogonal to the verdict — the host must
        /// still be permitted by an `allow` rule. Empty for a policy that designates no h2 host.
        http2: Vec<String>,
        /// The traffic-capture level (`off`/`headers`/`bodies`) and, when bodies are captured, the
        /// per-body cap in KiB. Surfaced so a launch that retains the plaintext of its exchanges
        /// says so in `sbx config` — a capture is never silent.
        capture: String,
        capture_max_kb: Option<u64>,
        /// Whether a permitted request may ride an upstream connection an earlier one left behind
        /// (`pool`). A transport choice like `http2`, orthogonal to the verdict, and surfaced for a
        /// sharper version of the same reason: the whole `[network]` table is trusted/global-only,
        /// and unlike `http2` — which announces itself by breaking a host that speaks HTTP/1.1 —
        /// reuse is invisible from inside the cage. A global layer could otherwise set it for a
        /// project with no way to see it.
        pool: bool,
        /// How long the proxy holds a resolved address, in seconds, when a layer set `dns_cache_ttl`
        /// — `None` when none did and the built-in cache applies. Surfaced alongside `pool` and for
        /// the same reason: it decides how long an address stands, and nothing in the cage observes
        /// it.
        dns_cache_ttl: Option<u64>,
        builtin: Vec<String>,
    },
}

/// Whether a listed egress rule allows, denies, or mutes (`dontaudit` — suppresses a denied
/// request's log line without changing the verdict).
#[derive(Serialize, Clone, Copy, PartialEq, Eq)]
pub(crate) enum NetRuleKind {
    Allow,
    Deny,
    Mute,
}

/// Where a listed egress rule came from: the resolved config (`.sbx.toml`/global, after the trust
/// gate), the always-allowed built-in set, or `Manual` — a runtime rule a live `ask`
/// session remembered from a `--session` answer (it lives in that session's memory, not config).
#[derive(Serialize, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RuleSourceView {
    Config,
    Builtin,
    Manual,
}

/// One egress rule projected for `sbx net rules`: its kind, its source, its display text, and — for
/// a rule expanded from a `[net.groups]` group — the group's name (`None` otherwise). In the default
/// (collapsed) view a contiguous run of one group's rules is a single row whose `rule` is `@<name>`;
/// under `--expand` each rule is its own row carrying `group` so the renderer can note its origin.
///
/// `catch_all` marks the one rule whose reach its own text does not show: a `re:` regex that matches
/// every host (see [`crate::allowlist::Rule::opens_every_host`]). The grammar refuses a bare `*`
/// precisely so a policy reads as what it does, and a catch-all regex is the accepted way to say the
/// same thing — so it is labelled here rather than left to be spotted. False for every other rule,
/// and for a collapsed `@<group>` row, whose text names no pattern to judge (`--expand` shows the
/// members, each judged on its own).
#[derive(Serialize, Clone)]
pub(crate) struct NetRuleView {
    pub(crate) kind: NetRuleKind,
    pub(crate) source: RuleSourceView,
    pub(crate) rule: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) group: Option<String>,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub(crate) catch_all: bool,
}

/// Project one config list (allow or deny) into rows. Collapsed (`expand == false`): a maximal
/// contiguous run of rules sharing one group becomes a single `@<name>` row, so a group reads as the
/// reference the user wrote instead of its expanded hosts. Expanded (`expand == true`): every rule is
/// its own row, carrying its `group` so the renderer can annotate the origin.
fn project_config_rules(
    rules: &[crate::allowlist::Rule],
    kind: NetRuleKind,
    expand: bool,
    out: &mut Vec<NetRuleView>,
) {
    if expand {
        for r in rules {
            out.push(NetRuleView {
                kind,
                source: RuleSourceView::Config,
                rule: r.to_string(),
                group: r.group.clone(),
                catch_all: r.opens_every_host(),
            });
        }
        return;
    }
    let mut i = 0;
    while i < rules.len() {
        match &rules[i].group {
            Some(g) => {
                let mut j = i + 1;
                while j < rules.len() && rules[j].group.as_deref() == Some(g.as_str()) {
                    j += 1;
                }
                out.push(NetRuleView {
                    kind,
                    source: RuleSourceView::Config,
                    rule: format!("@{g}"),
                    group: Some(g.clone()),
                    catch_all: false,
                });
                i = j;
            }
            None => {
                out.push(NetRuleView {
                    kind,
                    source: RuleSourceView::Config,
                    rule: rules[i].to_string(),
                    group: None,
                    catch_all: rules[i].opens_every_host(),
                });
                i += 1;
            }
        }
    }
}

/// Project a filtered-egress policy's rules for listing: the config allow rules, then the config
/// deny rules, then the built-in allow set — each tagged with its source. A group-expanded config
/// rule collapses to a `@<name>` row unless `expand` is set (see [`project_config_rules`]). The
/// built-in set is the same one [`network_view`] surfaces, so the two cannot drift, and never
/// carries a group. Only meaningful under a filtering posture; `shared`/`none` carry no rules,
/// which the caller handles.
pub(crate) fn net_rules_view(
    policy: &crate::allowlist::EgressPolicy,
    expand: bool,
) -> Vec<NetRuleView> {
    let mut rules = Vec::new();
    project_config_rules(policy.allow_rules(), NetRuleKind::Allow, expand, &mut rules);
    project_config_rules(policy.deny_rules(), NetRuleKind::Deny, expand, &mut rules);
    // Mute (`dontaudit`) rules are policy too — surfaced so `sbx net rules` shows what refusals are
    // suppressed from the default log. They never change a verdict; the renderer tags them.
    project_config_rules(policy.mute_rules(), NetRuleKind::Mute, expand, &mut rules);
    for r in sandbox::builtin_allow_rules() {
        rules.push(NetRuleView {
            kind: NetRuleKind::Allow,
            source: RuleSourceView::Builtin,
            rule: r.to_string(),
            group: None,
            // The built-in self-equip set names its hosts; asked anyway, so the label follows the
            // rule rather than an assumption about which list it sits in.
            catch_all: r.opens_every_host(),
        });
    }
    rules
}

/// The resolved GUI posture.
#[derive(Serialize)]
pub(crate) enum GuiView {
    None,
    Offscreen,
    Wayland,
}

/// The resolved process/exec posture, for `sbx config show`.
#[derive(Serialize, Default)]
pub(crate) struct ProcView {
    /// `off` / `observe` / `enforce` / `ask`.
    pub(crate) mode: String,
    pub(crate) allow: Vec<String>,
    pub(crate) deny: Vec<String>,
}

/// Project a resolved [`crate::proc_policy::ProcPolicy`] into its view.
pub(crate) fn proc_view(p: &crate::proc_policy::ProcPolicy) -> ProcView {
    ProcView {
        mode: p.mode.as_str().to_string(),
        allow: p.allow.iter().map(|r| r.as_str().to_string()).collect(),
        deny: p.deny.iter().map(|r| r.as_str().to_string()).collect(),
    }
}

/// The resolved refusal-notification policy, for `sbx config show`: one mode per event, always all
/// of them. Rendered in full rather than only where it differs from the default, because "which
/// refusals will I actually hear about" is the question this row exists to answer, and a partial
/// listing would leave a reader inferring the rest.
#[derive(Serialize, Default)]
pub(crate) struct NotifyView {
    /// Event name → `off` / `once` / `always`, in the events' declaration order.
    pub(crate) events: Vec<(String, String)>,
    /// The quiet period between repeats of one problem, as it was written (`"5m"`), or empty when
    /// every occurrence is announced.
    pub(crate) repeat_after: String,
}

/// Project a resolved [`crate::notify::NotifyPolicy`] into its view.
pub(crate) fn notify_view(p: &crate::notify::NotifyPolicy) -> NotifyView {
    NotifyView {
        events: crate::notify::NotifyEvent::ALL
            .iter()
            .map(|e| (e.as_str().to_string(), p.mode_for(*e).as_str().to_string()))
            .collect(),
        repeat_after: p
            .repeat_after()
            .map(|d| format!("{}s", d.as_secs()))
            .unwrap_or_default(),
    }
}

/// The cage's effective cgroup resource limits: the throttle threshold, the hard memory ceiling,
/// and the task cap, each its config override when set or sbx's built-in default otherwise.
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

/// One declared operation, as the static view shows it: what it is called, what it says it does,
/// and which layer declared it. The command is deliberately absent — an operation is a *fixed*
/// command plus a credential the caller never holds, and `sbx task show` is where the whole
/// contract (params, secrets, output disposition) is read. Here the question is only whether the
/// block survived validation, and where it came from.
#[derive(Serialize)]
pub(crate) struct TaskView {
    pub(crate) name: String,
    /// `null` when the operation declared none, which is a different fact from an empty string.
    pub(crate) description: Option<String>,
    /// `global`, `project`, `app:<name>` or `bundle:<name>` — the same `kind:name` token the rest
    /// of sbx uses for a kind and its instance.
    pub(crate) origin: String,
}

/// An injected credential, by destination and source — never the plaintext, which sbx reads only
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
/// allow/deny rules and the always-allowed built-in set: the proxy unions that set into
/// whatever policy is in effect at launch, so for an app it is part of what `sbx app <name>` can
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
    /// The host binds this overlay adds over the baseline — a security field, gated like the
    /// baseline binds, each read-only or read-write. The overlay's own paths, canonicalized to what
    /// a launch would mount. A count by default, each path (with its mode) under `--details`.
    pub(crate) binds: Vec<BindView>,
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
    /// The app's own GPU posture, when it set one (`Some(true)`/`Some(false)`); `None` inherits the
    /// baseline. Mirrors the app's `gui`.
    pub(crate) gpu: Option<bool>,
    /// The app's own audio posture, when it set one; `None` inherits the baseline. Mirrors the
    /// app's `gpu`.
    pub(crate) audio: Option<bool>,
    /// The app's own D-Bus posture, when it set one; `None` inherits the baseline. Mirrors the
    /// app's `gpu`.
    pub(crate) dbus: Option<bool>,
    /// The host loopback ports this overlay adds over the baseline — a security field, gated like
    /// the baseline `forward`. The overlay's own ports, not the baseline-merged set; the merge
    /// unions them only for the launch itself.
    pub(crate) forward: Vec<u16>,
    /// The seccomp relaxation this overlay adds over the baseline — its *own* allow tokens, not the
    /// baseline-merged set. Empty when it relaxes nothing; the merge unions it with the baseline
    /// only for the launch itself.
    pub(crate) seccomp: Vec<String>,
    /// The host device nodes this overlay grants over the baseline — its *own* `/dev/` paths, not the
    /// baseline-merged set. Empty when it grants none; the merge unions it with the baseline only for
    /// the launch itself.
    pub(crate) devices: Vec<String>,
    /// The project paths this overlay closes over the baseline — its *own* entries, not the
    /// baseline-merged set. Empty when it closes none.
    pub(crate) fs_deny: Vec<String>,
    pub(crate) fs_readonly: Vec<String>,
    /// The ssh-agent keys this overlay grants over the baseline — its *own* entries, not the
    /// baseline-merged set. Empty when it names none; the merge unions it with the baseline only for
    /// the launch itself.
    pub(crate) ssh_agent: Vec<String>,
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
/// declaration in that config file set it). This is what `sbx config show --app <name>` renders,
/// and it answers "what does this app actually run with, and which of it did the app change?" — a
/// view the compact baseline `apps:` section (overlay-own only) cannot give. Scalars carry their
/// effective value plus a [`ProvenanceView`]; collections carry the overlay's *own* additions plus
/// a count of how many baseline entries they inherit (never the inherited entries themselves —
/// those live in the baseline `sbx config show`, one hop away).
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
    /// The effective process/exec posture (the app's own, else the baseline's).
    pub(crate) proc: ProcView,
    pub(crate) proc_origin: ProvenanceView,
    /// The effective refusal-notification policy (the app's own, else the baseline's).
    pub(crate) notify: NotifyView,
    pub(crate) notify_origin: ProvenanceView,
    /// The effective GUI posture (the app's own, else the baseline's).
    pub(crate) gui: GuiView,
    pub(crate) gui_origin: ProvenanceView,
    /// The effective GPU posture (the app's own, else the baseline's).
    pub(crate) gpu: bool,
    pub(crate) gpu_origin: ProvenanceView,
    /// The effective audio posture (the app's own, else the baseline's).
    pub(crate) audio: bool,
    pub(crate) audio_origin: ProvenanceView,
    /// The effective D-Bus posture (the app's own, else the baseline's).
    pub(crate) dbus: bool,
    pub(crate) dbus_origin: ProvenanceView,
    /// The effective host loopback forward ports — the app's own ∪ the baseline's. The origin is
    /// `Inherited` when the app added none of its own.
    pub(crate) forward: Vec<u16>,
    pub(crate) forward_origin: ProvenanceView,
    /// The effective seccomp relaxation — the app's own ∪ the baseline's, as tokens. The origin is
    /// `Inherited` when the app added none of its own (it takes the baseline's relaxation).
    pub(crate) seccomp: Vec<String>,
    pub(crate) seccomp_origin: ProvenanceView,
    /// The effective host device grant — the app's own ∪ the baseline's, as `/dev/` paths. The origin
    /// is `Inherited` when the app added none of its own (it takes the baseline's grant).
    pub(crate) devices: Vec<String>,
    pub(crate) devices_origin: ProvenanceView,
    /// The effective mask set — the app's own ∪ the baseline's. The origin is `Inherited` when the
    /// app closed nothing of its own (it takes the baseline's masks).
    pub(crate) fs_deny: Vec<String>,
    pub(crate) fs_readonly: Vec<String>,
    pub(crate) fs_origin: ProvenanceView,
    /// The effective ssh-agent grant — the app's own ∪ the baseline's. The origin is `Inherited`
    /// when the app named no key of its own (it signs with whatever the baseline granted).
    pub(crate) ssh_agent: Vec<String>,
    pub(crate) ssh_agent_origin: ProvenanceView,
    /// Whether every signature must be confirmed on the host desktop first (`[ssh_agent] confirm`).
    pub(crate) ssh_agent_confirm: bool,
    /// The effective cgroup limits — the app's overrides folded onto the baseline — each field
    /// carrying its provenance (`Inherited` when the app left it to the baseline).
    pub(crate) limits: LimitsView,
    /// The environment this app *adds* over the baseline (its overlay-own entries), and how many
    /// baseline entries it inherits unchanged.
    pub(crate) env: Vec<AppEnvVar>,
    pub(crate) env_inherited: usize,
    /// The binds this app adds (each read-only or read-write), and the count it inherits from the
    /// baseline.
    pub(crate) binds: Vec<BindView>,
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
/// gathering only — no realisation, no nix, no network — exactly as `sbx config` has always been.
pub(crate) fn build(cwd: &Path) -> ConfigView {
    build_scoped(cwd, super::Source::All)
}

/// Assemble the view restricted to one configuration `source` — the single-source `sbx config show
/// --global/--local/--default` views. `build(cwd)` is `build_scoped(cwd, Source::All)`; a
/// restricted form projects the same model from fewer layers, so each value's provenance tag reads
/// as what that source contributes over the built-in defaults.
pub(crate) fn build_scoped(cwd: &Path, source: super::Source) -> ConfigView {
    let mut resolved = super::load_scoped(cwd, source);

    // Reflect an ambient one-shot override (`SBX_CONFIG`/`SBX_ENV_*` and the `SBX_*` typed
    // variables) in the full view, so `sbx config show` does not lie about what a launch in this
    // environment would do — its values then carry the `override` provenance tag. Only the full
    // (`All`) view: the single-source `--global/--local/--default` views show what one config *file*
    // contributes, which an override is not. Per-invocation CLI flags are not previewed here (run the
    // launch to see them); passing default (empty) CLI overrides reads only the ambient environment.
    if matches!(source, super::Source::All) {
        if let Ok(ov) = super::overrides::collect(&super::CliOverrides::default()) {
            if !ov.is_empty() {
                // A set-but-invalid override value would abort a real launch; here (a read-only view)
                // surface the error as a note and show the untouched baseline, so `sbx config show`
                // neither lies about the override nor pretends a bad value took effect.
                if let Err(e) = resolved.apply_override_channel(&ov) {
                    resolved.warnings.push(e);
                }
                if let Err(errs) = resolved.apply_override(ov) {
                    resolved.warnings.extend(errs);
                }
            }
        }
    }

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
        .binds
        .iter()
        .map(|b| BindView {
            path: b.path.display().to_string(),
            writable: b.writable,
            layer: resolved
                .bind_layer
                .get(&b.path)
                .copied()
                .map(ProvenanceView::from),
        })
        .collect();

    // The pinned revisions of any `flake:` packages, read network-free from the per-project lock —
    // the same source the launch consults — so the view can show a pin without resolving anything.
    // Pinned identities keyed by a package's locator: flake refs → revision, deb/appimage URLs →
    // short content hash. Keys almost never collide across backends (a `.deb` URL, an `.AppImage`
    // URL, and a flake ref look nothing alike); the one overlap is a `github:<owner>/<repo>` locator
    // shared by a `deb:`/`appimage:` pair pointing at the SAME repo, where the last `.extend` wins and
    // the display shows one pin for both. That is cosmetic — provisioning, upgrade, and gc each read
    // their own per-backend lock directly, never this merged display map.
    let mut flake_pins = sandbox::flake_pinned_revs(cwd);
    flake_pins.extend(sandbox::deb_pinned_hashes(cwd));
    flake_pins.extend(sandbox::appimage_pinned_hashes(cwd));
    flake_pins.extend(sandbox::tarball_pinned_hashes(cwd));

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
        super::GuiPolicy::Offscreen => GuiView::Offscreen,
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
        proc: proc_view(&resolved.proc),
        proc_origin: resolved.proc_origin.into(),
        notify: notify_view(&resolved.notify),
        notify_origin: resolved.notify_origin.into(),
        gui,
        gui_origin: resolved.gui_origin.into(),
        gpu: resolved.gpu,
        gpu_origin: resolved.gpu_origin.into(),
        audio: resolved.audio,
        audio_origin: resolved.audio_origin.into(),
        dbus: resolved.dbus,
        dbus_origin: resolved.dbus_origin.into(),
        forward: resolved.forward.clone(),
        forward_origin: resolved.forward_origin.into(),
        seccomp: resolved.seccomp.tokens(),
        seccomp_origin: resolved.seccomp_origin.into(),
        devices: device_paths(&resolved.devices),
        devices_origin: resolved.devices_origin.into(),
        fs_deny: resolved.fs.deny.clone(),
        fs_readonly: resolved.fs.readonly.clone(),
        fs_origin: resolved.fs_origin.into(),
        tasks: task_views(&resolved.tasks),
        ssh_agent: resolved.ssh_agent.clone(),
        ssh_agent_origin: resolved.ssh_agent_origin.into(),
        ssh_agent_confirm: resolved.ssh_agent_confirm,
        limits,
        secrets,
        apps,
        warnings: resolved.warnings.clone(),
    }
}

/// The device grant as display strings, in the resolved (sorted) order. A tiny shared conversion so
/// the baseline, per-app, and `--app` effective views render a device path identically.
fn device_paths(devices: &[std::path::PathBuf]) -> Vec<String> {
    devices.iter().map(|p| p.display().to_string()).collect()
}

/// Project the declared operations for the static view. Ordering is the resolver's, which already
/// folds an app's and a bundle's blocks onto the baseline, so the list reads as the launch would
/// offer it.
fn task_views(tasks: &[super::TaskSpec]) -> Vec<TaskView> {
    tasks
        .iter()
        .map(|t| TaskView {
            name: t.name.clone(),
            description: t.description.clone(),
            origin: t.origin.label(),
        })
        .collect()
}

/// Project one declared package, recording its backend, how it is realised, the trust verdict,
/// and — for a `flake:` package — its locked revision from the per-project lock (`None` floats).
fn package_view(p: &super::Package, flake_pins: &BTreeMap<String, String>) -> PackageView {
    let realised = match p.backend {
        Backend::Nix(_) => "host-side, durable",
        Backend::Mise(_) => "in-cage via mise, fetched at launch",
        Backend::Flake(_) => "host-side via nix build, durable",
        Backend::FlakeInline { .. } => "in-cage via nix build (inline flake)",
        Backend::Deb(_) => "host-side from prebuilt .deb, durable",
        Backend::AppImage(_) => "host-side from prebuilt AppImage, durable",
        Backend::Tarball(_) => "host-side from prebuilt tarball, durable",
        Backend::TarballResolve { .. } => "host-side from prebuilt tarball (auto-upgrade), durable",
        Backend::DebResolve { .. } => "host-side from prebuilt .deb (auto-upgrade), durable",
        Backend::AppImageResolve { .. } => {
            "host-side from prebuilt AppImage (auto-upgrade), durable"
        }
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

/// The locked pin for a `flake:` (revision) or `deb:`/`appimage:` (short content hash) package,
/// looked up by its locator in the merged pin map; `None` for an unpinned package or any other
/// backend. A `deb:`/`appimage:` pair naming the same `github:<owner>/<repo>` shares a key here, so
/// the display can show one the other's pin — cosmetic only (each backend provisions from its own
/// lock).
fn flake_pinned_rev(backend: &Backend, flake_pins: &BTreeMap<String, String>) -> Option<String> {
    match backend {
        // Flake refs and deb/appimage/tarball URLs are all looked up by locator in the merged pin map.
        Backend::Flake(reference) => flake_pins.get(reference).cloned(),
        Backend::Deb(url) | Backend::AppImage(url) | Backend::Tarball(url) => {
            flake_pins.get(url).cloned()
        }
        // An inline flake floats — no persisted lock, so nothing to show. A `tarball:resolve`
        // package's pin is keyed by `resolve:<name>` (not a locator in this map), so its rev is not
        // surfaced here; it is reported by `sbx app show`/inspect from the per-project lock.
        Backend::Nix(_)
        | Backend::Mise(_)
        | Backend::FlakeInline { .. }
        | Backend::TarballResolve { .. }
        | Backend::DebResolve { .. }
        | Backend::AppImageResolve { .. } => None,
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
/// built-in set so the effective policy is visible at a glance.
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
            mute: a.mute_rules().iter().map(|r| r.to_string()).collect(),
            http2: a.http2_hosts().iter().map(|h| h.display()).collect(),
            capture: a.capture_level().as_str().to_string(),
            capture_max_kb: a
                .capture_level()
                .captures_bodies()
                .then(|| a.capture_body_kb()),
            pool: a.pool(),
            dns_cache_ttl: a.dns_cache_ttl().map(|d| d.as_secs()),
            builtin: sandbox::builtin_allow_rules()
                .iter()
                .map(|r| r.to_string())
                .collect(),
        },
    }
}

/// Whether the `ask` park notice prints, projected for display: `None` when the default action is
/// not `ask` (moot), else `Some(true)` (shown, the default) or `Some(false)` (silenced by
/// `ask_notice = false`). Surfaced so a silenced notice is visible in `sbx config`.
fn ask_notice_view(a: &crate::allowlist::EgressPolicy) -> Option<bool> {
    if a.default_action() != crate::allowlist::DefaultAction::Ask {
        return None;
    }
    Some(a.ask_notice())
}

/// The ask-default's parked-request wait, projected for display: `None` when the default action is
/// not `ask` (the field is moot), `Some("none")` for an indefinite wait, or `Some("90s")` for a
/// configured bound. Surfaced so a configured timeout is visible in `sbx config`.
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

/// Project the cage's effective resource limits — each the config override when set, or sbx's
/// built-in default — with the layer that supplied it, so `sbx config` shows what the launch would
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
    // The roster shows the app's *own* network overlay; apply its read-by-default verb posture
    // (`default_methods`) to a clone so the expanded rules render the verbs the launch enforces —
    // matching `config show --app` and `net rules --app`, not the un-narrowed declared form.
    let app_network = app.network.clone().map(|mut n| {
        if let NetworkPolicy::Allowlist(p) = &mut n {
            p.apply_default_methods(&app.default_methods);
        }
        n
    });
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
        binds: app.binds.iter().map(app_bind_view).collect(),
        packages: app
            .packages
            .iter()
            .map(|p| package_view(p, flake_pins))
            .collect(),
        network: app_network.as_ref().map(|n| match n {
            NetworkPolicy::Shared => AppNetworkView::Shared,
            NetworkPolicy::Isolated => AppNetworkView::Isolated,
            NetworkPolicy::Allowlist(a) => AppNetworkView::Allowlist {
                default_action: a.default_action().into(),
                ask_timeout: ask_timeout_view(a),
                ask_notice: ask_notice_view(a),
                allow: a.allow_rules().iter().map(|r| r.to_string()).collect(),
                deny: a.deny_rules().iter().map(|r| r.to_string()).collect(),
                builtin: sandbox::builtin_allow_rules()
                    .iter()
                    .map(|r| r.to_string())
                    .collect(),
            },
        }),
        gui: app.gui.as_ref().map(|g| match g {
            super::GuiPolicy::Wayland => GuiView::Wayland,
            super::GuiPolicy::Offscreen => GuiView::Offscreen,
            super::GuiPolicy::None => GuiView::None,
        }),
        gpu: app.gpu,
        audio: app.audio,
        dbus: app.dbus,
        forward: app.forward.clone(),
        seccomp: app.seccomp.tokens(),
        devices: device_paths(&app.devices),
        fs_deny: app.fs.deny.clone(),
        fs_readonly: app.fs.readonly.clone(),
        ssh_agent: app.ssh_agent.clone(),
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

/// Assemble the per-app detail view for `name` in `cwd` — the effective configuration `sbx app
/// <name>` would launch with, annotated with provenance. `None` when no such app is declared (the
/// CLI then errors, listing the available names). Pure data gathering, like [`build`].
pub(crate) fn build_app_detail(cwd: &Path, name: &str) -> Option<AppDetailView> {
    let resolved = super::load(cwd);
    let app = resolved.apps.get(name)?;
    // Pinned identities keyed by a package's locator: flake refs → revision, deb/appimage URLs →
    // short content hash. Keys almost never collide across backends (a `.deb` URL, an `.AppImage`
    // URL, and a flake ref look nothing alike); the one overlap is a `github:<owner>/<repo>` locator
    // shared by a `deb:`/`appimage:` pair pointing at the SAME repo, where the last `.extend` wins and
    // the display shows one pin for both. That is cosmetic — provisioning, upgrade, and gc each read
    // their own per-backend lock directly, never this merged display map.
    let mut flake_pins = sandbox::flake_pinned_revs(cwd);
    flake_pins.extend(sandbox::deb_pinned_hashes(cwd));
    flake_pins.extend(sandbox::appimage_pinned_hashes(cwd));
    flake_pins.extend(sandbox::tarball_pinned_hashes(cwd));
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
    // Effective network/GUI: the app's own posture when it set one, else the baseline's — then the
    // app's read-by-default verb posture applied to it, mirroring `merge_app` so the detail view
    // shows the verbs the launch enforces (the merge_app-agreement guard pins this).
    let mut eff_network = app
        .network
        .clone()
        .unwrap_or_else(|| baseline.network.clone());
    if let NetworkPolicy::Allowlist(policy) = &mut eff_network {
        policy.apply_default_methods(&app.default_methods);
    }
    let network = network_view(&eff_network);
    let network_origin = origin_or_inherited(app.network.is_some(), app.network_origin);
    let eff_proc = app.proc.clone().unwrap_or_else(|| baseline.proc.clone());
    let proc = proc_view(&eff_proc);
    let proc_origin = origin_or_inherited(app.proc.is_some(), app.proc_origin);
    let eff_notify = app.notify.unwrap_or(baseline.notify);
    let notify = notify_view(&eff_notify);
    let notify_origin = origin_or_inherited(app.notify.is_some(), app.notify_origin);
    let eff_gui = app.gui.unwrap_or(baseline.gui);
    let gui = match eff_gui {
        super::GuiPolicy::Wayland => GuiView::Wayland,
        super::GuiPolicy::Offscreen => GuiView::Offscreen,
        super::GuiPolicy::None => GuiView::None,
    };
    let gui_origin = origin_or_inherited(app.gui.is_some(), app.gui_origin);
    let eff_gpu = app.gpu.unwrap_or(baseline.gpu);
    let gpu_origin = origin_or_inherited(app.gpu.is_some(), app.gpu_origin);
    let eff_audio = app.audio.unwrap_or(baseline.audio);
    let audio_origin = origin_or_inherited(app.audio.is_some(), app.audio_origin);
    let eff_dbus = app.dbus.unwrap_or(baseline.dbus);
    let dbus_origin = origin_or_inherited(app.dbus.is_some(), app.dbus_origin);

    // Effective forward: the app's own ports ∪ the baseline's — the same union `merge_app`
    // performs — with the origin `Inherited` when the app added none of its own.
    let mut eff_forward = baseline.forward.clone();
    super::union_forward(&mut eff_forward, app.forward.clone());
    let forward_origin = origin_or_inherited(!app.forward.is_empty(), app.forward_origin);

    // Effective seccomp: the app's own relaxation ∪ the baseline's — the same union `merge_app`
    // performs — with the origin `Inherited` when the app added none of its own.
    let mut eff_seccomp = baseline.seccomp.clone();
    eff_seccomp.union(&app.seccomp);
    let seccomp_origin = origin_or_inherited(!app.seccomp.is_empty(), app.seccomp_origin);

    // Effective devices: the app's own grant ∪ the baseline's — the same union `merge_app` performs
    // — with the origin `Inherited` when the app added none of its own.
    let mut eff_devices = baseline.devices.clone();
    super::union_devices(&mut eff_devices, app.devices.clone());
    let devices_origin = origin_or_inherited(!app.devices.is_empty(), app.devices_origin);
    // Effective masks: the app's own ∪ the baseline's — the same union `merge_app` performs, and
    // the same direction (an app closes more, never less).
    let mut eff_fs = baseline.fs.clone();
    eff_fs.union(app.fs.clone());
    let fs_origin = origin_or_inherited(!app.fs.is_empty(), app.fs_origin);

    // Effective ssh-agent grant: the app's own ∪ the baseline's — the same union `merge_app`
    // performs — with the origin `Inherited` when the app named no key of its own.
    let mut eff_ssh_agent = baseline.ssh_agent.clone();
    super::union_ssh_agent(&mut eff_ssh_agent, app.ssh_agent.clone());
    let ssh_agent_origin = origin_or_inherited(!app.ssh_agent.is_empty(), app.ssh_agent_origin);

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
    // count — and the note — match what `sbx app <name>` would actually inject; otherwise the
    // view over-reports credentials an app silently drops by narrowing its network.
    let mut eff_secrets = baseline.declared_secrets.clone();
    eff_secrets.extend(app.secrets.iter().cloned());
    let mut secret_notes = Vec::new();
    super::enforce_secret_posture(&eff_network, &mut eff_secrets, &mut secret_notes);
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
        proc,
        proc_origin,
        notify,
        notify_origin,
        gui,
        gui_origin,
        gpu: eff_gpu,
        gpu_origin,
        audio: eff_audio,
        audio_origin,
        dbus: eff_dbus,
        dbus_origin,
        forward: eff_forward,
        forward_origin,
        seccomp: eff_seccomp.tokens(),
        seccomp_origin,
        devices: device_paths(&eff_devices),
        devices_origin,
        fs_deny: eff_fs.deny,
        fs_readonly: eff_fs.readonly,
        fs_origin,
        ssh_agent: eff_ssh_agent,
        ssh_agent_origin,
        // ORed, like the merge: an app may ask for the prompt, and cannot remove the baseline's.
        ssh_agent_confirm: baseline.ssh_agent_confirm || app.ssh_agent_confirm,
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
        binds: app.binds.iter().map(app_bind_view).collect(),
        // Inherited baseline binds are those whose path the app does not shadow — the same
        // path-keyed union `merge_app` performs, so the count matches what the launch mounts.
        binds_inherited: baseline
            .binds
            .iter()
            .filter(|b| !app.binds.iter().any(|a| a.path == b.path))
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
        let rules = net_rules_view(&policy, false);
        // Config rules render through the rule `Display`, so an L7 host shows the implicit scheme.
        assert!(rules.iter().any(|r| r.rule == "https://github.com"
            && r.kind == NetRuleKind::Allow
            && r.source == RuleSourceView::Config));
        assert!(rules.iter().any(|r| r.rule == "https://evil.com"
            && r.kind == NetRuleKind::Deny
            && r.source == RuleSourceView::Config));
        // Every built-in entry is an allow tagged `builtin`, rendered through the same rule `Display`
        // (so it shows its scheme), and the set matches the one `network_view` surfaces (the same
        // built-in source) so the two cannot drift.
        let builtin: Vec<&str> = rules
            .iter()
            .filter(|r| r.source == RuleSourceView::Builtin)
            .map(|r| r.rule.as_str())
            .collect();
        // a read-only built-in host shows its `{GET,HEAD}` scope and the implicit scheme
        assert!(builtin.contains(&"{GET,HEAD} https://cache.nixos.org"));
        // github.com is also {GET,HEAD} (tarball fetch is GET); a git POST is the user's to allow
        assert!(builtin.contains(&"{GET,HEAD} https://github.com"));
        assert!(rules
            .iter()
            .filter(|r| r.source == RuleSourceView::Builtin)
            .all(|r| r.kind == NetRuleKind::Allow));
        assert_eq!(builtin.len(), sandbox::builtin_allow_rules().len());
    }

    #[test]
    fn net_rules_view_collapses_a_group_and_expands_on_demand() {
        use crate::allowlist::{classify, EgressPolicy};
        // Two rules tagged as one group, plus a directly-written rule.
        let mut g1 = classify("{*} a.example.com:443").unwrap();
        g1.group = Some("mcp".into());
        let mut g2 = classify("{*} b.example.com:443").unwrap();
        g2.group = Some("mcp".into());
        let direct = classify("{*} api.example.com:443").unwrap();
        let policy = EgressPolicy::new(vec![g1, g2, direct], vec![]);

        // Collapsed: the contiguous group run becomes a single `@mcp` row; the direct rule stays.
        let collapsed: Vec<_> = net_rules_view(&policy, false)
            .into_iter()
            .filter(|r| r.source == RuleSourceView::Config)
            .collect();
        assert_eq!(collapsed.len(), 2, "the group collapses to one row");
        assert_eq!(collapsed[0].rule, "@mcp");
        assert_eq!(collapsed[0].group.as_deref(), Some("mcp"));
        assert!(collapsed[1].rule.contains("api.example.com") && collapsed[1].group.is_none());

        // Expanded: both group hosts appear, each carrying its group; the direct rule has none.
        let expanded: Vec<_> = net_rules_view(&policy, true)
            .into_iter()
            .filter(|r| r.source == RuleSourceView::Config)
            .collect();
        assert_eq!(expanded.len(), 3, "every rule is its own row when expanded");
        assert_eq!(
            expanded
                .iter()
                .filter(|r| r.group.as_deref() == Some("mcp"))
                .count(),
            2,
            "both expanded group hosts carry their origin"
        );
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
            tasks: Vec::new(),
            fs_deny: Vec::new(),
            fs_origin: Default::default(),
            fs_readonly: Vec::new(),
            notify: Default::default(),
            notify_origin: Default::default(),
            ssh_agent_confirm: false,
            cwd: "/proj".into(),
            env: vec![EnvVar {
                key: "A".into(),
                value: "1".into(),
                layer: Some(ProvenanceView::Project),
            }],
            binds: vec![BindView {
                path: "/data".into(),
                writable: false,
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
                mute: vec![],
                http2: vec![],
                capture: "off".to_string(),
                capture_max_kb: None,
                pool: true,
                dns_cache_ttl: Some(30),
                builtin: vec!["cache.nixos.org".into()],
            },
            network_origin: ProvenanceView::Project,
            egress_stats: true,
            proc: Default::default(),
            proc_origin: Default::default(),
            gui: GuiView::Wayland,
            gui_origin: ProvenanceView::Global,
            gpu: true,
            audio: true,
            dbus: true,
            gpu_origin: ProvenanceView::Project,
            audio_origin: ProvenanceView::Project,
            dbus_origin: ProvenanceView::Project,
            forward: vec![1455],
            forward_origin: ProvenanceView::Global,
            seccomp: vec![],
            seccomp_origin: ProvenanceView::Default,
            devices: vec![],
            devices_origin: ProvenanceView::Default,
            ssh_agent: vec![],
            ssh_agent_origin: Default::default(),
            limits: Default::default(),
            secrets: vec![],
            apps: vec![AppView {
                fs_deny: Vec::new(),
                fs_readonly: Vec::new(),
                ssh_agent: Vec::new(),
                name: "demo-app".into(),
                cmd: Some("demo-app".into()),
                home_scope: "global (shared across projects)".into(),
                env: vec![AppEnvVar {
                    key: "DEMO_API_KEY".into(),
                    value: "placeholder".into(),
                }],
                binds: vec![BindView {
                    path: "/data/cache".into(),
                    writable: false,
                    layer: None,
                }],
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
                gpu: None,
                audio: None,
                dbus: None,
                forward: vec![1455],
                seccomp: vec![],
                devices: vec![],
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
        assert_eq!(json["binds"][0]["writable"], false);
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
        // The two transport settings a global layer can make invisibly for a project travel with
        // it too, so a front-end can show what the cage cannot observe about its own egress.
        assert_eq!(json["network"]["Allowlist"]["pool"], true);
        assert_eq!(json["network"]["Allowlist"]["dns_cache_ttl"], 30);
        assert_eq!(json["gui"], "Wayland");
        // The scalar postures' provenance is part of the serialization contract — a value's origin
        // (default/global/project) travels with it.
        assert_eq!(json["network_origin"], "Project");
        assert_eq!(json["gui_origin"], "Global");
        // The GPU posture and its provenance travel with the view too.
        assert_eq!(json["gpu"], true);
        assert_eq!(json["gpu_origin"], "Project");
        // The filtered-D-Bus posture and its provenance likewise.
        assert_eq!(json["dbus"], true);
        assert_eq!(json["dbus_origin"], "Project");
        // The forward port list + its origin travel with the view, so a front-end can render
        // the host-loopback forward ports and where they came from.
        assert_eq!(json["forward"][0], 1455);
        assert_eq!(json["forward_origin"], "Global");
        assert_eq!(json["apps"][0]["forward"][0], 1455);
        // An app overlay's allowlist serializes its rules and the built-in set in full, so the
        // JSON form carries what `sbx app <name>` can reach without a `--details` equivalent.
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
        assert_eq!(json["apps"][0]["binds"][0]["path"], "/data/cache");
        assert_eq!(json["apps"][0]["binds"][0]["writable"], false);
        // An app overlay's packages serialize as the full package projection — the backend and
        // trust verdict the baseline `packages` carries — so the JSON form shows an untrusted app
        // package as withheld without a `--details` equivalent.
        assert_eq!(json["apps"][0]["packages"][0]["name"], "demo-tool");
        assert_eq!(json["apps"][0]["packages"][0]["backend"], "mise");
        assert_eq!(json["apps"][0]["packages"][0]["trusted"], true);
        // An app overlay's injected credentials serialize by destination and source — never the
        // value — so the JSON form carries what `sbx app <name>` injects without a `--details` flag.
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
    fn a_pinned_deb_hash_surfaces_keyed_by_the_url_locator() {
        use crate::config::Package;
        // A deb package's locator is its URL; the merged pin map keys deb hashes by that URL, so the
        // same locator-keyed lookup that serves flake serves deb (disjoint key spaces, one map).
        let url = "https://e/app-linux-amd64.deb";
        let pins = BTreeMap::from([(url.to_string(), "jBGtMS5l".to_string())]);
        let deb = Package {
            name: "app".into(),
            backend: Backend::Deb(url.into()),
            state: TrustState::Trusted,
            libs: Vec::new(),
        };
        assert_eq!(deb.backend.locator(), url);
        assert_eq!(
            package_view(&deb, &pins).pinned_rev.as_deref(),
            Some("jBGtMS5l")
        );
        assert_eq!(package_view(&deb, &BTreeMap::new()).pinned_rev, None);
    }

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
            libs: Vec::new(),
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
            libs: Vec::new(),
        };
        assert_eq!(package_view(&nixpkg, &pins).pinned_rev, None);

        // App projection: the compact list carries the same pin, keyed identically.
        let app = ResolvedApp {
            fs: Default::default(),
            fs_origin: crate::config::Provenance::Default,
            notify: None,
            notify_origin: Default::default(),
            ssh_agent_confirm: false,
            ssh_agent_origin: Default::default(),
            ssh_agent: Vec::new(),
            cmd: vec!["pinned-tool".into()],
            home_scope: AppHomeScope::Global,
            env: vec![],
            binds: vec![],
            packages: vec![flake],
            network: None,
            gui: None,
            proc: None,
            proc_origin: Default::default(),
            gpu: None,
            audio: None,
            dbus: None,
            limits: Default::default(),
            forward: vec![],
            secrets: vec![],
            tasks: vec![],
            default_methods: crate::allowlist::Methods::Unspecified,
            cmd_origin: Default::default(),
            network_origin: Default::default(),
            gui_origin: Default::default(),
            gpu_origin: Default::default(),
            audio_origin: Default::default(),
            dbus_origin: Default::default(),
            forward_origin: Default::default(),
            limits_origin: Default::default(),
            seccomp: Default::default(),
            seccomp_origin: Default::default(),
            devices: Vec::new(),
            devices_origin: Default::default(),
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
            name: "api.example.com".into(),
            description: None,
            sources: vec![crate::config::SecretSource::Env("TOKEN".into())],
            to: crate::allowlist::Rule {
                kind: crate::allowlist::RuleKind::Host(
                    "api.example.com".into(),
                    crate::allowlist::Ports::Any,
                ),
                methods: crate::allowlist::Methods::Any,
                layer: crate::allowlist::Layer::L7,
                group: None,
            },
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
            fs: Default::default(),
            fs_origin: crate::config::Provenance::Default,
            notify: Default::default(),
            notify_origin: Default::default(),
            ssh_agent_confirm: false,
            env: vec![],
            env_layer: Default::default(),
            tasks: vec![],
            // One bind the app shadows by path (with a different mode), one it inherits unchanged.
            binds: vec![
                crate::config::Bind {
                    path: std::path::PathBuf::from("/shared"),
                    writable: false,
                },
                crate::config::Bind {
                    path: std::path::PathBuf::from("/base-only"),
                    writable: false,
                },
            ],
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
            gpu: false,
            audio: false,
            dbus: false,
            gpu_origin: Provenance::Default,
            audio_origin: Provenance::Default,
            dbus_origin: Provenance::Default,
            forward: vec![9090],
            forward_origin: Provenance::Global,
            proc: Default::default(),
            proc_origin: Default::default(),
            limits: sandbox::cgroup::Limits {
                memory_high: Some("50%".into()),
                memory_max: None,
                tasks_max: None,
            },
            limits_origin: Default::default(),
            secrets: vec![a_header_secret()],
            seccomp: Default::default(),
            seccomp_origin: Default::default(),
            devices: Vec::new(),
            devices_origin: Default::default(),
            ssh_agent: vec![],
            ssh_agent_origin: Default::default(),
            declared_secrets: vec![a_header_secret()],
            apps: Default::default(),
            warnings: vec![],
        };
        // The app overrides the network and the task cap, leaves the GUI and the throttle alone.
        let app = ResolvedApp {
            fs: Default::default(),
            fs_origin: crate::config::Provenance::Default,
            notify: None,
            notify_origin: Default::default(),
            ssh_agent_confirm: false,
            ssh_agent_origin: Default::default(),
            ssh_agent: Vec::new(),
            cmd: vec!["demo".into()],
            home_scope: AppHomeScope::Global,
            env: vec![],
            // Shadows the baseline `/shared` (read-write) and adds a new `/app-only`.
            binds: vec![
                crate::config::Bind {
                    path: std::path::PathBuf::from("/shared"),
                    writable: true,
                },
                crate::config::Bind {
                    path: std::path::PathBuf::from("/app-only"),
                    writable: true,
                },
            ],
            packages: vec![],
            network: Some(NetworkPolicy::Isolated),
            gui: None,
            gpu: None,
            audio: None,
            dbus: None,
            limits: sandbox::cgroup::Limits {
                memory_high: None,
                memory_max: None,
                tasks_max: Some("99".into()),
            },
            // The app adds its own port; the baseline's 9090 must survive the union.
            forward: vec![1455],
            secrets: vec![],
            tasks: vec![],
            proc: None,
            proc_origin: Default::default(),
            default_methods: crate::allowlist::Methods::Unspecified,
            cmd_origin: Provenance::Global,
            network_origin: Provenance::Global,
            gui_origin: Provenance::Default,
            gpu_origin: Provenance::Default,
            audio_origin: Provenance::Default,
            dbus_origin: Provenance::Default,
            forward_origin: Provenance::Global,
            limits_origin: crate::config::LimitsOrigin {
                memory_high: Provenance::Default,
                memory_max: Provenance::Default,
                tasks_max: Provenance::Global,
            },
            seccomp: Default::default(),
            seccomp_origin: Default::default(),
            devices: Vec::new(),
            devices_origin: Default::default(),
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

        // Effective forward must equal merge_app's union — the app's own 1455 plus the inherited
        // baseline 9090, sorted — so the detail view never misreports the forwarded ports.
        assert_eq!(
            detail.forward, merged.forward,
            "effective forward must match merge_app"
        );
        assert_eq!(
            merged.forward,
            vec![1455, 9090],
            "the union keeps both ports"
        );

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

        // Binds must agree too: the app's own binds plus the count it inherits must equal the
        // path-keyed union merge_app mounts — so `binds_inherited` cannot drift from the launch. The
        // app shadows `/shared` and adds `/app-only`; only `/base-only` is inherited.
        assert_eq!(detail.binds.len(), 2, "the app lists its own two binds");
        assert_eq!(
            detail.binds_inherited, 1,
            "only the un-shadowed baseline bind is inherited"
        );
        assert_eq!(
            detail.binds.len() + detail.binds_inherited,
            merged.binds.len(),
            "effective bind count must match merge_app's path-keyed union"
        );
    }
}
