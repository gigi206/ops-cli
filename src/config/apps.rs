//! The per-app overlay: an app's resolved view of the sandbox, and the layering that produces one.
//!
//! A sibling of the baseline engine next door rather than a part of it. `resolve` calls
//! [`resolve_apps`] once and hands it every baseline it needs; nothing here reads a local of that
//! pass. What the two share is the rule, not the code path: an app field is gated by the same
//! verdict, through the same `Gate`, as the baseline field it overlays, and the app layer is
//! layered global-under-project exactly as the baseline is.
//!
//! An app is the Mode-B surface — it names a command, a `$HOME` that outlives the run, and the
//! credentials that command reaches — so it carries one restriction the baseline has no need of:
//! the name is a path component (it keys the persistent home, and an imported profile's file), and
//! a name that could traverse out of its directory is dropped before it can key anything.

use super::*;

/// Where an app's persistent `$HOME` (its config, login state, history) is keyed. The home
/// is always per-app and isolated from the project's default shell home; this chooses whether
/// it is *also* per-project.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AppHomeScope {
    /// One home per app, shared across every project — the app keeps a single identity
    /// wherever it runs. The default. Carries a residual: an agent run on an untrusted
    /// project writes into the same home a trusted project's run uses (`"project"` isolates).
    Global,
    /// A home per (project, app) — what the agent writes in one project is invisible to
    /// another. Aligned with running an agent on untrusted code.
    Project,
}

/// An app's resolved overlay over the sandbox baseline: the command to run plus the extra
/// environment, binds, packages, network posture, and credentials it declares — each
/// already gated by the trust of the layer that supplied it (the global config, trusted by
/// location, or a project layer by its verdict). `sbx app <name>` folds this onto the
/// baseline with [`Resolved::merge_app`].
#[derive(Clone)]
pub(crate) struct ResolvedApp {
    /// The argv to run. Empty when no layer declared a `cmd` — a launch error, never a
    /// silent default.
    pub(crate) cmd: Vec<String>,
    /// The install steps this app's bundles contribute, in `use` order, each stamped with its
    /// bundle. They run before [`Self::cmd`] and never in its place; an app declares none of its
    /// own, which is why they arrive only through the fold.
    pub(crate) provisions: Vec<BundleProvision>,
    /// Where this app's persistent home is keyed (`Global` by default). Integrity-gated like
    /// `cmd`: an untrusted project may set its own app's scope but not flip a trusted app from
    /// `Project` to `Global`.
    pub(crate) home_scope: AppHomeScope,
    /// Extra environment, in application order; folded over the baseline's so the app wins.
    pub(crate) env: Vec<(String, String)>,
    /// Extra host binds this app adds (absolute; canonicalized in [`load()`], like the baseline),
    /// each read-only or read-write.
    pub(crate) binds: Vec<Bind>,
    /// Extra tools, each tagged with its source's trust; override a baseline tool by name.
    pub(crate) packages: Vec<Package>,
    /// Packages whose vendor publishes faster than a freshness delay tolerates, named by a trusted
    /// layer so their equip and their roll accept a release with no cooling-off period. Package
    /// names, deduplicated, in declaration order; see [`schema::RawConfig::accepts_fresh_releases`]
    /// for what the delay is and why lifting it is a trade.
    pub(crate) accepts_fresh_releases: Vec<String>,
    /// This app's URI handlers, its bundles' folded in beneath its own; override a baseline
    /// handler by scheme. A security field, gated like the app's `binds`.
    pub(crate) open: BTreeMap<String, OpenHandler>,
    /// This app's auxiliary services, its bundles' folded in beneath its own; override a baseline
    /// service by name. A security field, gated like the app's `binds`.
    pub(crate) service: BTreeMap<String, ServiceSpec>,
    /// The app's own network posture, set only when a trusted source declared one. `Some`
    /// overrides the baseline; `None` leaves the baseline posture in place.
    pub(crate) network: Option<NetworkPolicy>,
    /// The app's own process/exec posture, set only when a trusted source declared one. `Some`
    /// overrides the baseline; `None` leaves the baseline posture in place.
    pub(crate) proc: Option<crate::proc_policy::ProcPolicy>,
    /// The app's own refusal-notification policy, set only when a trusted source declared one.
    ///
    /// `Some` overrides the baseline; `None` leaves the baseline policy in place.
    pub(crate) notify: Option<crate::notify::NotifyPolicy>,
    /// The app's own GUI posture, set only when a trusted source declared one. `Some` overrides
    /// the baseline; `None` leaves the baseline posture in place.
    pub(crate) gui: Option<GuiPolicy>,
    /// The app's own GPU posture, set only when a trusted source declared one. `Some` overrides
    /// the baseline; `None` leaves the baseline posture in place. Gated like the app's `gui`.
    pub(crate) gpu: Option<bool>,
    /// The app's own plaintext-fetch posture, `None` when it declares none and inherits the
    /// baseline's. Its own contribution, like `gpu` — the effective value is folded by `merge_app`.
    pub(crate) allow_insecure_http: Option<bool>,
    /// The app's own audio posture, set only when a trusted source declared one. `Some` overrides
    /// the baseline; `None` leaves the baseline posture in place. Gated like the app's `gpu`.
    pub(crate) audio: Option<bool>,
    /// The app's own D-Bus posture, set only when a trusted source declared one. `Some` overrides
    /// the baseline; `None` leaves the baseline posture in place. Gated like the app's `gpu`.
    pub(crate) dbus: Option<bool>,
    /// The app's own cgroup limit overrides, set only from a trusted source (an untrusted
    /// project's app `[limits]` is dropped whole, like its `network`/`gui`). Each set field
    /// overrides the baseline at [`merge_app`](Resolved::merge_app); an unset one keeps the baseline value. All-`None`
    /// means the app tunes nothing and inherits the baseline limits.
    pub(crate) limits: crate::sandbox::cgroup::Limits,
    /// The app's own seccomp relaxation, set only from a trusted source (an untrusted project's app
    /// `[seccomp]` is dropped, like its `network`/`limits`). Unions onto the baseline at
    /// [`merge_app`](Resolved::merge_app); empty means the app relaxes nothing and inherits the baseline relaxation. A
    /// security field, gated like the baseline `[seccomp]`.
    pub(crate) seccomp: crate::sandbox::seccomp::SeccompPolicy,
    /// The app's own host device grant, set only from a trusted source (an untrusted project's app
    /// `[devices]` is dropped, like its `network`/`seccomp`). Unions onto the baseline at
    /// [`merge_app`](Resolved::merge_app); empty means the app grants no device and inherits the baseline grant. A
    /// security field, gated like the baseline `[devices]`.
    pub(crate) devices: Vec<PathBuf>,
    /// The app's own ssh-agent grant, set only from a trusted source (an untrusted project's app
    /// `[ssh_agent]` is dropped, like its `network`/`devices`). Unions onto the baseline at
    /// [`merge_app`](Resolved::merge_app); empty means the app names no key of its own and inherits the baseline grant.
    /// A security field, gated like the baseline `[ssh_agent]` — and the field that makes a deploy
    /// key grantable to one app rather than to every cage the project launches.
    pub(crate) ssh_agent: Vec<String>,
    /// The app's own `[fs]` masks. Unions onto the baseline at [`merge_app`](Resolved::merge_app); empty means the app
    /// closes nothing of its own. Ungated like the baseline `[fs]` — it only subtracts access — and
    /// the union direction means an app can close more of the tree for its own tool without being
    /// able to reopen what the project already closed.
    pub(crate) fs: fspolicy::FsPolicy,
    /// The app's own host loopback forward ports, set only from a trusted source (an untrusted
    /// project's app `forward` is dropped, like its `network`/`gui`). The set **unions** onto the
    /// baseline's at [`merge_app`](Resolved::merge_app); an empty vec means the app adds none and inherits the baseline
    /// set. A security field, gated like the baseline `forward`.
    pub(crate) forward: Vec<ForwardPort>,
    /// Credentials to inject for this app (gated; the plaintext never enters the cage).
    pub(crate) secrets: Vec<HeaderSecret>,
    /// Declared operations this app contributes, unioned onto the baseline's at [`merge_app`](Resolved::merge_app) (the
    /// app wins on a name collision). A security field, gated like the app's `secrets`.
    pub(crate) tasks: Vec<TaskSpec>,
    /// The verbs this app's unscoped (`{...}`-less) allow rules default to — its read-by-default
    /// posture. Every Mode-B app defaults to `Only(["GET","HEAD"])`; an `[app.<name>.network]
    /// default_methods` override sets a different set (or `Any` for `["*"]`, all verbs). Applied to
    /// the app's effective allowlist at [`merge_app`](Resolved::merge_app); the baseline `sbx run` never gets
    /// it (Mode A stays all-verbs).
    pub(crate) default_methods: crate::allowlist::Methods,
    /// Per-field provenance of this app's *scalar* overlay fields, for the per-app `sbx config`
    /// view — which app layer (`Global`/`Project`) set each. Read only when the app actually set
    /// the field; an unset scalar is shown as inherited from the baseline. `home_scope_origin` is
    /// `None` for the built-in default (`Global`), since the home scope is an app-only concept with
    /// no baseline to inherit. The launcher ignores all of these (a display affordance).
    pub(crate) cmd_origin: Provenance,
    pub(crate) network_origin: Provenance,
    pub(crate) proc_origin: Provenance,
    pub(crate) notify_origin: Provenance,
    pub(crate) gui_origin: Provenance,
    pub(crate) gpu_origin: Provenance,
    pub(crate) allow_insecure_http_origin: Provenance,
    pub(crate) audio_origin: Provenance,
    pub(crate) dbus_origin: Provenance,
    pub(crate) limits_origin: LimitsOrigin,
    /// Which app layer (`Global`/`Project`) supplied the app's own `forward` ports, or `Default`
    /// when the app declared none. The merged effective set is the app's own ∪ the baseline's;
    /// a port the app did not contribute is shown as inherited from the baseline.
    pub(crate) forward_origin: Provenance,
    /// Which app layer (`Global`/`Project`) supplied the app's own seccomp relaxation, or `Default`
    /// when the app declared none. The merged effective relaxation is the app's own ∪ the baseline's.
    pub(crate) seccomp_origin: Provenance,
    /// Which app layer (`Global`/`Project`) supplied the app's own device grant, or `Default` when
    /// the app declared none. The merged effective grant is the app's own ∪ the baseline's.
    pub(crate) devices_origin: Provenance,
    /// Which app layer (`Global`/`Project`) supplied the app's own `[fs]` masks, or `Default` when
    /// the app declared none. The merged effective set is the app's own ∪ the baseline's.
    pub(crate) fs_origin: Provenance,
    /// Which app layer (`Global`/`Project`) supplied the app's own ssh-agent grant, or `Default`
    /// when the app declared none. The merged effective grant is the app's own ∪ the baseline's.
    pub(crate) ssh_agent_origin: Provenance,
    /// Whether this app asks for a per-signature confirmation (`[app.<name>.ssh_agent] confirm`).
    /// ORed onto the baseline's at [`merge_app`](Resolved::merge_app), never subtracted.
    pub(crate) ssh_agent_confirm: bool,
    pub(crate) home_scope_origin: Option<Provenance>,
    /// Notes about what this app's resolution dropped or ignored — surfaced when the app is
    /// launched, not on every `sbx run`.
    pub(crate) warnings: Vec<String>,
}

/// The built-in app default: a Mode-B agent's unscoped allow rules default to `{GET,HEAD}` (read by
/// default; declare `{*}`/`{POST}` per host, or `default_methods` per app, to write). The baseline
/// `sbx run` (Mode A) never gets this — it stays all-verbs.
pub(super) fn builtin_app_default_methods() -> crate::allowlist::Methods {
    crate::allowlist::Methods::Only(vec!["GET".to_string(), "HEAD".to_string()])
}

/// Resolve an app layer's `default_methods` override (the raw verbs, peeked before the network field
/// moved into `validate_network`) into the effective app default, warning (and falling back to the
/// built-in `{GET,HEAD}`) on a malformed value. `None` (the layer set none) leaves the running
/// default unchanged. Called only when the layer's network was honored, so an invalid value is not
/// warned about for a dropped/untrusted network.
fn resolve_app_default_methods(
    warnings: &mut Vec<String>,
    source: &str,
    raw: Option<Vec<String>>,
) -> Option<crate::allowlist::Methods> {
    let verbs = raw?;
    Some(
        crate::allowlist::parse_default_methods(&verbs).unwrap_or_else(|e| {
            warnings.push(format!(
                "{source}: ignoring invalid `default_methods` — {e}; using the built-in {{GET,HEAD}} \
                 app default"
            ));
            builtin_app_default_methods()
        }),
    )
}

/// Warn when an app's `[network]` table carries a `stats` toggle: the egress-stats switch is
/// baseline-only (it applies to every launch), so an `[app.<name>.network] stats = …` is parsed but
/// has no effect. Surfacing it (rather than silently dropping it) keeps a profile author from
/// believing they disabled an agent's audit when they did not.
fn warn_if_app_sets_stats(warnings: &mut Vec<String>, source: &str, field: &NetworkField) {
    if network_stats_of(field).is_some() {
        warnings.push(format!(
            "{source}: ignoring `stats` under `[network]` — the egress-stats toggle is baseline-only; \
             set `[network] stats` at the top level (it applies to every launch)"
        ));
    }
}

/// Report the keys an app declared that sbx does not know, the app-scoped half of
/// [`warn_unknown_keys`].
///
/// An app profile is a **subset** of the baseline schema, which is what makes this worth saying out
/// loud rather than leaving to the additive-schema rule. A baseline-only field written on an app —
/// `timezone`, `nixpkgs`, `[network] groups` — parses, is dropped, and changes nothing, and the only
/// way its author could notice was the value not taking effect. The message names the key and says
/// where such a field belongs, since "unknown" is misleading for a key that is a real field one
/// layer up.
///
/// The remedy names the two config files rather than the `[app.<name>]` shape, because an app has
/// two declaration shapes and only one of them is a table: a global app is a profile file whose
/// fields are at its top level, so "outside `[app.<name>]`" would describe a wrapper that file does
/// not have.
pub(super) fn warn_unknown_app_keys(
    warnings: &mut Vec<String>,
    source: &str,
    rest: &BTreeMap<String, schema::RawIgnored>,
) {
    for key in rest.keys() {
        warnings.push(format!(
            "{source}: ignoring unknown key `{key}` — sbx does not know this field on an app \
             (check the spelling; a field that exists only on the baseline, like `timezone`, is \
             declared at the top level of `{GLOBAL_CONFIG}` or `{PROJECT_CONFIG}`, never on an app)"
        ));
    }
}

/// Resolve every declared app into a gated overlay. The set of names is the union of the
/// global and project app tables; each app is layered global-under-project and gated by the
/// trust of the layer that supplied each field — identical to the baseline. An app whose name
/// is not a safe path component is dropped with a warning before it can ever key a directory.
#[allow(clippy::too_many_arguments)]
pub(super) fn resolve_apps(
    warnings: &mut Vec<String>,
    mut global_apps: BTreeMap<String, RawApp>,
    project_apps: Option<(BTreeMap<String, RawApp>, TrustState)>,
    secret_defaults: &SecretDefaults,
    project_secret_defaults: &SecretDefaults,
    task_defaults: &tasks::TaskDefaults,
    net_groups: &NetGroups,
    baseline_network: &NetworkPolicy,
    baseline_proc: &crate::proc_policy::ProcPolicy,
    baseline_notify: &crate::notify::NotifyPolicy,
    baseline_allow_insecure_http: bool,
    plugins: &PluginRegistry,
) -> BTreeMap<String, ResolvedApp> {
    let (mut project_apps, project_state) = match project_apps {
        Some((map, state)) => (map, Some(state)),
        None => (BTreeMap::new(), None),
    };
    let names: BTreeSet<String> = global_apps
        .keys()
        .chain(project_apps.keys())
        .cloned()
        .collect();
    let mut out = BTreeMap::new();
    for name in names {
        if !is_valid_app_name(&name) {
            warnings.push(format!(
                "ignoring app `{name}`: a name must be 1–64 of [A-Za-z0-9._-] and not `.`/`..` \
                 (it keys an on-disk home directory)"
            ));
            continue;
        }
        let global = global_apps.remove(&name);
        let project = project_apps.remove(&name).zip(project_state);
        let resolved = resolve_app(
            &name,
            global,
            project,
            secret_defaults,
            project_secret_defaults,
            task_defaults,
            net_groups,
            baseline_network,
            baseline_proc,
            baseline_notify,
            baseline_allow_insecure_http,
            plugins,
        );
        out.insert(name, resolved);
    }
    out
}

/// Whether an app name is safe to use as a single on-disk path component (it keys the app's
/// persistent home directory and, for an imported profile, its file). Restricted to a conservative
/// charset and length, and `.`/`..` are rejected outright so a name can never traverse out of a
/// directory. A name that coincides with a `sbx app` subcommand verb (`run`, `show`, …) is
/// perfectly valid: launching always goes through `sbx app run <name>`, so the name never collides
/// with the subcommand.
pub(crate) fn is_valid_app_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && name != "."
        && name != ".."
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

/// Resolve one app: layer its global definition (trusted by location) under its project
/// definition (gated by the project's verdict), reusing the baseline's per-field gating. The
/// project layer overrides the global per field. Security fields (`binds`/`network`/`secret`)
/// are honored only from a trusted source; `env` is free (denylisted for an untrusted
/// project); the command may come from either (the project wins). Each app collects its own
/// warnings, surfaced when the app is launched rather than on every `sbx run`.
#[allow(clippy::too_many_arguments)]
fn resolve_app(
    name: &str,
    global: Option<RawApp>,
    project: Option<(RawApp, TrustState)>,
    secret_defaults: &SecretDefaults,
    project_secret_defaults: &SecretDefaults,
    task_defaults: &tasks::TaskDefaults,
    net_groups: &NetGroups,
    baseline_network: &NetworkPolicy,
    baseline_proc: &crate::proc_policy::ProcPolicy,
    baseline_notify: &crate::notify::NotifyPolicy,
    baseline_allow_insecure_http: bool,
    plugins: &PluginRegistry,
) -> ResolvedApp {
    let mut warnings = Vec::new();
    let mut env: Vec<(String, String)> = Vec::new();
    let mut binds: Vec<Bind> = Vec::new();
    let mut packages: Vec<Package> = Vec::new();
    let mut accepts_fresh_releases: Vec<String> = Vec::new();
    let mut secrets: Vec<HeaderSecret> = Vec::new();
    let mut tasks: Vec<TaskSpec> = Vec::new();
    let mut open: BTreeMap<String, OpenHandler> = BTreeMap::new();
    let mut service: BTreeMap<String, ServiceSpec> = BTreeMap::new();
    let mut network: Option<NetworkPolicy> = None;
    // Every Mode-B app reads by default ({GET,HEAD}); a trusted layer's `default_methods` overrides it.
    let mut default_methods = builtin_app_default_methods();
    let mut proc: Option<crate::proc_policy::ProcPolicy> = None;
    let mut notify: Option<crate::notify::NotifyPolicy> = None;
    let mut gui: Option<GuiPolicy> = None;
    let mut gpu: Option<bool> = None;
    let mut audio: Option<bool> = None;
    let mut dbus: Option<bool> = None;
    // The app's own cgroup limit overrides, accumulated like `network`/`gui`: the global layer
    // sets them by location, a trusted project overlays per field, an untrusted one is dropped.
    let mut limits = crate::sandbox::cgroup::Limits::default();
    // The app's own seccomp relaxation, accumulated like the limits: global by location, a trusted
    // project unions, an untrusted one dropped. Empty means the app inherits the baseline's.
    let mut seccomp = crate::sandbox::seccomp::SeccompPolicy::default();
    let mut seccomp_origin = Provenance::Default;
    // The app's own device grant, accumulated like the seccomp relaxation: global by location, a
    // trusted project unions, an untrusted one dropped. Empty means the app inherits the baseline's.
    let mut devices: Vec<PathBuf> = Vec::new();
    let mut devices_origin = Provenance::Default;
    let mut fs = FsPolicy::default();
    let mut fs_origin = Provenance::Default;
    let mut ssh_agent: Vec<String> = Vec::new();
    let mut ssh_agent_origin = Provenance::Default;
    let mut ssh_agent_confirm = false;
    let mut cmd: Vec<String> = Vec::new();
    // The install steps the layers' bundles contributed, in the order they were folded. A step is
    // carried, never merged: two bundles each finish their own tool. The same bundle named by both
    // layers contributes once — running one install twice is at best waste and at worst a fight
    // over the same directory.
    let mut provisions: Vec<BundleProvision> = Vec::new();
    let absorb_provisions = |steps: Vec<BundleProvision>, provisions: &mut Vec<BundleProvision>| {
        for step in steps {
            if !provisions.contains(&step) {
                provisions.push(step);
            }
        }
    };
    // Whether a trusted layer defined this app **at all** — a global profile file, trusted by its
    // location. It gates the two fields that steer what an app *is* rather than what it may reach:
    // `cmd` and `home_scope`.
    //
    // The question is the app's provenance, not the field's. Gating on "did a trusted layer set
    // this field" left the hole open in the shape that matters: a profile publishing a posture
    // (network, binds, gui) and **no** `cmd` was completed by an untrusted project, and
    // `sbx app <name>` then ran that repo's command under the trusted app's posture — the
    // integrity-of-intent hijack the field-level flag was written to stop, arriving through the
    // app the flag says nothing about. An untrusted project still defines its *own* app freely:
    // there is nothing trusted to steer when no trusted layer named it.
    let defined_by_a_trusted_layer = global.is_some();
    // The persistent-home keying, defaulting to one global home per app. Gated by
    // `defined_by_a_trusted_layer` for the same reason as `cmd`: an untrusted project may set the
    // scope of its own app, but must not choose it for a trusted one — `Global` routes the
    // untrusted run into the home a trusted run shares.
    let mut home_scope = AppHomeScope::Global;
    // Per-field provenance of the scalar overlay fields, for the per-app `sbx config` view: which
    // app layer set each, recorded at the same point the value is. A scalar the overlay never sets
    // stays `Default` here and the view shows it inherited from the baseline; `home_scope_origin`
    // stays `None` for the built-in default.
    let mut cmd_origin = Provenance::Default;
    let mut network_origin = Provenance::Default;
    let mut proc_origin = Provenance::Default;
    let mut notify_origin = Provenance::Default;
    let mut gui_origin = Provenance::Default;
    let mut gpu_origin = Provenance::Default;
    let mut audio_origin = Provenance::Default;
    let mut dbus_origin = Provenance::Default;
    // The app's own loopback forward ports — a security field, gated like `network`/`gui`. The
    // merged effective set (app ∪ baseline) is computed at `merge_app`; this holds only the app's
    // own contribution, with its origin for the per-app view.
    let mut forward: Vec<ForwardPort> = Vec::new();
    let mut forward_origin = Provenance::Default;
    let mut limits_origin = LimitsOrigin::default();
    let mut home_scope_origin: Option<Provenance> = None;

    // The app's own `allow_insecure_http`, resolved ahead of its `apply_tools` calls for exactly
    // the reason the baseline one is (see `resolve`): it decides how this app's package values are
    // validated, so reading it after them would validate against a flag not yet supplied. Unset at
    // both layers, the app inherits the baseline — an app that says nothing does not quietly
    // re-tighten what the machine already opened, nor open what it did not.
    let mut own_allow_insecure_http: Option<bool> = None;
    let mut allow_insecure_http_origin = Provenance::Default;
    if let Some(app) = global.as_ref()
        && let Some(value) = app.allow_insecure_http
    {
        own_allow_insecure_http = Some(value);
        allow_insecure_http_origin = Provenance::Global;
    }
    if let Some((app, state)) = project.as_ref()
        && let Some(value) = app.allow_insecure_http
    {
        if *state == TrustState::Trusted {
            own_allow_insecure_http = Some(value);
            allow_insecure_http_origin = Provenance::Project;
        } else {
            refuse_untrusted(
                &mut warnings,
                &project_app_source(name),
                "`allow_insecure_http`",
                *state,
            );
        }
    }
    // Derived once from the app's own answer rather than tracked beside it: two variables assigned
    // in lockstep are two variables that can stop agreeing, and the `None` here is exactly what the
    // per-app view reports as inherited.
    let allow_insecure_http = own_allow_insecure_http.unwrap_or(baseline_allow_insecure_http);

    // The global layer — trusted by location, honored in full.
    if let Some(app) = global {
        let source = global_app_source(name);
        warn_unknown_app_keys(&mut warnings, &source, &app.rest);
        absorb_provisions(app.provisions, &mut provisions);
        apply_env(&mut env, None, &mut warnings, &source, app.env, false);
        apply_binds(&mut binds, None, &mut warnings, &source, app.binds);
        // The bundles this app names were folded under it at load, so this table already holds
        // theirs beneath the app's own.
        open.extend(validate_open(&mut warnings, &source, app.open));
        service.extend(validate_service(&mut warnings, &source, app.service));
        apply_tools(
            &mut packages,
            &mut warnings,
            &source,
            app.packages,
            app.flakes,
            app.tarball,
            app.deb,
            app.appimage,
            app.binary,
            TrustState::Trusted,
            false,
            allow_insecure_http,
        );
        apply_fresh_releases(
            &mut accepts_fresh_releases,
            &mut warnings,
            &source,
            app.accepts_fresh_releases,
            TrustState::Trusted,
        );
        if let Some(field) = app.network {
            warn_if_app_sets_stats(&mut warnings, &source, &field);
            let raw_dm = network_default_methods_of(&field).cloned();
            // A mode-less app `[network]` inherits its mode from the resolved baseline (the app's
            // own rules are kept). At the global app layer nothing has overridden it yet, so the
            // parent is the baseline.
            let parent = network.as_ref().unwrap_or(baseline_network);
            let resolved = validate_network(&mut warnings, &source, field, net_groups, parent);
            if let Some(policy) = resolved {
                network = Some(policy);
                network_origin = Provenance::Global;
                if let Some(m) = resolve_app_default_methods(&mut warnings, &source, raw_dm) {
                    default_methods = m;
                }
            }
        }
        if let Some(field) = app.proc {
            warn_unknown_proc_keys(&mut warnings, &source, &field);
            // A table without a mode inherits from the app's own proc so far, else the baseline.
            let parent = proc.as_ref().unwrap_or(baseline_proc);
            if let Some(policy) = validate_proc(&mut warnings, &source, field, parent) {
                proc = Some(policy);
                proc_origin = Provenance::Global;
            }
        }
        if let Some(field) = app.notify {
            warn_unknown_notify_keys(&mut warnings, &source, &field);
            // A table without a mode inherits per event from the app's own policy so far, else the
            // baseline.
            let parent = notify.as_ref().unwrap_or(baseline_notify);
            if let Some(policy) = validate_notify(&mut warnings, &source, field, parent) {
                notify = Some(policy);
                notify_origin = Provenance::Global;
            }
        }
        if let Some(value) = app.gui
            && let Some(policy) = validate_gui(&mut warnings, &source, value)
        {
            gui = Some(policy);
            gui_origin = Provenance::Global;
        }
        if let Some(value) = app.gpu {
            gpu = Some(value);
            gpu_origin = Provenance::Global;
        }
        if let Some(value) = app.audio {
            audio = Some(value);
            audio_origin = Provenance::Global;
        }
        if let Some(value) = app.dbus {
            dbus = Some(value);
            dbus_origin = Provenance::Global;
        }
        // `forward` is trusted by location at the global app layer; invalid ports are dropped
        // (warned). The app's own set is kept separate here — it unions onto the baseline at
        // `merge_app` — so the origin records only that this layer contributed.
        if let Some(raw) = app.forward.as_deref() {
            let validated = validate_forward(&mut warnings, &source, raw);
            if !validated.is_empty() {
                forward_origin = Provenance::Global;
            }
            union_forward(&mut forward, validated);
        }
        let global_limits = validate_limits(&mut warnings, &source, app.limits);
        mark_limit_origins(&mut limits_origin, &global_limits, Provenance::Global);
        overlay_limits(&mut limits, global_limits);
        let global_seccomp = apply_seccomp(&mut warnings, &source, app.seccomp);
        if !global_seccomp.is_empty() {
            seccomp_origin = Provenance::Global;
        }
        seccomp.union(&global_seccomp);
        let global_devices = apply_devices(&mut warnings, &source, app.devices);
        if !global_devices.is_empty() {
            devices_origin = Provenance::Global;
        }
        union_devices(&mut devices, global_devices);
        let global_fs = apply_fs(&mut warnings, &source, app.fs);
        if !global_fs.declares_nothing() {
            fs_origin = Provenance::Global;
        }
        fs.union(global_fs);
        let (global_ssh_agent, confirm) = apply_ssh_agent(&mut warnings, &source, app.ssh_agent);
        ssh_agent_confirm |= confirm;
        if !global_ssh_agent.is_empty() {
            ssh_agent_origin = Provenance::Global;
        }
        union_ssh_agent(&mut ssh_agent, global_ssh_agent);
        if let Some(section) = app.secret {
            apply_app_secret(
                &mut secrets,
                &mut warnings,
                &source,
                section,
                secret_defaults,
                plugins,
            );
        }
        // The app's tasks — trusted by location at this layer, like its secrets. The section
        // ceilings come from the baseline's `[task.defaults]`; an app tunes a task's own `timeout`
        // and `max_output` on the task itself.
        if let Some(section) = app.task {
            warn_unknown_task_keys(&mut warnings, &source, &section);
            tasks::apply_task_section(
                &mut tasks,
                &mut warnings,
                &tasks::TaskLayer {
                    source: &source,
                    origin: TaskOrigin::App(name.to_string()),
                },
                section,
                task_defaults,
                secret_defaults,
                plugins,
            );
        }
        if let Some(c) = app.cmd {
            cmd = c.into_argv();
            cmd_origin = Provenance::Global;
        }
        if let Some(raw) = app.home_scope
            && let Some(scope) = validate_home_scope(&mut warnings, &source, &raw)
        {
            home_scope = scope;
            home_scope_origin = Some(Provenance::Global);
        }
    }

    // The project layer — gated by the project's verdict, overriding the global per field.
    if let Some((app, state)) = project {
        let trusted = state == TrustState::Trusted;
        let source = project_app_source(name);
        // Reported whatever the verdict, like the baseline's: an unknown key is a spelling
        // question, not a capability, so an untrusted project hears about its own typo too.
        warn_unknown_app_keys(&mut warnings, &source, &app.rest);
        let gate = Gate {
            trusted,
            state,
            source: &source,
        };
        // A trusted layer's `use` was already folded into the fields above, before resolution, so
        // the references are only reported here — as the per-app note the untrusted case owes the
        // user, in the same place and shape as the `network` one below. Without it, the drop would
        // show only as an app mysteriously short of a tool and an egress rule.
        if !app.uses.is_empty() && !trusted {
            gate.refuse(
                &format!(
                    "`use` of bundle(s) {}",
                    app.uses
                        .iter()
                        .map(|b| format!("`{b}`"))
                        .collect::<Vec<_>>()
                        .join(", ")
                ),
                &mut warnings,
            );
        }
        // Only a trusted layer was folded, so only a trusted layer can carry steps; the untrusted
        // case is already reported above rather than silently dropped.
        absorb_provisions(app.provisions, &mut provisions);
        apply_env(&mut env, None, &mut warnings, &source, app.env, !trusted);
        if !app.binds.is_empty() {
            if trusted {
                apply_binds(&mut binds, None, &mut warnings, &source, app.binds);
            } else {
                warnings.push(dropped_binds_warning(state, app.binds.len()));
            }
        }
        // `[open]` is gated like the app's binds. An untrusted project defining its *own* app is
        // not the exception it is for `cmd`: a handler is not the app's identity but a program run
        // on someone else's click, so an untrusted layer never supplies one.
        if !app.open.is_empty() {
            if trusted {
                open.extend(validate_open(&mut warnings, &source, app.open));
            } else {
                gate.refuse("`[open]` URI handlers", &mut warnings);
            }
        }
        // `[service]` is gated on the same footing, and the exception `cmd` gets does not extend to
        // it either: a service is not the app's identity, it is a second program the launch runs.
        if !app.service.is_empty() {
            if trusted {
                service.extend(validate_service(&mut warnings, &source, app.service));
            } else {
                gate.refuse("`[service]` auxiliary processes", &mut warnings);
            }
        }
        // An untrusted project may add its own app's packages but may not override a package a
        // trusted layer supplied (the `cmd`-integrity guard, applied to the tool).
        apply_tools(
            &mut packages,
            &mut warnings,
            &source,
            app.packages,
            app.flakes,
            app.tarball,
            app.deb,
            app.appimage,
            app.binary,
            state,
            !trusted,
            allow_insecure_http,
        );
        apply_fresh_releases(
            &mut accepts_fresh_releases,
            &mut warnings,
            &source,
            app.accepts_fresh_releases,
            state,
        );
        if let Some(field) = app.network {
            gate.take_validated(
                &mut network,
                &mut network_origin,
                "`network` policy",
                &mut warnings,
                |w, current| {
                    warn_if_app_sets_stats(w, &source, &field);
                    let raw_dm = network_default_methods_of(&field).cloned();
                    // A mode-less table inherits from whatever posture is in effect so far — the
                    // app's own global layer if it set one, else the baseline.
                    let parent = current.as_ref().unwrap_or(baseline_network);
                    let policy = validate_network(w, &source, field, net_groups, parent)?;
                    // Only once the policy stands: the verb posture belongs to a policy that exists.
                    if let Some(m) = resolve_app_default_methods(w, &source, raw_dm) {
                        default_methods = m;
                    }
                    Some(Some(policy))
                },
            );
        }
        // `proc` mirrors `network`: an untrusted project may not set an exec posture, on its own app
        // or by overriding a trusted one (the flagship property — an agent runs *on* untrusted code
        // without that code being able to forge or loosen the enforcement of its own agent).
        if let Some(field) = app.proc {
            gate.take_validated(
                &mut proc,
                &mut proc_origin,
                "`proc` policy",
                &mut warnings,
                |w, current| {
                    warn_unknown_proc_keys(w, &source, &field);
                    let parent = current.as_ref().unwrap_or(baseline_proc);
                    validate_proc(w, &source, field, parent).map(Some)
                },
            );
        }
        // `notify` mirrors `proc`: an untrusted project may not quieten an app's refusals, on its own
        // app or by overriding a trusted one — the announcement is how a refusal is seen at all.
        if let Some(field) = app.notify {
            gate.take_validated(
                &mut notify,
                &mut notify_origin,
                "`notify` policy",
                &mut warnings,
                |w, current| {
                    warn_unknown_notify_keys(w, &source, &field);
                    let parent = current.as_ref().unwrap_or(baseline_notify);
                    validate_notify(w, &source, field, parent).map(Some)
                },
            );
        }
        // `gui` mirrors `network`: an untrusted project may not open a display, on its own app
        // or by overriding a trusted one (the flagship property — an agent runs *on* untrusted
        // code without that code being able to expose the user's compositor).
        if let Some(value) = app.gui {
            gate.take_validated(
                &mut gui,
                &mut gui_origin,
                "`gui` posture",
                &mut warnings,
                |w, _| validate_gui(w, &source, value).map(Some),
            );
        }
        // `gpu` mirrors `gui`: an untrusted project may not open GPU rendering, on its own app or
        // by overriding a trusted one (a render node and the `/sys` device tree widen the kernel
        // attack surface).
        if let Some(value) = app.gpu {
            gate.take(
                &mut gpu,
                &mut gpu_origin,
                "`gpu` posture",
                Some(value),
                &mut warnings,
            );
        }
        // `audio` mirrors `gpu`: an untrusted project may not open audio, on its own app or by
        // overriding a trusted one (the PulseAudio bus exposes the microphone and all system audio).
        if let Some(value) = app.audio {
            gate.take(
                &mut audio,
                &mut audio_origin,
                "`audio` posture",
                Some(value),
                &mut warnings,
            );
        }
        // `dbus` mirrors `gpu`: an untrusted project may not stand up the in-cage portal, on its own
        // app or by overriding a trusted one (a bus sits near the keyring and the portals).
        if let Some(value) = app.dbus {
            gate.take(
                &mut dbus,
                &mut dbus_origin,
                "`dbus` posture",
                Some(value),
                &mut warnings,
            );
        }
        // `[limits]` mirrors `network`/`gui`: a trusted project may tune the cage's limits, on its
        // own app or by overriding a trusted one; an untrusted project may not (loosening them
        // weakens the anti-DoS control). Dropping the untrusted layer here — before any overlay —
        // is what keeps a globally-defined app's tight limits intact under an untrusted project.
        if let Some(raw) = app.limits {
            if trusted {
                let project_limits = validate_limits(&mut warnings, &source, Some(raw));
                mark_limit_origins(&mut limits_origin, &project_limits, Provenance::Project);
                overlay_limits(&mut limits, project_limits);
            } else {
                gate.refuse("`[limits]`", &mut warnings);
            }
        }
        // `[seccomp]` mirrors `[limits]`: a trusted project may relax the denylist for its own app
        // or a trusted one; an untrusted project may not (loosening the kernel-attack-surface
        // control). Dropping the untrusted layer here — before the union — is what keeps a global
        // app's relaxation from being widened by an untrusted project.
        if let Some(raw) = app.seccomp {
            if trusted {
                let project_seccomp = apply_seccomp(&mut warnings, &source, Some(raw));
                if !project_seccomp.is_empty() {
                    seccomp_origin = Provenance::Project;
                }
                seccomp.union(&project_seccomp);
            } else {
                gate.refuse("`[seccomp]`", &mut warnings);
            }
        }
        // `[devices]` mirrors `[seccomp]`: a trusted project may grant a host device to its own app
        // or a trusted one; an untrusted project may not (a device widens the kernel attack surface).
        // Dropping the untrusted layer here — before the union — is what keeps a global app's device
        // grant from being widened by an untrusted project.
        if let Some(raw) = app.devices {
            gate.union(
                &mut devices,
                &mut devices_origin,
                "`[devices]`",
                &mut warnings,
                |w| apply_devices(w, &source, Some(raw)),
                union_devices,
            );
        }
        // `[fs]` masks are ungated here for the reason they are ungated everywhere: an app's masks
        // only take access away from that app's own cage, so an untrusted project declaring them
        // buys nothing.
        //
        // `scan_max_kb` is the exception, and the only
        // gated key in the table: it is not a mask but a ceiling on how many bytes of a file the
        // content lens *reads* before letting the open through, so lowering it closes fewer files.
        // An untrusted project setting `scan_max_kb = 1` therefore widens what its cage may read
        // past, which is the one direction the exemption above does not cover. Stripped and named
        // rather than left to lose a fold, so the author reads why the ceiling did not apply — and
        // stripped *before* `declares_nothing`, so a layer whose only key was this one contributes
        // nothing and does not move the provenance.
        if let Some(raw) = app.fs {
            let mut project_fs = apply_fs(&mut warnings, &source, Some(raw));
            if !gate.trusted && project_fs.scan_max_kb.take().is_some() {
                gate.refuse("`[fs] scan_max_kb`", &mut warnings);
            }
            if !project_fs.declares_nothing() {
                fs_origin = Provenance::Project;
            }
            fs.union(project_fs);
        }
        // `[ssh_agent]` mirrors `[devices]`: a trusted project may grant its own app a key to sign
        // with; an untrusted one may not, because such a key authenticates as the user on every host
        // that trusts it. Dropped before the union, so an untrusted project cannot widen the grant a
        // global app was given.
        if let Some(raw) = app.ssh_agent {
            gate.union(
                &mut ssh_agent,
                &mut ssh_agent_origin,
                "`[ssh_agent]`",
                &mut warnings,
                |w| {
                    let (keys, confirm) = apply_ssh_agent(w, &source, Some(raw));
                    ssh_agent_confirm |= confirm;
                    keys
                },
                union_ssh_agent,
            );
        }
        // `forward` mirrors `network`/`gui`: a trusted project may add forward ports to its own
        // app or a trusted one; an untrusted project may not (opening a host port is an inbound
        // hole). The ports union onto the app's own set, so the project adds, never replaces.
        if let Some(raw) = app.forward {
            gate.union(
                &mut forward,
                &mut forward_origin,
                "`forward` ports",
                &mut warnings,
                |w| validate_forward(w, &source, &raw),
                union_forward,
            );
        }
        if let Some(section) = app.secret {
            if trusted {
                // A project-local app resolves its secrets against the project-effective defaults
                // (global + the project's own `[secret.defaults]`), unlike the global-layer site
                // above which uses the global defaults — a project's resolver order/bindings reach
                // its own apps, never a globally-declared one.
                apply_app_secret(
                    &mut secrets,
                    &mut warnings,
                    &source,
                    section,
                    project_secret_defaults,
                    plugins,
                );
            } else {
                let n = count_host_secrets(&section.hosts);
                if n > 0 {
                    gate.refuse(&format!("{n} secret(s)"), &mut warnings);
                }
            }
        }
        // A project layer's tasks mirror its secrets: a trusted project may declare tasks on its own
        // app or on a trusted one; an untrusted project may not — a task it could add would run a
        // program of its choosing with a credential attached.
        if let Some(section) = app.task {
            if trusted {
                warn_unknown_task_keys(&mut warnings, &source, &section);
                tasks::apply_task_section(
                    &mut tasks,
                    &mut warnings,
                    &tasks::TaskLayer {
                        source: &source,
                        origin: TaskOrigin::App(name.to_string()),
                    },
                    section,
                    task_defaults,
                    project_secret_defaults,
                    plugins,
                );
            } else if !section.tasks.is_empty() {
                gate.refuse(&format!("{} task(s)", section.tasks.len()), &mut warnings);
            }
        }
        if let Some(c) = app.cmd {
            if trusted || !defined_by_a_trusted_layer {
                cmd = c.into_argv();
                cmd_origin = Provenance::Project;
            } else {
                // Not phrased as an override: the trusted profile may have declared no `cmd` at
                // all, which is exactly the case this refusal exists for.
                gate.refuse("`cmd` for an app a trusted layer defines", &mut warnings);
            }
        }
        if let Some(raw) = app.home_scope {
            // A trusted project may set any scope; an untrusted one may set its own app's scope
            // (nothing trusted to steer) but not choose it for a trusted app — `Global` is the
            // shared home, the contamination vector, and a profile that named no scope takes the
            // built-in default rather than the project's word for it.
            if trusted || !defined_by_a_trusted_layer {
                if let Some(scope) = validate_home_scope(&mut warnings, &source, &raw) {
                    home_scope = scope;
                    home_scope_origin = Some(Provenance::Project);
                }
            } else {
                gate.refuse(
                    "`home_scope` for an app a trusted layer defines",
                    &mut warnings,
                );
            }
        }
    }

    ResolvedApp {
        allow_insecure_http: own_allow_insecure_http,
        allow_insecure_http_origin,
        cmd,
        provisions,
        home_scope,
        env,
        binds,
        packages,
        accepts_fresh_releases,
        open,
        service,
        network,
        proc,
        notify,
        gui,
        gpu,
        audio,
        dbus,
        limits,
        seccomp,
        devices,
        fs,
        ssh_agent,
        ssh_agent_confirm,
        forward,
        secrets,
        tasks,
        default_methods,
        cmd_origin,
        network_origin,
        proc_origin,
        notify_origin,
        gui_origin,
        gpu_origin,
        audio_origin,
        dbus_origin,
        forward_origin,
        seccomp_origin,
        devices_origin,
        fs_origin,
        ssh_agent_origin,
        limits_origin,
        home_scope_origin,
        warnings,
    }
}

/// Apply an app's `[app.<name>.secret]` section, merging any app-level `defaults` over the
/// base resolver defaults before resolving each host's credential — the same shape as the
/// baseline `[secret]` section.
fn apply_app_secret(
    out: &mut Vec<HeaderSecret>,
    warnings: &mut Vec<String>,
    source: &str,
    section: schema::RawSecretSection,
    base_defaults: &SecretDefaults,
    plugins: &PluginRegistry,
) {
    let effective = match &section.defaults {
        Some(raw) => {
            warn_resolver_bindings(warnings, source, raw, plugins);
            base_defaults.merged_with(raw)
        }
        None => base_defaults.clone(),
    };
    apply_secret_section(out, warnings, source, section.hosts, &effective, plugins);
}

/// The warning source label for a field of a **global** app — e.g. `"apps/demo-app.toml"`.
///
/// A global app is a profile file, whose fields sit at its top level: [`load::merge_profile_apps`]
/// clears any inline `[app.*]` in the global config before resolution, so every global app reaching
/// here came from that directory. Naming `sbx.toml [app.<name>]` would send the reader to a file
/// that does not carry the key, in a shape the loader refuses.
fn global_app_source(name: &str) -> String {
    format!("{PROFILES_DIR}/{name}.toml")
}

/// The warning source label for a field of a **project** app — e.g. `".sbx.toml [app.demo-app]"` —
/// so a dropped app field reads as clearly as a baseline one. A project app is inline by
/// construction: the profile directory is a sibling of the global config, never of a project's.
fn project_app_source(name: &str) -> String {
    format!("{PROJECT_CONFIG} [app.{name}]")
}
